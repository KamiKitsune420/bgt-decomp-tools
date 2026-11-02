"""Known-answer tests for the slot-web analysis.

One frame slot is not one variable: the compiler reuses a slot for several
source locals that are live at different times. Deciding which writes to a
slot are *one* variable is the standard hard problem of decompilation, and
this is the standard answer -- reaching definitions, then group the
definitions that share a use. The term `web` comes from register allocation,
where the analysis runs the other way round.

**It is not invented here, and neither is the trap.** Hex-Rays offers the same
split by hand (`Split variable`) and says it performs no checks; angr added
the automatic version and the commit that fixed it reads "split a seeded
stack region among vvars whose live ranges interfere" -- without which its
output rendered `v0 + v0`, which is this decompiler's
`(local_14 != 0) && (local_14 != 0)` under another name.

The three cases below are the ones whose answer is known independently, and
two of them pull in opposite directions -- which is the whole point: any rule
that splits must not split the joystick flag, and any rule that merges must
not merge Field Wars' chain with the write 5,000 instructions later.
"""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.path.insert(0, os.path.join(ROOT, "tools", "nvgt"))

import decompile                                              # noqa: E402
from asreader import Instr                                    # noqa: E402


def op(name, pos, w_arg=0, w_arg2=0, dw_arg=0, bc_type="", jump_target=None):
    return Instr(pos=pos, op=0, name=name, bc_type=bc_type, size=1,
                 w_arg=w_arg, w_arg2=w_arg2, dw_arg=dw_arg,
                 jump_target=jump_target)


def sim(instrs):
    """A FuncDecompiler with just enough state for the analysis."""
    fd = object.__new__(decompile.FuncDecompiler)
    fd.instrs = instrs
    fd.pos_of = {i.pos: k for k, i in enumerate(instrs)}
    return fd


class WorklistTests(unittest.TestCase):
    """The dataflow has to start from every instruction, not the entry.

    Seeded with `{0}` alone it ran exactly ONE round and stopped: the entry's
    state is empty, propagating an empty set changes nothing, and a node is
    re-queued only when its state changes -- so no definition was ever
    reached. Every write then came out as its own web, including the ones
    that must not be split, and the tell was the joystick flag reporting four
    writes and four webs when the right answer is one.
    """

    def test_a_definition_reaches_a_later_use(self):
        #  0 SetV4 v5,1   1 CpyVtoR4 v5 (a read)   2 RET
        instrs = [op("SetV4", 0, w_arg=5, dw_arg=1, bc_type="asBCTYPE_wW_DW_ARG"),
                  op("CpyVtoR4", 1, w_arg=5, bc_type="asBCTYPE_rW_ARG"),
                  op("SetV4", 2, w_arg=5, dw_arg=2, bc_type="asBCTYPE_wW_DW_ARG"),
                  op("CpyVtoR4", 3, w_arg=5, bc_type="asBCTYPE_rW_ARG"),
                  op("RET", 4)]
        fd = sim(instrs)
        webs = fd.slot_webs(5)
        # two writes, each with its own read and neither reaching the other's:
        # two variables that happen to share a slot, which is a split
        self.assertEqual(len(webs), 2, webs)


class InterferenceTests(unittest.TestCase):
    """Two writes a single read can both see are ONE variable.

    This is the joystick flag: `dynamic_menu`'s edge flag is written in the
    UP arm and in the DOWN arm and read at the top of the loop. Split, the UP
    arm wrote one name and only the DOWN arm read it -- so pressing up
    disarmed down, which is why this file settled on one name per slot before
    the interference check existed.
    """

    def _diamond(self):
        #  0 JZ -> 3        (conditional)
        #  1 SetV4 v7, 1    (then arm writes)
        #  2 JMP -> 4
        #  3 SetV4 v7, 2    (else arm writes)
        #  4 CpyVtoR4 v7    (the join reads)
        #  5 RET
        return [op("JZ", 0, jump_target=3),
                op("SetV4", 1, w_arg=7, dw_arg=1, bc_type="asBCTYPE_wW_DW_ARG"),
                op("JMP", 2, jump_target=4),
                op("SetV4", 3, w_arg=7, dw_arg=2, bc_type="asBCTYPE_wW_DW_ARG"),
                op("CpyVtoR4", 4, w_arg=7, bc_type="asBCTYPE_rW_ARG"),
                op("RET", 5)]

    def test_both_arms_of_a_diamond_are_one_web(self):
        webs = sim(self._diamond()).slot_webs(7)
        self.assertEqual(len(webs), 1, webs)
        self.assertEqual(webs[0], frozenset({1, 3}))

    def test_a_write_the_only_read_cannot_see_is_its_own_web(self):
        """A dead store belongs with nothing, and is reported as its own web
        so a caller can tell it apart from a live one."""
        instrs = self._diamond()
        # ...plus a write after the read, which that read cannot see
        instrs = instrs[:5] + [
            op("SetV4", 5, w_arg=7, dw_arg=9, bc_type="asBCTYPE_wW_DW_ARG"),
            op("RET", 6)]
        fd = sim(instrs)
        fd.pos_of = {i.pos: k for k, i in enumerate(instrs)}
        webs = fd.slot_webs(7)
        self.assertEqual(len(webs), 2, webs)
        self.assertIn(frozenset({1, 3}), webs)
        self.assertIn(frozenset({5}), webs)


class LoopTests(unittest.TestCase):
    """A back edge carries a write to an EARLIER read.

    `while (c) { use(x); x = 1; }` reads before it writes in position order,
    and the loop makes the write reach the read -- so a rule that read
    positions linearly would split them and leave `x` never assigned. The CFG
    is what gets this right, which is why the analysis builds one rather than
    sorting by offset.
    """

    def test_a_write_reaches_a_read_above_it_through_the_back_edge(self):
        #  0 CpyVtoR4 v3   (the read, first in position order)
        #  1 SetV4 v3, 1   (the write, after it)
        #  2 JMP -> 0      (the back edge)
        instrs = [op("CpyVtoR4", 0, w_arg=3, bc_type="asBCTYPE_rW_ARG"),
                  op("SetV4", 1, w_arg=3, dw_arg=1, bc_type="asBCTYPE_wW_DW_ARG"),
                  op("JMP", 2, jump_target=0),
                  op("SetV4", 3, w_arg=3, dw_arg=2, bc_type="asBCTYPE_wW_DW_ARG"),
                  op("RET", 4)]
        fd = sim(instrs)
        webs = fd.slot_webs(3)
        # the write at 1 reaches the read at 0, so it is live there; the one
        # at 3 is unreachable from that read and is its own web
        self.assertTrue(any(1 in web for web in webs), webs)


class DecliningTests(unittest.TestCase):
    def test_a_slot_with_one_write_cannot_be_split(self):
        instrs = [op("SetV4", 0, w_arg=4, dw_arg=1, bc_type="asBCTYPE_wW_DW_ARG"),
                  op("CpyVtoR4", 1, w_arg=4, bc_type="asBCTYPE_rW_ARG"),
                  op("RET", 2)]
        self.assertEqual(sim(instrs).slot_webs(4), [])

    def test_a_slot_nothing_reads_has_no_webs(self):
        instrs = [op("SetV4", 0, w_arg=4, dw_arg=1, bc_type="asBCTYPE_wW_DW_ARG"),
                  op("SetV4", 1, w_arg=4, dw_arg=2, bc_type="asBCTYPE_wW_DW_ARG"),
                  op("RET", 2)]
        self.assertEqual(sim(instrs).slot_webs(4), [])

    def test_a_body_too_big_to_analyse_declines(self):
        """Crazy Party's generated `ajouteLangue` is 1,074,460 instructions.
        Declining is the conservative answer: no split, which is what this
        file does everywhere today."""
        self.assertGreater(decompile.WEB_ANALYSIS_LIMIT, 30000)
        self.assertLess(decompile.WEB_ANALYSIS_LIMIT, 1000000)


class WebLocalNamingTests(unittest.TestCase):
    """`is_named_here` -- the whole-body answer, asked of one web.

    The slot is the wrong unit for this question and the file records it
    failing in both directions: one answer for the body collapses a
    short-circuit chain whose slot is promoted for an unrelated value two
    thousand instructions away, and a fresh name per promotion splits a
    variable the compiler wrote in one branch and read in another.
    """

    def _fd(self, named, webs, sc_defs=(), pos=0):
        from decompile import FuncDecompiler

        class _Ins:
            def __init__(self, pos):
                self.pos = pos

        fd = object.__new__(FuncDecompiler)
        fd.var_names = {off: "local_%d" % off for off in named}
        fd._web_cache = {off: list(w) for off, w in webs.items()}
        fd.sc_defs = set(sc_defs)
        fd.instrs = [_Ins(p) for p in range(0, 400)]
        fd._pos = lambda: pos
        return fd

    def test_an_unnamed_slot_is_unnamed_everywhere(self):
        fd = self._fd(named=(), webs={})
        self.assertFalse(fd.is_named_here(4))

    def test_ONE_web_keeps_the_whole_body_answer(self):
        """Nothing to split, so nothing moves -- which is what keeps every
        slot that really is one variable exactly as it was."""
        fd = self._fd(named=(4,), webs={4: []})
        self.assertTrue(fd.is_named_here(4))

    def test_a_web_with_TWO_definitions_is_a_variable(self):
        """Two paths write it and a read sees both, which is what a declared
        local looks like once the compiler has laid it out."""
        fd = self._fd(named=(4,), webs={4: [frozenset({10, 20}),
                                            frozenset({300})]}, pos=30)
        self.assertTrue(fd.is_named_here(4))

    def test_a_web_with_ONE_definition_is_a_temporary(self):
        fd = self._fd(named=(4,), webs={4: [frozenset({10, 20}),
                                            frozenset({300})]}, pos=320)
        self.assertFalse(fd.is_named_here(4))

    def test_the_governing_definition_is_the_LATEST_at_or_before_here(self):
        """Which is how the simulation walks a body."""
        webs = {4: [frozenset({10}), frozenset({100, 200})]}
        self.assertFalse(self._fd(named=(4,), webs=webs, pos=50)
                         .is_named_here(4))
        self.assertTrue(self._fd(named=(4,), webs=webs, pos=150)
                        .is_named_here(4))

    def test_before_every_write_it_keeps_the_whole_body_answer(self):
        """There is no definition to ask about, so guessing is worse than
        answering what the body says."""
        fd = self._fd(named=(4,), webs={4: [frozenset({10}),
                                            frozenset({20})]}, pos=5)
        self.assertTrue(fd.is_named_here(4))

    def test_a_SHORT_CIRCUIT_destination_is_not_a_variable(self):
        """It has two definitions as well -- the `SetV dest,0|1` and the
        arm's store -- and must still fold, or the structurer loses the
        condition. Field Wars' movement conditions and the `cs` server's
        command dispatcher are what forcing it costs."""
        fd = self._fd(named=(4,), webs={4: [frozenset({10, 20}),
                                            frozenset({300})]},
                      sc_defs=(10, 20), pos=30)
        self.assertFalse(fd.is_named_here(4))

    def test_a_real_variable_that_ALSO_takes_a_merge_is_still_a_variable(self):
        """Psycho Strike's `find_likely_request` is `int local_1 = -1;` whose
        slot is also a merge's destination. Excluding by slot folded its
        arms away and remade the `|| true` defect from a new direction, so
        only the merge's OWN definitions are excluded."""
        fd = self._fd(named=(1,), webs={1: [frozenset({10, 20, 30}),
                                            frozenset({300})]},
                      sc_defs=(30,), pos=40)
        self.assertTrue(fd.is_named_here(1))


class ReferenceRegisterWriteTests(unittest.TestCase):
    """A slot written THROUGH the reference register is written.

    `a++` is `LDV 1 ; INCi`, so the increment names no slot and
    `slot_writes` -- the record that is supposed to hold every write --
    could not see it. `pre_and_post` returned 777 for 757 because of it,
    and `bgt oracle` is what said so.
    """

    def _writes(self, names):
        """Call the REAL walk, never a copy of it.

        The first version of this test re-implemented the loop, which is the
        trap this project records about building an inverse from the same
        table: it would have agreed with a wrong table.
        """
        from decompile import _ref_register_writes

        class _Ins:
            def __init__(self, pos, name, arg):
                self.pos, self.name, self.w_arg = pos, name, arg

        return _ref_register_writes(
            [_Ins(k, name, arg) for k, (name, arg) in enumerate(names)])

    def test_an_increment_through_the_register_writes_the_loaded_slot(self):
        self.assertEqual(self._writes([("LDV", 1), ("INCi", 0)]), {1: [1]})

    def test_a_write_through_it_counts_too(self):
        self.assertEqual(self._writes([("LDV", 7), ("WRTV4", 0)]), {7: [1]})

    def test_the_run_ENDS_when_something_else_is_loaded(self):
        """The register then holds a member, a global or a returned
        reference, so a write after it is not a write to any slot this can
        name."""
        self.assertEqual(
            self._writes([("LDV", 1), ("LoadThisR", 0), ("INCi", 0)]), {})
        self.assertEqual(
            self._writes([("LDV", 1), ("CALLSYS", 0), ("INCi", 0)]), {})

    def test_a_second_LDV_redirects_it(self):
        self.assertEqual(
            self._writes([("LDV", 1), ("INCi", 0), ("LDV", 2), ("DECi", 0)]),
            {1: [1], 2: [3]})

    def test_pre_and_post_s_own_shape(self):
        """`int a = 5; int b = a++; int c = ++a;` -- both increments act on
        slot 1 through the register, and neither names it."""
        self.assertEqual(
            self._writes([("SetV4", 1), ("LDV", 1), ("RDR4", 2), ("INCi", 0),
                          ("CpyVtoV4", 3), ("LDV", 1), ("INCi", 0),
                          ("RDR4", 2), ("CpyVtoV4", 4)]),
            {1: [3, 6]})


class PromoteOnceTests(unittest.TestCase):
    """Promoting one slot twice assigns it to itself.

    `_promote_temp` ends by putting the slot's own name into `temps[off]`, so
    a second promotion emits `local_4 = local_4;` at the FIRST one's bind
    position -- which is how it was found: one `CpyVtoV4 4 3` emitting three
    statements. 630 of them across eight titles, 459 on the `cs` server
    alone.
    """

    def test_a_value_that_is_already_the_slot_s_name_emits_nothing(self):
        from decompile import FuncDecompiler, Atom
        fd = object.__new__(FuncDecompiler)
        fd.temps = {4: Atom("var", "local_4", 1)}
        fd.temp_bound = {4: (76, 3)}
        fd.var_names = {4: "local_4"}
        fd.events = []
        back = fd._promote_temp(4)
        self.assertEqual(fd.events, [])
        self.assertEqual(back.text, "local_4")

    def test_the_originals_own_self_assignment_is_NOT_this(self):
        """Paladin's `arg0 = arg0;` is a real `string::opAssign` in the
        bytecode, rendered at its own instruction through the call path --
        so a value that is a CALL still promotes."""
        from decompile import FuncDecompiler, Atom
        fd = object.__new__(FuncDecompiler)
        fd.temps = {4: Atom("call", "local_4")}
        fd.temp_bound = {4: (76, 3)}
        fd.var_names = {4: "local_4"}
        fd.var_types = {}
        fd.events = []
        fd.forced_slots = set()
        fd.consumed_temps = set()
        fd.mixed_boolean_slots = set()
        fd.stmt_count = 0
        fd.stmt_texts = []
        fd._promote_temp(4)
        self.assertEqual(len(fd.events), 1)


    def test_a_bool_promoted_into_a_NUMERIC_slot_is_converted(self):
        """`mixed_boolean_slots`' contract is that the store writes 1/0, and
        a promotion writes its own statement -- so it has to honour it too.
        The Gate's `load()` came out `local_4 = __nvgt_out_4_248;` with
        `int local_4`, which the engine rejects."""
        from decompile import FuncDecompiler, Atom, DataType, PRIMITIVE_TOKENS
        fd = object.__new__(FuncDecompiler)
        fd.temps = {4: Atom("var", "__nvgt_out_4_248",
                            data_type=DataType(
                                token_type=PRIMITIVE_TOKENS["bool"]))}
        fd.temp_bound = {4: (103, 1)}
        fd.var_names = {4: "local_4"}
        fd.var_types = {4: DataType(token_type=PRIMITIVE_TOKENS["int"])}
        fd.mixed_boolean_slots = set()
        fd.forced_slots, fd.consumed_temps = set(), set()
        fd.events, fd.stmt_count, fd.stmt_texts = [], 0, []
        fd._promote_temp(4)
        self.assertEqual(
            [e.data for e in fd.events],
            [("", "local_4 = (__nvgt_out_4_248 ? 1 : 0);")])
        self.assertIn(4, fd.mixed_boolean_slots)

class ConversionTypeTests(unittest.TestCase):
    """A conversion's result type is known exactly, so the atom says so.

    Left untyped, everything downstream that asks what the value is got
    nothing -- and `_hold_pushed` then fell back to the type of the slot it
    was invalidating, which is a different variable by construction. `cs`'s
    server declared an `int` hold `string` and would not compile.
    """

    def test_the_token_table_is_the_READER_s_inverse(self):
        """One source of truth. Two spellings of one fact is what the
        `$beh0`/`_beh_0_` lesson in this project cost."""
        from decompile import PRIMITIVE_TOKENS
        from asreader import PRIMITIVE_NAMES
        self.assertEqual(PRIMITIVE_TOKENS,
                         {n: t for t, n in PRIMITIVE_NAMES.items()})

    def test_every_conversion_target_the_handler_spells_has_a_token(self):
        """The handler maps the opcode's suffix to a type name; a name with
        no token would silently give the atom no type again."""
        from decompile import PRIMITIVE_TOKENS
        for name in ("int", "uint", "float", "double", "int64",
                     "int8", "int16"):
            self.assertIn(name, PRIMITIVE_TOKENS, name)



    def test_the_HANDLER_really_attaches_it(self):
        """Testing the table alone passes with the handler's lookup deleted:
        the branch goes dead and nothing notices, which is the gap this
        project records for a pattern that matches nothing. `step` takes too
        many collaborators to drive honestly here, so what is pinned is that
        the conversion branch builds its atom's type from the table -- the
        same shape as the test that the compiler driver declares no
        `$Switch`.
        """
        import inspect
        from decompile import FuncDecompiler
        src = inspect.getsource(FuncDecompiler.step)
        branch = src[src.index("if name in CONV_OPS:"):]
        branch = branch[:branch.index("if name in (\"NEGf\"")]
        self.assertIn("PRIMITIVE_TOKENS.get(target)", branch)
        self.assertIn("data_type=(DataType(token_type=token)", branch)

    def test_a_NEGATION_carries_its_operand_s_type(self):
        """It does not change the type, which is the same reason it carries
        the origin."""
        import inspect
        from decompile import FuncDecompiler
        src = inspect.getsource(FuncDecompiler.step)
        branch = src[src.index("if name in (\"NEGf\""):]
        self.assertIn("data_type=neg.data_type", branch[:600])


class HoldTypeTests(unittest.TestCase):
    """A hold is typed from the VALUE, never from the slot being written."""

    def _fd(self, at, slot_type=None):
        from decompile import FuncDecompiler
        fd = object.__new__(FuncDecompiler)
        fd.slot_values = {}
        fd.var_types = {14: slot_type} if slot_type is not None else {}
        fd.held_pushed = set()
        fd.events = []
        fd.stmt_count = 0
        fd.stmt_texts = []
        fd._pos = lambda: 24133
        fd._append_stmt = lambda tn, text: fd.events.append((tn, text))
        return fd

    def test_it_takes_the_VALUE_s_type(self):
        from decompile import Atom, DataType, PRIMITIVE_TOKENS
        value = Atom("call", "int(-(stn(local_14)))",
                     data_type=DataType(token_type=PRIMITIVE_TOKENS["int"]))
        fd = self._fd(value)
        back = fd._hold_pushed(14, value)
        self.assertEqual(fd.events, [("int", "%s = int(-(stn(local_14)));"
                                      % back.text)])
        self.assertTrue(back.text.startswith("__nvgt_held_14_"))

    def test_it_does_NOT_fall_back_to_the_invalidated_slot_s_type(self):
        """That slot holds a different variable -- which is the whole reason
        a hold exists. `cs`'s server came out
        `string __nvgt_held_14_24133 = int(-(stn(local_14)));` and the engine
        said *No matching signatures to `player::give(string, string)`*
        against a candidate taking `(string, int)`."""
        from decompile import Atom, DataType, PRIMITIVE_TOKENS
        value = Atom("call", "int(-(stn(local_14)))")      # no type at all
        fd = self._fd(value,
                      slot_type=DataType(
                          token_type=PRIMITIVE_TOKENS["int"]))
        back = fd._hold_pushed(14, value)
        #: refused rather than declared with the other variable's type
        self.assertIs(back, value)
        self.assertEqual(fd.events, [])


class UnsignedStoreTests(unittest.TestCase):
    """A negative constant stored into an unsigned local needs the cast.

    `Implicit conversion changed sign of value` is a warning, and a warning
    stops an unattended compile on BGT's modal dialog. `uint(0 - 1)` and
    `4294967295` were both put to the compiler and both give 4294967295, so
    this is the spelling and not the value.
    """

    def test_a_negative_constant_expression_is_recognised(self):
        from decompile import _negative_constant
        for text in ("-1", "(0 - 1)", "(2 - 5)", "((0 - 1))"):
            self.assertTrue(_negative_constant(text), text)

    def test_a_non_negative_one_is_not(self):
        from decompile import _negative_constant
        for text in ("1", "(3 - 1)", "0", "(2 * 3)"):
            self.assertFalse(_negative_constant(text), text)

    def test_anything_that_is_not_pure_ARITHMETIC_is_not(self):
        """No name and no call can match, so evaluating one is bounded --
        and a value that merely LOOKS negative is left alone."""
        from decompile import _negative_constant
        for text in ("local_4", "-local_4", "f(-1)", "x - 1", "", "()",
                     "__import__('os')"):
            self.assertFalse(_negative_constant(text), text)


    def _assigner(self, slot_type):
        """A decompiler just complete enough to run `_emit_assign`."""
        from decompile import FuncDecompiler
        fd = object.__new__(FuncDecompiler)
        fd.temps, fd.consumed_temps = {}, set()
        fd.var_types = {9: slot_type}
        fd.var_names = {9: "local_9"}
        fd.mixed_boolean_slots = set()
        fd.declared = set()
        fd.slot_values = {}
        fd.held_pushed = set()
        fd.stack = []
        fd.events, fd.stmt_count, fd.stmt_texts = [], 0, []
        fd._pos = lambda: 529
        fd._append_stmt = lambda tn, text: fd.events.append((tn, text))
        fd._normalize_arg = lambda a, dt: a
        fd._snapshot_pushed = lambda off: None
        return fd

    def test_the_store_really_goes_through_the_cast(self):
        """The function passing its own tests says nothing about the call
        site: deleting it leaves every unit test green."""
        from decompile import Atom, DataType, PRIMITIVE_TOKENS
        fd = self._assigner(DataType(token_type=PRIMITIVE_TOKENS["uint"]))
        fd._emit_assign(9, Atom("call", "(0 - 1)"))
        self.assertEqual(fd.events, [("uint", "local_9 = uint((0 - 1));")])

    def test_a_SIGNED_slot_is_left_exactly_as_it_was(self):
        from decompile import Atom, DataType, PRIMITIVE_TOKENS
        fd = self._assigner(DataType(token_type=PRIMITIVE_TOKENS["int"]))
        fd._emit_assign(9, Atom("call", "(0 - 1)"))
        self.assertEqual(fd.events, [("int", "local_9 = (0 - 1);")])

class InitialiserDeclarationTests(unittest.TestCase):
    """A generated global initialiser needs its locals declared.

    `Structurer.render()` emits statements; the declaration hoisting that
    gives an ordinary function its locals lives in `_body`, and a global's
    initialiser never goes through it. `cs`'s server came out

        string __nvgt_global_init_64() {
            string changes;
            local_1 = (("\r\nnew in " + version) + "...");
            changes = local_1;
            return changes;
        }

    -- `Error: 'local_1' is not declared`, the one error that server had both
    before and after the type fixes beside it.
    """

    def _fd(self, types, names=None):
        from decompile import FuncDecompiler
        fd = object.__new__(FuncDecompiler)
        fd.var_types = dict(types)
        fd.var_names = dict(names or {off: "local_%d" % off for off in types})
        return fd

    def _string(self):
        from decompile import DataType, TypeInfo
        return DataType(obj_type=TypeInfo(name="string"))

    def _int(self):
        from decompile import DataType, PRIMITIVE_TOKENS
        return DataType(token_type=PRIMITIVE_TOKENS["int"])

    def test_a_local_the_statements_USE_is_declared(self):
        from decompile import _initialiser_declarations
        fd = self._fd({1: self._string()})
        got = _initialiser_declarations(
            fd, ['local_1 = ("a" + version);', "changes = local_1;"],
            "changes")
        self.assertEqual(got, ["string local_1;"])

    def test_a_local_nothing_mentions_is_NOT_declared(self):
        """A declaration nothing reads is noise, and this file counts an
        unused declaration as something to avoid rather than add."""
        from decompile import _initialiser_declarations
        fd = self._fd({1: self._string(), 2: self._int()})
        got = _initialiser_declarations(
            fd, ["changes = local_1;"], "changes")
        self.assertEqual(got, ["string local_1;"])

    def test_one_the_statements_ALREADY_declare_is_skipped(self):
        """A second declaration is an error of its own, and that is exactly
        what the generated `__nvgt_out_*` and `__nvgt_held_*` locals are:
        they carry their type on the statement."""
        from decompile import _initialiser_declarations
        fd = self._fd({4: self._int()}, {4: "__nvgt_held_4_12"})
        got = _initialiser_declarations(
            fd, ["int __nvgt_held_4_12 = 7;",
                 "changes = __nvgt_held_4_12;"], "changes")
        self.assertEqual(got, [])

    def test_the_GLOBAL_s_own_name_is_skipped(self):
        """The helper declares it already, so a second one would not
        compile."""
        from decompile import _initialiser_declarations
        fd = self._fd({1: self._string()}, {1: "changes"})
        self.assertEqual(
            _initialiser_declarations(fd, ["changes = \"a\";"], "changes"),
            [])

    def test_a_substring_of_another_name_is_not_a_match(self):
        from decompile import _initialiser_declarations
        fd = self._fd({1: self._string()})
        self.assertEqual(
            _initialiser_declarations(fd, ["changes = local_10;"], "changes"),
            [])

    def test_a_name_only_inside_a_STRING_still_counts(self):
        """Deliberately: a declaration nothing reads compiles, and refusing
        one that is read does not. The other way round is an error, so where
        the two cannot be told apart this takes the harmless side."""
        from decompile import _initialiser_declarations
        fd = self._fd({1: self._string()})
        self.assertEqual(
            _initialiser_declarations(fd, ['changes = "local_1";'],
                                      "changes"),
            ["string local_1;"])


class HandleComparisonTests(unittest.TestCase):
    """`null` compared with `==` is a handle comparison, whatever made it.

    AngelScript's `==` on a handle asks the type for an `opEquals`, and `null`
    has none -- which is what the engine warns about. `cmp_is_handle` is set
    by `CmpPtr` and by nothing else, so a comparison that reached `null`
    through any other opcode kept `==`:

        if (!((local_6 is local_5) || (null == local_5)))

    One site in the corpus, Crazy Party's `Combattant`, and one of that
    title's two remaining warnings -- which matter because BGT shows a warning
    in a modal dialog and waits on it.
    """

    def _pair(self, left, right):
        from decompile import Atom
        return (Atom(*left), Atom(*right))

    def test_CmpPtr_still_says_so_outright(self):
        from decompile import _handle_comparison
        self.assertTrue(_handle_comparison(
            self._pair(("var", "a"), ("var", "b")), True))

    def test_a_null_operand_says_so_too(self):
        from decompile import _handle_comparison
        self.assertTrue(_handle_comparison(
            self._pair(("null", "null"), ("var", "local_5")), False))
        self.assertTrue(_handle_comparison(
            self._pair(("var", "local_5"), ("null", "null")), False))

    def test_a_null_reached_as_a_CONSTANT_says_so(self):
        """`ClrVPtr` binds `Atom("const", "null", 2)`, so the kind is not the
        only spelling the text arrives under."""
        from decompile import _handle_comparison
        self.assertTrue(_handle_comparison(
            self._pair(("const", "null"), ("var", "local_5")), False))

    def test_an_ordinary_comparison_is_left_alone(self):
        from decompile import _handle_comparison
        self.assertFalse(_handle_comparison(
            self._pair(("var", "local_1"), ("const", "0")), False))
        self.assertFalse(_handle_comparison(
            self._pair(("var", "x"), ("const", "null_count")), False))

    def test_no_pair_is_not_a_handle_comparison(self):
        from decompile import _handle_comparison
        self.assertFalse(_handle_comparison(None, False))


if __name__ == "__main__":
    unittest.main()
