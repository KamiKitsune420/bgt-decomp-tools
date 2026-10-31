"""Which calls may be dropped -- `purity.Purity`.

Run with `python -m pytest tests/nvgt/test_purity.py -q`, or
`python -m unittest -v test_purity` from this directory.

Synthetic modules only: every `Function` and `Instr` here is built by hand,
so nothing in this file needs a game, an engine install or a fixture build.

What is being pinned is the *direction* of each answer. A function wrongly
reported pure is a dropped call that will never be reported again, so each
test below asserts the conservative answer for a shape the analysis cannot
see through, as well as the permissive answer for one it can.
"""
import unittest

import purity
from purity import Purity
from asreader import DataType, Function, Instr, Module


def ins(name: str, **kw) -> Instr:
    """One instruction, with the four positional fields the reader fills.

    `bc_type` and `size` are never read by the analysis -- it dispatches on
    the name -- so they carry a plausible value rather than the real one for
    each opcode, which would be a second copy of `opcodes.py`.
    """
    return Instr(pos=kw.pop("pos", 0), op=kw.pop("op", 0), name=name,
                 bc_type="asBCTYPE_NO_ARG", size=1, **kw)


def fn(name: str, body=None, *, func_type: int = 1, params=0) -> Function:
    """A script function, with bytecode unless `body` is None.

    `body=None` gives the shape a call operand really hands you: a
    signature-only stub, the way `asreader._read_used_function` builds one.
    """
    return Function(name=name, func_type=func_type,
                    param_types=[DataType() for _ in range(params)],
                    bytecode=list(body) if body else [])


def module(*bodies) -> Module:
    return Module(global_functions=list(bodies))


def call(target: Function, op: str = "CALL") -> Instr:
    return ins(op, func_ref=target)


RET = ins("RET")


class EngineSetTests(unittest.TestCase):
    """The list half of the answer: a registered function has no bytecode.

    Membership was decided by `bgt api <name>`, against the engine's own
    documentation and its registration strings. These tests pin the two
    answers that matter rather than re-deriving the list, which would mean
    an engine install.
    """

    def setUp(self):
        self.p = Purity(module())

    def test_listed_name_is_pure(self):
        self.assertTrue(self.p.is_pure(fn("round", func_type=0, params=2)))

    def test_random_is_not_pure(self):
        """`random` advances the generator -- the lost call this is for."""
        self.assertFalse(self.p.is_pure(fn("random", func_type=0, params=2)))
        self.assertIn("ENGINE_PURE", self.p.reason(fn("random", func_type=0)))

    def test_unlisted_registered_name_is_impure(self):
        """A name that is simply absent errs toward impure, by construction."""
        for name in ("joueSon", "set_sound_storage", "load", "stream",
                     "enter_confirmation", "update_sound_2d"):
            with self.subTest(name=name):
                self.assertFalse(self.p.is_pure(fn(name, func_type=0)))

    def test_application_tag_is_func_type_six(self):
        """`_read_used_function` rewrites the funcType of an `'a'`/`'s'`
        entry to 6, so a registered callee can arrive as 6 rather than 0.
        Both have to reach the engine set or every engine call reads as
        unknown."""
        self.assertTrue(self.p.is_pure(fn("round", func_type=6, params=2)))

    def test_rejected_names_are_not_in_the_pure_set(self):
        self.assertEqual(purity.ENGINE_PURE & purity.ENGINE_REJECTED, frozenset())

    def test_nothing_that_acts_is_listed(self):
        """A standing guard on the set as it grows: nothing named for an
        action, and no setter, may be in it."""
        acting = ("set_", "play", "load", "stream", "speak", "key_", "file_",
                  "directory_", "mouse_", "clipboard_", "url_get", "url_post",
                  "screen_reader", "random", "garbage_collect", "exit", "run",
                  "wait", "input_box", "alert", "question")
        # The two network names are spelled out in full because
        # `url_decode`/`url_encode` are string transforms and share the
        # prefix `url_`.
        for name in sorted(purity.ENGINE_PURE):
            with self.subTest(name=name):
                self.assertFalse(name.startswith(acting), name)


class WriteTests(unittest.TestCase):
    """A write outside the frame, and the one read-only shape."""

    def test_a_getter_that_only_reads_is_pure(self):
        getter = fn("getCentreX", [ins("LoadThisR"), ins("RDR4"),
                                   ins("CpyVtoR4"), RET])
        self.assertTrue(Purity(module(getter)).is_pure(getter))

    def test_writing_a_global_is_impure(self):
        f = fn("bump", [ins("SetG4", global_name="score"), RET])
        p = Purity(module(f))
        self.assertFalse(p.is_pure(f))
        self.assertIn("score", p.reason(f))

    def test_copying_a_variable_to_a_global_is_impure(self):
        f = fn("bump", [ins("CpyVtoG4", global_name="score"), RET])
        self.assertFalse(Purity(module(f)).is_pure(f))

    def test_writing_through_the_reference_register_is_impure(self):
        """`WRTV4` writes wherever the register points, and the bytecode
        does not say where. So this is impure even when the destination is
        one of the function's own locals -- which costs a statement and
        cannot cost correctness."""
        for op in ("WRTV1", "WRTV4", "WRTV8", "REFCPY", "RefCpyV", "COPY",
                   "INCi", "DECi", "INCi64", "DECd"):
            with self.subTest(op=op):
                f = fn("w", [ins("LoadThisR"), ins(op), RET])
                self.assertFalse(Purity(module(f)).is_pure(f))

    def test_incrementing_a_named_variable_is_not_a_write(self):
        """`IncVi` names the slot it increments, so that write is provably
        frame-local -- unlike `INCi`, which goes through the register."""
        f = fn("count", [ins("IncVi", w_arg=3), ins("DecVi", w_arg=3), RET])
        self.assertTrue(Purity(module(f)).is_pure(f))


class PropagationTests(unittest.TestCase):
    """The fixpoint half: purity travels along the call graph.

    Every callee here is a *stub* -- an empty-bytecode `Function` with the
    callee's signature -- because that is what a call operand really is.
    `asreader._read_used_function` reads only a signature even for a module
    function whose body it has already read, so the analysis has to find the
    body by signature or no script call resolves at all.
    """

    def test_caller_of_a_pure_callee_is_pure(self):
        b = fn("b", [ins("CpyVtoR4"), RET])
        a = fn("a", [call(fn("b")), RET])
        self.assertTrue(Purity(module(a, b)).is_pure(a))

    def test_caller_goes_impure_when_the_callee_does(self):
        b = fn("b", [ins("SetG4", global_name="score"), RET])
        a = fn("a", [call(fn("b")), RET])
        p = Purity(module(a, b))
        self.assertFalse(p.is_pure(b))
        self.assertFalse(p.is_pure(a))
        self.assertIn("impure", p.reason(a))

    def test_impurity_travels_more_than_one_edge(self):
        c = fn("c", [ins("LoadThisR"), ins("WRTV4"), RET])
        b = fn("b", [call(fn("c")), RET])
        a = fn("a", [call(fn("b")), RET])
        self.assertFalse(Purity(module(a, b, c)).is_pure(a))

    def test_mutual_recursion_terminates_and_reports_pure(self):
        """Starting optimistic is what makes this answer `pure`: neither
        function ever acquires a reason to be impure, so the loop settles."""
        a = fn("a", [call(fn("b")), RET])
        b = fn("b", [call(fn("a")), RET])
        p = Purity(module(a, b))
        self.assertTrue(p.is_pure(a))
        self.assertTrue(p.is_pure(b))

    def test_self_recursion_terminates(self):
        a = fn("a", [call(fn("a")), RET])
        self.assertTrue(Purity(module(a)).is_pure(a))

    def test_recursive_cycle_with_a_write_in_it_is_impure(self):
        a = fn("a", [call(fn("b")), RET])
        b = fn("b", [call(fn("a")), ins("SetG4", global_name="g"), RET])
        p = Purity(module(a, b))
        self.assertFalse(p.is_pure(a))
        self.assertFalse(p.is_pure(b))

    def test_an_unresolved_callee_is_impure(self):
        a = fn("a", [ins("CALL", func_ref=None), RET])
        p = Purity(module(a))
        self.assertFalse(p.is_pure(a))
        self.assertFalse(p.is_pure(None))

    def test_a_stub_with_no_body_in_the_module_is_impure(self):
        """A script-typed callee the module does not hold cannot be cleared.

        `a` is the only body here, so `b`'s stub resolves to nothing.
        """
        a = fn("a", [call(fn("b")), RET])
        p = Purity(module(a))
        self.assertFalse(p.is_pure(a))
        self.assertIn("no body", p.reason(fn("b")))

    def test_an_ambiguous_stub_is_impure(self):
        """Two bodies with one signature: resolving to either would be an
        answer about some other function."""
        one = fn("dup", [RET])
        two = fn("dup", [ins("SetG4", global_name="g"), RET])
        caller = fn("caller", [call(fn("dup")), RET])
        p = Purity(module(caller, one, two))
        self.assertFalse(p.is_pure(caller))

    def test_the_signature_picks_the_RIGHT_overload(self):
        """The exact signature is the identity, and it has to be: these two
        bodies share a name and an arity, and only one of them is pure."""
        pure_one = fn("ov", [ins("CpyVtoR4"), RET], params=1)
        pure_one.param_types = [DataType(token_type=70)]            # int
        impure_one = fn("ov", [ins("SetG4", global_name="g"), RET], params=1)
        impure_one.param_types = [DataType(token_type=94)]          # double
        p = Purity(module(pure_one, impure_one))

        int_stub = fn("ov", params=1)
        int_stub.param_types = [DataType(token_type=70)]
        double_stub = fn("ov", params=1)
        double_stub.param_types = [DataType(token_type=94)]
        self.assertTrue(p.is_pure(int_stub))
        self.assertFalse(p.is_pure(double_stub))

    def test_a_debug_build_body_still_matches_its_stub(self):
        """Parameter names must be left out of the identity key.

        They survive only in debug info, so a body from a debug build has
        them and the `usedFunctions` stub never does. Keyed with names, no
        stub would find its body, every script call would read as unknown,
        and the analysis would answer nothing while still passing every
        other test in this file.
        """
        body = fn("g", [ins("CpyVtoR4"), RET], params=1)
        body.param_names = ["how_many"]
        body.has_debug_info = True
        self.assertIn("how_many", body.signature(with_param_names=True))
        self.assertNotIn("how_many", body.signature(with_param_names=False))
        self.assertTrue(Purity(module(body)).is_pure(fn("g", params=1)))

    def test_a_signature_mismatched_stub_is_impure(self):
        """There is no looser fallback key, on purpose.

        A fallback could only turn an unresolved callee -- reported impure --
        into a resolved one that may be reported pure, which is the unsafe
        direction. So a stub whose signature names no body answers impure
        even when exactly one body shares its name and arity.
        """
        body = fn("g", [ins("CpyVtoR4"), RET], params=1)
        stub = fn("g", params=1)
        stub.return_type = DataType(token_type=70)   # int, where body says tok0
        self.assertNotEqual(stub.signature(with_param_names=False),
                            body.signature(with_param_names=False))
        self.assertFalse(Purity(module(body)).is_pure(stub))


class CallSiteTests(unittest.TestCase):
    """`is_pure_call`, which also knows the opcode."""

    def test_callptr_is_impure(self):
        """A funcdef-typed local: the target is whatever was bound."""
        a = fn("a", [ins("CallPtr", w_arg=4), RET])
        p = Purity(module(a))
        self.assertFalse(p.is_pure(a))
        self.assertFalse(p.is_pure_call(ins("CallPtr", w_arg=4)))

    def test_callbnd_is_impure(self):
        a = fn("a", [ins("CALLBND", func_ref=fn("imported", func_type=5)), RET])
        self.assertFalse(Purity(module(a)).is_pure(a))

    def test_a_virtual_dispatch_is_impure_even_to_a_pure_callee(self):
        """`CALLINTF` records the class that *declared* the method, not the
        override that runs, so the resolved callee's purity says nothing.
        Paladin's `door::door` calls `interact::reset` and `door::reset` is
        what executes.
        """
        declared = fn("reset", [ins("CpyVtoR4"), RET])
        p = Purity(module(declared))
        self.assertTrue(p.is_pure(declared))                       # the body
        self.assertFalse(p.is_pure_call(call(fn("reset"), "CALLINTF")))
        self.assertTrue(p.is_pure_call(call(fn("reset"), "CALL")))

    def test_alloc_without_a_constructor_index_is_impure(self):
        """`ALLOC` arg1 is a one-based `usedFunctions` index and 0 means the
        type has no script constructor, so the engine's own factory runs and
        nothing resolves."""
        self.assertFalse(Purity(module()).is_pure_call(ins("ALLOC")))

    def test_a_non_call_instruction_is_droppable(self):
        self.assertTrue(Purity(module()).is_pure_call(ins("PshV4")))


class OpcodeNameTests(unittest.TestCase):
    """A misspelled opcode name is a write the analysis never sees.

    CLAUDE.md records three occasions on which a pattern stopped matching
    anything and nothing failed, because a dead branch is not a test
    failure. `purity._assert_known_opcodes` runs at import; this calls it
    explicitly so the check is a named test rather than a side effect.
    """

    def test_every_opcode_name_is_real(self):
        purity._assert_known_opcodes()

    def test_the_sets_are_not_empty(self):
        for name in ("GLOBAL_WRITES", "REF_WRITES", "CALL_OPS",
                     "UNKNOWN_TARGET_OPS", "ENGINE_PURE"):
            with self.subTest(name=name):
                self.assertTrue(getattr(purity, name))

    def test_setg8_and_cpyvtog8_do_not_exist(self):
        """Checked rather than assumed: this instruction set has no 64-bit
        store-to-global opcode, so a 64-bit global is written through its
        address and `REF_WRITES` is what catches it."""
        from opcodes import OPCODES
        names = {entry[0] for entry in OPCODES.values()}
        self.assertNotIn("SetG8", names)
        self.assertNotIn("CpyVtoG8", names)
        self.assertIn("WRTV8", purity.REF_WRITES)


if __name__ == "__main__":
    unittest.main()
