"""Run with python -m unittest -v test_regressions."""
from pathlib import Path
import io
import subprocess
import tempfile
import unittest
import struct

import extract
from inspect_exe import identity, pe_imports
from asreader import Instr, _Stream
from decompile import load_any, decompile_module, _esc
from test_support import owned_pe_stub

ROOT = Path(__file__).resolve().parent / "fixtures"


def _unescape(text: str) -> bytes:
    """Read a rendered literal back the way the engine's lexer does.

    Deliberately not the inverse of `_esc` written from `_esc`: `\\xNN` is two
    hex digits and `\\\\`, `\\"`, `\\n`, `\\r`, `\\t` are themselves, and
    everything else is its own UTF-8 bytes. An inverse built from the same
    table would agree with a wrong table.
    """
    out = bytearray()
    i = 0
    while i < len(text):
        if text[i] != "\\":
            out += text[i].encode("utf-8")
            i += 1
            continue
        kind = text[i + 1]
        if kind == "x":
            out.append(int(text[i + 2:i + 4], 16))
            i += 4
        else:
            out += {"\\": b"\\", '"': b'"', "n": b"\n", "r": b"\r",
                    "t": b"\t"}[kind]
            i += 2
    return bytes(out)


class LoopExtentTests(unittest.TestCase):
    """A head-tested loop whose `continue` sits in the middle of its body.

    Paladin's `register_software` is the shape, and getting it wrong meant
    the game could not be registered at all: the validation ended up inside
    the branch where the key was left blank, so a real key was never checked
    and a blank one was compared against the derived key.

    The bytecode, with the compiler's own labels:

        L1: SetV1 t,1 ; JLowZ L4     ; a literal while(true); its exit is L4
            key = input_box(...)
            JLowZ L5                 ; key != "" -> L5
            ...empty handling...
            JMP L1                   ; the CONTINUE, mid-body
        L5: if (get_key(name) == key) { ...; return; }
        L7: "invalid"
            JMP L4                   ; the BREAK -- and L4 is the NEXT event
        L4: ...after the loop...
    """

    def _render(self):
        from decompile import Event, Structurer

        def stmt(pos, text):
            return Event("stmt", pos, ("", text))

        # Positions are dword positions; only their order matters here.
        events = [
            Event("branch", 0x10, ("true", 0x90)),     # the header test
            stmt(0x20, 'key = input_box("Key");'),
            Event("branch", 0x30, ('key != ""', 0x60)),  # -> L5
            stmt(0x40, 'speak("empty");'),
            Event("jump", 0x50, 0x10),                 # the CONTINUE
            Event("branch", 0x60, ("get_key(name) == key", 0x80)),   # L5
            stmt(0x70, "return;"),
            stmt(0x80, 'speak("invalid");'),           # L7
            Event("jump", 0x88, 0x90),                 # the BREAK, next event
            stmt(0x90, "after_the_loop();"),           # L4
        ]
        return Structurer(events).render()

    def test_the_body_runs_to_the_exit_not_to_the_back_edge(self):
        """The back edge closes the body only when nothing follows it.

        Ending at the back edge drops everything after the `continue` --
        here the whole validation -- and leaves the forward jump over it
        looking exactly like a `break`.
        """
        lines = [line.strip() for line in self._render() if line.strip()]
        self.assertIn("while (true) {", lines)
        # the empty-key arm continues rather than breaking out
        self.assertIn("continue;", lines)
        # ...and the validation is INSIDE the loop, not in the empty arm
        body = lines[lines.index("while (true) {") + 1:]
        self.assertTrue(any("get_key(name) == key" in l for l in body),
                        "the validation must be inside the loop: %r" % lines)
        # the code after the loop is emitted exactly once, outside it
        self.assertEqual(sum("after_the_loop();" == l for l in lines), 1)

    def test_a_break_to_the_very_next_event_is_not_a_fallthrough(self):
        """`JMP 0` -- a break whose target is the next instruction.

        A jump to the next event skips no source action and is normally a
        fallthrough, but falling through stays *inside* the loop: at the end
        of a body it goes round again. Dropped, an invalid key re-prompted
        for the key instead of returning to the name, and the statement
        after the loop became unreachable.
        """
        lines = [line.strip() for line in self._render() if line.strip()]
        self.assertIn("break;", lines)
        self.assertLess(lines.index("break;"), lines.index("after_the_loop();"))


class ReusedObjectSlotTests(unittest.TestCase):
    """A reused object slot is the compiler's scratch, not a variable.

    `objVariableTypes` names every object slot, so the decompiler has a
    declaration for each one and no way to tell which the source NAMED --
    the gap this whole file works around. For an object the engine answers
    it: a declared local is constructed ONCE where it is declared and
    re-assigned with `opAssign` after that, while the compiler's scratch
    slot is constructed afresh at every use.

    Counted over the originals, `STR ; <factory> ; PshRPtr ; PSF v ;
    CALLSYS ?` ends in `string::string(const string&in)` 544 times on Super
    Egg Hunt and 2,759 on Paladin, against `string::opAssign` 2 and 20 --
    while the recovery wrote 468 and 2,281 `local_N = "...";` lines, which
    is the `opAssign` spelling.

    Two of the three conditions are here because the first form broke a
    title, and both are pinned below.
    """

    def _sim(self, construct=None, known=None, assigned=None):
        from decompile import FuncDecompiler
        sim = object.__new__(FuncDecompiler)
        sim.construct_sites = construct or {}
        sim.known_construct_sites = known or {}
        sim.assigned_slots = set(assigned or ())
        return sim

    @staticmethod
    def _literal():
        from decompile import Atom
        return Atom("const", '"Product_Id"')

    @staticmethod
    def _a_call():
        from decompile import Atom
        return Atom("call", 'input_box("Registration", "the key")')

    def test_one_construction_site_is_a_declared_local(self):
        """Where it is declared. Nothing changes for these."""
        sim = self._sim(construct={3: [10]})
        self.assertFalse(sim._reused_object_slot(3, self._literal()))

    def test_two_construction_sites_are_the_compiler_reusing_a_slot(self):
        sim = self._sim(construct={3: [10, 44]})
        self.assertTrue(sim._reused_object_slot(3, self._literal()))

    def test_the_ALLOC_half_is_carried_from_the_PREVIOUS_pass(self):
        """`ALLOC` names its destination on the STACK, so only a pass that
        has run knows it -- and that is the commonest construction in the
        corpus (`PSF 1 ; STR ... ; CALLSYS factory ; PshRPtr ; ALLOC`)."""
        sim = self._sim(known={5: [71, 155, 204]})
        self.assertTrue(sim._reused_object_slot(5, self._literal()))
        # and the two halves add up rather than either one deciding alone
        sim = self._sim(construct={5: [10]}, known={5: [71]})
        self.assertTrue(sim._reused_object_slot(5, self._literal()))

    def test_a_slot_the_engine_REASSIGNS_is_one_the_source_declared(self):
        """`opAssign` only applies to a live object, so a slot it writes was
        already constructed. Without this, Manamon 1's `battle` came out
        with four `local_27 = local_27;` no-ops and that title carried 51
        self-identical lines against the one it has."""
        sim = self._sim(construct={27: [10, 44, 80, 120]}, assigned={27})
        self.assertFalse(sim._reused_object_slot(27, self._literal()))

    def test_a_value_that_is_not_free_to_RE_EVALUATE_is_refused(self):
        """The condition that matters, and the measurement behind it is the
        worst kind of defect in this file.

        Manamon 1's `handle_beta_registration` keeps
        `input_box("Registration", ...)` in a slot with six construction
        sites and no `opAssign` -- so it looks exactly like scratch -- and
        reads it three times. Folded, **the player is asked for the key
        three times**, which is the `file_menu` defect again, with 111 more
        call sites across that title.

        Nothing promotes it back, because `fold_reads` is counted in
        `_read_temp` and these reads never reach it, so a value read three
        times has no entry for the duplicate-bind pass to act on. A literal
        cannot have that problem: re-evaluating it duplicates nothing.
        """
        sim = self._sim(construct={9: [119, 154, 162, 321, 364, 415]})
        self.assertFalse(sim._reused_object_slot(9, self._a_call()))
        # ...and the same slot with a literal in it is still scratch
        self.assertTrue(sim._reused_object_slot(9, self._literal()))

    def test_no_value_at_all_falls_back_to_the_site_count(self):
        """So a caller that cannot say keeps the old behaviour."""
        sim = self._sim(construct={3: [10, 44]})
        self.assertTrue(sim._reused_object_slot(3))


class FoldSafetyTests(unittest.TestCase):
    """When a folded value stops being the value the bytecode computed.

    The decompiler folds a compiler temporary into the expression that reads
    it, and that fold is load-bearing: promoting every one to a variable cost
    Super Egg Hunt 0 residual gotos -> 182 and 0 compiler errors -> 187,
    because a loop condition promoted to a statement stops being a loop
    condition. So the rules here are narrow by necessity, and each one is a
    real failure that compiled cleanly and ran wrong.
    """

    def _sim(self, **attrs):
        """A decompiler with only the fields these predicates read.

        White-box on purpose: building a real one needs a module and a
        function, and what needs pinning is the decision, not the plumbing.
        """
        from decompile import FuncDecompiler
        sim = object.__new__(FuncDecompiler)
        # The diamond test reads three more fields. They default to
        # empty here so a case that is not about diamonds stays about
        # what it was written for; the diamond's own test sets them.
        sim.jmp_spans = []
        sim.slot_writes = {}
        # Writes through a behaviour, which no opcode names. Empty here so a
        # case that is not about object slots stays about what it was written
        # for; the behaviour case sets it.
        sim.behaviour_writes = {}
        sim.short_circuit_slots = set()
        # ...of which the OPERAND slots are the ones the fold rules
        # exempt. A real decompiler derives this by taking the merge
        # destinations out; empty here, and a case about it sets it.
        sim.merge_operands = set()
        sim.var_names = {}
        # `_stale_global` asks which of the module's globals a value
        # reads. A real decompiler always has this; empty here so a case
        # that is not about globals stays about what it was written for.
        sim.global_types = {}
        # A call whose result nothing consumes is parked here until it is
        # written out. It is admitted through the `stmt_count` guard only
        # when it touches a receiver of the value being folded -- the
        # `file::close()` case. A real decompiler always has both fields.
        sim.pending_value_call = None
        sim.pending_value_call_pos = 0
        # ...and the ones already written out, which `_stale_fold` asks
        # about by position.
        sim.flushed_calls = []
        for name, value in attrs.items():
            setattr(sim, name, value)
        return sim

    def test_a_value_computed_inside_a_branch_cannot_be_folded_past_the_join(self):
        """The simulation walks linearly, so a store inside a branch and a read
        after the join look like one straight line. They are not.

        `dynamic_menu::run_extended` sets a joystick flag inside a branch and
        reads it in the menu's arrow condition afterwards. Folded, that read
        became the constant the branch happened to store -- the recovered menu
        said `key_pressed(KEY_UP) || key_pressed(KEY_I) || true`, so the arm
        was always taken and the arrow keys did nothing.
        """
        instrs = [Instr(pos=p, op=0, name="SUSPEND", bc_type="", size=1)
                  for p in range(0, 40, 4)]
        sim = self._sim(instrs=instrs, k=8,          # reading at pos 32
                        cond_spans=[(8, 24)],        # branch 8 -> join 24
                        back_edges=[])
        # bound at 16: inside the branch, and the join is behind us now.
        self.assertTrue(sim._conditionally_bound(16))
        # bound at 4, before the branch: on every path.
        self.assertFalse(sim._conditionally_bound(4))
        # bound at 28, after the join: on every path.
        self.assertFalse(sim._conditionally_bound(28))
        # and a read still inside the branch folds, which is what keeps a
        # condition an expression.
        self.assertFalse(self._sim(instrs=instrs, k=5, cond_spans=[(8, 24)],
                                   back_edges=[])._conditionally_bound(16))

        # A value computed before a loop and read inside it is the same
        # problem through a back edge: the read runs once per iteration while
        # the computation ran once. `dynamic_menu`'s `speak_item` is set
        # before the loop and assigned true by every arrow branch inside it;
        # folded, the loop read `if (false)` and the menu never spoke.
        loop = self._sim(instrs=instrs, k=5,         # reading at pos 20
                         cond_spans=[], back_edges=[(16, 32)])
        self.assertTrue(loop._conditionally_bound(8))    # bound before the loop
        self.assertFalse(loop._conditionally_bound(16))  # bound at the head

    def test_an_expression_built_out_of_a_variable_goes_stale_with_it(self):
        """A property read is repeatable by kind; what it READS may not be.

        The check asked whether the whole value *was* one variable, so
        `arg0.interacts[local_2].mode` -- kind `prop`, no call in its text --
        folded past the statement that reassigned `local_2`.

        Paladin's `add_event` keeps the old interact's mode before removing
        it, because afterwards there is nothing to read it from. Folded, the
        `set_mode` at the end read the element at the *new* index, which the
        line above had removed, so every save that had passed through
        `init_events` died with `Index out of bounds` on load.
        """
        from decompile import Atom
        instrs = [Instr(pos=p, op=0, name="SUSPEND", bc_type="", size=1)
                  for p in range(0, 40, 4)]
        value = Atom(kind="prop", text="arg0.interacts[local_2].mode")

        def sim(writes):
            return self._sim(instrs=instrs, k=8,          # reading at pos 32
                             temps={12: value}, temp_bound={12: (8, 0)},
                             var_names={0: "arg0", 2: "local_2"},
                             slot_writes=writes, var_types={},
                             duplicate_binds=set(), cond_spans=[],
                             back_edges=[], stmt_count=3,
                             stmt_texts=["a;", "b;", "c;"])

        # local_2 written at 20: after the bind at 8, before this read.
        self.assertTrue(sim({2: [20]})._stale_fold(12))
        # written before the bind, so the expression still means what it did.
        self.assertFalse(sim({2: [4]})._stale_fold(12))
        # a slot the expression does not read is somebody else's business.
        self.assertFalse(sim({9: [20]})._stale_fold(12))
        # and a name that is only a property, never a slot, is not a read:
        # `interacts` and `mode` name members, and nothing writes them
        # through the frame.
        self.assertFalse(
            sim({2: [4], 0: [4]})._stale_fold(12))

    def test_a_global_read_goes_stale_through_any_call(self):
        """A global is not one of the frame's slots, and has no receiver.

        `slot_writes` cannot see a global and `_CALL_RECEIVER` finds
        nothing in `current_bgm` to be invalidated through, so a snapshot
        of one folded across whatever ran in between. Any call can write
        any global, which is the same argument `_prop_receiver` makes with
        `this` for a bare member, one scope out.

        Paladin's `pause_menu` keeps `current_bgm` across the menu music
        and restores it on the way out; folded, the restore read the
        global `change_music` had just overwritten, so leaving the pause
        menu re-applied the menu music. And `waiting` keeps
        `int(default_volume)` before the volume keys adjust it, so the
        guard became `default_volume != double(int(default_volume))` --
        always false, and the volume keys never reached the sound.
        """
        from decompile import Atom, DataType
        instrs = [Instr(pos=p, op=0, name="SUSPEND", bc_type="", size=1)
                  for p in range(0, 40, 4)]

        def sim(value, texts, stmt_at_bind=0):
            s = self._sim(instrs=instrs, k=8,
                          temps={12: value}, temp_bound={12: (8, stmt_at_bind)},
                          var_names={}, slot_writes={}, var_types={12: DataType(token_type=70)},
                          duplicate_binds=set(), cond_spans=[],
                          back_edges=[], stmt_count=len(texts),
                          stmt_texts=texts)
            s.global_types = {"current_bgm": DataType(token_type=70),
                              "default_volume": DataType(token_type=70)}
            return s

        bgm = Atom(kind="global", text="current_bgm")
        # A call ran in between, and any call can write any global.
        self.assertTrue(
            sim(bgm, ["change_music(local_5, false, 0);"])._stale_fold(12))
        # An assignment to that global in between counts too.
        self.assertTrue(
            sim(bgm, ["current_bgm = local_5;"])._stale_fold(12))
        # A statement that neither calls anything nor touches it does not.
        self.assertFalse(sim(bgm, ["local_4 = 3;"])._stale_fold(12))
        # Nothing has run since the bind: the same moment, so it folds.
        self.assertFalse(
            sim(bgm, ["change_music(local_5, false, 0);"],
                stmt_at_bind=1)._stale_fold(12))
        # A value BUILT OUT OF a global reaches the same answer by the
        # other path -- `int(default_volume)` is kind `call`, so it has no
        # receiver for `_CALL_RECEIVER` to find.
        cast = Atom(kind="call", text="int(default_volume)")
        self.assertTrue(
            sim(cast, ["default_volume = (default_volume - 2.0);"])
            ._stale_fold(12))

    def test_a_global_read_through_a_method_on_it_is_still_a_global_read(self):
        """The global rule was asked only where there was NO receiver.

        A global object is almost always read through a method on it, so
        the test above reached `int(default_volume)` and could not reach
        `int(music.get_volume())` -- `_CALL_RECEIVER` finds `music`, the
        receiver list is not empty, and the global question was never put.
        What decided it instead was whether some later statement calls a
        method on `music` or assigns it, which is a strictly weaker test
        and cannot see the case even in principle: the statement that
        changes the volume names a handle ALIAS of the global.

        Paladin's `good_thus_far` is the shape, and so is every other
        scene that ducks the soundtrack for dialogue:

            int old = int(music.get_volume());
            fade(local_5, music.get_volume(), -20.0, 250.0, false);
            storyline_scroll(...);
            fade(local_5, music.get_volume(), double(old), 250.0, false);

        Folded, the restore re-read the volume the first `fade` had taken
        down, so it faded -20 dB to -20 dB and the music stayed ducked.
        """
        from decompile import Atom, DataType
        instrs = [Instr(pos=p, op=0, name="SUSPEND", bc_type="", size=1)
                  for p in range(0, 40, 4)]

        def sim(value, texts, globals_=("music",)):
            s = self._sim(instrs=instrs, k=8,
                          temps={12: value}, temp_bound={12: (8, 0)},
                          var_names={}, slot_writes={},
                          var_types={12: DataType(token_type=70)},
                          duplicate_binds=set(), cond_spans=[],
                          back_edges=[], stmt_count=len(texts),
                          stmt_texts=texts)
            s.global_types = dict((g, DataType(token_type=70))
                                  for g in globals_)
            return s

        volume = Atom(kind="call", text="int(music.get_volume())")
        # The intervening statement names the global nowhere -- it changes
        # the volume through `local_5`, a handle to the same object -- so
        # only the global rule can answer, and it must be asked.
        self.assertTrue(
            sim(volume, ["fade(local_5, local_5.get_volume(), -20.0, 250.0,"
                         " false);"])._stale_fold(12))
        # A statement that calls nothing still does not invalidate it.
        self.assertFalse(sim(volume, ["local_4 = 3;"])._stale_fold(12))
        # And the receiver must really be a global: `item_list.length()`
        # over a LOCAL is the rule this file opens with, and it still
        # answers from the receiver test alone. An unrelated call in
        # between leaves it folded, which is what keeps a condition an
        # expression.
        length = Atom(kind="call", text="item_list.length()")
        self.assertFalse(
            sim(length, ["speak(local_4);"], globals_=())._stale_fold(12))
        self.assertTrue(
            sim(length, ["item_list.resize(4);"], globals_=())
            ._stale_fold(12))

    def test_a_snapshot_of_a_member_is_stale_once_that_member_is_assigned(self):
        """`_prop_receiver` gives `this` for a bare member, and a bare
        member assignment names no `this`.

        A method call on the object can change any field, which is why the
        receiver of a bare member is `this` -- but `curseur += arg0;` does
        not mention `this`, so the test could not see the statement that
        moved the very thing being snapshotted.

        Crazy Party's `CodexOmbre::moveCurseur` and six more of its classes
        keep `int old = curseur;`, move and clamp the cursor, and play the
        cursor sound only `if (curseur != old)`. Folded, that guard is
        `curseur != curseur` -- always false -- so arrowing through those
        menus made no sound at all. `audio_form`'s type-to-search uses the
        same snapshot for two guards, so its `==` one always fired (the
        wrap-around search overwrote a successful find) and its `!=` one
        never did (the item found was never spoken).
        """
        from decompile import Atom, DataType
        instrs = [Instr(pos=p, op=0, name="SUSPEND", bc_type="", size=1)
                  for p in range(0, 40, 4)]

        def sim(texts, text="curseur"):
            return self._sim(instrs=instrs, k=8,
                             temps={12: Atom(kind="prop", text=text)},
                             temp_bound={12: (8, 0)},
                             var_names={}, slot_writes={},
                             var_types={12: DataType(token_type=70)},
                             duplicate_binds=set(), cond_spans=[],
                             back_edges=[], stmt_count=len(texts),
                             stmt_texts=texts)

        # The member itself is assigned in between, written bare.
        self.assertTrue(sim(["curseur += arg0;"])._stale_fold(12))
        self.assertTrue(sim(["curseur = 0;"])._stale_fold(12))
        self.assertTrue(sim(["curseur++;"])._stale_fold(12))
        # ...and qualified, which the receiver test already caught.
        self.assertTrue(sim(["this.curseur = 0;"])._stale_fold(12))
        # A statement that only READS it does not invalidate it.
        self.assertFalse(sim(["local_4 = curseur;"])._stale_fold(12))
        # ...but a method call on the object still does, by the older half
        # of this test: a method can change any field, which is why a bare
        # member's receiver is `this` in the first place.
        self.assertTrue(sim(["this.lis(curseur, true);"])._stale_fold(12))
        # A different member is a different thing.
        self.assertFalse(sim(["curseurX += 1;"])._stale_fold(12))
        # And a dotted member path is matched as the whole path.
        self.assertTrue(
            sim(["c_form[i].list_position = 4;"],
                text="c_form[i].list_position")._stale_fold(12))

    def test_an_object_slot_is_written_by_a_behaviour_not_by_an_opcode(self):
        """`slot_writes` was built from opcodes, and a string is not filled
        by one.

        An object slot is filled by pushing its address and calling the
        constructor -- `PSF n` then `CALLSYS string::$beh0` -- so no entry
        in `_SLOT_WRITE_OPS` mentions slot `n` at all, and the question
        "has this slot been written since?" could not be asked about a
        string. `_short_circuit_slots` already knew this one place over.

        Manamon 1's `skill::will_fail` is the cost. The out string is taken
        by value into slot 1, `""` is then built in slot 3, and the two are
        compared -- `if (reason != "")`. Nothing could see slot 3 being
        rebuilt, so the copy's atom still read `local_3` and the condition
        rendered `if (local_3 != local_3)`: always false, so the skill's
        failure reason was never spoken and `unknown_gift::give` took its
        `else` arm whatever the reason was.

        For a computed value it counts where the slot is NAMED, and both
        halves of that are measured: counting every slot made every string
        literal's scratch slot stale and Paladin's `map::deserialize` gained
        56 lines for no correctness, while counting none of them passed a
        base's three coordinates as its health value in `cs`.
        """
        from decompile import Atom, DataType

        class Ref:
            def __init__(self, name):
                self.name = name

        def instr(pos, name, w_arg=0, func=None):
            i = Instr(pos=pos, op=0, name=name, bc_type="", size=1)
            i.w_arg = w_arg
            i.func_ref = Ref(func) if func else None
            return i

        # PSF 3 ; CALLSYS string::$beh0   -- slot 3 is constructed at pos 4.
        instrs = [instr(0, "SUSPEND"), instr(4, "PSF", 3),
                  instr(8, "CALLSYS", 0, "$beh0"), instr(12, "SUSPEND"),
                  instr(16, "SUSPEND")]
        fn = type("F", (), {"variables": [], "param_types": [],
                            "obj_variable_info": [], "has_debug_info": False,
                            "parameters": [], "name": "will_fail"})()

        def sim(kind):
            s = self._sim(instrs=instrs, k=4,          # reading at pos 16
                          temps={1: Atom(kind=kind, text="local_3")},
                          temp_bound={1: (0, 0)},
                          var_names={3: "local_3"},
                          var_types={1: DataType(token_type=70)},
                          duplicate_binds=set(), cond_spans=[],
                          back_edges=[], stmt_count=2,
                          stmt_texts=["local_3 = \"\";", "x = 1;"])
            s.slot_writes = {}
            s.behaviour_writes = {3: [4]}
            return s

        # The value IS slot 3, and slot 3 was rebuilt in between.
        self.assertTrue(sim("var")._stale_fold(1))
        # A computed value counts too, because slot 3 here is NAMED -- which
        # is the narrowing this file prescribed and the two tests below
        # pin from both sides. This assertion was `assertFalse` while the
        # rule was "only a value that IS a slot", on the measurement that
        # counting every slot cost 56 lines in one Paladin body: those were
        # string literals' scratch slots, which are unnamed temps.
        self.assertTrue(sim("call")._stale_fold(1))
        # And with no behaviour write recorded, nothing changes.
        bare = sim("var")
        bare.behaviour_writes = {}
        self.assertFalse(bare._stale_fold(1))

    def test_the_ORIGIN_answers_staleness_and_not_WHERE_THE_STORE_IS(self):
        """A bind is asked four questions and they want two answers.

        Whether anything has run that touches what this value reads is about
        the VALUE, so it takes the position the value ran at -- a copy
        carries the text, and `cs`'s `file_get_contents` read a closed file
        because the copy reset that position. Whether the store is skipped on
        another path, whether this bind was folded twice, and where a
        promoted assignment goes are all about the STORE.

        Writing the origin into `temp_bound` answers all four with the
        earlier position, and that made two unconditional stores in Paladin's
        `other_stuff` look conditionally bound: the `||` chain they belong to
        collapsed into
        `if ((((local_6 == 0) ? 1 : 0) == local_5) || (local_5 != 0))`, so
        which maps get their events initialised changed. It cost 155 lines of
        slot traffic on Super Egg Hunt too; split in two, that title is
        byte-identical.
        """
        from decompile import Atom, DataType
        # The value RAN at 10, inside a branch that ends at 15. The store
        # into this slot is at 30, outside it. The read is at 40.
        value = Atom("call", "local_1.read(0.0)", data_type=DataType(),
                     origin=(10, 0))
        sim = self._sim(instrs=[Instr(pos=40, op=0, name="RET", bc_type="",
                                      size=1)], k=0,
                        temps={4: value}, temp_bound={4: (30, 1)},
                        var_types={4: DataType()}, duplicate_binds=set(),
                        cond_spans=[(5, 15)], back_edges=[],
                        stmt_count=1, stmt_texts=["x();"])
        # Asked of the store, the span does not reach it, and nothing else
        # here touches `local_1`, so the fold stands.
        self.assertFalse(sim._stale_fold(4))
        # Asked of the origin -- which is what conflating the two does -- the
        # span covers it and the fold is refused for a store that is not
        # conditional at all.
        self.assertTrue(sim._conditionally_bound(10))
        self.assertFalse(sim._conditionally_bound(30))

    def test_a_value_that_ran_before_a_mutating_call_is_stale(self):
        """The other side of it, and the defect itself: the close ran at 39,
        the copy into the slot read at 43, and `local_1.read(0.0)` folded
        past it. A closed file reads empty."""
        from decompile import Atom, DataType
        value = Atom("call", "local_1.read(0.0)", data_type=DataType(),
                     origin=(25, 0))
        sim = self._sim(instrs=[Instr(pos=52, op=0, name="RET", bc_type="",
                                      size=1)], k=0,
                        temps={4: value}, temp_bound={4: (43, 1)},
                        var_types={4: DataType()}, duplicate_binds=set(),
                        cond_spans=[], back_edges=[],
                        stmt_count=1, stmt_texts=["x();"])
        sim.flushed_calls = [(39, "local_1.close();")]
        self.assertTrue(sim._stale_fold(4))
        # ...and a close recorded BEFORE the value ran does not count: the
        # window runs from where the value ran to where it is read.
        sim.flushed_calls = [(20, "local_1.close();")]
        self.assertFalse(sim._stale_fold(4))
        # ...nor does one recorded after the read.
        sim.flushed_calls = [(60, "local_1.close();")]
        self.assertFalse(sim._stale_fold(4))

    def test_a_merge_OPERAND_is_exempt_and_a_DESTINATION_is_not(self):
        """Which half of a short-circuit the fold rules may leave alone.

        `_conditionally_bound` carries the argument in its own docstring --
        promoting a merge's operand makes each term an unconditional
        statement, after which the condition reads one slot twice -- and the
        guard that acted on it sat in the DIAMOND half, below the
        `cond_spans` test, which fires first. So the argument was made and
        not applied to the half that fires first, and two shipped guards
        were collapsed by it:

            gift::get_gift     !is_in_party(c) && c != ""
            the save loader    !is_registered() && difficulty == 2

        **Exempting every slot in `short_circuit_slots` is too much**, and
        the measurement that says so is Psycho Strike's
        `find_likely_request`: `int local_1 = -1;` is a source variable the
        compiler reused as the merge's DESTINATION, so exempting it folded
        the conditional stores away and the `return` came out
        `(arg0.bordum >= 100) || false` -- the `|| true` defect, re-made from
        a new direction. An arm-only slot cannot be a source variable: it
        holds a piece of the right-hand operand and exists only while that
        operand is being computed.

        Two narrowings were tried before this one and neither separates the
        two bodies: a read past the merge (`find_likely_request`'s slot IS
        the destination, so its last read is the merge itself) and a write
        outside every arm (true of `local_1 = -1` and of the gift's operand
        slot alike).
        """
        import decompile
        with io.open(decompile.__file__, encoding="utf-8") as fh:
            body = fh.read()

        def method(name):
            cut = body[body.index("    def %s" % name):]
            return cut[:cut.index("    def ", 4)]

        #: the exemption fires FIRST, above the `cond_spans` test...
        head = method("_conditionally_bound")
        self.assertLess(head.index("self.merge_operands"),
                        head.index("self.cond_spans"))
        #: ...and reads the operands, never the whole set.
        self.assertNotIn("self.short_circuit_slots", head)
        #: `_diamond_bind` keeps the broad set, which is right there: a
        #: diamond's two stores are the two arms, so a destination written
        #: on both paths is not a conditional bind in the first place.
        self.assertIn("self.short_circuit_slots", method("_diamond_bind"))

        #: ...and an operand really is exempt where the whole slot set is
        #: not. `test_a_short_circuits_scratch_slots_are_found_from_the_
        #: bytecode` is where the two halves are separated from real
        #: instructions.
        self.assertFalse(
            self._sim(merge_operands={11})._conditionally_bound(6, 11))

    def test_a_computed_value_reading_a_NAMED_slot_goes_stale(self):
        """Rule ten counts a behaviour write -- an object slot filled through
        a pushed address -- and counted it only for a value that IS a slot.

        `cs`'s `load_bases` is what that cost: three `stn(local_16)` calls,
        each rendered with the slot's name, and by the call the slot holds
        the health file's contents. **A base's three coordinates were all
        its health value**, and every base in a save loaded in the same
        place.
        """
        from decompile import Atom, DataType
        value = Atom("call", "int(stn(local_16))", data_type=DataType())
        sim = self._sim(instrs=[Instr(pos=90, op=0, name="RET", bc_type="",
                                      size=1)], k=0,
                        temps={5: value}, temp_bound={5: (20, 1)},
                        var_names={16: "local_16"},
                        var_types={5: DataType()}, duplicate_binds=set(),
                        cond_spans=[], back_edges=[],
                        stmt_count=2, stmt_texts=["a();", "b();"])
        sim.behaviour_writes = {16: [40]}
        self.assertTrue(sim._stale_fold(5))

    def test_a_computed_value_reading_an_UNNAMED_slot_still_folds(self):
        """The half that was measured and rejected: every string literal is
        constructed into a scratch slot, so counting those made
        `(arg1 + local_1)` -- which merely mentions one -- stop folding, and
        Paladin's `map::deserialize` gained 56 lines for no correctness at
        all. A scratch slot is an unnamed temp; a NAMED slot is one the
        source declared."""
        from decompile import Atom, DataType
        value = Atom("call", "int(stn(local_16))", data_type=DataType())
        sim = self._sim(instrs=[Instr(pos=90, op=0, name="RET", bc_type="",
                                      size=1)], k=0,
                        temps={5: value}, temp_bound={5: (20, 1)},
                        var_names={},                 # slot 16 is not named
                        var_types={5: DataType()}, duplicate_binds=set(),
                        cond_spans=[], back_edges=[],
                        stmt_count=2, stmt_texts=["a();", "b();"])
        sim.behaviour_writes = {16: [40]}
        self.assertFalse(sim._stale_fold(5))

    def test_a_behaviour_write_is_the_receiver_pushed_last(self):
        """Only a `PSF` immediately before the call counts.

        The receiver of a behaviour is the address pushed LAST, so in
        `PSF 3 ; PSF 1 ; CALLSYS string::opAssign` slot 1 is assigned and
        slot 3 is merely read. And an operator only counts when it
        ASSIGNS: `opAdd` returns a new value and leaves its receiver
        alone, so a `PSF` before one is a receiver being read.
        """
        from decompile import _ASSIGN_OPS
        self.assertIn("opAssign", _ASSIGN_OPS)
        self.assertIn("opAddAssign", _ASSIGN_OPS)
        self.assertNotIn("opAdd", _ASSIGN_OPS)
        self.assertNotIn("opEquals", _ASSIGN_OPS)
        self.assertNotIn("opIndex", _ASSIGN_OPS)

    def test_assigning_a_field_of_an_object_changes_the_object(self):
        """`voice.rate++` is not a call on `voice` nor an assignment to it.

        So a snapshot taken before it survived it, and Paladin's
        `tts_selector` keeps one in each of its six settings branches:
        `int old = voice.rate; voice.rate++; if (voice.rate == old) ...`.
        Folded past the increment that is `voice.rate == voice.rate`,
        always true with the empty arm taken, so rate, pitch and volume
        all changed silently and nothing said what they had become.
        """
        from decompile import _mutates
        for statement in ("voice.rate++;", "voice.rate--;",
                          "voice.rate = 3;", "voice.rate += 3;",
                          "voice.reader.rate = 3;", "bag[2].count = 1;",
                          "voice.set_current_voice(local_6);"):
            self.assertTrue(_mutates(statement, statement.split(".")[0]
                                     .split("[")[0]),
                            statement)
        # Reading it, or comparing against it, is not writing it.
        for statement in ("local_4 = voice.rate;",
                          "if (voice.rate == local_12) {",
                          "local_4 = voice.rate + 1;",
                          "local_4 = other.rate;"):
            self.assertFalse(_mutates(statement, "voice"), statement)

    def test_lowering_the_duplication_threshold_for_calls_is_not_the_answer(self):
        """Pins the threshold, and the measurement that says why it is 3.

        `_is_repeatable` rejects any text with a bracket in it, so it cannot
        tell `do_damage(a, b)` from `(y - backward_range)`. Lowering the
        threshold only for the ones that really call something looks like the
        right narrowing and is not: it removes 561 duplicated calls from
        Crazy Party and takes that title from 14 residual gotos to 30, which
        is 16 new compiler errors, because AngelScript has no `goto`.

        The duplications it would fix are real -- Paladin's four hp-drain
        attacks each call `do_damage` twice, once to say the number and once
        to apply it -- so this is recorded rather than forgotten. The lever
        is wrong: what must stay folded is a fold inside a condition.
        """
        from decompile import DUPLICATE_FOLDS
        self.assertEqual(DUPLICATE_FOLDS, 3)

    def test_a_slot_tested_with_jlow_is_a_bool_whatever_its_width_says(self):
        """`JLow*` tests the low byte of the value register and follows no
        compare, so it is the bool protocol and nothing else.

        Typing a compiler scratch slot by width called this one an int, which
        made `_begin_bool_merge` decline `stick.get_y() < -100 && !moved`. It
        came out as an `if` with two empty arms and vanished from the
        condition it belonged to.
        """
        def op(name, w_arg=0):
            return Instr(pos=0, op=0, name=name, bc_type="", size=1, w_arg=w_arg)

        sim = self._sim(instrs=[op("CpyVtoV4"), op("CpyVtoR4", 28),
                                op("JLowZ"), op("RET")])
        self.assertTrue(sim._tested_as_bool(28, 1))
        # the load has to be of THAT slot...
        self.assertFalse(sim._tested_as_bool(29, 1))
        # ...and what follows it has to be the boolean test.
        sim = self._sim(instrs=[op("CpyVtoV4"), op("CpyVtoR4", 28),
                                op("CMPi"), op("JZ")])
        self.assertFalse(sim._tested_as_bool(28, 1))
        # SUSPEND is not an instruction for this purpose.
        sim = self._sim(instrs=[op("CpyVtoV4"), op("SUSPEND"),
                                op("CpyVtoR4", 28), op("JLowNZ")])
        self.assertTrue(sim._tested_as_bool(28, 1))
    def test_any_declarable_value_bound_on_one_path_is_promoted(self):
        """The rule is about the PATH, and only about the path.

        `_stale_fold` tested the *kind* of value before consulting
        `_conditionally_bound`, first `const` and then `_is_repeatable`, and
        each narrowing left real stores on the floor. A store inside a branch
        whose slot is read past the join is wrong to fold whatever it holds:
        the read is reachable without that path, so it sees whichever arm ran
        last in the bytecode rather than the one that ran.

        Three bugs, each the same shape. `dynamic_menu::run_extended` opens
        with `bool initial = auto_speak_first;` and clears it at five sites
        once the first item has been announced -- a parameter is repeatable,
        so the fold took it first, every read became `arg3`, which never
        changes, and the block re-armed `speak_item` every iteration: arrow to
        an item, stop, and the menu says its name again, forever.
        `sound_pool` clamps with `int true_y = listener_y; if (listener_y <
        delta_backward) true_y = delta_backward;` -- a *computed* store, so it
        folded away and the call received `delta_forward`, positioning 2D
        sound from the wrong y. And `person::teleport` accumulates
        `local_5 = this.entering_x; local_5 -= (this.x - xpos);`, which
        vanished outright.

        **The old boundary was measured, and the measurement went stale.**
        Promoting computed values was rejected for taking Paladin from 0
        compiler errors to 16, with holds like `__nvgt_hold_7_116 =
        __nvgt_out_7_215;` as the evidence -- and those names say what really
        caused it: a fresh local per promotion, which was separately fixed to
        one name per slot. Re-measured after that, all three titles hold at 0
        residual gotos with a verified split, every `bgt libcheck` score is
        unchanged, and Paladin's empty-bodied `if`s -- the signature this
        class of bug leaves behind -- fall from 33 to 9.
        """
        from decompile import Atom, DataType
        instrs = [Instr(pos=p, op=0, name="SUSPEND", bc_type="", size=1)
                  for p in range(0, 40, 4)]
        param = Atom("var", "arg3", data_type=DataType(token_type=67))

        def sim_for(value):
            return self._sim(instrs=instrs, k=5,          # reading at pos 20
                             cond_spans=[], back_edges=[(16, 32)],
                             temps={7: value}, temp_bound={7: (8, 0)},
                             duplicate_binds=set(), var_types={}, stmt_count=3,
                             stmt_texts=["a;", "b;", "c;"])

        # Bound before the loop head, read inside: promoted, parameter or not.
        self.assertTrue(sim_for(param)._stale_fold(7))
        self.assertTrue(sim_for(Atom("const", "0",
                                     data_type=DataType(token_type=67)))._stale_fold(7))
        # ...and a computed value too: `true_y = delta_backward` is as
        # conditional as `initial = false`, and folding it loses the clamp.
        call = Atom("call", "menu.run_extended(x)",
                    data_type=DataType(token_type=70))
        self.assertTrue(sim_for(call)._stale_fold(7))
        # ...and with no declared type there is nothing to declare, so the
        # value still folds rather than becoming an undeclared name.
        bare = self._sim(instrs=instrs, k=5, cond_spans=[], back_edges=[(16, 32)],
                         temps={7: Atom("var", "arg3")}, temp_bound={7: (8, 0)},
                         duplicate_binds=set(), var_types={}, stmt_count=3,
                         stmt_texts=["a;"])
        self.assertFalse(bare._stale_fold(7))

    def test_a_short_circuits_scratch_slots_are_found_from_the_bytecode(self):
        """They have to be known before the simulation starts, because what
        reads them is the rule that decides which slots become variables.

        BGT records no scalar local, so `bgt_asir` synthesises the
        declaration list in bytecode order -- and the "real source locals are
        the prefix before the first backward offset step" rule then reads
        scope out of an order that has none. In `use_screen_reader` that
        forced two short-circuit scratch slots to be variables, each arm's
        computation became an *unconditional* statement, and since the
        compiler reuses those slots the condition
        `screen_reader && voice.reader > -2 && !voice.sapi_only` collapsed to
        `!sapi_only` -- true where the source is false, so every `speak` went
        to a screen reader that was not there.
        """
        from decompile import FuncDecompiler

        def op(name, pos, w_arg=0, w_arg2=0, dw_arg=0, jump_target=None):
            return Instr(pos=pos, op=0, name=name, bc_type="", size=1,
                         w_arg=w_arg, w_arg2=w_arg2, dw_arg=dw_arg,
                         jump_target=jump_target)

        #   CpyVtoR4 3        ; load the left operand
        #   JLowNZ -> arm     ; if it is true, evaluate the right one
        #   SetV4 2, 0        ; otherwise the whole thing is false
        #   JMP -> merge
        #   arm: RDR4 1 ; CpyVtoV4 2, 1
        #   merge: CpyVtoR4 2
        instrs = [
            op("CpyVtoR4", 0, w_arg=3),
            op("JLowNZ", 1, jump_target=4),
            op("SetV4", 2, w_arg=2, dw_arg=0),
            op("JMP", 3, jump_target=6),
            op("RDR4", 4, w_arg=1),
            op("CpyVtoV4", 5, w_arg=2, w_arg2=1),
            op("CpyVtoR4", 6, w_arg=2),
            op("RET", 7),
        ]
        sim = object.__new__(FuncDecompiler)
        sim.instrs = instrs
        sim.pos_of = {i.pos: k for k, i in enumerate(instrs)}
        slots = sim._short_circuit_slots()

        # the merge's destination, and the slot the arm computes in
        self.assertIn(2, slots)
        self.assertIn(1, slots)
        # **But NOT the slot the jump tested.** The left-hand operand is
        # usually an ordinary local -- `int d = get_total_distance(a, b);
        # if (d > limit && ...)` -- and unforcing it folds the call into each
        # of its reads instead. Taking it cost Super Egg Hunt three
        # duplicated calls, one of them a confirmation prompt asked twice.
        self.assertNotIn(3, slots)
        # And the two kinds are kept apart, because the fold rules may
        # exempt an operand and must not exempt a destination: slot 2 is
        # where the merge's value arrives, slot 1 is a piece of the
        # right-hand operand. See `_conditionally_bound`.
        self.assertEqual(sim.merge_dests, {2})
        self.assertEqual(slots - sim.merge_dests, {1})

    def test_a_merge_LABEL_may_carry_the_arms_scope_cleanup(self):
        """The load is not always the instruction the `JMP` lands on.

        An arm opens a scope, so the compiler releases whatever that scope
        borrowed before the merge reads anything -- the same reason a `break`
        emits its destructors before its own `JMP`. Psycho Strike's
        `home::reset_rebels` indexes an array in its right-hand operand, so
        its merge label is `FREE 3` and the load sits one instruction on:

            JLowNZ -> arm ; SetV4 2,0 ; JMP -> merge
            arm: ... opIndex ; RefCpyV 3 ; ... ; CpyVtoV4 2,4
            merge: FREE 3 ; CpyVtoR4 2

        Reading the label alone missed the merge entirely, so slot 2 was
        forced to be a variable -- and it serves the loop bound *and* both
        operands of the `&&`, so the condition collapsed to
        `if ((local_2 != 0) && (local_2 != 0))` and which rebels get removed
        is wrong. With it the body is
        `if (!arg0 && !rebels[i].former_rebel) continue;`, and the loop comes
        back as the `for` its bound was hiding.

        **Only cleanup that cannot touch the destination is skipped.** A
        `FREE` of the destination itself is not cleanup before the merge, it
        is the end of the value's life, so the run stops there.
        """
        from decompile import FuncDecompiler

        def op(name, pos, w_arg=0, w_arg2=0, dw_arg=0, jump_target=None):
            return Instr(pos=pos, op=0, name=name, bc_type="", size=1,
                         w_arg=w_arg, w_arg2=w_arg2, dw_arg=dw_arg,
                         jump_target=jump_target)

        def build(free_slot):
            instrs = [
                op("CpyVtoR4", 0, w_arg=2),
                op("JLowNZ", 1, jump_target=4),
                op("SetV4", 2, w_arg=2, dw_arg=0),
                op("JMP", 3, jump_target=6),
                op("RefCpyV", 4, w_arg=3),
                op("CpyVtoV4", 5, w_arg=2, w_arg2=4),
                op("FREE", 6, w_arg=free_slot),      # the merge LABEL
                op("CpyVtoR4", 7, w_arg=2),          # ...and the load
                op("RET", 8),
            ]
            sim = object.__new__(FuncDecompiler)
            sim.instrs = instrs
            sim.pos_of = {i.pos: k for k, i in enumerate(instrs)}
            return sim._short_circuit_slots()

        #: the borrowed handle: cleanup, so the merge is found behind it
        self.assertIn(2, build(3))
        #: ...and the destination's own release is not skipped, so a slot
        #: whose life ends at the label is not read as a merge.
        self.assertNotIn(2, build(2))


    def test_an_object_slot_an_arm_constructs_belongs_to_that_arm(self):
        """An object slot is written by a *behaviour*, not by an opcode that
        names it.

        A string is filled by pushing its address and calling the constructor
        -- `PSF n` then `CALLSYS $beh0` -- so nothing in `_SLOT_WRITE_OPS`
        mentions slot `n` at all. Paladin's `item_type_to_function` is
        `arg0 == "healing potion" || arg0 == "medical miracle" || ...` over
        one reused string slot; forced to be a variable, the four assignments
        hoisted out ahead of the `if` and every comparison read the last, so
        three of the four healing items were classified as something else.

        **And a behaviour has two spellings.** The disassembler prints
        `string::_beh_0_`, which is what a reader reaches for; the name the
        IR carries is `$beh0`. Matching only the pretty one matched nothing,
        silently -- the same trap as the delegate factory's
        `%delegate_factory` / `$dlgte`.
        """
        from decompile import FuncDecompiler, Function

        def op(name, pos, w_arg=0, w_arg2=0, dw_arg=0, jump_target=None,
               func=None):
            instr = Instr(pos=pos, op=0, name=name, bc_type="", size=1,
                          w_arg=w_arg, w_arg2=w_arg2, dw_arg=dw_arg,
                          jump_target=jump_target)
            instr.func_ref = Function(name=func) if func else None
            return instr

        def build(behaviour):
            #   CpyVtoR4 5 ; JLowZ -> arm ; SetV1 1,1 ; JMP -> merge
            #   arm: PSF 2 ; CALLSYS <behaviour> ; CpyVtoV4 1,4
            #   merge: CpyVtoR4 1
            instrs = [
                op("CpyVtoR4", 0, w_arg=5),
                op("JLowZ", 1, jump_target=4),
                op("SetV1", 2, w_arg=1, dw_arg=1),
                op("JMP", 3, jump_target=7),
                op("PSF", 4, w_arg=2),
                op("CALLSYS", 5, func=behaviour),
                op("CpyVtoV4", 6, w_arg=1, w_arg2=4),
                op("CpyVtoR4", 7, w_arg=1),
                op("RET", 8),
            ]
            sim = object.__new__(FuncDecompiler)
            sim.instrs = instrs
            sim.pos_of = {i.pos: k for k, i in enumerate(instrs)}
            return sim._short_circuit_slots()

        # the name the IR really carries
        self.assertIn(2, build("$beh0"))
        # ...the destructor marks it too: a slot torn down inside the arm was
        # never one the enclosing scope owned
        self.assertIn(2, build("$beh2"))
        # ...and the spelling a reader would copy out of the disassembly
        self.assertIn(2, build("_beh_0_"))
        # an ordinary call on a slot is a READ, not a write: counting it would
        # unforce a real local and fold its value into every use
        self.assertNotIn(2, build("get_length"))

class LiteralRenderingTests(unittest.TestCase):
    """A literal has to reach the engine as the bytes the module held.

    The engine reads source as bytes. Every byte above 0x7F used to be emitted
    as a character into a UTF-8 file, which turned each one into two: Super Egg
    Hunt's pack key is a 32-byte AES blob in a literal, so the recovered
    project compiled, ran, and reported `Decryption failed because the key was
    incorrect`. It looked finished and had no sound.
    """

    CASES = {
        "an AES blob -- the case that broke":
            bytes([0xAC, 0x71, 0x68, 0x96, 0x26, 0x2B, 0x3E, 0x29, 0x1A]),
        "every byte there is": bytes(range(256)),
        "plain ASCII": b"logo.ogg",
        "UTF-8 text stays text": "caractère été".encode("utf-8"),
        "a lone high byte that is not UTF-8": bytes([0x63, 0xE8, 0x73]),
        "NUL inside a literal": b"able to\x00learn\x00",
        "quotes, slashes and newlines": b'say \\"hi\\"\r\n\tand "bye"',
    }

    def test_rendering_a_literal_round_trips_through_utf8_source(self):
        for label, raw in self.CASES.items():
            with self.subTest(label):
                rendered = _esc(raw.decode("latin-1"))
                # The project file is written UTF-8, so that is the encoding
                # the engine's bytes actually come from.
                through_file = rendered.encode("utf-8").decode("utf-8")
                self.assertEqual(_unescape(through_file), raw)

    def test_text_is_left_readable_and_binary_is_not_left_to_chance(self):
        """The two cases have to be told apart by decoding, not by taste."""
        self.assertEqual(_esc("caractère".encode("utf-8").decode("latin-1")),
                         "caractère")
        blob = bytes([0xAC, 0x96]).decode("latin-1")
        self.assertEqual(_esc(blob), "\\xac\\x96")
        # A control character is escaped even in text, because it is not
        # source anyone can read.
        self.assertEqual(_esc("a\x00b"), "a\\x00b")


class ExtractionTests(unittest.TestCase):
    def test_release_encryption_inverse_with_different_payload_lengths(self):
        for data in (b"a", bytes(range(256)) * 20, b"owned diagnostic module" * 300):
            payload = extract.encrypt_official(data)
            self.assertEqual(len(payload) % 16, 0)
            self.assertEqual(extract.decrypt_official(payload), data)

    def test_nine_byte_signed_integer_encoding(self):
        value = 0x123456789ABCDE
        for prefix, expected in ((0x7F, value), (0xFF, (-value) & ((1 << 64) - 1))):
            reader = _Stream(bytes([prefix]) + value.to_bytes(8, "big") + b"\x2a")
            self.assertEqual(reader.read_encoded_uint64(), expected)
            self.assertEqual(reader.u8(), 42)

    def test_engine_identity_literal_evidence(self):
        commit = "0123456789abcdef" * 2 + "01234567"
        date = "Tuesday, September 15, 2026 at 12:58:27 PM Türkiye Standart Saati"
        data = b"\0" + commit.encode() + b"\0" + date.encode("cp1252") + b"\0"
        data += b"0.10.2\0" + b"0.90.0-dev\0"
        report = identity(data)
        self.assertEqual(report["version"], "0.90.0-dev")
        self.assertEqual(report["commit_candidates"][0]["value"], commit)
        self.assertEqual(report["build_time_candidates"][0]["value"], date)
        self.assertEqual(data[report["commit_candidates"][0]["offset"]:41], commit.encode())
        self.assertIsNone(identity(data + b"0.91.0-dev\0")["version"])

    def test_pe_import_directory(self):
        imports = pe_imports(owned_pe_stub())
        self.assertIn("KERNEL32.dll", imports)
        self.assertEqual(pe_imports(b"not a PE"), [])

    def test_plugin_and_namespace_preamble(self):
        encode = extract.Reader.varint_bytes
        def string(value):
            data = value.encode("utf-8")
            return encode(len(data)) + data
        # A multi-byte length checks both the codec and preamble alignment.
        plugin = "p" * 140
        properties = list(range(extract.NUM_ENGINE_PROPERTIES))
        stream = (struct.pack("<H", 2) + string("legacy_sound") + string(plugin)
                  + struct.pack("<i", 1) + string("sound") + string("upcoming")
                  + b"".join(map(encode, properties)) + struct.pack("<qB", 123456, 1)
                  + b"bytecode marker")
        info = extract.split_stream(stream)
        self.assertEqual(info.plugins, ["legacy_sound", plugin])
        self.assertEqual(info.namespaces, [("sound", "upcoming")])
        self.assertEqual(info.engine_properties, properties)
        self.assertEqual(info.timestamp, 123456)
        self.assertEqual(info.no_auto_chdir, 1)
        self.assertEqual(info.bytecode, b"bytecode marker")

    def test_captured_release_key(self):
        key, iv = extract.official_key_iv(128)
        self.assertEqual(key.hex(), "37a5f29e0834648b1215cca9e6028d010232e9031695dce61c30d1b05e1169f6")
        self.assertEqual(iv.hex(), "f36755c35adc8ebf760ebb32ffa1a00d")

    def test_release_fixtures(self):
        if not all((ROOT / (name + ".exe")).exists() for name in ("dbgtest", "test_real", "BopIt")):
            self.skipTest("optional local executable fixtures unavailable")
        for name, size in (("dbgtest", 65), ("test_real", 1102), ("BopIt", 183997)):
            with self.subTest(name=name):
                info, stream = extract.extract(ROOT / (name + ".exe"))
                self.assertEqual(len(info.bytecode), size)
                self.assertEqual(info.plugins, [])
                self.assertGreater(len(stream), size)
        source = decompile_module(load_any(str(ROOT / "dbgtest.exe")))
        self.assertIn("wait(600000);", source)

    def test_repository_package(self):
        stub = owned_pe_stub()
        stream = b"test stream" * 100
        packaged = extract.package(stub, stream)
        self.assertEqual(extract.decrypt(extract.get_payload(packaged)), stream)

    def test_corrupted_release_rejected(self):
        payload = extract.encrypt_official(b"owned corrupt-payload fixture")
        damaged = payload[:-1] + bytes([payload[-1] ^ 1])
        with self.assertRaises(ValueError):
            extract.decrypt(damaged)


class RendererTests(unittest.TestCase):
    def test_bopit_reader(self):
        if not (ROOT / "BopIt.exe").exists():
            self.skipTest("optional BopIt executable unavailable")
        module = load_any(str(ROOT / "BopIt.exe"))
        self.assertEqual(len(module.classes), 17)
        self.assertEqual(len(module.enums), 6)
        self.assertEqual(module.enums[0].enum_values[:3],
                         [("clipboard_flag_copy", 1), ("clipboard_flag_cut", 2), ("clipboard_flag_paste", 4)])
        self.assertTrue(any(c.is_interface for c in module.classes))
        self.assertTrue(any(c.is_shared for c in module.classes))
        self.assertTrue(module.funcdefs)

    def test_bopit_core_vm_operations_are_lifted(self):
        if not (ROOT / "BopIt.exe").exists():
            self.skipTest("optional BopIt executable unavailable")
        source = decompile_module(load_any(str(ROOT / "BopIt.exe")))
        for opcode in ("WRTV1", "CmpPtr", "LDG", "LoadRObjR", "LoadVObjR",
                       "CallPtr", "DECi", "COPY"):
            self.assertNotIn(f"// {opcode} (unhandled)", source)

    def test_debug_corpus_recompiles(self):
        compiler = ROOT / "build/bcdump.exe"
        if not compiler.exists():
            self.skipTest("bcdump test compiler unavailable")
        # These are the original eight debug-enabled fixtures, not release output.
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as folder:
            for name in ("arg", "calls", "copy", "def", "hello", "min", "patterns", "real", "str"):
                with self.subTest(name=name):
                    bytecode = Path(folder) / f"original_{name}.bin"
                    first = subprocess.run([str(compiler), str(ROOT / f"test_{name}.as"), str(bytecode)],
                                           capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
                    self.assertEqual(first.returncode, 0, first.stderr)
                    source = decompile_module(load_any(str(bytecode)))
                    path = Path(folder) / (name + ".as")
                    path.write_text(source, encoding="utf-8")
                    result = subprocess.run([str(compiler), str(path), str(path.with_suffix(".bin"))],
                                            capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_stripped_control_flow_and_recompile(self):
        compiler = ROOT / "build/bcdump.exe"
        if not compiler.exists():
            self.skipTest("bcdump test compiler unavailable")
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as folder:
            bytecode = Path(folder) / "original.bin"
            first = subprocess.run([str(compiler), str(ROOT / "test_real.as"), str(bytecode), "--strip"],
                                   capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
            self.assertEqual(first.returncode, 0, first.stderr)
            source = decompile_module(load_any(str(bytecode)))
            self.assertIn("bool alive() const", source)
            self.assertIn("return (health > 0);", source)
            self.assertIn("while (local_1.alive() && (local_5 < 10))", source)
            path = Path(folder) / "stripped.as"
            path.write_text(source, encoding="utf-8")
            result = subprocess.run([str(compiler), str(path), str(path.with_suffix(".bin"))],
                                    capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_official_stripped_fixture_recompiles(self):
        if not (ROOT / "test_real.exe").exists() or not (ROOT / "build/bcdump.exe").exists():
            self.skipTest("optional official fixture/compiler unavailable")
        source = decompile_module(load_any(str(ROOT / "test_real.exe")))
        self.assertNotIn("tmp26", source)
        compiler = ROOT / "build/bcdump.exe"
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as folder:
            path = Path(folder) / "official.as"
            path.write_text(source, encoding="utf-8")
            result = subprocess.run([str(compiler), str(path), str(path.with_suffix(".bin"))],
                                    capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()


class BaseMethodCallTests(unittest.TestCase):
    """A base class's method, called through `this`, recurses forever.

    Paladin's `class person : interact` opens its override with
    `interact::reset();`. Rendered as `this.reset();` that is unbounded
    recursion -- starting a new game died with `Stack overflow` after 10,000
    frames of `person::reset` -- and the project reported 0 residual gotos, a
    verified split and `compiled cleanly` throughout. 62 sites in one title.
    """

    def _sim(self, here, fn_name="reset"):
        from decompile import FuncDecompiler, Function
        sim = object.__new__(FuncDecompiler)
        sim.fn = Function(name=fn_name, object_type=here)
        return sim

    @staticmethod
    def _cls(name, methods=(), base=None):
        from decompile import Function, TypeInfo
        return TypeInfo(name=name, derived_from=base,
                        methods=[Function(name=m) for m in methods])

    def test_an_ancestors_method_is_qualified_and_an_own_one_is_not(self):
        base = self._cls("interact", ["reset", "act", "is_inside"])
        here = self._cls("person", ["reset", "act"], base=base)
        sim = self._sim(here)

        # the base's `reset`, which this class overrides -> say the base
        self.assertTrue(sim._calls_a_base_method("interact", "reset"))
        # this class's own -> `this.reset()` is right, and qualifying it
        # would be the recursion all over again
        self.assertFalse(sim._calls_a_base_method("person", "reset"))
        # a name this class does not declare: the unqualified call already
        # reaches the base's one, so there is nothing to say
        self.assertFalse(sim._calls_a_base_method("interact", "is_inside"))
        # an unrelated class is not an ancestor
        self.assertFalse(sim._calls_a_base_method("sound_pool", "reset"))
        # no owner at all (a bare name) must not be qualified into `::reset`
        self.assertFalse(sim._calls_a_base_method("", "reset"))

    def test_only_derived_from_is_walked_so_an_interface_is_never_pinned(self):
        """That is what makes this safe without reading the opcode.

        An interface's methods are reached through `interfaces`, never the
        `derived_from` chain, so an interface dispatch cannot match here and
        cannot be pinned to a base by mistake. Gating on the opcode instead
        was tried and is not equivalent: it kept `person::reset` qualified
        while letting `clock::reset` fall back to `this.reset()`, because the
        resolved callee is not reported the same way at every call site.
        """
        from decompile import Function, TypeInfo
        iface = TypeInfo(name="speaker", is_interface=True,
                         methods=[Function(name="speak")])
        here = self._cls("person", ["speak"])
        here.interfaces = [iface]
        sim = self._sim(here, fn_name="speak")
        self.assertFalse(sim._calls_a_base_method("speaker", "speak"))

    def test_a_grandparent_counts(self):
        """The chain is walked, not just the immediate base, and a cycle in it
        terminates rather than hanging the decompiler."""
        top = self._cls("thing", ["reset"])
        mid = self._cls("interact", ["reset"], base=top)
        here = self._cls("person", ["reset"], base=mid)
        sim = self._sim(here)
        self.assertTrue(sim._calls_a_base_method("thing", "reset"))
        self.assertTrue(sim._calls_a_base_method("interact", "reset"))
        top.derived_from = here          # a cycle must not loop forever
        self.assertFalse(sim._calls_a_base_method("nowhere", "reset"))


class SwitchDefaultTests(unittest.TestCase):
    """The entry the gaps share is not always the default.

    `_dense_table` took the default to be the most common target in the jump
    table, on the argument that the compiler fills a range's gaps with the
    default label. That is true, and bounded: `asCCompiler::
    CompileSwitchStatement` starts a new table when
    `values[n-1] + 5 < values[n]`, so a run of filler is at most four -- a
    prediction the corpus confirms, with 4 reached in two titles and never
    exceeded across 82 tables.

    But several case labels stacked on one body put that arm in the table as
    many times, and nothing stops a real case outnumbering the gaps:

        case 1: case 2: case 3: speak("..."); break;

    Where a switch is a single table there is no next range to be sent to,
    so every guard jumps to the same place and *that* is the default, said
    outright instead of counted. Manamon 2 has two of these; `ms_davidson`
    has the table `[38, 45, 45, 52, 59, 66, 144]` with the default at 0x95,
    which is not in the table at all -- counted, the default became the arm
    two cases share, `case 2` and `case 3` vanished, and a `break` landed in
    the wrong arm. It compiles, it runs, and a dialogue function answers the
    wrong line.
    """

    def _sim(self, instrs):
        from decompile import FuncDecompiler
        sim = object.__new__(FuncDecompiler)
        sim.instrs = instrs
        sim.pos_of = {i.pos: k for k, i in enumerate(instrs)}
        return sim

    @staticmethod
    def _op(name, pos, w_arg=0, w_arg2=0, dw_arg=0, jump_target=None):
        return Instr(pos=pos, op=0, name=name, bc_type="", size=1,
                     w_arg=w_arg, w_arg2=w_arg2, dw_arg=dw_arg,
                     jump_target=jump_target)

    def _table(self, targets, guard_target):
        #   CMPIi v1, hi ; JP out ; CMPIi v1, lo ; JS out ; SUBIi v2,v1,1
        #   JMPP v2 ; JMP t0 ; JMP t1 ; ...
        op = self._op
        instrs = [
            op("CMPIi", 0, w_arg=1, dw_arg=len(targets)),
            op("JP", 1, jump_target=guard_target),
            op("CMPIi", 2, w_arg=1, dw_arg=1),
            op("JS", 3, jump_target=guard_target),
            op("SUBIi", 4, w_arg=2, w_arg2=1, dw_arg=1),
            op("JMPP", 5, w_arg=2),
        ]
        instrs += [op("JMP", 6 + i, jump_target=t)
                   for i, t in enumerate(targets)]
        return instrs

    def test_the_guards_name_the_default_when_they_agree(self):
        # `case 2:` and `case 3:` share one arm, so it appears twice while
        # the real default -- where both guards go -- appears not at all.
        instrs = self._table([38, 45, 45, 52, 59, 66, 144], guard_target=0x95)
        sim = self._sim(instrs)
        _, cases, default, _, _ = sim._dense_table(5)
        self.assertEqual(default, 0x95)
        self.assertEqual([value for value, _ in cases],
                         [1, 2, 3, 4, 5, 6, 7])
        self.assertEqual(dict(cases)[2], dict(cases)[3])

    def test_counting_still_answers_when_the_guards_disagree(self):
        # A link in a chain: its own high bound sends larger values to the
        # next range, so the guards differ and the gaps are the evidence
        # left. 0x40 is both the repeated entry and the right answer.
        instrs = self._table([0x30, 0x40, 0x40, 0x50], guard_target=0x99)
        instrs[1] = self._op("JP", 1, jump_target=0x77)     # -> next range
        sim = self._sim(instrs)
        _, cases, default, _, next_range = sim._dense_table(5)
        self.assertEqual(default, 0x40)
        self.assertEqual(cases, [(1, 0x30), (4, 0x50)])


class DiscardedCallTests(unittest.TestCase):
    """A call whose result nothing reads still ran.

    `_bind` parks a value in `temps[off]` and emits nothing, on the
    assumption that a later read will fold it in. A call that nothing reads
    has no such read, so the call itself disappears -- and a call is not a
    value, it is something the program did.

    BGT ships the proof. Stock `form.bgt` opens `create_window` with

        if(!active)
        {
        get_characters();
        }

    where `get_characters` returns a string nobody wants, because the point
    of calling it is to drain the keyboard buffer. Recovered, that came out
    as `if (!active) { }` -- so a recovered form never drains the buffer and
    stale keystrokes leak into the first field. Same shape in Psycho
    Strike's `character::find_target`, which ends
    `CALLINTF set_target_x ; LOADOBJ 8 ; RET` and lost the setter, and in
    `create_character`, which ends `CALL create_person ; LOADOBJ 1 ; RET`.

    Two of the four ends of a temp's life were handled (`FREE`, and the
    value register when a void function returns); these are the other two.
    Both were measured against BGT's own shipped library source before being
    kept, and the two that were *not* kept are recorded in the source beside
    them: flushing at every rebind emitted each intermediate of a built-up
    expression as its own statement, and sweeping the leftover temps at the
    end of a body emitted calls that had been consumed inside a loop.
    """

    def test_only_the_value_register_return_may_discard_a_pending_call(self):
        """`return` writes the pending call only when it returns that register.

        The other three return forms -- an out-reference, the *object*
        register, and the hidden return slot -- have nothing to do with the
        value register, so a call left pending there is an unrelated one
        that merely happened to run last. Discarding it unconditionally is
        what lost `set_target_x` and `create_person`.
        """
        import inspect
        from decompile import FuncDecompiler
        source = inspect.getsource(FuncDecompiler.step)
        ret = source[source.index('if name == "RET":'):]
        ret = ret[:ret.index("self.stack.clear()")]
        # The flag is set in exactly one branch: the one that writes the
        # register's value into the `return`.
        self.assertEqual(ret.count("returned_the_register = True"), 1)
        self.assertIn("value = self._normalize_arg(self.value_reg", ret)
        # ...and every other path flushes rather than drops.
        self.assertIn("if returned_the_register:", ret)
        self.assertIn("self._flush_pending_call()", ret)
        self.assertNotIn("self.pending_value_call = None\n            else:", ret)

    def test_a_destructor_is_not_a_read(self):
        """Destructing a temporary does not count as using it.

        `PSF 2 ; CALLSYS get_characters ; PSF 2 ; CALLSYS $beh2` destroys
        the string the call returned. Popping the receiver is what marks the
        slot consumed, so no later sweep can see that nothing read it.

        **The consumed mark must not be cleared to find out**, which was the
        first attempt: a slot whose value really had been read earlier then
        looked unread too, and every string built by a call was emitted a
        second time. Measured against BGT's shipped `include/`, that cost 20
        of 149 library functions their exact call sequence and 18 their
        exact literals; leaving the mark alone costs none of either.
        """
        import inspect
        from decompile import FuncDecompiler
        source = inspect.getsource(FuncDecompiler)
        branch = source[source.index("if meth in DTORS or meth.startswith"):]
        branch = branch[:branch.index("# A base-class constructor")]
        self.assertIn("self._discarded_call(off)", branch)
        self.assertNotIn("consumed_temps.discard", branch)

    def test_a_rebind_is_not_the_end_of_a_temps_life(self):
        """The two rejected flush points stay rejected, with their reasons.

        Both read as obvious fixes and both make the output worse, so the
        argument lives next to the code rather than in a commit message.
        """
        import inspect
        from decompile import FuncDecompiler
        bind = inspect.getsource(FuncDecompiler._bind)
        self.assertNotIn("self._discarded_call", bind)
        self.assertIn("tried and is wrong", bind)
        run = inspect.getsource(FuncDecompiler.run)
        self.assertNotIn("for off in sorted(self.temps)", run)
        self.assertIn("unsound", run)


class DiamondBindTests(unittest.TestCase):
    """`if (c) { x = A; } else { x = B; } f(x);` is two stores and one read.

    To a linear walk that is indistinguishable from an ordinary
    reassignment, so the read folds whichever arm came second in the
    bytecode. Paladin's `create_room` rendered

        if (arg6 == 14) {
        } else {
        }
        local_1.add_clock(26, 6, -2, -2);

    with both arms empty and the *else* arm's coordinates baked into the
    call, so every layout_2 cabin put its clock where the other layout's
    goes. `create_hallways` lost a pair of door coordinates the same way.
    Those were the only two double-empty `if`s in the title, which is what
    made them findable: an `if` with two empty arms is the signature this
    whole class of bug leaves behind.

    The shape the compiler emits is

        JNZ -> else ; <then: writes x> ; JMP -> join
        else: <... writes x ...> ; join: <the read>

    and the *conditional* jump lands at the first store rather than after
    it, so only the unconditional `JMP` says the second store is skipped.
    """

    @staticmethod
    def _op(name, pos, w_arg=0, jump_target=None):
        return Instr(pos=pos, op=0, name=name, bc_type="", size=1,
                     w_arg=w_arg, jump_target=jump_target)

    def _sim(self, **attrs):
        from decompile import FuncDecompiler
        sim = object.__new__(FuncDecompiler)
        #           JNZ->6   SetV4 x   JMP->10   SetV4 x   <read at 10>
        sim.instrs = [self._op("JNZ", 2, jump_target=6),
                      self._op("SetV4", 4, w_arg=11),
                      self._op("JMP", 5, jump_target=10),
                      self._op("SetV4", 6, w_arg=11),
                      self._op("SUSPEND", 10)]
        sim.pos_of = {i.pos: k for k, i in enumerate(sim.instrs)}
        sim.cond_spans = [(2, 6)]
        sim.jmp_spans = [(5, 10)]
        sim.slot_writes = {11: [4, 6]}
        sim.short_circuit_slots = set()
        # ...of which the OPERAND slots are the ones the fold rules
        # exempt. A real decompiler derives this by taking the merge
        # destinations out; empty here, and a case about it sets it.
        sim.merge_operands = set()
        sim.back_edges = []
        sim.k = 4                                  # reading at pos 10
        for name, value in attrs.items():
            setattr(sim, name, value)
        return sim

    def test_the_second_arm_of_a_diamond_is_conditionally_bound(self):
        sim = self._sim()
        # The else arm's store at 6, read at 10 past the join.
        self.assertTrue(sim._conditionally_bound(6, 11))
        # Without the slot there is nothing to recognise it by, which is the
        # state this was in: the plain conditional span ends *at* 6, not
        # after it, so the old rule saw nothing.
        self.assertFalse(sim._conditionally_bound(6, None))

    def test_a_short_circuit_merge_slot_is_never_a_diamond(self):
        """`(a && b)` has the diamond's exact shape and must not promote.

        Each operand is computed into one slot on mutually exclusive paths
        and read after the join. Promoted, every arm's computation becomes
        an unconditional statement and the terms overwrite each other:
        `(local_13.x < 4) && (local_13.y >= 6)` came out as
        `(local_6 < 4) && (local_6 != 0)`, reading one slot twice. Measured
        against BGT's shipped library, leaving them out is worth 8 of 149
        functions' exact call sequence and 3 of their literals.
        """
        self.assertFalse(
            self._sim(short_circuit_slots={11})._conditionally_bound(6, 11))

    def test_an_ordinary_jump_over_an_assignment_is_not_a_diamond(self):
        """A `break` inside a loop makes a forward `JMP` past a store too.

        Treating every one of those as a diamond is the loose version, and
        it costs the same 8 functions. What a diamond needs is the *other*
        arm writing the same slot, between the conditional jump and the
        `JMP` that skips this one.
        """
        # The then arm writes a different slot, so slot 11 has one store.
        self.assertFalse(self._sim(slot_writes={11: [6], 12: [4]})
                         ._conditionally_bound(6, 11))
        # ...and a conditional jump that does not enter this arm is no help.
        self.assertFalse(self._sim(cond_spans=[(2, 99)])
                         ._conditionally_bound(6, 11))


class VirtualVersusBaseCallTests(unittest.TestCase):
    """`CALL` names one implementation; `CALLINTF` goes through the vftable.

    For a virtual call the module records the class that first *declared* the
    method, not the one that will run, so both kinds arrive looking like a
    call to an ancestor's method:

        door::door    PshVPtr this ; CALL connection::connection
                      PshVPtr this ; CALLINTF interact::reset
        door::reset   PshVPtr this ; CALL connection::reset

    `door()` is `super(); reset();` -- a virtual call that runs
    `door::reset` -- while `door::reset` really is `connection::reset();`.
    Qualified alike, every derived constructor in Paladin came out as
    `super(); interact::reset();`, which runs the base's reset and nothing
    else. `door::reset` is what sets `connection_type = 1`;
    `get_floor_of_residence` looks for exactly that, so no cabin could be
    matched to its floor and starting a new game died with `Index out of
    bounds` on `world[-1]`.

    Of 93 such sites in Paladin, 60 are `CALL` and 33 `CALLINTF`.

    **This file recorded that the opcode was the wrong field to read**, on
    the evidence that gating on it let `clock::reset` fall back to
    `this.reset()` "although both sites disassemble to a plain `CALL`".
    `clock::reset` is a plain `CALL`, so a gate on the opcode keeps it
    qualified -- that conclusion came from an experiment measuring something
    else, and taking it on trust left the bug in place.
    """

    def _sim(self, here_name, base_name, declares):
        from decompile import FuncDecompiler, Function, TypeInfo
        base = TypeInfo(name=base_name, kind="class")
        here = TypeInfo(name=here_name, kind="class", derived_from=base,
                        methods=[Function(name=n) for n in declares])
        sim = object.__new__(FuncDecompiler)
        sim.fn = Function(name="reset", object_type=here)
        return sim

    def test_a_virtual_dispatch_is_not_a_base_call(self):
        sim = self._sim("door", "interact", ["reset"])
        self.assertTrue(sim._calls_a_base_method("interact", "reset", "CALL"))
        self.assertFalse(
            sim._calls_a_base_method("interact", "reset", "CALLINTF"))

    def test_the_other_two_conditions_still_hold(self):
        """The opcode is a third requirement, not a replacement."""
        # The owner must be an ancestor...
        sim = self._sim("door", "interact", ["reset"])
        self.assertFalse(sim._calls_a_base_method("unrelated", "reset", "CALL"))
        # ...and this class must declare the name, or the unqualified call
        # already reaches the base's one and saying so adds nothing.
        bare = self._sim("door", "interact", ["make_noise"])
        self.assertFalse(bare._calls_a_base_method("interact", "reset", "CALL"))
        # ...and a call to this class's own method is never a base call.
        self.assertFalse(sim._calls_a_base_method("door", "reset", "CALL"))

    def test_only_derived_from_is_walked(self):
        """An interface's methods hang off `interfaces`, never this chain, so
        an interface dispatch can never be pinned to a base by mistake."""
        import inspect
        from decompile import FuncDecompiler
        source = inspect.getsource(FuncDecompiler._calls_a_base_method)
        self.assertIn('"derived_from"', source)
        self.assertNotIn("interfaces", source.split('"""')[2])


class BorrowedHandleTests(unittest.TestCase):
    """A handle kept alive for one expression is not a statement.

    `RefCpyV` peeks the stack rather than popping, so the instruction after
    it reads the *stack* copy and never looks at the slot. The slot exists
    only to keep the object alive across that instruction, and `FREE`
    releases it immediately:

        RefCpyV 11 ; CALLSYS opIndex ; RDR4 ; FREE 11

    `objVariableTypes` names every object slot, so that copy was emitted as
    a statement -- and an event sorts by its own bytecode position while a
    branch sorts by the end of its condition, so it landed *ahead* of the
    `if` it belonged inside. `find_walls`

        while (true) { i += 1;
            if (arg2.length() <= i || arg2[i].length() <= j
                || arg2[i][j] == 0 || play_wall_tone(i, j)) ... }

    then indexed before the bounds check guarding it, and *entering* any map
    threw `Index out of bounds` -- `find_walls` always scans out to a wall
    or the edge, and the westward loop reaches `-1` before testing `< 0`.

    **Classifying the slot instead was tried twice and is much worse.**
    Adding every handle written inside a short-circuit arm cost Paladin 477
    lines and scrambled `load_event_flags` (call duplicated, wrong
    dictionary key, `bool` into an `int`); requiring the `FREE` to be in the
    same arm moved that to 447 and nothing else. The measurements are in
    CLAUDE.md. What works is local to the instruction stream.
    """

    #: What each opcode's operands are, in AngelScript's own naming, so the
    #: fixtures feed the production read-set computation rather than a stub
    #: of it. `wW` is a WRITTEN slot and `rW` a read one, which is the whole
    #: distinction the whole-body rule below turns on -- `FREE` releases a
    #: slot and so writes it, while `PshVPtr` and `PSF` read it.
    _SHAPES = {
        "RefCpyV": "asBCTYPE_wW_QW_ARG", "FREE": "asBCTYPE_wW_QW_ARG",
        "RDR4": "asBCTYPE_wW_ARG", "STOREOBJ": "asBCTYPE_wW_ARG",
        "PshVPtr": "asBCTYPE_rW_ARG", "PSF": "asBCTYPE_rW_ARG",
        "VAR": "asBCTYPE_rW_ARG", "LOADOBJ": "asBCTYPE_rW_ARG",
        "CpyVtoV4": "asBCTYPE_wW_rW_ARG",
        # BGT's `CallPtr` takes one word operand, which the reader normalises
        # into `w_arg2` with `w_arg` zeroed so one rule reads both engine
        # generations. So its shape disagrees with where its slot IS.
        "CallPtr": "asBCTYPE_rW_ARG",
        "CALLSYS": "asBCTYPE_DW_ARG", "JZ": "asBCTYPE_DW_ARG",
        "JMP": "asBCTYPE_DW_ARG", "SUSPEND": "asBCTYPE_NO_ARG",
    }

    @classmethod
    def _op(cls, name, pos, w_arg=0, w_arg2=0):
        return Instr(pos=pos, op=0, name=name, size=1, w_arg=w_arg,
                     w_arg2=w_arg2,
                     bc_type=cls._SHAPES.get(name, "asBCTYPE_NO_ARG"))

    def _sim(self, ops, k=0, window=None):
        from decompile import FuncDecompiler, _read_slots
        sim = object.__new__(FuncDecompiler)
        sim.instrs = ops
        sim.k = k
        # Exactly what `__init__` computes, through the real helper: a stub
        # read-set would agree with a wrong one.
        sim.read_slots = _read_slots(ops)
        sim.freed_slots = {i.w_arg for i in ops if i.name == "FREE"}
        if window is not None:
            sim.BORROW_WINDOW = window
        return sim

    def test_a_handle_freed_a_few_instructions_later_is_borrowed(self):
        ops = [self._op("RefCpyV", 0, 11), self._op("CALLSYS", 1),
               self._op("RDR4", 2, 4), self._op("FREE", 3, 11)]
        self.assertTrue(self._sim(ops)._borrowed_handle(11))

    def test_a_slot_read_before_its_free_is_a_real_assignment(self):
        """If something names the slot, it is being used, not borrowed."""
        ops = [self._op("RefCpyV", 0, 11), self._op("PshVPtr", 1, 11),
               self._op("CALLSYS", 2), self._op("FREE", 3, 11)]
        self.assertFalse(self._sim(ops)._borrowed_handle(11))

    def test_a_borrow_may_not_straddle_a_branch(self):
        """Otherwise it could reach a `FREE` belonging to another path.

        The slot has to be read SOMEWHERE for this to be the question: a
        slot nothing reads is not a variable on any path, so the whole-body
        rule answers first and the branch cannot matter. That read is what
        makes the fixture a straddling borrow rather than a dead one -- it
        sits past the window, so only the straddle condition is left to
        decide, which is what this pins.
        """
        ops = [self._op("RefCpyV", 0, 11), self._op("JZ", 1),
               self._op("FREE", 2, 11)] + [
            self._op("SUSPEND", i) for i in range(3, 9)] + [
            self._op("PshVPtr", 9, 11)]
        sim = self._sim(ops)
        self.assertIn(11, sim.read_slots)
        self.assertFalse(sim._borrowed_handle(11))

    def test_a_slot_nothing_reads_is_not_a_variable(self):
        """The whole-body rule, which the window alone could not reach.

        `sound_pool::verify_slot` is the case: BGT's own source indexes
        `items` three times, and the recovery declared a handle for the
        array and emitted `@local_2 = items;` three times while the index
        expression re-read `items` anyway -- 353 such dead assignments in
        50 of Super Egg Hunt's bodies. The `FREE` is eight instructions
        past the bind, so the window declined; nothing reads the slot, so
        this does not.
        """
        ops = [self._op("RefCpyV", 0, 2), self._op("CALLSYS", 1)] + [
            self._op("SUSPEND", i) for i in range(2, 9)] + [
            self._op("FREE", 9, 2)]
        sim = self._sim(ops)
        self.assertNotIn(2, sim.read_slots)
        self.assertTrue(sim._borrowed_handle(2))

    def test_a_slot_read_anywhere_still_goes_to_the_window(self):
        """Slots are REUSED, so "read nowhere" is a whole-body property.

        A slot the source does name elsewhere is read, so the whole-body
        rule says no about it -- and the window then decides this bind on
        its own, which is what keeps the measured narrowness.
        """
        ops = [self._op("RefCpyV", 0, 2), self._op("CALLSYS", 1)] + [
            self._op("SUSPEND", i) for i in range(2, 9)] + [
            self._op("FREE", 9, 2), self._op("PshVPtr", 10, 2)]
        self.assertFalse(self._sim(ops)._borrowed_handle(2))

    def test_a_slot_nothing_frees_is_not_a_borrow_either(self):
        """A handle the compiler materialised is always released."""
        ops = [self._op("RefCpyV", 0, 2)] + [
            self._op("SUSPEND", i) for i in range(1, 12)]
        sim = self._sim(ops)
        self.assertNotIn(2, sim.read_slots)
        self.assertFalse(sim._borrowed_handle(2))

    def test_FREE_is_a_write_and_PshVPtr_a_read(self):
        """The one distinction the whole-body rule turns on, pinned.

        Releasing a slot is not a use of its value, so a slot that is only
        ever bound and freed is read nowhere. Were `FREE` counted as a read
        -- which its operand being the slot makes tempting -- the rule
        would never fire at all, silently.
        """
        from decompile import _read_slots
        self.assertEqual(_read_slots([self._op("FREE", 0, 7)]), set())
        self.assertEqual(_read_slots([self._op("RefCpyV", 0, 7)]), set())
        self.assertEqual(_read_slots([self._op("PshVPtr", 0, 7)]), {7})
        self.assertEqual(_read_slots([self._op("CpyVtoV4", 0, 3, 7)]), {7})

    def test_CallPtr_reads_the_slot_the_READER_put_it_in(self):
        """The one opcode whose operands are not where `bc_type` says.

        BGT gives `CallPtr` a single word operand and the reader normalises
        it into `w_arg2`, zeroing `w_arg`, so one rule downstream can read
        both engine generations. Parsed generically that marks slot 0 as
        read -- usually `this`, so harmless -- and MISSES the funcdef slot,
        which is the half that matters: a bind to it would look unread and
        be folded away. Paladin's `final_heaven_scene` and `father_hologram`
        are the two sites in the corpus.
        """
        from decompile import _read_slots
        call = self._op("CallPtr", 0, w_arg=0, w_arg2=10)
        self.assertEqual(_read_slots([call]), {10})

    def test_a_slot_never_freed_nearby_is_a_real_assignment(self):
        ops = [self._op("RefCpyV", 0, 11)] + [
            self._op("SUSPEND", i) for i in range(1, 12)]
        self.assertFalse(self._sim(ops)._borrowed_handle(11))

    def test_the_window_is_small_on_purpose(self):
        """The pair brackets ONE subexpression. `find_walls` frees three
        instructions later; a wider window reaches past the expression and
        removed a further thousand lines of Paladin for no extra fix."""
        from decompile import FuncDecompiler
        self.assertLessEqual(FuncDecompiler.BORROW_WINDOW, 4)


class MergeOnAFreeTests(unittest.TestCase):
    """A handle release can sit on the merge point and says nothing about it.

    `interact_in_location` is a ten-term `&&`, and its last operand lands on
    `FREE 4` -- the chain borrowed an array element and the compiler released
    it exactly there -- while every earlier merge in the same chain lands
    straight on its `CpyVtoR4`:

        0x13C CpyVtoV4 v8 <- v7
        0x13E FREE 4            <- the jump target
        0x140 CpyVtoR4 v8       <- the merge

    Declining that merge detached the final operand from the chain, and the
    `return true` went with it. The recovered test became

        if (current_map.interacts[i].type != 16) { return true; }

    so every interact that is not type 16 blocked the player in every
    direction from the moment a map was entered -- the bump sound and no
    movement. The other nine terms, `is_solid` among them, were emitted as
    an `if` with two empty arms and dropped on the floor.

    `merge` is only ever used as a lower bound on position, so the recorded
    position stays the jump target; only the instruction the *shape* is read
    from moves past the release.
    """

    def test_the_shape_is_read_past_a_release_but_the_position_is_not(self):
        import inspect
        from decompile import FuncDecompiler
        source = inspect.getsource(FuncDecompiler._begin_bool_merge)
        self.assertIn('("FREE", "SUSPEND")', source)
        # The recorded merge position is still the jump target...
        self.assertIn("finish_pos = merge_pos", source)
        # ...and the shape is read from the instruction found past it.
        self.assertIn("merge_ins = self.instrs[shape_idx]", source)

    def test_the_arm_range_still_ends_at_the_jump_target(self):
        """The ternary-versus-`&&` test counts the instructions in the other
        arm, and a release swept into that range would stop it firing."""
        import inspect
        from decompile import FuncDecompiler
        source = inspect.getsource(FuncDecompiler._begin_bool_merge)
        arm = source[source.index("other_start ="):source.index("finish_pos =")]
        self.assertIn("self.instrs[other_start:merge_idx]", arm)
        self.assertNotIn("shape_idx", arm)


class BoolSlotIntegerConstantTests(unittest.TestCase):
    """A bool-typed slot destroys an integer constant, not just a float one.

    BGT records no scalar local, so `slot_types` infers one from the opcodes
    that *compute* with a slot -- and a slot the program only ever stores
    into has none, so it reads as bool. `_typed_constant` then renders any
    non-zero constant in it as `true`, and `true` assigned to an `int`
    member is **1**.

    `_stored_constant_types` exists for exactly this and was written for
    `pool.pan_step = 1.5`, so it only accepted a *float or double*
    destination. The integer case is far worse and went uncorrected.
    Paladin's `drunken_bert` introduces a party member with

        SetV4 v1, 20 ; LoadRObjR v7 ; WRTV4 v1
        SetV4 v2, 12 ; LoadRObjR v7 ; WRTV4 v2
        SetV4 v2, 80 ; LoadRObjR v7 ; WRTV4 v2

    over two slots the compiler reuses, and all seven of that character's
    stats came out as `1`: `strength = 1`, `av_damage = 1`,
    **`max_health = 1`**. The recovered game reached its tutorial battle,
    dealt one damage and died to one hit. It compiled, it ran, and every
    number in it was wrong the same way -- which is this file's worst
    failure shape, and it took a player to find it.

    Correcting it changes 92 constants across 6 of Paladin's files and
    nothing else: the line count is identical, `libcheck` is unchanged at
    144/149 and 148/149, and Super Egg Hunt and Psycho Strike render as
    before.
    """

    @staticmethod
    def _op(name, pos, w_arg=0, dw_arg=0, prop_name=None):
        return Instr(pos=pos, op=0, name=name, bc_type="", size=1,
                     w_arg=w_arg, dw_arg=dw_arg, prop_name=prop_name)

    def _sim(self, member_type, slot_type):
        from decompile import FuncDecompiler, DataType
        sim = object.__new__(FuncDecompiler)
        sim.instrs = [self._op("SetV4", 0, w_arg=2, dw_arg=80),
                      self._op("LoadRObjR", 2, w_arg=7, prop_name="max_health"),
                      self._op("WRTV4", 5, w_arg=2)]
        sim.var_types = {2: slot_type}
        sim.property_types = {"max_health": member_type}
        sim.global_types = {}
        return sim

    def test_an_int_member_settles_a_constant_in_a_bool_slot(self):
        from decompile import DataType
        sim = self._sim(DataType(token_type=70),      # int
                        DataType(token_type=67))      # the slot reads as bool
        typed = sim._stored_constant_types()
        self.assertIn(0, typed, "the store should be typed from the member")
        self.assertEqual(typed[0].token_type, 70)
        # ...and the constant then renders as itself rather than `true`.
        self.assertEqual(sim._typed_constant(80, typed[0]).text, "80")
        self.assertEqual(sim._typed_constant(80, DataType(token_type=67)).text,
                         "true")

    def test_the_float_case_it_was_written_for_still_works(self):
        from decompile import DataType
        sim = self._sim(DataType(token_type=81),      # float
                        DataType(token_type=67))
        self.assertIn(0, sim._stored_constant_types())

    def test_a_slot_already_typed_numeric_is_left_alone(self):
        """The slot's own type wins when the bytecode actually computed with
        it; this rule only speaks for a slot that has no evidence of its own."""
        from decompile import DataType
        sim = self._sim(DataType(token_type=70), DataType(token_type=70))
        self.assertEqual(sim._stored_constant_types(), {})

    def test_a_bool_member_is_not_overridden(self):
        """A genuinely boolean member keeps `true`/`false`."""
        from decompile import DataType
        sim = self._sim(DataType(token_type=67), DataType(token_type=67))
        self.assertEqual(sim._stored_constant_types(), {})

class LostCallTests(unittest.TestCase):
    """A call whose result nothing reads is still something the program did.

    Dropping an expression nothing reads is behaviour-preserving only while
    the expression is PURE. Manamon 1's `sound_pool_item::load_sound` writes
    a `bool` the original never reads, so the store was dropped -- and
    `handle.load(filename)` went with it, which is a recovered sound pool
    that loads nothing at all. It compiles, it runs, and no count moves.

    The first attempt asked `fold_reads` whether the bind had been read.
    That counter is incremented in one read path of several, so "no entry"
    meant "not read through that path" and most of a body's call binds
    qualified: 7,627 changed lines on Paladin and Psycho Strike's residual
    gotos 2 -> 4. What is asked instead is whether the call's text reached
    any statement, which is the thing itself and cannot be incomplete.
    """

    class _Ev:
        def __init__(self, text):
            self.data = ("", text)

    def _fd(self, binds):
        from decompile import FuncDecompiler
        fd = object.__new__(FuncDecompiler)
        fd.call_binds = binds
        return fd

    def test_a_call_whose_text_reaches_no_statement_is_lost(self):
        from decompile import _lost_calls
        fd = self._fd([(23, "handle.load(local_3)")])
        lost = _lost_calls(fd, [self._Ev("local_3 = filename;")])
        self.assertEqual(lost, [(23, "handle.load(local_3)")])

    def test_a_call_folded_into_a_statement_is_not_lost(self):
        """The fold is the normal case and must not be reported: the call is
        in the output, inside the expression that reads it."""
        from decompile import _lost_calls
        fd = self._fd([(23, "handle.load(local_3)")])
        lost = _lost_calls(fd, [self._Ev("local_1 = handle.load(local_3);")])
        self.assertEqual(lost, [])

    def test_two_binds_of_ONE_call_are_reported_once(self):
        """`CpyRtoV4` parks the result in the slot the register left it in and
        `CpyVtoV4` copies it into the slot a dead local owns. That is two
        binds of one call, and emitting both would be the duplication this
        project counts as a correctness defect."""
        from decompile import _lost_calls
        fd = self._fd([(23, "bump()"), (23, "bump()")])
        self.assertEqual(_lost_calls(fd, []), [(23, "bump()")])

    def test_two_calls_that_READ_ALIKE_are_two_calls(self):
        """Deduplicating by text instead would collapse them -- and
        `load_sound` is exactly this shape, one call in each arm of an `if`,
        which is also why an end-of-body sweep cannot find them: by `RET` the
        slot holds whichever arm ran last."""
        from decompile import _lost_calls
        fd = self._fd([(23, "bump()"), (46, "bump()")])
        self.assertEqual(_lost_calls(fd, []),
                         [(23, "bump()"), (46, "bump()")])

    def test_a_shared_text_under_reports_rather_than_over_reports(self):
        """Where two calls read alike and only one reached a statement, the
        other is not reported. The test is a substring test over the body, so
        it cannot tell them apart -- and a call wrongly reported would be
        emitted twice, so this is the safe way round."""
        from decompile import _lost_calls
        fd = self._fd([(23, "bump()"), (46, "bump()")])
        self.assertEqual(_lost_calls(fd, [self._Ev("x = bump();")]), [])


class RecordedCallTests(unittest.TestCase):
    """Which calls are watched for being lost, and which are not.

    `Atom("call", ...)` is the kind for any computed expression, so the atom
    cannot answer this: asked of the atom, the census reported `!use_hyper`,
    `false` and `(count - 6)` alongside `handle.load(local_3)` -- 115 rows on
    Super Egg Hunt, which has no lost call at all.
    """

    def _fd(self, pure):
        from decompile import FuncDecompiler

        class _Purity:
            def is_pure_call(self, instr):
                return pure

        fd = object.__new__(FuncDecompiler)
        fd.invocations = {}
        fd.call_sites = {}
        fd.purity = _Purity()
        fd.k, fd.instrs = 0, [None]
        fd._pos = lambda: 7
        return fd

    class _Ret:
        def __init__(self, owner):
            self.obj_type = owner

    class _Named:
        def __init__(self, name):
            self.name = name

    def test_an_impure_call_is_recorded(self):
        fd = self._fd(pure=False)
        fd._record_call(None, "handle.load(local_3)",
                        self._Named("load"), self._Ret(self._Named("bool")))
        self.assertEqual(fd.invocations, {"handle.load(local_3)": 7})
        self.assertEqual(fd.call_sites, {"handle.load(local_3)": 7})

    def test_a_PURE_call_is_not_recorded(self):
        """Crazy Party computes `int(round(double((w - 1) / 2), 0))` twice per
        minigame and reads neither result: `round` is pure and those are the
        original's own dead locals, so putting the call back would add two
        hundred statements that do nothing."""
        fd = self._fd(pure=True)
        fd._record_call(None, "round(double((local_6 / 2)), 0)",
                        self._Named("round"),
                        self._Ret(None))
        self.assertEqual(fd.invocations, {})
        # ...and `call_sites` keeps it, because `_value_origin` asks when a
        # value ran and purity has nothing to do with that.
        self.assertEqual(fd.call_sites,
                         {"round(double((local_6 / 2)), 0)": 7})

    def test_a_class_FACTORY_is_a_construction_not_a_call(self):
        """A member declared by value but held by reference is created by the
        generated `<global>::<class>` factory at the top of every constructor,
        and `_refcpy` already drops the store. Emitting the construction alone
        would hand the new object to nobody."""
        fd = self._fd(pure=False)
        fd._record_call(None, "sound_pool(500)", self._Named("sound_pool"),
                        self._Ret(self._Named("sound_pool")))
        self.assertEqual(fd.invocations, {})


class ClosedBeforeReadTests(unittest.TestCase):
    """A call made for its effect has RUN, and a copy of a value has not.

    `cs`'s file helpers recovered as `close()` before `read()`, which reads
    an empty string -- so that server's every load read nothing. Four
    separate blindnesses had to be closed, and each of them is one of these.
    """

    def _fd(self, **attrs):
        """A decompiler with only the fields these three methods read."""
        from decompile import FuncDecompiler
        fd = object.__new__(FuncDecompiler)
        fd.events, fd.stmt_count, fd.stmt_texts = [], 0, []
        fd.flushed_calls = []
        # Every call this body rendered, which is how a value that really
        # is a call is told from one that merely has the kind:
        # `(registered ? 1 : 0)` is kind "call" too. `invocations` is the
        # impure subset and would miss a pure one like `stn`.
        fd.call_sites = {"local_1.read(0.0)": 25}
        fd.pending_value_call = None
        fd.pending_value_call_pos = 0
        fd.temps, fd.temp_bound = {}, {}
        fd.k, fd.instrs = 0, [None]
        fd._pos = lambda: 40
        for name, value in attrs.items():
            setattr(fd, name, value)
        return fd

    # -- the flush -------------------------------------------------------
    def test_a_flushed_call_is_recorded_by_position(self):
        """`bool file::close() const` is called for its effect, so the call
        is parked and written out later -- and nothing said it had run."""
        fd = self._fd(pending_value_call="local_1.close()",
                      pending_value_call_pos=39)
        fd._flush_pending_call()
        self.assertEqual(fd.flushed_calls, [(39, "local_1.close();")])
        self.assertEqual(fd.events[0].pos, 39)

    def test_counting_the_flush_is_NOT_how_it_is_recorded(self):
        """The counter advances when the statement is written OUT, which is
        later than the position it is written AT -- so counting it made a
        value bound in between look stale when nothing had run, and `main()`
        came out `local_5 = netport;` before a call that could take the
        global. The position was knowable all along."""
        fd = self._fd(pending_value_call="start_profiling()",
                      pending_value_call_pos=3)
        fd._flush_pending_call()
        self.assertEqual(fd.stmt_count, 0)
        self.assertEqual(fd.stmt_texts, [])

    # -- the origin ------------------------------------------------------
    def test_a_calls_origin_survives_a_copy_into_another_slot(self):
        """The copy carries the text, so it must carry the position too.

            PSF 2 ; CALLSYS file::read     ; 25 -- the value
            PSF 4 ; PSF 2 ; opAssign       ; 33 -- string r = f.read();
            PshVPtr ; CALLSYS file::close  ; 39 -- f.close();
            PSF 0 ; PSF 4 ; opAssign       ; 43 -- return r;

        Asked at the `RET` with a bind of 43, the close at 39 was already
        behind it and the read folded past it.
        """
        from decompile import Atom
        a = Atom("call", "local_1.read(0.0)")
        fd = self._fd()
        fd._pos = lambda: 25
        self.assertEqual(fd._value_origin(a), (25, 0))
        fd._pos = lambda: 43
        fd.stmt_count = 4
        self.assertEqual(fd._value_origin(a), (25, 0))

    def test_only_a_CALL_carries_its_origin(self):
        """A constant or a plain variable is the same value at both moments,
        so widening the window for one of those can only make more folds
        look stale without fixing anything."""
        from decompile import Atom
        fd = self._fd()
        fd._pos = lambda: 25
        for kind, text in (("const", "0"), ("var", "local_4"),
                           ("global", "netport"), ("prop", "this.name"),
                           # ...and the trap: this kind is what EVERY
                           # computed expression gets, so the kind alone
                           # reached every bool merge in the corpus.
                           ("call", "(registered ? 1 : 0)")):
            a = Atom(kind, text)
            fd._value_origin(a)
            fd._pos = lambda: 99
            with self.subTest(kind=kind):
                self.assertEqual(fd._value_origin(a), (99, 0))
            fd._pos = lambda: 25

    # -- and the four layers the recorded order named, which are inert --
    def test_the_RETURN_SLOT_layers_were_not_where_the_fix_belonged(self):
        """This file recorded an order to take the file-close bug in:
        *teach the promotion to keep the `return`, then count the flush,
        then* three layers at the return slot -- record its bind position,
        ask `_stale_fold` at the `return`, relax the `off <= 0` exclusion.

        All four were built, and **all four are inert**: with them in, the
        four titles and the server render byte-identical and no
        `__nvgt_retval` appears anywhere in the corpus. The value is copied
        OUT of a slot into the return slot, so the question belongs at that
        slot's own read, which is where `_value_origin` answers it. They are
        removed rather than kept, because one of them relaxes a guard that
        exists to refuse `this` and the frame's negative parameter space.

        What remains is this test, so the next reader starts from the
        measurement instead of the order.
        """
        import decompile
        for name in ("_returned_temp", "_hold_return_value"):
            self.assertFalse(hasattr(decompile.FuncDecompiler, name), name)
        with io.open(decompile.__file__, encoding="utf-8") as fh:
            self.assertIn("if off <= 0:", fh.read())

    # -- and the register, which a Cast used to overwrite --------------
    def test_a_pending_call_is_written_out_before_a_CAST(self):
        """A call whose result nothing reads is parked in the value register,
        and a `Cast` takes its own operand off the STACK -- so the register's
        pending call has nothing to do with it and was simply dropped.

        Manamon 1's `coin::act` is the instance: it moves the coin, calls
        `pool.update_sound_2d(slot, x, y)` without reading the result, and
        then casts its owner to a `coin_collector@`. So **a coin's 2D
        position was never updated as it moved**, and the body came out with
        the call missing entirely.

        `CpyVtoR4`'s handler has flushed for this reason since the
        value-register work -- "preserve its side effect before the register
        is reused" -- and of the 27 places that overwrite that register, 16
        have no flush that reaches them. This is the one with a named
        instance behind it.
        """
        from decompile import Atom
        fd = self._fd(pending_value_call="game.update_sound_2d(slot, x, y)",
                      pending_value_call_pos=120)
        fd.last_set = None
        fd.sparse_switches, fd.dense_switches = {}, {}
        fd.stack = [Atom("var", "owner", 1)]
        fd.value_reg = Atom("raw", "<?reg>")
        fd.list_values = {}
        cast = Instr(pos=130, op=0, name="Cast", bc_type="", size=1)
        cast.type_ref = None
        cast.dw_arg = 7
        fd.instrs = [cast]
        fd.step(cast)
        self.assertEqual(fd.flushed_calls,
                         [(120, "game.update_sound_2d(slot, x, y);")])
        self.assertIsNone(fd.pending_value_call)
        #: ...and the statement lands where the call RAN, not at the cast.
        self.assertEqual(fd.events[0].pos, 120)
        #: the cast itself still happens
        self.assertIn("cast<", fd.value_reg.text)

    # -- the destructor --------------------------------------------------
    def test_destructing_a_slot_is_not_writing_to_it(self):
        """Built from a real module, because this is the PRODUCER side.

        `behaviour_writes` is the record of the writes no opcode names -- an
        object slot filled through a pushed address -- and it was built from
        every `$beh`, the destructor among them. Every object local is
        destructed in the epilogue, so a value copied out of a slot was
        stale at every read past that slot's end of life, and the commonest
        such read is the `return`: `cs`'s `list_members` and six more bodies
        gained a generated local holding `local_1` for nothing.

        `construct_sites` deliberately still counts both. It answers a
        different question -- how many times this slot was constructed, for
        `_reused_object_slot` -- and narrowing it is a separate change with
        a measurement of its own.
        """
        from asreader import Function, Instr, Module
        from decompile import FuncDecompiler

        def ins(name, pos, w=0, fr=None):
            return Instr(pos=pos, op=0, name=name, size=1,
                         bc_type="asBCTYPE_W_ARG", w_arg=w, func_ref=fr)

        def beh(name):
            return Function(name=name, func_type=0, param_types=[])

        body = [ins("PSF", 0, 1), ins("CALLSYS", 1, fr=beh("$beh0")),
                ins("PSF", 2, 1), ins("CALLSYS", 3, fr=beh("$beh2")),
                ins("RET", 4)]
        f = Function(name="probe", func_type=1, param_types=[], bytecode=body)
        fd = FuncDecompiler(Module(global_functions=[f]), f)
        self.assertEqual(fd.behaviour_writes, {1: [0]})
        self.assertEqual(fd.construct_sites, {1: [0, 2]})

    def test_a_destructor_has_more_than_one_spelling(self):
        """The `%delegate_factory`/`$dlgte` lesson: matching one spelling of
        a behaviour matches silently."""
        from decompile import DTORS, _DTOR_SPELLINGS
        self.assertTrue(DTORS <= _DTOR_SPELLINGS)
        for name in ("$beh2", "$beh3", "_beh_2_", "_beh_3_"):
            with self.subTest(name=name):
                self.assertIn(name, _DTOR_SPELLINGS)
        for name in ("$beh0", "_beh_0_", "$beh1", "opAssign"):
            with self.subTest(name=name):
                self.assertNotIn(name, _DTOR_SPELLINGS)


class DeclarationOutranksTheAtomTests(unittest.TestCase):
    """A bool atom that outlived its value, against a numeric declaration.

    One slot serves several source locals, so the atom's type is the type of
    the value the slot was last GIVEN, not the type it is declared with. A
    bare slot name declared `int` must therefore not be wrapped as
    `(local_3 ? 1 : 0)` -- the engine answers "Expression must be of boolean
    type" -- and the declaration is the better witness about a name.

    That branch existed and **crashed every time it was reached**: it read
    `atom.stack_size`, and the field is `dw_size`. The body is given up on
    and counted, so it read as one body the structurer could not shape
    rather than as a typo. On `cs`'s server it was the whole network
    dispatcher -- 119 calls, 218 of them `send` -- and on Paladin it is
    reached as soon as a fold change puts a bool atom in that position.
    """

    def _fd(self):
        from asreader import DataType, Function, Module
        from decompile import FuncDecompiler
        fd = object.__new__(FuncDecompiler)
        fd.m = Module()
        fd.fn = Function(name="probe")
        fd.var_names = {3: "local_3"}
        fd.var_types = {3: DataType(token_type=70)}
        return fd

    def test_a_numeric_declaration_is_kept_rather_than_wrapped(self):
        from asreader import DataType
        from decompile import Atom
        fd = self._fd()
        atom = Atom("var", "local_3", 1, data_type=DataType(token_type=67))
        out = fd._normalize_arg(atom, DataType(token_type=70))
        self.assertEqual(out.text, "local_3")
        self.assertEqual(out.kind, "var")
        self.assertEqual(out.dw_size, 1)

    def test_a_name_with_no_numeric_declaration_is_still_wrapped(self):
        """The other side of the same branch, which always worked."""
        from asreader import DataType
        from decompile import Atom
        fd = self._fd()
        atom = Atom("var", "local_9", 1, data_type=DataType(token_type=67))
        out = fd._normalize_arg(atom, DataType(token_type=70))
        self.assertEqual(out.text, "(local_9 ? 1 : 0)")

    def test_every_atom_field_this_file_names_exists(self):
        """A field name that does not exist raises where it is read, and a
        per-body `except` turns that into a count rather than a traceback."""
        from decompile import Atom
        fields = set(Atom.__dataclass_fields__)
        self.assertIn("dw_size", fields)
        self.assertNotIn("stack_size", fields)


class PushedValueTests(unittest.TestCase):
    """A value already on the stack, and the slot it reads is rewritten.

    The compiler builds each argument of a call through one scratch slot and
    pushes as it goes, so `local_17 = parts[6] ; CALL stn ; push` six times
    leaves six copies of `stn(local_17)` waiting -- and the call renders them
    all with whatever the slot held last. `cs`'s map loader built a safezone
    whose six bounds are one number, and a platform the same, for every map.

    No fold rule could reach it: `_stale_fold` is asked at a READ of a temp,
    and these values are read by the call, which pops them off the simulated
    stack and renders them there.
    """

    def _fd(self, **attrs):
        from decompile import FuncDecompiler
        fd = object.__new__(FuncDecompiler)
        fd.events, fd.stmt_count, fd.stmt_texts = [], 0, []
        fd.stack, fd.slot_values, fd.held_pushed = [], {}, set()
        fd.var_names, fd.var_types = {17: "local_17"}, {}
        fd.declared, fd.temps, fd.temp_bound = set(), {}, {}
        fd.consumed_temps, fd.mixed_boolean_slots = set(), set()
        fd.k, fd.instrs = 0, [None]
        fd._pos = lambda: 264
        fd._order_out_arguments = lambda text: None
        for name, value in attrs.items():
            setattr(fd, name, value)
        return fd

    def test_a_pushed_call_that_reads_the_slot_is_taken_into_a_local(self):
        from decompile import Atom, DataType
        fd = self._fd()
        pushed = Atom("call", "stn(local_17)", 1, data_type=DataType())
        fd.stack.append(pushed)
        fd._snapshot_pushed(17)
        self.assertEqual(fd.stack[0].kind, "var")
        self.assertTrue(fd.stack[0].text.startswith("__nvgt_held_17_"))
        self.assertEqual(len(fd.events), 1)
        self.assertIn("= stn(local_17);", fd.events[0].data[1])

    def test_a_pushed_value_that_does_not_read_the_slot_is_left_alone(self):
        from decompile import Atom, DataType
        fd = self._fd()
        for atom in (Atom("const", "7", 1),
                     Atom("call", "stn(local_9)", 1, data_type=DataType()),
                     Atom("var", "local_4", 1, data_type=DataType())):
            fd.stack = [atom]
            fd._snapshot_pushed(17)
            with self.subTest(text=atom.text):
                self.assertIs(fd.stack[0], atom)
        self.assertEqual(fd.events, [])

    def test_a_pushed_value_with_no_known_type_is_left_alone(self):
        """An undeclared name does not compile at all, where a stale read
        does -- so a value this cannot declare is not held."""
        from decompile import Atom
        fd = self._fd()
        pushed = Atom("call", "stn(local_17)", 1)      # no data_type
        fd.stack.append(pushed)
        fd._snapshot_pushed(17)
        self.assertIs(fd.stack[0], pushed)
        self.assertEqual(fd.events, [])

    def test_a_pushed_value_that_IS_the_slot_takes_what_the_slot_held(self):
        """...and the recursion is free: if THAT slot is written while this
        value still waits, the same rule fires again."""
        from decompile import Atom, DataType
        fd = self._fd()
        fd.slot_values = {17: Atom("var", "local_4", 1,
                                   data_type=DataType())}
        fd.stack.append(Atom("var", "local_17", 1, data_type=DataType()))
        fd._snapshot_pushed(17)
        self.assertEqual(fd.stack[0].text, "local_4")
        self.assertEqual(fd.events, [])


class SignedComparisonTests(unittest.TestCase):
    """`uint > -1` can never pass, and the original compared it signed.

    One slot serves several source locals, so a slot may carry a `uint` loop
    counter *and* a signed index, and only one of them can be the
    declaration. BGT was asked rather than assumed, with a script that writes
    its answers to a file:

        uint  b = 5;    b > -1       FALSE
        int   s = 5;    s > -1       TRUE
        uint8 c = 200;  c > -1       FALSE
        int8(c) > -1                 FALSE
        int(c)  > -1                 TRUE

    -- the signed literal converts to unsigned, even for a one-byte type, and
    the engine says so with `Implicit conversion changed sign of value`. That
    warning also stops an unattended compile at its modal dialog.

    `cs`'s server is the instance, in ground-truth code:
    `int b = get_base_index(map); if (b > -1)` shares slot 2 with the `uint i`
    of the loop above it, so **the vault dispenser report could never run.**
    16 sites in that one artefact, and 1 in Psycho Strike.
    """

    def _fd(self, slot_type, atom_type=None):
        from decompile import Atom, DataType, FuncDecompiler, NUMERIC_TYPES
        fd = object.__new__(FuncDecompiler)
        fd.var_types = {4: DataType(token_type=NUMERIC_TYPES[slot_type])}
        dt = (DataType(token_type=NUMERIC_TYPES[atom_type])
              if atom_type else fd.var_types[4])
        return fd, Atom("var", "local_4", 1, data_type=dt)

    def test_an_unsigned_slot_compared_signed_gets_a_cast(self):
        fd, atom = self._fd("u")
        self.assertEqual(fd._as_signed(atom, 4, "CMPIi").text, "int(local_4)")

    def test_the_cast_is_the_COMPARISONS_width_not_the_slots_sibling(self):
        """A `uint8` slot holds its value zero-extended in four bytes, so
        `CMPIi` sees 0..255 -- but `int8(200)` is -56, so a width-matched cast
        answers the opposite of what the original computes. The
        narrow-sibling mapping was written first and the engine refuted it.
        """
        from asreader import TT_UINT8
        fd, atom = self._fd("u")
        fd.var_types[4].token_type = TT_UINT8
        self.assertEqual(fd._as_signed(atom, 4, "CMPIi").text, "int(local_4)")
        self.assertEqual(fd._as_signed(atom, 4, "CMPIi64").text,
                         "int64(local_4)")

    def test_a_signed_slot_is_left_alone(self):
        fd, atom = self._fd("i")
        self.assertIs(fd._as_signed(atom, 4, "CMPIi"), atom)

    def test_a_value_whose_OWN_type_is_signed_needs_nothing(self):
        """The slot is `uint` for another local's sake and what is in it here
        is, say, `array<T>::find`'s `int`. Psycho Strike had three sites of
        this shape -- `weapon::ammunition` is a plain `int` -- and casting
        them was harmless noise."""
        fd, atom = self._fd("u", atom_type="i")
        self.assertIs(fd._as_signed(atom, 4, "CMPIi"), atom)

    def test_an_unknown_slot_is_left_alone(self):
        from decompile import FuncDecompiler, Atom
        fd = object.__new__(FuncDecompiler)
        fd.var_types = {}
        atom = Atom("var", "local_4", 1)
        self.assertIs(fd._as_signed(atom, 4, "CMPIi"), atom)
