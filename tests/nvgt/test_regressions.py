"""Run with python -m unittest -v test_regressions."""
from pathlib import Path
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
    def test_a_repeatable_value_bound_on_one_path_is_promoted_too(self):
        """The rule is about the PATH, not about the kind of value.

        `_stale_fold` tested `value.kind == "const"` before consulting
        `_conditionally_bound`, so a parameter copy never reached it:
        `dynamic_menu::run_extended` opens with
        `bool initial = auto_speak_first;` and clears it at five sites once
        the first item has been announced. A parameter is repeatable, so the
        fold took it first, every read became `arg3` -- which never changes --
        and all five `initial = false;` stores went with it. The block then
        re-armed `speak_item` every iteration: arrow to an item, stop, and the
        menu says its name again and again, forever.
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
        # A computed value is still left alone here -- promoting those is a
        # different question (duplication, not a dead branch) and took Paladin
        # from 0 compiler errors to 16.
        call = Atom("call", "menu.run_extended(x)",
                    data_type=DataType(token_type=70))
        self.assertFalse(sim_for(call)._stale_fold(7))
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
