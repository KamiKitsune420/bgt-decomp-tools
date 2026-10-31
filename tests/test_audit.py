"""
Known-answer tests for `bgt audit` -- the bytecode-against-text audits.

Synthetic inputs only, no game files and no engine, so these run anywhere. The
module they cover is an instrument, and an instrument is worth exactly what its
calibration is worth, so these target the three ways a comparison can be wrong
while reading perfectly:

  * **An escape compared against the byte it escapes.** The recovery writes a
    byte above 0x7F as `\\xNN`, so a naive comparison measures spelling. The
    unescaper is checked against all 256 byte values, and -- as
    `tests/nvgt/test_regressions.LiteralRenderingTests` insists -- against a
    renderer written here from the documented rule rather than imported, so an
    inverse built from a wrong table cannot agree with itself.
  * **A number compared as a string.** `-100.0` and `-100` are one constant.
  * **One reading of a bit pattern taken for the only one.** A one-byte `255`
    is `-1` where the source wrote `this.walk(-1, false)`; and the opposite
    error, offering the narrow reading for a wide store, is what lets a lost
    constant find a match and go unreported.

And then the measurement in the other direction, which is the point: three
defects are injected into a synthetic recovered project -- a dropped literal, a
constant flattened to 1, a deleted call -- and each has to come back. A check
that reports nothing on a clean tree cannot be told from one that is blind.

Run:  python tests/test_audit.py      (or: python -m pytest tests/ -q)
"""

import os
import shutil
import struct
import sys
import tempfile
import unittest

try:                                   # after `pip install -e .`
    from bgtdecomp import as_disasm, as_write, bgt_audit
except ImportError:                    # straight from a checkout
    TOOLS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools")
    sys.path.insert(0, TOOLS)
    import as_disasm
    import as_write
    import bgt_audit


# --------------------------------------------------------------------------
# rule one: an escape is not the byte it escapes
# --------------------------------------------------------------------------

class UnescapeTests(unittest.TestCase):
    """`unescape` reads a rendered literal back as the engine's lexer would."""

    #: The rendering rule, written here from what the recovery DOCUMENTS it
    #: does -- bytes that are not printable ASCII become `\xNN`, the five
    #: specials are escaped, everything else stands -- rather than imported
    #: from the renderer. An inverse built from the renderer's own table would
    #: agree with a wrong table, which is the whole reason this test exists.
    ESCAPES = {0x5C: "\\\\", 0x22: '\\"', 0x0A: "\\n", 0x0D: "\\r", 0x09: "\\t"}

    @classmethod
    def render(cls, raw):
        out = []
        for byte in raw:
            if byte in cls.ESCAPES:
                out.append(cls.ESCAPES[byte])
            elif 0x20 <= byte < 0x7F:
                out.append(chr(byte))
            else:
                out.append("\\x%02x" % byte)
        return "".join(out)

    def test_every_byte_there_is_round_trips(self):
        raw = bytes(range(256))
        rendered = self.render(raw)
        # The project file is written UTF-8, so that is the encoding the
        # engine's bytes really come from.
        self.assertEqual(bgt_audit.unescape(rendered.encode("utf-8")
                                            .decode("utf-8")), raw)

    def test_each_byte_on_its_own(self):
        for value in range(256):
            raw = bytes([value])
            with self.subTest(value=value):
                self.assertEqual(bgt_audit.unescape(self.render(raw)), raw)

    def test_the_aes_blob_that_broke_super_egg_hunt(self):
        self.assertEqual(bgt_audit.unescape("\\xac\\x71\\x96"),
                         bytes([0xAC, 0x71, 0x96]))

    def test_text_that_stayed_text_is_its_own_utf8_bytes(self):
        """`caractere` with a grave accent is written as itself, not escaped."""
        self.assertEqual(bgt_audit.unescape("caract\u00e8re"),
                         "caract\u00e8re".encode("utf-8"))

    def test_the_specials(self):
        self.assertEqual(bgt_audit.unescape('say \\"hi\\"\\r\\n\\tand \\\\'),
                         b'say "hi"\r\n\tand \\')

    def test_a_backslash_opening_nothing_stands_for_itself(self):
        """BGT warns about an unknown escape rather than consuming it, and the
        octal form is one: `"\\254"` is `Warning: Invalid escape sequence`."""
        self.assertEqual(bgt_audit.unescape("\\254"), b"\\254")
        self.assertEqual(bgt_audit.unescape("\\q"), b"\\q")
        self.assertEqual(bgt_audit.unescape("a\\xZZ"), b"a\\xZZ")
        self.assertEqual(bgt_audit.unescape("\\x4"), b"\\x4")
        self.assertEqual(bgt_audit.unescape("ends with \\"), b"ends with \\")

    def test_a_hex_escape_is_exactly_two_digits(self):
        """`\\x41b` is 'A' then 'b', not a three-digit escape."""
        self.assertEqual(bgt_audit.unescape("\\x41b"), b"Ab")


# --------------------------------------------------------------------------
# rule two: a number is a number, not a spelling
# --------------------------------------------------------------------------

class NumericEquivalenceTests(unittest.TestCase):

    def test_a_float_and_an_integer_spelling_are_one_constant(self):
        self.assertTrue(bgt_audit.same_number(-100.0, -100))
        self.assertTrue(bgt_audit.same_number(4.0, 4))
        self.assertFalse(bgt_audit.same_number(-100.0, -101))

    def test_a_tolerance_absorbs_a_rounded_spelling(self):
        self.assertTrue(bgt_audit.same_number(1.9950000047683716,
                                              1.99500000476837160001))
        self.assertFalse(bgt_audit.same_number(1.995, 1.996))

    def test_a_tiny_value_is_not_zero(self):
        """The trap an ABSOLUTE tolerance sets: the float reading of a small
        integer is a denormal, and almost every body's text holds a zero. With
        `abs_tol` in the comparison the constant audit reported nothing while a
        flattened 250 sat in front of it."""
        tiny = struct.unpack("<f", struct.pack("<I", 250))[0]
        self.assertFalse(bgt_audit.same_number(tiny, 0.0))

    def test_the_stock_library_float_spelling(self):
        """`SetV4 0xC2C80000` is -100.0; a substituted stock file spells it
        `-100`, and four of Paladin's rows were only that."""
        self.assertIn(-100.0, bgt_audit.readings(0xC2C80000, 4))
        self.assertIn(-100.0, bgt_audit.readings(-1027080192, 4))

    def test_a_double_constant(self):
        bits = struct.unpack("<Q", struct.pack("<d", 4.0))[0]
        self.assertIn(4.0, bgt_audit.readings(bits, 8))

    def test_a_denormal_reading_is_not_offered(self):
        self.assertEqual(bgt_audit.readings(250, 4), [250])

    def test_the_text_side_reads_hex_floats_and_a_leading_minus(self):
        body = _body("{ a = -100; b = 0x1F; c = 1.5f; d = 2e3; "
                     "local_4 = v3; }")
        values = bgt_audit.text_numbers(body)
        for want in (-100.0, 100.0, 31.0, 1.5, 2000.0):
            self.assertIn(want, values)
        self.assertNotIn(4.0, values)          # `local_4` is a name, not a 4
        self.assertNotIn(3.0, values)          # ...and so is `v3`

    def test_a_number_inside_a_string_or_a_comment_is_not_evidence(self):
        body = _body('{ speak("30 seconds"); /* 77 */ // 88\n }')
        self.assertEqual(bgt_audit.text_numbers(body), [])


# --------------------------------------------------------------------------
# rule three: the same bits have more than one honest reading
# --------------------------------------------------------------------------

class SignedReadingTests(unittest.TestCase):

    def test_a_one_byte_255_may_be_spelled_minus_one(self):
        """Three of Psycho Strike's rows were this: `this.walk(-1, false)`
        into an `int8` parameter is a one-byte 255 in the bytecode."""
        self.assertIn(-1, bgt_audit.readings(255, 1))

    def test_a_four_byte_store_does_not_get_a_one_byte_reading(self):
        """The opposite error, and the dangerous one: every spurious reading is
        one more way for a lost constant to find a match in the text and go
        unreported. `SetV4 250` is 250, never the int8 -6."""
        self.assertNotIn(-6, bgt_audit.readings(250, 4))
        self.assertNotIn(-6.0, bgt_audit.readings(250, 4))

    def test_an_operand_arrives_signed_and_the_bits_are_recovered(self):
        """`as_opcodes` decodes the varint's sign flag, so the same
        instruction is `SetV4 -1` and `SetV4 0xFFFFFFFF`."""
        self.assertEqual(bgt_audit.readings(-1, 4)[0], 0xFFFFFFFF)
        self.assertIn(-1, bgt_audit.readings(-1, 4))
        self.assertIn(-1, bgt_audit.readings(0xFFFFFFFF, 4))

    def test_a_wide_signed_constant(self):
        self.assertIn(-1, bgt_audit.readings((1 << 64) - 1, 8))


# --------------------------------------------------------------------------
# what the text holds, and what is declined
# --------------------------------------------------------------------------

def _body(text, name="f", label="<global>::f", stock=False):
    """A Body over `text`, scrubbed the way the audit scrubs a real file."""
    try:
        from bgtdecomp import bgt_apicheck
    except ImportError:
        import bgt_apicheck
    return bgt_audit.Body(name, label, "x.bgt", "x.bgt", 1, text,
                          bgt_apicheck.scrub(text), stock)


class TextExtractionTests(unittest.TestCase):

    SOURCE = """\
// a header comment with a "quote" and a 99 in it
namespace rhythm {
    class player : base {
        player() {
            super();
        }
        void reset()
        {
            if (ready) {
                this.walk(-1, false);
            }
            while (go(1)) { }
            events[index].fire();
        }
    }
}

void prepare_audio()
{
    local_4 = "data.dat";
    set_sound_storage(local_4);
}
"""

    def heads(self):
        try:
            from bgtdecomp import bgt_apicheck
        except ImportError:
            import bgt_apicheck
        scrubbed = bgt_apicheck.scrub(self.SOURCE)
        return scrubbed, bgt_audit.function_heads(scrubbed)

    def test_a_function_head_is_a_name_a_parameter_list_and_a_brace(self):
        _scrubbed, heads = self.heads()
        self.assertEqual(sorted(h[0] for h in heads),
                         ["player", "prepare_audio", "reset"])

    def test_a_clause_that_looks_like_a_head_is_not_one(self):
        _scrubbed, heads = self.heads()
        for word in ("if", "while", "for", "switch"):
            self.assertNotIn(word, [h[0] for h in heads])

    def test_a_method_is_labelled_with_its_namespace_and_class(self):
        scrubbed, heads = self.heads()
        found = bgt_audit.scopes(scrubbed)
        labels = {name: bgt_audit.body_label(found, name, head)
                  for name, head, _s, _e in heads}
        self.assertEqual(labels["reset"], "rhythm::player::reset")
        self.assertEqual(labels["player"], "rhythm::player::player")
        # A free function has no owner in the module even inside a namespace.
        self.assertEqual(labels["prepare_audio"], "<global>::prepare_audio")

    def test_a_method_on_an_indexed_receiver_is_seen(self):
        """`bgt_libcheck.calls` could not reach a name after a `]`, and the
        first version of the call audit reported 67 lost `add_event` calls that
        were every one of them present."""
        body = _body("{ global_interacts[slot].add_event(find(x)); }")
        self.assertEqual(bgt_audit.text_calls(body),
                         {"add_event": 1, "find": 1})

    def test_literals_come_from_the_raw_text_at_scrubbed_offsets(self):
        body = _body('{ // not a "literal"\n a = "x\\xacy"; b = "two"; }')
        self.assertEqual(bgt_audit.text_literals(body),
                         {b"x\xacy": 1, b"two": 1})


class DeclinedCallTests(unittest.TestCase):
    """A call the text has no syntax for is not a lost call."""

    def test_what_is_invisible(self):
        for name in ("get_volume", "set_pan_step", "_beh_0_", "$beh2",
                     "opAdd", "opIndex", "opImplConv", "_string_factory_",
                     "$str", "%delegate_factory", "$dlgte", "factstub",
                     "$list", "_builtin_function_"):
            self.assertTrue(bgt_audit.invisible_in_source(name), name)

    def test_a_global_set_function_is_a_call_the_text_spells(self):
        """BGT registers `set_sound_storage` and `set_sound_decryption_key` as
        ordinary global functions. A blanket `set_` prefix declined both, and
        the second is the one call whose loss is the difference between a
        recovery with sound and one without."""
        for name in ("set_sound_storage", "set_sound_decryption_key",
                     "get_SCRIPT_COMPILED"):
            self.assertFalse(bgt_audit.invisible_in_source(name, owned=False),
                             name)
            self.assertTrue(bgt_audit.invisible_in_source(name, owned=True),
                            name)

    def test_what_is_not(self):
        """`open` and `option` begin with `op` and are ordinary calls; a name
        rule that swallowed them would hide every lost `open`."""
        for name in ("open", "option", "optimise", "settings", "getter",
                     "operator_name", "beh", "stream"):
            self.assertFalse(bgt_audit.invisible_in_source(name), name)


# --------------------------------------------------------------------------
# a synthetic module, so the whole pipeline runs with no game file
# --------------------------------------------------------------------------

class _Assembler:
    """Hand-assembled bytecode, through the repository's own varint encoder.

    One table, invented opcode numbers and real encoding: the audit reads an
    operand's role and an instruction's name, never an opcode number, so what
    has to be real here is the decode -- and that is `as_opcodes.disassemble`,
    reached exactly as `as_disasm.disassemble_function` reaches it.
    """

    TABLE = {
        0x01: ("SetV1", 2), 0x02: ("SetV2", 2), 0x03: ("SetV4", 2),
        0x04: ("SetV8", 2), 0x05: ("STR", 1), 0x06: ("CALLSYS", 1),
        0x07: ("CALL", 1), 0x08: ("PGA", 1), 0x09: ("ALLOC", 2),
        0x0A: ("PshVPtr", 1), 0x0B: ("RET", 1),
    }

    def __init__(self):
        self.data = bytearray()
        self.opcodes = {op: {"name": name, "type": 0, "operands": n,
                             "dwords": 1, "stackInc": 0}
                        for op, (name, n) in self.TABLE.items()}
        self.by_name = {name: op for op, (name, _n) in self.TABLE.items()}

    def body(self, instructions):
        """Append one body and return its (start, end) span and length."""
        start = len(self.data)
        count = 0
        for name, *args in instructions:
            self.data.append(self.by_name[name])
            for value in args:
                self.data += as_write.encode_encoded_uint(value)
            count += 1
        return (start, len(self.data)), count


class _Module(as_disasm.Module):
    """An `as_disasm.Module` whose tables are supplied rather than parsed.

    Subclassed so that `resolve`, `disassemble_function` and everything else
    that names an operand is the REAL code: one reader stays one reader, and a
    test that re-implemented operand resolution would pass while the tool was
    wrong.
    """

    def __init__(self, assembler, functions, strings, used_functions,
                 globals_=(), plain_global_index=True):
        self.data = bytes(assembler.data)
        self.opcodes = assembler.opcodes
        self.path = "<synthetic>"
        self.info = {}
        self.dialect = "tagged"
        self.blocks = []
        self.tail = {}
        self.parse_errors = []
        self.used_functions = list(used_functions)
        self.used_strings = list(strings)
        self.used_global_props = list(globals_)
        self.used_object_props = []
        self.used_types = []
        self.used_type_ids = []
        self.properties = {}
        self.script_classes = frozenset()
        self.script_classes_qualified = frozenset()
        self.non_value_types = frozenset()
        self.functions = list(functions)
        self.register_returns = frozenset()
        self.plain_global_index = plain_global_index


def _function(name, span, count, owner=None, params=()):
    f = {"name": name, "body": span, "instructions": count,
         "params": list(params), "returns": None}
    if owner is not None:
        f["owner"] = {"kind": "named", "name": owner}
    return f


def _used(name, owner=None):
    return _function(name, (0, 0), 0, owner)


PROJECT = {
    "game.bgt": """\
// the entry script
#include "includes/functions/part_0.bgt"
#include "includes/classes/player.bgt"
""",
    "includes/functions/part_0.bgt": """\
// includes/functions/part_0.bgt
// Recovered from synthetic.exe.

void prepare_audio()
{
    string local_4;
    local_4 = "data.dat";
    set_sound_storage(local_4);
    volume = 30;
}

void describe()
{
    string local_2;
    local_2 = "it\\x92s here";
    speak(local_2);
}

void stock_spelling()
{
    pool.behind_pan_step = -100;
}
""",
    "includes/classes/player.bgt": """\
// includes/classes/player.bgt
// Recovered from synthetic.exe.

class player {

    void reset()
    {
        this.walk(-1, false);
        this.step = 4.0;
    }

}
""",
}


def _write_project(root):
    for relpath, text in PROJECT.items():
        path = os.path.join(root, relpath.replace("/", os.sep))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)


def _build_module():
    """The bytecode the project above is supposed to be a recovery of."""
    asm = _Assembler()
    strings = [b"data.dat", b"it\x92s here"]
    used = [_used("set_sound_storage"), _used("speak"), _used("walk", "player"),
            _used("_string_factory_"), _used("get_volume", "sound")]
    double_four = struct.unpack("<Q", struct.pack("<d", 4.0))[0]

    span, n = asm.body([
        ("STR", 0),                     # "data.dat"
        ("CALLSYS", 3),                 # _string_factory_ -- invisible
        ("CALLSYS", 0),                 # set_sound_storage
        ("SetV4", 2, 30),               # volume = 30
        ("RET", 0)])
    prepare = _function("prepare_audio", span, n)

    span, n = asm.body([
        ("STR", 1),                     # "it\x92s here"
        ("CALLSYS", 1),                 # speak
        ("RET", 0)])
    describe = _function("describe", span, n)

    span, n = asm.body([
        ("SetV4", 3, 0xC2C80000),       # -100.0f, spelled `-100` in the text
        ("CALLSYS", 4),                 # get_volume -- invisible
        ("RET", 0)])
    spelling = _function("stock_spelling", span, n)

    span, n = asm.body([
        ("SetV1", 1, 255),              # the int8 -1
        ("PshVPtr", 0),
        ("CALLSYS", 2),                 # player::walk
        ("SetV8", 4, double_four),      # this.step = 4.0
        ("RET", 0)])
    reset = _function("reset", span, n, owner="player")

    return _Module(asm, [prepare, describe, spelling, reset], strings, used)


class SyntheticAuditTests(unittest.TestCase):
    """The clean tree, which must be clean -- and clean for the right reasons."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="bgt_audit_")
        self.addCleanup(shutil.rmtree, self.root, True)
        _write_project(self.root)
        self.mod = _build_module()

    def run_audit(self, root=None):
        return bgt_audit.audit(root or self.root, mod=self.mod)

    def test_every_body_pairs(self):
        report = self.run_audit()
        self.assertEqual(report["counts"]["paired"], 4)
        self.assertEqual(report["counts"]["ambiguous"], 0)

    def test_a_faithful_recovery_reports_nothing(self):
        report = self.run_audit()
        self.assertEqual([r.as_dict() for r in report["_rows"]], [])

    def test_the_declined_calls_are_counted_rather_than_ignored(self):
        """Two of the four bodies call something the text cannot spell, and an
        audit that reports nothing has to say how much it looked at."""
        report = self.run_audit()
        self.assertEqual(report["totals"]["calls"]["declined"], 2)

    def test_the_three_rules_are_what_make_it_clean(self):
        """Not a tautology: with each rule defeated the same tree reports."""
        report = self.run_audit()
        self.assertEqual(report["_rows"], [])

        original = bgt_audit.unescape
        bgt_audit.unescape = lambda text: text.encode("latin-1", "replace")
        try:
            rows = self.run_audit()["_rows"]
        finally:
            bgt_audit.unescape = original
        self.assertEqual([r.name for r in rows if r.audit == "literals"],
                         ["describe"])

        original = bgt_audit.same_number
        bgt_audit.same_number = lambda a, b: repr(a) == repr(b)
        try:
            rows = self.run_audit()["_rows"]
        finally:
            bgt_audit.same_number = original
        # Under string comparison an `int` reading never equals a `float`
        # spelling, so `SetV4 30` against a text `30` is a row.
        self.assertEqual(sorted(r.name for r in rows if r.audit == "constants"),
                         ["prepare_audio", "reset"])

        original = bgt_audit.readings
        bgt_audit.readings = lambda value, width: [value]
        try:
            rows = self.run_audit()["_rows"]
        finally:
            bgt_audit.readings = original
        self.assertIn("reset", [r.name for r in rows if r.audit == "constants"])


class InjectedDefectTests(unittest.TestCase):
    """Measured in both directions. Each defect has to come back."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="bgt_audit_inject_")
        self.addCleanup(shutil.rmtree, self.root, True)
        _write_project(self.root)
        self.mod = _build_module()
        self.target = os.path.join(self.root, "includes", "functions",
                                   "part_0.bgt")

    def injure(self, old, new):
        with open(self.target, encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn(old, text)
        with open(self.target, "w", encoding="utf-8", newline="") as fh:
            fh.write(text.replace(old, new, 1))
        return bgt_audit.audit(self.root, mod=self.mod)

    def rows(self, report, audit):
        return [r for r in report["_rows"] if r.audit == audit]

    def test_a_dropped_literal_is_reported(self):
        report = self.injure('local_4 = "data.dat";', 'local_4 = "";')
        rows = self.rows(report, "literals")
        self.assertEqual([r.name for r in rows], ["prepare_audio"])
        self.assertIn("data.dat", rows[0].values[0])

    def test_a_constant_flattened_to_one_is_reported(self):
        """The defect the whole constant audit exists for: a slot typed `bool`
        rendered every constant stored into it as `true`, which is 1."""
        report = self.injure("volume = 30;", "volume = true;")
        rows = self.rows(report, "constants")
        self.assertEqual([r.name for r in rows], ["prepare_audio"])
        self.assertIn("30", rows[0].values[0])

    def test_a_deleted_call_is_reported(self):
        report = self.injure("    set_sound_storage(local_4);\n", "")
        rows = self.rows(report, "calls")
        self.assertEqual([r.name for r in rows], ["prepare_audio"])
        self.assertEqual(rows[0].values, ["set_sound_storage"])

    def test_a_high_byte_literal_mangled_into_text_is_reported(self):
        """The failure that cost Super Egg Hunt its sound: a byte above 0x7F
        written as a character into a UTF-8 file becomes two bytes."""
        report = self.injure('"it\\x92s here"', '"it\u2019s here"')
        rows = self.rows(report, "literals")
        self.assertEqual([r.name for r in rows], ["describe"])

    def test_an_ambiguous_name_is_declined_rather_than_mispaired(self):
        """A second body of the same name makes the pair unsafe, and a row
        guessed from the wrong body is worse than no row."""
        with open(self.target, "a", encoding="utf-8", newline="") as fh:
            fh.write("\nvoid prepare_audio()\n{\n}\n")
        report = bgt_audit.audit(self.root, mod=self.mod)
        self.assertEqual(report["counts"]["paired"], 3)
        self.assertEqual(report["counts"]["ambiguous"], 1)
        self.assertEqual(report["_rows"], [])


class StockFileTests(unittest.TestCase):
    """A substituted stock file's text is BGT's own source, and a row from one
    is a comparison against a different artefact -- so it is marked."""

    def test_the_marker_is_the_header_the_substitution_writes(self):
        root = tempfile.mkdtemp(prefix="bgt_audit_stock_")
        self.addCleanup(shutil.rmtree, root, True)
        path = os.path.join(root, "sound_positioning.bgt")
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write("// sound_positioning.bgt -- BGT's own copy of this "
                     "file, from\n// C:\\BGT\\include\\sound_positioning.bgt\n"
                     "void position_sound_1d(sound@ s)\n{\n    s.pan = 0;\n}\n")
        bodies = bgt_audit.text_bodies(root)
        body = bodies["<global>::position_sound_1d"][0]
        self.assertTrue(body.stock)


if __name__ == "__main__":
    unittest.main(verbosity=2)
