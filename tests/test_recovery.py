"""
Known-answer tests for project recovery: the IR adapter, the compiler driver
and the project writer.

Synthetic inputs only -- no game files, no compiler -- so these run anywhere.
As in `test_toolkit.py`, they target what fails *quietly*:

  * the token mapping between the two AngelScript generations: every id below
    36 is unchanged, so a wrong mapping is right about `int`-free code
  * which instruction field each operand lands in: a pointer operand read from
    the wrong field still resolves to a real name from the wrong table
  * the global-pointer pre-shift touching only the pointer field -- shifting
    the value field too rewrote every constant assigned to a global as 2n+1,
    which is a plausible constant
  * an inherited-property prefix: re-declared, it is a name conflict, and the
    flags this generation writes do not mark it
  * the compiler's own report, which carries the candidate signatures that say
    what a call got wrong
  * the project split, which must not reorder declarations: that changes
    global initialisation order while still compiling

Run:  python tests/test_recovery.py      (or: python -m pytest tests/ -q)
"""

import inspect
import os
import sys
import tempfile

try:                                   # after `pip install -e .`
    from bgtdecomp import (bgt_api, bgt_apicheck, bgt_asir, bgt_compile,
                           bgt_pack, bgt_project)
    from bgtdecomp.nvgt import asreader, decompile
except ImportError:                    # straight from a checkout
    TOOLS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools")
    sys.path.insert(0, TOOLS)
    sys.path.insert(0, os.path.join(TOOLS, "nvgt"))
    import asreader
    import bgt_api
    import bgt_apicheck
    import bgt_asir
    import decompile
    import bgt_compile
    import bgt_pack
    import bgt_project


# -- the token mapping between the two generations -------------------------

def test_token_mapping_matches_both_generations():
    """BGT's primitive ids, read from its own binaries, in the newer numbering.

    Two tokens were inserted into eTokenType, at 36 and 64, so an id below 36
    is unchanged -- which is why a wrong mapping still reads `bool` (65) as
    something and only shows up on a type nobody checked.
    """
    assert bgt_asir._token(5) == 5           # identifier: an object type
    assert bgt_asir._token(65) == 67         # bool
    assert bgt_asir._token(68) == 70         # int
    assert bgt_asir._token(69) == 71         # int8
    assert bgt_asir._token(70) == 72         # int16
    assert bgt_asir._token(71) == 73         # int64
    assert bgt_asir._token(75) == 77         # uint
    assert bgt_asir._token(76) == 78         # uint8
    assert bgt_asir._token(79) == 81         # float
    assert bgt_asir._token(80) == 82         # void
    assert bgt_asir._token(92) == 94         # double
    # ...and those are the names the newer reader gives them.
    assert asreader.PRIMITIVE_NAMES[bgt_asir._token(68)] == "int"
    assert asreader.PRIMITIVE_NAMES[bgt_asir._token(92)] == "double"


# -- operand layout ---------------------------------------------------------

def test_slot_fields_are_only_the_variable_operands():
    """`wW` and `rW` are frame slots; a plain `W` is some other word.

    ADDSi is rW_W_DW: a slot, an object-property index and a type id. Taking
    the property index for a slot types the wrong variable.
    """
    assert bgt_asir.SLOT_FIELDS["asBCTYPE_rW_W_DW_ARG"] == ("w_arg",)
    assert bgt_asir.SLOT_FIELDS["asBCTYPE_wW_rW_rW_ARG"] == ("w_arg", "w_arg2", "qw_arg")
    assert bgt_asir.SLOT_FIELDS["asBCTYPE_NO_ARG"] == ()
    assert bgt_asir.SLOT_FIELDS["asBCTYPE_DW_ARG"] == ()


def test_every_bytecode_type_names_as_many_fields_as_its_name_implies():
    for bc_type, fields in bgt_asir.BC_FIELDS.items():
        parts = bc_type[len("asBCTYPE_"):-len("_ARG")].split("_")
        expected = 0 if parts == ["NO"] else len(parts)
        assert len(fields) == expected, bc_type
        assert len(set(fields)) == len(fields), bc_type


def test_legacy_overrides_cover_exactly_the_pointer_width_opcodes():
    """The three opcodes whose operand count differs in a 32-bit build.

    Checked against the newer table: these three disagree and nothing else
    does, which is what makes sharing one opcode table safe.
    """
    assert set(bgt_asir.LEGACY_BC_TYPE) == {"ALLOC", "CALLSYS", "CallPtr"}
    # ALLOC keeps the 64-bit field order so the object type stays in the
    # quadword field, which is where TranslateFunction reads it.
    assert bgt_asir.BC_FIELDS[bgt_asir.LEGACY_BC_TYPE["ALLOC"]] == ("qw_arg", "dw_arg")
    assert bgt_asir.BC_FIELDS[bgt_asir.LEGACY_BC_TYPE["CALLSYS"]] == ("dw_arg",)
    assert bgt_asir.BC_FIELDS[bgt_asir.LEGACY_BC_TYPE["CallPtr"]] == ("w_arg",)


# -- a synthetic build ------------------------------------------------------

def _table(*names):
    """An opcode table shaped like the one asBCInfo[] yields, for these names."""
    out = {}
    for op, name in enumerate(names):
        _, bc_type, _, _ = asreader.OPCODES[_opcode(name)]
        bc_type = bgt_asir.LEGACY_BC_TYPE.get(name, bc_type)
        out[_opcode(name)] = {"name": name, "type": 0,
                              "operands": len(bgt_asir.BC_FIELDS[bc_type]),
                              "dwords": 1 + len(bgt_asir.BC_FIELDS[bc_type]),
                              "stackInc": 0}
    return out


def _opcode(name):
    for op, entry in asreader.OPCODES.items():
        if entry[0] == name:
            return op
    raise KeyError(name)


def _encode(value):
    """ReadEncodedUInt64's single-byte and two-byte forms, which is all a test
    body needs (the decoder itself is covered in test_toolkit).

    The two-byte lead byte is `10xxxxxx`: bit 6 selects the width, and bit 7 is
    the sign flag, not part of it.
    """
    assert 0 <= value < 0x4000
    if value < 0x40:
        return bytes([value])
    return bytes([0x40 | (value >> 8), value & 0xFF])


def _builder(table, data=b""):
    info = {"dialect": "tagged", "enums": [], "classes": [], "funcdefs": [],
            "blocks": [], "tail": {}}
    return bgt_asir.Builder(data, info, table)


def test_decode_places_each_operand_in_the_field_the_layout_names():
    table = _table("SetV4", "CALLSYS", "RET")
    body = (bytes([_opcode("SetV4")]) + _encode(3) + _encode(7)
            + bytes([_opcode("CALLSYS")]) + _encode(100)
            + bytes([_opcode("RET")]) + _encode(0))
    instrs = _builder(table, body).decode((0, len(body)), 3, "probe")
    assert [i.name for i in instrs] == ["SetV4", "CALLSYS", "RET"]
    assert (instrs[0].w_arg, instrs[0].dw_arg) == (3, 7)
    # CALLSYS is a dword operand in a 32-bit build, and TranslateFunction
    # reads the call target from dw_arg.
    assert instrs[1].dw_arg == 100
    # positions are dword offsets, taken from this build's own widths
    assert [i.pos for i in instrs] == [0, 3, 5]


def test_decode_refuses_a_body_that_does_not_end_where_the_record_does():
    table = _table("SetV4", "RET")
    body = bytes([_opcode("SetV4")]) + _encode(1) + _encode(1)
    try:
        _builder(table, body).decode((0, len(body) + 4), 1, "probe")
    except bgt_asir.AdapterError as exc:
        assert "ends at" in str(exc)
    else:
        raise AssertionError("a short body was accepted")


def test_decode_rejects_a_build_whose_operand_count_disagrees():
    """The check that makes one shared opcode table safe.

    A build that wrote `ALLOC` with a different number of operands would have
    every later instruction of the body decoded at the wrong offset, while
    still producing real opcode names.
    """
    table = _table("ALLOC", "RET")
    table[_opcode("ALLOC")]["operands"] = 3
    body = bytes([_opcode("ALLOC")]) + _encode(1) + _encode(2) + _encode(3)
    try:
        _builder(table, body).decode((0, len(body)), 1, "probe")
    except bgt_asir.AdapterError as exc:
        assert "operands" in str(exc)
    else:
        raise AssertionError("a disagreeing operand count was accepted")


def test_global_pointer_shift_touches_only_the_pointer_field():
    """SetG4 carries the global in the pointer field and the VALUE in the other.

    The older dialect has no table-selector bit, so the pointer field is
    pre-shifted to `2n + 1`. Shifting the value field as well rewrote every
    constant assigned to a global: `const int male = 1` came out as 3, which
    reads like a real constant and not like a bug.
    """
    table = _table("SetG4", "RET")
    body = (bytes([_opcode("SetG4")]) + _encode(4) + _encode(1)
            + bytes([_opcode("RET")]) + _encode(0))
    builder = _builder(table, body)
    f = asreader.Function(name="init")
    f.bytecode = builder.decode((0, len(body)), 2, "init")
    module = asreader.Module()
    module.saved_functions = [f]
    builder.normalise(module)
    setg4 = f.bytecode[0]
    assert setg4.qw_arg == 4 * 2 + 1       # the global, with the selector bit
    assert setg4.dw_arg == 1               # the value, untouched


def test_str_operand_moves_to_the_field_the_translator_reads():
    """STR's string index is a word operand here and a dword one there.

    Left in the word field it resolves to whichever literal sits at index 0 --
    a real string, in every body that has one.
    """
    table = _table("STR", "RET")
    body = (bytes([_opcode("STR")]) + _encode(1552)
            + bytes([_opcode("RET")]) + _encode(0))
    builder = _builder(table, body)
    f = asreader.Function(name="probe")
    f.bytecode = builder.decode((0, len(body)), 2, "probe")
    assert f.bytecode[0].w_arg == 1552
    module = asreader.Module()
    module.saved_functions = [f]
    builder.normalise(module)
    assert f.bytecode[0].dw_arg == 1552


def test_default_arguments_are_aligned_from_the_last_parameter():
    """The list is written last parameter first, and only where one exists.

    Read in file order every default lands on the wrong parameter, which still
    prints a plausible declaration and changes what a call that omits an
    argument does. Paladin's `storyline_scroll(string, bool = true, bool =
    true, bool = false, STORYLINE_LOOP@ = null)` came out as `bool = null,
    bool = false, bool = true, STORYLINE_LOOP@ = true`: 220 errors.
    """
    builder = _builder(_table("RET"))
    record = {
        "name": "storyline_scroll",
        "returns": {"token": 80, "type": None, "handle": False, "const": False,
                    "reference": False, "readonly": False},
        "params": [{"token": t, "type": None, "handle": False, "const": False,
                    "reference": False, "readonly": False}
                   for t in (5, 65, 65, 65, 5)],
        "funcType": 1, "owner": None, "namespace": "",
        "inOut": [], "defaults": ["null", "false", "true", "true"],
    }
    f = builder.fn(record)
    assert f.default_args == [None, "true", "true", "false", "null"]


def test_a_slot_used_as_bool_and_number_records_both_declarations():
    """A reused slot is recorded, not resolved.

    `clear_pathway` writes slot 1 with SetV1/WRTV1 -- one byte, through a
    `bool&out` parameter -- and reads it with RDR4/CMPIi as the int it
    returns. Either type alone was 104 errors in that one body; both
    declarations is what the newer format would hold, and what the decompiler
    reads to pick the numeric type and convert the boolean uses.
    """
    votes = bgt_asir.Builder._slot_votes(1, [70], {1: 67})
    assert votes == [67, 70]
    votes = bgt_asir.Builder._slot_votes(1, [67, 70], {})
    assert votes == [67, 70]
    # No bool evidence: the first type-tagged vote stands alone.
    assert bgt_asir.Builder._slot_votes(1, [70], {1: 70}) == [70]
    assert bgt_asir.Builder._slot_votes(1, [94, 70], {}) == [94]


def test_behaviour_names_become_the_newer_conventions():
    table = _table("RET")
    builder = _builder(table)
    module = asreader.Module()
    module.saved_functions = [asreader.Function(name=n)
                              for n in ("_beh_0_", "_beh_2_", "_beh_3_",
                                        "_beh_not_a_number_", "ordinary")]
    builder.normalise(module)
    assert [f.name for f in module.saved_functions] == [
        "$beh0", "$beh2", "$beh3", "_beh_not_a_number_", "ordinary"]


def test_template_subtype_written_as_a_token_becomes_that_primitive():
    """A template argument that is not an object is written as a token type.

    Psycho Strike's are 65, 68, 75 and 76 -- bool, int, uint and uint8 -- and
    read as anything else the array's element type has no name at all.
    """
    builder = _builder(_table("RET"))
    ref = {"kind": "template", "name": "array", "namespace": "",
           "subtypes": [{"typeid": 68}]}
    subtypes = builder.subtypes(ref)
    assert [s.format() for s in subtypes] == ["int"]
    dt = builder.dt_of_type(ref)
    dt.obj_type.template_syntax = "suffix"
    assert dt.format() == "int[]"


def test_inherited_property_prefix_is_flagged_not_dropped():
    """A derived class's property table opens with its base's, unflagged here.

    Re-declared in the derived class every one is a name conflict; the entries
    still have to be there to resolve a member access, so they are marked the
    way the newer format marks them.
    """
    builder = _builder(_table("RET"))
    base = asreader.TypeInfo(kind="class", name="character")
    base.properties = [("health", asreader.DataType(token_type=70), 0),
                       ("name", asreader.DataType(token_type=70), 0)]
    derived = asreader.TypeInfo(kind="class", name="animal", derived_from=base)
    derived.properties = list(base.properties) + [
        ("legs", asreader.DataType(token_type=70), 0)]
    module = asreader.Module()
    module.classes = [base, derived]
    builder.mark_inherited(module)
    assert [flags & 4 for _, _, flags in derived.properties] == [4, 4, 0]
    assert [flags & 4 for _, _, flags in base.properties] == [0, 0]


def test_a_property_table_that_is_not_a_prefix_is_left_alone():
    """Marking by position would hide a real property.

    If the table does not open with the base's, the layout is not understood,
    and nothing is marked rather than something being silently dropped.
    """
    builder = _builder(_table("RET"))
    base = asreader.TypeInfo(kind="class", name="base")
    base.properties = [("a", asreader.DataType(token_type=70), 0),
                       ("b", asreader.DataType(token_type=70), 0)]
    derived = asreader.TypeInfo(kind="class", name="derived", derived_from=base)
    derived.properties = [("b", asreader.DataType(token_type=70), 0),
                          ("a", asreader.DataType(token_type=70), 0)]
    module = asreader.Module()
    module.classes = [base, derived]
    builder.mark_inherited(module)
    assert [flags for _, _, flags in derived.properties] == [0, 0]


# -- the compiler's report --------------------------------------------------

REPORT = """File: C:\\game\\strike.bgt
On line: 1 (4)
Information: Compiling void main()

File: C:\\game\\strike.bgt
On line: 5 (5)
Line:     ::garbage_collect(int(1000));
Error: No matching signatures to '::garbage_collect(const int)'

File: C:\\game\\strike.bgt
On line: 5 (5)
Information: Candidates are:

File: C:\\game\\strike.bgt
On line: 5 (5)
Information: void garbage_collect()
"""


def test_the_report_parses_into_diagnostics_with_their_candidates():
    """The candidate list belongs to the error above it.

    It is the most useful thing in the report: it says what the recovered call
    got wrong -- here, an argument the engine's signature does not take.
    """
    diagnostics = bgt_compile.parse(REPORT)
    errors = [d for d in diagnostics if d.kind == "Error"]
    assert len(errors) == 1
    error = errors[0]
    assert error.line == 5 and error.column == 5
    assert error.message == "No matching signatures to '::garbage_collect(const int)'"
    assert error.source == "::garbage_collect(int(1000));"
    assert error.candidates == ["void garbage_collect()"]


def test_a_candidate_list_does_not_swallow_the_rest_of_the_report():
    """The list ends at the next error, and every later message still counts.

    Read as unbounded, the first `Candidates are:` made every following
    message a candidate of that one error: a report with 318 errors came back
    as seven, and the recovery looked almost finished.
    """
    report = REPORT + """
File: C:\\game\\strike.bgt
On line: 40 (3)
Line:     goto L00fb;
Error: Identifier 'goto' is not a data type

File: C:\\game\\strike.bgt
On line: 41 (3)
Error: 'local_8' is not declared
"""
    diagnostics = bgt_compile.parse(report)
    errors = [d for d in diagnostics if d.kind == "Error"]
    assert [d.line for d in errors] == [5, 40, 41]
    assert errors[0].candidates == ["void garbage_collect()"]
    assert errors[1].candidates == [] and errors[2].candidates == []


def test_a_crash_is_not_a_clean_compile():
    """The compiler dies silently on some inputs: no window, no message.

    Read as success -- which an exit code of 0 would be -- a module that
    crashes the compiler looks perfect.
    """
    assert not bgt_compile.Report(outcome="crashed", exit_code=-1073741819).ok
    assert "access violation" in bgt_compile.Report(
        outcome="crashed", exit_code=-1073741819).summary()
    assert bgt_compile.Report(outcome="compiled", exit_code=0).ok


def test_neutered_disarms_the_entry_point_and_keeps_the_module():
    with tempfile.TemporaryDirectory() as tmp:
        script = os.path.join(tmp, "game.bgt")
        with open(script, "w", encoding="utf-8") as fh:
            fh.write("void helper()\n{\n}\n\nvoid main()\n{\n    helper();\n}\n")
        target = bgt_compile.neutered(script, os.path.join(tmp, "check"))
        with open(target, encoding="utf-8") as fh:
            text = fh.read()
        assert "void __recovered_main()" in text      # still compiled
        assert "helper();" in text                    # the module is intact
        assert text.rstrip().endswith("}")
        assert text.count("void main()") == 1         # exactly one entry point


def test_an_inconclusive_check_is_not_a_capability_answer():
    """`nodriver`, `timeout` and `crashed` carry no diagnostics.

    Reading "no errors reported" as "this compiler is fine" made BGT 1.0 come
    back as *supporting* default arguments, so the warning that exists for
    exactly that never fired -- and one busy lock is enough to cause it,
    because two checks cannot run at once.
    """
    with tempfile.TemporaryDirectory() as tmp:
        exe = os.path.join(tmp, "bgt.exe")
        with open(exe, "wb") as fh:
            fh.write(b"MZ not really")
        real_check = bgt_compile.check
        # **A test must not write to the user's cache.** `capabilities`
        # remembers its answer on disk, so this one has been appending an
        # entry keyed on a throwaway 13-byte "bgt.exe" to the real
        # `%TEMP%/bgt_capabilities.json` on every run -- thirty of them on
        # this machine. They never match again, so nothing was ever read
        # back wrongly; a test that used a stable path would have poisoned
        # the answer for a real install.
        real_cache = bgt_compile._CAPS_CACHE
        bgt_compile._CAPS_CACHE = os.path.join(tmp, "caps.json")
        bgt_compile._CAPABILITIES.clear()
        try:
            for outcome in ("nodriver", "timeout", "crashed"):
                bgt_compile.check = lambda *a, **k: bgt_compile.Report(
                    outcome=outcome, raw="the check could not run")
                bgt_compile._CAPABILITIES.clear()
                assert bgt_compile.capabilities(exe) == {}, outcome
            # ...and a real verdict is still an answer.
            bgt_compile.check = lambda *a, **k: bgt_compile.Report(
                outcome="compiled", exit_code=0)
            bgt_compile._CAPABILITIES.clear()
            assert bgt_compile.capabilities(exe) == {"default_arguments": True}
        finally:
            bgt_compile.check = real_check
            bgt_compile._CAPS_CACHE = real_cache
            bgt_compile._CAPABILITIES.clear()


def test_shell_verbs_are_read_so_the_wrong_bgt_can_be_named():
    """BGT's installer registers five verbs and the newest install does not
    win: 1.0 over 1.3 leaves `open`, `run` and `compile` on 1.0. A project
    that compiles cleanly here then fails on a double-click."""
    verbs = bgt_compile.shell_verbs()
    assert isinstance(verbs, dict)
    assert set(verbs) <= set(bgt_compile.SHELL_VERBS)
    for exe in verbs.values():
        assert os.path.isfile(exe)
    # Nothing is claimed when the capability is unknown: a missing answer
    # must not read as a warning, and must not read as an all-clear either.
    assert bgt_compile.verb_warnings(needs_default_args=False) == []


def test_staging_repoints_relative_includes_at_the_real_files():
    """A staged copy does not sit where the includes are written against.

    `bgt compile` stages into `_compile_check/` so the executable the compiler
    writes lands there, and then BGT resolves `includes/classes/player.bgt`
    beside the copy and reports, truthfully, that there is no such file. Only
    `bgt recover --compile` knew that, with a `../includes/` string replace of
    its own -- so `bgt compile` on the project `bgt recover` had just written
    failed on its first include.
    """
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, "includes", "classes"))
        for rel in ("includes/types.bgt", "includes/classes/player.bgt"):
            with open(os.path.join(tmp, rel.replace("/", os.sep)), "w") as fh:
                fh.write("// a file\n")
        script = os.path.join(tmp, "game.bgt")
        with open(script, "w", encoding="utf-8") as fh:
            fh.write('#include "includes/types.bgt"\n'
                     '#include"includes/classes/player.bgt"\n'
                     '#include "%s"\n' % os.path.join(tmp, "includes", "types.bgt")
                     .replace(os.sep, "/"))
        check = os.path.join(tmp, "_compile_check")
        target = bgt_compile.stage(script, check)

        with open(target, encoding="utf-8") as fh:
            text = fh.read()
        # Every relative include now resolves from the staging directory...
        for line in text.splitlines():
            if "#include" not in line:
                continue
            name = line.split('"')[1]
            assert os.path.isfile(os.path.join(check, name.replace("/", os.sep))), name
        # ...the no-space spelling BGT's own sources use is handled...
        assert '#include"../includes/classes/player.bgt"' in text
        # ...and an absolute include is left exactly as it was.
        assert os.path.join(tmp, "includes", "types.bgt").replace(os.sep, "/") in text


# -- the project split ------------------------------------------------------

def _section(kind, name, text="x"):
    return bgt_project.Section(kind=kind, name=name, text=text + "\n")


def test_library_runs_keep_their_real_name_and_the_rest_get_one_file_each():
    sections = [_section("types", "types"),
                _section("class", "dynamic_menu"),
                _section("class", "menu"),
                _section("function", "speak"),
                _section("function", "game_loop"),
                _section("globals", "globals")]
    bgt_project.assign_paths(sections, {"dynamic_menu": "dynamic_menu.bgt",
                                        "speak": "speech.bgt"})
    assert [s.path for s in sections] == [
        "includes/types.bgt",
        "includes/dynamic_menu.bgt",
        "includes/classes/menu.bgt",
        "includes/speech.bgt",
        "includes/functions/part_1.bgt",
        "includes/globals.bgt"]


def test_a_change_of_origin_starts_a_new_part():
    """A part is never a mixture of two recovered files."""
    sections = [_section("function", "a"), _section("function", "b"),
                _section("function", "c")]
    bgt_project.assign_paths(sections, {"b": "speech.bgt"})
    assert [s.path for s in sections] == ["includes/functions/part_1.bgt",
                                          "includes/speech.bgt",
                                          "includes/functions/part_2.bgt"]


def test_verify_rejects_a_split_that_reorders_declarations():
    """`#include` is textual, so the files in order ARE the module.

    A split that reorders them can change global initialisation order, which
    is a behaviour change that compiles perfectly.
    """
    sections = [_section("class", "a", "class a {}"),
                _section("globals", "globals", "int g;")]
    bgt_project.assign_paths(sections, {})
    order = [s.path for s in sections]
    source = "class a {}\nint g;\n"
    assert bgt_project.verify(sections, order, source)
    assert not bgt_project.verify(sections, list(reversed(order)), source)


# -- the entry script, and what BGT calls an empty script section -----------

def test_the_entry_script_always_declares_something():
    """A declaration-empty entry script builds no executable at all.

    BGT reports "The script section is empty" for a file that declares
    nothing, in a modal dialog, and then writes **no executable**. Measured:
    an includes-only entry script compiled with that warning, the driver
    dismissed the window, the engine exited 0 -- and `--build release` left
    901,120 bytes of runtime stub with no script attached, which Windows
    declines to launch as "not a valid application for this OS platform".

    The old rule inlined the section at `includes/types.bgt`, as a proxy for
    "the section that declares the module's types". A module with no enums,
    typedefs or funcdefs still gets that section -- holding the decompiler's
    comment banner and nothing else -- so the proxy inlined a banner and the
    entry script stayed empty.
    """
    banner = "// Decompiled from NVGT/AngelScript bytecode.\n// Comments are not recoverable;\n"
    order = ["includes/types.bgt", "includes/classes/holder.bgt",
             "includes/functions/part_0.bgt"]
    written = {"includes/types.bgt": [banner],
               "includes/classes/holder.bgt": ["class holder { int level; }\n"],
               "includes/functions/part_0.bgt": ["void main() {}\n"]}

    inlined, problem = bgt_project.inline_prefix(order, written)
    assert problem is None
    # A PREFIX, so the concatenation is unchanged -- the banner cannot be
    # skipped over, because the inlined text is emitted ahead of every
    # `#include` and skipping would move a declaration.
    assert inlined == ["includes/types.bgt", "includes/classes/holder.bgt"]

    # ...and where the first section does declare something, nothing changes.
    written["includes/types.bgt"] = [banner + "enum team { red, blue }\n"]
    inlined, problem = bgt_project.inline_prefix(order, written)
    assert problem is None
    assert inlined == ["includes/types.bgt"]


def test_an_include_line_is_not_a_declaration():
    """`#include` is what an empty section is usually full of.

    The word boundaries in this pattern were once eaten by a shell and became
    literal backspace bytes, so it matched nothing and an includes-only file
    was judged to declare something -- which is the one case the whole check
    exists for.
    """
    assert not bgt_project.declares_anything('#include "includes/a.bgt"\n')
    assert not bgt_project.declares_anything("// just a comment\n")
    assert not bgt_project.declares_anything("   \n  \n")
    assert bgt_project.declares_anything("int g = 0;")
    # A `//` inside a string literal must not eat the rest of the line: that
    # is the trap `scrub` exists for, and a second scrubber would drift.
    assert bgt_project.declares_anything('string u = "http://x/y";')


def test_a_build_that_wrote_no_executable_is_not_a_clean_compile(self=None):
    """The compiler reporting no errors is not evidence that a file exists.

    BGT writes the executable only after its report window is answered, and
    writes none at all for a script section it calls empty. Read as success,
    a build that produced nothing looks exactly like a build that worked --
    and the next thing anyone does with a build is run it.
    """
    with tempfile.TemporaryDirectory() as tmp:
        script = os.path.join(tmp, "game.bgt")
        with open(script, "w", encoding="utf-8") as fh:
            fh.write("void main() {}\n")
        built = bgt_compile.built_path(script)
        assert built == os.path.join(tmp, "game.exe")

        # nothing written at all
        assert "no game.exe was written" in bgt_compile._unbuilt(script, None)

        # the runtime stub, with no script attached: the measured failure
        with open(built, "wb") as fh:
            fh.write(b"MZ" + b"\x00" * 4096)
        reason = bgt_compile._unbuilt(script, None)
        assert "no script attached" in reason

        # a real one passes: stub + overlay + the 12-byte trailer, whose
        # offset field `bgtlib` requires to point inside the file
        payload = b"MZ" + b"\x00" * 4096
        overlay = b"0 " + b"\xab\xcd" * 8
        trailer = b"xproc10\x00" + len(payload).to_bytes(4, "little")
        with open(built, "wb") as fh:
            fh.write(payload + overlay + trailer)
        assert bgt_compile._unbuilt(script, None) is None

        # ...and a stale one from an earlier build does not pass, because the
        # stamp taken before the compile is unchanged.
        before = bgt_compile._built_stamp(script)
        assert "untouched" in bgt_compile._unbuilt(script, before)


def test_no_source_file_holds_an_escape_a_shell_ate():
    """A control byte where `\b` was meant matches nothing, silently.

    This has happened twice. `_drop_unreachable`'s word boundaries became
    backspace bytes when the pass was edited through a shell, so `return` and
    `goto` quietly stopped terminating a block while the output stayed valid.
    And `method_gap`'s documentation test carried the same two bytes, so the
    help file -- the whole oracle for whether a method is absent, since a list
    makes an absence provable where a substring search cannot -- was never
    consulted at all.

    Neither failed a test, because a pattern that matches nothing just makes
    its branch dead. So the bytes are what get checked.

    Three times, in fact. The scan covered the code and not CLAUDE.md -- and
    the sentence in CLAUDE.md that documents this bug was itself carrying a
    literal 0x08 where it meant to show a `\b`, committed and unreadable. A
    prose file cannot have a dead branch, so the cost is only a line nobody
    can read; it is also the one file here whose whole job is to be read.
    """
    import glob

    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    allowed = {9, 10, 13}            # tab, LF, CR
    offenders = []
    for pattern in ("tools/**/*.py", "tests/**/*.py", "*.md", "docs/*.md"):
        for path in glob.glob(os.path.join(root, pattern), recursive=True):
            data = open(path, "rb").read()
            for index, byte in enumerate(data):
                if byte < 32 and byte not in allowed:
                    line = data[:index].count(b"\n") + 1
                    offenders.append("%s:%d holds byte 0x%02X"
                                     % (os.path.relpath(path, root), line, byte))
    assert not offenders, offenders


#: The one expression that formats a braced initialiser list.
JOIN_ITEMS = '", ".join(items)'


def test_one_implementation_renders_an_initialiser_list():
    """Both engine generations reach the same list factory, so one renderer.

    `string[] x = {"a", "b"}` compiles to the initialisation-list protocol,
    and the factory that consumes the buffer is reached as the behaviour
    `$list` in the newer engine and as a generated template factory stub --
    `string[]@ factstub(int&in)` -- in BGT's older one. The `$list` path
    rendered the buffer as `{...}` while the `factstub` path dropped it, so
    BGT arrays came out EMPTY: 681 elements across Crazy Party, 134 across
    Paladin, 52 across Super Egg Hunt. Valid source that compiles, runs, and
    loops zero times.

    Two places answering one question, with one of them stricter, is the
    failure this repository keeps recording. So it is asked once, and this
    pins that: one definition, at least two call sites, and the braced form
    built in exactly one place.
    """
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "..", "tools", "nvgt", "decompile.py")
    with open(path, encoding="utf-8") as fh:
        source = fh.read()

    assert source.count("def _list_literal(") == 1, (
        "the list renderer must have exactly one definition")
    callers = source.count("self._list_literal(")
    assert callers >= 2, (
        "both the $list and the factstub path must call it, found %d" % callers)
    builders = source.count(JOIN_ITEMS)
    assert builders == 1, (
        "the braced list is formatted in %d places, expected 1" % builders)


def test_the_documented_api_is_read_out_of_the_reference_pages():
    """One page per function, each carrying its signature verbatim.

    The engine's help file is the authoritative list of what it has, which is
    what makes "this type is not in your engine" a statement rather than a
    guess. Parsed from a synthetic tree here: the real one belongs to whoever
    installed BGT and is never copied into this repository.
    """
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "references", "foundation_layer",
                            "function_reference", "variable_management")
        os.makedirs(root)
        with open(os.path.join(root, "string_split.htm"), "w", encoding="utf-8") as fh:
            fh.write("<html><body><h1>string_split</h1><p>Splits a string.</p>"
                     "<p>string[] string_split(string source, string delimiter, "
                     "bool require_full_delimiter)</p></body></html>")
        methods = os.path.join(tmp, "references", "foundation_layer",
                               "object_reference", "timer")
        os.makedirs(methods)
        with open(os.path.join(methods, "restart.htm"), "w", encoding="utf-8") as fh:
            fh.write("<html><body><p>void timer::restart()</p></body></html>")
        # a tutorial page's example code is not an API
        tutorial = os.path.join(tmp, "tutorials")
        os.makedirs(tutorial)
        with open(os.path.join(tutorial, "lesson.htm"), "w", encoding="utf-8") as fh:
            fh.write("<html><body><p>void made_up_example(int x)</p></body></html>")
        open(os.path.join(tmp, "bgt.hhc"), "w").close()

        chm = os.path.join(tmp, "bgt.chm")
        open(chm, "w").close()
        api = bgt_api.read(chm, cache=tmp)      # the cache already holds the pages
        assert api["functions"]["string_split"] == [
            "string[] string_split(string source, string delimiter, "
            "bool require_full_delimiter)"]
        assert api["types"]["timer"]["methods"] == ["void timer::restart()"]
        assert "made_up_example" not in api["functions"]
        # No executable, so this is the documentation's answer alone.
        assert bgt_api.missing(["string_split", "timer", "weakref"], api,
                               exe="X:/no/such/bgt.exe") == ["weakref"]


def test_example_code_on_a_reference_page_is_not_an_api():
    """A reference page is named after the one API it documents.

    `garbage_collect`'s page defines `generate_garbage` to have something to
    collect, `get_call_stack`'s defines `first_dummy_method`, `serialize`'s
    defines `save`. Every signature on a page that is not the page's own is
    example code, and eleven of them were being counted as engine API --
    which matters in the dangerous direction, because this list is what
    decides whether an absence gets reported: a name it wrongly holds is a
    gap it will not report. The engine's registrations settle it, and so
    does the help file's own tree: not one of the eleven has a page.
    """
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "references", "foundation_layer",
                            "function_reference", "miscellaneous")
        os.makedirs(root)
        with open(os.path.join(root, "garbage_collect.htm"), "w",
                  encoding="utf-8") as fh:
            fh.write("<html><body><p>void garbage_collect()</p>"
                     "<p>Example:</p><p>void generate_garbage()</p>"
                     "</body></html>")
        open(os.path.join(tmp, "bgt.hhc"), "w").close()
        chm = os.path.join(tmp, "bgt.chm")
        open(chm, "w").close()
        api = bgt_api.read(chm, cache=tmp)
        assert "garbage_collect" in api["functions"]
        assert "generate_garbage" not in api["functions"]


def test_the_engines_own_registrations_are_read_off_the_executable():
    """AngelScript registers everything by handing over a declaration string.

    So the whole interface is a literal in `bgt.exe`, which is a stronger
    oracle than the help file for the one question asked of it: BGT 1.3
    registers `string_compress` and documents it nowhere, and Paladin's save
    path calls it. Asked of the documentation alone, "does this engine have
    that?" answered no.

    Three shapes have to be read and two refused, and each of the refusals
    was a real false positive:

    * an array return (`string[]@ find_files(...)`) -- rejecting it lost
      four functions the help file *did* document, which is the only reason
      it was noticed;
    * a factory, whose handle marker sits against the name
      (`network_event @f()`) -- all eighteen of them;
    * a file-dialog filter is shaped exactly like a declaration
      (`All Files (*.*)`), and a declaration's parameters are types;
    * a bare import name (`send()`) splits into a return type `sen` and a
      function `d`, because the type pattern backtracks -- four names out of
      the import table became registered types that way.
    """
    with tempfile.TemporaryDirectory() as tmp:
        exe = os.path.join(tmp, "bgt.exe")
        with open(exe, "wb") as fh:
            fh.write(b"\x00".join([
                b"string[]@ find_files(string& in)",
                b"network_event @f()",
                b"string string_compress(const string& in)",
                b"int pathfinder_callback(int x, int y, string data)",
                b"All Files (*.*)",
                b"BGT Scripts (*.bgt)",
                b"send()",
                b"socket()",
            ]))
        reg = bgt_api.registered(exe)
        assert sorted(reg) == ["f", "find_files", "pathfinder_callback",
                               "string_compress"]
        assert bgt_api.registered_types(decls=reg) == {
            "string", "network_event", "int"}
        # ...and nothing registered is ever reported absent.
        api = {"functions": {}, "types": {}}
        assert bgt_api.missing(["string_compress", "network_event", "weakref"],
                               api, exe=exe) == ["weakref"]


def test_engine_gap_names_a_type_the_installed_compiler_lacks():
    """The game's runtime has it and the installed compiler does not.

    Manamon 2 uses `weakref`, which is in its own `rpg.exe` and in neither
    BGT 1.0's nor 1.3's compiler: it was built with a newer engine, and its
    parse errors are the engine's age rather than the recovery's. Without this
    the report is a mystery.
    """
    with tempfile.TemporaryDirectory() as tmp:
        compiler = os.path.join(tmp, "bgt.exe")
        with open(compiler, "wb") as fh:
            fh.write(b"string\x00array\x00dictionary\x00")
        game = os.path.join(tmp, "game.exe")
        with open(game, "wb") as fh:
            fh.write(b"string\x00weakref\x00array\x00")
        gap = bgt_project.engine_gap(game, ["string", "array", "weakref"], compiler)
        assert gap == [("weakref", "game.exe")]
        # A type neither one has is not evidence of anything.
        assert bgt_project.engine_gap(game, ["nowhere"], compiler) == []


def test_a_games_own_runtime_says_what_the_build_that_made_it_offered():
    """A BGT game is the runtime with the module appended, so the runtime's
    registration strings are right there, uncompressed.

    That is better evidence than the name appearing somewhere in the file,
    which cannot be told from a coincidence. Manamon 2's `rpg.exe`
    registers 509 names and 52 types where stock 1.3 registers 432 and 32,
    so its `weakref` and `ecdh` are provably the build's rather than
    inferred from a substring.
    """
    with tempfile.TemporaryDirectory() as tmp:
        compiler = os.path.join(tmp, "bgt.exe")
        with open(compiler, "wb") as fh:
            fh.write(b"\x00".join([b"void timer_restart(string& in)"]))
        game = os.path.join(tmp, "game.exe")
        with open(game, "wb") as fh:
            fh.write(b"\x00".join([
                b"void timer_restart(string& in)",
                b"weakref @f()",                       # a registration
                b"a changelog mentioning ecdh here",   # merely a mention
            ]))
        assert bgt_project.engine_gap(
            game, ["weakref", "ecdh"], compiler) == [("weakref", "game.exe")]


def test_bgt_api_can_be_pointed_at_a_games_own_engine():
    """`--exe` is what makes "the engine's age, not the recovery's" checkable.

    Manamon 2's `rpg.exe` registers `void garbage_collect(int
    number_of_cycles=0)` where the installed 1.3 documents `void
    garbage_collect()`, so a recovered `garbage_collect(int(1000))` is the
    build's signature rather than a decompilation error -- and printing only
    the documented one would answer about the wrong engine. A registered
    *type* has no declaration of its own to print, so it needs saying too:
    `weakref` and `ecdh` are types, and they are the whole question.
    """
    import contextlib
    import io as _io

    with tempfile.TemporaryDirectory() as tmp:
        game = os.path.join(tmp, "rpg.exe")
        with open(game, "wb") as fh:
            fh.write(b"\x00".join([
                b"void garbage_collect(int number_of_cycles=0)",
                b"weakref @f()"]))
        chm = os.path.join(tmp, "bgt.chm")
        open(chm, "w").close()
        root = os.path.join(tmp, "references", "foundation_layer",
                            "function_reference", "miscellaneous")
        os.makedirs(root)
        with open(os.path.join(root, "garbage_collect.htm"), "w",
                  encoding="utf-8") as fh:
            fh.write("<html><body><p>void garbage_collect()</p></body></html>")
        open(os.path.join(tmp, "bgt.hhc"), "w").close()

        out = _io.StringIO()
        with contextlib.redirect_stdout(out):
            bgt_api.main(["--chm", chm, "--cache", tmp, "--exe", game,
                          "garbage_collect", "weakref"])
        printed = out.getvalue()
        assert "void garbage_collect()" in printed              # documented
        assert "int number_of_cycles=0" in printed              # and the build's
        assert "type weakref" in printed


def test_a_dll_the_script_loads_itself_is_brought_along():
    """`library` is stock, so a DLL loaded through it leaves no plugin trace.

    `plugin_dlls` finds a DLL by matching its stem against a *type* the
    module uses but does not declare, which is what makes `elias.dll`
    evidence. The engine's own `library` type is the other way a game
    depends on a DLL and it registers nothing: `bool load(const string& in)`
    takes the name as an ordinary string literal, so there is no type to
    match and nothing in the recovered source names the file.

    Manamon 2 is the live case -- a `sqlite3_legacy` class whose
    `load_library` calls `library::load("sqlite3.dll")`, with `Unable to
    locate sqlite3.dll.` as its own error text. Recovered without it the
    project compiles, runs, and loses whatever that database held.

    Both halves of the evidence are required, for the reason the pack search
    needs both: a name from the string constants, and a PE file of that name
    sitting beside the executable.
    """
    class _Type:
        def __init__(self, name):
            self.name = name

    class _Func:
        def __init__(self, owner, name):
            self.object_type, self.name = _Type(owner), name

    class _Module:
        def __init__(self, calls, strings):
            self.used_functions, self.used_strings = calls, strings

    with tempfile.TemporaryDirectory() as tmp:
        game = os.path.join(tmp, "game.exe")
        with open(game, "wb") as fh:
            fh.write(b"MZ a game")
        with open(os.path.join(tmp, "sqlite3.dll"), "wb") as fh:
            fh.write(b"MZ a library")
        # a game folder really can hold these, and neither is the answer:
        # one is the system's, and one only has the name.
        with open(os.path.join(tmp, "kernel32.dll"), "wb") as fh:
            fh.write(b"MZ the system's")
        with open(os.path.join(tmp, "notes.dll"), "wb") as fh:
            fh.write(b"this is not a PE file at all")

        strings = ["sqlite3.dll", "kernel32.dll", "notes.dll", "absent.dll",
                   "data.dat"]
        loads = _Module([_Func("library", "load")], strings)
        assert bgt_project.script_loaded_dlls(game, loads) == ["sqlite3.dll"]

        # a module that never calls `library` is not making a claim about
        # any `.dll` string it happens to hold
        quiet = _Module([_Func("sound", "load")], strings)
        assert bgt_project.script_loaded_dlls(game, quiet) == []


def test_a_method_name_inside_a_longer_one_is_still_an_absence():
    """`string::insert` was hidden by `array::insert_at`.

    `method_gap` corroborated an absence by searching the installed
    engine's **raw bytes** for the method name, and `insert` is a substring
    of `insert_at` and `insert_last`, which the array type registers. So
    Manamon 2's `string::insert` and the newer AngelScript `string` it
    comes from went unreported, while `string::erase` -- a name nothing
    else contains -- was reported. A list of registrations has no such
    accidents: 1.3 registers `insert_at` and `insert_last` and no `insert`.
    """
    class _Type:
        def __init__(self, name):
            self.name = name

    class _Func:
        def __init__(self, owner, name):
            self.object_type, self.name = _Type(owner), name

    class _Module:
        classes = ()

        def __init__(self, calls):
            self.used_functions = calls

    with tempfile.TemporaryDirectory() as tmp:
        compiler = os.path.join(tmp, "bgt.exe")
        with open(compiler, "wb") as fh:
            fh.write(b"\x00".join([b"void insert_at(uint, const T&in)",
                                   b"void insert_last(const T&in)"]))
        game = os.path.join(tmp, "game.exe")
        with open(game, "wb") as fh:
            fh.write(b"\x00".join([
                b"void insert_at(uint, const T&in)",
                b"void insert(uint pos, const string &in other)"]))
        module = _Module([_Func("string", "insert"), _Func("string", "insert_at")])
        chm = {"functions": {}, "types": {"string": {"methods": [],
                                                     "properties": []}}}
        real_read = bgt_api.read
        try:
            bgt_api.read = lambda *a, **k: chm
            gap = bgt_project.method_gap(game, module, compiler)
        finally:
            bgt_api.read = real_read
        assert gap == [("string::insert", "game.exe")]


def test_plugin_dlls_are_only_those_matching_a_used_type():
    """A plugin include is evidence, not a list of every DLL in the file."""
    with tempfile.NamedTemporaryFile("wb", suffix=".exe", delete=False) as fh:
        fh.write(b"KERNEL32.dll\x00elias.dll\x00elias @f()\x00unrelated.dll\x00")
        path = fh.name
    try:
        assert bgt_project.plugin_dlls(path, ["elias", "timer"]) == ["elias.dll"]
        assert bgt_project.plugin_dlls(path, ["timer"]) == []
    finally:
        os.unlink(path)


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("ok   %s" % name)
            except Exception as exc:                   # noqa: BLE001
                failures += 1
                print("FAIL %s: %r" % (name, exc))
    print("%d failure(s)" % failures)
    sys.exit(1 if failures else 0)


# -- a switch chain whose last link is a compare, not a table ---------------

def _switch_tail(constant, jump_name, fall_through, default, selector=35, ask=None):
    """Three instructions: `CMPIi sel, K ; JZ case ; JMP elsewhere`.

    `pos` is a dword offset, so each instruction here is two dwords wide,
    which is what the real stream looks like for these opcodes.
    """
    make = lambda i, name, **kw: asreader.Instr(
        pos=100 + 2 * i, op=0, name=name, bc_type="", size=2, **kw)
    instrs = [
        make(0, "CMPIi", w_arg=selector, dw_arg=constant),
        make(1, jump_name, dw_arg=0),
        make(2, "JMP", dw_arg=0),
    ]
    # `_jump_target` reads the branch's own position plus its operand, so the
    # operands are written as deltas from the instruction after the branch.
    instrs[1].dw_arg = 7777 - (instrs[1].pos + instrs[1].size)
    instrs[2].dw_arg = fall_through - (instrs[2].pos + instrs[2].size)

    class Stub:
        pass
    stub = Stub()
    stub.instrs = instrs
    stub.pos_of = {ins.pos: i for i, ins in enumerate(instrs)}
    return decompile.FuncDecompiler._equality_chain(
        stub, 0, 0, selector if ask is None else ask, default)


def test_equality_tail_of_a_switch_chain_becomes_a_case():
    """`case 27:` alone in its range is a compare, and it is still a case.

    Left unrecognised the chain simply stops, and the compare is emitted as a
    branch to the switch's exit -- which the switch handler has already
    consumed, so it is a `goto` to a label that never appears. That was the
    one error in Super Egg Hunt's whole recovery.
    """
    result = _switch_tail(27, "JZ", fall_through=9999, default=9999)
    assert result is not None
    cursor, cases, next_range = result
    assert cases == [(27, 7777)]
    assert cursor == 3                     # the whole chain is consumed
    assert next_range is None              # the fall-through is the default


def test_equality_tail_chains_on_when_the_fall_through_is_not_the_default():
    """A fall-through elsewhere is the next link, not the end of the chain."""
    _, cases, next_range = _switch_tail(27, "JZ", fall_through=4242, default=9999)
    assert cases == [(27, 7777)]
    assert next_range == 4242


def test_equality_tail_refuses_a_compare_on_another_slot():
    """The compare must test what the table normalised.

    A compare on a different slot is an ordinary `if` that happens to sit
    after the table; absorbed as a case it would both invent a case and
    swallow the real branch.
    """
    assert _switch_tail(27, "JZ", 9999, 9999, ask=36) is None


def test_equality_tail_refuses_a_non_adjacent_chain():
    """`cursor` is the span the switch handler skips.

    Extending it to a block that is not adjacent to the table's entries would
    swallow every instruction in between -- which compiles, and drops code.
    """

    class Stub:
        pass
    stub = Stub()
    stub.instrs = []
    stub.pos_of = {}
    assert decompile.FuncDecompiler._equality_chain(stub, 5, 0, 35, 9999) is None


def test_equality_tail_refuses_a_chain_with_no_fall_through():
    """Without a terminating JMP there is nothing to say where a miss goes."""
    assert _switch_tail(27, "JNZ", 9999, 9999) is None


# -- unreachable code, which a warning dialog makes a blocker ---------------

def test_unreachable_code_after_a_return_is_dropped():
    """A warning is not harmless here: BGT reports warnings in a modal dialog
    and waits on it, so an unattended compile never writes its executable.

    This pass had no test and stopped working silently: the word boundaries in
    its pattern were replaced by literal backspace bytes when it was edited,
    which matches nothing, so `return` and `goto` stopped terminating a block
    while `break;` and `continue;` went on working. Nothing failed -- the
    output stayed valid, and two "Unreachable code" warnings per title looked
    like something the compiler had a right to say.
    """
    kept = decompile._drop_unreachable([
        "        if (registered) {",
        "            return true;",
        "        }",
        "        return false;",
        "        return false;",          # unreachable: dropped
    ])
    assert kept == [
        "        if (registered) {",
        "            return true;",
        "        }",
        "        return false;",
    ]


def test_a_label_after_a_return_is_still_live():
    """`case` and `}` end the dead region: something else jumps there."""
    kept = decompile._drop_unreachable([
        "    switch (n) {",
        "        case 1:",
        "            return 1;",
        "        case 2:",
        "            return 2;",
        "    }",
    ])
    assert len(kept) == 6


def test_a_word_that_merely_starts_with_return_is_not_a_terminator():
    """`returned = f();` is an assignment, and the statement after it runs."""
    kept = decompile._drop_unreachable(["    returned = f();", "    g();"])
    assert len(kept) == 2


# -- braces, which the compiler blames on the wrong line --------------------

def test_unbalanced_braces_are_reported_per_file():
    """An unbalanced file cannot parse, and the compiler says so elsewhere.

    A `}` too many closes the class, so every declaration after it comes back
    as "Expected method or property" -- indistinguishable from the engine
    missing a keyword. Manamon 2's `cure_all_statuses` hid behind exactly that
    for a whole session: the structurer fell back to `goto` and emitted the
    arm anyway, leaving `} else {` with no `if`.
    """
    good = bgt_project.Section(kind="class", name="a", text="void f() {\n}\n")
    bad = bgt_project.Section(kind="class", name="b", text="void g() {\n")
    good.path = "includes/a.bgt"
    bad.path = "includes/b.bgt"
    found = bgt_project.unbalanced([good, bad])
    assert found == [("includes/b.bgt", 1)]


def test_a_brace_inside_a_string_is_not_structure():
    """`"{"` is text. Counting it would report every menu as unbalanced."""
    section = bgt_project.Section(kind="class", name="a",
                                  text='void f() {\n    s = "{";\n}\n')
    section.path = "includes/a.bgt"
    assert bgt_project.unbalanced([section]) == []


def test_sections_of_one_file_balance_together():
    """A file is several sections; each may be unbalanced on its own."""
    first = bgt_project.Section(kind="class", name="a", text="void f() {\n")
    second = bgt_project.Section(kind="class", name="b", text="}\n")
    first.path = second.path = "includes/a.bgt"
    assert bgt_project.unbalanced([first, second]) == []


def test_a_dangling_else_shows_up_as_an_imbalance_and_is_named():
    """The arm's closing brace has no opener, so the file is short a `{`.

    That is what separates a recovery bug from an engine keyword: Manamon 2's
    three structurally broken files are -2, -10 and -1 deep, while the file
    that fails only on `protected` balances at zero. `unbalanced` detects it;
    `dangling_else` says which construct it is.
    """
    section = bgt_project.Section(
        kind="class", name="b",
        text="void g() {\n    goto L1;\n    } else {\n        y();\n    }\n}\n")
    section.path = "includes/b.bgt"
    assert bgt_project.unbalanced([section]) == [("includes/b.bgt", -1)]
    assert bgt_project.dangling_else([section]) == [("includes/b.bgt", "} else {")]


def test_a_real_else_is_not_flagged():
    section = bgt_project.Section(
        kind="class", name="a",
        text="void f() {\n    if (c) {\n        x();\n    } else {\n        y();\n    }\n}\n")
    section.path = "includes/a.bgt"
    assert bgt_project.dangling_else([section]) == []


def test_an_else_on_its_own_line_still_sees_its_if():
    """A `}` on one line and `else {` on the next is the same construct;
    flagging it would make every such pair a false alarm."""
    section = bgt_project.Section(
        kind="class", name="a",
        text="void f() {\n    if (c) {\n        x();\n    }\n    else {\n        y();\n    }\n}\n")
    section.path = "includes/a.bgt"
    assert bgt_project.dangling_else([section]) == []


# -- the check that could not run --------------------------------------------

def test_a_check_that_did_not_run_says_why():
    """`nodriver` on its own reads like a result, and it is the opposite.

    Two compile checks ran at once here, one came back blank, and the report
    said `compiler nodriver` with the reason dropped on the floor -- which is
    indistinguishable from a module the compiler had nothing to say about.
    """
    report = bgt_compile.Report(outcome="nodriver", raw="another check holds the lock")
    assert "could not run" in report.summary()
    assert "another check holds the lock" in report.summary()
    assert not report.ok


def test_compile_checks_serialise():
    """One `bgt.exe` at a time: it is driven through the accessibility tree,
    and two at once do not both get read.

    The mechanism is an exclusive create, so that is what is checked -- and
    not by *waiting* on it, because a test that takes a minute is a test
    nobody runs, which is the same failure this whole area is about.
    """
    with bgt_compile._one_at_a_time(60.0) as held:
        assert held
        assert os.path.isfile(bgt_compile._LOCK)
        try:
            os.close(os.open(bgt_compile._LOCK,
                             os.O_CREAT | os.O_EXCL | os.O_WRONLY))
            raise AssertionError("a second holder got the lock")
        except FileExistsError:
            pass
    assert not os.path.isfile(bgt_compile._LOCK)


def test_a_stale_lock_does_not_block_forever():
    """A lock left by a killed run would stop every later check."""
    with open(bgt_compile._LOCK, "w") as fh:
        fh.write("")
    os.utime(bgt_compile._LOCK, (0, 0))               # ancient
    try:
        with bgt_compile._one_at_a_time(1.0) as held:
            assert held
    finally:
        if os.path.isfile(bgt_compile._LOCK):
            os.unlink(bgt_compile._LOCK)


# -- a namespaced copy of a library function --------------------------------

def test_a_namespaced_function_is_keyed_apart_from_the_global_one():
    """The namespace is the only thing telling the two copies apart.

    Manamon 2 declares `position_sound_1d` and `rhythm::position_sound_1d`.
    Attribution gets this right -- the global one is the library's, the
    namespaced one is the game's -- but the section was keyed on the bare
    name, so the namespaced copy inherited the library's file and moved 71
    lines fifty thousand lines earlier. That was the only thing wrong with
    Manamon 2's split, and the only thing `verify` was reporting.
    """
    class Fn:
        def __init__(self, name, namespace):
            self.name, self.namespace_ = name, namespace
            self.bytecode = []

    captured = []

    class Splitter(bgt_project._Splitter):
        def __init__(self):
            pass                                  # no module needed
        def _capture(self, kind, name, render):
            captured.append(name)

    sp = Splitter()
    for fn in (Fn("position_sound_1d", ""), Fn("position_sound_1d", "rhythm")):
        bgt_project._Splitter._render_function(sp, fn)
    assert captured == ["position_sound_1d", "rhythm::position_sound_1d"]


def test_a_goto_does_not_make_what_follows_unreachable():
    """`goto` leaves; it does not end the block.

    What follows a `goto` is a jump target reached from somewhere else, and
    this decompiler does not even emit the labels, so nothing here could
    prove otherwise. Counting it dropped seven live lines from Manamon 2's
    `character::cure_all_statuses` -- including the `if (...) {` -- which left
    `} else {` with no `if` and a file that could not parse. The structurer's
    own output was valid; this pass broke it.
    """
    body = [
        "        goto L003b;",
        "        int local_2 = 1;",
        "        if (arg0) {",
        "        } else {",
        "            x();",
        "        }",
    ]
    assert decompile._drop_unreachable(body) == body


def test_a_return_still_ends_its_block():
    """The pass must still do its job: BGT shows a modal dialog for the
    "Unreachable code" warning and waits on it."""
    kept = decompile._drop_unreachable(["    return 1;", "    return 1;"])
    assert kept == ["    return 1;"]


# -- parentheses after if/while ---------------------------------------------

def test_a_condition_gets_parentheses_unless_they_already_enclose_it():
    """`(0 + 2) < (x)` begins with `(` and ends with `)` and encloses nothing.

    A `startswith`/`endswith` test said it was already parenthesised, so
    nothing was added and the output read `while (0 + 2) < (x) {`. That was
    110 of Crazy Party's compiler errors, across `while` and `do while`. The
    file already had `_encloses` for this question; the condition wrapper was
    asking a different, wrong one.
    """
    assert decompile._condition("(0 + 2) < (x)") == "((0 + 2) < (x))"
    assert decompile._condition("(a) + (b)") == "((a) + (b))"
    assert decompile._condition("x") == "(x)"
    # ...and a condition that really is enclosed is left alone.
    assert decompile._condition("(a && b)") == "(a && b)"


def test_the_delegate_factory_renders_as_a_delegate():
    """Both spellings bind an object and a method; neither is a callable name.

    Left as the factory's own name, Crazy Party emitted
    `fadeOut(arg0, %delegate_factory(), arg1)` 132 times. BGT 1.3 compiles the
    delegate form `CbFade(this.att)`, which was checked by putting it to the
    compiler rather than assumed.
    """
    assert "$dlgte" in decompile.DELEGATE_FACTORIES
    assert "%delegate_factory" in decompile.DELEGATE_FACTORIES


def test_a_global_call_shadowed_by_a_method_is_qualified():
    """`::f(...)` when the enclosing class has its own `f`.

    Crazy Party's `Case::lanceMenu` calls the *global* 8-parameter
    `lanceMenu`. Unqualified, the class's own 6-parameter method shadows it
    and the compiler reports a 6-parameter candidate called with 8 arguments
    -- which reads like a decompiler arity bug and is a scoping one. BGT
    accepts `::f(...)`; that was checked against the compiler.
    """
    class Fn:
        def __init__(self, name):
            self.name = name

    class Ti:
        def __init__(self, methods, base=None):
            self.methods, self.derived_from = methods, base

    class Stub:
        pass

    stub = Stub()
    stub.fn = Fn("caller")
    stub.fn.object_type = Ti([Fn("lanceMenu")])
    assert decompile.FuncDecompiler._shadowed_by_enclosing_class(stub, "lanceMenu")
    assert not decompile.FuncDecompiler._shadowed_by_enclosing_class(stub, "other")

    # An inherited method shadows just as well.
    stub.fn.object_type = Ti([], base=Ti([Fn("inherited")]))
    assert decompile.FuncDecompiler._shadowed_by_enclosing_class(stub, "inherited")

    # A free function with no enclosing class needs no qualification.
    stub.fn.object_type = None
    assert not decompile.FuncDecompiler._shadowed_by_enclosing_class(stub, "anything")


def test_a_delegate_passed_as_an_argument_names_its_funcdef():
    """With no `STOREOBJ` after it there is no slot to take the type from.

    Crazy Party passes the delegate straight into a call, and the bare method
    is rejected: "Can't pass class method as arg directly". The bound
    method's own signature names the funcdef instead -- `Jeu::att(int, bool)`
    against the module's `void CbFade(int, bool)`. Ambiguity is left alone,
    because an unwrapped delegate fails visibly while the wrong funcdef would
    compile and bind the wrong callback.
    """
    class Dt:
        def __init__(self, text):
            self.text = text
        def format(self):
            return self.text

    class Fn:
        def __init__(self, name, ret, params, ns=""):
            self.name, self.return_type = name, Dt(ret)
            self.param_types = [Dt(p) for p in params]
            self.namespace_ = ns

    class Module:
        def __init__(self, funcdefs):
            self.funcdefs = funcdefs

    class Stub:
        pass

    stub = Stub()
    stub.m = Module([Fn("CbFade", "void", ["int", "bool"]),
                     Fn("menu_callback", "int", ["dynamic_menu@", "string"])])
    match = decompile.FuncDecompiler._funcdef_matching
    assert match(stub, Fn("att", "void", ["int", "bool"])) == "CbFade"
    assert match(stub, Fn("other", "int", ["dynamic_menu@", "string"])) == "menu_callback"
    # No funcdef has this shape, and nothing is invented.
    assert match(stub, Fn("nope", "void", ["string"])) == ""
    assert match(stub, None) == ""
    # Two funcdefs of one shape is ambiguous, so neither is chosen.
    stub.m = Module([Fn("A", "void", ["int"]), Fn("B", "void", ["int"])])
    assert match(stub, Fn("x", "void", ["int"])) == ""


# -- a loop whose body folded into its condition ----------------------------

def test_a_back_edge_with_no_events_becomes_an_empty_bodied_loop():
    """`do { y = random(0, h); } while (f(y) < 3);` has no statements left.

    Every statement folds into the condition, so the back edge's target
    resolves to the branch's own event index and there is nothing between
    them to put in a body. An empty-bodied `while (cond) { }` re-evaluates
    the condition per iteration, which is what the loop does -- and unlike a
    `goto` it compiles. This was all 17 of Crazy Party's residual gotos.

    Two earlier attempts missed it: the original handler needs the branch to
    be its slice's last event, and generalising to "the first backward branch
    anywhere in the slice" took the count from 17 to 55 by claiming inner
    loops before the outer ones were recognised.
    """
    # A lone backward branch: its target, 225, lies before the branch at 247
    # and no event sits there, so it resolves to the branch itself.
    events = [decompile.Event("branch", 247, ("(c)", 225))]
    rendered = decompile.Structurer(events, None, ()).render(0)
    assert rendered == ["while (c) {", "}"], rendered
    assert not any("goto" in line for line in rendered)


def test_a_backward_branch_with_a_real_body_is_still_a_do_while():
    """The folded case must not swallow the ordinary one.

    With a statement between the target and the branch there is a body, and
    the existing do-while handling renders it.
    """
    events = [decompile.Event("stmt", 225, ("", "y = roll();")),
              decompile.Event("branch", 247, ("(c)", 225))]
    rendered = decompile.Structurer(events, None, ()).render(0)
    assert "do {" in rendered[0], rendered
    assert any("y = roll();" in line for line in rendered), rendered
    assert not any("goto" in line for line in rendered), rendered


# -- the funcdef the module records only as a placeholder -------------------

def test_the_documented_signature_names_an_engine_funcdef():
    """`_builtin_function_@` is every funcdef, so the module cannot say which.

    AngelScript records funcdef-typed values under one placeholder with no
    signature. The engine's documentation can name it:
    `bool set_callback_function(pathfinder_callback@ callback)`. Without that,
    `pf.set_callback_function(obj.method)` is emitted with the bare method and
    rejected twice over, which was the last error left on Crazy Party.
    """
    placeholder = asreader.TypeInfo(name=bgt_asir.BUILTIN_FUNCTION, kind="app")
    param = asreader.DataType(obj_type=placeholder, is_object_handle=True)
    owner = asreader.TypeInfo(name="pathfinder", kind="app")
    fn = asreader.Function(name="set_callback_function", object_type=owner)
    fn.param_types = [param]
    module = asreader.Module()
    module.used_functions = [fn, None]
    api = {"types": {"pathfinder": {
        "methods": ["bool set_callback_function(pathfinder_callback@ callback)"],
        "properties": []}}}
    assert bgt_asir.name_engine_funcdefs(module, api) == 1
    assert param.obj_type.name == "pathfinder_callback"


def test_an_undocumented_type_is_left_alone():
    """No documentation, no change -- and no invented type name."""
    placeholder = asreader.TypeInfo(name=bgt_asir.BUILTIN_FUNCTION, kind="app")
    param = asreader.DataType(obj_type=placeholder, is_object_handle=True)
    fn = asreader.Function(name="whatever",
                           object_type=asreader.TypeInfo(name="elias", kind="app"))
    fn.param_types = [param]
    module = asreader.Module()
    module.used_functions = [fn]
    assert bgt_asir.name_engine_funcdefs(module, {"types": {}}) == 0
    assert param.obj_type.name == bgt_asir.BUILTIN_FUNCTION


def test_a_documented_signature_of_another_arity_is_not_applied():
    """Overloads differ by arity, and the wrong one would name the wrong type."""
    placeholder = asreader.TypeInfo(name=bgt_asir.BUILTIN_FUNCTION, kind="app")
    param = asreader.DataType(obj_type=placeholder, is_object_handle=True)
    owner = asreader.TypeInfo(name="pathfinder", kind="app")
    fn = asreader.Function(name="set_callback_function", object_type=owner)
    fn.param_types = [param]
    module = asreader.Module()
    module.used_functions = [fn]
    api = {"types": {"pathfinder": {
        "methods": ["bool set_callback_function(int a, int b)"], "properties": []}}}
    assert bgt_asir.name_engine_funcdefs(module, api) == 0
    assert param.obj_type.name == bgt_asir.BUILTIN_FUNCTION




# -- the assets a recovered script will go looking for ----------------------

def _game_folder(tmp, packs=(), junk=()):
    """A folder with an executable, some packs and some decoys."""
    exe = os.path.join(tmp, "game.exe")
    with open(exe, "wb") as fh:
        fh.write(b"MZ" + bytes(64))
    for name, items in packs:
        target = os.path.join(tmp, *name.split("/"))
        os.makedirs(os.path.dirname(target) or tmp, exist_ok=True)
        with open(target, "wb") as fh:
            fh.write(bgt_pack.build(items))
    for name, blob in junk:
        with open(os.path.join(tmp, name), "wb") as fh:
            fh.write(blob)
    return exe


class _Mod:
    """Just the two things `data_packs` and `asset_gaps` read."""

    def __init__(self, strings, called=()):
        self.used_strings = list(strings)
        self.used_functions = [type("F", (), {"name": n})() for n in called]


def test_only_real_packs_beside_the_game_are_claimed():
    """The magic separates a pack from the other names in the constants.

    The calls pass locals -- `set_sound_storage(local_8)` -- so the names come
    from the string constants, which also hold `log.txt`, `save.bin`, `.` and
    `/`. A file is a pack when it starts with `SFPv`, and that is the filter.
    """
    with tempfile.TemporaryDirectory() as tmp:
        exe = _game_folder(tmp,
                           packs=[("data/core.dat", [("beep.ogg", b"OggS")])],
                           junk=[("log.txt", b"not a pack"), ("save.bin", bytes(2))])
        mod = _Mod(["data/core.dat", "log.txt", "save.bin", ".", "/"])
        found = bgt_project.data_packs(exe, mod)
        assert [p["name"] for p in found] == ["data/core.dat"]
        assert found[0]["entries"] == 1 and found[0]["plain"] == 1


def test_a_name_outside_the_game_folder_is_never_followed():
    """A string constant is data: it must not reach out of the game's folder."""
    with tempfile.TemporaryDirectory() as tmp:
        inner = os.path.join(tmp, "game")
        os.makedirs(inner)
        with open(os.path.join(tmp, "outside.dat"), "wb") as fh:
            fh.write(bgt_pack.build([("x", b"1")]))
        exe = _game_folder(inner)
        assert bgt_project.data_packs(exe, _Mod(["../outside.dat"])) == []


def test_a_different_drive_is_outside_rather_than_an_error():
    """`commonpath` raises across drives; that is an answer, not a crash.

    Crazy Party's string constants hit this and the exception escaped
    `bgt recover` entirely.
    """
    sep = os.sep
    assert bgt_project._inside("C:" + sep + "game", "C:" + sep + "game" + sep + "d.dat")
    assert not bgt_project._inside("C:" + sep + "game", "D:" + sep + "else" + sep + "d.dat")
    assert not bgt_project._inside("C:" + sep + "game", "C:" + sep + "other")


def test_copying_keeps_the_name_the_engine_will_ask_for():
    """The engine opens the pack by the relative name the original used, so
    `data/core.dat` has to land at `data/core.dat`."""
    with tempfile.TemporaryDirectory() as tmp:
        exe = _game_folder(tmp, packs=[("data/core.dat", [("a.ogg", b"OggS")])])
        packs = bgt_project.data_packs(exe, _Mod(["data/core.dat"]))
        out = os.path.join(tmp, "project")
        os.makedirs(out)
        notes = bgt_project.bring_data(packs, out)
        assert os.path.isfile(os.path.join(out, "data", "core.dat"))
        assert "copied" in notes[0]


def test_extracting_writes_the_entries_and_stays_inside():
    """An entry name is data too, so a parent-directory name must not escape."""
    with tempfile.TemporaryDirectory() as tmp:
        exe = _game_folder(tmp, packs=[("d.dat", [("music/a.ogg", b"OggS-a"),
                                                  ("../../escape.ogg", b"no")])])
        out = os.path.join(tmp, "project")
        os.makedirs(out)
        notes = bgt_project.bring_data(
            bgt_project.data_packs(exe, _Mod(["d.dat"])), out, extract=True)
        root = os.path.join(out, "assets", "d")
        with open(os.path.join(root, "music", "a.ogg"), "rb") as fh:
            assert fh.read() == b"OggS-a"
        assert not os.path.exists(os.path.join(tmp, "escape.ogg"))
        assert "extracted" in notes[0]


def test_an_encrypted_pack_with_no_key_is_reported_not_written_as_ciphertext():
    """Writing entries that are still encrypted would look like success."""
    with tempfile.TemporaryDirectory() as tmp:
        blob = bgt_pack.encrypt_payload(b"OggS-real-audio", b"k" * 32)
        exe = _game_folder(tmp, packs=[("s.dat", [("a.ogg", blob)])])
        packs = bgt_project.data_packs(exe, _Mod(["s.dat"]))
        assert packs[0]["encrypted"] == 1
        out = os.path.join(tmp, "project")
        os.makedirs(out)
        notes = bgt_project.bring_data(packs, out, extract=True)
        assert "key was not recovered" in notes[0] and "bgt crack" in notes[0]
        assert not os.path.exists(os.path.join(out, "assets"))


def test_an_encrypted_pack_is_decrypted_when_the_key_is_known():
    """With the key, extraction has to produce the plaintext -- the whole point.

    Super Egg Hunt extracted nothing at all because the key was never
    recovered, and the report said so in a line that read like advice. The key
    was in the module.
    """
    with tempfile.TemporaryDirectory() as tmp:
        key = b"k" * 32
        blob = bgt_pack.encrypt_payload(b"OggS-real-audio", key)
        exe = _game_folder(tmp, packs=[("s.dat", [("a.ogg", blob)])])
        packs = bgt_project.data_packs(exe, _Mod(["s.dat"]))
        out = os.path.join(tmp, "project")
        os.makedirs(out)
        keys = {bgt_pack.tag_for_key(key): key}
        notes = bgt_project.bring_data(packs, out, extract=True, keys=keys)
        with open(os.path.join(out, "assets", "s", "a.ogg"), "rb") as fh:
            assert fh.read() == b"OggS-real-audio"
        assert "extracted 1 entries" in notes[0]


def test_an_entry_whose_key_does_not_verify_is_skipped_and_counted():
    """A wrong key must not write a file: ciphertext named `music.ogg` is worse
    than no file, because it looks like the extraction worked."""
    with tempfile.TemporaryDirectory() as tmp:
        good, bad = b"g" * 32, b"b" * 32
        exe = _game_folder(tmp, packs=[
            ("s.dat", [("ok.ogg", bgt_pack.encrypt_payload(b"OggS-ok", good)),
                       ("no.ogg", bgt_pack.encrypt_payload(b"OggS-no", bad))])])
        packs = bgt_project.data_packs(exe, _Mod(["s.dat"]))
        out = os.path.join(tmp, "project")
        os.makedirs(out)
        notes = bgt_project.bring_data(
            packs, out, extract=True,
            keys={bgt_pack.tag_for_key(good): good,
                  # a tag the pack has, mapped to a key that does not satisfy it
                  bgt_pack.tag_for_key(bad): b"x" * 32})
        root = os.path.join(out, "assets", "s")
        assert os.path.isfile(os.path.join(root, "ok.ogg"))
        assert not os.path.exists(os.path.join(root, "no.ogg"))
        assert "1 skipped: no key that verifies" in notes[0]


def test_the_screen_reader_client_is_brought_in_for_a_game_that_speaks():
    """Without `nvdaControllerClient32.dll` beside the script the engine does
    not fail -- it falls back to SAPI, so the game talks in the wrong voice
    and nothing says why. For an audio game that is the whole product.
    """
    with tempfile.TemporaryDirectory() as tmp:
        redist = os.path.join(tmp, "bgt", "redist", "screen_readers")
        for sub, name in (("nvda", "nvdaControllerClient32.dll"),
                          ("system_access", "SAAPI32.dll")):
            os.makedirs(os.path.join(redist, sub), exist_ok=True)
            with open(os.path.join(redist, sub, name), "wb") as fh:
                fh.write(b"MZ-not-really-a-dll")
        out = os.path.join(tmp, "project")
        os.makedirs(out)

        speaking = _Mod([], called=["screen_reader_speak", "key_pressed"])
        copied, notes = bgt_project.speech_clients(
            speaking, out, bgt_roots=[os.path.join(tmp, "bgt")])
        assert copied == ["nvdaControllerClient32.dll", "SAAPI32.dll"]
        assert os.path.isfile(os.path.join(out, "nvdaControllerClient32.dll"))
        assert any("NVDA" in note for note in notes)
        assert any("beside the script" in note for note in notes)

        # A game that never speaks through a screen reader gets nothing: this
        # is evidence from the module, not a DLL scattered into every project.
        quiet = os.path.join(tmp, "quiet")
        os.makedirs(quiet)
        assert bgt_project.speech_clients(
            _Mod([], called=["key_pressed"]), quiet,
            bgt_roots=[os.path.join(tmp, "bgt")]) == ([], [])
        assert os.listdir(quiet) == []


def test_a_missing_screen_reader_client_is_said_out_loud_not_skipped():
    """Falling back to SAPI is the quiet failure, so the absence is reported."""
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "project")
        os.makedirs(out)
        copied, notes = bgt_project.speech_clients(
            _Mod([], called=["screen_reader_speak"]), out,
            bgt_roots=[os.path.join(tmp, "no-bgt-here")])
        assert copied == []
        assert any("fall back to SAPI" in note for note in notes)


def test_copying_and_extracting_can_both_happen_in_one_run():
    """They answer different questions, so they are not alternatives.

    Forcing a choice meant the obvious way to get the assets out left a
    project the engine could not load a pack for -- `ERROR! could not load
    pack data/bgm.dat.`, reported from a real run.
    """
    with tempfile.TemporaryDirectory() as tmp:
        key = b"k" * 32
        blob = bgt_pack.encrypt_payload(b"OggS-real-audio", key)
        exe = _game_folder(tmp, packs=[("data/bgm.dat", [("a.ogg", blob)])])
        packs = bgt_project.data_packs(exe, _Mod(["data/bgm.dat"]))
        out = os.path.join(tmp, "project")
        os.makedirs(out)
        notes = bgt_project.bring_data(
            packs, out, extract=True, copy=True,
            keys={bgt_pack.tag_for_key(key): key})
        # the pack itself, where the script will look for it...
        assert os.path.isfile(os.path.join(out, "data", "bgm.dat"))
        # ...and its contents, decrypted, for reading.
        with open(os.path.join(out, "assets", "bgm", "a.ogg"), "rb") as fh:
            assert fh.read() == b"OggS-real-audio"
        assert any("copied" in note for note in notes)
        assert any("extracted" in note for note in notes)


def test_survey_reports_the_tags_themselves_not_only_how_many():
    """A key search needs the tags, and they are all it needs."""
    with tempfile.TemporaryDirectory() as tmp:
        key = b"k" * 32
        exe = _game_folder(tmp, packs=[
            ("s.dat", [("a.ogg", bgt_pack.encrypt_payload(b"OggS-a", key)),
                       ("b.ogg", bgt_pack.encrypt_payload(b"OggS-b", key)),
                       ("c.ogg", b"OggS-plain")])])
        info = bgt_pack.survey(os.path.join(os.path.dirname(exe), "s.dat"))
        assert info["keys"] == 1
        assert info["tags"] == [bgt_pack.tag_for_key(key)]
        assert info["encrypted"] == 2 and info["plain"] == 1


def test_using_the_asset_apis_with_no_pack_found_is_said_out_loud():
    """Finding nothing is the case that matters.

    Recovering from a copy of the executable -- the normal thing to do --
    finds no pack beside it, and silence there is the surprise to avoid: the
    engine does not quietly do without its sounds.
    """
    with tempfile.TemporaryDirectory() as tmp:
        exe = _game_folder(tmp)
        mod = _Mod(["data/core.dat"],
                   called=["set_sound_storage", "set_sound_decryption_key"])
        notes = bgt_project.asset_gaps(exe, mod, [])
        assert any("no pack was found beside" in n for n in notes)
        assert any("data/core.dat" in n for n in notes)
        assert any("bgt crack" in n for n in notes)
        # A game that never touches the asset APIs gets no warning at all.
        assert bgt_project.asset_gaps(exe, _Mod(["data/core.dat"]), []) == []


# -- library files taken from the engine instead of the module --------------

class _Described:
    """What `script_files.library_index` reports about one shipped file."""

    def __init__(self, classes=(), functions=(), enums=(), globals_=()):
        self.classes = (dict(classes) if isinstance(classes, dict)
                        else {c: set() for c in classes})
        self.functions = list(functions)
        self.enums = list(enums)
        self.globals = list(globals_)


class _Ti:
    def __init__(self, name, methods=(), properties=()):
        self.name = name
        self.methods = [type("M", (), {"name": m})() for m in methods]
        self.properties = [(p, None, 0) for p in properties]


class _Module2:
    def __init__(self, classes=()):
        self.classes = list(classes)


def _lib_section(name, kind, text, origin):
    section = bgt_project.Section(kind=kind, name=name, text=text)
    section.origin = origin
    return section


def test_parameter_types_ignore_names_and_defaults():
    """`tts_voice@ handle` and `voice_manager@ arg0` differ in the only part
    that matters; `bool persistent=false` and `bool arg2 = false` do not."""
    assert bgt_project._param_types("tts_voice@ handle") == ["tts_voice@"]
    assert bgt_project._param_types("voice_manager@ arg0") == ["voice_manager@"]
    assert bgt_project._param_types("string f, bool l, bool p=false") == [
        "string", "bool", "bool"]
    assert bgt_project._param_types("const string&in text") == ["const string&in"]
    assert bgt_project._param_types("") == []


def test_a_file_declaring_its_own_types_is_not_substituted():
    """`form.bgt` declares four enums, and `types.bgt` already carries every
    enum in the module, so taking the stock file too is four name conflicts.
    That is what it did to Psycho Strike."""
    described = _Described(classes=["audio_form"], enums=["control_types"])
    why = bgt_project._why_not_stock("form.bgt", described, "class audio_form {}",
                                     [], _Module2())
    assert "enum" in why


def test_an_added_member_is_not_substituted_away():
    """Super Egg Hunt's `dynamic_menu` has an `is_main` stock BGT lacks.

    Comparing class *names* -- all the first version of this did -- replaced
    it, and the game's own code then failed against the engine's class.
    """
    described = _Described(classes={"dynamic_menu": set()})
    module = _Module2([_Ti("dynamic_menu", methods=["run"], properties=["is_main"])])
    stock = "class dynamic_menu {" + chr(10) + "bool run() { return true; }" + chr(10) + "}"
    section = _lib_section("dynamic_menu", "class", "class dynamic_menu {}",
                       "dynamic_menu.bgt")
    why = bgt_project._why_not_stock("dynamic_menu.bgt", described, stock,
                                     [section], module)
    assert "is_main" in why


def test_a_changed_signature_is_not_substituted_away():
    """Paladin's `set_tts_object` takes its own `voice_manager@` where stock
    takes `tts_voice@`. The names match, which is why names were not enough,
    and the call site is what broke."""
    nl = chr(10)
    described = _Described(classes={"dynamic_menu": set()})
    module = _Module2([_Ti("dynamic_menu", methods=["set_tts_object"])])
    stock = nl.join(["class dynamic_menu {",
                     "bool set_tts_object(tts_voice@ handle)",
                     "{", "return true;", "}", "}"])
    mine = nl.join(["class dynamic_menu {",
                    "    bool set_tts_object(voice_manager@ arg0)",
                    "    {", "        return true;", "    }", "}"])
    section = _lib_section("dynamic_menu", "class", mine, "dynamic_menu.bgt")
    why = bgt_project._why_not_stock("dynamic_menu.bgt", described, stock,
                                     [section], module)
    assert "voice_manager@" in why and "tts_voice@" in why


def test_an_unmodified_library_file_is_substituted():
    """The whole point: when nothing says the game's copy differs, the
    engine's own source beats any decompilation of it."""
    nl = chr(10)
    described = _Described(classes={"number_speaker": set()})
    module = _Module2([_Ti("number_speaker", methods=["speak"],
                           properties=["rate"])])
    stock = nl.join(["class number_speaker {", "int rate;",
                     "bool speak(string text)", "{", "return true;", "}", "}"])
    mine = nl.join(["class number_speaker {", "    int rate;",
                    "    bool speak(string arg0)", "    {",
                    "        return true;", "    }", "}"])
    section = _lib_section("number_speaker", "class", mine, "number_speaker.bgt")
    assert bgt_project._why_not_stock("number_speaker.bgt", described, stock,
                                      [section], module) == ""


# -- which compiler ran, and whether it can read this source ----------------

def test_the_default_argument_probe_is_one_small_script():
    """There is no version string in bgt.exe and no version metadata on the
    file, so the only way to tell two installs apart is to put something to
    them. BGT 1.0 has no default arguments at all."""
    probe = bgt_compile._DEFAULT_ARG_PROBE
    assert "bool b = false" in probe
    assert "void main()" in probe          # it has to be runnable, not just parsable
    assert probe.count(chr(10)) >= 2


def test_default_argument_support_is_read_off_the_executable():
    """Asking the compiler puts a modal dialog in front of the user.

    The probe launches `bgt.exe`, and a `bgt.exe` that rejects the probe
    shows a modal error dialog on whoever is at the machine -- once per
    install, and once per candidate `bgt verbs --repoint` considers. The
    file answers for free, because **the engine registers three of its own
    functions with a default argument**: a registration string goes through
    the same parser a script does, so `string_create_from_pointer(uint,
    uint size=0)` is the feature in use rather than a marker that might
    coincide with it. The compiler also carries the diagnostics for a bad
    default argument, and a message exists only if the code path that emits
    it does.

    Both markers must agree, and on the two installs here they do. Where
    they disagree the file declines and the probe decides, because that is
    the case a reader should refuse rather than answer.

    **A negative needs a legible interface**, which is the guard that makes
    this safe rather than merely cheap: both markers are absences, and
    everything is absent from a file this cannot read -- a stub, or a packed
    `bgt.exe` whose strings sit inside the compressed image, which is not
    hypothetical when BGT's own runtime ships that way inside `exec.bin`.
    """
    def engine(path, extra=b""):
        body = b"\x00".join(b"void fn%d(int a)" % n for n in range(60))
        with open(path, "wb") as fh:
            fh.write(body + b"\x00" + extra)

    with tempfile.TemporaryDirectory() as tmp:
        yes = os.path.join(tmp, "yes.exe")
        engine(yes, b"\x00".join([
            b"string string_create_from_pointer(uint, uint size=0)",
            b"default arg for parameter %d in function '%s'"]))
        assert bgt_compile._default_args_in_binary(yes) is True

        no = os.path.join(tmp, "no.exe")
        engine(no)
        assert bgt_compile._default_args_in_binary(no) is False

        # one marker without the other is not an answer
        half = os.path.join(tmp, "half.exe")
        engine(half, b"default arg for parameter %d in function '%s'")
        assert bgt_compile._default_args_in_binary(half) is None

        # ...and neither is a file whose interface cannot be read at all,
        # which is what keeps a packed or stubbed engine out of the answer.
        stub = os.path.join(tmp, "stub.exe")
        with open(stub, "wb") as fh:
            fh.write(b"MZ not really")
        assert bgt_compile._default_args_in_binary(stub) is None
        assert bgt_compile._default_args_in_binary(
            os.path.join(tmp, "absent.exe")) is None


def test_capabilities_are_cached_per_compiler():
    """The probe compiles a script, so asking twice must not pay twice."""
    bgt_compile._CAPABILITIES.clear()
    bgt_compile._CAPABILITIES["X:/fake/bgt.exe"] = {"default_arguments": False}
    real = bgt_compile.find_compiler
    try:
        bgt_compile.find_compiler = lambda explicit=None: "X:/fake/bgt.exe"
        assert bgt_compile.capabilities() == {"default_arguments": False}
    finally:
        bgt_compile.find_compiler = real
        bgt_compile._CAPABILITIES.clear()


def test_no_compiler_means_no_claim_about_it():
    """With nothing found there is nothing to say, and guessing `True` would
    be the dangerous direction."""
    real = bgt_compile.find_compiler
    try:
        bgt_compile.find_compiler = lambda explicit=None: None
        assert bgt_compile.capabilities() == {}
    finally:
        bgt_compile.find_compiler = real


class _FakeKey:
    def __init__(self, path):
        self.path = path

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeWinreg:
    """Just enough of `winreg` to watch what repoint/restore would write.

    `repoint_verbs` imports winreg *inside* the function, so substituting the
    module in `sys.modules` reaches it without touching the machine's own
    registry -- which matters, because a test that rewrites a file association
    is a test that changes the computer it runs on.
    """
    HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE = 0, 1, 2
    REG_SZ = 1

    def __init__(self, existing=None):
        self.written = {}
        self.deleted = []
        self.existing = dict(existing or {})

    def CreateKey(self, root, path):
        return _FakeKey((root, path))

    def SetValueEx(self, handle, name, reserved, kind, value):
        self.written[handle.path] = value

    def OpenKey(self, root, path, *rest):
        if (root, path) not in self.existing:
            raise OSError(2, "no such key")
        return _FakeKey((root, path))

    def QueryValueEx(self, handle, name):
        return self.existing[handle.path], self.REG_SZ

    def DeleteKey(self, root, path):
        if (root, path) not in self.existing:
            raise OSError(2, "no such key")
        del self.existing[(root, path)]
        self.deleted.append(path)


def _with_fake_registry(body, existing=None, **patches):
    """Run `body(fake)` with a fake winreg and `bgt_compile` attrs patched."""
    fake = _FakeWinreg(existing=existing)
    saved_module = sys.modules.get("winreg")
    saved = {name: getattr(bgt_compile, name) for name in patches}
    sys.modules["winreg"] = fake
    try:
        for name, value in patches.items():
            setattr(bgt_compile, name, value)
        return body(fake)
    finally:
        for name, value in saved.items():
            setattr(bgt_compile, name, value)
        if saved_module is None:
            sys.modules.pop("winreg", None)
        else:
            sys.modules["winreg"] = saved_module


def test_the_merged_view_is_what_the_shell_reads_not_hklm():
    """HKCU outranks HKLM, and reading them the other way round hides the fix.

    `shell_verbs` used to try HKLM first and stop on the first hit. The shell
    resolves a ProgID through `HKEY_CLASSES_ROOT`, where a per-user key wins --
    so once `bgt verbs --repoint` writes that key, the old order went on
    reporting the *overridden* path. The one check able to confirm the repoint
    would have denied it, which is the worst shape a check can have.
    """
    assert bgt_compile._VERB_HIVES[0] == "HKEY_CLASSES_ROOT"
    hives = list(bgt_compile._VERB_HIVES)
    assert hives.index("HKEY_CURRENT_USER") < hives.index("HKEY_LOCAL_MACHINE")
    # HKCR is already rooted at the class table; the other two are not, and a
    # missing `SOFTWARE\Classes` would read nothing while looking fine.
    assert bgt_compile._VERB_KEYS["HKEY_CLASSES_ROOT"].startswith("bgtscript")
    # The hive name is validated against that same tuple, so the list and the
    # lookup cannot drift apart without something failing.
    try:
        bgt_compile.verb_commands("HKEY_USERS")
    except ValueError:
        pass
    else:
        raise AssertionError("an unknown hive must be refused, not guessed")
    for hive in ("HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE"):
        assert bgt_compile._VERB_KEYS[hive].startswith("SOFTWARE" + chr(92) + "Classes")


def test_repointing_a_verb_keeps_the_switch_that_decides_what_it_does():
    """Only the executable is substituted, never the rest of the command.

    The switch is the whole difference between running a script and compiling
    it -- `open` passes it bare, `compile` passes `-c"%1"` and
    `compile_release` `-C"%1"`. Rebuilding the command from a table of
    switches would work right up until BGT's installer used a different one,
    and a verb that silently started *running* a game instead of compiling it
    would look exactly like a repoint that had worked.
    """
    old = "C:" + chr(92) + "BGTV1.0" + chr(92) + "bgt.exe"
    new = "C:" + chr(92) + "BGT" + chr(92) + "bgt.exe"
    commands = {"open": '"%s" "%%1"' % old,
                "run": '"%s" "%%1"' % old,
                "compile": '"%s" -c"%%1"' % old}

    result = {}

    def body(fake):
        result["changed"] = bgt_compile.repoint_verbs()
        result["written"] = dict(fake.written)

    _with_fake_registry(body,
                        verb_commands=lambda *a, **k: dict(commands),
                        capabilities=lambda exe: {"default_arguments": True},
                        find_compiler=lambda explicit=None: new)

    changed = result["changed"]
    assert [v for v, _, _ in changed] == ["open", "run", "compile"]
    assert all(was == old and now == new for _, was, now in changed)
    written = {path[1].split(chr(92))[-2]: value
               for path, value in result["written"].items()}
    assert written["open"] == '"%s" "%%1"' % new
    assert written["run"] == '"%s" "%%1"' % new
    assert written["compile"] == '"%s" -c"%%1"' % new     # the switch survived


def test_repointing_refuses_an_engine_with_the_same_gap():
    """Pointing the shell at a second BGT 1.0 would report success and fix
    nothing. An inconclusive capability is refused the same way: this writes
    to the user's machine, so it declines rather than guesses."""
    commands = {"open": '"C:' + chr(92) + 'old.exe" "%1"'}

    for caps in ({"default_arguments": False}, {}):
        seen = {}

        def body(fake, caps=caps, seen=seen):
            try:
                bgt_compile.repoint_verbs()
            except RuntimeError as exc:
                seen["error"] = str(exc)
            seen["written"] = dict(fake.written)

        _with_fake_registry(body,
                            verb_commands=lambda *a, **k: dict(commands),
                            capabilities=lambda exe, caps=caps: dict(caps),
                            find_compiler=lambda explicit=None: "C:" + chr(92) + "other.exe")
        assert "error" in seen, "a compiler with the same gap must be refused: %r" % caps
        assert seen["written"] == {}, "a refusal must not have written anything"


def test_repointing_is_idempotent_and_leaves_a_correct_verb_alone():
    """A verb already on the right engine is not rewritten, so running this
    twice does not accumulate per-user keys -- and `--repoint` on a healthy
    machine reports honestly that there was nothing to do. The comparison is
    case-insensitive because the registry's spelling of a path is not."""
    good = "C:" + chr(92) + "BGT" + chr(92) + "bgt.exe"
    result = {}

    def body(fake):
        result["changed"] = bgt_compile.repoint_verbs()
        result["written"] = dict(fake.written)

    _with_fake_registry(body,
                        verb_commands=lambda *a, **k: {
                            "open": '"%s" "%%1"' % good,
                            "compile": '"%s" -c"%%1"' % good.lower()},
                        capabilities=lambda exe: {"default_arguments": True},
                        find_compiler=lambda explicit=None: good)
    assert result["changed"] == []
    assert result["written"] == {}


def test_the_undo_is_structural_rather_than_a_saved_copy():
    """`restore_verbs` deletes the override and HKLM's value applies again by
    construction. There is no backup file to lose and no way for the restore
    to write a path that was never registered -- which is what makes changing
    the association safe to offer at all."""
    hkcu = _FakeWinreg.HKEY_CURRENT_USER
    base = "SOFTWARE" + chr(92) + "Classes" + chr(92) + "bgtscript" + chr(92) + "shell"
    existing = {(hkcu, base + chr(92) + "open" + chr(92) + "command"): "x",
                (hkcu, base + chr(92) + "run" + chr(92) + "command"): "y"}
    result = {}

    def body(fake):
        result["removed"] = bgt_compile.restore_verbs()
        result["written"] = dict(fake.written)
        result["deleted"] = list(fake.deleted)

    _with_fake_registry(body, existing=existing)
    assert result["removed"] == ["open", "run"]
    assert result["written"] == {}, "an undo writes nothing, it only removes"
    assert all("command" in path for path in result["deleted"])


def test_the_driver_never_declares_a_parameter_named_switch():
    """A PowerShell parameter named `$Switch` breaks every `switch` statement
    in that script, silently.

    The driver picked its mode with
    `$flag = switch ($Switch) { "debug" {"-c"} "release" {"-C"} ... }`, and
    with `$Switch` declared in the `param()` block that statement matched
    nothing. `$flag` was always empty, so the driver passed no switch and the
    engine *ran* the script instead of compiling it -- and a disarmed entry
    point exiting 0 is exactly the compile-only success case, so
    `bgt compile --build` reported `compiled cleanly` and produced **no
    executable**, in either mode, while `bgt.exe -C"<path>"` by hand built one
    fine. Run mode passes no flag at all, so it was right by accident and hid
    the whole thing.

    This is the shape the repository keeps meeting: not a wrong answer, a
    confident one from a run that never happened.
    """
    driver = bgt_compile.DRIVER
    param_block = driver[driver.index("param("):driver.index(")", driver.index("param("))]
    assert "$Switch" not in param_block, (
        "a parameter named $Switch makes every `switch` statement in the "
        "driver evaluate to nothing")
    # The mode really is chosen by a `switch`, so the hazard is live rather
    # than hypothetical -- and the name Python passes has to be the name the
    # driver declares, or the default silently wins again.
    assert "switch ($Mode)" in driver
    assert "[string]$Mode" in param_block
    source = inspect.getsource(bgt_compile._check)
    assert '"-Mode"' in source, "the call site must pass the parameter the driver declares"
    assert '"-Switch"' not in source


def test_build_mode_asks_for_a_flag_and_run_mode_does_not():
    """`-c` / `-C` compile to an executable; no switch runs the script. The
    two are opposite outcomes, so the mapping is worth pinning: every value
    the Python side can send must reach a flag the engine documents."""
    driver = bgt_compile.DRIVER
    mapping = driver[driver.index("$flag = switch"):]
    mapping = mapping[:mapping.index(chr(10))]
    assert '"debug" { "-c" }' in mapping
    assert '"release" { "-C" }' in mapping
    # ...and those are exactly the choices the CLI offers, so none of them can
    # fall through to the default and quietly become a run.
    parser_source = inspect.getsource(bgt_compile.main)
    assert 'choices=("debug", "release")' in parser_source


# -- reading a recovered project's calls back ------------------------------

def test_a_line_comment_inside_a_string_literal_does_not_eat_the_quote():
    """Comments and strings have to be scrubbed in ONE left-to-right pass.

    Each construct can contain the other's opener, so two regexes applied in
    sequence desynchronise. Manamon 2 calls

        url_get("http://www.vgstorm.com/playmmn.txt");

    and a comment pass run first eats `//www.vgstorm...` as a line comment,
    taking the string's closing quote with it -- after which every quote in
    the rest of the file pairs with the wrong partner. That reported a
    one-argument call as taking ten, and then thirty-three.
    """
    text = 'f("http://a.com/b");\ng("x");  // a real comment\nh("i // j");\n'
    scrubbed = bgt_apicheck.scrub(text)
    assert len(scrubbed) == len(text), "byte positions must be preserved"
    # Every call survives, and each one has exactly one argument.
    for name in ("f", "g", "h"):
        at = scrubbed.index(name + "(")
        args, _ = bgt_apicheck.split_args(scrubbed, scrubbed.index("(", at))
        assert len(args) == 1, (name, args)
    assert "a real comment" not in scrubbed
    assert "vgstorm" not in scrubbed


def test_a_declaration_is_not_a_call():
    """`string serialize(dictionary@ d)` in a class body is a definition.

    Read as a call it is a two-argument call to the engine's registered
    `serialize`, which takes one -- and every class in Manamon 2 that
    declares one produced that false positive. What tells them apart is the
    token before the name: a declaration has a *type* there, a call has an
    operator, a bracket or a keyword.
    """
    assert bgt_apicheck.is_a_declaration("    string serialize(", 11)
    assert bgt_apicheck.is_a_declaration("void act()", 5)
    assert not bgt_apicheck.is_a_declaration("    return serialize(", 11)
    assert not bgt_apicheck.is_a_declaration("    x = serialize(", 8)
    assert not bgt_apicheck.is_a_declaration("    f(serialize(", 6)


def test_a_dropped_or_added_argument_is_reported():
    """The check that the compiler cannot run on Manamon 2.

    The simulation pops a callee's declared arity by construction, so this
    can only ever be a defect of the *rendering* -- which is exactly what
    temporary folding has introduced before.
    """
    known = {"string_replace": {(4, 4)}, "random": {(2, 2)},
             "garbage_collect": {(0, 1)}}
    def arity(call):
        args, _ = bgt_apicheck.split_args(call, call.index("("))
        return len(args)
    assert arity("string_replace(a, b, c, d)") == 4
    assert arity("string_replace(a, b, c)") == 3
    assert arity("garbage_collect()") == 0
    # A nested call is one argument, not three.
    assert arity("random(f(a, b), c)") == 2
    fits = lambda n, name: any(low <= n <= high for low, high in known[name])
    assert fits(4, "string_replace") and not fits(3, "string_replace")
    # A default argument widens the range rather than fixing it: Manamon 2's
    # own build declares `void garbage_collect(int number_of_cycles=0)`.
    assert fits(0, "garbage_collect") and fits(1, "garbage_collect")


def test_a_registered_types_constructor_is_declined_rather_than_guessed():
    """AngelScript registers every constructor under the literal name `f`.

    The owner type is a separate string argument, so `vector @f()` and `void
    f(float, float y=0, float z=0)` sit in the binary with nothing to say
    which type either belongs to. Taking the union of every `f` would accept
    0 to 3 arguments for anything, which is not a check -- so a call of a
    registered type's name is counted and not judged.
    """
    with tempfile.TemporaryDirectory() as tmp:
        exe = os.path.join(tmp, "game.exe")
        with open(exe, "wb") as fh:
            fh.write(b"\x00".join([b"vector @f()",
                                   b"void f(float, float y = 0, float z = 0)",
                                   b"int random(int, int)"]))
        reg = bgt_api.registered(exe)
        assert bgt_apicheck.declaration_arity(reg["random"][0]) == (2, 2)
        # The factory's own arities are readable; whose they are is not.
        assert sorted(map(bgt_apicheck.declaration_arity, reg["f"])) == [(0, 0),
                                                                        (1, 3)]
        assert "vector" in bgt_api.registered_types(decls=reg)


def test_a_funcdef_parameter_is_named_from_the_runtime_with_no_help_file():
    """Recovery does not need BGT installed; the game's own runtime is input.

    A registered **funcdef** is declared the way a function is, so it appears
    in `registered()` under its own name -- while a registered **type** never
    does, because a type's constructors are all declared under `f`. That is
    the direct test for "this parameter names a callback", and it is the
    whole surface: every BGT binary measured, 2010 to 2019 and two forks,
    registers exactly one funcdef.
    """
    with tempfile.TemporaryDirectory() as tmp:
        exe = os.path.join(tmp, "game.exe")
        with open(exe, "wb") as fh:
            fh.write(b"\x00".join([
                b"int pathfinder_callback(int x, int y, string data)",
                b"bool set_callback_function(pathfinder_callback@)",
                b"pathfinder @f()",
            ]))
        placeholder = asreader.TypeInfo(name=bgt_asir.BUILTIN_FUNCTION,
                                        kind="app")
        param = asreader.DataType(obj_type=placeholder, is_object_handle=True)
        callee = asreader.Function(name="set_callback_function",
                                   param_types=[param],
                                   object_type=asreader.TypeInfo(name="pathfinder"))
        module = asreader.Module(used_functions=[callee])
        # No documentation at all, and it is still named.
        assert bgt_asir.name_engine_funcdefs(module, api={}, exe=exe) == 1
        assert param.obj_type.name == "pathfinder_callback"


def test_a_funcdef_in_call_position_is_a_delegate_not_a_call():
    """`pathfinder_callback(arg0.callbackPf)` binds one method.

    It does not call the callback with the five arguments it declares, so a
    funcdef's own arity is the wrong thing to check a *call* of its name
    against -- which reported all thirteen of Crazy Party's delegates as
    mismatches. A funcdef in call position always takes exactly one
    argument, whatever its signature says.

    The module names its own funcdefs. A registered one is told from a
    registered function by the evidence that names it in the first place:
    its name is used as a parameter type somewhere in the registrations,
    which is true of a callback and of nothing else.
    """
    with tempfile.TemporaryDirectory() as tmp:
        exe = os.path.join(tmp, "game.exe")
        with open(exe, "wb") as fh:
            fh.write(b"\x00".join([
                b"int pathfinder_callback(int x, int y, string data)",
                b"bool set_callback_function(pathfinder_callback@)",
                b"int random(int, int)",
            ]))
        reg = bgt_api.registered(exe)
        module = asreader.Module(
            funcdefs=[asreader.Function(name="menu_callback",
                                        param_types=[asreader.DataType(),
                                                     asreader.DataType()])])
        names = bgt_apicheck.funcdef_names(module, reg)
        assert names == {"menu_callback", "pathfinder_callback"}
        # `random` is registered and is nobody's parameter type, so it keeps
        # the arity it declares.
        known = bgt_apicheck.arities(module, reg)
        assert known["pathfinder_callback"] == {(1, 1)}
        assert known["menu_callback"] == {(1, 1)}
        assert known["random"] == {(2, 2)}
        # ...and a name that is BOTH keeps both readings. Manamon 2 declares
        # a global funcdef `event` and the class `rhythm::event`, and
        # *replacing* the entry rather than adding to it threw the class's
        # constructor away and reported five good `event()` calls as taking
        # too few arguments. A name-keyed oracle unions; it never replaces.
        module.funcdefs.append(asreader.Function(name="event", func_type=4))
        module.classes.append(asreader.TypeInfo(name="event", kind="class",
                                                namespace_="rhythm"))
        both = bgt_apicheck.arities(module, reg)
        assert (0, 0) in both["event"], "the class constructor survives"
        assert (1, 1) in both["event"], "and so does the delegate"
