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

import os
import sys
import tempfile

try:                                   # after `pip install -e .`
    from bgtdecomp import bgt_api, bgt_asir, bgt_compile, bgt_project
    from bgtdecomp.nvgt import asreader, decompile
except ImportError:                    # straight from a checkout
    TOOLS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools")
    sys.path.insert(0, TOOLS)
    sys.path.insert(0, os.path.join(TOOLS, "nvgt"))
    import asreader
    import bgt_api
    import bgt_asir
    import decompile
    import bgt_compile
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
        assert bgt_api.missing(["string_split", "timer", "weakref"], api) == ["weakref"]


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
