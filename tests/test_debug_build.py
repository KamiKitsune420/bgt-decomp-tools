"""
Known-answer tests for a DEBUG build -- BGT's `-c`, which keeps the names.

This project said for a long time that a game's own file names, parameter
names and local variable names are "stripped and unrecoverable". That is
true of a release build (`-C`) and false of a debug one, and Air Puck 2PE
ships both halves built with `-c`. What those modules needed was one
placement:

  * the private/protected TRAITS BYTE sits in the middle of the debug
    fields, not after them. The engine writes the line numbers, the script
    sections and the variables as the last thing in the
    `funcType == asFUNC_SCRIPT` branch, closes the branch with that byte,
    and only then writes the script section, the declaration position and
    the parameter names. Read as one run, every record is one byte short and
    the class block desynchronises on the factory that follows -- which is
    exactly how it failed.

and, around it, three things that fail quietly:

  * the `noDebugInfo` flag IS byte 0, so a reader built over a FRAGMENT
    starting at 0 has no head above it -- and the first byte of a class
    block is a null marker, which reads as "debug build"
  * a variable's stack offset is stored plain and signed, not as the newer
    generation's `offset << 1 | onHeap`: read with that shift, two
    parameters at -1 and -2 both come back at -1
  * the source-path scan reads ONE byte of length, which is right for the
    2010-2012 generation's plain base-128 integer and wrong for every build
    since -- so a path of 64 characters or more lost its `.bgt` and was
    dropped, silently, and Air Puck's server named one file where it names
    fourteen

Synthetic inputs only -- no game files -- so these run anywhere.

Run:  python tests/test_debug_build.py    (or: python -m pytest tests/ -q)
"""

import os
import sys

try:                                   # after `pip install -e .`
    from bgtdecomp import as_module, bgt_asir, bgt_project, script_files
except ImportError:                    # straight from a checkout
    sys.path.insert(0, os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
    import as_module
    import bgt_asir
    import bgt_project
    import script_files

NUL = b"\x00"

_OPCODES = {0: {"name": "RET", "type": 1, "stackInc": 0, "operands": 0,
                "dwords": 1}}


def _eu(v):
    """ReadEncodedUInt64's encoding, for the widths these fixtures need."""
    if v < 64:
        return bytes([v])
    if v < (1 << 14):
        return bytes([0x40 | (v >> 8), v & 0xFF])
    raise ValueError("fixture only covers the one- and two-byte forms")


def _eu_signed(v):
    """The lead byte's top bit is a sign flag, so a small negative is one byte."""
    if not -64 < v <= 0:
        raise ValueError("fixture only covers small negatives")
    return bytes([0x80 | (-v)])


def _str(s):
    """A `tagged` new-string record: 'n', an encoded length, then the bytes."""
    return b"\x6e" + _eu(len(s)) + s if s else NUL


def _dt(token=68):
    """A fresh primitive data type: eu(0) eu(token) u8(flags)."""
    return NUL + _eu(token) + NUL


def _debug_function(traits_last=False):
    """One `tagged` funcType-1 record from a DEBUG build.

    `traits_last` builds it the way this reader used to expect -- the six
    debug fields in one run and then the traits byte -- which is the reading
    the format refuses.
    """
    head = (b"f" + _str(b"speak")
            + _dt(80)                          # returns void
            + _eu(1) + _dt(68)                 # one int parameter
            + _eu(1) + _eu(1)                  # inOut: written unconditionally
            + _eu(1)                           # funcType 1 -- a script function
            + NUL                              # 0 default arguments
            + NUL                              # owner: null
            + NUL                              # ...so a namespace string
            + _eu(1) + bytes([0])              # one instruction: RET
            + _eu(4)                           # stackNeeded
            + NUL                              # 0 object variables
            + NUL)                             # 0 objInfo entries
    # Line numbers are pairs: a program position, then `line | col << 20`.
    # Both fit the two-byte form here, so the pair is 0 and line 300.
    line_numbers = _eu(2) + _eu(0) + _eu(300)
    sections = _eu(0)
    variables = (_eu(1)                        # one declared variable
                 + _eu(0)                      # declared at program position 0
                 + _eu(1)                      # stack offset 1 -- a local
                 + _str(b"total")
                 + _dt(68))
    traits = bytes([2])                        # protected
    tail = (_str(b"game.bgt")
            + _eu(7)                           # declaredAt
            + _eu(1) + _str(b"howmany"))       # one parameter name
    if traits_last:
        return head + line_numbers + sections + variables + tail + traits
    return head + line_numbers + sections + variables + traits + tail


def _reader(record, pos=1):
    """A reader over a debug module, positioned past the `noDebugInfo` byte."""
    return as_module.Reader(NUL + record, as_module.TAGGED, pos,
                            opcodes=_OPCODES)


def test_the_traits_byte_sits_between_the_two_halves_of_the_debug_block():
    """Every field of a debug record, read back by value.

    A placement error cannot change how many fields there are, so the extent
    would match either way -- the values are the discriminator. `scriptSection`
    is what reads the traits byte under the wrong order.
    """
    record = _debug_function()
    r = _reader(record)
    rec = r.function()
    assert r.p == len(record) + 1, (r.p, len(record) + 1)
    assert rec["name"] == "speak", rec["name"]
    assert rec["traits"] == 2, rec["traits"]
    assert rec["scriptSection"] == b"game.bgt", rec["scriptSection"]
    assert rec["declaredAt"] == 7, rec["declaredAt"]
    assert rec["paramNames"] == [b"howmany"], rec["paramNames"]
    assert rec["lineNumbers"] == [0, 300], rec["lineNumbers"]
    assert len(rec["variables"]) == 1, rec["variables"]
    assert rec["variables"][0]["name"] == b"total"
    assert rec["variables"][0]["stack_offset"] == 1


def test_the_old_placement_is_refused_rather_than_misread():
    """The same record with the traits byte moved to the end.

    Two readings that both merely *consume* the bytes would not be a
    discriminator -- so the one that is wrong has to fail. It does: the
    traits byte lands where a string tag is read, and 0x02 is not one.
    """
    r = _reader(_debug_function(traits_last=True))
    try:
        r.function()
    except (as_module.ParseError, IndexError):
        return
    raise AssertionError("the wrong traits-byte placement was accepted")


def test_a_fragment_reader_is_not_a_debug_build():
    """`noDebugInfo` IS byte 0, so only a reader starting after it has one.

    A `Reader` built over a class block on its own begins at 0, where the
    first byte is a null type-info marker -- and taking that for the flag
    made such a reader look for debug fields that are not there.
    """
    block = NUL + NUL + NUL + NUL + _eu(0) + _eu(0)
    assert as_module.Reader(block, as_module.TAGGED, 0).debug_info is False
    assert as_module.Reader(NUL + block, as_module.TAGGED, 1).debug_info is True
    # ...and the release case stays false wherever it starts.
    assert as_module.Reader(b"\x01" + block, as_module.TAGGED, 1).debug_info is False


def test_a_variables_stack_offset_is_plain_and_signed():
    """Two parameters at -1 and -2, which is where this project says they live.

    The newer generation stores `offset << 1 | onHeap`; this one stores the
    offset. Read with the shift, -1 and -2 both come back as -1 on the heap
    -- which is one name for two parameters and reads perfectly.
    """
    record = (b"f" + _str(b"add")
              + _dt(80) + _eu(2) + _dt(68) + _dt(68)
              + _eu(2) + _eu(1) + _eu(1)
              + _eu(1) + NUL + NUL + NUL
              + _eu(1) + bytes([0]) + _eu(4) + NUL + NUL
              + _eu(0)                                  # no line numbers
              + _eu(0)                                  # no sections
              + _eu(2)
              + _eu(0) + _eu_signed(-1) + _str(b"item") + _dt(68)
              + _eu(0) + _eu_signed(-2) + _str(b"id") + _dt(68)
              + bytes([0])
              + _str(b"game.bgt") + _eu(1) + _eu(0))
    rec = _reader(record).function()
    offsets = [v["stack_offset"] for v in rec["variables"]]
    assert offsets == [-1, -2], offsets
    assert [v["name"] for v in rec["variables"]] == [b"item", b"id"]


def test_a_walk_that_fails_says_why():
    """`tail_error` is set only once the class blocks complete, so a module
    that died in its head reached the caller as "unknown" -- which names
    neither the failure nor the place, and a probe had to be written to see
    what Air Puck's modules were actually doing."""
    walk = as_module._walk(b"\x00\x05\xff\xff\xff\xff", as_module.TAGGED, 2,
                           n_enums=5, opcodes=None, template_namespace=True)
    assert walk["tail"] is None
    assert walk["tail_error"], "a failed walk reported no reason at all"
    assert "0x" in walk["tail_error"], walk["tail_error"]


# --------------------------------------------------------------------------
# the source paths a debug module names
# --------------------------------------------------------------------------

def test_a_long_source_path_is_not_truncated_by_the_length_field():
    """A 68-character path encodes its length as two bytes in this generation.

    Read as one byte it is 64 characters, which loses the `.bgt` and then
    loses the path -- so Air Puck's server named one file where it names
    fourteen, and nothing said so.
    """
    long_path = b"C:\\Users\\Tunmi\\Documents\\AirPuck 2PE\\BGT\\x\\includes\\puck.bgt"
    long_path = long_path + b"a" * (68 - len(long_path) - 4) + b".bgt"
    assert len(long_path) == 68, len(long_path)
    module = b"junk" + _str(long_path) + b"junk"
    assert script_files.script_sections(module) == [long_path.decode("latin1")]


def test_a_plain_base_128_length_still_reads():
    """The 2010-2012 generation encodes 68 as one byte, and both readings are
    offered because nothing in a scan says which generation wrote it."""
    path = b"E:\\C++ tests\\Bgt\\Games\\Grodan Gun\\groda.bgt"
    path = path + b"b" * (70 - len(path) - 4) + b".bgt"
    assert len(path) == 70, len(path)
    module = b"\x6e" + bytes([len(path)]) + path
    assert script_files.script_sections(module) == [path.decode("latin1")]


def test_a_short_path_reads_the_same_under_either_generation():
    """Under 64 characters there is only one reading, so this pins that the
    wider search did not disturb the case that already worked."""
    path = b"includes/menu.bgt"
    assert script_files.script_sections(_str(path)) == [path.decode("latin1")]


def test_a_records_source_path_is_read_under_either_readers_key():
    """`as_module` calls it `scriptSection` and `as_early` calls it `section`.

    Asking for one key left the 2010-2012 titles' own file names reaching
    `bgt files` only through the scan -- and a scan cannot prove a module is
    a debug build, because a release build can hold a `.bgt` name as an
    ordinary literal. Crazy Party generates part of its own source and
    carries `ajouteLangue.bgt`, and the scan reported that as a file list.
    """
    assert script_files.record_section({"scriptSection": b"a.bgt"}) == b"a.bgt"
    assert script_files.record_section({"section": "b.bgt"}) == "b.bgt"
    assert script_files.record_section({"section": None}) is None
    assert script_files.record_section({}) is None
    assert script_files.record_section(None) is None


# --------------------------------------------------------------------------
# the project layout
# --------------------------------------------------------------------------

def _section(kind, name, source_file="", declared_at=0):
    return bgt_project.Section(kind=kind, name=name, text="// %s\n" % name,
                               source_file=source_file,
                               declared_at=declared_at)


def test_the_reorder_is_inert_without_recorded_file_names():
    """Every title in this project's notes but Air Puck is a release build, so
    this must not touch one: the module's order is the only order there is."""
    sections = [_section("class", "a"), _section("function", "b"),
                _section("class", "c")]
    before = list(sections)
    assert bgt_project.reorder_by_file(sections) is False
    assert sections == before


def test_a_named_file_becomes_contiguous_in_source_order():
    """The module makes one pass over the types and another over the global
    functions, so a file's class sits a long way from its functions. Grouping
    by the real file name therefore moves declarations -- which is what
    `verify` reports, correctly -- so the order is rebuilt here and the
    one-file source re-rendered from it.
    """
    sections = [_section("class", "puck", "puck.bgt", declared_at=3),
                _section("class", "room", "room.bgt", declared_at=2),
                _section("function", "spin", "puck.bgt", declared_at=40),
                _section("function", "lock", "room.bgt", declared_at=9),
                _section("function", "hit", "puck.bgt", declared_at=20)]
    bgt_project.assign_paths(sections, {},
                             {s.name: s.source_file for s in sections})
    assert bgt_project.reorder_by_file(sections) is True
    assert [s.name for s in sections] == ["puck", "hit", "spin", "room", "lock"]
    # ...and the files really are contiguous, which is what `verify` needs.
    paths = [s.path for s in sections]
    assert paths == sorted(paths, key=paths.index)
    for path in set(paths):
        first, last = paths.index(path), len(paths) - 1 - paths[::-1].index(path)
        assert paths[first:last + 1] == [path] * (last - first + 1)


def test_a_declaration_with_no_recorded_position_keeps_its_place():
    """A debug build records a position per BODY, so a declaration with none
    -- anything the compiler generated -- must not be sorted to the front on
    a `declared_at` of 0, which would read as line 0 of the file."""
    sections = [_section("function", "real", "a.bgt", declared_at=12),
                _section("function", "generated", "a.bgt", declared_at=0)]
    bgt_project.assign_paths(sections, {},
                             {s.name: s.source_file for s in sections})
    bgt_project.reorder_by_file(sections)
    assert [s.name for s in sections] == ["real", "generated"]


def test_a_library_name_outranks_the_module_s_own():
    """Both can name a file and only the library attribution licenses
    substituting the engine's own source, so that one decides the path."""
    sections = [_section("class", "dynamic_menu", "my_menu.bgt")]
    bgt_project.assign_paths(sections, {"dynamic_menu": "dynamic_menu.bgt"},
                             {"dynamic_menu": "my_menu.bgt"})
    assert sections[0].path == "includes/dynamic_menu.bgt"
    assert sections[0].origin == "dynamic_menu.bgt"
    assert sections[0].source_file == "my_menu.bgt"


# --------------------------------------------------------------------------
# the names the adapter hands the decompiler
# --------------------------------------------------------------------------

def _debug_record(variables, param_names=(), section=b"game.bgt"):
    """One parsed function record, as `as_module` hands it over."""
    return {"name": "netloop", "params": [None] * len(param_names),
            "variables": [{"declared_at": at, "stack_offset": off,
                           "name": name, "type": {"token": 68}}
                          for off, name, at in variables],
            "paramNames": list(param_names),
            "scriptSection": section, "declaredAt": 1, "lineNumbers": []}


def _overlay(record, inferred):
    """Run `debug_names` over a function holding `inferred` slot entries."""
    asreader = bgt_asir.asreader      # however the adapter reached it

    builder = object.__new__(bgt_asir.Builder)
    builder._dts = {}
    builder._builtin_functions = []
    builder.dt = lambda d: asreader.DataType()
    f = asreader.Function()
    f.name = record["name"]
    f.variables = [asreader.ScriptVariable(stack_offset=off) for off in inferred]
    bgt_asir.Builder.debug_names(builder, f, record)
    return f


def test_every_declaration_a_slot_carries_is_kept():
    """One slot, every declaration the source made in it.

    Keyed by offset, only the last survived -- and these slots are reused
    hard: Air Puck's `netloop` makes twenty-seven declarations in slot 26,
    mixing `int`, `uint` and `bool`. Keeping one gave a loop counter the name
    and the type of a later `bool success`, so `success++` would not compile.
    """
    f = _overlay(_debug_record([(13, b"i", 10), (13, b"success", 90)]), [13])
    assert [v.name for v in f.variables] == ["i", "success"], f.variables
    assert [v.declared_at for v in f.variables] == [10, 90]


def test_two_slots_cannot_claim_one_name():
    """The source may declare `i` twice in one body, in different blocks.

    Air Puck's client has a `string i` in slot 18 and a `uint i` in slot 16,
    and a slot's declaration is hoisted to the top of the body -- so both
    wanted one name and the compiler reported
    `Can't implicitly convert from 'string' to 'uint'`.
    """
    f = _overlay(_debug_record([(18, b"i", 10), (16, b"i", 90)]), [18, 16])
    names = [v.name for v in f.variables]
    assert names == ["i", "i_2"], names
    assert len(set(names)) == len(names)


def test_a_name_reused_at_ONE_offset_keeps_it():
    """That is one variable the source declared in two scopes, which is what
    `redeclare` is for -- renaming it would invent a second variable."""
    f = _overlay(_debug_record([(12, b"pwtext", 10), (12, b"pwtext", 90)]), [12])
    assert [v.name for v in f.variables] == ["pwtext", "pwtext"]


def test_a_parameter_claims_its_name_first():
    """A local may not shadow a parameter: the declaration is `already
    declared` and the body then reads an uninitialised copy."""
    f = _overlay(_debug_record([(5, b"name", 10)], param_names=[b"name"]), [5])
    assert [v.name for v in f.variables] == ["name_2"], f.variables


def test_a_slot_the_source_never_named_keeps_its_inferred_entry():
    """`slot_types` types every slot the bytecode touches and debug info names
    only what the source declared, so the two are merged: the compiler's own
    scratch has to stay foldable."""
    f = _overlay(_debug_record([(7, b"total", 10)]), [7, 9])
    by_off = [(v.stack_offset, v.name) for v in f.variables]
    assert (9, "") in by_off, by_off
    assert (7, "total") in by_off, by_off


def test_the_inferred_order_is_preserved():
    """`FuncDecompiler` reads the order of `variables` to find where the
    compiler's own scratch begins, so the declarations go in at the position
    the inferred entry held."""
    f = _overlay(_debug_record([(9, b"second", 10)]), [4, 9, 12])
    assert [v.stack_offset for v in f.variables] == [4, 9, 12]


if __name__ == "__main__":
    failed = 0
    for key, value in sorted(list(globals().items())):
        if key.startswith("test_") and callable(value):
            try:
                value()
                print("ok   %s" % key)
            except Exception as exc:                      # noqa: BLE001
                failed += 1
                print("FAIL %s: %s: %s" % (key, type(exc).__name__, exc))
    print("\n%d failed" % failed)
    sys.exit(1 if failed else 0)
