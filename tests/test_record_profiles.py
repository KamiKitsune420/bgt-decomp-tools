"""The per-release record profiles, and the rendering they exposed.

`as_module` reads BGT 1.3's module format. One shipped build -- Screaming
Strike, on a 2012-07 engine -- is that format with seven records from the
generation
before it, and those seven are kept as a named PROFILE rather than as seven
more free fields in the trial. These checks are about that distinction as
much as about the records: a profile cannot re-describe a module that
already lands, where a free field can, and the day this was written one
extra free field in the other reader let a synthetic module with a spare
byte land on EOF.

Everything here is synthetic: a few bytes built by hand, or a source line.
No game file is involved.

Run:  python -m pytest tests/test_record_profiles.py -q
"""

import os
import re
import sys

import pytest

try:                                   # after `pip install -e .`
    from bgtdecomp import as_module
except ImportError:                    # straight from a checkout
    TOOLS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools")
    sys.path.insert(0, TOOLS)
    import as_module


def eu(value):
    """One encoded integer in the sign-flag form, for building a record."""
    assert 0 <= value
    if value < 64:
        return bytes([value])
    if value < 1 << 14:
        return bytes([0x40 | (value >> 8), value & 0xFF])
    raise AssertionError("the fixtures here do not need a wider form")


def test_the_encoder_here_agrees_with_the_readers_own_decoder():
    """Otherwise every record below is built against a different format.

    The pairs this document pins by hand are included, so a wrong encoder
    cannot agree with a wrong decoder.
    """
    for value in (0, 1, 5, 63, 64, 66, 86, 91, 129, 167, 231, 4096):
        got, end = as_module.read_encoded_uint(eu(value), 0)
        assert (got, end) == (value, len(eu(value))), value
    assert eu(63) == b"\x3f"
    assert eu(91) == b"\x40\x5b"


# ---------------------------------------------------------------- the table

def test_the_verified_profile_is_tried_first():
    """A module that already lands on EOF has to keep the reading this
    reader already held. Order is the whole of how that is guaranteed, so a
    later release's profile can only ever be reached by a module the
    verified one fails on."""
    assert as_module.RECORD_PROFILES[0][1] is as_module.RECORDS_13


def test_every_profile_answers_every_field():
    """A profile missing a field would read as the verified answer for it,
    silently -- which is the right default and the wrong way to get it."""
    keys = set(as_module.RECORDS_13)
    assert keys
    for name, profile in as_module.RECORD_PROFILES:
        assert set(profile) == keys, name


def test_a_reader_given_nothing_reads_the_verified_records():
    """Every caller that does not know about profiles -- and most of them do
    not -- has to get the reading that ten titles in this corpus land on."""
    r = as_module.Reader(b"\x00\x00", as_module.TAGGED, pos=1)
    assert r.records == as_module.RECORDS_13


def test_every_field_the_reader_reads_is_declared():
    """The field names in `Reader` have to be the field names in the table.

    `test_every_profile_answers_every_field` compares each profile against
    `RECORDS_13`, so it is blind to a field missing from ALL of them -- which
    is a `KeyError` out of the middle of a parse the first time a module
    reaches it. That is not hypothetical: a field added to `function()` and
    to no profile took Aliens Attack from landing exactly on EOF to "neither
    reader could parse this module", and the set-equality test above passed
    throughout. This reads the source for what is actually looked up.
    """
    with open(as_module.__file__, encoding="utf-8") as fh:
        source = fh.read()
    read = set(re.findall(r'self\.records\["([a-z_]+)"\]', source))
    assert read, "no self.records lookups found -- has the reader changed shape?"
    assert read <= set(as_module.RECORDS_13), sorted(read - set(as_module.RECORDS_13))


def test_the_two_profiles_really_differ():
    """A profile that answers the same as the verified one is dead weight in
    the trial and should not be in the table."""
    differing = [k for k in as_module.RECORDS_13
                 if as_module.RECORDS_13[k] != as_module.RECORDS_2012[k]]
    assert len(differing) >= 7, differing


# ------------------------------------------------------------ ReadDataType

def _reader(payload, records, template_namespace=False):
    #: `template_namespace=False` because that is the answer the one module
    #: these records were read from lands on, and it is the axis the trial
    #: already had: a template's name is followed by a namespace in some
    #: builds and not others.
    return as_module.Reader(b"\x00" + payload, as_module.TAGGED, pos=1,
                            records=records,
                            template_namespace=template_namespace)


def test_the_two_datatype_conventions_are_opposite():
    """1.3 reads `eu(v)`, where a NON-zero v is a back-reference into the
    saved types and zero says a token follows. The generation before it is
    the other way round: zero introduces a back-reference and a non-zero
    lead IS the token. Read out of `ReadDataType` at 0x419AE0, whose
    `test edi,edi / jne` takes the token branch when v is non-zero.

    `itemComingTime`, Screaming Strike's first global, is the record: `40 42
    00 00` is token 66 -- that generation's `int` -- and two flag bytes.
    """
    payload = eu(66) + b"\x00\x00"
    early = _reader(payload, as_module.RECORDS_2012)
    dt = early.data_type()
    assert dt["token"] == 66
    assert early.p == 1 + len(payload), "two flag bytes, not one"

    # The same bytes under 1.3's rule are a back-reference to saved type 65,
    # of which there are none -- which is what the wrong reading produced
    # before this, and why the record after it was lost.
    plain = _reader(payload, as_module.RECORDS_13)
    assert plain.data_type() == {"ref": 65}


def test_an_object_datatype_carries_four_flag_bytes_in_that_build():
    """Two for the handle and const markers and two more for reference and
    read-only, where 1.3 packs all four into one byte's low bits."""
    payload = eu(5) + b"\x00" + b"\x01\x00\x00\x00"   # null type-info, handle
    r = _reader(payload, as_module.RECORDS_2012)
    dt = r.data_type()
    assert dt["token"] == 5 and dt["handle"] is True
    assert dt["const"] is False and dt["reference"] is False
    assert r.p == 1 + len(payload)


def test_a_back_reference_resolves_under_either_convention():
    """The index is spelled differently and has to mean the same thing."""
    first = eu(66) + b"\x00\x00"
    r = _reader(first + eu(0) + eu(0), as_module.RECORDS_2012)
    a = r.data_type()
    b = r.data_type()
    assert b is a, "a zero lead then the index is a back-reference"


# ------------------------------------------------------ the initialiser gate

def test_a_globals_initialiser_gate_must_be_zero_or_one():
    """The byte says whether a function record follows, so a third value
    means the data type before it desynchronised -- and reading on would
    take whatever is there for a function tag."""
    payload = b"\x6e\x01a" + b"\x00" + eu(66) + b"\x00\x00" + b"\x40"
    r = _reader(payload, as_module.RECORDS_2012)
    with pytest.raises(as_module.ParseError) as caught:
        r.global_property()
    assert "neither 0 nor 1" in str(caught.value)


def test_a_zero_gate_means_the_global_has_no_initialiser():
    payload = b"\x6e\x01a" + b"\x00" + eu(66) + b"\x00\x00" + b"\x00"
    r = _reader(payload, as_module.RECORDS_2012)
    rec = r.global_property()
    assert rec["name"] == "a" and rec["init"] is None
    assert r.p == 1 + len(payload), "the gate is read and nothing follows it"


# ------------------------------------------------- the template type-info

def test_a_template_type_info_may_carry_no_subtype_count():
    """That AngelScript has no multi-subtype template, so the subtype's own
    tag follows the name directly. `objectTimer`, an `array<timer>`, is the
    record that showed it: reading a count takes the subtype's `'s'` tag for
    115 subtypes.
    """
    payload = (b"\x61" + b"\x6e\x05array"          # 'a', "array"
               + b"\x73"                           # the subtype tag, 's'
               + eu(5) + b"\x6f" + b"\x6e\x05timer" + b"\x00"
               + b"\x00\x00\x00\x00")
    r = _reader(payload, as_module.RECORDS_2012)
    ti = r.type_info()
    assert ti["kind"] == "template" and ti["name"] == "array"
    assert len(ti["subtypes"]) == 1
    assert r.p == 1 + len(payload)


# ----------------------------------------------------------- the token shift

def test_the_token_shift_travels_with_the_profile():
    """`eTokenType` moved twice between this build's AngelScript and the one
    the IR uses, so the shift is a fact about the release. Choosing it by
    asking whether the module came through the *early reader* instead got it
    wrong for a 1.3-shaped build: every `void` function came out returning
    `uint64` and every `int` local as `tok68`.
    """
    assert as_module.RECORDS_13["token_shift"] == 2
    assert as_module.RECORDS_2012["token_shift"] == 4


def test_the_adapter_reads_that_shift_rather_than_guessing_from_the_reader():
    """A source check, because the failure is a rendering and the corpus
    cannot see it: both 1.3 titles and this one go through the same adapter,
    and only the profile says which numbering applies."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "..", "tools", "bgt_asir.py")
    with open(path, encoding="utf-8") as handle:
        src = handle.read()
    assert 'info.get("token_shift")' in src


# --------------------------------------------------------- one trial, shared

def test_detect_and_summarize_trial_the_same_thing():
    """They each built the best walk, and `detect`'s copy was pinned at
    `template_namespace=True` -- so a module whose landing needs False was
    reported as not landing by the half that chooses the dialect, and then
    landed in the half that reports it. Two places answering one question
    with one of them stricter.

    Checked in the source, because the behaviour needs a module that
    exercises the disagreement and this repository holds no game files.
    """
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "..", "tools", "as_module.py")
    with open(path, encoding="utf-8") as handle:
        src = handle.read()
    assert src.count("def _trial(") == 1
    # ...and both callers go through it rather than looping themselves.
    body = src.split("def detect(", 1)[1].split("\ndef ", 1)[0]
    assert "_trial(" in body
    assert "for namespaced in" not in body
    summary = src.split("def summarize(", 1)[1].split("\ndef ", 1)[0]
    assert "_trial(" in summary
    assert "for namespaced in" not in summary


def test_a_cursor_past_the_end_is_not_progress():
    """`raw` advances before it refuses, so a runaway walk reported an `end`
    of 0x7B660 on a 23,859-byte module -- and `_score` ranks by `end`, so
    that bogus reading outranked a real partial parse."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "..", "tools", "as_module.py")
    with open(path, encoding="utf-8") as handle:
        src = handle.read()
    assert '"end": min(r.p, len(data))' in src


# ------------------------------------------- the rendering it exposed

def test_a_declaration_with_no_arguments_has_no_parentheses():
    """`sound s(500);` constructs in place, which is the only form a class
    with no default constructor accepts. With NO arguments there is nothing
    to construct with and the parentheses stop being an argument list:
    `sound s();` is a function declaration to a parser that has to choose.

    Air Puck and Build to Survive are debug builds, so they settle what the
    author wrote: `file f;` and `savedata sd;`.
    """
    sys.path.insert(0, os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "tools", "nvgt"))
    import decompile

    src = open(decompile.__file__, encoding="utf-8").read()
    # The branch that renders a construction onto its declaration.
    assert 'text = f"{name}({args});" if args else f"{name};"' in src
    # ...and a construction WITH arguments keeps them, which is the form
    # this file records as the only one that compiles for such a class.
    assert 'args = a.text[len(tn) + 1:-1].strip()' in src
def test_an_allocs_callee_operand_is_only_read_where_the_engine_reads_it():
    """One build translates it only for a SCRIPT object, so for a registered
    type it holds whatever the compiler left there. All fifty of Screaming
    Strike's read `6, 33` -- a constant, where a real index would vary --
    and one-based that resolves to the engine's `random`, two parameters,
    so the simulation took the ALLOC's destination for an argument and the
    slot the string was in was never written.
    """
    assert as_module.RECORDS_13["alloc_callee_script_only"] is False
    assert as_module.RECORDS_2012["alloc_callee_script_only"] is True


def test_the_alloc_arity_falls_back_on_the_type_not_the_callee():
    """An owner match was tried first and did nothing: the bogus callee is a
    global function with no owner at all, so "no owner, therefore a factory"
    waved it through. The engine asks about the TYPE -- is it one the module
    declares -- which is what the fallback has to ask too.

    A source check, because reaching it needs a module of that build and
    this repository holds no game files.
    """
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "..", "tools", "nvgt", "decompile.py")
    with open(path, encoding="utf-8") as handle:
        src = handle.read()
    assert "_alloc_callee_is_readable" in src
    assert "alloc_callee_script_only" in src
    # the question is asked of the module's own classes, not of the callee
    body = src.split("def _alloc_callee_is_readable", 1)[1].split("\n    def ", 1)[0]
    assert "self.m.classes" in body
    assert "object_type" not in body
