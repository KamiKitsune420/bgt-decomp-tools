"""
Tests for the pieces that join the BGT and NVGT halves of the toolkit.

Synthetic inputs only, like test_toolkit.py: owned PE stubs, packs built here,
modules built here. Each test targets a failure that is quiet rather than loud:

  * the NVGT embedded-pack walk      -- reading a pack name's length as a u32
                                        (as the original code did) consumes the
                                        name itself and loses the whole payload
  * the NVGT pack format             -- a TOC that does not land exactly on EOF,
                                        a checksum, offsets that do not add up
  * engine identification            -- a guess would send a user down the wrong
                                        half of the toolkit with confident errors
  * the two AngelScript integer codecs, which must agree although the two
    readers were written independently
  * the CLI group dispatch           -- `bgt nvgt --help` must not be swallowed

Run:  python -m pytest tests/ -q
"""

import os
import struct
import sys
import tempfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.join(HERE, "..", "tools")
if TOOLS not in sys.path:
    sys.path.insert(0, TOOLS)

import pytest

import as_module
import bgt_ghidra
import bgt_repack
import cli
import engine
from nvgt import asreader, extract, nvgt_pack

sys.path.insert(0, os.path.join(HERE, "nvgt"))
from test_support import owned_pe_stub    # noqa: E402  (after the path setup)

NUL = b"\x00"


# --------------------------------------------------------------------------
# builders
# --------------------------------------------------------------------------

def _poco_string(text):
    raw = text.encode("utf-8")
    return extract.Reader.varint_bytes(len(raw)) + raw


def _nvgt_stream(bytecode=b"\x01\x00module-bytes"):
    """A decrypted NVGT stream: the Poco preamble, then the module."""
    props = b"".join(extract.Reader.varint_bytes(i)
                     for i in range(extract.NUM_ENGINE_PROPERTIES))
    return (struct.pack("<H", 1) + _poco_string("legacy_sound")
            + struct.pack("<i", 0) + props + struct.pack("<qB", 42, 0)
            + bytecode)


def _nvgt_exe(packs=(), stream=None):
    """An owned PE stub + embedded packs + a repository-profile payload.

    The repository profile is NVGT's open-source default (nvgt_config.h: key
    SHA256("Kernel32.lib"), size XOR 47635) -- the layout `write_embedded_packs`
    and `write_payload` produce, byte for byte.
    """
    stub = owned_pe_stub()
    block = extract.Reader.varint_bytes(len(packs))
    for name, data in packs:
        block += _poco_string(name) + struct.pack("<I", len(data)) + data
    payload = extract.encrypt_stream(stream if stream is not None else _nvgt_stream())
    size = extract.Reader.varint_bytes(len(payload) ^ extract.NVGT_BYTECODE_NUMBER_XOR_REPO)
    return stub + block + size + payload


def _bgt_exe(module=b"\x01\x00" + b"module" * 20):
    stub = bytes(range(256)) * 2
    skeleton = stub + b"0 " + NUL * 32 + b"xproc10" + NUL + struct.pack("<I", len(stub))
    return bgt_repack.repack(skeleton, module, seed=0x11, flag=3,
                             magic=b"6188CAE85A13D82754756DC38920FA09")


def _temp(data, suffix=".exe"):
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return path


# --------------------------------------------------------------------------
# NVGT embedded packs
# --------------------------------------------------------------------------

def test_embedded_pack_names_are_poco_strings_not_u32_lengths():
    """load_embedded_packs reads `br >> name` -- a 7-bit length and the bytes.
    With a u32 length the name's own bytes become a length of ~2 GB and the
    payload is never reached; that is what the original code did."""
    pack = nvgt_pack.build([("hello.txt", b"Hello")])
    exe = _nvgt_exe(packs=[("sounds.dat", pack)])
    packs = extract.embedded_packs(exe)
    assert [p.name for p in packs] == ["sounds.dat"]
    assert exe[packs[0].offset:packs[0].offset + packs[0].size] == pack
    info, _ = extract.extract_data(exe)
    assert info.bytecode == b"\x01\x00module-bytes"


def test_several_embedded_packs_are_walked_in_order():
    first = nvgt_pack.build([("a", b"1")])
    second = nvgt_pack.build([("b", b"22")], key="k", nonce=bytes(24))
    exe = _nvgt_exe(packs=[("one.dat", first), ("two.dat", second)])
    packs = extract.embedded_packs(exe)
    assert [p.name for p in packs] == ["one.dat", "two.dat"]
    got = nvgt_pack.parse(exe[packs[1].offset:packs[1].offset + packs[1].size], "k")
    assert got.read("b") == b"22"


def test_no_embedded_packs_is_a_zero_count():
    assert extract.embedded_packs(_nvgt_exe()) == []


def test_owned_repackaging_keeps_the_pack_block_intact():
    """package_owned_module walks the same block; it has to agree with the
    loader on where the size field starts, or it writes the wrong XOR."""
    exe = _nvgt_exe(packs=[("x.dat", nvgt_pack.build([("f", b"data")]))])
    rebuilt = extract.package_owned_module(exe, _nvgt_stream(b"\x01\x00other"))
    info, _ = extract.extract_data(rebuilt)
    assert info.bytecode == b"\x01\x00other"


# --------------------------------------------------------------------------
# NVGT packs
# --------------------------------------------------------------------------

def test_poco_7bit_known_answers():
    for value, encoded in ((0, b"\x00"), (127, b"\x7f"), (128, b"\x80\x01"),
                           (300, b"\xac\x02"), (1 << 32, b"\x80\x80\x80\x80\x10")):
        assert nvgt_pack.write_7bit(value) == encoded
        assert nvgt_pack.read_7bit(encoded, 0) == (value, len(encoded))


def test_poco_7bit_is_not_angelscripts_encoding():
    """The high bit continues in Poco and is a SIGN flag in AngelScript. An
    NVGT executable holds both side by side, so mixing them up is easy."""
    assert nvgt_pack.read_7bit(b"\x81\x01", 0)[0] == 129
    assert as_module.read_encoded_uint(b"\x81", 0)[0] == -1


def test_plain_pack_layout_matches_the_writer():
    blob = nvgt_pack.build([("a.txt", b"abc"), ("dir/b.bin", b"\x00\xff")])
    assert blob[:4] == struct.pack("<I", 0xDADFADED)
    toc_offset, crc = struct.unpack_from("<QI", blob, 4)
    assert toc_offset == 64 + 5
    assert crc == zlib.crc32(blob[toc_offset:]) & 0xFFFFFFFF
    pack = nvgt_pack.parse(blob)
    assert pack.names() == ["a.txt", "dir/b.bin"]
    assert [e.offset for e in pack.entries] == [64, 67]
    assert pack.read("dir/b.bin") == b"\x00\xff"


def test_encrypted_pack_roundtrips_and_rejects_wrong_or_missing_key():
    blob = nvgt_pack.build([("s.ogg", b"OggS" + bytes(100))], key="pw", nonce=bytes(24))
    assert blob[:24] == bytes(24)
    assert nvgt_pack.parse(blob, "pw").read("s.ogg")[:4] == b"OggS"
    with pytest.raises(nvgt_pack.PackError):
        nvgt_pack.parse(blob, "wrong")
    with pytest.raises(nvgt_pack.PackError):
        nvgt_pack.parse(blob)


def test_key_derivation_is_unkeyed_blake2b_256():
    import hashlib
    assert nvgt_pack.derive_key("s3cret") == hashlib.blake2b(b"s3cret", digest_size=32).digest()


def test_empty_pack_is_rejected_as_nvgts_reader_does():
    """load() needs toc_offset < file size: an empty pack has no TOC to read."""
    with pytest.raises(nvgt_pack.PackError):
        nvgt_pack.parse(nvgt_pack.build([]))


def test_toc_checksum_is_verified():
    blob = bytearray(nvgt_pack.build([("a", b"x")]))
    blob[-1] ^= 1                                # the last TOC byte: entry size
    with pytest.raises(nvgt_pack.PackError):
        nvgt_pack.parse(bytes(blob))


def test_entry_sizes_must_land_exactly_on_the_toc():
    blob = bytearray(nvgt_pack.build([("a", b"xyz")]))
    toc = struct.unpack_from("<Q", blob, 4)[0]
    blob[64:64] = b"!"                            # one stray data byte
    struct.pack_into("<Q", blob, 4, toc + 1)      # header still self-consistent
    with pytest.raises(nvgt_pack.PackError, match="unexplained"):
        nvgt_pack.parse(bytes(blob))


def test_invalid_names_are_refused_both_ways():
    for name in ("bad\x01name", "dup"):
        items = [(name, b"1")] + ([("dup", b"2")] if name == "dup" else [])
        with pytest.raises(nvgt_pack.PackError):
            nvgt_pack.build(items)


def test_extraction_refuses_to_escape_the_output_folder():
    with pytest.raises(nvgt_pack.PackError):
        nvgt_pack._safe_join("out", "../../evil.dll")
    assert nvgt_pack._safe_join("out", "sub\\a.wav").endswith(os.path.join("sub", "a.wav"))


# --------------------------------------------------------------------------
# engine identification
# --------------------------------------------------------------------------

def test_identify_recognises_bgt():
    ident = engine.identify_bytes(_bgt_exe())
    assert ident.engine == engine.BGT
    assert ident.facts["seed"] == 0x11


def test_identify_recognises_nvgt_and_lists_embedded_packs():
    exe = _nvgt_exe(packs=[("sounds.dat", nvgt_pack.build([("a", b"1")]))])
    ident = engine.identify_bytes(exe)
    assert ident.engine == engine.NVGT
    assert ident.facts["embedded_packs"] == ["sounds.dat"]
    assert ident.facts["plugins"] == ["legacy_sound"]


def test_identify_refuses_to_guess_and_says_why():
    ident = engine.identify_bytes(owned_pe_stub())
    assert not ident.known
    assert "nothing is appended" in ident.rejected[engine.NVGT]
    assert engine.BGT in ident.rejected


def test_redirect_hint_points_across_the_two_halves():
    nvgt_path = _temp(_nvgt_exe())
    bgt_path = _temp(_bgt_exe())
    try:
        assert "bgt nvgt recover" in engine.redirect_hint(nvgt_path, engine.BGT)
        assert "bgt unpack" in engine.redirect_hint(bgt_path, engine.NVGT)
        assert engine.redirect_hint(bgt_path, engine.BGT) is None
    finally:
        os.unlink(nvgt_path)
        os.unlink(bgt_path)


# --------------------------------------------------------------------------
# the two independently written AngelScript readers must agree
# --------------------------------------------------------------------------

@pytest.mark.parametrize("raw", [
    b"\x00", b"\x3f", b"\x40\x40", b"\x40\x5b", b"\x5f\xff", b"\x60\x01\x00",
    b"\x70\x00\x01\x00", b"\x81", b"\xc0\x5b", b"\x7f" + bytes(range(1, 9)),
])
def test_both_readers_decode_encoded_uints_identically(raw):
    """as_module (BGT) and asreader (NVGT) each implement ReadEncodedUInt64,
    from different builds of asCReader. The NVGT one returns the 64-bit two's
    complement where the BGT one returns a signed value; otherwise they must
    agree on every width, including the sign flag."""
    bgt_value, bgt_end = as_module.read_encoded_uint(raw, 0)
    stream = asreader._Stream(raw)
    nvgt_value = stream.read_encoded_uint64()
    assert (bgt_value & 0xFFFFFFFFFFFFFFFF) == nvgt_value
    assert bgt_end == stream.pos


# --------------------------------------------------------------------------
# CLI and tooling glue
# --------------------------------------------------------------------------

def test_nvgt_group_help_is_not_swallowed_by_the_top_level_parser(capsys):
    assert cli.main(["nvgt", "--help"]) == 0
    assert "recover" in capsys.readouterr().out


def test_nvgt_group_rejects_an_unknown_tool():
    assert cli.main(["nvgt", "no-such-tool"]) == 2


def test_cli_identify_exit_status_reflects_the_result(capsys):
    path = _temp(_nvgt_exe())
    try:
        assert cli.main(["identify", path]) == 0
        assert "NVGT" in capsys.readouterr().out
    finally:
        os.unlink(path)


def test_cli_nvgt_pack_lists_an_embedded_pack(capsys):
    exe = _nvgt_exe(packs=[("snd.dat", nvgt_pack.build([("x.wav", b"RIFF")], key="k"))])
    path = _temp(exe)
    try:
        assert cli.main(["nvgt", "pack", "list", path, "--key", "k"]) == 0
        out = capsys.readouterr().out
        assert "snd.dat" in out and "x.wav" in out
    finally:
        os.unlink(path)


def test_batch_unsafe_paths_are_copied_before_reaching_analyzeheadless():
    """analyzeHeadless.bat breaks on the `)` in "Program Files (x86)" --
    exactly where BGT installs."""
    root = tempfile.mkdtemp()
    tricky = os.path.join(root, "Program Files (x86)")
    os.makedirs(tricky)
    src = os.path.join(tricky, "bgt.exe")
    with open(src, "wb") as fh:
        fh.write(b"MZ")
    safe = bgt_ghidra.batch_safe_path(src, os.path.join(root, "scratch"))
    if os.name == "nt":
        assert "(" not in safe and os.path.basename(safe) == "bgt.exe"
        with open(safe, "rb") as fh:
            assert fh.read() == b"MZ"
    else:
        assert safe == src
