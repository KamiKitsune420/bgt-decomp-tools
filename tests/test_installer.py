"""Known-answer tests for reading a game out of an Inno Setup installer.

Everything here is built by the test. No installer and no game file is
involved, which is the rule for this folder -- and it is affordable because
the three layers are separable: the payload is an ordinary LZMA1 stream behind
a four-byte magic, the filter is arithmetic on five-byte windows, and the
carve is accepted by `bgtlib.unpack` rather than by anything here.

The filter is tested by vectors computed in the test from the documented rule
rather than by round-tripping through an encoder written as this decoder's
inverse: an inverse built from the same arithmetic would agree with a wrong
reading of it, which is the trap this project keeps paying for.

The end-to-end test needs a payload the filter does not touch, so it builds a
synthetic game and keeps rebuilding it until its bytes hold no `0xE8` or
`0xE9`. That is not a trick to make a test pass -- the filter has its own
vectors above -- it is how the *other* three layers get exercised without one
layer's output standing in for another's input.
"""

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "tools"))

import bgt_installer                                            # noqa: E402
import bgt_repack                                               # noqa: E402
import bgtlib                                                   # noqa: E402

NUL = b"\x00"
MAGIC = b"6188CAE85A13D82754756DC38920FA09"


# --------------------------------------------------------------------------
# the filter
# --------------------------------------------------------------------------

def test_a_payload_with_no_call_or_jmp_is_left_exactly_alone():
    data = bytes(b for b in range(256) if b not in (0xE8, 0xE9)) * 40
    assert bgt_installer.unfilter(data, flip=True) == data
    assert bgt_installer.unfilter(data, flip=False) == data


def test_a_call_window_becomes_the_relative_address():
    """The documented rule, computed here: the low 24 bits become
    (operand - window end) & 0xFFFFFF."""
    body = bytearray(b"\x11" * 32)
    body[8:13] = bytes([0xE8, 0x40, 0x30, 0x20, 0x00])
    operand = 0x00203040
    want = (operand - 13) & 0xFFFFFF

    out = bgt_installer.unfilter(bytes(body), flip=True)
    assert out[8] == 0xE8
    assert out[9] | (out[10] << 8) | (out[11] << 16) == want
    assert out[12] == 0x00                      # bit 23 clear, so no flip
    assert out[:8] == bytes(body[:8]) and out[13:] == bytes(body[13:])


def test_a_high_byte_that_is_not_a_sign_byte_leaves_the_window_alone():
    body = bytearray(b"\x11" * 32)
    body[8:13] = bytes([0xE9, 0x40, 0x30, 0x20, 0x7F])
    assert bgt_installer.unfilter(bytes(body), flip=True) == bytes(body)


def test_the_flip_applies_only_from_5_3_9_onward():
    """A relative value with bit 23 set is where the two forms differ."""
    body = bytearray(b"\x11" * 32)
    # operand 0 at window end 13 gives (0 - 13) & 0xFFFFFF, whose bit 23 is set
    body[8:13] = bytes([0xE8, 0x00, 0x00, 0x00, 0x00])
    rel = (0 - 13) & 0xFFFFFF
    assert rel & 0x800000

    flipped = bgt_installer.unfilter(bytes(body), flip=True)
    plain = bgt_installer.unfilter(bytes(body), flip=False)
    assert flipped[12] == 0xFF
    assert plain[12] == 0x00
    assert flipped[9:12] == plain[9:12]


def test_a_window_that_crosses_a_block_boundary_is_skipped():
    """Inno filters in 64 KiB blocks aligned on the stream's own offsets, so a
    window with fewer than five bytes left in its block is not touched."""
    block = bgt_installer.FILTER_BLOCK
    data = bytearray(b"\x11" * (block + 64))
    at = block - 3                              # only three bytes left
    data[at:at + 5] = bytes([0xE8, 0x40, 0x30, 0x20, 0x00])
    out = bgt_installer.unfilter(bytes(data), flip=True)
    assert out[at:at + 5] == bytes([0xE8, 0x40, 0x30, 0x20, 0x00])


def test_the_version_decides_the_filter_and_an_absent_one_tries_both():
    assert bgt_installer.inno_version(
        b"junk" + b"Inno Setup Setup Data (5.3.10)" + NUL * 8) == (5, 3, 10)
    assert bgt_installer.inno_version(
        b"Inno Setup Setup Data (5.3.3)" + NUL) == (5, 3, 3)
    assert bgt_installer.inno_version(b"no version here") is None


# --------------------------------------------------------------------------
# the payload and the carve
# --------------------------------------------------------------------------

def _filter_clean_game(variant=bgtlib.MULTIPLY):
    """A synthetic BGT executable holding no 0xE8 or 0xE9 byte.

    The ciphertext is not under the test's control, so the module is perturbed
    and the executable rebuilt until one comes out clean. It is small on
    purpose: the chance of a clean build falls with every byte.
    """
    for n in range(400):
        module = b"\x01\x00" + bytes([n & 0xFF]) + b"\x00" * 13
        stub = b"MZ" + NUL * 0x3A + struct.pack("<I", 0x40) + b"PE\0\0" + NUL * 56
        skeleton = (stub + b"0 " + NUL * 32 + b"xproc10" + NUL
                    + struct.pack("<I", len(stub)))
        exe = bgt_repack.repack(skeleton, module, seed=0x11, flag=3,
                                magic=MAGIC, variant=variant)
        if 0xE8 not in exe and 0xE9 not in exe:
            return exe, module
    raise AssertionError("no filter-clean synthetic game in 400 tries")


def _installer_around(payload, version=b"5.3.10"):
    """A synthetic single-file Inno setup: an id, then one compressed chunk.

    Inno writes the five-byte LZMA1 properties header and no uncompressed
    length, so the eight length bytes `FORMAT_ALONE` adds are dropped here --
    which is exactly what the reader has to cope with.
    """
    import lzma
    alone = lzma.compress(payload, format=lzma.FORMAT_ALONE)
    stream = alone[:5] + alone[13:]
    return (b"MZ" + NUL * 64
            + b"Inno Setup Setup Data (" + version + b")" + NUL * 32
            + bgt_installer.CHUNK_MAGIC + stream)


def test_a_synthetic_installer_yields_the_game_it_holds():
    exe, module = _filter_clean_game()
    payload = b"readme contents\n" + exe + b"trailing file\n"
    installer = _installer_around(payload)

    found = list(bgt_installer.bgt_games(payload))
    assert len(found) == 1
    begin, end, got = found[0]
    assert got == exe
    assert bgtlib.unpack(got).bytecode == module

    # ...and through the whole three-layer path, from the installer's bytes
    import io
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "setup.exe")
        with open(path, "wb") as fh:
            fh.write(installer)
        games = [g for g, _note in bgt_installer.games_in(path)]
    assert games == [exe]
    del io, begin, end


def test_a_decoy_trailer_past_the_real_one_does_not_lengthen_the_game():
    """The bug this carve was rewritten for.

    A payload can hold a second `xproc10` a few hundred bytes past the real
    one -- another file's bytes, or padding. Carving to the later trailer keeps
    those extra bytes, which shifts the ciphertext and leaves the whole chain
    failing deep inside LZ77, a long way from the cause. `unpack` is what
    rejects it.
    """
    exe, _module = _filter_clean_game()
    decoy = b"x" * 500 + b"xproc10" + NUL + struct.pack("<I", 0x40)
    payload = exe + decoy

    found = list(bgt_installer.bgt_games(payload))
    assert [len(g) for _b, _e, g in found] == [len(exe)]
    assert found[0][2] == exe


def test_an_installer_holding_no_bgt_game_says_so():
    installer = _installer_around(b"just some files, no game here\n" * 40)
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "setup.exe")
        with open(path, "wb") as fh:
            fh.write(installer)
        try:
            list(bgt_installer.games_in(path))
        except bgt_installer.InstallerError as exc:
            assert "no BGT executable" in str(exc)
        else:
            raise AssertionError("an installer with no game was accepted")


def test_the_payload_is_found_without_the_setup_header():
    """The compressed header holds the file names and is deliberately not read,
    so an installer whose header block this cannot parse still gives its
    games."""
    exe, _module = _filter_clean_game()
    installer = _installer_around(exe, version=b"5.3.3")
    blobs = list(bgt_installer.payloads(installer))
    assert len(blobs) == 1 and blobs[0] == exe
