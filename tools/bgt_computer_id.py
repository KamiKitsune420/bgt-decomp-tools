"""BGT's `generate_computer_id`, read out of the engine and reproduced exactly.

A BGT game's registration key is checked against this value, so a port that
computes anything else cannot validate a key the player already has. The
engine's own answer is therefore the only acceptable one, and this module is
checked against it rather than argued from the disassembly: `bgt computerid
--verify` drives `bgt.exe` over a table of application ids and compares.

Read out of `bgt.exe` 1.3 (2014-06-01) at these addresses:

| what | where |
|---|---|
| `generate_computer_id` | `0x004962D0` |
| the drive component | `0x0048D6C0` |
| the volume component | `0x0048D7F0` |
| the CPU component | `0x0048D640` |
| the memory component | `0x0048D790` |
| the SHA-1 | `0x00496190`, update `0x0048FDB0`, finalize `0x00490320` |
| the base64 | `0x00495DA0`, shared with `string_base64_encode` |

The shape, and every step of it is one a wrong guess gets silently wrong:

    s  = drive_geometry()                  "%I64d%u%u%u%u"
    s += hardware_only ? " " : volume()    "%u", or "" when the serial is 0
    s += application_id
    s += cpu()                             "%u%u"
    s += total_physical_memory()           "%I64d"
    d  = sha1(s)                           ...with each word LITTLE-endian
    a  = 0x7FFF; for i,b in d: a *= (int8)b; if i==4: a -= (int8)d[1]
    o  = base64(d) without its "=" padding
    srand(a); 13 draws discarded
    for i in o: if rand() % 10 + 1 > 6: swap(o[i], o[0])

Three of those are the reason a reimplementation from the help file alone
cannot work:

- **the digest words are little-endian.** The engine's SHA-1 assigns its five
  state dwords to the output string as they sit in memory, so every group of
  four bytes is reversed against a standard SHA-1 digest. Nothing downstream
  announces it: the result is still 20 bytes and still base64s to 27
  characters.
- **`rand()` is Visual C++'s**, so the shuffle is reproducible only with that
  generator's constants. Another CRT's `rand` gives a different permutation of
  the same characters -- which is the quiet failure, because the character
  multiset still matches.
- **the drive component is GEOMETRY, not a serial.** The help file says the
  non-hardware half uses "the hard drive serial assigned by the operating
  system when the drive was last formatted", and that is the *volume* serial;
  the hardware half is `IOCTL_DISK_GET_DRIVE_GEOMETRY` on
  `\\\\.\\PhysicalDrive0`, which survives a reformat.

**BGT 1.0's answer is a different number**, and this module does not compute
it: that build has no `\\\\.\\PhysicalDrive0` and reads the CPU's `FeatureSet`
registry value instead, which on this machine is `0x311B3DFF` where
`CPUID.1.EDX` is `0xBFCBFBFF`. So the two engines disagree about one
component, and a key issued for a 1.0 game is not a key for a 1.3 one.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import os
import struct
import sys
from typing import Dict, Optional, Tuple

#: `IOCTL_DISK_GET_DRIVE_GEOMETRY`, as the engine passes it.
IOCTL_DISK_GET_DRIVE_GEOMETRY = 0x70000

#: The device the engine opens, spelled without a backslash escape in sight:
#: this file has been through a shell heredoc more than once.
PHYSICAL_DRIVE_0 = bytes([0x5C, 0x5C, 0x2E, 0x5C]) + b"PhysicalDrive0"

#: The root the volume serial is read for. Hardcoded in the engine, so a game
#: installed anywhere still keys off C:.
VOLUME_ROOT = b"C:" + bytes([0x5C])

#: How many draws the engine throws away after seeding. Read at `0x00496649`.
DISCARDED_DRAWS = 13

#: The swap fires when `rand() % 10 + 1` exceeds this. `0x00496670`.
SWAP_THRESHOLD = 6


class ComputerIdError(Exception):
    """A component could not be read, so no id can be computed."""


# --------------------------------------------------------------------------
# the stages that do not touch the machine, and so can be tested anywhere
# --------------------------------------------------------------------------

def _int8(byte: int) -> int:
    """A `char` is signed here, and the checksum multiplies by it."""
    return byte - 256 if byte > 127 else byte


def _int32(value: int) -> int:
    return ctypes.c_int32(value).value


def native_digest(data: bytes) -> bytes:
    """SHA-1 with each state word left little-endian, which is what BGT does.

    The engine copies its five state dwords straight into a 20-byte string, so
    the digest differs from a standard one by a byte reversal inside every
    group of four. Both are 20 bytes and both base64 to the same length, which
    is why reading this off the disassembly was necessary -- no length or
    alphabet check can tell them apart.
    """
    standard = hashlib.sha1(data).digest()
    return b"".join(standard[i:i + 4][::-1] for i in range(0, 20, 4))


def checksum(digest: bytes) -> int:
    """The 32-bit value the shuffle is seeded with. `0x00496507`.

    A running product over the digest's SIGNED bytes, with the second byte
    subtracted once after the fifth multiply. The product overflows constantly
    and the overflow is part of the answer, so it is taken as a 32-bit signed
    int at every step rather than at the end.
    """
    acc = 0x7FFF
    for index, byte in enumerate(digest):
        acc = _int32(acc * _int8(byte))
        if index == 4:
            acc = _int32(acc - _int8(digest[1]))
    return acc


class MsvcRand:
    """Visual C++'s `rand()`, which is the generator the engine's shuffle uses.

    Reproduced rather than borrowed from the host, because every other CRT
    answers differently and the difference is invisible: the shuffle is a
    permutation, so a wrong generator returns the right characters in the
    wrong order.
    """

    def __init__(self, seed: int) -> None:
        self.state = seed & 0xFFFFFFFF

    def next(self) -> int:
        self.state = (self.state * 214013 + 2531011) & 0xFFFFFFFF
        return (self.state >> 16) & 0x7FFF


def mangle(digest: bytes) -> str:
    """Digest to id: base64, strip the padding, then the seeded swap pass.

    The swap is `swap(s[i], s[0])` and not a rotation or a reversal, so the
    first character takes part in every swap that fires.
    """
    out = list(base64.b64encode(digest).decode("ascii").rstrip("="))
    rand = MsvcRand(checksum(digest))
    for _ in range(DISCARDED_DRAWS):
        rand.next()
    for index in range(len(out)):
        if rand.next() % 10 + 1 > SWAP_THRESHOLD:
            out[index], out[0] = out[0], out[index]
    return "".join(out)


def computer_id_from_components(application_id: str, hardware_only: bool,
                                drive: str, volume: str, cpu: str,
                                memory: str) -> Tuple[str, str]:
    """The id and the string it was hashed from, with every component given.

    Split out from `computer_id` so the whole algorithm can be exercised on a
    machine other than the one the components came from -- which is what makes
    a known-answer test of this possible at all.
    """
    if not application_id:
        return "", ""
    preimage = drive
    preimage += " " if hardware_only else volume
    preimage += application_id
    preimage += cpu
    preimage += memory
    return mangle(native_digest(preimage.encode("latin-1"))), preimage


# --------------------------------------------------------------------------
# the components, which only Windows can answer
# --------------------------------------------------------------------------

def _kernel32():
    if os.name != "nt":
        raise ComputerIdError("the components are Windows-only: BGT reads a "
                              "physical drive's geometry, a volume serial, "
                              "CPUID and the installed memory")
    import ctypes.wintypes as wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileA.restype = ctypes.c_void_p
    k32.CreateFileA.argtypes = [ctypes.c_char_p, wintypes.DWORD,
                                wintypes.DWORD, ctypes.c_void_p,
                                wintypes.DWORD, wintypes.DWORD,
                                ctypes.c_void_p]
    k32.DeviceIoControl.argtypes = [ctypes.c_void_p, wintypes.DWORD,
                                    ctypes.c_void_p, wintypes.DWORD,
                                    ctypes.c_void_p, wintypes.DWORD,
                                    ctypes.c_void_p, ctypes.c_void_p]
    k32.CloseHandle.argtypes = [ctypes.c_void_p]
    return k32, wintypes


def drive_component() -> str:
    """`"%I64d%u%u%u%u"` of PhysicalDrive0's geometry. `0x0048D6C0`.

    The `%I64d` is the whole disk in bytes -- cylinders times tracks times
    sectors times bytes-per-sector, computed as a 64-bit signed product -- and
    the four `%u` are the cylinder count's low and high halves, the tracks per
    cylinder and the sectors per track.

    **BytesPerSector is pushed and never consumed.** The engine pushes five
    values and the format reads four, so the last one falls off the end of the
    varargs. That is not a transcription slip: counting it in would change
    every id on every machine.
    """
    k32, wintypes = _kernel32()
    handle = k32.CreateFileA(PHYSICAL_DRIVE_0, 0, 3, None, 3, 0, None)
    invalid = (None, 0xFFFFFFFF, (1 << 64) - 1)
    if handle in invalid:
        raise ComputerIdError("could not open PhysicalDrive0")
    buf = (ctypes.c_ubyte * 24)()
    returned = wintypes.DWORD()
    ok = k32.DeviceIoControl(handle, IOCTL_DISK_GET_DRIVE_GEOMETRY, None, 0,
                             ctypes.byref(buf), 24, ctypes.byref(returned),
                             None)
    k32.CloseHandle(handle)
    if not ok:
        raise ComputerIdError("PhysicalDrive0 refused the geometry request")
    low, high, _media, tracks, sectors, per_sector = struct.unpack(
        "<IIIIII", bytes(buf))
    cylinders = (high << 32) | low
    total = (cylinders * tracks * sectors * per_sector) & 0xFFFFFFFFFFFFFFFF
    total = ctypes.c_longlong(total).value
    return "%d%u%u%u%u" % (total, low, high, tracks, sectors)


def volume_component() -> str:
    """`"%u"` of C:'s volume serial, or `""` when it reads back as zero.

    The engine skips the `sprintf` entirely on a zero serial (`0x0048D859`),
    so the component is absent rather than `"0"` -- which matters, because an
    absent component shortens the preimage.
    """
    k32, wintypes = _kernel32()
    serial = wintypes.DWORD()
    ok = k32.GetVolumeInformationA(VOLUME_ROOT, None, 0,
                                   ctypes.byref(serial), None, None, None, 0)
    if not ok or serial.value == 0:
        return ""
    return "%u" % serial.value


def cpu_component() -> str:
    """`"%u%u"` of CPUID leaf 1's EAX and EDX. `0x0048D640`.

    Run as machine code through `VirtualAlloc`, because there is no other way
    to reach `cpuid` from Python and the registry does not hold the same
    numbers: Windows' own `FeatureSet` value is the kernel's feature mask, not
    `CPUID.1.EDX`. `CPU Family Model Stepping` IS `CPUID.1.EAX`, but it is not
    present on every Windows.
    """
    if os.name != "nt":
        raise ComputerIdError("CPUID is read with native code; Windows only")
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.VirtualAlloc.restype = ctypes.c_void_p
    k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                 ctypes.c_uint32, ctypes.c_uint32]
    if struct.calcsize("P") == 8:
        code = bytes((0x49, 0x89, 0xC8,              # mov r8, rcx
                      0x53,                          # push rbx
                      0xB8, 0x01, 0x00, 0x00, 0x00,  # mov eax, 1
                      0x31, 0xC9,                    # xor ecx, ecx
                      0x0F, 0xA2,                    # cpuid
                      0x41, 0x89, 0x00,              # mov [r8], eax
                      0x41, 0x89, 0x50, 0x04,        # mov [r8+4], edx
                      0x5B,                          # pop rbx
                      0xC3))
    else:
        code = bytes((0x53, 0x56,                    # push ebx, esi
                      0x8B, 0x74, 0x24, 0x0C,        # mov esi,[esp+0xc]
                      0xB8, 0x01, 0x00, 0x00, 0x00,  # mov eax, 1
                      0x31, 0xC9,                    # xor ecx, ecx
                      0x0F, 0xA2,                    # cpuid
                      0x89, 0x06,                    # mov [esi], eax
                      0x89, 0x56, 0x04,              # mov [esi+4], edx
                      0x5E, 0x5B,                    # pop esi, ebx
                      0xC3))
    page = k32.VirtualAlloc(None, len(code), 0x3000, 0x40)
    if not page:
        raise ComputerIdError("could not allocate a page for CPUID")
    ctypes.memmove(page, code, len(code))
    out = (ctypes.c_uint32 * 2)()
    ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_uint32))(page)(out)
    return "%u%u" % (out[0], out[1])


def memory_component() -> str:
    """`"%I64d"` of `GlobalMemoryStatusEx`'s `ullTotalPhys`. `0x0048D790`."""
    if os.name != "nt":
        raise ComputerIdError("the installed memory is read through "
                              "GlobalMemoryStatusEx; Windows only")
    import ctypes.wintypes as wintypes

    class MemoryStatusEx(ctypes.Structure):
        _fields_ = [("dwLength", wintypes.DWORD),
                    ("dwMemoryLoad", wintypes.DWORD),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]

    status = MemoryStatusEx()
    status.dwLength = ctypes.sizeof(status)
    ctypes.WinDLL("kernel32").GlobalMemoryStatusEx(ctypes.byref(status))
    return "%d" % ctypes.c_longlong(status.ullTotalPhys).value


def components() -> Dict[str, str]:
    """Every component this machine answers with, for a report or a test."""
    return {"drive": drive_component(), "volume": volume_component(),
            "cpu": cpu_component(), "memory": memory_component()}


def computer_id(application_id: str, hardware_only: bool = False,
                parts: Optional[Dict[str, str]] = None) -> str:
    """This machine's BGT 1.3 computer id for `application_id`.

    An empty `application_id` is an error in the engine too (`0x0049632B`
    sets -2 and returns an empty string), so it returns `""` rather than
    hashing an empty one.
    """
    parts = components() if parts is None else parts
    return computer_id_from_components(application_id, hardware_only,
                                       parts["drive"], parts["volume"],
                                       parts["cpu"], parts["memory"])[0]


# --------------------------------------------------------------------------
# checking it against the engine, which is the only evidence that counts
# --------------------------------------------------------------------------

#: What `--verify` asks the engine about. Deliberately includes the shapes a
#: wrong reading survives: one character, a long id, an id made of digits, and
#: a `%` sequence, since the components go through `sprintf`.
VERIFY_IDS = ("a", "ab", "Z", "appone", "apptwo", "x", "0123456789abcdef",
              "MyGame v1.0", "with space", "pct%u%I64d", "0", "00", "-1",
              "A" * 64, "super egg hunt")


def _probe_source() -> str:
    lines = ["void main()", "{", "    file f;",
             '    f.open("bgt_computerid_out.txt", "wb");']
    for index, name in enumerate(VERIFY_IDS):
        for flag in ("false", "true"):
            lines.append('    f.write("%d|%s|%s|" + '
                         'generate_computer_id("%s", %s) + "\\r\\n");'
                         % (index, flag, name, name, flag))
    lines += ["    f.close();", "    exit();", "}", ""]
    return "\n".join(lines)


def verify(timeout: int = 120) -> Tuple[int, int, str]:
    """Run the engine over `VERIFY_IDS` and compare. Returns (ok, total, note).

    The engine is the authority, so this is the check that says the module is
    right -- and it is the only one that can, because every stage of the
    algorithm is invisible from outside: a wrong digest byte order, a wrong
    generator and a wrong component all produce 27 plausible characters.
    """
    try:
        from . import bgt_compile
    except ImportError:
        import bgt_compile

    import tempfile

    engine = bgt_compile.find_compiler()
    if engine is None:
        return 0, 0, "no bgt.exe found, so the engine could not be asked"
    scratch = tempfile.mkdtemp(prefix="bgt_computerid_")
    script = os.path.join(scratch, "computerid.bgt")
    with open(script, "w", newline="\n") as handle:
        handle.write(_probe_source())
    # No `build` is run mode: the engine runs the script rather than
    # compiling it, which is all the probe needs and is what writes the
    # table. Its working directory is the script's own, so the table
    # lands beside it.
    report = bgt_compile.check(script, timeout=timeout)
    out = os.path.join(scratch, "bgt_computerid_out.txt")
    if not os.path.exists(out):
        return 0, 0, "the probe wrote no table (%s)" % report.outcome
    parts = components()
    ok = total = 0
    bad = []
    with open(out, encoding="latin-1") as handle:
        for row in handle:
            row = row.rstrip("\r\n")
            if not row:
                continue
            _index, flag, name, expected = row.split("|", 3)
            total += 1
            got = computer_id(name, flag == "true", parts)
            if got == expected:
                ok += 1
            else:
                bad.append("%r hardware_only=%s: got %s, engine says %s"
                           % (name, flag, got, expected))
    return ok, total, "\n".join(bad)


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="bgt computerid",
        description="BGT's generate_computer_id, reproduced exactly")
    ap.add_argument("application_id", nargs="?",
                    help="the game's own id, as the script passes it")
    ap.add_argument("--hardware-only", action="store_true",
                    help="the engine's second argument: leave the volume "
                         "serial out, so a reinstall of Windows does not "
                         "change the answer")
    ap.add_argument("--components", action="store_true",
                    help="print the four components and the hashed string")
    ap.add_argument("--verify", action="store_true",
                    help="ask bgt.exe for %d answers and compare"
                         % (len(VERIFY_IDS) * 2))
    args = ap.parse_args(argv)

    if args.verify:
        ok, total, note = verify()
        if not total:
            print("could not verify: %s" % note)
            return 2
        print("%d of %d match the engine" % (ok, total))
        if note:
            print(note)
        return 0 if ok == total else 1

    if not args.application_id:
        ap.error("an application_id is required unless --verify is given")
    try:
        parts = components()
    except ComputerIdError as exc:
        print("could not read a component: %s" % exc)
        return 2
    value, preimage = computer_id_from_components(
        args.application_id, args.hardware_only, parts["drive"],
        parts["volume"], parts["cpu"], parts["memory"])
    if args.components:
        for name in ("drive", "volume", "cpu", "memory"):
            print("%-8s %s" % (name, parts[name] or "(absent)"))
        print("%-8s %s" % ("hashed", preimage))
    print(value)
    return 0


if __name__ == "__main__":
    sys.exit(main())
