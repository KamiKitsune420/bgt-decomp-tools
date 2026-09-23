"""Synthetic fixtures containing no supplied games or engine binaries."""
import struct


def owned_pe_stub():
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 128)
    data[128:132] = b"PE\0\0"
    struct.pack_into("<HH", data, 132, 0x8664, 1)
    struct.pack_into("<H", data, 148, 240)
    struct.pack_into("<H", data, 152, 0x20b)
    struct.pack_into("<I", data, 212, 512)
    struct.pack_into("<II", data, 272, 4096, 40)
    struct.pack_into("<8sIIII", data, 392, b".rdata\0\0", 512, 4096, 512, 512)
    struct.pack_into("<I", data, 524, 4160)
    data[576:589] = b"KERNEL32.dll\0"
    return bytes(data)
