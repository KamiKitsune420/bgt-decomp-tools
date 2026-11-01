"""
bgt_string_crypt -- BGT's string_encrypt / string_decrypt.

Read out of the runtime (`FUN_0045b3d0` and the routines it calls). The same three
pieces show up everywhere BGT encrypts anything, which is why identifying them once
explains the executable overlay, the asset packs and the script's own calls at once:

    FUN_00458800   the KDF                     -> bgt_kdf.kdf()
    FUN_00495fc0   key setup                   -> SHA256(cstring) then makeKey/cipherInit
    FUN_004967a0   the CBC operation

Key setup, transcribed:

    SHA256_Init(); SHA256_Update(pw, strlen(pw)); SHA256_Final(digest)   # 32 bytes
    hex = 64-char lowercase hex of digest
    makeKey(enc, DIR_ENCRYPT, hex);  makeKey(dec, DIR_DECRYPT, hex)      # AES-256
    cipherInit(cipher, mode = (flag != 0) + 1, hex)                      # 1=ECB 2=CBC

Two things fall straight out of that:

* The key is taken with **strlen**, so it stops at the first NUL. That is exactly why
  the KDF scrubs NULs out of its own output -- a NUL there would silently truncate
  the key.
* `cipherInit` is handed the *same* hex, and the reference API reads 32 hex chars of
  it as the IV, so **IV = digest[:16]** -- the identical arrangement as the overlay.

The plaintext is wrapped before encryption:

    "printf" + decimal(len(data)) + "\\0" + data

`string_decrypt` decrypts, requires the result to start with `printf`, reads the
decimal length, and returns exactly that many bytes. It is the same length-declaring
container convention as the executable overlay -- BGT reuses it everywhere.

`FUN_0045b3d0` takes a flag choosing whether the key argument is used **raw** or is
first put through the KDF. Both variants are provided below.
"""

import hashlib
from typing import Optional, Tuple, Union

try:
    from Crypto.Cipher import AES
except ImportError:
    from Cryptodome.Cipher import AES

try:
    from . import bgt_kdf
except ImportError:
    import bgt_kdf


def _cstr(b: bytes) -> bytes:
    """BGT hands the key to strlen, so everything past the first NUL is dropped."""
    i = b.find(b"\x00")
    return b if i < 0 else b[:i]


def aes_params(password: Union[bytes, str], use_kdf: bool = True) -> Tuple[bytes, bytes]:
    """Return (key, iv) exactly as FUN_00495fc0 builds them."""
    if isinstance(password, str):
        password = password.encode("utf-8")
    if use_kdf:
        password = bgt_kdf.kdf(password)
    digest = hashlib.sha256(_cstr(password)).digest()
    return digest, digest[:16]


def wrap(data: bytes) -> bytes:
    """The plaintext container: printf<len>\\0<data>."""
    return b"printf" + str(len(data)).encode() + b"\x00" + data


def unwrap(plaintext: bytes) -> Optional[bytes]:
    """Reverse of wrap(); returns None if the header is not there."""
    if not plaintext.startswith(b"printf"):
        return None
    nul = plaintext.find(b"\x00", 6)
    if nul < 0:
        return None
    try:
        n = int(plaintext[6:nul])
    except ValueError:
        return None
    return plaintext[nul + 1:nul + 1 + n] if n > 0 else None


def string_encrypt(data: Union[bytes, str], password: Union[bytes, str],
                   use_kdf: bool = True) -> bytes:
    if isinstance(data, str):
        data = data.encode("utf-8")
    key, iv = aes_params(password, use_kdf)
    pt = wrap(data)
    pt += b"\x00" * ((-len(pt)) % 16)
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pt)


def string_decrypt(blob: bytes, password: Union[bytes, str],
                   use_kdf: bool = True) -> Optional[bytes]:
    key, iv = aes_params(password, use_kdf)
    n = len(blob) - len(blob) % 16
    return unwrap(AES.new(key, AES.MODE_CBC, iv).decrypt(blob[:n]))


def head_matches(blob: bytes, password: Union[bytes, str],
                 use_kdf: bool = True) -> bool:
    """Would this password open this blob? Decided on the FIRST BLOCK alone.

    `string_decrypt` is self-checking -- the plaintext has to begin `printf` --
    and CBC decrypts the first block from the IV alone, so a candidate costs
    one AES block rather than a decryption of the whole file. That is the
    difference between searching a module's literals and not bothering:
    Manamon 1 offers tens of thousands of candidates and its room files are
    25 KB each, so a full decrypt per candidate is gigabytes of work to learn
    something the first sixteen bytes already settle.

    A false positive would need a wrong key whose first block happens to begin
    with those six bytes, which is one chance in 2^48. The caller still
    confirms with a real decryption before believing it.
    """
    if len(blob) < 16:
        return False
    key, iv = aes_params(password, use_kdf)
    head = AES.new(key, AES.MODE_CBC, iv).decrypt(bytes(blob[:16]))
    return head.startswith(b"printf")


def pack_key(password: Union[bytes, str]) -> bytes:
    """The AES key a pack entry ends up with after set_sound_decryption_key().

    Same path as everything else: KDF, then SHA256 of the NUL-terminated result.
    Pack payloads themselves are ECB, so only the key matters, not the IV.
    """
    return aes_params(password, use_kdf=True)[0]


if __name__ == "__main__":
    import sys
    data = (sys.argv[1] if len(sys.argv) > 1 else "hello").encode()
    pw = (sys.argv[2] if len(sys.argv) > 2 else "key").encode()
    blob = string_encrypt(data, pw)
    print("encrypted %d -> %d bytes: %s..." % (len(data), len(blob), blob[:24].hex()))
    print("round-trip:", string_decrypt(blob, pw) == data)
