"""Known-answer tests for BGT's `generate_computer_id`.

Every value here is machine-independent: the components are a recorded
measurement rather than a live read, so the whole algorithm is exercised
anywhere while the only machine-specific part -- reading the four components
-- is left to `bgt computerid --verify`, which asks the engine.

The vectors are the engine's own answers, taken from `bgt.exe` 1.3 on the
machine whose components are pinned below. Keeping both halves is the point:
without the components the answers mean nothing, and without the answers the
components are only a dump.
"""

import base64
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                os.pardir, "tools"))

import bgt_computer_id as cid


#: The four components as `bgt.exe` 1.3 read them on one machine, with the
#: engine's own answers beside them. A wrong reading of any stage breaks at
#: least one row: the five ids share every component but the application id,
#: so they pin the concatenation as well as the hash.
COMPONENTS = {"drive": "51210593280062260025563",
              "volume": "3759812106",
              "cpu": "7225953217816575",
              "memory": "16674521088"}

ENGINE_ANSWERS = (
    ("appone", False, "uSTDy7OEnTlz+M5rbReHPFeRHYE"),
    ("appone", True, "p2KDnvvdu1Qis/QqmbXJVjt/uA8"),
    ("apptwo", False, "E8DChgVYjNgfKw+iB5brqKfxthh"),
    ("x", False, "ktC/LvtcNk0qZ/x/sYqvKPWAuGD"),
    ("0123456789abcdef", False, "wPTnA7VDt/lzLgGmzvMyGv23XMF"),
)


def _id(application_id, hardware_only):
    return cid.computer_id_from_components(
        application_id, hardware_only, COMPONENTS["drive"],
        COMPONENTS["volume"], COMPONENTS["cpu"], COMPONENTS["memory"])[0]


class ComputerIdTests(unittest.TestCase):

    def test_the_engines_own_answers(self):
        for application_id, hardware_only, expected in ENGINE_ANSWERS:
            with self.subTest(application_id=application_id,
                              hardware_only=hardware_only):
                self.assertEqual(_id(application_id, hardware_only), expected)

    def test_hardware_only_replaces_the_volume_serial_with_a_space(self):
        """And so is a different id, which is the whole point of the flag."""
        _value, preimage = cid.computer_id_from_components(
            "appone", True, COMPONENTS["drive"], COMPONENTS["volume"],
            COMPONENTS["cpu"], COMPONENTS["memory"])
        self.assertNotIn(COMPONENTS["volume"], preimage)
        self.assertIn(" ", preimage)
        self.assertNotEqual(_id("appone", True), _id("appone", False))

    def test_the_application_id_separates_two_games_on_one_machine(self):
        self.assertNotEqual(_id("appone", False), _id("apptwo", False))

    def test_an_empty_application_id_is_an_error_and_not_a_hash(self):
        """The engine sets -2 and returns an empty string (`0x0049632B`)."""
        self.assertEqual(cid.computer_id_from_components(
            "", False, "a", "b", "c", "d"), ("", ""))

    def test_the_id_is_always_27_characters_of_base64(self):
        alphabet = set(base64.b64encode(bytes(range(256))).decode()) - {"="}
        for application_id, hardware_only, _expected in ENGINE_ANSWERS:
            value = _id(application_id, hardware_only)
            self.assertEqual(len(value), 27)
            self.assertTrue(set(value) <= alphabet)
            self.assertNotIn("=", value)


class DigestTests(unittest.TestCase):
    """The engine's SHA-1 leaves its five state words little-endian.

    Nothing downstream can see that: the digest is still 20 bytes and still
    base64s to 27 characters, so the only check is against a standard digest
    of the same input.
    """

    def test_each_word_is_reversed_against_a_standard_sha1(self):
        self.assertEqual(cid.native_digest(b"abc").hex(),
                         "363e99a96a81064771253eba6cc250789dd8d09c")

    def test_a_standard_digest_gives_a_different_id(self):
        """Measured in the other direction, because this is the quiet one."""
        import hashlib
        standard = hashlib.sha1(b"abc").digest()
        self.assertNotEqual(cid.mangle(standard),
                            cid.mangle(cid.native_digest(b"abc")))

    def test_the_two_digests_hold_the_same_bytes(self):
        """Which is why no length, alphabet or multiset check can tell them
        apart -- and why this had to be read out of the binary."""
        import hashlib
        self.assertEqual(sorted(hashlib.sha1(b"abc").digest()),
                         sorted(cid.native_digest(b"abc")))


class ChecksumTests(unittest.TestCase):

    def test_the_recorded_value_for_a_known_digest(self):
        self.assertEqual(cid.checksum(cid.native_digest(b"abc")), 159383552)

    def test_the_bytes_are_signed(self):
        """A digest byte above 0x7F multiplies as a negative number. Read as
        unsigned the accumulator diverges at the first high byte."""
        digest = bytes([0x80] + [1] * 19)
        self.assertEqual(cid.checksum(digest),
                         cid._int32(0x7FFF * -128 - 1))

    def test_the_fifth_multiply_subtracts_the_SECOND_byte(self):
        """Not the fifth, and not the first: `0x00496530` indexes 1."""
        a = cid.checksum(bytes([1, 2, 3, 4, 5] + [1] * 15))
        b = cid.checksum(bytes([1, 9, 3, 4, 5] + [1] * 15))
        self.assertNotEqual(a, b)

    def test_the_accumulator_wraps_at_32_bits(self):
        """The product overflows constantly and the overflow is the answer, so
        it is taken as a signed 32-bit int at every step."""
        digest = bytes([0x7F] * 20)
        self.assertEqual(cid.checksum(digest),
                         cid._int32(cid.checksum(digest)))
        self.assertLess(abs(cid.checksum(digest)), 1 << 31)


class MsvcRandTests(unittest.TestCase):
    """Visual C++'s generator, pinned against its documented sequence.

    This is the one stage with an authority outside BGT, so it is checked
    against that rather than against the engine: `srand(1)` then `rand()` five
    times is 41, 18467, 6334, 26500, 19169 in every Microsoft CRT.
    """

    def test_the_documented_sequence_after_srand_1(self):
        rand = cid.MsvcRand(1)
        self.assertEqual([rand.next() for _ in range(5)],
                         [41, 18467, 6334, 26500, 19169])

    def test_every_draw_is_fifteen_bits(self):
        rand = cid.MsvcRand(0x7FFFFFFF)
        for _ in range(200):
            value = rand.next()
            self.assertTrue(0 <= value <= 0x7FFF)

    def test_a_negative_seed_is_taken_as_unsigned(self):
        """`srand` takes an `unsigned int`, and the checksum is signed, so a
        negative accumulator has to seed the same series as its two's
        complement rather than raising or masking to zero."""
        signed = cid.MsvcRand(-1)
        unsigned = cid.MsvcRand(0xFFFFFFFF)
        self.assertEqual([signed.next() for _ in range(5)],
                         [unsigned.next() for _ in range(5)])
        self.assertNotEqual([cid.MsvcRand(-1).next() for _ in range(1)],
                            [cid.MsvcRand(1).next() for _ in range(1)])


class ShuffleTests(unittest.TestCase):

    def test_the_shuffle_is_a_permutation(self):
        """Which is what makes a wrong generator invisible: the characters are
        right and only the order moves."""
        digest = cid.native_digest(b"abc")
        plain = base64.b64encode(digest).decode().rstrip("=")
        self.assertEqual(sorted(cid.mangle(digest)), sorted(plain))

    def test_the_recorded_value_for_a_known_digest(self):
        self.assertEqual(cid.mangle(cid.native_digest(b"abc")),
                         "wN6ZqWqBBkdjJT6x6MbJeJQY3J0")

    def test_the_discarded_draws_matter(self):
        """Thirteen of them, and skipping any changes the permutation."""
        digest = cid.native_digest(b"abc")
        plain = base64.b64encode(digest).decode().rstrip("=")
        self.assertEqual(cid.DISCARDED_DRAWS, 13)

        def shuffled(discard):
            out = list(plain)
            rand = cid.MsvcRand(cid.checksum(digest))
            for _ in range(discard):
                rand.next()
            for index in range(len(out)):
                if rand.next() % 10 + 1 > cid.SWAP_THRESHOLD:
                    out[index], out[0] = out[0], out[index]
            return "".join(out)

        self.assertEqual(shuffled(13), cid.mangle(digest))
        self.assertNotEqual(shuffled(12), cid.mangle(digest))
        self.assertNotEqual(shuffled(0), cid.mangle(digest))


class ConstantTests(unittest.TestCase):
    """The constants read out of the engine, so a stray edit shows up here.

    Each one was a separate read, and each is a value a plausible guess gets
    wrong: the device could have been a volume path, the IOCTL could have been
    `GET_LENGTH_INFO`, and the threshold could have been a half.
    """

    def test_the_device_path(self):
        self.assertEqual(cid.PHYSICAL_DRIVE_0,
                         b"\\\\.\\PhysicalDrive0")

    def test_the_volume_root(self):
        self.assertEqual(cid.VOLUME_ROOT, b"C:\\")

    def test_the_ioctl_is_get_drive_geometry(self):
        self.assertEqual(cid.IOCTL_DISK_GET_DRIVE_GEOMETRY, 0x70000)

    def test_the_swap_threshold(self):
        self.assertEqual(cid.SWAP_THRESHOLD, 6)


if __name__ == "__main__":
    unittest.main()
