# flake8: noqa: F403,F405
from common import *  # isort:skip

from trezor.crypto import hashlib


class TestCryptoSha512_256(unittest.TestCase):

    # Test vectors from NIST CSRC / FIPS 180-4
    # See: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512_256.pdf
    vectors = [
        (
            b"abc",
            "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
        ),
        (
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a",
        ),
    ]

    def test_digest(self):
        for b, d in self.vectors:
            self.assertEqual(hashlib.sha512_256(b).digest(), unhexlify(d))

    def test_update(self):
        for b, d in self.vectors:
            x = hashlib.sha512_256()
            x.update(b)
            self.assertEqual(x.digest(), unhexlify(d))

    def test_empty(self):
        # SHA-512/256("") known value
        x = hashlib.sha512_256(b"")
        self.assertEqual(
            x.digest(),
            unhexlify(
                "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"
            ),
        )

    def test_digest_size(self):
        x = hashlib.sha512_256()
        self.assertEqual(x.digest_size, 32)

    def test_block_size(self):
        x = hashlib.sha512_256()
        self.assertEqual(x.block_size, 128)

    def test_digest_multi(self):
        x = hashlib.sha512_256()
        d0 = x.digest()
        d1 = x.digest()
        d2 = x.digest()
        self.assertEqual(d0, d1)
        self.assertEqual(d0, d2)

    def test_algorand_address_checksum(self):
        """Verify SHA-512/256 produces correct Algorand address checksums.

        Test that a known public key hashes to the expected digest,
        from which the last 4 bytes form the address checksum.
        """
        # This is a placeholder - fill in with a known Algorand pubkey/address pair
        # TODO: Add test vector from a known Algorand SDK or the Ledger app
        pass


if __name__ == "__main__":
    unittest.main()
