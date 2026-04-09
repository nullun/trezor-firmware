"""Helpers for deriving and using FALCON-DET1024 keypairs.

The FALCON private key is *never* stored on the device: it is
re-derived from the HD seed each time signing is required, and the
caller is expected to wipe the returned bytearray with
``zeroize_privkey`` (which calls memzero in C) once it is no longer
needed. ``derive_falcon_keypair`` should therefore be used inside a
``try/finally`` block.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apps.common.keychain import Keychain


def _falcon_seed_path(address_n: list[int]) -> list[bytes]:
    from . import FALCON_SLIP21_PATH

    # Encode each BIP-32 component as fixed-width big-endian bytes so the
    # path continues to namespace the FALCON key without reusing Ed25519
    # child key material as the FALCON seed.
    return list(FALCON_SLIP21_PATH) + [n.to_bytes(4, "big") for n in address_n]


def derive_falcon_keypair(
    keychain: "Keychain", address_n: list[int]
) -> tuple[bytearray, bytes]:
    """Deterministically derive a FALCON-DET1024 keypair.

    A domain-separated 32-byte seed is derived from the mnemonic via
    SLIP-0021 using the Algorand FALCON namespace and the encoded
    BIP-32 path components. That seed is then fed into Falcon's
    SHAKE256-based PRNG so the same mnemonic and path always yield the
    same keypair without reusing Ed25519 child key material. The
    returned ``privkey`` is a *mutable* bytearray so the caller can wipe
    it with ``zeroize_privkey``.
    """
    from trezor.crypto import falcon

    seed_bytes = keychain.derive_slip21(_falcon_seed_path(address_n)).key()

    return falcon.keygen(seed_bytes)


def falcon_sign(privkey: bytearray, data: bytes) -> bytes:
    """Sign ``data`` (typically a 32-byte TxID) with FALCON-DET1024.

    The returned compressed signature is up to ~1.4 KB. The C extension
    wipes its internal work buffer before returning.
    """
    from trezor.crypto import falcon

    return falcon.sign_compressed(privkey, data)


def zeroize_privkey(privkey: bytearray) -> None:
    """Securely scrub a FALCON private-key buffer in place."""
    from trezor.crypto import falcon

    falcon.zeroize(privkey)
