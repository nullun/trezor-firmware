from typing import *
from buffer_types import *


PRIVKEY_SIZE: int
PUBKEY_SIZE: int
SIG_COMPRESSED_MAXSIZE: int


# upymod/modtrezorcrypto/modtrezorcrypto-falcon.h
def keygen(seed: bytes) -> tuple[bytearray, bytes]:
    """
    Generate a FALCON-DET1024 keypair deterministically from a 32-byte
    seed. Uses an internal static work buffer (~80 KB).

    Returns a tuple (privkey, pubkey) where privkey is a mutable
    bytearray (so it can be securely zeroized via falcon.zeroize())
    of FALCON_DET1024_PRIVKEY_SIZE bytes, and pubkey is bytes of
    FALCON_DET1024_PUBKEY_SIZE bytes.
    """


# upymod/modtrezorcrypto/modtrezorcrypto-falcon.h
def sign_compressed(privkey: bytes, data: bytes) -> bytes:
    """
    Sign data with FALCON-DET1024 in compressed format.
    Uses an internal static work buffer (~80 KB).
    Returns a variable-length signature (up to
    FALCON_DET1024_SIG_COMPRESSED_MAXSIZE bytes).
    """


# upymod/modtrezorcrypto/modtrezorcrypto-falcon.h
def zeroize(buf: bytearray) -> None:
    """
    Securely zeroize a mutable buffer (typically a FALCON private key
    held in a bytearray). Resists compiler dead-store elimination.
    """
