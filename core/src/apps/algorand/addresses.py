from trezor.crypto import base32
from trezor.crypto.hashlib import sha512_256


def public_key_to_address(pubkey: bytes) -> str:
    """Convert a 32-byte Ed25519 public key to a 58-char Algorand address."""
    digest = sha512_256(pubkey).digest()
    checksum = digest[-4:]
    address_bytes = pubkey + checksum
    return base32.encode(address_bytes).rstrip("=")


def address_to_public_key(address: str) -> bytes:
    """Decode a 58-char Algorand address to its 32-byte public key."""
    padded = address + "=" * (-len(address) % 8)
    decoded = base32.decode(padded)
    pubkey = decoded[:32]
    checksum = decoded[32:]
    digest = sha512_256(pubkey).digest()
    if digest[-4:] != checksum:
        raise ValueError("Invalid address checksum")
    return pubkey
