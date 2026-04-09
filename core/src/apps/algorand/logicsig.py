"""FALCON-DET1024 Logic Signature address derivation.

Algorand exposes post-quantum signing via Logic Signature contract
accounts: a small TEAL program embeds the FALCON public key, calls the
``falcon_verify`` opcode, and the SHA-512/256 hash of the assembled
program (with a "Program" prefix) becomes the 32-byte account address.

The on-chain template looks like::

    #pragma version 12
    bytecblock <COUNTER>
    txn TxID
    arg 0
    pushbytes <FALCON_PUBKEY>
    falcon_verify

Where:
- ``<COUNTER>`` is a one-byte salt that we iterate until the resulting
  address is *not* a valid Ed25519 point. This guarantees no classical
  private key can spend from the account.
- ``<FALCON_PUBKEY>`` is the 1793-byte deterministic FALCON-1024 public
  key derived from the HD seed.

The device carries the assembled bytecode template directly. We don't
ship a TEAL assembler.
"""

from micropython import const

# Pre-compiled TEAL v12 bytecode template:
#   0x0c                 -- pragma version 12
#   0x26 0x01 0x01       -- bytecblock with 1 constant of length 1
#   0x00                 -- COUNTER placeholder (offset 4)
#   0x31 0x17            -- txn TxID (opcode 0x31, field index 23)
#   0x2d                 -- arg_0 (optimised form of arg 0)
#   0x80                 -- pushbytes
#   0x81 0x0e            -- varuint 1793 (LEB128: 0x81, 0x0e -> 0x701)
#                          followed by 1793 bytes of public key
#   0x85                 -- falcon_verify
TEAL_V12_TEMPLATE = (
    b"\x0c"
    b"\x26\x01\x01"
    b"\x00"  # COUNTER placeholder at offset 4
    b"\x31\x17"
    b"\x2d"
    b"\x80"
    b"\x81\x0e"
)
TEAL_V12_SUFFIX = b"\x85"

COUNTER_OFFSET = const(4)
PUBKEY_SIZE = const(1793)

# Forward-compatible registry. Future TEAL versions (e.g. v13 with
# native PQ accounts) can be added without touching the derivation loop.
TEMPLATES = {
    12: (TEAL_V12_TEMPLATE, TEAL_V12_SUFFIX),
}
DEFAULT_TEAL_VERSION = const(12)


def _compile_logicsig(
    pubkey: bytes, counter: int, teal_version: int = DEFAULT_TEAL_VERSION
) -> bytes:
    """Splice ``pubkey`` and ``counter`` into the TEAL template."""
    from trezor.wire import DataError

    entry = TEMPLATES.get(teal_version)
    if entry is None:
        raise DataError("Unsupported TEAL version")
    if len(pubkey) != PUBKEY_SIZE:
        raise DataError("Invalid FALCON public key size")

    prefix, suffix = entry
    return (
        prefix[:COUNTER_OFFSET]
        + bytes([counter])
        + prefix[COUNTER_OFFSET + 1 :]
        + pubkey
        + suffix
    )


def derive_falcon_logicsig_address(
    pubkey: bytes,
    teal_version: int = DEFAULT_TEAL_VERSION,
) -> tuple[bytes, int]:
    """Derive the LogicSig contract account for a FALCON public key.

    Embeds ``pubkey`` into the TEAL template, then iterates a one-byte
    counter until the SHA-512/256 hash of ``b"Program" + program`` is
    *not* a valid Ed25519 point. Returns ``(address_bytes, counter)``.
    """
    from trezor.crypto.curve import ed25519
    from trezor.crypto.hashlib import sha512_256
    from trezor.wire import DataError

    for counter in range(256):
        program = _compile_logicsig(pubkey, counter, teal_version)
        address = sha512_256(b"Program" + program).digest()
        if not ed25519.point_is_on_curve(address):
            return address, counter

    raise DataError("Could not derive off-curve FALCON LogicSig address")
