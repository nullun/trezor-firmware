#!/usr/bin/env python3
"""Capture a FALCON-DET1024 KAT vector from a connected Trezor.

Non-destructive: just calls AlgorandGetFalconAddress and AlgorandSignTx
with a fixed minimal payment payload. Compare the output before vs.
after flashing the asm-enabled firmware to confirm determinism.

Usage:
    python tools/falcon_kat_device.py [BIP32-PATH]

Default path is m/44h/283h/0h/0h/0h. Requires a non-debug device
connected over USB; uses trezorlib transport directly so no debuglink
firmware is needed.
"""

from __future__ import annotations

import hashlib
import sys
import time
from struct import pack

from trezorlib.algorand import SIG_FALCON_DET1024, get_falcon_address, sign_tx
from trezorlib.client import get_default_client
from trezorlib.tools import parse_path


def minimal_msgpack_payment(sender: bytes) -> bytes:
    """Same canonical Algorand payment skeleton as test_falcon.py."""

    def fixstr(s: str) -> bytes:
        b = s.encode("ascii")
        return bytes([0xA0 | len(b)]) + b

    def bin32(b: bytes) -> bytes:
        assert len(b) == 32
        return bytes([0xC4, 32]) + b

    def pos_int(n: int) -> bytes:
        if n < 0x80:
            return bytes([n])
        if n <= 0xFF:
            return bytes([0xCC, n])
        if n <= 0xFFFF:
            return bytes([0xCD]) + pack(">H", n)
        if n <= 0xFFFFFFFF:
            return bytes([0xCE]) + pack(">I", n)
        return bytes([0xCF]) + pack(">Q", n)

    fields = [
        ("fee", pos_int(1000)),
        ("fv", pos_int(1)),
        ("gh", bin32(b"\x00" * 32)),
        ("lv", pos_int(1000)),
        ("rcv", bin32(b"\x00" * 32)),
        ("snd", bin32(sender)),
        ("type", fixstr("pay")),
    ]
    body = b"".join(fixstr(k) + v for k, v in fields)
    return bytes([0x80 | len(fields)]) + body


def algorand_address_decode(address: str) -> bytes:
    import base64
    padded = address + "=" * (-len(address) % 8)
    return base64.b32decode(padded)[:32]


def main() -> int:
    bip32 = sys.argv[1] if len(sys.argv) > 1 else "m/44h/283h/0h/0h/0h"
    address_n = parse_path(bip32)

    client = get_default_client("falcon_kat_device")
    session = client.get_session()

    t0 = time.perf_counter()
    info = get_falcon_address(session, address_n)
    t_address = time.perf_counter() - t0
    pubkey_sha = hashlib.sha256(info.public_key).hexdigest()

    print(f"path           = {bip32}")
    print(f"address        = {info.address}")
    print(f"counter        = {info.counter}")
    print(f"teal_version   = {info.teal_version}")
    print(f"pubkey_len     = {len(info.public_key)}")
    print(f"pubkey_sha256  = {pubkey_sha}")
    print(f"t_get_address  = {t_address*1000:.1f} ms (keygen + LogicSig search)")

    sender = algorand_address_decode(info.address)
    raw = minimal_msgpack_payment(sender)

    t0 = time.perf_counter()
    sig = sign_tx(session, address_n, raw, signature_type=SIG_FALCON_DET1024)
    t_sign = time.perf_counter() - t0
    sig_sha = hashlib.sha256(sig).hexdigest()

    print(f"sig_len        = {len(sig)}")
    print(f"sig_sha256     = {sig_sha}")
    print(f"t_sign_tx      = {t_sign*1000:.1f} ms (keygen + sign + UI confirm)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
