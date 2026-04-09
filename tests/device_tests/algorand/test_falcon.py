# This file is part of the Trezor project.
#
# Copyright (C) SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

"""Device tests for the Algorand FALCON-DET1024 (post-quantum) signing path.

These tests exercise the device side of the post-quantum flow:

* Address derivation returns a 58-character LogicSig contract address
  along with the raw 1793-byte FALCON public key.
* Signing the same transaction twice yields bitwise-identical
  signatures (deterministic mode).
* Trying to sign a transaction whose sender does not match the LogicSig
  account is rejected.

Signature verification is intentionally *not* performed on-device:
verification happens on-chain via the AVM ``falcon_verify`` opcode.
Host-side verification, when required, can be done with the
``algorandfoundation/falcon-signatures`` library or the Falcon C library
directly. These tests therefore only check structural properties of the
returned signatures and the device's deterministic behaviour.
"""

import base64
import hashlib

import pytest

from trezorlib.algorand import (
    SIG_FALCON_DET1024,
    get_falcon_address,
    sign_tx,
)
from trezorlib.debuglink import DebugSession as Session
from trezorlib.exceptions import TrezorFailure
from trezorlib.tools import parse_path

from ...input_flows import InputFlowConfirmAllWarnings

pytestmark = [
    pytest.mark.altcoin,
    pytest.mark.algorand,
    pytest.mark.models("core"),
]


# Falcon-1024 raw public key length.
FALCON_PUBKEY_SIZE = 1793
# Compressed FALCON-DET1024 signatures are bounded above but not fixed.
FALCON_SIG_MAX = 1500
# Loose lower bound — anything materially smaller would indicate the
# library returned an Ed25519-sized payload by mistake.
FALCON_SIG_MIN = 600

DEFAULT_PATH = "m/44h/283h/0h/0h/0h"


def test_get_falcon_address(session: Session) -> None:
    info = get_falcon_address(session, parse_path(DEFAULT_PATH))

    # 58-char base32 with no padding.
    assert isinstance(info.address, str)
    assert len(info.address) == 58
    # Public key has the deterministic Falcon-1024 size.
    assert isinstance(info.public_key, bytes)
    assert len(info.public_key) == FALCON_PUBKEY_SIZE
    # Counter is at most one byte; default TEAL version is 12.
    assert 0 <= info.counter <= 255
    assert info.teal_version == 12


def test_get_falcon_address_is_deterministic(session: Session) -> None:
    """Same path twice must yield identical address and pubkey."""
    a = get_falcon_address(session, parse_path(DEFAULT_PATH))
    b = get_falcon_address(session, parse_path(DEFAULT_PATH))
    assert a.address == b.address
    assert a.public_key == b.public_key
    assert a.counter == b.counter


def test_sign_tx_falcon_single(session: Session) -> None:
    address_n = parse_path(DEFAULT_PATH)
    info = get_falcon_address(session, address_n)
    raw = _minimal_msgpack_payment(sender=_algorand_address_decode(info.address))

    with session.client as client:
        client.set_input_flow(InputFlowConfirmAllWarnings(session).get())
        sig = sign_tx(
            session,
            address_n=address_n,
            serialized_tx=raw,
            signature_type=SIG_FALCON_DET1024,
        )

    assert isinstance(sig, bytes)
    assert FALCON_SIG_MIN <= len(sig) <= FALCON_SIG_MAX


def test_sign_tx_falcon_is_deterministic(session: Session) -> None:
    address_n = parse_path(DEFAULT_PATH)
    info = get_falcon_address(session, address_n)
    raw = _minimal_msgpack_payment(sender=_algorand_address_decode(info.address))

    with session.client as client:
        client.set_input_flow(InputFlowConfirmAllWarnings(session).get())
        sig_a = sign_tx(
            session, address_n, raw, signature_type=SIG_FALCON_DET1024
        )

    with session.client as client:
        client.set_input_flow(InputFlowConfirmAllWarnings(session).get())
        sig_b = sign_tx(
            session, address_n, raw, signature_type=SIG_FALCON_DET1024
        )

    # Deterministic FALCON: same key + same message must give the same
    # bytes. Any non-determinism is a catastrophic security failure.
    assert sig_a == sig_b


def test_sign_tx_falcon_wrong_sender(session: Session) -> None:
    """Signing a tx whose sender is not the FALCON LogicSig must fail."""
    info = get_falcon_address(session, parse_path(DEFAULT_PATH))
    # Use the first 32 bytes of the FALCON pubkey as a deliberate wrong
    # "sender" — definitely not the LogicSig contract address. The device
    # should reject the request before any signing happens.
    bogus_sender = info.public_key[:32]

    serialized_tx = _minimal_msgpack_payment(sender=bogus_sender)

    with pytest.raises(TrezorFailure):
        sign_tx(
            session,
            parse_path(DEFAULT_PATH),
            serialized_tx,
            signature_type=SIG_FALCON_DET1024,
        )


def _algorand_address_decode(address: str) -> bytes:
    padded = address + "=" * (-len(address) % 8)
    decoded = base64.b32decode(padded)
    pubkey = decoded[:32]
    checksum = decoded[32:]
    digest = hashlib.new("sha512_256", pubkey).digest()
    if digest[-4:] != checksum:
        raise ValueError("Invalid address checksum")
    return pubkey


def _minimal_msgpack_payment(sender: bytes) -> bytes:
    """Hand-rolled canonical MsgPack payment skeleton.

    Produces ``{"fee":1000,"fv":1,"gh":<32 zero bytes>,"lv":1000,
    "rcv":<32 zero bytes>,"snd":<sender>,"type":"pay"}``. Keys are
    sorted, integers are packed minimally and ``type`` is "pay".
    """
    from struct import pack

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

    fields: list[tuple[str, bytes]] = [
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
