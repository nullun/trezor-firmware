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

"""One signing test per transaction type / distinct review screen.

Each vector is built with the reference implementation (algosdk) and the
device's signature is verified as ed25519 over ``"TX" || txn`` — so every
type is a conformance check that `tiny-algo` parses the canonical bytes and
signs the exact right message. The rekey/close variants also exercise the
full-screen danger gates, which previously had no coverage at all.
"""

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from trezorlib.debuglink import DebugSession as Session
from trezorlib.tools import parse_path

from . import algorand_ext, signing, vectors

PATH = "m/44'/283'/0'/0'/0'"


def _sign_and_verify(session, instance_id, txn):
    """Sign a single transaction and verify the returned signature."""
    path = parse_path(PATH)
    payload = vectors.encode(txn)
    pk = algorand_ext.get_public_key(session, instance_id, path).public_key
    res = signing.sign(session, instance_id, path, payload)
    assert len(res.signatures) == 1
    record = res.signatures[0]
    assert record.index == 0
    # vectors.SENDER isn't the device account -> rekey-authority sign.
    assert record.auth_address == pk
    Ed25519PublicKey.from_public_bytes(pk).verify(
        bytes(record.signature), vectors.TX_DOMAIN + payload
    )


# ── one of every transaction type ───────────────────────────────────


def test_sign_keyreg_online(session: Session, instance_id: int):
    _sign_and_verify(session, instance_id, vectors.keyreg_online())


def test_sign_keyreg_offline(session: Session, instance_id: int):
    _sign_and_verify(session, instance_id, vectors.keyreg_offline())


def test_sign_keyreg_nonpart(session: Session, instance_id: int):
    _sign_and_verify(session, instance_id, vectors.keyreg_nonpart())


def test_sign_asset_transfer(session: Session, instance_id: int):
    _sign_and_verify(session, instance_id, vectors.asset_transfer(5_000))


def test_sign_asset_freeze(session: Session, instance_id: int):
    _sign_and_verify(session, instance_id, vectors.asset_freeze(frozen=True))


def test_sign_asset_create(session: Session, instance_id: int):
    _sign_and_verify(session, instance_id, vectors.asset_create())


def test_sign_asset_reconfigure(session: Session, instance_id: int):
    _sign_and_verify(session, instance_id, vectors.asset_reconfigure())


def test_sign_asset_destroy(session: Session, instance_id: int):
    _sign_and_verify(session, instance_id, vectors.asset_destroy())


def test_sign_app_create(session: Session, instance_id: int):
    _sign_and_verify(session, instance_id, vectors.app_create())


def test_sign_app_call_blind(session: Session, instance_id: int):
    # App call carrying args -> exercises the blind-signing acknowledgement gate.
    _sign_and_verify(session, instance_id, vectors.app_call(args=[b"method", b"\x01"]))


# ── danger gates ─────────────────────────────────────────────────────


# rekey is a common header field, not payment-specific: any transaction type
# can carry it, so the rekey danger gate must fire regardless of body type.
@pytest.mark.parametrize(
    "make",
    [
        lambda: vectors.payment(1_000_000),
        vectors.keyreg_offline,
        lambda: vectors.asset_transfer(5_000),
        lambda: vectors.app_call(),
    ],
    ids=["payment", "keyreg", "asset_transfer", "app_call"],
)
def test_sign_rekey(session: Session, instance_id: int, make):
    _sign_and_verify(session, instance_id, vectors.rekey(make()))


# close-out fields, by contrast, ARE type-specific.
def test_sign_payment_close(session: Session, instance_id: int):
    _sign_and_verify(session, instance_id, vectors.payment(1_000_000, close_to=vectors.CLOSE_TO))


def test_sign_asset_transfer_close(session: Session, instance_id: int):
    _sign_and_verify(session, instance_id, vectors.asset_transfer(5_000, close_to=vectors.CLOSE_TO))
