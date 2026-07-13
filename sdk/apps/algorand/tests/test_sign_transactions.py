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

"""Single-transaction signing.

The transaction is built with the reference implementation (algosdk, via
`vectors`) and the device's signature is verified cryptographically as ed25519
over ``"TX" || txn`` — so the test proves `tiny-algo` parsed the canonical bytes
and signed the exact right message, rather than merely reproducing a recorded
signature.
"""

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from trezorlib.debuglink import DebugSession as Session
from trezorlib.exceptions import TrezorFailure
from trezorlib.tools import parse_path

from . import algorand_ext, signing, vectors

PATH = "m/44'/283'/0'/0'/0'"


def _verify(payload: bytes, signatures, pubkey: bytes) -> None:
    assert len(signatures) == 1
    record = signatures[0]
    assert record.index == 0
    # vectors.SENDER isn't the device account, so this is a rekey-authority
    # sign and the signing key is reported in auth_address.
    assert record.auth_address == pubkey
    Ed25519PublicKey.from_public_bytes(pubkey).verify(
        bytes(record.signature), vectors.TX_DOMAIN + payload
    )


@pytest.mark.parametrize("amount", [1_000_000], ids=["single_payment"])
def test_algorand_sign_transactions(session: Session, instance_id: int, amount):
    path = parse_path(PATH)
    payload = vectors.encode(vectors.payment(amount))
    pk = algorand_ext.get_public_key(session, instance_id, path).public_key
    res = signing.sign(session, instance_id, path, payload)
    _verify(payload, res.signatures, pk)


@pytest.mark.parametrize("amount", [1_000_000], ids=["single_payment"])
def test_algorand_sign_transactions_chunked(session: Session, instance_id: int, amount):
    """Same transaction uploaded in small chunks to exercise the device's
    AlgorandContinueSignTransactions path; ed25519 signing is deterministic, so
    the chunked upload must produce a signature that verifies identically."""
    path = parse_path(PATH)
    payload = vectors.encode(vectors.payment(amount))
    pk = algorand_ext.get_public_key(session, instance_id, path).public_key
    res = signing.sign(session, instance_id, path, payload, chunk_size=16)
    _verify(payload, res.signatures, pk)


def test_algorand_sign_transactions_empty(session: Session, instance_id: int):
    # Empty payload is rejected before any review screen, so no input flow.
    path = parse_path(PATH)
    with pytest.raises(TrezorFailure):
        algorand_ext.sign_transactions(session, instance_id, path, b"")
