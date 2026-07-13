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

"""Atomic transaction group tests.

The device recomputes the group ID from the members and verifies each member's
`grp` field against it *before* showing any confirmation screen — so the
security-critical checks (a tampered or malformed group must never be signed)
reject early and need no confirmation. The happy-path multi-sign drives the
on-device review screens via the shared input flow in `signing`, verifying
every returned ed25519 signature.

Group payloads are built with the reference implementation (py-algorand-sdk,
via `vectors`), so the device's `tiny-algo` codec and group-ID computation are
checked against algosdk rather than against a second hand-rolled copy.
"""

import pytest

from trezorlib.debuglink import DebugSession as Session
from trezorlib.exceptions import TrezorFailure
from trezorlib.tools import parse_path

from . import algorand_ext, signing, vectors

PATH = "m/44'/283'/0'/0'/0'"


def _pay(amount: int):
    """A distinct, valid payment transaction (distinct amount => distinct txid)."""
    return vectors.payment(amount)


def _reject(session, instance_id, payload: bytes, expect_message: str):
    """Assert the device rejects `payload` with the exact failing-index message.

    Checking the message (not just that *some* failure was raised) is what
    proves the device rejected for the right reason and pinpointed the right
    member — the whole point of group validation.
    """
    with pytest.raises(TrezorFailure) as exc:
        algorand_ext.sign_transactions(
            session, instance_id, parse_path(PATH), payload
        )
    assert expect_message in str(exc.value), (
        f"expected {expect_message!r} in {str(exc.value)!r}"
    )


# ── rejection / validation (runs before any confirm screen) ──────────


def test_group_member_grp_tampered(session: Session, instance_id: int):
    """Only the second member carries a wrong group ID; the device must
    recompute the ID, find member 2 mismatched, and name it.

    Rejecting at member 2 (not member 1) is also an implicit cross-check of the
    group-ID computation: member 1's grp is our computed group ID, and it was
    accepted as matching, so the device's recomputed ID agrees with ours."""
    txns = [_pay(1), _pay(2)]
    gid = vectors.group_id(txns)
    payload, _, _ = vectors.group(txns, grps=[gid, bytes([0xFF]) * 32])
    _reject(session, instance_id, payload, "Transaction 2: Invalid transaction group")


def test_group_all_members_grp_wrong(session: Session, instance_id: int):
    """No member's grp matches the recomputed group ID -> rejected at member 1."""
    txns = [_pay(1), _pay(2)]
    wrong = bytes(32)
    payload, _, _ = vectors.group(txns, grps=[wrong, wrong])
    _reject(session, instance_id, payload, "Transaction 1: Invalid transaction group")


def test_group_without_grp_rejected(session: Session, instance_id: int):
    """Multiple transactions with no grp field cannot be signed as a group."""
    txns = [_pay(1), _pay(2)]
    payload, _, _ = vectors.group(txns, grps=[None, None])
    _reject(session, instance_id, payload, "Transaction 1: Invalid transaction group")


def test_group_too_large_rejected(session: Session, instance_id: int):
    """A group larger than the 16-member cap is rejected at parse."""
    txns = [_pay(i + 1) for i in range(vectors.MAX_GROUP_SIZE + 1)]
    payload = vectors.concat(txns)
    _reject(session, instance_id, payload, "Transaction 17: Too many transactions")


def test_single_txn_wrong_grp_rejected(session: Session, instance_id: int):
    """A lone transaction whose grp doesn't match its own 1-member group ID."""
    txn = _pay(1)
    txn.group = bytes([0xFF]) * 32
    _reject(session, instance_id, vectors.encode(txn), "Transaction 1: Invalid transaction group")


def test_group_member_malformed_rejected(session: Session, instance_id: int):
    """A structurally broken member is rejected at that member (truncated)."""
    _, members, _ = vectors.group([_pay(1), _pay(2)])
    truncated = members[0] + members[1][:-3]
    _reject(session, instance_id, truncated, "Transaction 2: Transaction data truncated")


def test_group_reordered_rejected(session: Session, instance_id: int):
    """Members signed for one order can't be replayed in another: reordering
    changes the recomputed group ID, so the members' grp no longer matches."""
    _, members, _ = vectors.group([_pay(1), _pay(2)])  # each carries the [0,1]-order id
    reordered = members[1] + members[0]
    _reject(session, instance_id, reordered, "Transaction 1: Invalid transaction group")


# ── happy path: signing a valid group (auto-confirms every review screen) ──


def _verify_group(payload_members: list[bytes], signatures, pubkey: bytes) -> None:
    """Each record must verify as ed25519 over TX || member_bytes, and its
    `index` must point at the member it signs.

    These vectors use a `SENDER` that isn't the device's own address, so the
    device signs as that account's rekeyed authority — every record must
    carry the signing key in `auth_address`.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    vk = Ed25519PublicKey.from_public_bytes(pubkey)
    assert len(signatures) == len(payload_members)
    for pos, (record, member) in enumerate(zip(signatures, payload_members)):
        assert record.index == pos
        assert record.auth_address == pubkey
        vk.verify(bytes(record.signature), vectors.TX_DOMAIN + member)


def test_group_sign_two(session: Session, instance_id: int):
    payload, members, _ = vectors.group([_pay(1_000), _pay(2_000)])
    pk = algorand_ext.get_public_key(session, instance_id, parse_path(PATH)).public_key
    res = signing.sign(session, instance_id, parse_path(PATH), payload)
    _verify_group(members, res.signatures, pk)


def test_group_sign_max(session: Session, instance_id: int):
    payload, members, _ = vectors.group([_pay(i + 1) for i in range(vectors.MAX_GROUP_SIZE)])
    pk = algorand_ext.get_public_key(session, instance_id, parse_path(PATH)).public_key
    res = signing.sign(session, instance_id, parse_path(PATH), payload)
    _verify_group(members, res.signatures, pk)


def test_group_sign_subset(session: Session, instance_id: int):
    """Request signatures for only a subset of a group: the device reviews
    the whole group (to recompute the group ID) but returns one record per
    selected index, each naming the index it signs."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    payload, members, _ = vectors.group([_pay(1_000), _pay(2_000), _pay(3_000)])
    pk = algorand_ext.get_public_key(session, instance_id, parse_path(PATH)).public_key
    res = signing.sign(
        session, instance_id, parse_path(PATH), payload, sign_indices=[0, 2]
    )
    assert [r.index for r in res.signatures] == [0, 2]
    vk = Ed25519PublicKey.from_public_bytes(pk)
    for record in res.signatures:
        vk.verify(bytes(record.signature), vectors.TX_DOMAIN + members[record.index])
        # SENDER isn't the device address, so each is a rekey-authority sign.
        assert record.auth_address == pk
