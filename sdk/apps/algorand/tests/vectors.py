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

"""Build Algorand test vectors with the reference py-algorand-sdk.

algosdk is the independent oracle for the device's `tiny-algo` codec. The
device must parse the exact canonical msgpack algosdk emits, recompute the same
atomic-group ID, encode the same address, and sign the exact ``"TX" || txn``
message. Feeding it algosdk-built vectors and checking the results against
algosdk / a standalone ed25519 verify is therefore a genuine cross-implementation
conformance test — there is no hand-rolled protocol code to trust.
"""

from __future__ import annotations

import base64

from algosdk import encoding, transaction

#: ed25519 signing-domain prefix Algorand puts in front of a transaction.
TX_DOMAIN = b"TX"

#: Matches the device's ``MAX_TXN_GROUP_SIZE``; algosdk enforces the same cap.
MAX_GROUP_SIZE = 16

#: Shared test identities. ``SENDER`` is deliberately not the device's own
#: account, so the device signs as that account's rekeyed authority and reports
#: its own key in ``auth_address`` (asserted by the group tests).
SENDER = encoding.encode_address(bytes([0xAA]) * 32)
RECEIVER = encoding.encode_address(bytes([0xBB]) * 32)
GENESIS_HASH = bytes(range(32))


def address_of(pubkey: bytes) -> str:
    """Reference Algorand address for a 32-byte ed25519 public key."""
    return encoding.encode_address(pubkey)


def _params(
    *, fee: int = 1000, first: int = 100, last: int = 1100, genesis_hash: bytes = GENESIS_HASH
) -> transaction.SuggestedParams:
    return transaction.SuggestedParams(
        fee=fee,
        first=first,
        last=last,
        gh=base64.b64encode(genesis_hash).decode(),
        gen=None,
        flat_fee=True,
    )


def _addr(byte: int) -> str:
    return encoding.encode_address(bytes([byte]) * 32)


# Fixed auxiliary identities/ids so every builder is deterministic (stable
# golden fixtures). Distinct bytes keep addresses visually distinguishable.
MANAGER = _addr(0xC1)
RESERVE = _addr(0xC2)
FREEZE = _addr(0xC3)
CLAWBACK = _addr(0xC4)
REKEY_TO = _addr(0xC5)
CLOSE_TO = _addr(0xC6)
FREEZE_TARGET = _addr(0xC7)
ASSET_ID = 1234
APP_ID = 999
# Opaque fixed "program" bytes; the device hashes and byte-counts them, it
# does not execute TEAL, so any stable bytes work.
_PROGRAM = bytes([0x0A, 0x81, 0x01, 0x22, 0x43])


def payment(
    amount: int,
    *,
    sender: str = SENDER,
    receiver: str = RECEIVER,
    close_to: "str | None" = None,
    rekey_to: "str | None" = None,
    **params,
):
    """A fresh payment transaction (mutable; grouping mutates its ``group``)."""
    return transaction.PaymentTxn(
        sender=sender,
        sp=_params(**params),
        receiver=receiver,
        amt=amount,
        close_remainder_to=close_to,
        rekey_to=rekey_to,
    )


def keyreg_online(*, sender: str = SENDER, **params):
    return transaction.KeyregOnlineTxn(
        sender=sender,
        sp=_params(**params),
        votekey=base64.b64encode(bytes([0x10]) * 32).decode(),
        selkey=base64.b64encode(bytes([0x20]) * 32).decode(),
        sprfkey=base64.b64encode(bytes([0x30]) * 64).decode(),
        votefst=1,
        votelst=1000,
        votekd=10,
    )


def keyreg_offline(*, sender: str = SENDER, **params):
    return transaction.KeyregOfflineTxn(sender=sender, sp=_params(**params))


def keyreg_nonpart(*, sender: str = SENDER, **params):
    return transaction.KeyregNonparticipatingTxn(sender=sender, sp=_params(**params))


def asset_transfer(
    amount: int,
    *,
    asset_id: int = ASSET_ID,
    sender: str = SENDER,
    receiver: str = RECEIVER,
    close_to: "str | None" = None,
    **params,
):
    return transaction.AssetTransferTxn(
        sender=sender,
        sp=_params(**params),
        receiver=receiver,
        amt=amount,
        index=asset_id,
        close_assets_to=close_to,
    )


def asset_freeze(*, asset_id: int = ASSET_ID, target: str = FREEZE_TARGET, frozen: bool = True, sender: str = SENDER, **params):
    return transaction.AssetFreezeTxn(
        sender=sender,
        sp=_params(**params),
        index=asset_id,
        target=target,
        new_freeze_state=frozen,
    )


def asset_create(*, sender: str = SENDER, **params):
    return transaction.AssetConfigTxn(
        sender=sender,
        sp=_params(**params),
        index=0,
        total=1_000_000,
        decimals=2,
        default_frozen=False,
        unit_name="TAT",
        asset_name="Test Asset",
        url="https://example.com/asset",
        manager=MANAGER,
        reserve=RESERVE,
        freeze=FREEZE,
        clawback=CLAWBACK,
        strict_empty_address_check=False,
    )


def asset_reconfigure(*, asset_id: int = ASSET_ID, sender: str = SENDER, **params):
    return transaction.AssetConfigTxn(
        sender=sender,
        sp=_params(**params),
        index=asset_id,
        manager=MANAGER,
        reserve=RESERVE,
        freeze=FREEZE,
        clawback=CLAWBACK,
        strict_empty_address_check=False,
    )


def asset_destroy(*, asset_id: int = ASSET_ID, sender: str = SENDER, **params):
    return transaction.AssetConfigTxn(
        sender=sender, sp=_params(**params), index=asset_id, strict_empty_address_check=False
    )


def app_create(*, sender: str = SENDER, **params):
    return transaction.ApplicationCallTxn(
        sender=sender,
        sp=_params(**params),
        index=0,
        on_complete=0,  # NoOp
        approval_program=_PROGRAM,
        clear_program=_PROGRAM,
        global_schema=transaction.StateSchema(num_uints=1, num_byte_slices=1),
        local_schema=transaction.StateSchema(num_uints=0, num_byte_slices=0),
    )


def app_call(*, app_id: int = APP_ID, on_complete: int = 0, args: "list | None" = None, sender: str = SENDER, **params):
    return transaction.ApplicationCallTxn(
        sender=sender,
        sp=_params(**params),
        index=app_id,
        on_complete=on_complete,
        app_args=args,
    )


def rekey(txn, *, to: str = REKEY_TO):
    """Attach a rekey to any transaction and return it.

    `rekey` is a common transaction-header field — every type can carry it —
    so the device's rekey danger gate is type-agnostic.
    """
    txn.rekey_to = to
    return txn


def encode(txn) -> bytes:
    """Canonical msgpack of the bare transaction map — what the device parses."""
    return base64.b64decode(encoding.msgpack_encode(txn))


def group_id(txns: list) -> bytes:
    """The atomic-group ID algosdk computes for ``txns`` (does not mutate them)."""
    return transaction.calculate_group_id(txns)


def group(txns: list, *, grps: "list | None" = None) -> "tuple[bytes, list[bytes], bytes]":
    """Build a group payload; return ``(concatenated, [member_bytes], group_id)``.

    By default every member carries the correct group ID (a valid group). Pass
    ``grps`` to override per-member ``grp``: 32 bytes forces a value, ``None``
    omits the field — this is how the rejection tests forge tampered/ungrouped
    members without any hand-rolled encoding.
    """
    gid = transaction.calculate_group_id(txns)
    if grps is None:
        grps = [gid] * len(txns)
    for txn, grp in zip(txns, grps):
        txn.group = grp
    members = [encode(txn) for txn in txns]
    return b"".join(members), members, gid


def concat(txns: list) -> bytes:
    """Concatenate encoded transactions without grouping — for the too-large
    case, where the device rejects on member count before any group check."""
    return b"".join(encode(txn) for txn in txns)
