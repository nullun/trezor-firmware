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

import io
from typing import TYPE_CHECKING, Any, Optional

from trezorlib import exceptions, protobuf
from trezorlib.messages import Failure, TrezorAppMessage, TrezorAppResponse

from .generated import messages as algorand_messages

if TYPE_CHECKING:
    from trezorlib.client import Session
    from trezorlib.tools import Address


def message_id(msg: type[protobuf.MessageType] | algorand_messages.MessageType) -> int:
    """Return app-specific numeric message ID for a message class or instance."""
    if isinstance(msg, type):
        name = msg.__name__
    else:
        name = msg.__class__.__name__

    try:
        return int(algorand_messages.MessageType[name])
    except KeyError as e:
        raise ValueError(f"Unknown message type: {name}") from e


def message_type(msg_id: int) -> type[protobuf.MessageType]:
    """Convert message ID (int) to message class type."""
    try:
        enum_name = algorand_messages.MessageType(msg_id).name
        return getattr(algorand_messages, enum_name)
    except ValueError as e:
        raise ValueError(f"Unknown message ID: {msg_id}") from e


def call_ext(
    session: "Session",
    instance_id: int,
    *,
    msg_data: algorand_messages.MessageType,
    expect: list[type[algorand_messages.MessageType]],
    timeout: float | None = None,
) -> Any:
    """Send one app message and decode the response into a concrete type.

    The inner request body is serialized into the opaque `data` field of a
    `TrezorAppMessage`; the response's `message_id` selects which of the
    `expect` classes to decode the response `data` against.
    """
    buf = io.BytesIO()
    protobuf.dump_message(buf, msg_data)

    msg = TrezorAppMessage(
        instance_id=instance_id,
        message_id=message_id(msg_data),
        data=buf.getvalue(),
    )
    if session.is_invalid:
        raise exceptions.InvalidSessionError(session.id)
    with session:
        resp = session.client._call(
            session, msg, expect=TrezorAppResponse, timeout=timeout
        )
        buf = io.BytesIO(resp.data)

        assert isinstance(expect, list)
        assert len(expect) > 0

        expect_ids = [message_id(cls) for cls in expect]
        try:
            idx = expect_ids.index(resp.message_id)
        except ValueError:
            raise exceptions.TrezorFailure(
                failure=Failure(message="Unexpected response type")
            )
        # Decode errors propagate (they're real bugs, not "unexpected type").
        return protobuf.load_message(buf, expect[idx])


# ====== Client functions ====== #


def get_public_key(
    session: "Session",
    instance_id: int,
    n: "Address",
    show_display: bool = False,
) -> algorand_messages.AlgorandPublicKey:
    """Request the ed25519 public key and canonical Algorand address."""
    return call_ext(
        session,
        instance_id,
        msg_data=algorand_messages.AlgorandGetPublicKey(
            address_n=n,
            show_display=show_display,
        ),
        expect=[algorand_messages.AlgorandPublicKey],
    )


def sign_transactions(
    session: "Session",
    instance_id: int,
    n: "Address",
    transactions: bytes,
    *,
    chunk_size: Optional[int] = None,
    sign_indices: Optional[list[int]] = None,
) -> algorand_messages.AlgorandTransactionSignatures:
    """Sign concatenated canonical-msgpack transactions.

    `transactions` is the full payload (one txn, or 2..=16 group members
    concatenated in canonical order). When `chunk_size` is given and smaller
    than the payload, only the first `chunk_size` bytes are sent with the
    opening message; the device then pulls the rest by responding with
    `AlgorandTxRequest`, answered here with `AlgorandTxAck` chunks (capped at
    both the device's requested `data_length` and `chunk_size`). Otherwise
    the payload is sent in a single message.

    `sign_indices` selects a subset of the group to sign; when omitted the
    device signs every member.
    """
    if chunk_size is None or chunk_size >= len(transactions):
        return call_ext(
            session,
            instance_id,
            msg_data=algorand_messages.AlgorandSignTransactions(
                address_n=n,
                transactions=transactions,
                sign_indices=sign_indices,
            ),
            expect=[algorand_messages.AlgorandTransactionSignatures],
        )

    expect = [
        algorand_messages.AlgorandTxRequest,
        algorand_messages.AlgorandTransactionSignatures,
    ]
    first, rest = transactions[:chunk_size], transactions[chunk_size:]
    resp = call_ext(
        session,
        instance_id,
        msg_data=algorand_messages.AlgorandSignTransactions(
            address_n=n,
            transactions=first,
            total_size=len(transactions),
            sign_indices=sign_indices,
        ),
        expect=expect,
    )
    while isinstance(resp, algorand_messages.AlgorandTxRequest):
        size = min(resp.data_length, chunk_size)
        chunk, rest = rest[:size], rest[size:]
        resp = call_ext(
            session,
            instance_id,
            msg_data=algorand_messages.AlgorandTxAck(data=chunk),
            expect=expect,
        )

    return algorand_messages.AlgorandTransactionSignatures.ensure_isinstance(resp)


def resp_filter(msg: protobuf.MessageType) -> protobuf.MessageType:
    """Decode a TrezorAppResponse payload into its concrete message instance."""
    if isinstance(msg, TrezorAppResponse):
        message_type_cls = message_type(msg.message_id)
        return protobuf.load_message(io.BytesIO(msg.data), message_type_cls)
    else:
        return msg
