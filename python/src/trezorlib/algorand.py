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

from typing import TYPE_CHECKING, List, Optional

from . import messages
from .tools import workflow

if TYPE_CHECKING:
    from .client import Session


@workflow(capability=messages.Capability.Algorand)
def get_public_key(
    session: "Session",
    address_n: List[int],
    show_display: bool = False,
) -> bytes:
    return session.call(
        messages.AlgorandGetPublicKey(
            address_n=address_n,
            show_display=show_display,
        ),
        expect=messages.AlgorandPublicKey,
    ).public_key


@workflow(capability=messages.Capability.Algorand)
def get_address(
    session: "Session",
    address_n: List[int],
    show_display: bool = False,
    chunkify: bool = False,
) -> str:
    return session.call(
        messages.AlgorandGetAddress(
            address_n=address_n,
            show_display=show_display,
            chunkify=chunkify,
        ),
        expect=messages.AlgorandAddress,
    ).address


@workflow(capability=messages.Capability.Algorand)
def sign_tx(
    session: "Session",
    address_n: List[int],
    serialized_tx: bytes,
) -> bytes:
    """Sign a single Algorand transaction."""
    return sign_tx_group(session, address_n, [serialized_tx])[0]


@workflow(capability=messages.Capability.Algorand)
def sign_tx_group(
    session: "Session",
    address_n: List[int],
    serialized_txs: List[bytes],
) -> List[bytes]:
    """Sign an Algorand transaction group (1-16 transactions).

    Returns a list of signatures, one per transaction.
    Signatures are 64 bytes for transactions where the signer is the sender,
    or empty bytes for transactions belonging to other accounts.
    """
    group_size = len(serialized_txs)
    if group_size < 1 or group_size > 16:
        raise ValueError("Group must contain 1-16 transactions")

    # Send the first transaction via AlgorandSignTx
    resp = session.call(
        messages.AlgorandSignTx(
            address_n=address_n,
            serialized_tx=serialized_txs[0],
            group_size=group_size,
            group_index=0,
        ),
    )

    # For groups, handle the TxRequest/TxAck loop
    for i in range(1, group_size):
        if not isinstance(resp, messages.AlgorandTxRequest):
            raise RuntimeError(f"Expected AlgorandTxRequest, got {type(resp)}")
        resp = session.call(
            messages.AlgorandTxAck(serialized_tx=serialized_txs[i]),
        )

    if not isinstance(resp, messages.AlgorandTxSignature):
        raise RuntimeError(f"Expected AlgorandTxSignature, got {type(resp)}")

    if group_size == 1:
        return [resp.signature]
    else:
        return list(resp.group_signatures)


@workflow(capability=messages.Capability.Algorand)
def sign_data(
    session: "Session",
    address_n: List[int],
    data: bytes,
    domain: str,
    auth_data: bytes,
    request_id: Optional[str] = None,
) -> bytes:
    return session.call(
        messages.AlgorandSignData(
            address_n=address_n,
            data=data,
            domain=domain,
            auth_data=auth_data,
            request_id=request_id,
        ),
        expect=messages.AlgorandDataSignature,
    ).signature
