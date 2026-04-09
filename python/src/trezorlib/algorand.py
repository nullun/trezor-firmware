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

from typing import TYPE_CHECKING, List, NamedTuple, Optional

from . import messages
from .tools import workflow

if TYPE_CHECKING:
    from .client import Session

SIG_ED25519 = 0
SIG_FALCON_DET1024 = 1


class FalconAccountInfo(NamedTuple):
    """All metadata needed to use a FALCON-controlled Algorand account.

    `address` is the 58-character LogicSig contract account that the user
    funds and transacts from. `public_key` is the raw 1793-byte FALCON
    public key, which the host needs to reconstruct the LogicSig program
    bytecode for transaction submission. `counter` and `teal_version`
    pin down which template was used.
    """

    address: str
    public_key: bytes
    counter: int
    teal_version: int


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
    signature_type: int = SIG_ED25519,
) -> bytes:
    """Sign a single Algorand transaction.

    Pass `signature_type=SIG_FALCON_DET1024` to use the post-quantum
    FALCON path; the device will return a variable-length compressed
    Falcon signature instead of the 64-byte Ed25519 signature.
    """
    return sign_tx_group(
        session, address_n, [serialized_tx], signature_type=signature_type
    )[0]


@workflow(capability=messages.Capability.Algorand)
def sign_tx_group(
    session: "Session",
    address_n: List[int],
    serialized_txs: List[bytes],
    signature_type: int = SIG_ED25519,
) -> List[bytes]:
    """Sign an Algorand transaction group (1-16 transactions).

    Returns a list of signatures, one per transaction. Signatures are
    64 bytes for Ed25519 or up to ~1.4 KB for FALCON-DET1024 when the
    signer is the sender, or empty bytes for transactions belonging to
    other accounts.
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
            signature_type=signature_type,
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
def get_falcon_address(
    session: "Session",
    address_n: List[int],
    show_display: bool = False,
    chunkify: bool = False,
) -> FalconAccountInfo:
    """Get the FALCON-controlled Algorand LogicSig address.

    The device derives the FALCON keypair from the HD seed, embeds the
    public key into the TEAL LogicSig template and iterates a counter
    until the resulting address is off the Ed25519 curve. Returns the
    full set of metadata the host needs to reconstruct the LogicSig
    program for transaction submission.
    """
    resp = session.call(
        messages.AlgorandGetFalconAddress(
            address_n=address_n,
            show_display=show_display,
            chunkify=chunkify,
        ),
        expect=messages.AlgorandFalconAddress,
    )
    return FalconAccountInfo(
        address=resp.address,
        public_key=resp.public_key,
        counter=resp.counter if resp.counter is not None else 0,
        teal_version=resp.teal_version if resp.teal_version is not None else 12,
    )


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
