"""Inline protobuf type declarations for the Algorand extapp wire payloads.

The Algorand app exchanges its inner request/response bodies inside the
opaque `data` field of `TrezorAppMessage`/`TrezorAppResponse`. Those bodies use
the schema in `../protob/messages-algorand.proto`. The schema is not
registered with the firmware's `MessageType` enum because extapps don't
need a firmware-known wire ID, so `trezorlib.messages` doesn't carry
typed builders for them. We declare them here against the in-repo
encoder so the test scripts stay self-contained and don't pull anything
firmware-side.

Keep field tags and types in sync with `messages-algorand.proto`.
"""

from typing import Optional, Sequence

from trezorlib import protobuf


class AlgorandGetPublicKey(protobuf.MessageType):
    FIELDS = {
        1: protobuf.Field("address_n", "uint32", repeated=True, required=False, default=None),
        2: protobuf.Field("show_display", "bool", repeated=False, required=False, default=None),
    }

    address_n: Sequence[int]
    show_display: Optional[bool]


class AlgorandPublicKey(protobuf.MessageType):
    FIELDS = {
        1: protobuf.Field("public_key", "bytes", repeated=False, required=True),
        2: protobuf.Field("address", "string", repeated=False, required=True),
    }

    public_key: bytes
    address: str


class AlgorandSignTransactions(protobuf.MessageType):
    FIELDS = {
        1: protobuf.Field("address_n", "uint32", repeated=True, required=False, default=None),
        2: protobuf.Field("transactions", "bytes", repeated=False, required=True),
        3: protobuf.Field("total_size", "uint32", repeated=False, required=False, default=None),
        4: protobuf.Field("sign_indices", "uint32", repeated=True, required=False, default=None),
    }

    address_n: Sequence[int]
    transactions: bytes
    total_size: Optional[int]
    sign_indices: Sequence[int]


class AlgorandContinueSignTransactions(protobuf.MessageType):
    FIELDS = {
        1: protobuf.Field("data", "bytes", repeated=False, required=True),
    }

    data: bytes


class AlgorandTransactionSignature(protobuf.MessageType):
    FIELDS = {
        1: protobuf.Field("index", "uint32", repeated=False, required=True),
        2: protobuf.Field("signature", "bytes", repeated=False, required=True),
        3: protobuf.Field("auth_address", "bytes", repeated=False, required=False, default=None),
    }

    index: int
    signature: bytes
    auth_address: Optional[bytes]


class AlgorandTransactionSignatures(protobuf.MessageType):
    FIELDS = {
        1: protobuf.Field("signatures", "AlgorandTransactionSignature", repeated=True, required=False, default=None),
    }

    signatures: Sequence["AlgorandTransactionSignature"]
