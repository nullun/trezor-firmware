#!/usr/bin/env python3
"""
Test script for Algorand SignTransactions via external app interface.

Sends a single unsigned payment transaction; the device parses it,
validates structure, confirms the details on screen (if connected
to a real screen — the emulator just records the button request),
prepends the "TX" domain-separator, signs, and returns one signature.

For an atomic group, set `transactions` to a concatenation of 2..=16
canonical msgpack transactions, each with the matching `grp` field
set. The device will recompute the group ID and reject any member
whose `grp` doesn't match before signing. Building such a group
needs canonical-msgpack tooling (e.g. py-algorand-sdk) which isn't
a hard dep of this repo, so the example here is single-txn.
"""

import argparse
import io
import sys
from pathlib import Path

from trezorlib import messages, protobuf
from trezorlib.client import get_default_client, get_default_session

sys.path.insert(0, str(Path(__file__).parent))
from algorand_messages import AlgorandSignTransactions, AlgorandTransactionSignatures
from app_loader import add_app_args, load_app


def main():
    parser = argparse.ArgumentParser(
        description="Test Algorand SignTransactions via the external app interface"
    )
    add_app_args(parser)
    args = parser.parse_args()

    client = get_default_client("algorand_test")

    # Canonical msgpack encoding of an unsigned Algorand pay transaction.
    txn_hex = (
        "89a3616d7401a3666565cd03e8a266760ba367656eaa64656d6f6e65742d7631"
        "a26768c4201b94a30589da148aaffd78187ffb1c98a2d9416e0de4553c93256f"
        "9d22e90e47a26c76cd03f3a3726376c42002d0227f1a4b8a636aa6a0bdcaa1a1"
        "ff5e8ef9de66af6d6f6a3691b023092d07a3736e64c42002e3fa1b390b58126f"
        "2cf66bfa8e923a6bf3054e739b14c60bafeade016cc17ea474797065a3706179"
    )
    txn_hex = (
        "8ba3616d74ce000f4240a3666565cd03e8a2667610a367656eaa64656d6f6e65"
        "742d7631a26768c4206cd3423bf1bed341e83d11756466b9c939b1bf73345a08"
        "f3ca407fbc609c5b4ba3677270c42030e71d558697dd7814a42ca868ba8bb7dd"
        "33853e095ec6f6b394be0e18271570a26c76cd03f8a46e6f7465c4083b8c61b4"
        "54909c65a3726376c42002d0227f1a4b8a636aa6a0bdcaa1a1ff5e8ef9de66af"
        "6d6f6a3691b023092d07a3736e64c42002e3fa1b390b58126f2cf66bfa8e923a"
        "6bf3054e739b14c60bafeade016cc17ea474797065a37061798ba3616d74ce00"
        "16e360a3666565cd03e8a2667615a367656eaa64656d6f6e65742d7631a26768"
        "c4206cd3423bf1bed341e83d11756466b9c939b1bf73345a08f3ca407fbc609c"
        "5b4ba3677270c42030e71d558697dd7814a42ca868ba8bb7dd33853e095ec6f6"
        "b394be0e18271570a26c76cd03fda46e6f7465c4086cb14f7f4fe4069ca37263"
        "76c4200b821c07701f60686be40e0e7a4fe9ff896ba8ae9174d6e3184788e043"
        "a3db35a3736e64c42002e3fa1b390b58126f2cf66bfa8e923a6bf3054e739b14"
        "c60bafeade016cc17ea474797065a3706179"
    )

    request = AlgorandSignTransactions(
        address_n=[
            44 | 0x80000000,
            283 | 0x80000000,
            0 | 0x80000000,
            0 | 0x80000000,
            0 | 0x80000000,
        ],
        transactions=bytes.fromhex(txn_hex),
    )

    buf = io.BytesIO()
    protobuf.dump_message(buf, request)
    request_data = buf.getvalue()

    print(f"Request: {request}")
    print(f"Serialized ({len(request_data)} bytes): {request_data.hex()}")

    session = get_default_session(client)
    instance_id = load_app(session, args)

    print(f"App loaded with instance ID: {instance_id}\n")

    envelope = messages.TrezorAppMessage(
        instance_id=instance_id,
        message_id=2,  # AlgorandMessages::SignTransactions
        data=request_data,
    )
    resp = session.call(envelope, expect=messages.TrezorAppResponse)

    response_buf = io.BytesIO(resp.data)
    response = protobuf.load_message(
        response_buf, AlgorandTransactionSignatures
    )
    print(protobuf.format_message(response))
    print(f"\n{len(response.signatures)} signature(s) returned:")
    for record in response.signatures:
        auth = f" auth={record.auth_address.hex()}" if record.auth_address else ""
        print(f"  [{record.index}] {record.signature.hex()}{auth}")


if __name__ == "__main__":
    main()
