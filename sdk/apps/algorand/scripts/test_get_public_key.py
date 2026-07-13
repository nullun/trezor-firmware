#!/usr/bin/env python3
"""
Test script for Algorand GetPublicKey via external app interface.

This script:
1. Loads the algorand app onto the device.
2. Serializes an AlgorandGetPublicKey protobuf message.
3. Wraps it in TrezorAppMessage and sends it.
4. Deserializes the AlgorandPublicKey response.
"""

import argparse
import io
import sys
from pathlib import Path

from trezorlib import messages, protobuf
from trezorlib.client import get_default_client, get_default_session

sys.path.insert(0, str(Path(__file__).parent))
from algorand_messages import AlgorandGetPublicKey, AlgorandPublicKey
from app_loader import add_app_args, load_app


def main():
    parser = argparse.ArgumentParser(
        description="Test Algorand GetPublicKey via the external app interface"
    )
    add_app_args(parser)
    args = parser.parse_args()

    client = get_default_client("algorand_test")

    # m/44'/283'/0'/0/0 — Algorand SLIP-44 coin type 283. Path content doesn't
    # matter for this skeleton (zero validation on the device side).
    request = AlgorandGetPublicKey(
        address_n=[
            44 | 0x80000000,
            283 | 0x80000000,
            0 | 0x80000000,
            0 | 0x80000000,
            0 | 0x80000000,
        ],
        show_display=False,
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
        message_id=0,  # AlgorandMessages::GetPublicKey
        data=request_data,
    )
    resp = session.call(envelope, expect=messages.TrezorAppResponse)

    response_buf = io.BytesIO(resp.data)
    response = protobuf.load_message(response_buf, AlgorandPublicKey)
    print(protobuf.format_message(response))
    print(f"\naddress:    {response.address}")
    print(f"public_key: {response.public_key.hex()}")


if __name__ == "__main__":
    main()
