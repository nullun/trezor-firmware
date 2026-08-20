#!/usr/bin/env python3
"""algoctl — drive the Algorand modular app on a connected Trezor/emulator.

A small stand-in for `trezorctl algorand …`. The modular app's messages
travel inside the opaque `data` field of the `TrezorAppMessage` /
`TrezorAppResponse` envelope and aren't registered in trezorlib's global
`MessageType`, so `trezorctl` has no built-in commands for them. This script
loads the app (every run gets a fresh instance id) and issues one request.

The emulator must already be running and the app artifact built — see the
app README. App selection (`--app`, `--model`, `--hardware`, `--app-path`)
works on each subcommand; defaults match the published t3w1 emulator build.

Examples:
  uv run python scripts/algoctl.py get-public-key
  uv run python scripts/algoctl.py gpk --path "m/44'/283'/1'/0'/0'" --show
  uv run python scripts/algoctl.py sign --txn <hex>
  uv run python scripts/algoctl.py sign --txn <hex0> --txn <hex1> --sign-indices 0
  uv run python scripts/algoctl.py sign --txn-file group.bin --chunk 7000
"""

import argparse
import base64
import hashlib
import io
import sys
from pathlib import Path

from trezorlib import messages, protobuf
from trezorlib.client import get_default_client, get_default_session
from trezorlib.exceptions import TrezorFailure
from trezorlib.tools import parse_path

sys.path.insert(0, str(Path(__file__).parent))
from algorand_messages import (  # noqa: E402
    AlgorandTxAck,
    AlgorandTxRequest,
    AlgorandGetPublicKey,
    AlgorandPublicKey,
    AlgorandSignTransactions,
    AlgorandTransactionSignatures,
)
from app_loader import add_app_args, load_app  # noqa: E402

# Message ids — mirror `AlgorandMessages` in src/main.rs.
MSG_GET_PUBLIC_KEY = 0
MSG_SIGN_TRANSACTIONS = 2
MSG_TRANSACTION_SIGNATURES = 3
MSG_TX_REQUEST = 4
MSG_TX_ACK = 5

DEFAULT_PATH = "m/44'/283'/0'/0'/0'"


def _algorand_address(pubkey: bytes) -> str:
    """32-byte ed25519 public key -> canonical Algorand address.

    base32(pubkey || sha512_256(pubkey)[-4:]) with the trailing base32
    padding stripped (Algorand addresses are 58 chars). Mirrors the device's
    Address::encode so the auth address reads the same as `goal`/wallets.
    """
    checksum = hashlib.new("sha512_256", pubkey).digest()[-4:]
    return base64.b32encode(pubkey + checksum).decode()[:58]


def _send(session, instance_id, message_id, inner, verbose=False):
    """Wrap `inner` in a TrezorAppMessage, send it, return the raw response."""
    buf = io.BytesIO()
    protobuf.dump_message(buf, inner)
    data = buf.getvalue()
    if verbose:
        print(f"-> id={message_id} ({len(data)} bytes): {data.hex()}", file=sys.stderr)
    envelope = messages.TrezorAppMessage(
        instance_id=instance_id, message_id=message_id, data=data
    )
    resp = session.call(envelope, expect=messages.TrezorAppResponse)
    if verbose:
        print(f"<- id={resp.message_id} ({len(resp.data)} bytes): {resp.data.hex()}",
              file=sys.stderr)
    return resp


def cmd_get_public_key(session, instance_id, args):
    req = AlgorandGetPublicKey(address_n=parse_path(args.path), show_display=args.show)
    resp = _send(session, instance_id, MSG_GET_PUBLIC_KEY, req, args.verbose)
    res = protobuf.load_message(io.BytesIO(resp.data), AlgorandPublicKey)
    print(f"address:    {res.address}")
    print(f"public_key: {res.public_key.hex()}")


def _load_payload(args) -> bytes:
    """Concatenate the transaction bytes from --txn / --txn-file, in order."""
    chunks = []
    for hexstr in args.txn or []:
        chunks.append(bytes.fromhex("".join(hexstr.split())))
    for path in args.txn_file or []:
        raw = Path(path).read_bytes()
        # Accept either a hex dump or raw msgpack bytes in the file.
        try:
            chunks.append(bytes.fromhex(raw.decode().strip()))
        except (UnicodeDecodeError, ValueError):
            chunks.append(raw)
    if not chunks:
        sys.exit("sign: pass at least one --txn HEX or --txn-file FILE")
    return b"".join(chunks)


def cmd_sign(session, instance_id, args):
    payload = _load_payload(args)
    sign_indices = (
        [int(i) for i in args.sign_indices.split(",")] if args.sign_indices else None
    )

    if not args.chunk or args.chunk >= len(payload):
        req = AlgorandSignTransactions(
            address_n=parse_path(args.path),
            transactions=payload,
            sign_indices=sign_indices,
        )
        resp = _send(session, instance_id, MSG_SIGN_TRANSACTIONS, req, args.verbose)
    else:
        # Chunked upload: the first message declares total_size; the device
        # then pulls the rest with TxRequest, each answered by a TxAck.
        chunk = args.chunk
        first, rest = payload[:chunk], payload[chunk:]
        req = AlgorandSignTransactions(
            address_n=parse_path(args.path),
            transactions=first,
            total_size=len(payload),
            sign_indices=sign_indices,
        )
        resp = _send(session, instance_id, MSG_SIGN_TRANSACTIONS, req, args.verbose)
        while resp.message_id == MSG_TX_REQUEST:
            tx_request = protobuf.load_message(io.BytesIO(resp.data), AlgorandTxRequest)
            size = min(tx_request.data_length, chunk)
            nxt, rest = rest[:size], rest[size:]
            ack = AlgorandTxAck(data=nxt)
            resp = _send(session, instance_id, MSG_TX_ACK, ack, args.verbose)

    res = protobuf.load_message(io.BytesIO(resp.data), AlgorandTransactionSignatures)
    print(f"{len(res.signatures)} signature(s):")
    for r in res.signatures:
        print(f"  [{r.index}] sig (base64): {base64.b64encode(r.signature).decode()}")
        print(f"      sig (hex):    {r.signature.hex()}")
        if r.auth_address:
            # Rekeyed account: the host puts this in the SignedTxn `sgnr` field.
            print(f"      auth address: {_algorand_address(r.auth_address)}")
            print(f"      auth (base64): {base64.b64encode(r.auth_address).decode()}")


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    add_app_args(common)
    common.add_argument(
        "-v", "--verbose", action="store_true", help="print request/response wire bytes"
    )

    parser = argparse.ArgumentParser(
        description="Drive the Algorand modular app on a connected Trezor/emulator."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    gpk = sub.add_parser(
        "get-public-key", aliases=["gpk"], parents=[common],
        help="derive the ed25519 key and Algorand address for a path",
    )
    gpk.add_argument("--path", default=DEFAULT_PATH, help=f"BIP-32 path (default {DEFAULT_PATH})")
    gpk.add_argument("--show", action="store_true", help="show the address on the device")
    gpk.set_defaults(func=cmd_get_public_key)

    sign = sub.add_parser(
        "sign", parents=[common],
        help="sign one transaction or an atomic group",
    )
    sign.add_argument("--path", default=DEFAULT_PATH, help=f"BIP-32 path (default {DEFAULT_PATH})")
    sign.add_argument(
        "--txn", action="append", metavar="HEX",
        help="canonical-msgpack txn as hex; repeat to build a group, in order",
    )
    sign.add_argument(
        "--txn-file", action="append", metavar="FILE",
        help="file with txn bytes (hex dump or raw); repeat to build a group",
    )
    sign.add_argument(
        "--sign-indices", metavar="LIST",
        help="comma-separated group indices to sign (default: all)",
    )
    sign.add_argument(
        "--chunk", type=int, metavar="N",
        help="upload in N-byte chunks to exercise the chunked path",
    )
    sign.set_defaults(func=cmd_sign)
    return parser


def main():
    args = build_parser().parse_args()
    client = get_default_client("algoctl")
    session = get_default_session(client)
    instance_id = load_app(session, args)
    try:
        args.func(session, instance_id, args)
    except TrezorFailure as e:
        sys.exit(f"device rejected the request: {e}")


if __name__ == "__main__":
    main()
