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

"""Regenerate ``fixtures/sign_tx.json`` from the algosdk-built vectors.

ed25519 signing is deterministic, so the expected device signatures can be
computed offline: derive the test seed's SLIP-10 key at the fixture path and
sign the same ``"TX" || txn`` message the device signs. The derivation is
cross-checked against the recorded public key in
``fixtures/get_public_key.json`` before anything is written.

Run from the app directory::

    uv run python -m tests.gen_fixtures
"""

from __future__ import annotations

import hashlib
import hmac
import json
import struct
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from . import vectors

HERE = Path(__file__).resolve().parent

MNEMONIC = " ".join(["all"] * 12)
PATH = "m/44'/283'/0'/0'/0'"
HARDENED = 0x8000_0000
PATH_N = [44 | HARDENED, 283 | HARDENED, HARDENED, HARDENED, HARDENED]


def slip10_ed25519_key(seed: bytes, path: list[int]) -> bytes:
    """SLIP-10 ed25519 private key for a fully hardened path."""
    digest = hmac.new(b"ed25519 seed", seed, hashlib.sha512).digest()
    key, chain_code = digest[:32], digest[32:]
    for index in path:
        assert index & HARDENED, "ed25519 has hardened derivation only"
        data = b"\x00" + key + struct.pack(">I", index)
        digest = hmac.new(chain_code, data, hashlib.sha512).digest()
        key, chain_code = digest[:32], digest[32:]
    return key


def device_key() -> Ed25519PrivateKey:
    seed = hashlib.pbkdf2_hmac("sha512", MNEMONIC.encode(), b"mnemonic", 2048)
    key = Ed25519PrivateKey.from_private_bytes(slip10_ed25519_key(seed, PATH_N))
    # Cross-check the derivation against the recorded device public key.
    recorded = json.loads((HERE / "fixtures" / "get_public_key.json").read_text())
    expected = next(
        t["result"]["public_key"]
        for t in recorded["tests"]
        if t["parameters"]["path"] == PATH
    )
    derived = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    assert derived.hex() == expected, "derived key does not match the device"
    return key


#: name -> single-transaction builder; one entry per transaction type or
#: distinct review screen (the rekey/close variants exercise the danger
#: gates). ``vectors.SENDER`` isn't the device account, so every signature
#: is a rekey-authority sign and carries ``auth_address``.
VECTORS = {
    "payment": lambda: vectors.payment(1_000_000),
    "payment_close": lambda: vectors.payment(1_000_000, close_to=vectors.CLOSE_TO),
    "keyreg_online": vectors.keyreg_online,
    "keyreg_offline": vectors.keyreg_offline,
    "keyreg_nonpart": vectors.keyreg_nonpart,
    "asset_transfer": lambda: vectors.asset_transfer(5_000),
    "asset_transfer_close": lambda: vectors.asset_transfer(
        5_000, close_to=vectors.CLOSE_TO
    ),
    "asset_freeze": lambda: vectors.asset_freeze(frozen=True),
    "asset_unfreeze": lambda: vectors.asset_freeze(frozen=False),
    "asset_create": vectors.asset_create,
    "asset_reconfigure": vectors.asset_reconfigure,
    "asset_destroy": vectors.asset_destroy,
    "app_create": vectors.app_create,
    "app_call_blind": lambda: vectors.app_call(args=[b"method", b"\x01"]),
    "rekey_payment": lambda: vectors.rekey(vectors.payment(1_000_000)),
    "rekey_keyreg": lambda: vectors.rekey(vectors.keyreg_offline()),
    "rekey_asset_transfer": lambda: vectors.rekey(vectors.asset_transfer(5_000)),
    "rekey_app_call": lambda: vectors.rekey(vectors.app_call()),
}


def main() -> None:
    key = device_key()
    pubkey = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    tests = []
    for name, make in VECTORS.items():
        payload = vectors.encode(make())
        signature = key.sign(vectors.TX_DOMAIN + payload)
        tests.append(
            {
                "name": name,
                "parameters": {
                    "path": PATH,
                    "transactions": payload.hex(),
                },
                "result": {
                    "signatures": [
                        {
                            "index": 0,
                            "signature": signature.hex(),
                            "auth_address": pubkey.hex(),
                        }
                    ]
                },
            }
        )

    out = {
        "setup": {"mnemonic": MNEMONIC, "passphrase": ""},
        "tests": tests,
    }
    path = HERE / "fixtures" / "sign_tx.json"
    path.write_text(json.dumps(out, indent=4) + "\n")
    print(f"wrote {len(tests)} vectors to {path}")


if __name__ == "__main__":
    main()
