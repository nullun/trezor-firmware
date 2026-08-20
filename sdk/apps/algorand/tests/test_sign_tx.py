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

"""One signing test per transaction type / distinct review screen.

The vectors in ``fixtures/sign_tx.json`` are built with the reference
implementation (algosdk) and carry golden ed25519 signatures over
``"TX" || txn`` computed offline from the test seed — so every case is a
conformance check that the device parses the canonical bytes and signs the
exact right message. Regenerate the file with ``uv run python -m
tests.gen_fixtures`` after changing the vectors. The rekey/close variants
exercise the full-screen danger gates.
"""

from trezorlib.debuglink import DebugSession as Session
from trezorlib.tools import parse_path

from . import signing
from .common import parametrize_using_common_fixtures


@parametrize_using_common_fixtures("sign_tx.json")
def test_algorand_sign_tx(session: Session, instance_id: int, parameters, result):
    path = parse_path(parameters["path"])
    payload = bytes.fromhex(parameters["transactions"])
    res = signing.sign(session, instance_id, path, payload)
    assert len(res.signatures) == len(result["signatures"])
    for record, expected in zip(res.signatures, result["signatures"]):
        assert record.index == expected["index"]
        assert record.signature.hex() == expected["signature"]
        auth = record.auth_address.hex() if record.auth_address else None
        assert auth == expected.get("auth_address")
