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

import pytest

from trezorlib.algorand import sign_tx
from trezorlib.debuglink import DebugSession as Session
from trezorlib.exceptions import TrezorFailure
from trezorlib.tools import parse_path

from ...common import parametrize_using_common_fixtures
from ...input_flows import InputFlowConfirmAllWarnings

pytestmark = [pytest.mark.altcoin, pytest.mark.algorand, pytest.mark.models("core")]


@parametrize_using_common_fixtures(
    "algorand/sign_tx.json",
)
def test_algorand_sign_tx(session: Session, parameters, result):
    """Sign each transaction type and verify the signature.

    Each test vector provides canonical MsgPack bytes as hex and an expected
    Ed25519 signature. The signature is over b"TX" + serialized_tx.
    """
    with session.test_ctx as client:
        IF = InputFlowConfirmAllWarnings(session)
        client.set_input_flow(IF.get())

        if "expected_signature" in result:
            actual_result = sign_tx(
                session,
                address_n=parse_path(parameters["path"]),
                serialized_tx=bytes.fromhex(parameters["serialized_tx"]),
            )
            assert actual_result == bytes.fromhex(result["expected_signature"])

        elif "error_message" in result:
            with pytest.raises(TrezorFailure, match=result["error_message"]):
                sign_tx(
                    session,
                    address_n=parse_path(parameters["path"]),
                    serialized_tx=bytes.fromhex(parameters["serialized_tx"]),
                )
        else:
            pytest.fail("Invalid expected result")
