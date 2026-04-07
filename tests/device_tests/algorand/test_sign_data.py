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

from trezorlib.algorand import sign_data
from trezorlib.debuglink import DebugSession as Session
from trezorlib.exceptions import TrezorFailure
from trezorlib.tools import parse_path

from ...common import parametrize_using_common_fixtures
from ...input_flows import InputFlowConfirmAllWarnings

pytestmark = [pytest.mark.altcoin, pytest.mark.algorand, pytest.mark.models("core")]


@parametrize_using_common_fixtures(
    "algorand/sign_data.json",
)
def test_algorand_sign_data(session: Session, parameters, result):
    """Sign arbitrary data (ARC-60) and verify the signature.

    The signed message is SHA-256(data) + SHA-256(auth_data).
    """
    with session.test_ctx as client:
        IF = InputFlowConfirmAllWarnings(session)
        client.set_input_flow(IF.get())

        actual_result = sign_data(
            session,
            address_n=parse_path(parameters["path"]),
            data=bytes.fromhex(parameters["data"]),
            domain=parameters["domain"],
            auth_data=bytes.fromhex(parameters["auth_data"]),
            request_id=parameters.get("request_id"),
        )

        assert actual_result == bytes.fromhex(result["expected_signature"])


def test_algorand_sign_data_invalid_domain(session: Session):
    """Sign data with non-ASCII domain should fail."""
    with pytest.raises(TrezorFailure, match="Invalid domain"):
        sign_data(
            session,
            address_n=parse_path("m/44'/283'/0'/0'/0'"),
            data=b'{"message":"hello"}',
            domain="bad\x01domain",
            auth_data=b"\x00" * 32,
        )


def test_algorand_sign_data_bad_auth(session: Session):
    """Sign data with auth_data not matching SHA-256(domain) should fail."""
    with pytest.raises(TrezorFailure, match="Domain authentication failed"):
        sign_data(
            session,
            address_n=parse_path("m/44'/283'/0'/0'/0'"),
            data=b'{"message":"hello"}',
            domain="example.com",
            auth_data=b"\x00" * 32,
        )
