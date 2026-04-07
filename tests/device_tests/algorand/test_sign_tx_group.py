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

from trezorlib.algorand import sign_tx_group
from trezorlib.debuglink import DebugSession as Session
from trezorlib.exceptions import TrezorFailure
from trezorlib.tools import parse_path

from ...common import parametrize_using_common_fixtures
from ...input_flows import InputFlowConfirmAllWarnings

pytestmark = [pytest.mark.altcoin, pytest.mark.algorand, pytest.mark.models("core")]


@parametrize_using_common_fixtures(
    "algorand/sign_tx_group.json",
)
def test_algorand_sign_tx_group(session: Session, parameters, result):
    """Sign atomic transaction groups and verify signatures.

    Tests both full-signing (all txs from same sender) and partial-signing
    (mixed senders, where non-owned txs get empty signatures).
    """
    with session.test_ctx as client:
        IF = InputFlowConfirmAllWarnings(session)
        client.set_input_flow(IF.get())

        serialized_txs = [
            bytes.fromhex(tx_hex) for tx_hex in parameters["serialized_txs"]
        ]

        actual_signatures = sign_tx_group(
            session,
            address_n=parse_path(parameters["path"]),
            serialized_txs=serialized_txs,
        )

        expected = result["expected_signatures"]
        assert len(actual_signatures) == len(expected)
        for actual, expected_hex in zip(actual_signatures, expected):
            if expected_hex:
                assert actual == bytes.fromhex(expected_hex)
            else:
                assert actual == b""


def test_algorand_group_wrong_group_id(session: Session):
    """Submit a group where one transaction has a wrong grp field.

    Expected: DataError.
    """
    # TODO: Construct two payment transactions with mismatched grp fields
    # and verify the device rejects them.
    pytest.skip("TODO: generate test vectors")


def test_algorand_group_missing_group_id(session: Session):
    """Submit a group where one transaction omits the grp field.

    Expected: DataError.
    """
    # TODO: Construct two payment transactions where one lacks grp
    # and verify the device rejects them.
    pytest.skip("TODO: generate test vectors")


def test_algorand_group_oversized(session: Session):
    """Attempt group_size=17.

    Expected: DataError.
    """
    # TODO: Attempt to send a group of 17 transactions
    # and verify the device rejects with "Invalid group size".
    pytest.skip("TODO: generate test vectors")
