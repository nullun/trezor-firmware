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

from trezorlib.debuglink import DebugSession as Session
from trezorlib.exceptions import TrezorFailure
from trezorlib.tools import parse_path

from . import algorand_ext, vectors
from .common import parametrize_using_common_fixtures


@parametrize_using_common_fixtures("get_public_key.json")
def test_algorand_get_public_key(
    session: Session, instance_id: int, parameters, result
):
    path = parse_path(parameters["path"])
    res = algorand_ext.get_public_key(session, instance_id, path)
    assert res.public_key.hex() == result["public_key"]
    assert res.address == result["address"]
    # Cross-check tiny-algo's address encoding against the reference (algosdk).
    assert res.address == vectors.address_of(res.public_key)


# The app accepts only fully-hardened m/44'/283'/account'/change'/index' paths
# (see `check_path` in src/main.rs).
@pytest.mark.parametrize(
    "path",
    [
        "m/44'/283'/0'/0/0",  # change/index not hardened
        "m/44'/0'/0'/0'/0'",  # wrong SLIP-44 coin type
        "m/44'/283'/0'/0'",  # too short
        "m/44'/283'/0'/0'/0'/0'",  # too long
    ],
)
def test_algorand_get_public_key_invalid_path(
    session: Session, instance_id: int, path
):
    with pytest.raises(TrezorFailure):
        algorand_ext.get_public_key(session, instance_id, parse_path(path))
