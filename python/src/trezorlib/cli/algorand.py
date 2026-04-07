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

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

import click

from .. import algorand, tools
from . import with_session

if TYPE_CHECKING:
    from ..client import Session

PATH_HELP = "BIP-32 path to key, e.g. m/44h/283h/0h/0h/0h"
DEFAULT_PATH = "m/44h/283h/0h/0h/0h"


@click.group(name="algorand")
def cli() -> None:
    """Algorand commands."""


@cli.command()
@click.option("-n", "--address", default=DEFAULT_PATH, help=PATH_HELP)
@click.option("-d", "--show-display", is_flag=True)
@with_session
def get_public_key(
    session: "Session",
    address: str,
    show_display: bool,
) -> bytes:
    """Get Algorand public key."""
    address_n = tools.parse_path(address)
    return algorand.get_public_key(session, address_n, show_display)


@cli.command()
@click.option("-n", "--address", default=DEFAULT_PATH, help=PATH_HELP)
@click.option("-d", "--show-display", is_flag=True)
@click.option("-C", "--chunkify", is_flag=True)
@with_session
def get_address(
    session: "Session",
    address: str,
    show_display: bool,
    chunkify: bool,
) -> str:
    """Get Algorand address."""
    address_n = tools.parse_path(address)
    return algorand.get_address(session, address_n, show_display, chunkify)


@cli.command()
@click.argument("serialized_txs", type=str, nargs=-1)
@click.option("-n", "--address", default=DEFAULT_PATH, help=PATH_HELP)
@click.option(
    "-f",
    "--file",
    "tx_file",
    type=click.File("r"),
    help="Read transactions from file (one hex-encoded tx per line). "
    "Use '-' for stdin. Cannot be combined with positional arguments.",
)
@with_session
def sign_tx(
    session: "Session",
    address: str,
    serialized_txs: tuple[str, ...],
    tx_file: "click.utils.LazyFile | None",
) -> str:
    """Sign an Algorand transaction or atomic transaction group.

    Each transaction is a hex string of canonical MsgPack bytes. Pass one
    transaction to sign a standalone tx, or 2-16 transactions to sign an
    atomic group. Transactions may be supplied as positional arguments or
    via --file (one hex-encoded tx per line; blank lines and lines starting
    with '#' are ignored).

    For a single transaction the signature is printed as a hex string. For a
    group, one signature per line is printed in input order; transactions
    whose sender is not the signing account produce an empty line.
    """
    if tx_file is not None and serialized_txs:
        raise click.UsageError(
            "Pass transactions either as positional arguments or via --file, not both."
        )

    if tx_file is not None:
        hex_txs = [
            line.strip()
            for line in tx_file
            if line.strip() and not line.lstrip().startswith("#")
        ]
    else:
        hex_txs = list(serialized_txs)

    if not hex_txs:
        raise click.UsageError("At least one transaction is required.")
    if len(hex_txs) > 16:
        raise click.UsageError("An Algorand group can contain at most 16 transactions.")

    address_n = tools.parse_path(address)
    raw_txs = [bytes.fromhex(tx) for tx in hex_txs]

    signatures = algorand.sign_tx_group(session, address_n, raw_txs)

    if len(signatures) == 1:
        return signatures[0].hex()
    return "\n".join(sig.hex() for sig in signatures)


@cli.command()
@click.argument("data", required=False, default=None)
@click.option("-n", "--address", default=DEFAULT_PATH, help=PATH_HELP)
@click.option("-D", "--domain", required=True, help="Domain requesting the signature (printable ASCII).")
@click.option(
    "--auth-data",
    default=None,
    help="Hex-encoded authenticatorData. If omitted, defaults to SHA-256(domain).",
)
@click.option("--request-id", default=None, help="Optional request ID string.")
@click.option(
    "-f",
    "--file",
    "data_file",
    type=click.File("rb"),
    default=None,
    help="Read data from file (raw bytes) instead of DATA argument. Use '-' for stdin.",
)
@with_session
def sign_data(
    session: "Session",
    address: str,
    data: str | None,
    domain: str,
    auth_data: str | None,
    request_id: str | None,
    data_file: "click.utils.LazyFile | None",
) -> str:
    """Sign arbitrary data using ARC-60 (Algorand data signing).

    DATA is a UTF-8 string (typically JSON) to be signed. Use --file to read
    raw bytes from a file instead.

    The authenticatorData defaults to SHA-256(domain) when --auth-data is not
    provided. Pass --auth-data as hex to supply full FIDO2-style authenticator
    data (flags, signCount, etc.).

    The 64-byte Ed25519 signature is printed as a hex string.
    """
    if data_file is not None and data is not None:
        raise click.UsageError(
            "Pass data either as a positional argument or via --file, not both."
        )

    if data_file is not None:
        data_bytes = data_file.read()
    elif data is not None:
        data_bytes = data.encode("utf-8")
    else:
        raise click.UsageError("Either DATA argument or --file is required.")

    if auth_data is not None:
        auth_data_bytes = bytes.fromhex(auth_data)
    else:
        auth_data_bytes = hashlib.sha256(domain.encode("utf-8")).digest()

    address_n = tools.parse_path(address)
    signature = algorand.sign_data(
        session,
        address_n=address_n,
        data=data_bytes,
        domain=domain,
        auth_data=auth_data_bytes,
        request_id=request_id,
    )
    return signature.hex()
