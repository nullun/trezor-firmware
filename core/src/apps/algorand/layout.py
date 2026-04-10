from typing import TYPE_CHECKING

from trezor import TR
from trezor.ui.layouts import confirm_properties, show_danger

from .format import (
    format_address,
    format_algo_amount,
    format_asset_amount,
    format_network,
    is_printable,
)
from .types import OnCompletion, TxType, TX_TYPE_ABBREVS

if TYPE_CHECKING:
    from trezor.ui.layouts import PropertyType

    from .transaction import Transaction


async def confirm_group_overview(transactions: list[Transaction]) -> None:
    """Show a compact summary of all transactions in an atomic group."""
    items: list[PropertyType] = []

    for i, tx in enumerate(transactions):
        abbrev = TX_TYPE_ABBREVS.get(tx.tx_type, "???")
        summary = _group_summary(tx)
        items.append((f"#{i + 1}", f"{abbrev}  {summary}", None))

    await confirm_properties(
        "confirm_group",
        TR.algorand__group_overview,
        items,
    )


def _group_summary(tx: Transaction) -> str:
    """Generate a one-line summary for the group overview."""
    from .asa import get_asset_info

    td = tx.type_data

    if tx.tx_type == TxType.PAYMENT:
        return format_algo_amount(td["amount"])

    elif tx.tx_type == TxType.APPLICATION:
        app_id = td.get("app_id", 0)
        return f"#{app_id}" if app_id else "Create"

    elif tx.tx_type == TxType.ASSET_XFER:
        asset_info = get_asset_info(td["asset_id"])
        return format_asset_amount(
            td["amount"], asset_info.decimals, asset_info.unit
        )

    elif tx.tx_type == TxType.ASSET_FREEZE:
        status = "Freeze" if td["frozen"] else "Unfreeze"
        return f"{status} #{td['asset_id']}"

    elif tx.tx_type == TxType.ASSET_CONFIG:
        asset_id = td.get("asset_id", 0)
        if asset_id == 0:
            return "Create"
        elif td.get("params"):
            return "Update"
        else:
            return "Destroy"

    elif tx.tx_type == TxType.KEYREG:
        return "Offline" if td.get("nonpart") else "Online"

    return ""


def _get_app_subtype(td: dict) -> str:
    """Determine application call subtype for the header."""
    app_id = td.get("app_id", 0)
    oc = td.get("on_completion", OnCompletion.NOOP)

    if app_id == 0:
        if oc == OnCompletion.DELETE_APP:
            return "Ephemeral"
        return "Creation"

    if oc == OnCompletion.NOOP:
        return "Call"
    elif oc == OnCompletion.OPT_IN:
        return "OptIn"
    elif oc == OnCompletion.CLOSE_OUT:
        return "OptOut"
    elif oc == OnCompletion.CLEAR_STATE:
        return "Remove"
    elif oc == OnCompletion.UPDATE_APP:
        return "Update"
    elif oc == OnCompletion.DELETE_APP:
        return "Delete"
    return "Call"


def _get_acfg_subtype(td: dict) -> str:
    """Determine asset config subtype for the header."""
    asset_id = td.get("asset_id", 0)
    if asset_id == 0:
        return "Creation"
    if td.get("params"):
        return "Update"
    return "Destroy"


async def confirm_transaction(
    tx: Transaction,
    group_index: int | None = None,
    group_size: int | None = None,
    signature_type: int = 0,
) -> None:
    """Show transaction details for user confirmation."""
    from trezor.crypto import base64

    from . import SIG_FALCON_DET1024

    items: list[PropertyType] = []
    td = tx.type_data

    # --- Build header: (i/n) TxnType [PQ] ---
    header = _build_header(tx, group_index, group_size, signature_type)

    # --- Warning dialogs (shown before the properties screen) ---
    if tx.rekey is not None:
        await show_danger(
            title=TR.words__important,
            content=TR.algorand__rekey_warning,
            br_name="confirm_rekey",
        )

    close_to = _get_close_to(tx)
    if close_to is not None:
        await show_danger(
            title=TR.words__important,
            content=TR.algorand__close_to_warning,
            br_name="confirm_close_to",
        )

    is_destroy = (
        tx.tx_type == TxType.ASSET_CONFIG and _get_acfg_subtype(td) == "Destroy"
    )
    if is_destroy:
        await show_danger(
            title=TR.words__important,
            content=TR.algorand__destroy_warning,
            br_name="confirm_destroy",
        )

    # --- Common fields (spec order) ---

    # 1. Rekey To
    if tx.rekey is not None:
        items.append((TR.algorand__rekey_to, format_address(tx.rekey), None))

    # 2. Sender
    items.append((TR.algorand__sender, format_address(tx.sender), None))

    # 3. Fee
    items.append((TR.algorand__fee, format_algo_amount(tx.fee), None))

    # 4. Network
    items.append((TR.algorand__network, format_network(tx.genesis_id), None))

    # 5. Valid Till
    valid_range = tx.last_valid - tx.first_valid
    items.append(
        (TR.algorand__valid_till, f"{tx.first_valid}+{valid_range}", None)
    )

    # 6. Lease
    if tx.lease is not None:
        items.append((TR.algorand__lease, base64.encode(tx.lease), None))

    # --- Type-specific fields ---
    if not is_destroy:
        _add_type_items(items, tx)

    # --- Note (shown last) ---
    if tx.note is not None:
        _add_note(items, tx.note)

    await confirm_properties(
        "confirm_transaction",
        header,
        items,
    )


def _build_header(
    tx: Transaction,
    group_index: int | None,
    group_size: int | None,
    signature_type: int,
) -> str:
    """Build the header line: (i/n) TxnType [PQ]."""
    from . import SIG_FALCON_DET1024
    from .types import TX_TYPE_NAMES

    td = tx.type_data

    if tx.tx_type == TxType.ASSET_CONFIG:
        subtype = _get_acfg_subtype(td)
        type_name = f"Asset {subtype}"
    elif tx.tx_type == TxType.APPLICATION:
        subtype = _get_app_subtype(td)
        if subtype == "Ephemeral":
            type_name = "Ephemeral Application"
        elif subtype == "Creation":
            type_name = "Application Creation"
        else:
            type_name = f"Application {subtype}"
    else:
        type_name = TX_TYPE_NAMES.get(tx.tx_type, "Unknown")

    parts: list[str] = []
    if group_index is not None and group_size is not None:
        parts.append(f"({group_index + 1}/{group_size})")
    parts.append(type_name)
    if signature_type == SIG_FALCON_DET1024:
        parts.append("[PQ]")
    return " ".join(parts)


def _get_close_to(tx: Transaction) -> bytes | None:
    """Get the close-to address from payment or asset transfer, if set."""
    if tx.tx_type == TxType.PAYMENT:
        return tx.type_data.get("close_to")
    elif tx.tx_type == TxType.ASSET_XFER:
        return tx.type_data.get("close_to")
    return None


def _add_note(items: list, note: bytes) -> None:
    """Add note field: text if printable, otherwise base64."""
    from trezor.crypto import base64

    label = f"Note [{len(note)} bytes]"

    if is_printable(note):
        items.append((label, note.decode("ascii"), None))
    else:
        items.append((label, base64.encode(note), None))


def _add_type_items(items: list, tx: Transaction) -> None:
    """Add type-specific fields to the property list."""
    from trezor.crypto import base64

    from .asa import get_asset_info

    td = tx.type_data

    if tx.tx_type == TxType.PAYMENT:
        items.append(
            (TR.algorand__receiver, format_address(td["receiver"]), None)
        )
        items.append(
            (TR.algorand__amount, format_algo_amount(td["amount"]), None)
        )
        if td.get("close_to") is not None:
            items.append(
                (TR.algorand__close_to, format_address(td["close_to"]), None)
            )

    elif tx.tx_type == TxType.KEYREG:
        if td.get("vote_pk") is not None:
            items.append(
                (TR.algorand__vote_pk, base64.encode(td["vote_pk"]), None)
            )
        if td.get("vrf_pk") is not None:
            items.append(
                (TR.algorand__vrf_pk, base64.encode(td["vrf_pk"]), None)
            )
        if td.get("sprf_pk") is not None:
            items.append(
                (
                    TR.algorand__state_proof_pk,
                    base64.encode(td["sprf_pk"]),
                    None,
                )
            )
        if td.get("vote_first") is not None:
            items.append(
                (TR.algorand__vote_first, str(td["vote_first"]), None)
            )
        if td.get("vote_last") is not None:
            items.append(
                (TR.algorand__vote_last, str(td["vote_last"]), None)
            )
        if td.get("key_dilution") is not None:
            items.append(
                (TR.algorand__key_dilution, str(td["key_dilution"]), None)
            )
        if td.get("nonpart"):
            items.append(
                (
                    TR.algorand__participating,
                    TR.algorand__non_participation,
                    None,
                )
            )
        else:
            items.append((TR.algorand__participating, TR.words__yes, None))

    elif tx.tx_type == TxType.ASSET_XFER:
        asset_id = td["asset_id"]
        asset_info = get_asset_info(asset_id)

        # Asset Sender (only for clawback)
        if td.get("sender") is not None:
            items.append(
                (
                    TR.algorand__asset_sender,
                    format_address(td["sender"]),
                    None,
                )
            )

        # Asset Receiver
        items.append(
            (
                TR.algorand__asset_receiver,
                format_address(td["receiver"]),
                None,
            )
        )

        # Asset
        items.append((TR.algorand__asset, asset_info.display_name, None))

        # Amount
        items.append(
            (
                TR.algorand__amount,
                format_asset_amount(
                    td["amount"], asset_info.decimals, asset_info.unit
                ),
                None,
            )
        )

        # Close To
        if td.get("close_to") is not None:
            items.append(
                (TR.algorand__close_to, format_address(td["close_to"]), None)
            )

    elif tx.tx_type == TxType.ASSET_FREEZE:
        asset_id = td["asset_id"]
        asset_info = get_asset_info(asset_id)

        items.append((TR.algorand__asset, asset_info.display_name, None))
        items.append(
            (TR.words__account, format_address(td["account"]), None)
        )
        status = (
            TR.algorand__freeze if td["frozen"] else TR.algorand__unfreeze
        )
        items.append((TR.algorand__status, status, None))

    elif tx.tx_type == TxType.ASSET_CONFIG:
        _add_asset_config_items(items, td)

    elif tx.tx_type == TxType.APPLICATION:
        _add_application_items(items, td)


def _add_asset_config_items(items: list, td: dict) -> None:
    """Add asset configuration fields in spec order."""
    from trezor.crypto import base64
    from trezor.strings import format_amount

    params = td.get("params", {})

    # Asset Name
    if "asset_name" in params:
        items.append(
            (TR.algorand__asset_name, params["asset_name"], None)
        )

    # Unit Name
    if "unit_name" in params:
        items.append(
            (TR.algorand__unit_name, params["unit_name"], None)
        )

    # Total Supply (derived from total units + decimals)
    if "total" in params:
        total = params["total"]
        decimals = params.get("decimals", 0)
        if decimals > 0:
            total_str = format_amount(total, decimals)
        else:
            total_str = str(total)
        items.append((TR.algorand__total_supply, total_str, None))

    # URL (string if printable, otherwise base64)
    if "url" in params:
        url = params["url"]
        if is_printable(url.encode()):
            items.append((TR.algorand__url, url, None))
        else:
            items.append(
                (TR.algorand__url, base64.encode(url.encode()), None)
            )

    # Metadata Hash (string if printable, otherwise base64)
    if "metadata_hash" in params:
        mh = params["metadata_hash"]
        if is_printable(mh):
            items.append(
                (TR.algorand__metadata_hash, mh.decode("ascii"), None)
            )
        else:
            items.append(
                (TR.algorand__metadata_hash, base64.encode(mh), None)
            )

    # Manager, Reserve, Freezer, Clawback
    for role, key in [
        ("manager", "manager"),
        ("reserve", "reserve"),
        ("freezer", "freeze"),
        ("clawback", "clawback"),
    ]:
        if key in params:
            addr = params[key]
            label = getattr(TR, f"algorand__{role}")
            if addr == b"\x00" * 32:
                items.append((label, TR.algorand__unset, None))
            else:
                items.append((label, format_address(addr), None))

    # Default Frozen
    if "default_frozen" in params:
        frozen_str = (
            TR.words__yes if params["default_frozen"] else TR.words__no
        )
        items.append((TR.algorand__default_frozen, frozen_str, None))


def _add_application_items(items: list, td: dict) -> None:
    """Add application call fields in spec order."""
    from ubinascii import hexlify

    from trezor.crypto.hashlib import sha256

    # Application ID
    app_id = td.get("app_id", 0)
    items.append((TR.algorand__application, str(app_id), None))

    # Args (printable string list if printable, otherwise count)
    if "app_args" in td:
        args = td["app_args"]
        all_printable = all(
            len(arg) > 0 and is_printable(arg) for arg in args
        )
        if all_printable:
            args_str = ", ".join(arg.decode("ascii") for arg in args)
            items.append((TR.algorand__args, args_str, None))
        else:
            items.append(
                (TR.algorand__args, f"{len(args)} args", None)
            )

    # References or Access List (mutually exclusive)
    if "access_list" in td:
        _add_access_list_items(items, td["access_list"])
    else:
        _add_reference_items(items, td)

    # Approval Program (hex SHA-256)
    if "approval_program" in td:
        prog_hash = sha256(td["approval_program"]).digest()
        items.append(
            (
                TR.algorand__approval_program,
                hexlify(prog_hash).decode(),
                None,
            )
        )

    # Clear Program (hex SHA-256)
    if "clear_program" in td:
        prog_hash = sha256(td["clear_program"]).digest()
        items.append(
            (
                TR.algorand__clear_program,
                hexlify(prog_hash).decode(),
                None,
            )
        )

    # Global Schema
    if "global_schema" in td:
        schema = td["global_schema"]
        items.append(
            (
                TR.algorand__global_schema,
                f"uint: {schema['num_uint']}, bytes: {schema['num_byteslice']}",
                None,
            )
        )

    # Local Schema
    if "local_schema" in td:
        schema = td["local_schema"]
        items.append(
            (
                TR.algorand__local_schema,
                f"uint: {schema['num_uint']}, bytes: {schema['num_byteslice']}",
                None,
            )
        )

    # Extra Pages
    if "extra_pages" in td:
        items.append(
            (TR.algorand__extra_pages, str(td["extra_pages"]), None)
        )

    # Reject Version
    if "reject_version" in td and td["reject_version"] > 0:
        items.append(
            (TR.algorand__reject_version, str(td["reject_version"]), None)
        )


def _add_reference_items(items: list, td: dict) -> None:
    """Add reference counts for old-style foreign references."""
    if td.get("num_accounts", 0) > 0:
        items.append(
            (TR.algorand__accounts, str(td["num_accounts"]), None)
        )
    if td.get("num_foreign_apps", 0) > 0:
        items.append(
            (TR.algorand__applications, str(td["num_foreign_apps"]), None)
        )
    if td.get("num_foreign_assets", 0) > 0:
        items.append(
            (TR.algorand__assets, str(td["num_foreign_assets"]), None)
        )
    if td.get("boxes") and len(td["boxes"]) > 0:
        items.append(
            (TR.algorand__boxes, str(len(td["boxes"])), None)
        )


def _add_access_list_items(items: list, al: list) -> None:
    """Add counts for access list resources by type."""
    counts = {"d": 0, "p": 0, "s": 0, "h": 0, "l": 0, "b": 0}
    for entry in al:
        if isinstance(entry, dict):
            for key in ("d", "p", "s", "h", "l", "b"):
                if key in entry:
                    counts[key] += 1
                    break

    if counts["d"] > 0:
        items.append(
            (TR.algorand__accounts, str(counts["d"]), None)
        )
    if counts["p"] > 0:
        items.append(
            (TR.algorand__applications, str(counts["p"]), None)
        )
    if counts["s"] > 0:
        items.append(
            (TR.algorand__assets, str(counts["s"]), None)
        )
    if counts["h"] > 0:
        items.append(
            (TR.algorand__holdings, str(counts["h"]), None)
        )
    if counts["l"] > 0:
        items.append(
            (TR.algorand__locals, str(counts["l"]), None)
        )
    if counts["b"] > 0:
        items.append(
            (TR.algorand__boxes, str(counts["b"]), None)
        )


async def confirm_data_signing(
    data: bytes,
    domain: str,
    signer: str,
    request_id: str | None,
    auth_data: bytes,
) -> None:
    """Show ARC-60 data signing details for user confirmation."""
    from trezor.crypto import base64

    items: list[PropertyType] = []

    items.append((TR.algorand__domain, domain, None))
    items.append((TR.algorand__signer, signer, None))

    if request_id is not None:
        items.append((TR.algorand__request_id, request_id, None))

    # Try to display data as individual JSON key-value pairs for readability.
    # Falls back to raw string / base64 if the data is not a flat JSON object.
    try:
        data_str = data.decode("utf-8")
        parsed = _parse_json_object(data_str)
        if parsed is not None:
            for key, value in parsed:
                display_value = (
                    value if len(value) <= 256 else value[:253] + "..."
                )
                items.append((key, display_value, None))
        else:
            if len(data_str) > 256:
                data_str = data_str[:253] + "..."
            items.append((TR.algorand__sign_data, data_str, None))
    except UnicodeError:
        items.append(
            (TR.algorand__sign_data, base64.encode(data), None)
        )

    items.append(
        (
            TR.algorand__auth_data,
            f"{len(auth_data)} {TR.algorand__bytes}",
            None,
        )
    )

    await confirm_properties(
        "confirm_data_signing",
        TR.algorand__sign_data,
        items,
    )


def _parse_json_object(s: str) -> list[tuple[str, str]] | None:
    """Parse a flat JSON object into a list of (key, value_str) pairs.

    Returns None if the string is not a JSON object or contains nested
    structures (arrays/objects) — in those cases the caller should fall
    back to displaying the raw string.
    """
    s = s.strip()
    if not s.startswith("{") or not s.endswith("}"):
        return None

    result: list[tuple[str, str]] = []
    pos = 1  # skip opening brace

    while pos < len(s):
        pos = _skip_ws(s, pos)
        if pos >= len(s):
            return None
        if s[pos] == "}":
            return result

        # expect comma between entries
        if result:
            if s[pos] != ",":
                return None
            pos = _skip_ws(s, pos + 1)

        # parse key (must be a string)
        if pos >= len(s) or s[pos] != '"':
            return None
        key, pos = _parse_string(s, pos)
        if key is None:
            return None

        pos = _skip_ws(s, pos)
        if pos >= len(s) or s[pos] != ":":
            return None
        pos = _skip_ws(s, pos + 1)

        # parse value — reject nested objects/arrays
        if pos >= len(s):
            return None
        ch = s[pos]
        if ch == "{" or ch == "[":
            return None
        elif ch == '"':
            value, pos = _parse_string(s, pos)
            if value is None:
                return None
        else:
            # number, bool, null — read until delimiter
            end = pos
            while end < len(s) and s[end] not in (",", "}", " ", "\t", "\n", "\r"):
                end += 1
            value = s[pos:end]
            pos = end

        result.append((key, value))

    return None  # missing closing brace


def _skip_ws(s: str, pos: int) -> int:
    while pos < len(s) and s[pos] in (" ", "\t", "\n", "\r"):
        pos += 1
    return pos


def _parse_string(s: str, pos: int) -> tuple[str | None, int]:
    """Parse a JSON string starting at pos (must be a quote character).

    Returns (parsed_string, new_pos) or (None, pos) on error.
    """
    if s[pos] != '"':
        return None, pos
    pos += 1
    chars: list[str] = []
    while pos < len(s):
        ch = s[pos]
        if ch == '"':
            return "".join(chars), pos + 1
        if ch == "\\":
            pos += 1
            if pos >= len(s):
                return None, pos
            esc = s[pos]
            if esc == '"' or esc == "\\" or esc == "/":
                chars.append(esc)
            elif esc == "n":
                chars.append("\n")
            elif esc == "r":
                chars.append("\r")
            elif esc == "t":
                chars.append("\t")
            elif esc == "b":
                chars.append("\b")
            elif esc == "f":
                chars.append("\f")
            elif esc == "u":
                if pos + 4 >= len(s):
                    return None, pos
                hex_str = s[pos + 1 : pos + 5]
                try:
                    chars.append(chr(int(hex_str, 16)))
                except ValueError:
                    return None, pos
                pos += 4
            else:
                return None, pos
        else:
            chars.append(ch)
        pos += 1
    return None, pos  # unterminated string
