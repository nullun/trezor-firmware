from typing import TYPE_CHECKING

from trezor import TR
from trezor.enums import ButtonRequestType
from trezor.ui.layouts import confirm_properties, show_danger

from .format import format_algo_amount, format_asset_amount, format_address
from .types import TxType, TX_TYPE_NAMES, ON_COMPLETION_NAMES

if TYPE_CHECKING:
    from trezor.ui.layouts import PropertyType
    from .transaction import Transaction


async def confirm_group_overview(transactions: list[Transaction]) -> None:
    """Show a summary of all transactions in an atomic group."""
    items: list[PropertyType] = []
    items.append(
        (
            TR.algorand__group_contains_template.format(len(transactions)),
            "",
            None,
        )
    )

    for i, tx in enumerate(transactions):
        type_name = TX_TYPE_NAMES.get(tx.tx_type, "Unknown")
        items.append(
            (
                TR.algorand__tx_index_template.format(i + 1, len(transactions)),
                f"{type_name} from {format_address(tx.sender)[:8]}...",
                None,
            )
        )

    await confirm_properties(
        "confirm_group",
        TR.algorand__group_overview,
        items,
    )


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

    # Transaction type header
    type_name = TX_TYPE_NAMES.get(tx.tx_type, "Unknown")
    if group_index is not None and group_size is not None:
        type_name = f"{type_name} ({group_index + 1}/{group_size})"

    # Highlight when the user is about to authorise a post-quantum
    # FALCON signature instead of the default Ed25519 path.
    if signature_type == SIG_FALCON_DET1024:
        items.append((TR.algorand__signature_type, TR.algorand__falcon_pq, None))

    # Common fields
    items.append((TR.algorand__sender, format_address(tx.sender), None))
    items.append((TR.algorand__fee, format_algo_amount(tx.fee), None))
    items.append((TR.algorand__first_valid, str(tx.first_valid), None))
    items.append((TR.algorand__last_valid, str(tx.last_valid), None))
    items.append((TR.algorand__genesis_hash, base64.encode(tx.genesis_hash), None))

    if tx.genesis_id is not None:
        items.append((TR.algorand__genesis_id, tx.genesis_id, None))
    if tx.lease is not None:
        items.append((TR.algorand__lease, base64.encode(tx.lease), None))
    if tx.group_id is not None:
        items.append((TR.algorand__group_id, base64.encode(tx.group_id), None))
    if tx.note is not None:
        items.append(
            (TR.algorand__note, f"{len(tx.note)} {TR.algorand__bytes}", None)
        )

    # Rekey warning
    if tx.rekey is not None:
        await show_danger(
            title=TR.words__important,
            content=TR.algorand__rekey_warning,
            br_name="confirm_rekey",
        )

    # Type-specific fields
    _add_type_items(items, tx)

    await confirm_properties(
        "confirm_transaction",
        type_name,
        items,
    )


def _add_type_items(items: list, tx: Transaction) -> None:
    from trezor.crypto import base64

    from .asa import get_asset_info

    td = tx.type_data

    if tx.tx_type == TxType.PAYMENT:
        items.append((TR.algorand__receiver, format_address(td["receiver"]), None))
        items.append((TR.algorand__amount, format_algo_amount(td["amount"]), None))
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
                (TR.algorand__state_proof_pk, base64.encode(td["sprf_pk"]), None)
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
                (TR.algorand__participating, TR.algorand__non_participation, None)
            )
        else:
            items.append((TR.algorand__participating, TR.words__yes, None))

    elif tx.tx_type == TxType.ASSET_XFER:
        asset_id = td["asset_id"]
        asset_info = get_asset_info(asset_id)
        items.append((TR.algorand__asset_id, asset_info.display_name, None))
        items.append(
            (
                TR.algorand__amount,
                format_asset_amount(
                    td["amount"], asset_info.decimals, asset_info.unit
                ),
                None,
            )
        )
        items.append(
            (TR.algorand__destination, format_address(td["receiver"]), None)
        )
        if td.get("sender") is not None:
            items.append(
                (TR.algorand__source, format_address(td["sender"]), None)
            )
        if td.get("close_to") is not None:
            items.append(
                (TR.algorand__close_to, format_address(td["close_to"]), None)
            )

    elif tx.tx_type == TxType.ASSET_FREEZE:
        asset_id = td["asset_id"]
        asset_info = get_asset_info(asset_id)
        items.append((TR.algorand__asset_id, asset_info.display_name, None))
        items.append(
            (TR.words__account, format_address(td["account"]), None)
        )
        frozen_str = (
            TR.algorand__frozen if td["frozen"] else TR.algorand__unfrozen
        )
        items.append((TR.words__status, frozen_str, None))

    elif tx.tx_type == TxType.ASSET_CONFIG:
        asset_id = td.get("asset_id", 0)
        if asset_id == 0:
            items.append(
                (TR.algorand__asset_id, TR.algorand__create_asset, None)
            )
        else:
            items.append((TR.algorand__asset_id, str(asset_id), None))
        params = td.get("params", {})
        if "total" in params:
            items.append(
                (TR.algorand__total_units, str(params["total"]), None)
            )
        if "default_frozen" in params:
            items.append(
                (
                    TR.algorand__default_frozen,
                    TR.words__yes
                    if params["default_frozen"]
                    else TR.words__no,
                    None,
                )
            )
        if "unit_name" in params:
            items.append(
                (TR.algorand__unit_name, params["unit_name"], None)
            )
        if "decimals" in params:
            items.append(
                (TR.algorand__decimals, str(params["decimals"]), None)
            )
        if "asset_name" in params:
            items.append(
                (TR.algorand__asset_name, params["asset_name"], None)
            )
        if "url" in params:
            items.append((TR.algorand__url, params["url"], None))
        if "metadata_hash" in params:
            items.append(
                (
                    TR.algorand__metadata_hash,
                    base64.encode(params["metadata_hash"]),
                    None,
                )
            )
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

    elif tx.tx_type == TxType.APPLICATION:
        app_id = td.get("app_id", 0)
        if app_id == 0:
            items.append(
                (TR.algorand__app_id, TR.algorand__create_app, None)
            )
        else:
            items.append((TR.algorand__app_id, str(app_id), None))

        if "on_completion" in td:
            oc_name = ON_COMPLETION_NAMES.get(td["on_completion"], "Unknown")
            items.append((TR.algorand__on_completion, oc_name, None))

        if td.get("num_accounts", 0) > 0:
            items.append(
                (TR.algorand__accounts, str(td["num_accounts"]), None)
            )
        if td.get("num_foreign_apps", 0) > 0:
            items.append(
                (TR.algorand__foreign_apps, str(td["num_foreign_apps"]), None)
            )
        if td.get("num_foreign_assets", 0) > 0:
            items.append(
                (TR.algorand__foreign_assets, str(td["num_foreign_assets"]), None)
            )
        if td.get("num_app_args", 0) > 0:
            items.append(
                (
                    TR.algorand__app_args,
                    str(td["num_app_args"]) + " (shown as SHA-256)",
                    None,
                )
            )

        # Show app args as SHA-256 hashes
        for i, arg in enumerate(td.get("app_args", [])):
            from trezor.crypto.hashlib import sha256

            arg_hash = sha256(arg).digest()
            items.append((f"Arg {i}", base64.encode(arg_hash), None))

        for i, app_id in enumerate(td.get("foreign_apps", [])):
            items.append((f"Foreign app {i}", str(app_id), None))
        for i, asset_id in enumerate(td.get("foreign_assets", [])):
            items.append((f"Foreign asset {i}", str(asset_id), None))
        for i, acct in enumerate(td.get("accounts", [])):
            items.append((f"Account {i}", format_address(acct), None))

        if "approval_program" in td:
            from trezor.crypto.hashlib import sha256

            prog = td["approval_program"]
            items.append(
                (
                    TR.algorand__approval_program,
                    base64.encode(sha256(prog).digest()),
                    None,
                )
            )
        if "clear_program" in td:
            from trezor.crypto.hashlib import sha256

            prog = td["clear_program"]
            items.append(
                (
                    TR.algorand__clear_program,
                    base64.encode(sha256(prog).digest()),
                    None,
                )
            )

        if "global_schema" in td:
            schema = td["global_schema"]
            items.append(
                (
                    TR.algorand__global_schema,
                    f"uint: {schema['num_uint']}, bytes: {schema['num_byteslice']}",
                    None,
                )
            )
        if "local_schema" in td:
            schema = td["local_schema"]
            items.append(
                (
                    TR.algorand__local_schema,
                    f"uint: {schema['num_uint']}, bytes: {schema['num_byteslice']}",
                    None,
                )
            )
        if "extra_pages" in td:
            items.append(
                (TR.algorand__extra_pages, str(td["extra_pages"]), None)
            )
        if "reject_version" in td and td["reject_version"] > 0:
            items.append(
                (TR.algorand__reject_version, str(td["reject_version"]), None)
            )
        if "boxes" in td:
            for i, box in enumerate(td["boxes"]):
                items.append(
                    (
                        f"Box {i}",
                        f"index: {box['i']}, name: {base64.encode(box['n'])}",
                        None,
                    )
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
                display_value = value if len(value) <= 256 else value[:253] + "..."
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
        (TR.algorand__auth_data, f"{len(auth_data)} {TR.algorand__bytes}", None)
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
