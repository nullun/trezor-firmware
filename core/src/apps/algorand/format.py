from trezor.strings import format_amount


def format_algo_amount(microalgos: int) -> str:
    """Format microAlgos as ALGO string with 6 decimal places."""
    from trezor.strings import format_amount_unit

    return format_amount_unit(format_amount(microalgos, 6), "ALGO")


def format_asset_amount(amount: int, decimals: int, unit: str) -> str:
    """Format an asset amount with given decimals and unit."""
    from trezor.strings import format_amount_unit

    return format_amount_unit(format_amount(amount, decimals), unit)


def truncate_middle(s: str) -> str:
    """Middle-truncate a string to 18 characters (8..8) if longer."""
    if len(s) <= 18:
        return s
    return f"{s[:8]}..{s[-8:]}"


def format_address(address_bytes: bytes) -> str:
    """Format a 32-byte address as a middle-truncated Algorand address."""
    from .addresses import public_key_to_address

    return truncate_middle(public_key_to_address(address_bytes))


_KNOWN_NETWORKS: dict[str, str] = {
    "mainnet-v1.0": "Mainnet",
    "testnet-v1.0": "Testnet",
    "betanet-v1.0": "Betanet",
    "fnet-v1.0": "Fnet",
}


def format_network(genesis_id: str | None) -> str:
    """Derive a human-readable network name from the genesis ID."""
    if genesis_id is not None:
        name = _KNOWN_NETWORKS.get(genesis_id)
        if name is not None:
            return name
        return genesis_id
    return "Unknown"


def is_printable(data: bytes) -> bool:
    """Check if all bytes are printable ASCII (0x20-0x7E)."""
    for b in data:
        if b < 0x20 or b > 0x7E:
            return False
    return True
