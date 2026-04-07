from trezor.strings import format_amount


def format_algo_amount(microalgos: int) -> str:
    """Format microAlgos as ALGO string with 6 decimal places."""
    from trezor.strings import format_amount_unit

    return format_amount_unit(format_amount(microalgos, 6), "ALGO")


def format_asset_amount(amount: int, decimals: int, unit: str) -> str:
    """Format an asset amount with given decimals and unit."""
    from trezor.strings import format_amount_unit

    return format_amount_unit(format_amount(amount, decimals), unit)


def format_address(address_bytes: bytes) -> str:
    """Format a 32-byte address as a 58-char Algorand address string."""
    from .addresses import public_key_to_address

    return public_key_to_address(address_bytes)
