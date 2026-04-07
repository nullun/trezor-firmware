from typing import TYPE_CHECKING

from apps.common.keychain import with_slip44_keychain

from . import CURVE, PATTERNS, SLIP44_ID

if TYPE_CHECKING:
    from trezor.messages import AlgorandAddress, AlgorandGetAddress
    from apps.common.keychain import Keychain


@with_slip44_keychain(*PATTERNS, slip44_id=SLIP44_ID, curve=CURVE)
async def get_address(
    msg: AlgorandGetAddress,
    keychain: Keychain,
) -> AlgorandAddress:
    from trezor import TR
    from trezor.messages import AlgorandAddress
    from trezor.ui.layouts import show_address
    from apps.common import paths

    from .addresses import public_key_to_address
    from .get_public_key import derive_public_key

    public_key = derive_public_key(keychain, msg.address_n)
    address = public_key_to_address(public_key)

    if msg.show_display:
        await show_address(
            address,
            subtitle=TR.address__coin_address_template.format("ALGO"),
            path=paths.address_n_to_str(msg.address_n),
            chunkify=bool(msg.chunkify),
        )

    return AlgorandAddress(address=address)
