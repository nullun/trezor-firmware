from typing import TYPE_CHECKING

from apps.common import seed
from apps.common.keychain import with_slip44_keychain

from . import CURVE, PATTERNS, SLIP44_ID

if TYPE_CHECKING:
    from trezor.messages import AlgorandGetPublicKey, AlgorandPublicKey
    from apps.common.keychain import Keychain


@with_slip44_keychain(*PATTERNS, slip44_id=SLIP44_ID, curve=CURVE)
async def get_public_key(
    msg: AlgorandGetPublicKey, keychain: Keychain
) -> AlgorandPublicKey:
    from trezor.messages import AlgorandPublicKey
    from trezor.ui.layouts import show_pubkey

    public_key = derive_public_key(keychain, msg.address_n)

    if msg.show_display:
        from apps.common.paths import address_n_to_str

        from .addresses import public_key_to_address

        path = address_n_to_str(msg.address_n)
        address = public_key_to_address(public_key)
        await show_pubkey(address, path=path)

    return AlgorandPublicKey(public_key=public_key)


def derive_public_key(keychain: Keychain, address_n: list[int]) -> bytes:
    node = keychain.derive(address_n)
    return seed.remove_ed25519_prefix(node.public_key())
