from typing import TYPE_CHECKING

from apps.common.keychain import with_slip44_keychain

from . import CURVE, FALCON_SLIP21_PATH, PATTERNS, SLIP44_ID

if TYPE_CHECKING:
    from trezor.messages import AlgorandFalconAddress, AlgorandGetFalconAddress
    from apps.common.keychain import Keychain


@with_slip44_keychain(
    *PATTERNS,
    slip44_id=SLIP44_ID,
    curve=CURVE,
    slip21_namespaces=[FALCON_SLIP21_PATH],
)
async def get_falcon_address(
    msg: AlgorandGetFalconAddress,
    keychain: Keychain,
) -> AlgorandFalconAddress:
    from trezor import TR
    from trezor.messages import AlgorandFalconAddress
    from trezor.ui.layouts import show_address
    from apps.common import paths

    from .addresses import public_key_to_address
    from .falcon_keys import derive_falcon_keypair, zeroize_privkey
    from .logicsig import DEFAULT_TEAL_VERSION, derive_falcon_logicsig_address

    privkey, pubkey = derive_falcon_keypair(keychain, msg.address_n)
    # The public key is everything we need from the keypair; wipe the
    # private key immediately rather than letting it linger in RAM.
    zeroize_privkey(privkey)

    address_bytes, counter = derive_falcon_logicsig_address(pubkey)
    address = public_key_to_address(address_bytes)

    if msg.show_display:
        await show_address(
            address,
            subtitle=TR.address__coin_address_template.format("ALGO (PQ)"),
            path=paths.address_n_to_str(msg.address_n),
            chunkify=bool(msg.chunkify),
        )

    return AlgorandFalconAddress(
        address=address,
        public_key=pubkey,
        counter=counter,
        teal_version=DEFAULT_TEAL_VERSION,
    )
