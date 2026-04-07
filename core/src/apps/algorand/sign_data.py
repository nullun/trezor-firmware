from typing import TYPE_CHECKING

from apps.common.keychain import with_slip44_keychain

from . import CURVE, PATTERNS, SLIP44_ID

if TYPE_CHECKING:
    from trezor.messages import AlgorandDataSignature, AlgorandSignData
    from apps.common.keychain import Keychain


@with_slip44_keychain(*PATTERNS, slip44_id=SLIP44_ID, curve=CURVE)
async def sign_data(
    msg: AlgorandSignData,
    keychain: Keychain,
) -> AlgorandDataSignature:
    from trezor.crypto.curve import ed25519
    from trezor.crypto.hashlib import sha256
    from trezor.messages import AlgorandDataSignature
    from trezor.wire import DataError

    from apps.common import seed

    from .addresses import public_key_to_address
    from .layout import confirm_data_signing

    # Derive public key
    node = keychain.derive(msg.address_n)
    public_key = seed.remove_ed25519_prefix(node.public_key())

    # Validate domain: printable ASCII only
    domain = msg.domain
    for ch in domain:
        if ord(ch) < 32 or ord(ch) > 126:
            raise DataError("Invalid domain")

    # Validate auth_data: first 32 bytes must be SHA-256(domain)
    if not msg.auth_data or len(msg.auth_data) < 32:
        raise DataError("Missing auth data")
    domain_hash = sha256(domain.encode()).digest()
    if msg.auth_data[:32] != domain_hash:
        raise DataError("Domain authentication failed")

    # Validate data is valid UTF-8
    try:
        msg.data.decode("utf-8")
    except UnicodeDecodeError:
        raise DataError("Invalid data encoding")

    # Show UI confirmation
    await confirm_data_signing(
        data=msg.data,
        domain=domain,
        signer=public_key_to_address(public_key),
        request_id=msg.request_id if msg.request_id else None,
        auth_data=msg.auth_data,
    )

    # Sign: SHA-256(data) + SHA-256(auth_data)
    data_hash = sha256(msg.data).digest()
    auth_hash = sha256(msg.auth_data).digest()
    message = data_hash + auth_hash

    signature = ed25519.sign(node.private_key(), message)
    return AlgorandDataSignature(signature=signature)
