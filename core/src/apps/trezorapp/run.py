from micropython import const
from typing import TYPE_CHECKING

import trezorcrypto_api
import trezorui_api
import ustruct  # pyright: ignore[reportMissingImports]
from storage import cache_common as cc
from storage.cache import get_sessionless_cache
from trezor import app, io, loop
from trezor.messages import TrezorAppMessage, TrezorAppResponse
from trezor.ui import ProgressLayout
from trezor.ui.layouts.common import interact
from trezor.ui.layouts.progress import progress
from trezor.wire import context
from trezor.wire.errors import DataError, Error as WireError

from apps.common import paths
from apps.common.keychain import Keychain, get_keychain
from apps.ethereum.definitions import Definitions

if __debug__:
    from trezor import log

if TYPE_CHECKING:
    from trezorio import IpcMessage
    from typing import NoReturn

_SERVICE_WIRE_START = const(0)
_SERVICE_WIRE_CONTINUE = const(1)
_SERVICE_WIRE_END = const(2)
_SERVICE_WIRE_ERROR = const(3)
_SERVICE_UI = const(4)
_SERVICE_PROGRESS = const(5)
_SERVICE_CRYPTO = const(6)

_SERVICE_PROGRESS_INIT = const(0)
_SERVICE_PROGRESS_REPORT = const(1)
_SERVICE_PROGRESS_STOP = const(2)

_SERVICE_CRYPTO_GET_XPUB = const(0)
_SERVICE_CRYPTO_GET_PUBLIC_KEY = const(1)
_SERVICE_CRYPTO_SIGN_DIGEST = const(2)
_SERVICE_CRYPTO_SIGN_TYPED_HASH = const(3)
_SERVICE_CRYPTO_GET_ADDRESS_MAC = const(4)
_SERVICE_CRYPTO_CHECK_ADDRESS_MAC = const(5)
_SERVICE_CRYPTO_VERIFY_NONCE_CACHE = const(6)
# Family/scheme-based crypto ops. Match the `id()` numbering in
# `sdk/crates/trezor-app-sdk/src/structs.rs`.
_SERVICE_CRYPTO_SCHEME_GET_PUBLIC_KEY = const(7)
_SERVICE_CRYPTO_SCHEME_SIGN_DIGEST = const(8)
_SERVICE_CRYPTO_SCHEME_SIGN_MESSAGE = const(9)

# Scheme tags — must match `scheme_to_int` in
# `core/embed/rust/src/crypto/api/firmware_micropython.rs`.
_SCHEME_SECP256K1_ETHEREUM = const(0)
_SCHEME_ED25519 = const(1)
_SCHEME_ED25519_KECCAK = const(2)

# Result kind tags for `send_crypto_result_typed` — must match the
# `CRYPTO_RESULT_KIND_*` constants in firmware_micropython.rs.
_CRYPTO_RESULT_KIND_PUBLIC_KEY = const(0)
_CRYPTO_RESULT_KIND_SIGNATURE = const(1)


def fn_id(service: int, message_id: int) -> int:
    return (service << 16) | (message_id & 0xFFFF)


def from_fn_id(fn_id: int) -> tuple[int, int]:
    return ((fn_id >> 16) & 0xFFFF, fn_id & 0xFFFF)


async def run(request: TrezorAppMessage) -> TrezorAppResponse:
    if request.message_id > 0xFFFF:
        raise DataError("Invalid message ID.")

    instance_ids = get_sessionless_cache().get(cc.APP_EXTAPP_IDS)
    if instance_ids is None:
        raise DataError(f"Invalid instance ID: {request.instance_id}")
    image_handle, instance_id = ustruct.unpack("<II", instance_ids)
    if instance_id != request.instance_id:
        raise DataError(f"Invalid instance ID: {request.instance_id}")

    image = app.image_by_handle(image_handle)

    curves: list[str] = list(image.allowed_curves())
    slip44_id: int = image.slip44_id()
    if len(curves) != 1:
        raise DataError("Expected exactly one allowed curve")
    curve = curves[0]

    patterns: list[str] = list(image.allowed_paths())

    if __debug__:
        log.debug(
            __name__,
            f"Allowed curves: {curves}, slip44_id: {slip44_id}, patterns: {patterns}",
        )
    schemas = []
    for pattern in patterns:
        schemas.append(paths.PathSchema.parse(pattern, slip44_id))
    schemas: list[paths.PathSchema] = [s.copy() for s in schemas]

    if not image.is_running():
        if __debug__:
            log.error(__name__, f"Task not running: {request.instance_id}")
        raise DataError(f"Task not running: {request.instance_id}")

    def die(exception: Exception) -> NoReturn:
        if __debug__:
            log.error(__name__, f"Task died due to exception: {exception}")
        image.stop()  # TODO or image.delete ???
        raise exception

    task_id = image.task_id()

    try:
        if __debug__:
            log.debug(__name__, f"Sending wire start IPC message: {request.message_id}")
        io.ipc_send(
            task_id,
            fn_id(_SERVICE_WIRE_START, request.message_id),
            request.data,
        )
    except Exception as e:
        if __debug__:
            log.error(__name__, "Failed to send IPC message")
        die(DataError(f"Failed to send IPC message: {e}"))

    progress_obj: ProgressLayout | None = None

    def crypto_resp_cb(data: bytes) -> None:
        log.debug(__name__, "Sending crypto result")
        io.ipc_send(task_id, fn_id(_SERVICE_CRYPTO, 0), data)

    def ui_resp_cb(data: bytes) -> None:
        io.ipc_send(task_id, fn_id(_SERVICE_UI, 0), data)

    while True:
        if not image.is_running():
            raise DataError(f"Task stopped: {request.instance_id}")
        try:
            msg: IpcMessage = await loop.wait(
                io.IPC2_EVENT | io.POLL_READ, timeout_ms=1000
            )
        except loop.Timeout:
            die(DataError("Timeout waiting for message"))

        service, message_id = from_fn_id(msg.fn)

        if service == _SERVICE_UI:
            main_layout_obj, br_code, br_name = trezorui_api.process_ipc_message(
                data=bytes(msg.data)
            )

            result = await interact(
                main_layout_obj, br_name, br_code, raise_on_cancel=None
            )
            log.debug(__name__, f"UI interaction result: {result}")
            # Serialize and send the result back
            trezorui_api.send_ui_result(result=result, ipc_cb=ui_resp_cb)

        elif service == _SERVICE_CRYPTO:
            # `result_kind = None` selects the legacy send_crypto_result path;
            # family-based ops below set it to a `_CRYPTO_RESULT_KIND_*` value.
            result_kind: int | None = None
            try:
                if __debug__:
                    log.debug(__name__, "Processing crypto message")
                obj = trezorcrypto_api.deserialize_crypto_message(data=bytes(msg.data))

                if message_id == _SERVICE_CRYPTO_GET_XPUB:
                    assert len(obj) == 2
                    address_n: list[int] = obj[0]
                    xpub_magic: int = obj[1]
                    try:
                        if __debug__:
                            log.debug(
                                __name__,
                                f"Getting xpub for path: {address_n}, xpub_magic: {xpub_magic}",
                            )
                        keychain = await get_keychain(
                            curve, [paths.AlwaysMatchingSchema]
                        )
                        result = await _get_xpub(address_n, keychain, xpub_magic)
                    except Exception:
                        if __debug__:
                            log.error(__name__, "Failed to get xpub")
                        result = False

                elif message_id == _SERVICE_CRYPTO_GET_PUBLIC_KEY:
                    assert len(obj) == 2
                    address_n: list[int] = obj[0]
                    compressed: bool = obj[1]
                    try:
                        if __debug__:
                            log.debug(
                                __name__,
                                "Deriving keychain",
                            )
                        keychain = await get_keychain(
                            curve, [paths.AlwaysMatchingSchema]
                        )
                        if __debug__:
                            log.debug(
                                __name__,
                                f"Getting public key bytes for path: {address_n} compressed={compressed}",
                            )
                        result = [
                            0,
                            await _get_public_key(
                                address_n, compressed, keychain, curve
                            ),
                        ]
                        if __debug__:
                            log.debug(
                                __name__,
                                f"Result: {len(result[1])} bytes",
                            )
                    except Exception as e:
                        if __debug__:
                            log.error(
                                __name__,
                                f"Failed to get public key bytes due to exception: {e}",
                            )
                        result = False

                elif message_id == _SERVICE_CRYPTO_SIGN_DIGEST:
                    assert len(obj) == 3
                    address_n: list[int] = obj[0]
                    digest: bytes = obj[1]
                    compressed: bool = obj[2]
                    try:
                        if __debug__:
                            log.debug(__name__, f"Signing digest for path: {address_n}")
                        keychain = await get_keychain(curve, schemas, [[b"SLIP-0024"]])
                        result = await _sign_digest(
                            address_n, digest, compressed, keychain, curve
                        )

                    except Exception:
                        log.error(__name__, "Failed to sign digest")
                        result = False

                elif message_id == _SERVICE_CRYPTO_SIGN_TYPED_HASH:
                    assert len(obj) == 6
                    address_n: list[int] = obj[0]
                    data_hash: bytes = obj[1]
                    encoded_network: bytes | None = obj[2]
                    encoded_token: bytes | None = obj[3]
                    chain_id: int | None = obj[4]
                    show_progress: bool = obj[5]
                    try:
                        if __debug__:
                            log.debug(
                                __name__, f"Signing typed hash for path: {address_n}"
                            )
                        keychain = None
                        if (
                            encoded_network is None
                            and encoded_token is None
                            and chain_id is None
                        ):
                            keychain = await get_keychain(curve, schemas)
                        result = await _sign_typed_hash(
                            address_n,
                            data_hash,
                            keychain,
                            encoded_network,
                            encoded_token,
                            chain_id,
                            show_progress,
                        )

                    except Exception:
                        log.error(__name__, "Failed to sign typed hash")
                        result = False

                elif message_id == _SERVICE_CRYPTO_GET_ADDRESS_MAC:
                    assert len(obj) == 2
                    address_n: list[int] = obj[0]
                    address_str: str = obj[1]
                    try:
                        if __debug__:
                            log.debug(
                                __name__, f"Getting address MAC for path: {address_n}"
                            )
                        keychain = await get_keychain(curve, schemas, [[b"SLIP-0024"]])
                        await paths.validate_path(keychain, address_n)
                        from apps.common.address_mac import get_address_mac

                        result = get_address_mac(
                            address_str, paths.unharden(slip44_id), address_n, keychain
                        )
                    except Exception:
                        log.error(__name__, "Failed to get address MAC")
                        result = False
                elif message_id == _SERVICE_CRYPTO_CHECK_ADDRESS_MAC:
                    assert len(obj) == 3
                    address_n: list[int] = obj[0]
                    mac: bytes = obj[1]
                    address_str: str = obj[2]
                    try:
                        if __debug__:
                            log.debug(
                                __name__, f"Checking address MAC for path: {address_n}"
                            )
                        keychain = await get_keychain(curve, schemas, [[b"SLIP-0024"]])
                        await paths.validate_path(keychain, address_n)
                        from apps.common.address_mac import check_address_mac

                        check_address_mac(
                            address_str,
                            mac,
                            paths.unharden(slip44_id),
                            address_n,
                            keychain,
                        )
                        result = True
                    except Exception:
                        log.error(__name__, "Failed to check address MAC")
                        result = False
                elif message_id == _SERVICE_CRYPTO_VERIFY_NONCE_CACHE:
                    nonce: bytes = obj
                    try:
                        if __debug__:
                            log.debug(
                                __name__, f"Verifying nonce cache for nonce: {nonce}"
                            )
                        result = await _verify_nonce_cache(bytes(nonce))
                    except Exception:
                        log.error(__name__, "Failed to verify nonce cache")
                        result = False
                # -- family/scheme-based operations -----------------------
                elif message_id == _SERVICE_CRYPTO_SCHEME_GET_PUBLIC_KEY:
                    assert len(obj) == 2
                    scheme: int = obj[0]
                    address_n: list[int] = obj[1]
                    try:
                        result = await _get_public_key_for_scheme(scheme, address_n)
                        result_kind = _CRYPTO_RESULT_KIND_PUBLIC_KEY
                    except:  # noqa: E722
                        result = False
                elif message_id == _SERVICE_CRYPTO_SCHEME_SIGN_DIGEST:
                    assert len(obj) == 4
                    scheme: int = obj[0]
                    address_n: list[int] = obj[1]
                    digest: bytes = obj[2]
                    context: bytes | None = obj[3]
                    try:
                        result = await _sign_digest_for_scheme(
                            scheme, address_n, digest, context
                        )
                        result_kind = _CRYPTO_RESULT_KIND_SIGNATURE
                    except:  # noqa: E722
                        result = False
                elif message_id == _SERVICE_CRYPTO_SCHEME_SIGN_MESSAGE:
                    assert len(obj) == 3
                    scheme: int = obj[0]
                    address_n: list[int] = obj[1]
                    message: bytes = obj[2]
                    try:
                        result = await _sign_message_for_scheme(
                            scheme, address_n, message
                        )
                        result_kind = _CRYPTO_RESULT_KIND_SIGNATURE
                    except:  # noqa: E722
                        result = False
                else:
                    log.error(__name__, f"Unknown crypto operation: {message_id}")
                    die(DataError("Unknown crypto operation"))

            except Exception:
                log.error(__name__, "Failed to process crypto message")
                result = False

            # Serialize and send the result back. Family-based ops set
            # `result_kind` to select the typed result variant; legacy ops
            # leave it as None and use the length-discriminated entry point.
            try:
                if __debug__:
                    log.debug(__name__, "Serializing crypto result")
                if result_kind is None:
                    trezorcrypto_api.send_crypto_result(
                        result=result, ipc_cb=crypto_resp_cb
                    )
                else:
                    trezorcrypto_api.send_crypto_result_typed(
                        kind=result_kind,
                        result=result,
                        ipc_cb=crypto_resp_cb,
                    )
            except Exception:
                if __debug__:
                    log.error(__name__, "Failed to serialize or send crypto result")
                die(DataError("Failed to serialize or send crypto result"))

        elif service == _SERVICE_WIRE_CONTINUE:
            # usb request/ack
            response = TrezorAppResponse(
                message_id=message_id, data=msg.data, finished=False
            )
            ack = await context.call(response, TrezorAppMessage)
            if ack.message_id > 0xFFFF:
                die(DataError("Invalid message ID."))
            io.ipc_send(
                task_id,
                fn_id(_SERVICE_WIRE_CONTINUE, ack.message_id),
                ack.data,
            )

        elif service == _SERVICE_WIRE_END:
            if __debug__:
                log.debug(__name__, f"Forwarding wire end message: {message_id}")
            # usb final message
            response = TrezorAppResponse(
                message_id=message_id, data=msg.data, finished=True
            )
            if __debug__:
                log.info(__name__, "Ending trezorapp run function")
            return response

        elif service == _SERVICE_PROGRESS:
            if __debug__:
                log.debug(__name__, f"Processing progress message: {message_id}")
            obj = trezorui_api.deserialize_progress_message(data=bytes(msg.data))
            if message_id == _SERVICE_PROGRESS_INIT:
                # Initialize a progress context
                assert isinstance(obj, tuple)
                assert len(obj) == 4
                description: str | None = obj[0]
                title: str | None = obj[1]
                indeterminate: bool = obj[2]
                danger: bool = obj[3]
                progress_obj = progress(
                    description=description,
                    title=title,
                    indeterminate=indeterminate,
                    danger=danger,
                )
            elif message_id == _SERVICE_PROGRESS_REPORT:
                if progress_obj is None:
                    die(DataError("Progress not initialized"))
                # Report progress update
                assert isinstance(obj, tuple)
                assert len(obj) == 2
                description: str | None = obj[0]
                value: int = obj[1]
                progress_obj.report(value, description=description)
            elif message_id == _SERVICE_PROGRESS_STOP:
                if progress_obj is None:
                    die(DataError("Progress not initialized"))
                # Stop the progress context
                progress_obj.stop()
                progress_obj = None
            else:
                die(DataError("Unknown progress message ID"))

            # Serialize and send the result back
            try:
                io.ipc_send(
                    task_id,
                    fn_id(_SERVICE_PROGRESS, message_id),
                    b"",
                )
            except Exception:
                die(DataError("Failed to send progress result"))

        elif service == _SERVICE_WIRE_ERROR:
            # Terminal response: the app reports an error, we surface it to
            # the host as a Failure and exit `run`. The wire layer converts a
            # `wire.Error` into `Failure(code, message)` for us. The app task
            # stays alive in its own receive loop, ready for the next
            # TrezorAppMessage from the host.
            err_message = (
                msg.data.decode("utf-8", "replace")
                if isinstance(msg.data, (bytes, bytearray))
                else str(msg.data)
            )
            if __debug__:
                log.debug(__name__, f"Received wire error message: {err_message}")
            raise WireError(message_id, err_message)

        else:
            if __debug__:
                log.error(
                    __name__,
                    f"Unknown IPC function: service={service}, message_id={message_id}",
                )
            die(RuntimeError("Unknown IPC function"))


async def _get_xpub(address_n: list[int], keychain: Keychain, xpub_magic: int) -> str:
    from apps.common import paths
    from apps.common.keychain import ForbiddenKeyPath

    if address_n and address_n[0] == paths.SLIP25_PURPOSE:
        # UnlockPath is required to access SLIP25 paths.
        log.error(__name__, "Forbidden key path: SLIP25 purpose detected")
        raise ForbiddenKeyPath()

    node = keychain.derive(address_n)
    node_xpub = node.serialize_public(xpub_magic)
    return node_xpub


async def _get_public_key(
    address_n: list[int], compressed: bool, keychain: Keychain, curve_name: str
) -> bytes:
    from apps.common import paths
    from apps.common.keychain import ForbiddenKeyPath

    if address_n and address_n[0] == paths.SLIP25_PURPOSE:
        # UnlockPath is required to access SLIP25 paths.
        log.error(__name__, "Forbidden key path: SLIP25 purpose detected")
        raise ForbiddenKeyPath()

    log.debug(__name__, f"Deriving keychain for path: {address_n}")
    node = keychain.derive(address_n)

    if curve_name == "secp256k1":
        from trezor.crypto.curve import secp256k1

        log.debug(
            __name__,
            f"Getting secp256k1 public key bytes for path: {address_n} compressed={compressed}",
        )
        return secp256k1.publickey(node.private_key(), compressed)
    elif curve_name == "nist256p1":
        from trezor.crypto.curve import nist256p1

        return nist256p1.publickey(node.private_key(), compressed)
    elif curve_name == "ed25519":
        from trezor.crypto.curve import ed25519

        return ed25519.publickey(node.private_key())
    elif curve_name == "curve25519":
        from trezor.crypto.curve import curve25519

        return curve25519.publickey(node.private_key())
    elif curve_name == "bip340":
        from trezor.crypto.curve import bip340

        return bip340.publickey(node.private_key())
    else:
        raise DataError(f"Unsupported curve: {curve_name}")


async def _sign_digest(
    address_n: list[int],
    digest: bytes,
    compressed: bool,
    keychain: Keychain,
    curve_name: str,
) -> bytes:

    await paths.validate_path(keychain, address_n)
    node = keychain.derive(address_n)

    if curve_name == "secp256k1":
        from trezor.crypto.curve import secp256k1

        return secp256k1.sign(node.private_key(), digest, compressed)
    elif curve_name == "nist256p1":
        from trezor.crypto.curve import nist256p1

        return nist256p1.sign(node.private_key(), digest, compressed)
    elif curve_name == "ed25519":
        from trezor.crypto.curve import ed25519

        return ed25519.sign(node.private_key(), digest)
    elif curve_name == "bip340":
        from trezor.crypto.curve import bip340

        return bip340.sign(node.private_key(), digest)
    else:
        raise DataError(f"Unsupported curve: {curve_name} for signing digest")


async def _sign_typed_hash(
    address_n: list[int],
    data_hash: bytes,
    keychain: Keychain | None,
    encoded_network: bytes | None,
    encoded_token: bytes | None,
    chain_id: int | None,
    show_progress: bool,
) -> bytes:
    from trezor import TR
    from trezor.crypto.curve import secp256k1
    from trezor.ui.layouts.progress import progress

    if keychain is None:

        from apps.ethereum.keychain import (
            PATTERNS_ADDRESS,
            _schemas_from_network,
            _slip44_from_address_n,
        )

        if chain_id is not None:
            if __debug__:
                log.debug(
                    __name__,
                    f"Getting definitions from encoded network and token for chain_id: {chain_id}",
                )
            defs = Definitions.from_encoded(
                encoded_network, encoded_token, chain_id=chain_id
            )
        else:
            slip44 = _slip44_from_address_n(address_n)
            defs = Definitions.from_encoded(
                encoded_network, encoded_token, slip44=slip44
            )
        schemas = _schemas_from_network(PATTERNS_ADDRESS, defs.network)
        keychain = await get_keychain("secp256k1", schemas, [[b"SLIP-0024"]])

    await paths.validate_path(keychain, address_n)

    node = keychain.derive(address_n)
    if show_progress:
        progress_obj = progress(title=TR.progress__signing_transaction)
        progress_obj.report(600)
    signature = secp256k1.sign(
        node.private_key(),
        data_hash,
        False,
        secp256k1.CANONICAL_SIG_ETHEREUM,
    )
    if show_progress:
        progress_obj.stop()
    return signature


async def _verify_nonce_cache(nonce: bytes) -> bool:
    from storage.cache_common import APP_COMMON_NONCE

    result = context.cache_get(APP_COMMON_NONCE) == nonce

    if result:
        context.cache_delete(APP_COMMON_NONCE)

    return result


# ---------------------------------------------------------------------------
# Family/scheme-based crypto handlers
# ---------------------------------------------------------------------------
#
# These mirror the `TrezorCryptoEnum::SchemeGetPublicKey / SchemeSignDigest /
# SchemeSignMessage` variants in `sdk/crates/trezor-app-sdk/src/structs.rs`. Adding a new scheme
# inside an existing family means: extend the `Scheme` enum, register a branch
# below, and add a typed wrapper in `sdk/crates/trezor-app-sdk/src/crypto.rs`.
# The IPC schema does not change.


def _validate_ed25519_path(address_n: list[int]) -> None:
    # SLIP-10 ed25519 keychains require fully-hardened paths.
    if not address_n or not all(i & 0x80000000 for i in address_n):
        raise DataError("Ed25519 paths must be fully hardened")


def _ed25519_curve_name(scheme: int) -> str:
    if scheme == _SCHEME_ED25519:
        return "ed25519"
    if scheme == _SCHEME_ED25519_KECCAK:
        return "ed25519-keccak"
    raise DataError("Unknown ed25519 scheme")


async def _get_public_key_for_scheme(scheme: int, address_n: list[int]) -> bytes:
    from trezor.crypto.curve import ed25519, secp256k1

    if scheme == _SCHEME_SECP256K1_ETHEREUM:
        keychain = await get_keychain(
            "secp256k1", [paths.AlwaysMatchingSchema], [[b"SLIP-0024"]]
        )
        node = keychain.derive(address_n)
        # Uncompressed secp256k1 public key (0x04 || X || Y) — 65 bytes.
        return secp256k1.publickey(node.private_key(), False)

    if scheme in (_SCHEME_ED25519, _SCHEME_ED25519_KECCAK):
        _validate_ed25519_path(address_n)
        keychain = await get_keychain(
            _ed25519_curve_name(scheme), [paths.AlwaysMatchingSchema]
        )
        node = keychain.derive(address_n)
        # Raw ed25519 public key — 32 bytes.
        return ed25519.publickey(node.private_key())

    raise DataError("Unsupported scheme for SchemeGetPublicKey")


async def _sign_digest_for_scheme(
    scheme: int,
    address_n: list[int],
    digest: bytes,
    context: bytes | None,
) -> bytes:
    # `context` is reserved for scheme-specific extras (chain id, OID prefix,
    # etc.). For v1 no scheme consumes it; future Ethereum / FIPS HashML-DSA
    # handlers will. Keeping it in the wire shape avoids a later schema change.
    from trezor.crypto.curve import secp256k1

    if scheme == _SCHEME_SECP256K1_ETHEREUM:
        keychain = await get_keychain(
            "secp256k1", [paths.AlwaysMatchingSchema], [[b"SLIP-0024"]]
        )
        node = keychain.derive(address_n)
        # 65-byte signature (recid in byte 0), Ethereum canonical (low-S).
        return secp256k1.sign(
            node.private_key(),
            digest,
            False,
            secp256k1.CANONICAL_SIG_ETHEREUM,
        )

    if scheme in (_SCHEME_ED25519, _SCHEME_ED25519_KECCAK):
        # Pure-mode ed25519 signs the message, not a digest. Pre-hashed
        # ("HashEdDSA", RFC 8032 §8) would belong here behind a separate
        # Scheme::Ed25519Hash{Sha512|Keccak} entry; not implemented yet.
        raise DataError(
            "Ed25519 schemes do not support SignDigest; use SignMessage"
        )

    raise DataError("Unsupported scheme for SchemeSignDigest")


async def _sign_message_for_scheme(
    scheme: int,
    address_n: list[int],
    message: bytes,
) -> bytes:
    from trezor.crypto.curve import ed25519

    if scheme == _SCHEME_ED25519:
        _validate_ed25519_path(address_n)
        keychain = await get_keychain("ed25519", [paths.AlwaysMatchingSchema])
        node = keychain.derive(address_n)
        return ed25519.sign(node.private_key(), message)

    if scheme == _SCHEME_ED25519_KECCAK:
        _validate_ed25519_path(address_n)
        keychain = await get_keychain(
            "ed25519-keccak", [paths.AlwaysMatchingSchema]
        )
        node = keychain.derive(address_n)
        return ed25519.sign(node.private_key(), message, "keccak")

    if scheme == _SCHEME_SECP256K1_ETHEREUM:
        # secp256k1 needs a digest, not a raw message. Use SignDigest.
        raise DataError(
            "Secp256k1Ethereum does not support SignMessage; use SignDigest"
        )

    raise DataError("Unsupported scheme for SchemeSignMessage")
