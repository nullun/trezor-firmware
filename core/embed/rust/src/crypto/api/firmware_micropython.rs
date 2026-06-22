#[cfg(feature = "app_loading")]
use core::mem::MaybeUninit;

#[cfg(feature = "app_loading")]
use rkyv::{
    api::low::to_bytes_in_with_alloc,
    rancor::Failure,
    ser::{allocator::SubAllocator, writer::Buffer},
    util::Align,
    Archived,
};
#[cfg(feature = "app_loading")]
use trezor_app_sdk::crypto::{ArchivedScheme, Slice, TrezorCryptoEnum, TrezorCryptoResultRef};

#[cfg(feature = "app_loading")]
use crate::micropython::gc::Gc;
use crate::micropython::macros::{obj_fn_kw, obj_module};
use crate::micropython::map::Map;
use crate::micropython::module::Module;
use crate::micropython::obj::Obj;
use crate::micropython::qstr::Qstr;
#[cfg(feature = "app_loading")]
use crate::{
    error::Error,
    micropython::{list::List, util},
};

/// Stable integer encoding of `Scheme` handed across the Rust↔Python boundary.
/// Kept here (not derived from rkyv's archive discriminant) so the Python side
/// has a contract that doesn't shift when archive layout changes.
#[cfg(feature = "app_loading")]
fn scheme_to_int(scheme: &ArchivedScheme) -> u8 {
    match scheme {
        ArchivedScheme::Secp256k1Ethereum => 0,
        ArchivedScheme::Ed25519 => 1,
        ArchivedScheme::Ed25519Keccak => 2,
    }
}

/// Tag for `new_send_crypto_result_typed` — keep in sync with `run.py`.
#[cfg(feature = "app_loading")]
const CRYPTO_RESULT_KIND_PUBLIC_KEY: u8 = 0;
#[cfg(feature = "app_loading")]
const CRYPTO_RESULT_KIND_SIGNATURE: u8 = 1;

#[cfg(feature = "app_loading")]
extern "C" fn new_deserialize_crypto_message(
    n_args: usize,
    args: *const Obj,
    kwargs: *mut Map,
) -> Obj {
    let block = |_args: &[Obj], kwargs: &Map| {
        let obj: Obj = kwargs.get(Qstr::MP_QSTR_data)?;

        let data = unwrap!(unsafe { crate::micropython::buffer::get_buffer(obj) });

        fn obj_from_dp_slice(slice: &Archived<Slice<u32>>) -> Obj {
            let slice = slice.as_ref();
            let mut list = unwrap!(List::with_capacity(slice.len()));

            for &item in slice {
                unwrap!(list.append(unwrap!(Obj::try_from(item.to_native()))));
            }
            unwrap!(List::alloc(unsafe { list.as_slice() })).into()
        }

        // Deserialize the rkyv archived data directly from the static buffer
        let archived = unsafe { rkyv::access_unchecked::<Archived<TrezorCryptoEnum>>(data) };

        // Access the archived data zero-copy using safe Deref access
        let result: Obj = match archived {
            Archived::<TrezorCryptoEnum>::GetXpub {
                address_n,
                xpub_magic,
            } => {
                let dp_obj = obj_from_dp_slice(address_n);
                let magic_obj = unwrap!(Obj::try_from(xpub_magic.to_native()));
                (dp_obj, magic_obj).try_into()?
            }
            Archived::<TrezorCryptoEnum>::GetPublicKey {
                address_n,
                compressed,
            } => {
                let dp_obj = obj_from_dp_slice(address_n);
                let compressed_obj = unwrap!(Obj::try_from(*compressed));
                (dp_obj, compressed_obj).try_into()?
            }
            Archived::<TrezorCryptoEnum>::SignDigest {
                address_n,
                digest,
                compressed,
            } => {
                let digest_obj = Obj::try_from(digest.as_slice())?;
                (
                    obj_from_dp_slice(address_n),
                    digest_obj,
                    Obj::try_from(*compressed)?,
                )
                    .try_into()?
            }
            Archived::<TrezorCryptoEnum>::SignTypedHash {
                address_n,
                hash,
                encoded_network,
                encoded_token,
                chain_id,
                show_progress,
            } => {
                let hash_obj = Obj::try_from(hash.as_slice())?;
                let network_obj = match encoded_network.as_ref() {
                    Some(network) => Obj::try_from(network.as_ref())?,
                    None => Obj::const_none(),
                };
                let token_obj = match encoded_token.as_ref() {
                    Some(token) => Obj::try_from(token.as_ref())?,
                    None => Obj::const_none(),
                };
                let chain_id_obj = match chain_id.as_ref() {
                    Some(id) => Obj::try_from(id.to_native())?,
                    None => Obj::const_none(),
                };
                (
                    obj_from_dp_slice(address_n),
                    hash_obj,
                    network_obj,
                    token_obj,
                    chain_id_obj,
                    Obj::try_from(*show_progress)?,
                )
                    .try_into()?
            }
            Archived::<TrezorCryptoEnum>::GetAddressMac { address_n, address } => {
                (obj_from_dp_slice(address_n), address.as_ref().try_into()?).try_into()?
            }
            Archived::<TrezorCryptoEnum>::VerifyNonceCache { nonce } => {
                Obj::try_from(nonce.as_ref())?
            }
            Archived::<TrezorCryptoEnum>::CheckAddressMac {
                address_n,
                mac,
                address,
            } => (
                obj_from_dp_slice(address_n),
                mac.as_ref().try_into()?,
                address.as_ref().try_into()?,
            )
                .try_into()?,
            Archived::<TrezorCryptoEnum>::SchemeGetPublicKey { scheme, address_n } => {
                let scheme_int = scheme_to_int(scheme);
                (Obj::try_from(scheme_int)?, obj_from_dp_slice(address_n)).try_into()?
            }
            Archived::<TrezorCryptoEnum>::SchemeSignDigest {
                scheme,
                address_n,
                digest,
                context,
            } => {
                let scheme_int = scheme_to_int(scheme);
                let digest_obj = Obj::try_from(digest.as_slice())?;
                let context_obj = match context.as_ref() {
                    Some(ctx) => Obj::try_from(ctx.as_ref())?,
                    None => Obj::const_none(),
                };
                (
                    Obj::try_from(scheme_int)?,
                    obj_from_dp_slice(address_n),
                    digest_obj,
                    context_obj,
                )
                    .try_into()?
            }
            Archived::<TrezorCryptoEnum>::SchemeSignMessage {
                scheme,
                address_n,
                message,
            } => {
                let scheme_int = scheme_to_int(scheme);
                let message_obj = Obj::try_from(message.as_ref())?;
                (
                    Obj::try_from(scheme_int)?,
                    obj_from_dp_slice(address_n),
                    message_obj,
                )
                    .try_into()?
            }
        };

        Ok(result)
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

#[cfg(not(feature = "app_loading"))]
extern "C" fn new_deserialize_crypto_message(
    _n_args: usize,
    _args: *const Obj,
    _kwargs: *mut Map,
) -> Obj {
    unimplemented!()
}

#[cfg(feature = "app_loading")]
extern "C" fn new_send_crypto_result(n_args: usize, args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = |_args: &[Obj], kwargs: &Map| {
        let obj: Obj = kwargs.get(Qstr::MP_QSTR_result)?;

        let ipc_callback: Option<Obj> = kwargs
            .get(Qstr::MP_QSTR_ipc_cb)
            .unwrap_or_else(|_| Obj::const_none())
            .try_into_option()?;

        let ipc_cb = unwrap!(ipc_callback.map(|cb| {
            move |bytes: &[u8]| {
                unwrap!(cb.call_with_n_args(&[unwrap!(bytes.try_into())]));
            }
        }));

        // Map MicroPython CryptoResult object to Rust enum for serialization
        let msg = if obj.is_str() {
            let data = unwrap!(unsafe { crate::micropython::buffer::get_buffer(obj) });
            match data.len() {
                111 => TrezorCryptoResultRef::Xpub(unwrap!(data.try_into())),
                _ => {
                    return Err(Error::TypeError);
                }
            }
        } else if obj.is_bytes() {
            let data = unwrap!(unsafe { crate::micropython::buffer::get_buffer(obj) });
            match data.len() {
                32 => TrezorCryptoResultRef::AddressMac(unwrap!(data.try_into())),
                65 => TrezorCryptoResultRef::Signature(unwrap!(data.try_into())),
                _ => {
                    return Err(Error::TypeError);
                }
            }
        } else if obj.is_immediate() {
            TrezorCryptoResultRef::Boolean(unwrap!(bool::try_from(obj)))
        } else {
            // Expect a (type_tag: int, bytes) tuple for ambiguous lengths (e.g. 65 bytes)
            let list: Gc<List> = obj.try_into()?;
            assert!(
                list.len() == 2,
                "Expected a tuple of (type_tag: int, bytes)"
            );
            let tag_obj = list.get(0)?;
            let tag: u8 = unwrap!(tag_obj.try_into());
            let bytes_obj = list.get(1)?;
            let data = unwrap!(unsafe { crate::micropython::buffer::get_buffer(bytes_obj) });
            match tag {
                0 => {
                    assert!(
                        data.len() == 32 || data.len() == 33 || data.len() == 65,
                        "Expected public key to be 32, 33 or 65 bytes"
                    );
                    TrezorCryptoResultRef::PublicKey(unwrap!(data.try_into()))
                }
                _ => {
                    return Err(Error::TypeError);
                }
            }
        };

        let mut arena = [MaybeUninit::<u8>::uninit(); 200];
        let mut out = Align([MaybeUninit::<u8>::uninit(); 200]);

        let bytes = unwrap!(to_bytes_in_with_alloc::<_, _, Failure>(
            &msg,
            Buffer::from(&mut *out),
            SubAllocator::new(&mut arena),
        ));
        //Send the response back via the ipc_cb callback
        ipc_cb(bytes.as_ref());

        Ok(Obj::const_none())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

#[cfg(not(feature = "app_loading"))]
extern "C" fn new_send_crypto_result(_n_args: usize, _args: *const Obj, _kwargs: *mut Map) -> Obj {
    unimplemented!()
}

/// Serialize a typed crypto result whose variant is selected by an explicit
/// `kind` tag rather than length-discrimination. Used for the new family-based
/// result variants (`PublicKey`, `SignatureBytes`); the length-based
/// `new_send_crypto_result` keeps serving the legacy variants unchanged.
#[cfg(feature = "app_loading")]
extern "C" fn new_send_crypto_result_typed(
    n_args: usize,
    args: *const Obj,
    kwargs: *mut Map,
) -> Obj {
    let block = |_args: &[Obj], kwargs: &Map| {
        let kind_obj: Obj = kwargs.get(Qstr::MP_QSTR_kind)?;
        let result_obj: Obj = kwargs.get(Qstr::MP_QSTR_result)?;

        let ipc_callback: Option<Obj> = kwargs
            .get(Qstr::MP_QSTR_ipc_cb)
            .unwrap_or_else(|_| Obj::const_none())
            .try_into_option()?;

        let ipc_cb = unwrap!(ipc_callback.map(|cb| {
            move |bytes: &[u8]| {
                unwrap!(cb.call_with_n_args(&[unwrap!(bytes.try_into())]));
            }
        }));

        let kind: u8 = kind_obj.try_into()?;
        let data = unwrap!(unsafe { crate::micropython::buffer::get_buffer(result_obj) });

        let msg = match kind {
            CRYPTO_RESULT_KIND_PUBLIC_KEY => {
                TrezorCryptoResultRef::PublicKey(unwrap!(data.try_into()))
            }
            CRYPTO_RESULT_KIND_SIGNATURE => {
                TrezorCryptoResultRef::SignatureBytes(unwrap!(data.try_into()))
            }
            _ => {
                log::error!("Unknown typed crypto result kind: {}", kind);
                return Err(Error::TypeError);
            }
        };

        // Buffer sized for the variable-length payloads above (public keys and
        // signatures of today's schemes are at most 65 bytes) plus rkyv
        // archive overhead.
        let mut arena = [MaybeUninit::<u8>::uninit(); 256];
        let mut out = Align([MaybeUninit::<u8>::uninit(); 256]);

        let bytes = unwrap!(to_bytes_in_with_alloc::<_, _, Failure>(
            &msg,
            Buffer::from(&mut *out),
            SubAllocator::new(&mut arena),
        ));
        ipc_cb(bytes.as_ref());

        Ok(Obj::const_none())
    };
    unsafe { util::try_with_args_and_kwargs(n_args, args, kwargs, block) }
}

#[cfg(not(feature = "app_loading"))]
extern "C" fn new_send_crypto_result_typed(
    _n_args: usize,
    _args: *const Obj,
    _kwargs: *mut Map,
) -> Obj {
    unimplemented!()
}

#[no_mangle]
pub static mp_module_trezorcrypto_api: Module = obj_module! {

    /// mock:global
    Qstr::MP_QSTR___name__ => Qstr::MP_QSTR_trezorcrypto_api.to_obj(),

    /// def send_crypto_result(
    ///     *,
    ///     result: CryptoResult,
    ///     ipc_cb: Callable[[bytes], None],
    /// ) -> None:
    ///     """Serialize a crypto result (e.g. CryptoResult) into bytes and send it back via the ipc_cb callback."""
    Qstr::MP_QSTR_send_crypto_result => obj_fn_kw!(0, new_send_crypto_result).as_obj(),

    /// def send_crypto_result_typed(
    ///     *,
    ///     kind: int,
    ///     result: bytes,
    ///     ipc_cb: Callable[[bytes], None],
    /// ) -> None:
    ///     """Serialize a single variable-length crypto result (either a PublicKey or a SignatureBytes,
    ///     selected by `kind`) and send it back via the ipc_cb callback. One call delivers one result;
    ///     a signing request returns only a signature, a public-key request returns only a public key.
    ///     `kind` values are the CRYPTO_RESULT_KIND_* constants in apps/trezorapp/run.py."""
    Qstr::MP_QSTR_send_crypto_result_typed => obj_fn_kw!(0, new_send_crypto_result_typed).as_obj(),

    /// def deserialize_crypto_message(
    ///     *,
    ///     data: bytes,
    /// ) -> Obj:
    ///     """Deserialize a crypto message from bytes and return it as a MicroPython object."""
    Qstr::MP_QSTR_deserialize_crypto_message => obj_fn_kw!(0, new_deserialize_crypto_message).as_obj(),
};
