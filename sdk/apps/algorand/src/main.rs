#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#![feature(non_exhaustive_omitted_patterns_lint)]

#[cfg(test)]
fn main() {}

// `alloc` is only needed by the unit tests (host std build); the firmware
// itself is allocation-free.
#[cfg(test)]
extern crate alloc;

use tiny_algo::address::{Address, ENCODED_LEN as ADDRESS_LEN};
use tiny_algo::txn::{TransactionType, Transaction};
use tiny_algo::{TXN_DOMAIN, Transactions, ValidateError};
use trezor_app_sdk::service::{self, CoreIpcService};
use trezor_app_sdk::util::Timeout;
use trezor_app_sdk::{
    CORE_SERVICE, Error, IpcMessage, Result, crypto, error, info, ui,
};

mod button_request;
mod strutil;
mod transactions;
mod wire;

use button_request::ButtonRequestType;

#[derive(Copy, Clone, PartialEq, Eq, num_enum::FromPrimitive, num_enum::IntoPrimitive)]
#[repr(u16)]
enum AlgorandMessages {
    GetPublicKey = 0,
    PublicKey = 1,
    SignTransactions = 2,
    TransactionSignatures = 3,
    ContinueSignTransactions = 4,
    #[num_enum(catch_all)]
    Unknown(u16),
}

// The app's own logic is allocation-free: transactions are staged into fixed
// static buffers (`SIGN_STAGE`/`SIGN_MEMBER`) and every display string is built
// on the stack. The only heap use is the SDK's transient IPC `AlignedVec`
// (signing embeds the whole `"TX" || txn` in one `SignMessage`). The SDK owns
// the `#[global_allocator]` and its fixed heap, so the app declares none of its
// own — a max-size app transaction must fit within that SDK heap.

/// BIP-32 hardened-derivation bit.
const HARDENED: u32 = 0x8000_0000;

/// SLIP-44 coin type for Algorand (`283'`).
const SLIP44_ALGORAND: u32 = HARDENED | 283;

/// BIP-44 purpose constant (`44'`).
const PURPOSE_BIP44: u32 = HARDENED | 44;

/// BIP-32 path length the Algorand app accepts:
/// `m/44'/283'/account'/change'/index'`. Shared by `check_path` and the
/// chunked-upload state so the path-buffer sizing tracks the validator.
const ALGORAND_PATH_LEN: usize = 5;

/// Hard cap on `total_size` for chunked-upload requests, and the size of
/// the staging buffer body. A 16-application atomic group with large
/// programs lands around ~73 KiB on the wire; 96 KiB leaves headroom for
/// envelope overhead without letting a host request an oversized buffer.
const MAX_TXN_GROUP_BYTES: usize = 96 * 1024;

/// The transaction signing-domain prefix ("TX"), reserved at the front of
/// [`SIGN_STAGE`] so a standalone transaction can be signed in place.
const SIGN_PREFIX_LEN: usize = TXN_DOMAIN.len();

/// Framing added around a single transaction when it is sent to core to be
/// signed: the rkyv `SignMessage` envelope (scheme + `address_n` + slice
/// headers), the kernel IPC queue-item header, and the `TXN_DOMAIN` prefix.
/// Comfortably covers the ~130 B actually used; the slack is harmless — no real
/// Algorand transaction comes near this size.
const SIGN_IPC_FRAMING: usize = 512;

/// Largest single transaction the device can sign. Every transaction is signed
/// on its own — a standalone one, or each member of a group in turn — and core
/// copies the whole serialised sign request into its IPC inbox (32 KiB on the
/// emulator; the kernel's `IPC_MAX_BUFFER_SIZE` hard cap is 64 KiB). So a single
/// transaction must fit that inbox once framed. An over-size request is rejected
/// cleanly (`Error::FailedToSend`), never a crash, but capping here rejects it
/// early with a specific error. Also sizes the per-member signing scratch.
/// (Emulator-derived; revisit if the hardware IPC inbox differs.)
const MAX_SINGLE_TXN_BYTES: usize = 32 * 1024 - SIGN_IPC_FRAMING;

/// Staging buffer for the incoming transaction (group), laid out as
/// `[ "TX" | wire bytes ]`. Both the direct and chunked-upload paths
/// accumulate the wire bytes into `[SIGN_PREFIX_LEN..]`; parsing reads that
/// region. The reserved prefix slot means a standalone transaction's
/// `"TX" ‖ map` message is already contiguous, so it is signed with no
/// copy — the zero-copy layout tiny-algo's `parse_signable`/`signable` is
/// built around.
static mut SIGN_STAGE: [u8; SIGN_PREFIX_LEN + MAX_TXN_GROUP_BYTES] =
    [0u8; SIGN_PREFIX_LEN + MAX_TXN_GROUP_BYTES];

/// Scratch for signing one member of an atomic group, staged as
/// `[ "TX" | member ]`. Standalone transactions never touch this.
static mut SIGN_MEMBER: [u8; SIGN_PREFIX_LEN + MAX_SINGLE_TXN_BYTES] =
    [0u8; SIGN_PREFIX_LEN + MAX_SINGLE_TXN_BYTES];

/// Copy `data` into the staging buffer body at offset `at`. Callers must
/// keep `at + data.len() <= MAX_TXN_GROUP_BYTES`.
///
/// SAFETY rationale: single-threaded extapp, and this is the only writer of
/// `SIGN_STAGE`; no shared borrow of the buffer is live across a call.
fn stage_body_write(at: usize, data: &[u8]) {
    debug_assert!(at + data.len() <= MAX_TXN_GROUP_BYTES);
    unsafe {
        let base = core::ptr::addr_of_mut!(SIGN_STAGE) as *mut u8;
        core::ptr::copy_nonoverlapping(data.as_ptr(), base.add(SIGN_PREFIX_LEN + at), data.len());
    }
}

/// Shared read view of the staged transaction body (`len` bytes).
///
/// SAFETY: single-threaded extapp; the caller holds no mutable access to
/// `SIGN_STAGE` while the returned slice is live.
unsafe fn stage_body(len: usize) -> &'static [u8] {
    unsafe {
        let base = core::ptr::addr_of!(SIGN_STAGE) as *const u8;
        core::slice::from_raw_parts(base.add(SIGN_PREFIX_LEN), len)
    }
}

/// Write the domain prefix into the reserved slot and return the contiguous
/// `"TX" ‖ body` message for a standalone transaction — the exact bytes to
/// sign, with no copy.
///
/// SAFETY: single-threaded extapp. The prefix write touches only
/// `[..SIGN_PREFIX_LEN]`, disjoint from the parsed body at
/// `[SIGN_PREFIX_LEN..]`, and uses raw pointers so it never aliases a live
/// `&` to the body.
unsafe fn stage_signable(len: usize) -> &'static [u8] {
    unsafe {
        let base = core::ptr::addr_of_mut!(SIGN_STAGE) as *mut u8;
        core::ptr::copy_nonoverlapping(TXN_DOMAIN.as_ptr(), base, SIGN_PREFIX_LEN);
        core::slice::from_raw_parts(base as *const u8, SIGN_PREFIX_LEN + len)
    }
}

/// Stage `[ "TX" | member ]` into [`SIGN_MEMBER`] and return it for signing.
/// Rejects a member larger than [`MAX_SINGLE_TXN_BYTES`].
///
/// SAFETY: single-threaded extapp; the returned slice is used immediately
/// (to sign) before the next member overwrites the buffer.
fn member_signable(member: &[u8]) -> Result<&'static [u8]> {
    if member.len() > MAX_SINGLE_TXN_BYTES {
        return Err(Error::DataError("Transaction too large to sign"));
    }
    unsafe {
        let base = core::ptr::addr_of_mut!(SIGN_MEMBER) as *mut u8;
        core::ptr::copy_nonoverlapping(TXN_DOMAIN.as_ptr(), base, SIGN_PREFIX_LEN);
        core::ptr::copy_nonoverlapping(member.as_ptr(), base.add(SIGN_PREFIX_LEN), member.len());
        Ok(core::slice::from_raw_parts(
            base as *const u8,
            SIGN_PREFIX_LEN + member.len(),
        ))
    }
}

/// Accept only the shape Pera Wallet and the Ledger Algorand app
/// produce, so signatures from this device round-trip with the keys
/// those wallets derive for the same seed. ed25519 has no unhardened
/// derivation, so a non-hardened component could never have produced
/// a usable key anyway.
fn check_path(address_n: &[u32]) -> Result<()> {
    if address_n.len() != ALGORAND_PATH_LEN {
        return Err(Error::DataError(
            "BIP-32 path must be m/44'/283'/account'/change'/index'",
        ));
    }
    if address_n[0] != PURPOSE_BIP44 {
        return Err(Error::DataError("BIP-32 path must start with 44'"));
    }
    if address_n[1] != SLIP44_ALGORAND {
        return Err(Error::DataError("BIP-32 path must use Algorand coin type 283'"));
    }
    if !address_n.iter().all(|&i| i & HARDENED != 0) {
        return Err(Error::DataError("BIP-32 path must be fully hardened"));
    }
    Ok(())
}

fn send_wire_end(id: AlgorandMessages, bytes: &[u8]) -> Result<()> {
    IpcMessage::new(id.into(), bytes)
        .send(service::CORE_SERVICE_REMOTE, CoreIpcService::WireEnd.into())?;
    Ok(())
}

fn send_wire_error(err: Error) -> Result<()> {
    IpcMessage::new(err.code(), err.message().as_bytes())
        .send(service::CORE_SERVICE_REMOTE, CoreIpcService::WireError.into())?;
    Ok(())
}

/// Send a `WireError` whose payload is composed at runtime.
///
/// `Error::DataError` is `&'static str`, so anything we want to put in
/// front of the host that depends on runtime data (e.g. "Transaction 3:
/// missing receiver") cannot route through that variant. The wire
/// transport itself takes `&[u8]`, so we build the IpcMessage directly
/// here. The error code mirrors `Error::DataError(_).code()` (= 3) so
/// the host sees a `DataError` failure as it would for any static
/// message — only the body differs.
fn send_wire_error_dynamic(msg: &str) -> Result<()> {
    const DATA_ERROR_CODE: u16 = 3;
    IpcMessage::new(DATA_ERROR_CODE, msg.as_bytes())
        .send(service::CORE_SERVICE_REMOTE, CoreIpcService::WireError.into())?;
    Ok(())
}

fn handle_get_public_key(request_data: &[u8]) -> Result<()> {
    let request = wire::decode_get_public_key(request_data)?;

    info!(
        "Algorand GetPublicKey for path: {:?}",
        request.address_n.as_slice()
    );

    check_path(request.address_n.as_slice())?;

    let pk = crypto::ed25519_get_public_key(request.address_n.as_slice())?;
    let mut addr_buf = [0u8; ADDRESS_LEN];
    let address = transactions::address_to_str(&Address::from_pubkey(&pk), &mut addr_buf);

    if request.show_display {
        ui::error_if_not_confirmed(ui::confirm_value(ui::ConfirmValue::new(
            "Algorand address",
            address,
            None,
            Some("show_address"),
            ButtonRequestType::Address.into(),
            true,
            None,
            None,
            false,
            false,
            false,
            false,
            false,
            false,
            None,
        ))?)?;
    }

    let mut response_buf = [0u8; wire::PUBLIC_KEY_RESPONSE_LEN];
    let response_bytes = wire::encode_public_key(&mut response_buf, &pk, &addr_buf);
    send_wire_end(AlgorandMessages::PublicKey, response_bytes)
}

/// Map a tiny-algo error kind to a short human-readable string.
///
/// The `non_exhaustive_omitted_patterns` lint is set to `deny`, so adding a
/// variant to `tiny_algo::Error` becomes a compile error here until the new
/// variant is triaged — either with a bespoke string or by adding it to the
/// shared "Transaction rejected" arm.
#[deny(non_exhaustive_omitted_patterns)]
fn validation_message(kind: tiny_algo::Error) -> &'static str {
    use tiny_algo::Error;
    match kind {
        // Parse-side
        Error::Truncated => "Transaction data truncated",
        Error::UnexpectedTag => "Invalid msgpack encoding",
        Error::InvalidLength => "Too many transactions",
        Error::NonCanonical => "Non-canonical encoding",
        Error::UnknownField => "Unknown transaction field",
        Error::MissingField => "Required field missing",
        Error::MissingTypeTag => "Missing transaction type tag",
        Error::IntegerOverflow => "Integer overflow",
        Error::TxnTypeMismatch => "Transaction type tag does not match body",
        Error::InvalidOnCompletion => "Invalid application on-completion value",
        Error::NestingTooDeep => "Transaction too deeply nested",
        // Validate-side
        Error::MissingGenesisHash => "Missing genesis hash",
        Error::InvalidValidityWindow => "Invalid validity window",
        Error::ValidityWindowTooLong => "Validity window too long",
        Error::ZeroSender => "Sender is the zero address",
        Error::NoteTooLarge => "Note too large",
        Error::ZeroAssetId => "Asset id must be non-zero",
        Error::AssetClawbackClose => "Clawback cannot close out asset",
        Error::MissingFreezeAddress => "Missing freeze address",
        Error::MissingApprovalProgram => "Missing approval program",
        Error::MissingClearProgram => "Missing clear-state program",
        Error::InvalidAppCreation => "Invalid application creation",
        Error::InvalidKeyRegFields => "Invalid key-registration fields",
        Error::BadGroup => "Invalid transaction group",
        // Variants the app's call sites can't produce (address-string decode,
        // base64 decode, signature verify, encode-buffer sizing). Listed
        // explicitly to satisfy the lint and share one string.
        Error::BufferTooSmall
        | Error::BadChecksum
        | Error::BadBase32Char
        | Error::BadBase64Char
        | Error::BadAddressLength
        | Error::BadSignature
        | Error::UnsupportedSigKind
        | Error::ThresholdNotMet => "Transaction rejected",
        // Fallback for variants added to tiny-algo after this code was written;
        // the lint above will fire first and force a triage.
        _ => "Transaction rejected",
    }
}

/// Report a tiny-algo validation failure to the host with the failing
/// transaction's index, then short-circuit.
fn fail_with(err: ValidateError) -> Result<()> {
    let kind_msg = validation_message(err.kind);
    let mut msg_buf = [0u8; 96];
    let msg = uformat!(&mut msg_buf, "Transaction {}: {}", err.index as usize + 1, kind_msg);
    info!("Rejected: {}", msg);
    send_wire_error_dynamic(msg)
}

/// Chunked-upload state for large transaction payloads.
static mut CHUNKED_UPLOAD: Option<ChunkedUpload> = None;

struct ChunkedUpload {
    address_n: [u32; ALGORAND_PATH_LEN],
    total: u32,
    /// Bytes accumulated so far in `SIGN_STAGE[SIGN_PREFIX_LEN..]`.
    len: u32,
    sign_mask: u16,
}

/// Clear any in-flight chunked-upload state. The dispatcher calls this for
/// every wire message except a `ContinueSignTransactions` continuation, so
/// an abandoned upload from a prior host exchange can't bleed into a later,
/// unrelated request. The staged bytes in `SIGN_STAGE` are left as-is; the
/// next upload overwrites them from the front.
fn reset_chunked_upload() {
    // SAFETY: single-threaded extapp.
    unsafe {
        let ptr = core::ptr::addr_of_mut!(CHUNKED_UPLOAD);
        (*ptr) = None;
    }
}

fn handle_sign_transactions(request_data: &[u8]) -> Result<()> {
    let request = wire::decode_sign_transactions(request_data)?;

    info!(
        "Algorand SignTransactions for path: {:?}, payload {} bytes",
        request.address_n.as_slice(),
        request.transactions.len()
    );

    check_path(request.address_n.as_slice())?;

    let first_len = request.transactions.len();
    // Everything that lands in a single message must fit the staging body;
    // a chunked upload's `total_size` is bounded separately below.
    if first_len > MAX_TXN_GROUP_BYTES {
        return Err(Error::DataError("Transaction payload exceeds maximum size"));
    }

    // Chunked upload: if total_size > len(transactions), accumulate.
    if let Some(total) = request.total_size {
        let total_usize = total as usize;
        if total_usize > MAX_TXN_GROUP_BYTES {
            return Err(Error::DataError("Chunked upload exceeds maximum size"));
        }
        if total_usize < first_len {
            return Err(Error::DataError("Chunked upload total_size below first chunk"));
        }
        if total_usize > first_len {
            info!("Chunked upload: {} of {} bytes", first_len, total);
            // The dispatcher already dropped any abandoned upload before
            // reaching here, so the staging buffer is ours to claim.
            // `check_path` guarantees address_n is exactly ALGORAND_PATH_LEN.
            debug_assert_eq!(request.address_n.as_slice().len(), ALGORAND_PATH_LEN);
            let mut addr = [0u32; ALGORAND_PATH_LEN];
            addr.copy_from_slice(request.address_n.as_slice());
            stage_body_write(0, request.transactions);
            // SAFETY: single-threaded extapp.
            unsafe {
                let ptr = core::ptr::addr_of_mut!(CHUNKED_UPLOAD);
                (*ptr) = Some(ChunkedUpload {
                    address_n: addr,
                    total,
                    len: first_len as u32,
                    sign_mask: request.sign_mask,
                });
            }
            return send_wire_end(AlgorandMessages::ContinueSignTransactions, &[]);
        }
    }
    // Complete in one message: stage the payload and sign it.
    stage_body_write(0, request.transactions);
    sign_transactions_inner(request.address_n.as_slice(), first_len, request.sign_mask)
}

fn handle_continue_sign_transactions(request_data: &[u8]) -> Result<()> {
    let request = wire::decode_continue_sign_transactions(request_data)?;

    // SAFETY: single-threaded extapp.  Use raw pointer to avoid
    // creating a &mut to a mutable static (Rust 2024 forbids it).
    let mut state = unsafe {
        let ptr = core::ptr::addr_of_mut!(CHUNKED_UPLOAD);
        match (*ptr).take() {
            Some(s) => s,
            None => return Err(Error::DataError("No chunked upload in progress")),
        }
    };

    // Enforce the declared size *before* staging. On entry `len < total`
    // always holds (the equal/over branches consume the state), so
    // `total - len` cannot underflow. Checking first stops a host from
    // writing past the staging buffer with an oversized continuation chunk.
    let total = state.total as usize;
    let have = state.len as usize;
    if request.data.len() > total - have {
        return Err(Error::DataError("Chunked upload exceeded expected size"));
    }
    stage_body_write(have, request.data);
    let got = have + request.data.len();
    state.len = got as u32;
    info!("Chunked upload: {} of {} bytes", got, total);

    if got == total {
        let addr = state.address_n;
        let sign_mask = state.sign_mask;
        sign_transactions_inner(&addr, total, sign_mask)
    } else {
        unsafe {
            let ptr = core::ptr::addr_of_mut!(CHUNKED_UPLOAD);
            (*ptr) = Some(state);
        }
        send_wire_end(AlgorandMessages::ContinueSignTransactions, &[])
    }
}

fn sign_transactions_inner(address_n: &[u32], total: usize, sign_mask: u16) -> Result<()> {
    // SAFETY: single-threaded extapp; the staged body is stable for the
    // duration of this call and only read (the prefix slot written for
    // in-place signing is disjoint from this body view).
    let body = unsafe { stage_body(total) };
    let txns = match Transactions::parse(body) {
        Ok(t) => t,
        Err(e) => return fail_with(e),
    };

    let n = txns.len();
    if n == 0 {
        return Err(Error::DataError("No transactions in request"));
    }

    let gid = match txns.validate() {
        Ok(g) => g,
        Err(e) => return fail_with(e),
    };

    // Resolve the host's sign selection. An empty mask means "sign every
    // member" (the single-signer default); otherwise a set bit selects
    // member `i`. Reject any requested index that doesn't name a member of
    // *this* group — `decode_sign_transactions` only bounded indices by
    // `MAX_TXN_GROUP_SIZE`, not by the actual count.
    let sign_all = sign_mask == 0;
    let is_signed = |i: usize| sign_all || (sign_mask & (1u16 << i)) != 0;
    if !sign_all {
        for bit in 0..wire::MAX_SIGNATURE_RECORDS {
            if sign_mask & (1u16 << bit) != 0 && bit >= n {
                return Err(Error::DataError("Sign index exceeds transaction count"));
            }
        }
    }

    // Derive this device's key once. `our_addr` is the account the
    // signatures actually authorise; when it differs from a transaction's
    // sender we are signing as the sender's rekeyed authority and must
    // report the auth key back to the host.
    let pk = crypto::ed25519_get_public_key(address_n)?;
    let our_addr = Address::from_pubkey(&pk);

    let txn_at = |i: usize| -> Transaction<'_> {
        txns.get(i)
            .expect("index < len")
            .expect("slots already validated by Transactions::parse")
    };

    // An atomic group must target a single network and is summarised by
    // one aggregate validity window. Reject a mixed-network group, and
    // derive the window — the highest first-valid and lowest last-valid
    // round, i.e. where every member is simultaneously valid — for the
    // overview screen.
    if n > 1 {
        let network = txn_at(0).genesis_hash().copied();
        let mut window_start = txn_at(0).first_valid();
        let mut window_end = txn_at(0).last_valid();
        for i in 1..n {
            let t = txn_at(i);
            if t.genesis_hash().copied() != network {
                return Err(Error::DataError("Atomic group mixes networks"));
            }
            window_start = window_start.max(t.first_valid());
            window_end = window_end.min(t.last_valid());
        }
        if let Some(gid) = &gid {
            transactions::confirm_group_header(n, gid, network.as_ref(), window_start, window_end)?;
        }
    }

    // Review every transaction, then one hold-to-sign for groups.
    //
    // Type filtering: `Transactions::parse` routes the type tag through
    // `TransactionType::from_tag`, which only knows variants gated in by tiny-algo
    // features. An unsupported txn type normally fails parse with
    // `Error::UnknownField` before any UI is shown — but a future
    // tiny-algo variant added behind a feature this app enables could
    // otherwise fall through and be signed without a confirm screen, so
    // the wildcard arm refuses to sign rather than silently authorising.
    let mut signed_count = 0;
    for i in 0..n {
        let txn = txn_at(i);
        let signing = is_signed(i);
        if signing {
            signed_count += 1;
        }
        // The signer (auth) address only differs from the sender when this
        // account is rekeyed to us; surface it on the review screen so the
        // user sees they're authorising another account's transaction.
        let auth = if signing && txn.sender() != Some(our_addr) {
            Some(our_addr)
        } else {
            None
        };
        let ctx = transactions::common::ReviewCtx { signing, auth };
        // Control- and balance-changing fields (rekey, close-out) are gated
        // here, before the type body, but only for transactions we sign —
        // those dangers protect *our* key; an unsigned group member's
        // close/rekey is authorised by some other party.
        if signing {
            transactions::common::run_danger_gates(&txn)?;
        }
        match txn.tx_type() {
            TransactionType::Payment => transactions::confirm_payment(&txn, i, n, ctx)?,
            TransactionType::KeyReg => transactions::confirm_keyreg(&txn, i, n, ctx)?,
            TransactionType::AssetTransfer => {
                transactions::confirm_asset_transfer(&txn, i, n, ctx)?
            }
            TransactionType::AssetFreeze => transactions::confirm_asset_freeze(&txn, i, n, ctx)?,
            TransactionType::AssetConfig => transactions::confirm_asset_config(&txn, i, n, ctx)?,
            TransactionType::Application => transactions::confirm_application(&txn, i, n, ctx)?,
            _ => return Err(Error::DataError("Unsupported transaction type")),
        }
    }

    if n > 1 {
        transactions::confirm_sign_all(signed_count, n)?;
    }

    let mut response_buf = [0u8; wire::MAX_SIGNATURE_RECORDS * wire::MAX_SIGNATURE_RECORD_LEN];
    let mut response_len = 0;

    for i in 0..n {
        if !is_signed(i) {
            continue;
        }
        let txn = txn_at(i);
        // The message to sign is `TXN_DOMAIN ‖ txn map`. A standalone
        // transaction already sits behind the reserved prefix slot in
        // `SIGN_STAGE`, so sign it in place with no copy; a group member is
        // packed against its neighbours, so stage `"TX" ‖ member` into the
        // per-member scratch first.
        let msg: &[u8] = if n == 1 {
            // A standalone txn signs in place from SIGN_STAGE (staged up to the
            // 96 KiB group cap), but the sign request must still fit core's IPC
            // inbox, so it is bound by the single-transaction cap like a member.
            if total > MAX_SINGLE_TXN_BYTES {
                return Err(Error::DataError("Transaction too large to sign"));
            }
            // SAFETY: single-threaded extapp; writes only the reserved
            // prefix slot, disjoint from the body `txns` borrows.
            unsafe { stage_signable(total) }
        } else {
            member_signable(txn.bytes())?
        };

        let sig = crypto::ed25519_sign(address_n, msg)?;
        let auth = (txn.sender() != Some(our_addr)).then_some(&pk);
        response_len =
            wire::write_signature_record(&mut response_buf, response_len, i as u32, &sig, auth);
    }

    send_wire_end(
        AlgorandMessages::TransactionSignatures,
        &response_buf[..response_len],
    )
}

#[unsafe(no_mangle)]
pub fn app() -> Result<()> {
    loop {
        let message = CORE_SERVICE.receive(Timeout::max())?;
        let result = match message.service().into() {
            CoreIpcService::WireStart => handle_wire_message(&message),
            _ => {
                error!(
                    "Invalid service invoked: {:?}, message id {:?}",
                    message.service(),
                    message.id()
                );
                Err(Error::InvalidFunction)
            }
        };
        if let Err(e) = result {
            error!("Handler failed: {}", e.message());
            let _ = send_wire_error(e);
        }
    }
}

fn handle_wire_message(message: &IpcMessage) -> Result<()> {
    let id: AlgorandMessages = message.id().into();
    // Only a continuation chunk may build on an in-flight upload; every
    // other message (including a fresh SignTransactions, a key request, or
    // an unknown id) abandons it, so a stale partial payload can't linger
    // on the heap or be appended to by an unrelated request.
    if id != AlgorandMessages::ContinueSignTransactions {
        reset_chunked_upload();
    }
    match id {
        AlgorandMessages::GetPublicKey => handle_get_public_key(message.data()),
        AlgorandMessages::SignTransactions => handle_sign_transactions(message.data()),
        AlgorandMessages::ContinueSignTransactions => {
            handle_continue_sign_transactions(message.data())
        }
        _ => Err(Error::InvalidFunction),
    }
}
