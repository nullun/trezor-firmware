//! Shared transaction-confirmation mechanism.
//!
//! Every transaction type funnels its type-specific fields through
//! [`finalize`], which appends the common header fields — network (for a
//! single transaction), validity window, note, lease — and renders the
//! tap-through or hold-to-sign review screen as a property list. Fields
//! that change account
//! control or empty an account (rekey, close-out) are not body lines:
//! [`run_danger_gates`] surfaces each as its own full-screen
//! hold-to-confirm gate *before* the body, so they cannot be tapped past
//! as part of a routine review. Concentrating the common and dangerous
//! fields here is what lets us say every header field is either displayed
//! or gated, regardless of transaction type.

use tiny_algo::address::{Address, ENCODED_LEN as ADDRESS_LEN};
use tiny_algo::base64;
use tiny_algo::txn::{Transaction, TransactionType};
use trezor_app_sdk::{Result, ui, ui::Property};

use super::address_to_str;
use crate::button_request::ButtonRequestType;
use crate::strutil::{self, PropVec};
use crate::uformat;

/// Upper bound on the property list `finalize` assembles: the largest
/// type-specific screen (application) emits 16, and finalize appends up to
/// 6 common header fields.
const MAX_FINALIZE_PROPS: usize = 24;

/// Buffer length for a danger-gate body: prose plus one encoded address.
const DANGER_BODY_LEN: usize = 320;

/// Per-transaction review context: how this device treats the transaction
/// it's about to show. Lets the shared screen render whether the device
/// signs it and, for a rekeyed account, under which authorising key.
#[derive(Copy, Clone)]
pub struct ReviewCtx {
    /// Whether this device produces a signature for this transaction.
    pub signing: bool,
    /// The signer (auth) address, set only when signing *and* it differs
    /// from the transaction's sender — i.e. the sender is rekeyed to this
    /// key. `None` when not signing, or when the signer is the sender.
    pub auth: Option<Address>,
}

/// base64 length of a 32-byte genesis hash / transaction id (44 chars).
pub const HASH_B64_LEN: usize = base64::encoded_len(32);

/// Map a network's genesis hash to a friendly name.
///
/// Grounded in the genesis *hash* — the network identity `validate`
/// requires — never the `genesis_id` string, which a host sets freely.
/// The three public networks (genesis ids `mainnet-v1.0`, `testnet-v1.0`,
/// `betanet-v1.0`) are named; any other hash is unknown to the caller.
pub fn network_name(genesis_hash: &[u8; 32]) -> Option<&'static str> {
    let mut buf = [0u8; HASH_B64_LEN];
    let _ = base64::encode(genesis_hash, &mut buf);
    match &buf {
        b"wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=" => Some("Mainnet"),
        b"SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=" => Some("Testnet"),
        b"mFgazF+2uRS1tMiL9dsj01hJGySEmPN28B/TjjvpVW0=" => Some("Betanet"),
        _ => None,
    }
}

/// Friendly network name for a (possibly absent) genesis hash, falling
/// back to "Unknown". `validate` guarantees the hash is present on an
/// accepted transaction, so the `None` arm is only defensive.
pub fn network_label(genesis_hash: Option<&[u8; 32]>) -> &'static str {
    match genesis_hash {
        Some(gh) => network_name(gh).unwrap_or("Unknown"),
        None => "Unknown",
    }
}

/// Format a validity window as "<first>+<rounds>": the first-valid round
/// followed by the number of rounds it stays valid. Shared by the single
/// transaction screen and the atomic-group overview so the two read
/// identically; for a group `start`/`end` are the highest first-valid and
/// lowest last-valid rounds, i.e. where every member is simultaneously
/// valid.
/// Buffer length for `format_validity` output (`<first>+<rounds>`): two
/// u64 decimals plus the separator.
pub const VALIDITY_LEN: usize = 2 * strutil::U64_LEN + 1;

pub fn format_validity(start: u64, end: u64, buf: &mut [u8; VALIDITY_LEN]) -> &str {
    uformat!(buf, "{}+{}", start, end.saturating_sub(start))
}

/// Render a transaction's review screen as a property list and ask the
/// user to accept it.
///
/// The single shared exit point for every `confirm_*` screen: it takes
/// the type-specific `props`, appends the common header fields — network
/// and validity window (single transactions only; an atomic group shows
/// both once in its overview), note, lease — and shows a tap-through
/// (`total > 1`) or hold-to-sign (`total == 1`) confirmation. Adding a
/// header field here adds it for every transaction type at once. Property
/// keys render in a small label font and values on their own line(s);
/// `mono` selects the data style used for addresses, hashes and ids.
pub fn finalize(
    title: &str,
    props: &[Property<'_>],
    br_name: &str,
    txn: &Transaction<'_>,
    total: usize,
    ctx: ReviewCtx,
) -> Result<()> {
    // Network and validity belong to the group overview for a group; for a
    // single transaction they live here instead, in the same format.
    let single = total == 1;
    let mut validity_buf = [0u8; VALIDITY_LEN];
    let validity: Option<&str> = if single {
        Some(format_validity(txn.first_valid(), txn.last_valid(), &mut validity_buf))
    } else {
        None
    };
    let mut note_buf = [0u8; strutil::LABEL_LEN];
    let note: Option<&str> = match txn.note() {
        Some(n) => Some(uformat!(&mut note_buf, "{} bytes", n.len())),
        None => None,
    };
    // Render the rekey-auth address into a buffer owned by this scope so it
    // can be borrowed into the property list below.
    let mut auth_buf = [0u8; ADDRESS_LEN];
    let auth = ctx.auth.map(|a| address_to_str(&a, &mut auth_buf));

    // Collect the type-specific props followed by the common header fields
    // into one fixed-capacity list. The type-specific values outlive this
    // call; the common-field values are borrowed from locals above.
    let mut all = PropVec::<MAX_FINALIZE_PROPS>::new();
    for p in props {
        all.push(Property::new(p.key.as_str(), p.value.as_str(), p.mono));
    }
    // Flag a group member this device is *not* signing, so it reads as
    // context rather than something the user is authorising here.
    if !ctx.signing {
        all.push(Property::new("Signed here", "No", false));
    }
    // The account whose key authorises this transaction, when it isn't the
    // sender (a rekeyed account signing through us).
    if let Some(auth) = auth {
        all.push(Property::new("Auth address", auth, true));
    }
    if single {
        all.push(Property::new(
            "Network",
            network_label(txn.genesis_hash()),
            false,
        ));
    }
    if let Some(validity) = validity {
        all.push(Property::new("Validity", validity, false));
    }
    if let Some(note) = note {
        all.push(Property::new("Note", note, false));
    }
    if txn.lease().is_some() {
        all.push(Property::new("Lease", "set", false));
    }

    let (verb, hold) = if total > 1 {
        (Some("Continue"), false)
    } else {
        (Some("Sign"), true)
    };
    ui::error_if_not_confirmed(ui::confirm_properties(ui::ConfirmProperties::new(
        title,
        all.as_slice(),
        None,
        verb,
        hold,
        Some(br_name),
        ButtonRequestType::SignTx.into(),
    ))?)
}

/// Full-screen hold-to-confirm gate for a control- or balance-changing
/// field. Separate from the body so it interrupts the review rather than
/// reading as one more line the user taps past.
fn danger_gate(title: &str, body: &str, br_name: &str, verb: &str) -> Result<()> {
    ui::error_if_not_confirmed(ui::confirm_value(ui::ConfirmValue::new(
        title,
        body,
        None,
        Some(br_name),
        ButtonRequestType::SignTx.into(),
        true,
        Some(verb),
        None,
        false,
        true, // hold to confirm
        false,
        false,
        true, // cancellable
        false,
        None,
    ))?)
}

/// Surface the dangerous fields — rekey and close-out — as their own
/// gates before the type body. Rekey is a header field shared by every
/// type; close-out lives on the payment / asset-transfer body. Called
/// for every transaction, including each member of a group, so a rekey
/// or close-out hidden in one group member cannot ride along unseen.
pub fn run_danger_gates(txn: &Transaction<'_>) -> Result<()> {
    if let Some(rekey) = txn.rekey_to() {
        let mut buf = [0u8; ADDRESS_LEN];
        let mut body_buf = [0u8; DANGER_BODY_LEN];
        let body = uformat!(
            &mut body_buf,
            "This changes the signing key for the account.\n\nAfter signing, this address will control the account:\n{}\n\nYou may permanently lose access.",
            address_to_str(&rekey, &mut buf),
        );
        danger_gate("Rekey account", body, "confirm_rekey", "Allow rekey")?;
    }

    match txn.tx_type() {
        TransactionType::Payment => {
            if let Some(close) = txn.as_payment().and_then(|b| b.close_remainder_to()) {
                let mut buf = [0u8; ADDRESS_LEN];
                let mut body_buf = [0u8; DANGER_BODY_LEN];
                let body = uformat!(
                    &mut body_buf,
                    "The entire remaining balance will be sent to:\n{}\n\nand this account will be closed.",
                    address_to_str(&close, &mut buf),
                );
                danger_gate("Close account", body, "confirm_close", "Close account")?;
            }
        }
        TransactionType::AssetTransfer => {
            if let Some(close) = txn.as_asset_transfer().and_then(|b| b.close_to()) {
                let mut buf = [0u8; ADDRESS_LEN];
                let mut body_buf = [0u8; DANGER_BODY_LEN];
                let body = uformat!(
                    &mut body_buf,
                    "Your entire balance of this asset will be sent to:\n{}",
                    address_to_str(&close, &mut buf),
                );
                danger_gate("Close out asset", body, "confirm_close_asset", "Close out")?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Acknowledge an application call that carries data not rendered in full
/// (args, account/asset/app/box references, access list). The call body
/// shows counts and the transaction id; this gate makes the user accept
/// that the details are being blind-signed.
pub fn confirm_blind_signing() -> Result<()> {
    danger_gate(
        "Blind signing",
        "This app call includes arguments and references that are not fully shown on this device. Only continue if you trust the source.",
        "confirm_blind",
        "I understand",
    )
}

/// base64 of the transaction id, written into the caller-supplied buffer.
/// Lets an app-call screen bind blind-sign consent to the exact bytes.
pub fn txid_b64<'a>(txn: &Transaction<'_>, buf: &'a mut [u8; HASH_B64_LEN]) -> &'a str {
    let txid = txn.txid();
    let _ = base64::encode(&txid, buf);
    core::str::from_utf8(buf).expect("base64 is ASCII")
}
