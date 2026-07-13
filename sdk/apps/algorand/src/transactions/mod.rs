//! Per-transaction-type screens.
//!
//! Each sub-module exposes a single `confirm_*` function that renders
//! the transaction details and asks the user to accept (tap-through for
//! group members, hold-to-sign for singletons). The group header and
//! final sign-commitment screens live here as well.

pub mod application;
pub mod asset_config;
pub mod asset_freeze;
pub mod asset_transfer;
pub mod common;
pub mod keyreg;
pub mod payment;

pub use application::confirm_application;
pub use asset_config::confirm_asset_config;
pub use asset_freeze::confirm_asset_freeze;
pub use asset_transfer::confirm_asset_transfer;
pub use keyreg::confirm_keyreg;
pub use payment::confirm_payment;

use tiny_algo::address::{Address, ENCODED_LEN as ADDRESS_LEN};
use tiny_algo::base64;
use trezor_app_sdk::{Error, Result, ui, ui::Property, unwrap};

use crate::button_request::ButtonRequestType;
use crate::strutil;
use crate::uformat;

/// Encode an [`Address`] into the caller-provided `buf` and return a
/// `&str` view over it. base32 only emits ASCII, so the conversion is
/// infallible.
pub fn address_to_str<'a>(addr: &Address, buf: &'a mut [u8; ADDRESS_LEN]) -> &'a str {
    addr.encode(buf);
    core::str::from_utf8(buf).expect("base32 output is ASCII")
}

/// Maximum byte length of the `format_microalgo` output: 20 digits for a
/// u64 worth of whole ALGO + 1 dot + 6 fractional + " ALGO" = 32.
pub const ALGO_FMT_LEN: usize = 32;

/// Format microAlgos as "X.YYY ALGO" with trailing-zero trimming, into
/// the caller-supplied `buf`. Returning a `&str` view avoids the per-
/// call `String` allocation.
pub fn format_microalgo(microalgo: u64, buf: &mut [u8; ALGO_FMT_LEN]) -> &str {
    use ufmt::uwrite;
    let mut w = strutil::BufWriter::new(buf);
    let whole = microalgo / 1_000_000;
    let frac = (microalgo % 1_000_000) as u32;
    if frac == 0 {
        unwrap!(uwrite!(w, "{} ALGO", whole));
    } else {
        let mut digits = [b'0'; 6];
        let mut v = frac;
        for i in (0..6).rev() {
            digits[i] = b'0' + (v % 10) as u8;
            v /= 10;
        }
        let end = digits.iter().rposition(|&b| b != b'0').unwrap_or(0) + 1;
        let trimmed = core::str::from_utf8(&digits[..end]).expect("ascii digits");
        unwrap!(uwrite!(w, "{}.{} ALGO", whole, trimmed));
    }
    w.into_str()
}

// --- Group-level screens -------------------------------------------

/// 32 bytes → 44 base64 chars — matches the canonical Algorand group-ID
/// display (`MOcd…FXA=`).
const GROUP_ID_B64_LEN: usize = base64::encoded_len(32);

/// Render the atomic-group overview shown once before the per-transaction
/// confirmations: network, the group-wide validity window, and the group
/// id. The caller has enforced a single network across the group and
/// derived the window — `window_start` is the highest first-valid round
/// and `window_end` the lowest last-valid round, i.e. the range in which
/// every member is simultaneously valid.
pub fn confirm_group_header(
    n: usize,
    group_id: &[u8; 32],
    genesis_hash: Option<&[u8; 32]>,
    window_start: u64,
    window_end: u64,
) -> Result<()> {
    let mut buf = [0u8; GROUP_ID_B64_LEN];
    let written = base64::encode(group_id, &mut buf)
        .map_err(|_| Error::DataError("Failed to encode group ID"))?;
    debug_assert_eq!(written, GROUP_ID_B64_LEN);
    let gid_b64 = core::str::from_utf8(&buf).expect("base64 output is ASCII");

    let mut title_buf = [0u8; strutil::LABEL_LEN];
    let title = uformat!(&mut title_buf, "Atomic group of {}", n);
    // `window_start` is the highest first-valid and `window_end` the lowest
    // last-valid across the group. If the former exceeds the latter there's
    // no round in which every member is simultaneously valid, so the group
    // can never commit — surface that rather than a misleading "+0" window.
    let mut validity_buf = [0u8; common::VALIDITY_LEN];
    let validity: &str = if window_end < window_start {
        "Invalid"
    } else {
        common::format_validity(window_start, window_end, &mut validity_buf)
    };

    let props = [
        Property::new("Network", common::network_label(genesis_hash), false),
        Property::new("Validity", validity, false),
        Property::new("Group ID", gid_b64, true),
    ];
    ui::error_if_not_confirmed(ui::confirm_properties(ui::ConfirmProperties::new(
        title,
        &props,
        None,
        Some("Continue"),
        false,
        Some("confirm_group"),
        ButtonRequestType::SignTx.into(),
    ))?)
}

/// Final hold-to-sign commitment shown after every member of an atomic
/// group has been reviewed. One gesture authorises signing the device's
/// share of the batch — `signed` of the `total` members (they're equal
/// unless the host requested a subset via `sign_indices`).
pub fn confirm_sign_all(signed: usize, total: usize) -> Result<()> {
    let mut body_buf = [0u8; 128];
    let body: &str = if signed == total {
        uformat!(
            &mut body_buf,
            "Sign all {} transactions in this atomic group?\n\nHold to confirm.",
            total
        )
    } else {
        uformat!(
            &mut body_buf,
            "Sign {} of {} transactions in this atomic group?\n\nHold to confirm.",
            signed,
            total
        )
    };
    ui::error_if_not_confirmed(ui::confirm_value(ui::ConfirmValue::new(
        "Sign atomic group",
        body,
        None,
        Some("sign_all"),
        ButtonRequestType::SignTx.into(),
        false,
        Some("Sign all"),
        None,
        false,
        true,
        false,
        false,
        true,
        false,
        None,
    ))?)
}
