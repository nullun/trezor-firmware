//! Application-call (`appl`) confirmation screen.

use tiny_algo::address::ENCODED_LEN as ADDRESS_LEN;
use tiny_algo::base64;
use tiny_algo::hash::sha512_256;
use tiny_algo::txn::{OnCompletion, Transaction};
use trezor_app_sdk::{Result, ui::Property};

use super::{address_to_str, common, format_microalgo, ALGO_FMT_LEN};
use crate::strutil::{self, PropVec};
use crate::uformat;

/// Base64-encoded length of a 32-byte SHA-512/256 digest. Matches the
/// hash shown by `goal app info` and other Algorand tooling.
const HASH_B64_LEN: usize = base64::encoded_len(32); // 44

/// Render the SHA-512/256 of a program into the caller-supplied buffer
/// and return the ASCII view. Identifies *which* TEAL the user is being
/// asked to authorise; without it the screen only shows a byte count.
fn program_hash_str<'a>(program: &[u8], buf: &'a mut [u8; HASH_B64_LEN]) -> &'a str {
    let digest = sha512_256(program);
    let _ = base64::encode(&digest, buf);
    core::str::from_utf8(buf).expect("base64 output is ASCII")
}

fn oc_label(oc: OnCompletion) -> &'static str {
    match oc {
        OnCompletion::NoOp => "NoOp",
        OnCompletion::OptIn => "OptIn",
        OnCompletion::CloseOut => "CloseOut",
        OnCompletion::ClearState => "ClearState",
        OnCompletion::UpdateApp => "UpdateApp",
        OnCompletion::DeleteApp => "DeleteApp",
    }
}

/// Render a single application-call transaction summary and ask the user
/// to confirm.
pub fn confirm_application(
    txn: &Transaction<'_>,
    index: usize,
    total: usize,
    ctx: common::ReviewCtx,
) -> Result<()> {
    let body = txn
        .as_application()
        .expect("validate ensures Application body");

    let sender = txn.sender().expect("validate rejects missing sender");
    let fee = txn.fee();

    let app_id = body.application_id();
    let oc = body.on_completion();
    let is_create = app_id == 0;

    let is_group = total > 1;
    let (prefix, solo_title) = if is_create {
        ("App create", "Confirm app create")
    } else {
        ("App call", "Confirm app call")
    };
    let mut title_buf = [0u8; strutil::LABEL_LEN];
    let title: &str = if is_group {
        uformat!(&mut title_buf, "{} {} of {}", prefix, index + 1, total)
    } else {
        solo_title
    };

    let mut app_id_buf = [0u8; strutil::U64_LEN];
    let app_id_str = uformat!(&mut app_id_buf, "{}", app_id);
    let mut fee_buf = [0u8; ALGO_FMT_LEN];
    let fee_str = format_microalgo(fee, &mut fee_buf);
    let mut from_buf = [0u8; ADDRESS_LEN];
    let from = address_to_str(&sender, &mut from_buf);

    // Create-only program metadata, formatted into locals so the props
    // below can borrow them.
    let approval = body.approval_program();
    let clear = body.clear_program();
    let mut approval_hash_buf = [0u8; HASH_B64_LEN];
    let mut clear_hash_buf = [0u8; HASH_B64_LEN];
    let mut approval_len_buf = [0u8; strutil::LABEL_LEN];
    let mut clear_len_buf = [0u8; strutil::LABEL_LEN];
    let approval_len: Option<&str> = match approval {
        Some(ap) => Some(uformat!(&mut approval_len_buf, "{} bytes", ap.len())),
        None => None,
    };
    let clear_len: Option<&str> = match clear {
        Some(cp) => Some(uformat!(&mut clear_len_buf, "{} bytes", cp.len())),
        None => None,
    };
    let approval_hash = approval.map(|ap| program_hash_str(ap, &mut approval_hash_buf));
    let clear_hash = clear.map(|cp| program_hash_str(cp, &mut clear_hash_buf));
    let schema = match (
        body.local_schema_raw().is_some(),
        body.global_schema_raw().is_some(),
    ) {
        (true, true) => Some("local global"),
        (true, false) => Some("local"),
        (false, true) => Some("global"),
        (false, false) => None,
    };
    let extra = body.extra_program_pages();
    let mut extra_buf = [0u8; strutil::U64_LEN];
    let extra_str: Option<&str> = if extra != 0 {
        Some(uformat!(&mut extra_buf, "{}", extra))
    } else {
        None
    };

    // Args and resource references define what the call actually does but
    // are not rendered in full. Surface counts and the transaction id so
    // consent binds to the exact bytes, then gate on an explicit
    // blind-signing acknowledgement.
    let n_args = body.args().ok().flatten().map(|it| it.count()).unwrap_or(0);
    let n_accounts = body.accounts().ok().flatten().map(|it| it.count()).unwrap_or(0);
    let has_foreign = body.foreign_apps_raw().is_some() || body.foreign_assets_raw().is_some();
    let has_boxes = body.boxes_raw().is_some();
    let has_access = body.access_raw().is_some();
    let blind = n_args > 0 || n_accounts > 0 || has_foreign || has_boxes || has_access;
    let mut args_buf = [0u8; strutil::U64_LEN];
    let mut accounts_buf = [0u8; strutil::U64_LEN];
    let args_str = uformat!(&mut args_buf, "{}", n_args);
    let accounts_str = uformat!(&mut accounts_buf, "{}", n_accounts);
    let mut txid_buf = [0u8; common::HASH_B64_LEN];
    let txid = common::txid_b64(txn, &mut txid_buf);

    let reject_version = body.reject_version();
    let mut reject_version_buf = [0u8; strutil::U64_LEN];
    let reject_version_str: Option<&str> = if reject_version != 0 {
        Some(uformat!(&mut reject_version_buf, "{}", reject_version))
    } else {
        None
    };

    let mut props = PropVec::<16>::new();
    if !is_create {
        props.push(Property::new("App ID", app_id_str, false));
    }
    props.push(Property::new("On completion", oc_label(oc), false));
    props.push(Property::new("Fee", fee_str, false));
    props.push(Property::new("From", from, true));

    if is_create {
        if let Some(len) = approval_len {
            props.push(Property::new("Approval program", len, false));
        }
        if let Some(h) = approval_hash {
            props.push(Property::new("Approval hash", h, true));
        }
        if let Some(len) = clear_len {
            props.push(Property::new("Clear program", len, false));
        }
        if let Some(h) = clear_hash {
            props.push(Property::new("Clear hash", h, true));
        }
        if let Some(s) = schema {
            props.push(Property::new("State schema", s, false));
        }
        if let Some(e) = extra_str {
            props.push(Property::new("Extra pages", e, false));
        }
    }

    if blind {
        props.push(Property::new("Args", args_str, false));
        props.push(Property::new("Accounts", accounts_str, false));
        if has_foreign {
            props.push(Property::new("Foreign apps/assets", "yes", false));
        }
        if has_boxes {
            props.push(Property::new("Box refs", "yes", false));
        }
        if has_access {
            props.push(Property::new("Access list", "yes", false));
        }
        props.push(Property::new("TxID", txid, true));
    }
    if let Some(rv) = reject_version_str {
        props.push(Property::new("Reject version", rv, false));
    }

    if blind {
        common::confirm_blind_signing()?;
    }

    common::finalize(title, props.as_slice(), "confirm_application", txn, total, ctx)
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use tiny_algo::txn::application::{ApplicationCallBuilder, OnCompletion};
    use tiny_algo::txn::{Transaction, TransactionType};
    use tiny_algo::validate::validate;

    fn static_refs() -> ([u8; 32], [u8; 32]) {
        ([1u8; 32], [3u8; 32])
    }

    fn build(b: &ApplicationCallBuilder<'_>) -> Vec<u8> {
        let mut buf = [0u8; 8192];
        let n = b.write_into(&mut buf).unwrap();
        buf[..n].to_vec()
    }

    #[test]
    fn create_app_parses_and_validates() {
        let (snd, gh) = static_refs();
        let approval = b"#pragma version 10";
        let clear = b"#pragma version 10\nint 1";
        let b = ApplicationCallBuilder {
            sender: &snd,
            fee: 1000,
            first_valid: 100,
            last_valid: 1100,
            genesis_hash: &gh,
            genesis_id: None,
            note: None,
            group: None,
            lease: None,
            rekey_to: None,
            application_id: 0,
            on_completion: OnCompletion::NoOp,
            args: &[],
            accounts: &[],
            foreign_assets: &[],
            foreign_apps: &[],
            approval_program: Some(approval),
            clear_program: Some(clear),
            local_schema: Some((1, 2)),
            global_schema: Some((3, 4)),
            extra_program_pages: 0,
            reject_version: 0,
            access: None,
            boxes: None,
        };
        let buf = build(&b);
        let txn = Transaction::parse(&buf).unwrap();
        assert_eq!(txn.tx_type(), TransactionType::Application);
        let body = txn.as_application().unwrap();
        assert_eq!(body.application_id(), 0);
        assert_eq!(body.on_completion(), OnCompletion::NoOp);
        assert!(body.approval_program().is_some());
        assert!(body.clear_program().is_some());
        assert!(validate(&txn).is_ok());
    }

    #[test]
    fn create_without_approval_rejected() {
        let (snd, gh) = static_refs();
        let clear = b"int 1";
        let b = ApplicationCallBuilder {
            sender: &snd,
            fee: 1000,
            first_valid: 100,
            last_valid: 1100,
            genesis_hash: &gh,
            genesis_id: None,
            note: None,
            group: None,
            lease: None,
            rekey_to: None,
            application_id: 0,
            on_completion: OnCompletion::NoOp,
            args: &[],
            accounts: &[],
            foreign_assets: &[],
            foreign_apps: &[],
            approval_program: None, // missing
            clear_program: Some(clear),
            local_schema: None,
            global_schema: None,
            extra_program_pages: 0,
            reject_version: 0,
            access: None,
            boxes: None,
        };
        let buf = build(&b);
        let txn = Transaction::parse(&buf).unwrap();
        assert!(validate(&txn).is_err());
    }

    #[test]
    fn call_parses_and_validates() {
        let (snd, gh) = static_refs();
        let b = ApplicationCallBuilder {
            sender: &snd,
            fee: 1000,
            first_valid: 100,
            last_valid: 1100,
            genesis_hash: &gh,
            genesis_id: None,
            note: None,
            group: None,
            lease: None,
            rekey_to: None,
            application_id: 42,
            on_completion: OnCompletion::OptIn,
            args: &[],
            accounts: &[],
            foreign_assets: &[],
            foreign_apps: &[],
            approval_program: None,
            clear_program: None,
            local_schema: None,
            global_schema: None,
            extra_program_pages: 0,
            reject_version: 0,
            access: None,
            boxes: None,
        };
        let buf = build(&b);
        let txn = Transaction::parse(&buf).unwrap();
        let body = txn.as_application().unwrap();
        assert_eq!(body.application_id(), 42);
        assert_eq!(body.on_completion(), OnCompletion::OptIn);
        assert!(validate(&txn).is_ok());
    }

    #[test]
    fn delete_app_parses() {
        let (snd, gh) = static_refs();
        let b = ApplicationCallBuilder {
            sender: &snd,
            fee: 1000,
            first_valid: 100,
            last_valid: 1100,
            genesis_hash: &gh,
            genesis_id: None,
            note: None,
            group: None,
            lease: None,
            rekey_to: None,
            application_id: 7,
            on_completion: OnCompletion::DeleteApp,
            args: &[],
            accounts: &[],
            foreign_assets: &[],
            foreign_apps: &[],
            approval_program: None,
            clear_program: None,
            local_schema: None,
            global_schema: None,
            extra_program_pages: 0,
            reject_version: 0,
            access: None,
            boxes: None,
        };
        let buf = build(&b);
        let txn = Transaction::parse(&buf).unwrap();
        let body = txn.as_application().unwrap();
        assert_eq!(body.on_completion(), OnCompletion::DeleteApp);
        assert!(validate(&txn).is_ok());
    }
}
