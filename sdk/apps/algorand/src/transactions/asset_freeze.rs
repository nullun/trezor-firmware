//! Asset-freeze (`afrz`) confirmation screen.

use tiny_algo::address::ENCODED_LEN as ADDRESS_LEN;
use tiny_algo::txn::Transaction;
use trezor_app_sdk::{Result, ui::Property};

use super::{address_to_str, common, format_microalgo, ALGO_FMT_LEN};
use crate::strutil::{self, PropVec};
use crate::uformat;

/// Render a single asset-freeze transaction summary and ask the user
/// to confirm.
pub fn confirm_asset_freeze(
    txn: &Transaction<'_>,
    index: usize,
    total: usize,
    ctx: common::ReviewCtx,
) -> Result<()> {
    let body = txn
        .as_asset_freeze()
        .expect("validate ensures AssetFreeze body");

    let sender = txn.sender().expect("validate rejects missing sender");
    let fee = txn.fee();

    let freeze_account = body.freeze_account();
    let freeze_asset = body.freeze_asset();
    let frozen = body.frozen();

    let is_group = total > 1;
    let (action_word, lower) = if frozen {
        ("Freeze", "freeze")
    } else {
        ("Unfreeze", "unfreeze")
    };
    let mut title_buf = [0u8; strutil::LABEL_LEN];
    let title: &str = if is_group {
        uformat!(&mut title_buf, "{} {} of {}", action_word, index + 1, total)
    } else {
        uformat!(&mut title_buf, "Confirm {}", lower)
    };

    let mut asset_id_buf = [0u8; strutil::U64_LEN];
    let asset_id_str = uformat!(&mut asset_id_buf, "{}", freeze_asset);
    let mut fee_buf = [0u8; ALGO_FMT_LEN];
    let fee_str = format_microalgo(fee, &mut fee_buf);
    let mut from_buf = [0u8; ADDRESS_LEN];
    let from = address_to_str(&sender, &mut from_buf);
    let mut acct_buf = [0u8; ADDRESS_LEN];

    let mut props = PropVec::<4>::new();
    props.push(Property::new(tr!("algorand__asset_id"), asset_id_str, false));
    props.push(Property::new(tr!("algorand__fee"), fee_str, false));
    props.push(Property::new(tr!("algorand__from"), from, true));
    if let Some(acct) = freeze_account {
        let key = if frozen {
            tr!("algorand__freeze_account")
        } else {
            tr!("algorand__unfreeze_account")
        };
        props.push(Property::new(key, address_to_str(&acct, &mut acct_buf), true));
    }

    common::finalize(title, props.as_slice(), "confirm_asset_freeze", txn, total, ctx)
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use tiny_algo::txn::asset_freeze::AssetFreezeBuilder;
    use tiny_algo::txn::{Transaction, TransactionType};
    use tiny_algo::validate::validate;

    fn static_refs() -> ([u8; 32], [u8; 32], [u8; 32]) {
        ([1u8; 32], [2u8; 32], [3u8; 32])
    }

    fn build(b: &AssetFreezeBuilder<'_>) -> Vec<u8> {
        let mut buf = [0u8; 8192];
        let n = b.write_into(&mut buf).unwrap();
        buf[..n].to_vec()
    }

    fn base_builder<'a>(
        snd: &'a [u8; 32],
        fadd: &'a [u8; 32],
        gh: &'a [u8; 32],
    ) -> AssetFreezeBuilder<'a> {
        AssetFreezeBuilder {
            sender: snd,
            fee: 1000,
            first_valid: 100,
            last_valid: 1100,
            genesis_hash: gh,
            genesis_id: None,
            note: None,
            group: None,
            lease: None,
            rekey_to: None,
            freeze_account: fadd,
            freeze_asset: 7,
            frozen: true,
        }
    }

    #[test]
    fn freeze_parses_and_validates() {
        let (snd, fadd, gh) = static_refs();
        let b = base_builder(&snd, &fadd, &gh);
        let buf = build(&b);
        let txn = Transaction::parse(&buf).unwrap();
        assert_eq!(txn.tx_type(), TransactionType::AssetFreeze);
        let body = txn.as_asset_freeze().unwrap();
        assert_eq!(body.freeze_asset(), 7);
        assert!(body.frozen());
        assert!(body.freeze_account().is_some());
        assert!(validate(&txn).is_ok());
    }

    #[test]
    fn unfreeze_parses() {
        let (snd, fadd, gh) = static_refs();
        let mut b = base_builder(&snd, &fadd, &gh);
        b.frozen = false;
        let buf = build(&b);
        let txn = Transaction::parse(&buf).unwrap();
        let body = txn.as_asset_freeze().unwrap();
        // frozen=false → omitempty; the field is absent in msgpack.
        assert!(!body.frozen());
        assert!(validate(&txn).is_ok());
    }

    #[test]
    fn zero_asset_id_rejected() {
        let (snd, fadd, gh) = static_refs();
        let mut b = base_builder(&snd, &fadd, &gh);
        b.freeze_asset = 0;
        let buf = build(&b);
        let txn = Transaction::parse(&buf).unwrap();
        assert!(validate(&txn).is_err());
    }
}
