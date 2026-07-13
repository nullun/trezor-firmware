//! Asset-transfer (`axfer`) confirmation screen.

use tiny_algo::address::ENCODED_LEN as ADDRESS_LEN;
use tiny_algo::txn::Transaction;
use trezor_app_sdk::{Result, ui::Property};

use super::{address_to_str, common, format_microalgo, ALGO_FMT_LEN};
use crate::strutil::{self, PropVec};
use crate::uformat;

/// Render a single asset-transfer transaction summary and ask the user
/// to confirm.
pub fn confirm_asset_transfer(
    txn: &Transaction<'_>,
    index: usize,
    total: usize,
    ctx: common::ReviewCtx,
) -> Result<()> {
    let body = txn
        .as_asset_transfer()
        .expect("validate ensures AssetTransfer body");

    let sender = txn.sender().expect("validate rejects missing sender");
    let fee = txn.fee();

    let asset_id = body.xfer_asset();
    let amount = body.amount();
    let asset_sender = body.asset_sender();
    let receiver = body.receiver();

    let mut title_buf = [0u8; strutil::LABEL_LEN];
    let title: &str = if total > 1 {
        uformat!(&mut title_buf, "Asset xfer {} of {}", index + 1, total)
    } else {
        "Confirm asset transfer"
    };

    let mut asset_id_buf = [0u8; strutil::U64_LEN];
    let mut amount_buf = [0u8; strutil::U64_LEN];
    let asset_id_str = uformat!(&mut asset_id_buf, "{}", asset_id);
    let amount_str = uformat!(&mut amount_buf, "{}", amount);
    let mut fee_buf = [0u8; ALGO_FMT_LEN];
    let fee_str = format_microalgo(fee, &mut fee_buf);
    let mut from_buf = [0u8; ADDRESS_LEN];
    let from = address_to_str(&sender, &mut from_buf);
    let mut to_buf = [0u8; ADDRESS_LEN];
    let mut asnd_buf = [0u8; ADDRESS_LEN];

    let mut props = PropVec::<6>::new();
    props.push(Property::new("Asset ID", asset_id_str, false));
    props.push(Property::new("Amount", amount_str, false));
    props.push(Property::new("Fee", fee_str, false));
    props.push(Property::new("From", from, true));
    if let Some(rcv) = receiver {
        props.push(Property::new("To", address_to_str(&rcv, &mut to_buf), true));
    }
    if let Some(asnd) = asset_sender {
        props.push(Property::new(
            "Clawback from",
            address_to_str(&asnd, &mut asnd_buf),
            true,
        ));
    }

    // Close-to empties the asset holding; shown as a dedicated danger gate
    // in `common::run_danger_gates`, not as a field here.
    common::finalize(title, props.as_slice(), "confirm_asset_transfer", txn, total, ctx)
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use tiny_algo::txn::asset_transfer::AssetTransferBuilder;
    use tiny_algo::txn::{Transaction, TransactionType};
    use tiny_algo::validate::validate;

    fn static_refs() -> ([u8; 32], [u8; 32], [u8; 32]) {
        ([1u8; 32], [2u8; 32], [3u8; 32])
    }

    fn build(b: &AssetTransferBuilder<'_>) -> Vec<u8> {
        let mut buf = [0u8; 8192];
        let n = b.write_into(&mut buf).unwrap();
        buf[..n].to_vec()
    }

    fn base_builder<'a>(
        snd: &'a [u8; 32],
        rcv: &'a [u8; 32],
        gh: &'a [u8; 32],
    ) -> AssetTransferBuilder<'a> {
        AssetTransferBuilder {
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
            xfer_asset: 42,
            amount: 99,
            asset_sender: None,
            receiver: rcv,
            close_to: None,
        }
    }

    #[test]
    fn basic_transfer_parses_and_validates() {
        let (snd, rcv, gh) = static_refs();
        let b = base_builder(&snd, &rcv, &gh);
        let buf = build(&b);
        let txn = Transaction::parse(&buf).unwrap();
        assert_eq!(txn.tx_type(), TransactionType::AssetTransfer);
        let body = txn.as_asset_transfer().unwrap();
        assert_eq!(body.xfer_asset(), 42);
        assert_eq!(body.amount(), 99);
        assert!(body.receiver().is_some());
        assert!(body.asset_sender().is_none());
        assert!(validate(&txn).is_ok());
    }

    #[test]
    fn clawback_parses() {
        let (snd, rcv, gh) = static_refs();
        let clawback = [5u8; 32];
        let mut b = base_builder(&snd, &rcv, &gh);
        b.asset_sender = Some(&clawback);
        let buf = build(&b);
        let txn = Transaction::parse(&buf).unwrap();
        let body = txn.as_asset_transfer().unwrap();
        assert!(body.asset_sender().is_some());
    }

    #[test]
    fn clawback_with_close_rejected() {
        // aclose + asnd together is forbidden (clawback close-out).
        let (snd, rcv, gh) = static_refs();
        let clawback = [5u8; 32];
        let close = [6u8; 32];
        let mut b = base_builder(&snd, &rcv, &gh);
        b.asset_sender = Some(&clawback);
        b.close_to = Some(&close);
        let buf = build(&b);
        let txn = Transaction::parse(&buf).unwrap();
        assert!(validate(&txn).is_err());
    }

    #[test]
    fn zero_asset_id_with_amount_rejected() {
        let (snd, rcv, gh) = static_refs();
        let mut b = base_builder(&snd, &rcv, &gh);
        b.xfer_asset = 0;
        // amount is 99 (nonzero) but xaid is 0 → reject.
        let buf = build(&b);
        let txn = Transaction::parse(&buf).unwrap();
        assert!(validate(&txn).is_err());
    }

    #[test]
    fn zero_asset_id_zero_amount_valid() {
        // xaid=0 + aamt=0 is allowed (no-op asset ref).
        let (snd, rcv, gh) = static_refs();
        let mut b = base_builder(&snd, &rcv, &gh);
        b.xfer_asset = 0;
        b.amount = 0;
        let buf = build(&b);
        let txn = Transaction::parse(&buf).unwrap();
        assert!(validate(&txn).is_ok());
    }
}
