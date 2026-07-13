//! Payment (`pay`) confirmation screen.

use tiny_algo::address::{Address, ENCODED_LEN as ADDRESS_LEN};
use tiny_algo::txn::Transaction;
use trezor_app_sdk::{Result, ui::Property};

use super::{address_to_str, common, format_microalgo, ALGO_FMT_LEN};
use crate::strutil;
use crate::uformat;

/// Render a single payment transaction summary and ask the user to confirm.
///
/// For a single-transaction request (`total == 1`) this is also the sign
/// commitment — `hold = true`, `verb = "Sign"`. For atomic groups it's
/// a tap-through review screen (`hold = false`, `verb = "Continue"`),
/// and the actual sign commitment happens once on `confirm_sign_all`
/// after every member has been reviewed.
pub fn confirm_payment(
    txn: &Transaction<'_>,
    index: usize,
    total: usize,
    ctx: common::ReviewCtx,
) -> Result<()> {
    let body = txn.as_payment().expect("validate ensures Payment body");

    let sender = txn.sender().expect("validate rejects missing sender");
    let receiver = body.receiver().unwrap_or(Address::ZERO);
    let amount = body.amount();
    let fee = txn.fee();

    let mut title_buf = [0u8; strutil::LABEL_LEN];
    let title: &str = if total > 1 {
        uformat!(&mut title_buf, "Payment {} of {}", index + 1, total)
    } else {
        "Confirm payment"
    };
    let mut amount_buf = [0u8; ALGO_FMT_LEN];
    let mut fee_buf = [0u8; ALGO_FMT_LEN];
    let amount_str = format_microalgo(amount, &mut amount_buf);
    let fee_str = format_microalgo(fee, &mut fee_buf);
    let mut from_buf = [0u8; ADDRESS_LEN];
    let mut to_buf = [0u8; ADDRESS_LEN];
    let from = address_to_str(&sender, &mut from_buf);
    let to = address_to_str(&receiver, &mut to_buf);

    // Close-remainder-to empties the account; it is shown as a dedicated
    // danger gate in `common::run_danger_gates`, not as a field here.
    let props = [
        Property::new("Amount", amount_str, false),
        Property::new("Fee", fee_str, false),
        Property::new("From", from, true),
        Property::new("To", to, true),
    ];
    common::finalize(title, &props, "confirm_payment", txn, total, ctx)
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use tiny_algo::txn::payment::PaymentBuilder;
    use tiny_algo::txn::{Transaction, TransactionType};
    use tiny_algo::validate::{validate, MAX_NOTE_LEN};

    fn static_refs() -> ([u8; 32], [u8; 32], [u8; 32]) {
        ([1u8; 32], [2u8; 32], [3u8; 32])
    }

    fn build(b: &PaymentBuilder<'_>) -> Vec<u8> {
        // 8 KiB: ample for a max-size note plus msgpack overhead.
        let mut buf = [0u8; 8192];
        let n = b.write_into(&mut buf).unwrap();
        buf[..n].to_vec()
    }

    fn base_pay<'a>(
        snd: &'a [u8; 32],
        rcv: &'a [u8; 32],
        gh: &'a [u8; 32],
    ) -> PaymentBuilder<'a> {
        PaymentBuilder {
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
            receiver: rcv,
            amount: 1_000,
            close_remainder_to: None,
        }
    }

    #[test]
    fn basic_payment_parses_and_validates() {
        let (snd, rcv, gh) = static_refs();
        let b = base_pay(&snd, &rcv, &gh);
        let buf = build(&b);
        let txn = Transaction::parse(&buf).unwrap();
        assert_eq!(txn.tx_type(), TransactionType::Payment);
        let body = txn.as_payment().unwrap();
        assert_eq!(body.amount(), 1_000);
        assert!(body.receiver().is_some());
        assert!(body.close_remainder_to().is_none());
        assert!(validate(&txn).is_ok());
    }

    #[test]
    fn close_remainder_payment_parses() {
        let (snd, rcv, gh) = static_refs();
        let close = [5u8; 32];
        let mut b = base_pay(&snd, &rcv, &gh);
        b.close_remainder_to = Some(&close);
        let buf = build(&b);
        let txn = Transaction::parse(&buf).unwrap();
        let body = txn.as_payment().unwrap();
        assert!(body.close_remainder_to().is_some());
        assert!(validate(&txn).is_ok());
    }

    #[test]
    fn close_only_payment_valid() {
        // close-only (no rcv) is a valid "close out account" form.
        let (snd, _rcv, gh) = static_refs();
        let close = [5u8; 32];
        let zero = [0u8; 32];
        let b = PaymentBuilder {
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
            receiver: &zero, // zero address = omitempty on wire
            amount: 0,
            close_remainder_to: Some(&close),
        };
        let buf = build(&b);
        let txn = Transaction::parse(&buf).unwrap();
        let body = txn.as_payment().unwrap();
        assert!(body.close_remainder_to().is_some());
        assert!(validate(&txn).is_ok());
    }

    #[test]
    fn zero_sender_rejected() {
        let zero = [0u8; 32];
        let (_, rcv, gh) = static_refs();
        let b = base_pay(&zero, &rcv, &gh);
        let buf = build(&b);
        let txn = Transaction::parse(&buf).unwrap();
        assert!(validate(&txn).is_err());
    }

    #[test]
    fn validity_window_too_long_rejected() {
        let (snd, rcv, gh) = static_refs();
        let mut b = base_pay(&snd, &rcv, &gh);
        b.first_valid = 100;
        b.last_valid = 1102; // window = 1002 > 1000
        let buf = build(&b);
        let txn = Transaction::parse(&buf).unwrap();
        assert!(validate(&txn).is_err());
    }

    #[test]
    fn fv_greater_than_lv_rejected() {
        let (snd, rcv, gh) = static_refs();
        let mut b = base_pay(&snd, &rcv, &gh);
        b.first_valid = 600;
        b.last_valid = 500;
        let buf = build(&b);
        let txn = Transaction::parse(&buf).unwrap();
        assert!(validate(&txn).is_err());
    }

    #[test]
    fn note_too_large_rejected() {
        let (snd, rcv, gh) = static_refs();
        let mut b = base_pay(&snd, &rcv, &gh);
        b.note = Some(&[0u8; MAX_NOTE_LEN + 1]);
        let mut buf = [0u8; 8192];
        let n = b.write_into(&mut buf).unwrap();
        let vec = buf[..n].to_vec();
        let txn = Transaction::parse(&vec).unwrap();
        assert!(validate(&txn).is_err());
    }

    #[test]
    fn note_at_limit_passes() {
        let (snd, rcv, gh) = static_refs();
        let mut b = base_pay(&snd, &rcv, &gh);
        b.note = Some(&[0u8; MAX_NOTE_LEN]);
        let mut buf = [0u8; 8192];
        let n = b.write_into(&mut buf).unwrap();
        let vec = buf[..n].to_vec();
        let txn = Transaction::parse(&vec).unwrap();
        assert!(validate(&txn).is_ok());
    }
}
