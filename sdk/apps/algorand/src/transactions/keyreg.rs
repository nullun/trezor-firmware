//! Key-registration (`keyreg`) confirmation screen.

use tiny_algo::address::ENCODED_LEN as ADDRESS_LEN;
use tiny_algo::base64;
use tiny_algo::txn::Transaction;
use trezor_app_sdk::{Result, ui::Property};

use super::{address_to_str, common, format_microalgo, ALGO_FMT_LEN};
use crate::strutil;
use crate::uformat;

/// Base64-encoded length of a 32-byte key (e.g. vote / selection key).
const KEY32_B64_LEN: usize = base64::encoded_len(32); // 44
/// Base64-encoded length of a 64-byte state-proof key.
const KEY64_B64_LEN: usize = base64::encoded_len(64); // 88

/// Render a single key-registration transaction summary and ask the user
/// to confirm.
pub fn confirm_keyreg(
    txn: &Transaction<'_>,
    index: usize,
    total: usize,
    ctx: common::ReviewCtx,
) -> Result<()> {
    let body = txn.as_keyreg().expect("validate ensures Keyreg body");

    let sender = txn.sender().expect("validate rejects missing sender");
    let fee = txn.fee();

    let is_group = total > 1;
    let mut title_buf = [0u8; strutil::LABEL_LEN];
    let title: &str = if is_group {
        uformat!(&mut title_buf, "Key reg {} of {}", index + 1, total)
    } else {
        "Confirm key registration"
    };

    let nonpart = body.nonparticipation();

    let mut fee_buf = [0u8; ALGO_FMT_LEN];
    let fee_str = format_microalgo(fee, &mut fee_buf);
    let mut from_buf = [0u8; ADDRESS_LEN];
    let from = address_to_str(&sender, &mut from_buf);

    let vote_pk = body.vote_pk();

    if nonpart {
        let props = [
            Property::new("Status", "Offline (nonparticipating)", false),
            Property::new("Fee", fee_str, false),
            Property::new("From", from, true),
        ];
        common::finalize(title, &props, "confirm_keyreg", txn, total, ctx)
    } else if let Some(vpk) = vote_pk {
        // Online registration: all key fields guaranteed present by validate.
        let sel_pk = body.selection_pk().expect("validate ensures selection key");
        let sprf_pk = body.state_proof_pk().expect("validate ensures state-proof key");
        let mut vf_buf = [0u8; strutil::U64_LEN];
        let mut vl_buf = [0u8; strutil::U64_LEN];
        let mut vkd_buf = [0u8; strutil::U64_LEN];
        let vote_first = uformat!(&mut vf_buf, "{}", body.vote_first());
        let vote_last = uformat!(&mut vl_buf, "{}", body.vote_last());
        let vote_kd = uformat!(&mut vkd_buf, "{}", body.vote_key_dilution());

        let mut vk_buf = [0u8; KEY32_B64_LEN];
        let mut sk_buf = [0u8; KEY32_B64_LEN];
        let mut sp_buf = [0u8; KEY64_B64_LEN];
        let _ = base64::encode(vpk, &mut vk_buf);
        let _ = base64::encode(sel_pk, &mut sk_buf);
        let _ = base64::encode(sprf_pk, &mut sp_buf);
        let vk_str = core::str::from_utf8(&vk_buf).expect("base64 is ASCII");
        let sk_str = core::str::from_utf8(&sk_buf).expect("base64 is ASCII");
        let sp_str = core::str::from_utf8(&sp_buf).expect("base64 is ASCII");

        let props = [
            Property::new("Fee", fee_str, false),
            Property::new("From", from, true),
            Property::new("Vote key", vk_str, true),
            Property::new("Selection key", sk_str, true),
            Property::new("State proof key", sp_str, true),
            Property::new("Vote first", vote_first, false),
            Property::new("Vote last", vote_last, false),
            Property::new("Key dilution", vote_kd, false),
        ];
        common::finalize(title, &props, "confirm_keyreg", txn, total, ctx)
    } else {
        // Go offline (no keys, no nonpart flag).
        let props = [
            Property::new("Status", "Offline", false),
            Property::new("Fee", fee_str, false),
            Property::new("From", from, true),
        ];
        common::finalize(title, &props, "confirm_keyreg", txn, total, ctx)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use tiny_algo::txn::keyreg::KeyregBuilder;
    use tiny_algo::txn::{Transaction, TransactionType};
    use tiny_algo::validate::validate;

    fn static_refs() -> ([u8; 32], [u8; 32], [u8; 32], [u8; 64]) {
        ([1u8; 32], [2u8; 32], [3u8; 32], [0u8; 64])
    }

    fn build(b: &KeyregBuilder<'_>) -> Vec<u8> {
        let mut buf = [0u8; 8192];
        let n = b.write_into(&mut buf).unwrap();
        buf[..n].to_vec()
    }

    fn online_builder<'a>(
        snd: &'a [u8; 32],
        gh: &'a [u8; 32],
        vk: &'a [u8; 32],
        sk: &'a [u8; 32],
        spk: &'a [u8; 64],
    ) -> KeyregBuilder<'a> {
        KeyregBuilder {
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
            vote_pk: Some(vk),
            selection_pk: Some(sk),
            state_proof_pk: Some(spk),
            vote_first: 100,
            vote_last: 1100,
            vote_key_dilution: 10,
            nonparticipation: false,
        }
    }

    #[test]
    fn online_parses_and_validates() {
        let (snd, vk, gh, spk) = static_refs();
        let b = online_builder(&snd, &gh, &vk, &vk, &spk);
        let buf = build(&b);
        let txn = Transaction::parse(&buf).unwrap();
        assert_eq!(txn.tx_type(), TransactionType::KeyReg);
        let body = txn.as_keyreg().unwrap();
        assert!(body.vote_pk().is_some());
        assert!(body.selection_pk().is_some());
        assert!(body.state_proof_pk().is_some());
        assert_eq!(body.vote_first(), 100);
        assert_eq!(body.vote_last(), 1100);
        assert!(!body.nonparticipation());
        assert!(validate(&txn).is_ok());
    }

    #[test]
    fn two_keyreg_in_batch_parse() {
        let (snd, vk, gh, spk) = static_refs();
        let b = online_builder(&snd, &gh, &vk, &vk, &spk);
        let mut buf = [0u8; 2048];
        let n0 = b.write_into(&mut buf).unwrap();
        let n1 = b.write_into(&mut buf[n0..]).unwrap();
        let total = n0 + n1;
        let txns = tiny_algo::Transactions::parse(&buf[..total]).unwrap();
        assert_eq!(txns.len(), 2);
        // Group-level binding (grp fields) is covered by tiny-algo's own
        // test suite; here we just confirm multi-txn parsing.
        let t0 = txns.get(0).unwrap().unwrap();
        assert_eq!(t0.tx_type(), TransactionType::KeyReg);
        let t1 = txns.get(1).unwrap().unwrap();
        assert_eq!(t1.tx_type(), TransactionType::KeyReg);
    }

    #[test]
    fn nonpart_parses_and_validates() {
        let (snd, _vk, gh, _spk) = static_refs();
        let b = KeyregBuilder {
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
            vote_pk: None,
            selection_pk: None,
            state_proof_pk: None,
            vote_first: 0,
            vote_last: 0,
            vote_key_dilution: 0,
            nonparticipation: true,
        };
        let buf = build(&b);
        let txn = Transaction::parse(&buf).unwrap();
        let body = txn.as_keyreg().unwrap();
        assert!(body.nonparticipation());
        assert!(body.vote_pk().is_none());
        assert!(validate(&txn).is_ok());
    }

    #[test]
    fn go_offline_parses_and_validates() {
        let (snd, _vk, gh, _spk) = static_refs();
        let b = KeyregBuilder {
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
            vote_pk: None,
            selection_pk: None,
            state_proof_pk: None,
            vote_first: 0,
            vote_last: 0,
            vote_key_dilution: 0,
            nonparticipation: false,
        };
        let buf = build(&b);
        let txn = Transaction::parse(&buf).unwrap();
        let body = txn.as_keyreg().unwrap();
        assert!(!body.nonparticipation());
        assert!(body.vote_pk().is_none());
        assert!(validate(&txn).is_ok());
    }

    #[test]
    fn partial_keys_rejected() {
        let (snd, vk, gh, spk) = static_refs();
        let mut b = online_builder(&snd, &gh, &vk, &vk, &spk);
        b.selection_pk = None;
        let buf = build(&b);
        let txn = Transaction::parse(&buf).unwrap();
        assert!(validate(&txn).is_err());
    }

    #[test]
    fn nonpart_with_keys_rejected() {
        let (snd, vk, gh, spk) = static_refs();
        let mut b = online_builder(&snd, &gh, &vk, &vk, &spk);
        b.nonparticipation = true;
        let buf = build(&b);
        let txn = Transaction::parse(&buf).unwrap();
        assert!(validate(&txn).is_err());
    }

    #[test]
    fn vote_window_inverted_rejected() {
        let (snd, vk, gh, spk) = static_refs();
        let mut b = online_builder(&snd, &gh, &vk, &vk, &spk);
        b.vote_first = 500;
        b.vote_last = 100;
        let buf = build(&b);
        let txn = Transaction::parse(&buf).unwrap();
        assert!(validate(&txn).is_err());
    }
}
