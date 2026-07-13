//! Asset-config (`acfg`) confirmation screen.

use tiny_algo::address::ENCODED_LEN as ADDRESS_LEN;
use tiny_algo::txn::Transaction;
use trezor_app_sdk::{Result, ui::Property};

use super::{address_to_str, common, format_microalgo, ALGO_FMT_LEN};
use crate::strutil::{self, PropVec};
use crate::uformat;

/// Render a single asset-config transaction summary and ask the user
/// to confirm.
pub fn confirm_asset_config(
    txn: &Transaction<'_>,
    index: usize,
    total: usize,
    ctx: common::ReviewCtx,
) -> Result<()> {
    let body = txn
        .as_asset_config()
        .expect("validate ensures AssetConfig body");

    let sender = txn.sender().expect("validate rejects missing sender");
    let fee = txn.fee();
    let caid = body.config_asset();
    let params = body.asset_params();

    let is_group = total > 1;

    let mut fee_buf = [0u8; ALGO_FMT_LEN];
    let fee_str = format_microalgo(fee, &mut fee_buf);
    let mut from_buf = [0u8; ADDRESS_LEN];
    let from = address_to_str(&sender, &mut from_buf);

    if caid == 0 {
        // Create asset.
        let mut title_buf = [0u8; strutil::LABEL_LEN];
        let title: &str = if is_group {
            uformat!(&mut title_buf, "Asset create {} of {}", index + 1, total)
        } else {
            "Confirm asset creation"
        };

        let mut mgr_buf = [0u8; ADDRESS_LEN];
        let mut rsv_buf = [0u8; ADDRESS_LEN];
        let mut frz_buf = [0u8; ADDRESS_LEN];
        let mut clw_buf = [0u8; ADDRESS_LEN];
        let mut total_buf = [0u8; strutil::U64_LEN];
        let mut decimals_buf = [0u8; strutil::U64_LEN];

        let mut props = PropVec::<12>::new();
        props.push(Property::new("Fee", fee_str, false));
        props.push(Property::new("From", from, true));
        if let Some(p) = params {
            if let Some(name) = p.asset_name() {
                props.push(Property::new(
                    "Name",
                    core::str::from_utf8(name).unwrap_or("<non-utf8>"),
                    false,
                ));
            }
            if let Some(un) = p.unit_name() {
                props.push(Property::new(
                    "Unit",
                    core::str::from_utf8(un).unwrap_or("<non-utf8>"),
                    false,
                ));
            }
            if p.total() != 0 {
                let total_str = uformat!(&mut total_buf, "{}", p.total());
                props.push(Property::new("Total", total_str, false));
            }
            if p.decimals() != 0 {
                let decimals_str = uformat!(&mut decimals_buf, "{}", p.decimals());
                props.push(Property::new("Decimals", decimals_str, false));
            }
            if p.default_frozen() {
                props.push(Property::new("Default frozen", "yes", false));
            }
            if let Some(url) = p.url() {
                props.push(Property::new(
                    "URL",
                    core::str::from_utf8(url).unwrap_or("<non-utf8>"),
                    false,
                ));
            }
            // Show every role, with "Empty" when absent. On create an empty
            // role is permanently disabled (e.g. no freeze/clawback); on
            // reconfigure omitting a role *removes* it irreversibly — either
            // way the user must see the gap, not have it silently hidden.
            if let Some(m) = p.manager() {
                props.push(Property::new("Manager", address_to_str(&m, &mut mgr_buf), true));
            } else {
                props.push(Property::new("Manager", "Empty", false));
            }
            if let Some(r) = p.reserve() {
                props.push(Property::new("Reserve", address_to_str(&r, &mut rsv_buf), true));
            } else {
                props.push(Property::new("Reserve", "Empty", false));
            }
            if let Some(f) = p.freeze() {
                props.push(Property::new("Freeze", address_to_str(&f, &mut frz_buf), true));
            } else {
                props.push(Property::new("Freeze", "Empty", false));
            }
            if let Some(c) = p.clawback() {
                props.push(Property::new("Clawback", address_to_str(&c, &mut clw_buf), true));
            } else {
                props.push(Property::new("Clawback", "Empty", false));
            }
        }

        common::finalize(title, props.as_slice(), "confirm_asset_config", txn, total, ctx)
    } else if params.is_some() {
        // Reconfigure asset.
        let mut title_buf = [0u8; strutil::LABEL_LEN];
        let title: &str = if is_group {
            uformat!(&mut title_buf, "Asset config {} of {}", index + 1, total)
        } else {
            "Confirm asset reconfiguration"
        };

        let mut caid_buf = [0u8; strutil::U64_LEN];
        let caid_str = uformat!(&mut caid_buf, "{}", caid);
        let mut mgr_buf = [0u8; ADDRESS_LEN];
        let mut rsv_buf = [0u8; ADDRESS_LEN];
        let mut frz_buf = [0u8; ADDRESS_LEN];
        let mut clw_buf = [0u8; ADDRESS_LEN];

        let mut props = PropVec::<7>::new();
        props.push(Property::new("Asset ID", caid_str, false));
        props.push(Property::new("Fee", fee_str, false));
        props.push(Property::new("From", from, true));
        if let Some(p) = params {
            // Show every role, with "Empty" when absent. On create an empty
            // role is permanently disabled (e.g. no freeze/clawback); on
            // reconfigure omitting a role *removes* it irreversibly — either
            // way the user must see the gap, not have it silently hidden.
            if let Some(m) = p.manager() {
                props.push(Property::new("Manager", address_to_str(&m, &mut mgr_buf), true));
            } else {
                props.push(Property::new("Manager", "Empty", false));
            }
            if let Some(r) = p.reserve() {
                props.push(Property::new("Reserve", address_to_str(&r, &mut rsv_buf), true));
            } else {
                props.push(Property::new("Reserve", "Empty", false));
            }
            if let Some(f) = p.freeze() {
                props.push(Property::new("Freeze", address_to_str(&f, &mut frz_buf), true));
            } else {
                props.push(Property::new("Freeze", "Empty", false));
            }
            if let Some(c) = p.clawback() {
                props.push(Property::new("Clawback", address_to_str(&c, &mut clw_buf), true));
            } else {
                props.push(Property::new("Clawback", "Empty", false));
            }
        }

        common::finalize(title, props.as_slice(), "confirm_asset_config", txn, total, ctx)
    } else {
        // Destroy asset.
        let mut title_buf = [0u8; strutil::LABEL_LEN];
        let title: &str = if is_group {
            uformat!(&mut title_buf, "Asset destroy {} of {}", index + 1, total)
        } else {
            "Confirm asset destruction"
        };

        let mut caid_buf = [0u8; strutil::U64_LEN];
        let caid_str = uformat!(&mut caid_buf, "{}", caid);
        let props = [
            Property::new("Destroy asset", caid_str, false),
            Property::new("Fee", fee_str, false),
            Property::new("From", from, true),
        ];

        common::finalize(title, &props, "confirm_asset_config", txn, total, ctx)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use tiny_algo::txn::asset_config::{AssetConfigBuilder, AssetParamsBuilder};
    use tiny_algo::txn::{Transaction, TransactionType};
    use tiny_algo::validate::validate;

    fn static_refs() -> ([u8; 32], [u8; 32]) {
        ([1u8; 32], [3u8; 32])
    }

    fn build(b: &AssetConfigBuilder<'_>) -> Vec<u8> {
        let mut buf = [0u8; 8192];
        let n = b.write_into(&mut buf).unwrap();
        buf[..n].to_vec()
    }

    #[test]
    fn create_asset_parses_and_validates() {
        let (snd, gh) = static_refs();
        let params = AssetParamsBuilder {
            total: 1_000_000,
            decimals: 6,
            asset_name: Some(b"TestCoin"),
            unit_name: Some(b"TST"),
            ..Default::default()
        };
        let b = AssetConfigBuilder {
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
            config_asset: 0, // create
            params: Some(&params),
        };
        let buf = build(&b);
        let txn = Transaction::parse(&buf).unwrap();
        assert_eq!(txn.tx_type(), TransactionType::AssetConfig);
        let body = txn.as_asset_config().unwrap();
        assert_eq!(body.config_asset(), 0);
        assert!(body.asset_params().is_some());
        assert!(validate(&txn).is_ok());
    }

    #[test]
    fn reconfigure_parses_and_validates() {
        let (snd, gh) = static_refs();
        let manager = [9u8; 32];
        let params = AssetParamsBuilder {
            manager: Some(&manager),
            ..Default::default()
        };
        let b = AssetConfigBuilder {
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
            config_asset: 123, // reconfigure
            params: Some(&params),
        };
        let buf = build(&b);
        let txn = Transaction::parse(&buf).unwrap();
        let body = txn.as_asset_config().unwrap();
        assert_eq!(body.config_asset(), 123);
        assert!(body.asset_params().is_some());
        assert!(validate(&txn).is_ok());
    }

    #[test]
    fn destroy_parses_and_validates() {
        let (snd, gh) = static_refs();
        let b = AssetConfigBuilder {
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
            config_asset: 99, // destroy
            params: None,     // absent = destroy
        };
        let buf = build(&b);
        let txn = Transaction::parse(&buf).unwrap();
        let body = txn.as_asset_config().unwrap();
        assert_eq!(body.config_asset(), 99);
        assert!(body.asset_params().is_none());
        assert!(validate(&txn).is_ok());
    }
}
