//! BIP-32 path constants, validation, and display helpers.
//!
//! The allowed pattern is also declared in `[package.metadata.trezor]`
//! (`Cargo.toml`) and enforced by Core; [`check_path`] repeats the check
//! in-app so a rejected path gets a specific error message. The display
//! helpers ([`format_path`], [`account_name`]) feed the address screen's
//! account-info menu, in the same format the reference apps use.

use ufmt::uwrite;

use trezor_app_sdk::{Error, Result, unwrap};

use crate::strutil::BufWriter;

/// Coin label shown in screen subtitles and account names.
pub const COIN: &str = "ALGO";

/// BIP-32 hardened-derivation bit.
pub const HARDENED: u32 = 0x8000_0000;

/// SLIP-44 coin type for Algorand (`283'`).
pub const SLIP44_ALGORAND: u32 = HARDENED | 283;

/// BIP-44 purpose constant (`44'`).
pub const PURPOSE_BIP44: u32 = HARDENED | 44;

/// BIP-32 path length the Algorand app accepts:
/// `m/44'/283'/account'/change'/index'`. Shared by `check_path` and the
/// chunked-upload state so the path-buffer sizing tracks the validator.
pub const ALGORAND_PATH_LEN: usize = 5;

/// Accept only the shape Pera Wallet and the Ledger Algorand app
/// produce, so signatures from this device round-trip with the keys
/// those wallets derive for the same seed. ed25519 has no unhardened
/// derivation, so a non-hardened component could never have produced
/// a usable key anyway.
pub fn check_path(address_n: &[u32]) -> Result<()> {
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

/// Buffer length for [`format_path`] output: `m` plus, per component,
/// `/` + up to 10 decimal digits + `'`.
pub const PATH_STR_LEN: usize = 1 + ALGORAND_PATH_LEN * 12;

/// Render a derivation path as `m/44'/283'/0'/0'/0'` (`'` marks a
/// hardened component) into the caller-supplied buffer.
pub fn format_path<'a>(address_n: &[u32], buf: &'a mut [u8; PATH_STR_LEN]) -> &'a str {
    let mut w = BufWriter::new(buf);
    unwrap!(uwrite!(w, "m"));
    for &item in address_n {
        if item & HARDENED != 0 {
            unwrap!(uwrite!(w, "/{}'", item & !HARDENED));
        } else {
            unwrap!(uwrite!(w, "/{}", item));
        }
    }
    w.into_str()
}

/// Buffer length for [`account_name`] output: the coin label plus
/// ` #` and up to 10 decimal digits.
pub const ACCOUNT_NAME_LEN: usize = COIN.len() + 2 + 10;

/// Human-readable account name for a checked path, e.g. `ALGO #1` for
/// account `0'`. Callers run [`check_path`] first, so the account
/// component is at the fixed BIP-44 position.
pub fn account_name<'a>(address_n: &[u32], buf: &'a mut [u8; ACCOUNT_NAME_LEN]) -> &'a str {
    let account = address_n[2] & !HARDENED;
    let mut w = BufWriter::new(buf);
    unwrap!(uwrite!(w, "{} #{}", COIN, account + 1));
    w.into_str()
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK_PATH: [u32; 5] = [
        PURPOSE_BIP44,
        SLIP44_ALGORAND,
        HARDENED,
        HARDENED,
        HARDENED,
    ];

    #[test]
    fn test_check_path_accepts_canonical() {
        assert!(check_path(&OK_PATH).is_ok());
    }

    #[test]
    fn test_check_path_rejects_bad_shapes() {
        // too short / too long
        assert!(check_path(&OK_PATH[..4]).is_err());
        assert!(check_path(&[OK_PATH.as_slice(), &[HARDENED]].concat()).is_err());
        // wrong purpose / coin type
        let mut p = OK_PATH;
        p[0] = HARDENED | 45;
        assert!(check_path(&p).is_err());
        let mut p = OK_PATH;
        p[1] = HARDENED | 60;
        assert!(check_path(&p).is_err());
        // unhardened component
        let mut p = OK_PATH;
        p[4] = 0;
        assert!(check_path(&p).is_err());
    }

    #[test]
    fn test_format_path() {
        let mut buf = [0u8; PATH_STR_LEN];
        assert_eq!(format_path(&OK_PATH, &mut buf), "m/44'/283'/0'/0'/0'");
        let mut p = OK_PATH;
        p[2] = HARDENED | 7;
        let mut buf = [0u8; PATH_STR_LEN];
        assert_eq!(format_path(&p, &mut buf), "m/44'/283'/7'/0'/0'");
    }

    #[test]
    fn test_account_name() {
        let mut buf = [0u8; ACCOUNT_NAME_LEN];
        assert_eq!(account_name(&OK_PATH, &mut buf), "ALGO #1");
        let mut p = OK_PATH;
        p[2] = HARDENED | 41;
        let mut buf = [0u8; ACCOUNT_NAME_LEN];
        assert_eq!(account_name(&p, &mut buf), "ALGO #42");
    }
}
