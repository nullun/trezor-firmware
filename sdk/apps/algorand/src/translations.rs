// Include generated translations
include!(concat!(env!("OUT_DIR"), "/translations.rs"));

#[cfg(test)]
mod tests {
    #[test]
    fn test_known_key_compile() {
        // Any known key must expand to a &'static str.
        let s: &str = tr!("algorand__fee");
        assert!(!s.is_empty());
    }

    #[cfg(feature = "lang_en")]
    #[test]
    fn test_english_key() {
        assert_eq!(tr!("algorand__fee"), "Fee");
    }

    #[cfg(feature = "lang_cs")]
    #[test]
    fn test_czech_key() {
        assert_eq!(tr!("algorand__fee"), "Poplatek");
    }

    #[cfg(all(feature = "lang_en", feature = "model_t3w1"))]
    #[test]
    fn test_english_eckhart_key() {
        assert_eq!(tr!("send__transaction_signed"), "Transaction signed.");
    }

    #[cfg(all(feature = "lang_en", feature = "model_t3t1"))]
    #[test]
    fn test_english_delizia_key() {
        assert_eq!(tr!("send__transaction_signed"), "Transaction signed");
    }
}
