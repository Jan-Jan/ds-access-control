use alloc::string::String;
use unicode_normalization::UnicodeNormalization;

/// Normalizes a string to NFC form for deterministic serialization and hashing.
pub fn to_nfc(s: &str) -> String {
    s.nfc().collect()
}
