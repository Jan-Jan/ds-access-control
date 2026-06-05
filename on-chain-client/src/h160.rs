//! `h160_of(account_id_32)` — pallet-revive's AccountId32 → H160 mapping.
//! This is what determines an org's slot key in `OrgRegistry` storage:
//! whatever 20 bytes pallet-revive maps the pure proxy's AccountId32 to
//! IS the on-chain OrgId.
//!
//! pallet-revive (recent Polkadot SDK) uses two cases:
//!
//! 1. If the AccountId32 has the EVM-fallback prefix (the last 12 bytes
//!    are all `0xEE`), the *first* 20 bytes are themselves the H160 —
//!    this is the reverse mapping for accounts derived from a known
//!    EVM address.
//! 2. Otherwise, keccak256 of the full 32-byte AccountId, take the last
//!    20 bytes. This is the "stateless forward" mapping for Substrate-
//!    style 32-byte accounts (the case our pure proxies live in).
//!
//! The exact byte position of the `0xEE` prefix has changed across
//! pallet-revive versions; (a later integration test pins our implementation
//! against chopsticks-captured ground truth before the OrgId invariant
//! relies on it).

use tiny_keccak::{Hasher, Keccak};

/// Mark byte (12 copies of) used by pallet-revive to identify accounts
/// that are EVM-derived (reverse mapping). Lives in the LAST 12 bytes
/// of the AccountId32 — Substrate accounts that came from an H160 are
/// `H160 || [0xEE; 12]`. Confirm against the live runtime in Task 7.
const EVM_FALLBACK_MARK: u8 = 0xEE;

/// Map a 32-byte AccountId32 to its pallet-revive H160.
///
/// Two paths:
///   - Reverse: if the last 12 bytes are `0xEE`, return the first 20.
///   - Forward: keccak256(account_id_32)[12..32].
pub fn h160_of(account_id_32: [u8; 32]) -> [u8; 20] {
    if account_id_32[20..32].iter().all(|b| *b == EVM_FALLBACK_MARK) {
        let mut h160 = [0u8; 20];
        h160.copy_from_slice(&account_id_32[..20]);
        return h160;
    }
    let mut hasher = Keccak::v256();
    hasher.update(&account_id_32);
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);
    let mut h160 = [0u8; 20];
    h160.copy_from_slice(&hash[12..32]);
    h160
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_mapping_strips_ee_suffix() {
        // EVM-derived account: H160 || [0xEE; 12].
        let mut id = [0u8; 32];
        for (i, byte) in id.iter_mut().enumerate().take(20) {
            *byte = i as u8;
        }
        for byte in id.iter_mut().skip(20) {
            *byte = EVM_FALLBACK_MARK;
        }
        let h160 = h160_of(id);
        let mut expected = [0u8; 20];
        for (i, byte) in expected.iter_mut().enumerate() {
            *byte = i as u8;
        }
        assert_eq!(h160, expected);
    }

    #[test]
    fn forward_mapping_keccaks_then_truncates() {
        // Substrate-style account (no 0xEE suffix): keccak256, take low 20.
        let id = [0xAA; 32];
        let h160 = h160_of(id);

        // Re-derive independently as a sanity check against an
        // implementation typo: keccak256([0xAA; 32]), low 20 bytes.
        let mut hasher = Keccak::v256();
        hasher.update(&id);
        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash);
        let mut expected = [0u8; 20];
        expected.copy_from_slice(&hash[12..32]);
        assert_eq!(h160, expected);
    }

    #[test]
    fn forward_path_taken_when_only_some_suffix_bytes_are_ee() {
        // 11 of 12 suffix bytes are 0xEE → still goes through the
        // keccak path (the all() guard in h160_of).
        let mut id = [0u8; 32];
        for byte in id.iter_mut().skip(21) {
            *byte = EVM_FALLBACK_MARK;
        }
        // byte 20 is not 0xEE → forward path
        let h160 = h160_of(id);
        let mut hasher = Keccak::v256();
        hasher.update(&id);
        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash);
        let mut expected = [0u8; 20];
        expected.copy_from_slice(&hash[12..32]);
        assert_eq!(h160, expected);
    }
}
