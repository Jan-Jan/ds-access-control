//! Named types mirroring the on-chain `OrgRegistry` fields. Newtypes around
//! fixed-size byte arrays — chosen over naked primitives so the public API
//! can't accidentally swap `OrgPubKey` for `OnChainRootHash` (both are 32
//! bytes). Matches the surface declared in spec §3.

use core::fmt;

/// H160 address of an org's pure proxy `P`. Stable for the lifetime of the
/// org: rotating the controlling multisig `M(signers, threshold)` does not
/// affect `P`, so this value is the on-chain OrgId.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OrgAdmin(pub [u8; 20]);

/// The 32-byte sparse-merkle root from `org-members`, anchored on-chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OnChainRootHash(pub [u8; 32]);

/// The org's public key as stored on-chain. Opaque 32 bytes; the scheme
/// (Ed25519 today; sr25519 / BLS / PQ on the V2 roadmap — see
/// `on-chain/POST_POC.md`) is conveyed off-chain by the trie.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OrgPubKey(pub [u8; 32]);

/// Monotonic per-org counter. `0` = uninitialised slot; `1` = post-genesis;
/// `+1` per successful `update(...)`. Wraparound is not reachable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Epoch(pub u64);

impl fmt::Display for Epoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newtypes_have_expected_widths() {
        // Locks the public byte layout: any accidental change to the
        // wrapped array size becomes a compile-then-test failure.
        assert_eq!(core::mem::size_of::<OrgAdmin>(), 20);
        assert_eq!(core::mem::size_of::<OnChainRootHash>(), 32);
        assert_eq!(core::mem::size_of::<OrgPubKey>(), 32);
        assert_eq!(core::mem::size_of::<Epoch>(), 8);
    }

    #[test]
    fn epoch_display_is_the_inner_value() {
        // Smoke test; the Display impl is used in error messages and logs.
        let e = Epoch(42);
        assert_eq!(alloc::format!("{e}"), "42");
    }
}
