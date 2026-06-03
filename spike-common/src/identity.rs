//! Identity types shared by both spikes.
//!
//! These mirror the `org-members` type shapes but are re-defined locally
//! so the spike is isolated from `org-members` evolution. PII-free; no
//! handles.

use ed25519_dalek::VerifyingKey;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// 32-byte immutable member identifier. SMT key on the trie side; opaque
/// principal on the library side.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MemberId(pub [u8; 32]);

/// Member-as-a-group key (ed25519 verifying key). The "member" public key
/// the local-first library uses when granting access to a `Principal::Member`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct P2pMemberKey(pub VerifyingKey);

/// Per-device verifying key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct P2pDeviceKey(pub VerifyingKey);

/// Organisation-as-a-pseudo-group key (ed25519 verifying key).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OrgKey(pub VerifyingKey);

/// Monotonic epoch counter for trie/CGKA versioning.
#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Epoch(pub u64);

/// Opaque principal type. The library can only dereference these via
/// `MemberKeyResolver`. This is the type-system half of the substitution-1
/// enforcement (the other half is the no-direct-cache invariant in Flow B).
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Principal {
    Member(MemberId),
    Org,
}

#[cfg(test)]
#[cfg(feature = "serde")]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn member_id_postcard_roundtrip() {
        let id = MemberId([7u8; 32]);
        let bytes = postcard::to_allocvec(&id).unwrap();
        let back: MemberId = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn p2p_member_key_postcard_roundtrip() {
        let signing = SigningKey::from_bytes(&[3u8; 32]);
        let key = P2pMemberKey(signing.verifying_key());
        let bytes = postcard::to_allocvec(&key).unwrap();
        let back: P2pMemberKey = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(key, back);
    }

    #[test]
    fn principal_postcard_roundtrip() {
        let m = Principal::Member(MemberId([1u8; 32]));
        let o = Principal::Org;
        for p in [m, o] {
            let bytes = postcard::to_allocvec(&p).unwrap();
            let back: Principal = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(p, back);
        }
    }

    #[test]
    fn epoch_ordering() {
        assert!(Epoch(0) < Epoch(1));
        assert!(Epoch(u64::MAX) > Epoch(u64::MAX - 1));
    }
}
