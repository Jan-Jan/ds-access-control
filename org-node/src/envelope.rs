//! SignedDeltaEnvelope: the authenticated wire form for a trie change.
//! Transcript signed = org_id (20) ‖ parent_seq LE (8) ‖ delta_bytes.
use ed25519_dalek::{Signature, VerifyingKey};
use org_members::delta::Delta;
use serde::{Deserialize, Serialize};

use crate::error::OrgNodeError;
use crate::ids::OrgId;
use crate::keys::{verify, SigningKeypair};

/// Serde helper: serialize/deserialize `[u8; 64]` as a fixed-length byte array.
/// serde's derive does not implement these for arrays larger than 32 in all
/// configurations; this helper bridges the gap for postcard (and any other
/// Serializer that supports byte-array hints).
mod sig_bytes {
    use serde::{Deserializer, Serializer};
    use serde::de::{Error, SeqAccess, Visitor};
    use core::fmt;

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        struct Vis;
        impl<'de> Visitor<'de> for Vis {
            type Value = [u8; 64];
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("64-byte signature")
            }
            fn visit_bytes<E: Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                v.try_into().map_err(|_| E::invalid_length(v.len(), &"64"))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = [0u8; 64];
                for b in out.iter_mut() {
                    *b = seq.next_element::<u8>()?
                        .ok_or_else(|| A::Error::invalid_length(0, &"64"))?;
                }
                Ok(out)
            }
        }
        d.deserialize_bytes(Vis)
    }
}

/// A signed, org-bound, sequence-bound trie delta.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedDeltaEnvelope {
    pub org_id: OrgId,
    pub parent_seq: u64,
    pub delta_bytes: Vec<u8>, // postcard(Delta)
    #[serde(with = "sig_bytes")]
    pub signature: [u8; 64],
}

/// Build the exact byte transcript that gets signed/verified.
fn transcript(org_id: &OrgId, parent_seq: u64, delta_bytes: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(20 + 8 + delta_bytes.len());
    buf.extend_from_slice(org_id.as_bytes());
    buf.extend_from_slice(&parent_seq.to_le_bytes());
    buf.extend_from_slice(delta_bytes);
    buf
}

impl SignedDeltaEnvelope {
    /// Author side: encode `delta`, bind it to (org, seq), and sign with `author`.
    pub fn build(
        org_id: OrgId,
        parent_seq: u64,
        delta: &Delta,
        author: &SigningKeypair,
    ) -> Result<Self, OrgNodeError> {
        // to_allocvec on a valid Delta is infallible in practice; reuse MalformedDelta for the unreachable encode error.
        let delta_bytes = postcard::to_allocvec(delta).map_err(|_| OrgNodeError::MalformedDelta)?;
        let sig = author.sign(&transcript(&org_id, parent_seq, &delta_bytes));
        Ok(Self { org_id, parent_seq, delta_bytes, signature: sig.to_bytes() })
    }

    /// Decode the inner Delta from postcard bytes (no signature check).
    pub fn decode_delta(&self) -> Result<Delta, OrgNodeError> {
        postcard::from_bytes(&self.delta_bytes).map_err(|_| OrgNodeError::MalformedDelta)
    }

    /// Verify the signature against a *known* member verifying key.
    /// Does NOT check org_id/seq/root — that is verify.rs's job.
    pub fn verify_signature(&self, author_member_key: &VerifyingKey) -> bool {
        let sig = Signature::from_bytes(&self.signature);
        verify(author_member_key, &transcript(&self.org_id, self.parent_seq, &self.delta_bytes), &sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::{admit_member_delta, genesis_trie, member, NodeFixture};
    use rand::rngs::OsRng;

    #[test]
    fn build_then_verify_signature_succeeds() {
        let admin = SigningKeypair::generate(&mut OsRng);
        let (delta, _new_trie) = admit_member_delta(&admin);
        let org = OrgId::new([5u8; 20]);
        let env = SignedDeltaEnvelope::build(org, 1, &delta, &admin).unwrap();
        assert!(env.verify_signature(&admin.verifying_key()));
    }

    #[test]
    fn wrong_key_fails_signature() {
        let admin = SigningKeypair::generate(&mut OsRng);
        let other = SigningKeypair::generate(&mut OsRng);
        let (delta, _) = admit_member_delta(&admin);
        let env = SignedDeltaEnvelope::build(OrgId::new([5u8; 20]), 1, &delta, &admin).unwrap();
        assert!(!env.verify_signature(&other.verifying_key()));
    }

    #[test]
    fn tampering_with_org_id_breaks_signature() {
        let admin = SigningKeypair::generate(&mut OsRng);
        let (delta, _) = admit_member_delta(&admin);
        let mut env = SignedDeltaEnvelope::build(OrgId::new([5u8; 20]), 1, &delta, &admin).unwrap();
        env.org_id = OrgId::new([6u8; 20]);
        assert!(!env.verify_signature(&admin.verifying_key()));
    }

    #[test]
    fn tampering_with_parent_seq_breaks_signature() {
        let admin = SigningKeypair::generate(&mut OsRng);
        let (delta, _) = admit_member_delta(&admin);
        let mut env = SignedDeltaEnvelope::build(OrgId::new([5u8; 20]), 1, &delta, &admin).unwrap();
        env.parent_seq += 1;
        assert!(!env.verify_signature(&admin.verifying_key()));
    }

    #[test]
    fn tampering_with_delta_bytes_breaks_signature() {
        let admin = SigningKeypair::generate(&mut OsRng);
        let (delta, _) = admit_member_delta(&admin);
        let mut env = SignedDeltaEnvelope::build(OrgId::new([5u8; 20]), 1, &delta, &admin).unwrap();
        assert!(!env.delta_bytes.is_empty(), "admit delta must be non-empty");
        env.delta_bytes[0] ^= 0xff;
        assert!(!env.verify_signature(&admin.verifying_key()));
    }

    #[test]
    fn decode_delta_round_trips() {
        let admin = SigningKeypair::generate(&mut OsRng);
        let (delta, _) = admit_member_delta(&admin);
        let env = SignedDeltaEnvelope::build(OrgId::new([5u8; 20]), 1, &delta, &admin).unwrap();
        // Delta doesn't implement PartialEq; verify round-trip via re-encoding.
        let decoded = env.decode_delta().unwrap();
        let re_encoded = postcard::to_allocvec(&decoded).unwrap();
        assert_eq!(env.delta_bytes, re_encoded);
    }

    // Silence unused-import warnings for fixtures used by later tasks.
    #[allow(unused_imports)]
    use {genesis_trie as _g, member as _m, NodeFixture as _F};
    #[allow(unused_imports)]
    use org_members::{trie::OrgTrie, hasher::Blake3Hasher};
    type _T = OrgTrie<Blake3Hasher>;
}
