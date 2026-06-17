//! verify-against-chain: the single security property of the PoC. A received
//! envelope is committed only if applying its delta reproduces a root that
//! independently matches the on-chain root at a newer epoch. See spec §5.2.
use ed25519_dalek::VerifyingKey;
use org_members::hasher::Blake3Hasher;
use org_members::trie::OrgTrie;

use crate::chain::ChainReader;
use crate::envelope::SignedDeltaEnvelope;
use crate::error::OrgNodeError;
use crate::ids::OrgId;
use crate::sequence::SeqGuard;

pub type Trie = OrgTrie<Blake3Hasher>;

/// Inputs that pin what the receiver already trusts about the org.
pub struct VerifyContext<'a> {
    /// The org we expect this envelope to be for.
    pub expected_org_id: OrgId,
    /// The author's member key, learned out-of-band / from the trie.
    pub author_member_key: &'a VerifyingKey,
    /// Replay guard for this org.
    pub seq_guard: SeqGuard,
    /// The last on-chain epoch this receiver has already committed (0 if none).
    pub last_committed_epoch: u64,
}

/// The result of a successful verification: the new committed trie and the
/// advanced guards. Caller persists these atomically.
///
/// `Debug` is derived for test convenience; `OrgTrie`'s `Debug` output includes
/// the full node tree (member leaves redact PII, but it is still large). Avoid
/// logging `VerifiedUpdate` at trace/debug level in production code.
#[derive(Debug)]
pub struct VerifiedUpdate {
    pub trie: Trie,
    pub seq_guard: SeqGuard,
    pub epoch: u64,
}

/// Verify an envelope against the local trie and an independent chain oracle.
///
/// Order is security-critical: cheap authenticity checks first, chain read and
/// root match last. Returns the committed trie or a typed rejection; never
/// panics, never mutates `local_trie`.
pub fn verify_envelope_against_chain<C: ChainReader>(
    local_trie: &Trie,
    envelope: &SignedDeltaEnvelope,
    ctx: &VerifyContext<'_>,
    chain: &C,
) -> Result<VerifiedUpdate, OrgNodeError> {
    // 1. Org binding.
    if envelope.org_id != ctx.expected_org_id {
        return Err(OrgNodeError::OrgIdMismatch);
    }
    // 2. Authenticity — before touching delta bytes.
    if !envelope.verify_signature(ctx.author_member_key) {
        return Err(OrgNodeError::BadSignature);
    }
    // 3. Replay.
    ctx.seq_guard.check(envelope.parent_seq)?;
    // 4. Decode the delta (typed error on malformed/non-canonical wire form).
    let delta = envelope.decode_delta()?;
    // 5. Base-root must match the local trie (apply_delta also checks this, but
    //    we surface the specific error before doing work).
    if delta.base_root() != &local_trie.root_hash()? {
        return Err(OrgNodeError::DeltaBaseMismatch);
    }
    // 6. Apply → candidate.
    let candidate = local_trie.apply_delta(&delta)?;
    // 7. Independent trusted root + epoch from the chain.
    let on_chain = chain
        .get_org_state(&ctx.expected_org_id)
        .map_err(OrgNodeError::Chain)?
        .ok_or(OrgNodeError::OrgNotOnChain)?;
    if on_chain.epoch <= ctx.last_committed_epoch {
        return Err(OrgNodeError::StaleEpoch { got: on_chain.epoch, last: ctx.last_committed_epoch });
    }
    // 8. The decisive check: recomputed root must equal the on-chain root.
    let committed = candidate
        .verify_against(&on_chain.root_hash)
        .map_err(|_| OrgNodeError::RootMismatch)?;

    let mut seq_guard = ctx.seq_guard;
    seq_guard.advance(envelope.parent_seq);
    Ok(VerifiedUpdate { trie: committed, seq_guard, epoch: on_chain.epoch })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{MockChain, OrgState};
    use crate::keys::SigningKeypair;
    use crate::test_fixtures::{admit_member_delta, genesis_trie};
    use org_members::RootHash;

    fn setup() -> (SigningKeypair, OrgId, Trie, SignedDeltaEnvelope, RootHash) {
        let admin = SigningKeypair::from_seed([1u8; 32]);
        let local = genesis_trie(&admin, &admin); // receiver's mirror (epoch 1 state)
        // NOTE: admit_member_delta builds its own genesis internally from the same
        // admin; both genesis tries agree by construction (deterministic fixtures).
        let (delta, new_trie) = admit_member_delta(&admin);
        let org = OrgId::new([5u8; 20]);
        let env = SignedDeltaEnvelope::build(org, 2, &delta, &admin).unwrap();
        let new_root = new_trie.root_hash().unwrap();
        (admin, org, local, env, new_root)
    }

    #[test]
    fn happy_path_commits_when_root_matches_chain() {
        let (admin, org, local, env, new_root) = setup();
        let mut chain = MockChain::new();
        chain.set(org, OrgState { root_hash: new_root, org_pub_key: [0u8; 32], epoch: 2 });
        let ctx = VerifyContext {
            expected_org_id: org,
            author_member_key: &admin.verifying_key(),
            seq_guard: SeqGuard::from_last_seen(1),
            last_committed_epoch: 1,
        };
        let out = verify_envelope_against_chain(&local, &env, &ctx, &chain).unwrap();
        assert_eq!(out.epoch, 2);
        assert_eq!(out.seq_guard.last_seen(), 2);
        assert_eq!(out.trie.root_hash().unwrap(), new_root);
    }

    #[test]
    fn rejects_wrong_org_id() {
        let (admin, _org, local, env, _) = setup();
        let chain = MockChain::new();
        let ctx = VerifyContext {
            expected_org_id: OrgId::new([0xff; 20]),
            author_member_key: &admin.verifying_key(),
            seq_guard: SeqGuard::from_last_seen(1),
            last_committed_epoch: 1,
        };
        assert_eq!(verify_envelope_against_chain(&local, &env, &ctx, &chain).unwrap_err(), OrgNodeError::OrgIdMismatch);
    }

    #[test]
    fn rejects_bad_signature() {
        let (_admin, org, local, env, _) = setup();
        let imposter = SigningKeypair::from_seed([0xaa; 32]);
        let chain = MockChain::new();
        let ctx = VerifyContext {
            expected_org_id: org,
            author_member_key: &imposter.verifying_key(),
            seq_guard: SeqGuard::from_last_seen(1),
            last_committed_epoch: 1,
        };
        assert_eq!(verify_envelope_against_chain(&local, &env, &ctx, &chain).unwrap_err(), OrgNodeError::BadSignature);
    }

    #[test]
    fn rejects_stale_seq() {
        let (admin, org, local, env, new_root) = setup();
        let mut chain = MockChain::new();
        chain.set(org, OrgState { root_hash: new_root, org_pub_key: [0u8; 32], epoch: 2 });
        let ctx = VerifyContext {
            expected_org_id: org,
            author_member_key: &admin.verifying_key(),
            seq_guard: SeqGuard::from_last_seen(2), // env.parent_seq == 2, not > 2
            last_committed_epoch: 1,
        };
        assert_eq!(
            verify_envelope_against_chain(&local, &env, &ctx, &chain).unwrap_err(),
            OrgNodeError::StaleSeq { got: 2, last_seen: 2 }
        );
    }

    #[test]
    fn rejects_when_org_absent_from_chain() {
        let (admin, org, local, env, _) = setup();
        let chain = MockChain::new(); // empty
        let ctx = VerifyContext {
            expected_org_id: org,
            author_member_key: &admin.verifying_key(),
            seq_guard: SeqGuard::from_last_seen(1),
            last_committed_epoch: 1,
        };
        assert_eq!(verify_envelope_against_chain(&local, &env, &ctx, &chain).unwrap_err(), OrgNodeError::OrgNotOnChain);
    }

    #[test]
    fn rejects_root_mismatch_when_chain_root_differs() {
        let (admin, org, local, env, _new_root) = setup();
        let mut chain = MockChain::new();
        // Attacker-influenced delta but honest chain root that does NOT match.
        chain.set(org, OrgState { root_hash: RootHash::from_bytes([0xde; 32]), org_pub_key: [0u8; 32], epoch: 2 });
        let ctx = VerifyContext {
            expected_org_id: org,
            author_member_key: &admin.verifying_key(),
            seq_guard: SeqGuard::from_last_seen(1),
            last_committed_epoch: 1,
        };
        assert_eq!(verify_envelope_against_chain(&local, &env, &ctx, &chain).unwrap_err(), OrgNodeError::RootMismatch);
    }

    #[test]
    fn rejects_stale_epoch() {
        let (admin, org, local, env, new_root) = setup();
        let mut chain = MockChain::new();
        chain.set(org, OrgState { root_hash: new_root, org_pub_key: [0u8; 32], epoch: 1 });
        let ctx = VerifyContext {
            expected_org_id: org,
            author_member_key: &admin.verifying_key(),
            seq_guard: SeqGuard::from_last_seen(1),
            last_committed_epoch: 1, // chain epoch 1 is not newer
        };
        assert_eq!(
            verify_envelope_against_chain(&local, &env, &ctx, &chain).unwrap_err(),
            OrgNodeError::StaleEpoch { got: 1, last: 1 }
        );
    }
}
