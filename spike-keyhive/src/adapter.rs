//! `MemberId` ↔ `VerifyingKey` mapping cache for Keyhive call sites.
//!
//! Keyhive's `Identifier`, `IndividualId`, `GroupId`, and `DocumentId` are
//! concrete newtypes over `ed25519_dalek::VerifyingKey`. There is no
//! generic-ID escape hatch at the public surface, so the spike's gate-1
//! salvage is a **call-site adapter** that materialises a `VerifyingKey`
//! from the `MemberKeyResolver` on every Keyhive boundary.
//!
//! The adapter also maintains the reverse mapping (`VerifyingKey →
//! MemberId`) needed by gate 5's `PolicyManager` — populated lazily as
//! members are resolved. Cold reverse lookups for never-seen peers are
//! a foundation-layer gap (see `evidence/s5.md`).
//!
//! See `evidence/s1.md` for the verified API surface and severity rationale.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ed25519_dalek::VerifyingKey;
use keyhive_core::principal::identifier::Identifier;
use keyhive_core::principal::individual::id::IndividualId;
use spike_common::identity::MemberId;
use spike_common::resolver::{MemberKeyResolver, ResolverError};

/// Maps `MemberId` to `VerifyingKey` (and back) by querying a
/// [`MemberKeyResolver`].
///
/// The cache is non-authoritative: the resolver (and ultimately the
/// on-chain trie) is the source of truth. The cache exists for two
/// reasons:
///
/// 1. Cheap reverse lookups (`member_id_for(vk)`) for gate 5.
/// 2. A place to record what `VerifyingKey` Keyhive saw for a given
///    `MemberId` at delegation time, so callers can detect drift.
///
/// On rotation, callers invoke [`invalidate`](IdAdapter::invalidate) to
/// drop the stale entry; the next [`resolve`](IdAdapter::resolve) call
/// repopulates from the trie. Drift detection at the Keyhive layer (the
/// delegation log holds the *original* `VerifyingKey`) is handled by the
/// gate-3 rotation cascade (`force_pcs_update`), not by this adapter.
#[derive(Clone, Default)]
pub struct IdAdapter {
    mapping: Arc<Mutex<HashMap<MemberId, VerifyingKey>>>,
}

impl IdAdapter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolve a `MemberId` to its current `VerifyingKey`, populating the
    /// cache. Returns `None` if the resolver does not know `id`.
    pub fn resolve<R: MemberKeyResolver>(
        &self,
        resolver: &R,
        id: &MemberId,
    ) -> Option<VerifyingKey> {
        let key = match resolver.p2p_member_key(id) {
            Ok(k) => k.0,
            Err(ResolverError::UnknownMember(_)) => return None,
            Err(_) => return None,
        };
        let mut m = self.mapping.lock().unwrap_or_else(|e| e.into_inner());
        m.insert(*id, key);
        Some(key)
    }

    /// Resolve a `MemberId` to a Keyhive [`Identifier`] in one step.
    pub fn resolve_identifier<R: MemberKeyResolver>(
        &self,
        resolver: &R,
        id: &MemberId,
    ) -> Option<Identifier> {
        self.resolve(resolver, id).map(Identifier::from)
    }

    /// Resolve a `MemberId` to a Keyhive [`IndividualId`] in one step.
    pub fn resolve_individual_id<R: MemberKeyResolver>(
        &self,
        resolver: &R,
        id: &MemberId,
    ) -> Option<IndividualId> {
        self.resolve(resolver, id).map(IndividualId::from)
    }

    /// Drop the cached `VerifyingKey` for `id`. Call this when the trie
    /// reports a rotation; the next `resolve` reads the fresh key.
    pub fn invalidate(&self, id: &MemberId) {
        let mut m = self.mapping.lock().unwrap_or_else(|e| e.into_inner());
        m.remove(id);
    }

    /// Reverse lookup: which `MemberId` (if any) is currently mapped to
    /// `vk`? Returns `None` for keys that have never been resolved (cold
    /// peers). Phase 3 needs `MemberKeyResolver::find_member_by_device`
    /// to handle cold lookups; see `evidence/s5.md`.
    pub fn member_id_for(&self, vk: &VerifyingKey) -> Option<MemberId> {
        let m = self.mapping.lock().unwrap_or_else(|e| e.into_inner());
        m.iter().find_map(|(mid, k)| (k == vk).then_some(*mid))
    }

    /// Returns the number of cached entries. Diagnostic helper.
    pub fn len(&self) -> usize {
        self.mapping.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spike_common::identity::P2pMemberKey;
    use spike_common::scenarios::revocation_fixture;

    fn alice_id(fixture: &spike_common::scenarios::ScenarioFixture) -> MemberId {
        fixture.initial.members[0].id
    }

    #[test]
    fn empty_adapter_starts_empty() {
        let adapter = IdAdapter::new();
        assert!(adapter.is_empty());
        assert_eq!(adapter.len(), 0);
    }

    #[test]
    fn resolve_populates_cache() {
        let fixture = revocation_fixture();
        let trie = fixture.bootstrap_stub_trie();
        let adapter = IdAdapter::new();
        let alice = alice_id(&fixture);

        let resolved = adapter.resolve(&trie, &alice).expect("alice in trie");
        let direct = trie.p2p_member_key(&alice).expect("alice in trie").0;
        assert_eq!(resolved, direct);
        assert_eq!(adapter.len(), 1);
        assert_eq!(adapter.member_id_for(&resolved), Some(alice));
    }

    #[test]
    fn resolve_unknown_returns_none() {
        let fixture = revocation_fixture();
        let trie = fixture.bootstrap_stub_trie();
        let adapter = IdAdapter::new();

        let unknown = MemberId([0xff; 32]);
        assert!(adapter.resolve(&trie, &unknown).is_none());
        assert!(adapter.is_empty());
    }

    #[test]
    fn invalidate_drops_entry() {
        let fixture = revocation_fixture();
        let trie = fixture.bootstrap_stub_trie();
        let adapter = IdAdapter::new();
        let alice = alice_id(&fixture);

        adapter.resolve(&trie, &alice).unwrap();
        assert_eq!(adapter.len(), 1);
        adapter.invalidate(&alice);
        assert_eq!(adapter.len(), 0);
    }

    #[test]
    fn resolve_identifier_and_individual_id_share_key() {
        let fixture = revocation_fixture();
        let trie = fixture.bootstrap_stub_trie();
        let adapter = IdAdapter::new();
        let alice = alice_id(&fixture);

        let identifier = adapter
            .resolve_identifier(&trie, &alice)
            .expect("alice in trie");
        let individual_id = adapter
            .resolve_individual_id(&trie, &alice)
            .expect("alice in trie");
        assert_eq!(identifier.0, individual_id.0 .0);
    }

    #[test]
    fn rotation_via_resolve_picks_up_new_key() {
        let fixture = revocation_fixture();
        let trie = fixture.bootstrap_stub_trie();
        let adapter = IdAdapter::new();
        let alice = alice_id(&fixture);

        let pre = adapter.resolve(&trie, &alice).unwrap();
        let new_signing = ed25519_dalek::SigningKey::from_bytes(&[0xa9u8; 32]);
        let new_key = P2pMemberKey(new_signing.verifying_key());
        let trie = trie.stub_rotate_member_key(&alice, new_key);

        // resolve always re-queries the resolver; the cache is overwritten.
        let post = adapter.resolve(&trie, &alice).unwrap();
        assert_ne!(pre, post);
        assert_eq!(post, new_signing.verifying_key());
    }
}
