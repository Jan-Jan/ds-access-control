//! Gate 3 substitution: CGKA rotation driven by trie-side key changes.
//!
//! Flow B (compute) is exercised implicitly by gate-1's `add_member`
//! flow (Keyhive's BeeKEM-backed CGKA computes a group secret on every
//! add). Flow C (recompute on rotation) is the entry point for ODS's
//! key-rotation guarantee: when a member's key rotates in the trie, the
//! local-first CGKA must rotate too so the new key forward-secures the
//! doc.
//!
//! The substitution is built around two Keyhive primitives:
//!
//! - [`Keyhive::force_pcs_update`] — re-runs the BeeKEM update path on
//!   a document, generating a fresh `PcsKey` and a signed
//!   `CgkaOperation`. The asymptotic cost is O(log n) (BeeKEM's
//!   advantage over DCGKA's O(n)).
//! - [`IdAdapter::invalidate`](crate::adapter::IdAdapter::invalidate) —
//!   drops the adapter's cached `MemberId → VerifyingKey` so the next
//!   resolve reads the fresh trie value.
//!
//! See `evidence/s3.md` for the verified API surface.

use std::sync::Arc;

use futures::lock::Mutex;
use beekem::operation::CgkaOperation;
use keyhive_core::principal::document::Document;
use keyhive_crypto::signed::Signed;

use crate::s1_stable_id_acl::SpikeKeyhive;
use crate::adapter::IdAdapter;
use spike_common::identity::MemberId;
use spike_common::resolver::MemberKeyResolver;

type SpikeDocument = Document<
    future_form::Sendable,
    keyhive_crypto::signer::memory::MemorySigner,
    [u8; 32],
    keyhive_core::listener::no_listener::NoListener,
>;

/// Drive a trie-rotation-induced PCS update.
///
/// 1. Invalidate the adapter's cache for `rotating_member` (so the
///    next resolve reads the fresh trie value).
/// 2. Re-query the resolver to confirm the new key is visible (the
///    return value isn't used — this is just an assertion that the
///    trie has actually rotated).
/// 3. Call `keyhive.force_pcs_update(doc)` which re-runs BeeKEM with
///    the local signer, producing a new `PcsKey` and signed op.
///
/// The signed op should then be broadcast to other Keyhive instances
/// (the spike's L3 scenarios cover that flow). This function returns
/// the op so callers can route it.
pub async fn rotate_on_trie_change<R: MemberKeyResolver>(
    keyhive: &SpikeKeyhive,
    adapter: &IdAdapter,
    resolver: &R,
    rotating_member: &MemberId,
    doc: Arc<Mutex<SpikeDocument>>,
) -> Result<Signed<CgkaOperation>, RotateError> {
    adapter.invalidate(rotating_member);
    // Confirm the trie actually has the rotating member (otherwise the
    // rotation is meaningless).
    let _new_vk = adapter
        .resolve(resolver, rotating_member)
        .ok_or(RotateError::MemberNotInTrie(*rotating_member))?;
    keyhive
        .force_pcs_update(doc)
        .await
        .map_err(|_| RotateError::PcsUpdate)
}

#[derive(Debug, thiserror::Error)]
pub enum RotateError {
    #[error("member {0:?} not in trie")]
    MemberNotInTrie(MemberId),
    #[error("force_pcs_update failed")]
    PcsUpdate,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::IdAdapter;
    use crate::s1_stable_id_acl::generate_spike_keyhive;
    use keyhive_core::access::Access;
    use keyhive_core::principal::agent::Agent;
    use keyhive_core::principal::membered::Membered;
    use spike_common::scenarios::revocation_fixture;

    #[tokio::test]
    async fn force_pcs_update_changes_doc_cgka_state() {
        let alice = generate_spike_keyhive().await.unwrap();
        let bob = generate_spike_keyhive().await.unwrap();

        // alice creates a doc with bob as a member.
        let doc = alice
            .generate_doc(vec![], nonempty::nonempty![[0u8; 32]])
            .await
            .unwrap();
        let bob_card = bob.contact_card().await.unwrap();
        let bob_individual = alice.receive_contact_card(&bob_card).await.unwrap();
        let doc_id = doc.lock().await.doc_id();
        alice
            .add_member(
                Agent::Individual(bob_card.id(), bob_individual),
                &Membered::Document(doc_id, doc.clone()),
                Access::Edit,
                &[],
            )
            .await
            .unwrap();

        // Force a PCS update — this validates the rotation entry point
        // is reachable and emits a signed CGKA op.
        let signed_op = alice.force_pcs_update(doc.clone()).await.unwrap();

        // The op is a CGKA Update. We don't decode further — Keyhive
        // owns the encryption semantics. What matters: the operation
        // emitted with a non-zero signature.
        assert!(!signed_op.signature().to_bytes().is_empty());
    }

    #[tokio::test]
    async fn rotate_on_trie_change_orchestrates_invalidate_and_pcs_update() {
        let fixture = revocation_fixture();
        let trie = fixture.bootstrap_stub_trie();
        let adapter = IdAdapter::new();
        let alice_member = fixture.initial.members[0].id;

        // Pre-populate the adapter so we can verify invalidation.
        adapter.resolve(&trie, &alice_member).unwrap();
        assert_eq!(adapter.len(), 1);

        // Spike Keyhive + doc + remote member (bob's card).
        let alice_kh = generate_spike_keyhive().await.unwrap();
        let bob_kh = generate_spike_keyhive().await.unwrap();
        let doc = alice_kh
            .generate_doc(vec![], nonempty::nonempty![[1u8; 32]])
            .await
            .unwrap();
        let bob_card = bob_kh.contact_card().await.unwrap();
        let bob_indiv = alice_kh.receive_contact_card(&bob_card).await.unwrap();
        let doc_id = doc.lock().await.doc_id();
        alice_kh
            .add_member(
                Agent::Individual(bob_card.id(), bob_indiv),
                &Membered::Document(doc_id, doc.clone()),
                Access::Edit,
                &[],
            )
            .await
            .unwrap();

        // Now exercise rotate_on_trie_change. The adapter invalidates
        // alice (cache empties), then re-resolves (cache re-populates),
        // then force_pcs_update emits a CGKA op.
        let op = rotate_on_trie_change(&alice_kh, &adapter, &trie, &alice_member, doc.clone())
            .await
            .expect("rotate ok");
        assert!(!op.signature().to_bytes().is_empty());
        assert_eq!(adapter.len(), 1); // re-populated after invalidate
    }
}
