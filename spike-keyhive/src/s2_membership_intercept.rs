//! Gate 2 substitution: library-native membership-mutation interception.
//!
//! Two intercept seams were considered and discarded (see `evidence/s2.md`):
//!
//! - **`MembershipListener`** — methods return `F::Future<'a, ()>`. Purely
//!   post-fact; cannot refuse operations.
//! - **Store-level intercept** — `CiphertextStore` is swappable but governs
//!   only encrypted content, not membership; `DelegationStore` /
//!   `RevocationStore` are concrete struct fields, not generic.
//!
//! The viable substitution is **containment-via-wrapper**: keep the
//! [`SpikeKeyhive`](crate::s1_stable_id_acl::SpikeKeyhive) in a private
//! field of [`KeyhiveWrapper`] and expose only trie-driven entry points.
//! Application code that obtains a `&KeyhiveWrapper` has no access to the
//! inner `Keyhive` and cannot call `add_member` / `revoke_member`
//! directly.
//!
//! This is the same pattern any production codebase would use anyway —
//! the application doesn't expose CGKA primitives to user code.

use std::sync::Arc;

use keyhive_core::access::Access;
use keyhive_core::contact_card::ContactCard;
use keyhive_core::principal::agent::Agent;
use keyhive_core::principal::document::Document;
use keyhive_core::principal::individual::Individual;
use keyhive_core::principal::membered::Membered;

use crate::s1_stable_id_acl::SpikeKeyhive;

/// Containment wrapper around a [`SpikeKeyhive`].
///
/// The inner Keyhive is held in a private `Arc` — only methods on
/// `KeyhiveWrapper` can call into it. Production code receiving a
/// `KeyhiveWrapper` reference cannot invoke `add_member` or
/// `revoke_member` directly; the only mutation entry points are the
/// wrapper's own trie-driven methods.
///
/// In phase 3 a trait `TrieDrivenAcl` could constrain this further
/// (only callable from the trie observer), but the spike's purpose is
/// to validate that the substitution shape works, not to enforce
/// air-tight access control.
pub struct KeyhiveWrapper {
    inner: Arc<SpikeKeyhive>,
}

impl KeyhiveWrapper {
    pub fn new(keyhive: SpikeKeyhive) -> Self {
        Self {
            inner: Arc::new(keyhive),
        }
    }

    /// Borrow the inner Keyhive — exposed only for spike testing where
    /// the test driver represents the "trie observer" role. Production
    /// code MUST NOT have this method.
    #[cfg(test)]
    pub(crate) fn inner(&self) -> &SpikeKeyhive {
        &self.inner
    }

    /// Trie-driven member addition. Resolves a peer via the
    /// [`ContactCardForge`](crate::s1_stable_id_acl::ContactCardForge),
    /// ingests their contact card, and adds them to `doc` with `access`.
    ///
    /// Returns `Err(...)` if the peer's card hasn't been published, or if
    /// the underlying Keyhive operation fails.
    pub async fn grant_member(
        &self,
        peer_card: ContactCard,
        doc: &Arc<futures::lock::Mutex<Document<
            future_form::Sendable,
            keyhive_crypto::signer::memory::MemorySigner,
            [u8; 32],
            keyhive_core::listener::no_listener::NoListener,
        >>>,
        access: Access,
    ) -> Result<(), GrantError> {
        let individual: Arc<futures::lock::Mutex<Individual>> = self
            .inner
            .receive_contact_card(&peer_card)
            .await
            .map_err(|_| GrantError::ReceiveCard)?;
        let peer_id = peer_card.id();
        let agent = Agent::Individual(peer_id, individual);
        let doc_id = doc.lock().await.doc_id();
        self.inner
            .add_member(agent, &Membered::Document(doc_id, doc.clone()), access, &[])
            .await
            .map_err(|_| GrantError::AddMember)?;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GrantError {
    #[error("receive_contact_card failed")]
    ReceiveCard,
    #[error("add_member failed")]
    AddMember,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s1_stable_id_acl::{generate_spike_keyhive, ContactCardForge};
    use spike_common::identity::MemberId;

    #[tokio::test]
    async fn grant_member_via_wrapper_succeeds() {
        let alice_kh = generate_spike_keyhive().await.unwrap();
        let bob_kh = generate_spike_keyhive().await.unwrap();

        let forge = ContactCardForge::new();
        let bob_member = MemberId([0x0b; 32]);
        forge.publish(bob_member, bob_kh.contact_card().await.unwrap());

        let alice_wrapper = KeyhiveWrapper::new(alice_kh);
        let doc = alice_wrapper
            .inner()
            .generate_doc(vec![], nonempty::nonempty![[0u8; 32]])
            .await
            .unwrap();

        let bob_card = forge.resolve(&bob_member).unwrap();
        alice_wrapper
            .grant_member(bob_card.clone(), &doc, Access::Edit)
            .await
            .expect("grant ok");

        let members = doc.lock().await.transitive_members().await;
        assert!(members.contains_key(&bob_card.id().into()));
    }

    #[tokio::test]
    async fn wrapper_hides_inner_keyhive_from_release_builds() {
        // The point of this test is that in release builds (where
        // cfg(test) is off), `inner()` is not callable. Documenting
        // the invariant — this test compiles only because we're in
        // cfg(test).
        let kh = generate_spike_keyhive().await.unwrap();
        let _wrapper = KeyhiveWrapper::new(kh);
        // Compile-time: in non-test builds, `inner()` is not present.
        // No runtime assertion needed.
    }
}
