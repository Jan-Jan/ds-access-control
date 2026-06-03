//! Gate 1 substitution: stable-ID ACL via call-site adapter + contact-card exchange.
//!
//! ## Implementation finding
//!
//! The API-only analysis (see `evidence/s1.md` first revision) hypothesised
//! that resolving `MemberId → VerifyingKey` would be sufficient to drive
//! `Keyhive::add_member`. **Running code revealed this is not the case.**
//!
//! Keyhive's `Individual::new(initial_op: KeyOp)` requires a signed
//! [`KeyOp`](keyhive_core::principal::individual::op::KeyOp), not a bare
//! `VerifyingKey`. The canonical Keyhive-native flow is:
//!
//! 1. Each member runs their own Keyhive instance and publishes a signed
//!    [`ContactCard`](keyhive_core::contact_card::ContactCard) via
//!    `keyhive.contact_card().await`.
//! 2. Peers ingest the card via
//!    `keyhive.receive_contact_card(&card).await`, which returns an
//!    `Arc<Mutex<Individual>>`.
//! 3. `add_member` accepts an `Agent::Individual(id, individual_arc)`.
//!
//! For ODS this means the trie cannot just publish raw `VerifyingKey`s —
//! it must publish (or sign-on-demand) `ContactCard`s. This is an
//! architectural escalation for gate 1: the trie's `MemberKeyResolver`
//! contract needs a new method `contact_card(&MemberId)` returning a
//! Keyhive-compatible signed KeyOp.
//!
//! ## Spike implementation
//!
//! - [`SpikeKeyhive`] — a type alias that fixes Keyhive's seven generic
//!   parameters to the spike's canonical instantiation.
//! - [`generate_spike_keyhive`] — async constructor mirroring
//!   `keyhive_core::test_utils::make_simple_keyhive` (the upstream helper
//!   is not exposed because `test_utils` is gated only on `cfg(test)`).
//! - [`ContactCardForge`] — spike-only helper that maintains a
//!   `MemberId → ContactCard` mapping populated by clients publishing
//!   their contact cards. In Phase 3 the trie owns this mapping.
//!
//! See `evidence/s1.md` for the updated finding and severity.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};

use future_form::Sendable;
use keyhive_core::contact_card::ContactCard;
use keyhive_core::keyhive::Keyhive;
use keyhive_core::listener::no_listener::NoListener;
use keyhive_core::store::ciphertext::memory::MemoryCiphertextStore;
use keyhive_crypto::signed::SigningError;
use keyhive_crypto::signer::memory::MemorySigner;
use rand::rngs::OsRng;

use spike_common::identity::MemberId;

/// The spike's canonical Keyhive instantiation.
///
/// Locks the seven generic parameters of [`Keyhive`] to the same
/// choices `make_simple_keyhive` uses upstream:
/// - `FutureForm = Sendable`
/// - `AsyncSigner = MemorySigner`
/// - `ContentRef = [u8; 32]`
/// - `Plaintext = Vec<u8>`
/// - `CiphertextStore = MemoryCiphertextStore<[u8; 32], Vec<u8>>`
/// - `MembershipListener = NoListener`
/// - `CryptoRng = OsRng`
pub type SpikeKeyhive = Keyhive<
    Sendable,
    MemorySigner,
    [u8; 32],
    Vec<u8>,
    MemoryCiphertextStore<[u8; 32], Vec<u8>>,
    NoListener,
    OsRng,
>;

/// Generate a fresh [`SpikeKeyhive`] instance with a random signing key.
///
/// Mirrors `keyhive_core::test_utils::make_simple_keyhive`, which is
/// inaccessible from downstream crates (the `test_utils` module is gated
/// behind `cfg(any(test, feature = "test_utils"))` but the feature is
/// not declared in keyhive_core's Cargo manifest).
pub async fn generate_spike_keyhive() -> Result<SpikeKeyhive, SigningError> {
    let mut csprng = OsRng;
    let sk = MemorySigner::generate(&mut csprng);
    Keyhive::generate(sk, MemoryCiphertextStore::new(), NoListener, csprng).await
}

/// Spike-only stand-in for the Phase 3 trie-side contact-card index.
///
/// In production, the trie publishes (or vouches for) each
/// `MemberId`'s `ContactCard`. The spike's `ContactCardForge` is a
/// thread-safe in-memory map that simulates that publication — clients
/// `publish(member_id, card)` and peers `resolve(&member_id) -> Option<ContactCard>`.
#[derive(Clone, Default)]
pub struct ContactCardForge {
    cards: Arc<StdMutex<HashMap<MemberId, ContactCard>>>,
}

impl ContactCardForge {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `member_id` has published `card`. Subsequent
    /// `resolve` calls return this card.
    pub fn publish(&self, member_id: MemberId, card: ContactCard) {
        self.cards
            .lock().unwrap_or_else(|e| e.into_inner())
            .insert(member_id, card);
    }

    /// Look up the published `ContactCard` for `member_id`. Returns
    /// `None` if the member has never published.
    pub fn resolve(&self, member_id: &MemberId) -> Option<ContactCard> {
        self.cards
            .lock().unwrap_or_else(|e| e.into_inner())
            .get(member_id)
            .cloned()
    }

    pub fn len(&self) -> usize {
        self.cards.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn keyhive_constructor_works() {
        let kh = generate_spike_keyhive().await.expect("Keyhive::generate ok");
        // Generated Keyhives carry an active identity; calling contact_card
        // should succeed.
        let card = kh.contact_card().await.expect("contact_card ok");
        // Sanity: the card's ID matches the keyhive instance.
        assert_eq!(card.id(), kh.id());
    }

    #[tokio::test]
    async fn contact_card_forge_round_trip() {
        let kh = generate_spike_keyhive().await.unwrap();
        let card = kh.contact_card().await.unwrap();
        let forge = ContactCardForge::new();

        let member_id = MemberId([0x07; 32]);
        forge.publish(member_id, card.clone());
        let resolved = forge.resolve(&member_id).expect("card published");
        assert_eq!(resolved.id(), card.id());
        assert_eq!(forge.len(), 1);
    }
}
