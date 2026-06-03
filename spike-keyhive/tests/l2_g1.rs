//! L2 integration test — Gate 1, Flow A (delegation) for the Member principal.
//!
//! Verifies that:
//! 1. Two independent Keyhive instances can exchange `ContactCard`s
//!    via the spike's `ContactCardForge` (simulating trie-side
//!    publication).
//! 2. `Keyhive::receive_contact_card` ingests a peer's card and returns
//!    the `Arc<Mutex<Individual>>` ready for `add_member`.
//! 3. After alice grants bob access to her document, `transitive_members`
//!    reports both members.
//!
//! See `spike-keyhive/src/evidence/s1.md` for the integration finding
//! that motivated the contact-card-driven shape.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use futures::lock::Mutex;
use keyhive_core::access::Access;
use keyhive_core::principal::agent::Agent;
use keyhive_core::principal::membered::Membered;
use spike_common::identity::MemberId;
use spike_keyhive::s1_stable_id_acl::{generate_spike_keyhive, ContactCardForge};

#[tokio::test]
async fn two_party_acl_via_contact_card_exchange() {
    // 1. Each "member" runs a Keyhive instance.
    let alice = generate_spike_keyhive().await.unwrap();
    let bob = generate_spike_keyhive().await.unwrap();

    // 2. Both publish their ContactCards to the (simulated) trie.
    let forge = ContactCardForge::new();
    let alice_member = MemberId([0x0a; 32]);
    let bob_member = MemberId([0x0b; 32]);
    forge.publish(alice_member, alice.contact_card().await.unwrap());
    forge.publish(bob_member, bob.contact_card().await.unwrap());

    // 3. alice creates a document; she is the only initial member.
    let doc = alice
        .generate_doc(vec![], nonempty::nonempty![[0u8; 32]])
        .await
        .expect("generate_doc ok");

    // 4. alice resolves bob via the forge and ingests his contact card.
    //    The card's `id()` is the IndividualId — the call-site adapter.
    let bob_card = forge.resolve(&bob_member).expect("bob published");
    let bob_individual: Arc<Mutex<_>> = alice
        .receive_contact_card(&bob_card)
        .await
        .expect("receive_contact_card ok");

    // 5. alice grants bob Edit access to the doc.
    let bob_id = bob_card.id();
    let bob_agent: Agent<_, _, _, _> = Agent::Individual(bob_id, bob_individual);
    let doc_id = doc.lock().await.doc_id();
    alice
        .add_member(
            bob_agent,
            &Membered::Document(doc_id, doc.clone()),
            Access::Edit,
            &[],
        )
        .await
        .expect("add_member ok");

    // 6. Verify both alice and bob appear in the doc's transitive
    //    membership.
    let members = doc.lock().await.transitive_members().await;
    let alice_id = alice.id();
    assert!(
        members.contains_key(&alice_id.into()),
        "alice (the doc owner) must be in transitive_members"
    );
    assert!(
        members.contains_key(&bob_id.into()),
        "bob (added via contact-card exchange) must be in transitive_members"
    );
    assert_eq!(members.len(), 2);
}

#[tokio::test]
async fn unknown_member_id_yields_no_card() {
    let forge = ContactCardForge::new();
    let unknown = MemberId([0xff; 32]);
    assert!(forge.resolve(&unknown).is_none());
}
