//! L3 end-to-end scenario — lazy onboarding (the ODS two-tier model).
//!
//! Validates the lazy-CGKA design committed on 2026-06-03: alice grants
//! bob access AFTER writing pre-onboarding content, bob is placed in
//! the CGKA tree at that later moment, post-onboarding content flows to
//! bob directly, and pre-onboarding history is recovered via
//! re-transmission by an already-authorised peer under the new CGKA
//! epoch.
//!
//! Observable invariants — the headline claims of the lazy-CGKA design:
//!
//! 1. Pre-onboarding ciphertexts (epoch N, alice-only) are NOT
//!    decryptable by bob even after he is added in epoch N+1.
//!    BeeKEM gives forward security in the new-member direction
//!    too — old epochs were never encrypted to bob.
//! 2. Post-onboarding ciphertexts (epoch N+1+) ARE decryptable by bob.
//! 3. **History transfer**: alice re-encrypts the pre-onboarding
//!    plaintext (which she has at-rest) under the current epoch;
//!    bob decrypts the retransmission successfully, recovering the
//!    original bytes. No privilege extension — alice already had
//!    read access; she's transferring her view to a co-authorised
//!    member.
//!
//! The test exercises Keyhive's high-level `add_member` path for the
//! ACL grant + CGKA placement step; the ODS production design will
//! descend below this entry point to `keyhive_core` delegation log +
//! `beekem::Cgka::add` directly so the placement can be driven by the
//! coming-online member's own client. The mechanism this test validates
//! (BeeKEM epoch separation + plaintext re-transmission) is identical
//! under both compositions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use dupe::Dupe;
use keyhive_core::access::Access;
use keyhive_core::principal::agent::Agent;
use keyhive_core::principal::membered::Membered;
use spike_keyhive::s1_stable_id_acl::generate_spike_keyhive;

#[tokio::test]
async fn lazy_onboarding_post_add_decrypts_history_via_retransmission() {
    // Phase 1 — Alice bootstraps alone. Bob doesn't yet exist in alice's
    // world. Alice creates a doc and writes pre-onboarding content.
    let alice = generate_spike_keyhive().await.unwrap();

    let pre_content = b"pre-onboarding content (alice only at this point)".to_vec();
    let pre_ref: [u8; 32] = blake3::hash(&pre_content).into();
    let doc = alice
        .generate_doc(vec![], nonempty::nonempty![pre_ref])
        .await
        .unwrap();
    let doc_id = doc.lock().await.doc_id();

    let pre_encrypted = alice
        .try_encrypt_content(doc.dupe(), &pre_ref, &vec![], &pre_content)
        .await
        .unwrap();

    // Phase 2 — Bob comes online (generates his own keyhive locally).
    // In production this is where his client materialises against the
    // trie's record of his MemberId; in the spike we simulate it by
    // generating a fresh SpikeKeyhive.
    let bob = generate_spike_keyhive().await.unwrap();
    let bob_card = bob.contact_card().await.unwrap();

    // Phase 3 — LAZY ADD: alice grants bob access to the doc, after
    // pre-content was already encrypted. This is the lazy-CGKA path —
    // ACL grant happens now, not at doc-creation time. The high-level
    // add_member call advances the CGKA epoch and places bob in the
    // tree.
    let bob_indiv = alice.receive_contact_card(&bob_card).await.unwrap();
    alice
        .add_member(
            Agent::Individual(bob_card.id(), bob_indiv),
            &Membered::Document(doc_id, doc.dupe()),
            Access::Read,
            &[],
        )
        .await
        .unwrap();

    // Phase 4 — Alice writes post-onboarding content. This is in the
    // new CGKA epoch which includes bob.
    let post_content = b"post-onboarding content (alice + bob)".to_vec();
    let post_ref: [u8; 32] = blake3::hash(&post_content).into();
    let post_encrypted = alice
        .try_encrypt_content(doc.dupe(), &post_ref, &vec![pre_ref], &post_content)
        .await
        .unwrap();

    // Phase 5 — Sync alice's state to bob (everything: the doc, the
    // pre-content op, the add_member op, the post-content op).
    let bob_active_agent: Agent<_, _, _, _> = bob.active().lock().await.clone().into();
    let events = alice.static_events_for_agent(&bob_active_agent).await;
    bob.ingest_unsorted_static_events(events.into_values().collect())
        .await;
    let doc_on_bob = bob.get_document(doc_id).await.unwrap();

    // Phase 6 — Forward-security boundary. Bob CANNOT decrypt
    // pre-onboarding content, because that ciphertext was produced in
    // an epoch he was not a member of. This is the BeeKEM guarantee in
    // the new-member direction (symmetric to the revocation direction
    // exercised by l3_revocation).
    let pre_decrypt_attempt = bob
        .try_decrypt_content(doc_on_bob.dupe(), pre_encrypted.encrypted_content())
        .await;
    assert!(
        pre_decrypt_attempt.is_err(),
        "bob must NOT be able to decrypt pre-onboarding content directly; \
         got {:?}",
        pre_decrypt_attempt.map(|p| String::from_utf8_lossy(&p).into_owned()),
    );

    // Phase 7 — Post-onboarding content decrypts directly.
    let post_plain = bob
        .try_decrypt_content(doc_on_bob.dupe(), post_encrypted.encrypted_content())
        .await
        .unwrap();
    assert_eq!(post_plain, post_content);

    // Phase 8 — HISTORY TRANSFER via re-transmission. Alice has the
    // pre-onboarding plaintext at-rest. She re-encrypts it under the
    // current CGKA epoch (which now includes bob) and broadcasts the
    // resulting ciphertext as a fresh content op. Production would
    // typically model this as a "retransmission" op with a distinct
    // content_ref; we use a labelled hash here.
    let retrans_ref: [u8; 32] = blake3::hash(b"retransmission:pre-onboarding").into();
    let retrans_encrypted = alice
        .try_encrypt_content(
            doc.dupe(),
            &retrans_ref,
            &vec![post_ref],
            &pre_content, // SAME plaintext as the original pre-content
        )
        .await
        .unwrap();

    // Sync retransmission to bob.
    let events = alice.static_events_for_agent(&bob_active_agent).await;
    bob.ingest_unsorted_static_events(events.into_values().collect())
        .await;

    // Phase 9 — Bob decrypts the retransmitted history. The recovered
    // bytes are the original pre_content. This is the ODS history-
    // transfer guarantee.
    let retrans_plain = bob
        .try_decrypt_content(doc_on_bob.dupe(), retrans_encrypted.encrypted_content())
        .await
        .unwrap();
    assert_eq!(
        retrans_plain, pre_content,
        "bob must be able to decrypt the re-transmitted pre-onboarding content"
    );

    // Phase 10 — Sanity: alice can still decrypt all three ciphertexts
    // (her view is consistent across the lazy onboarding event).
    let alice_pre = alice
        .try_decrypt_content(doc.dupe(), pre_encrypted.encrypted_content())
        .await
        .unwrap();
    assert_eq!(alice_pre, pre_content);
    let alice_post = alice
        .try_decrypt_content(doc.dupe(), post_encrypted.encrypted_content())
        .await
        .unwrap();
    assert_eq!(alice_post, post_content);
    let alice_retrans = alice
        .try_decrypt_content(doc.dupe(), retrans_encrypted.encrypted_content())
        .await
        .unwrap();
    assert_eq!(alice_retrans, pre_content);
}
