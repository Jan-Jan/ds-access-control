//! L3 end-to-end scenario — revocation.
//!
//! Composes gates 1 (member ACL) + 2 (containment wrapper) + 3 (CGKA
//! rotation) against the `revocation_fixture` from spike-common. The
//! observable invariants from the fixture:
//!
//! - "bob's device cannot decrypt new doc payloads after revocation"
//! - "alice's device can still decrypt the doc"
//! - "(D)CGKA has advanced one epoch"
//!
//! This test validates the spirit of all three by running two Keyhive
//! instances against each other in-process with state sync via
//! `static_events_for_agent` + `ingest_unsorted_static_events`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use dupe::Dupe;
use keyhive_core::access::Access;
use keyhive_core::principal::agent::Agent;
use keyhive_core::principal::membered::Membered;
use spike_keyhive::s1_stable_id_acl::generate_spike_keyhive;

#[tokio::test]
async fn revocation_kills_forward_security_for_revoked_peer() {
    // Phase 1 — bootstrap: alice + bob.
    let alice = generate_spike_keyhive().await.unwrap();
    let bob = generate_spike_keyhive().await.unwrap();

    // Alice creates a doc.
    let init_content = b"pre-revoke content".to_vec();
    let init_hash = blake3::hash(&init_content);
    let init_ref: [u8; 32] = init_hash.into();
    let doc = alice
        .generate_doc(vec![], nonempty::nonempty![init_ref])
        .await
        .unwrap();
    let doc_id = doc.lock().await.doc_id();

    // Alice ingests bob's contact card and adds him to the doc.
    let bob_card = bob.contact_card().await.unwrap();
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

    // Phase 2 — alice encrypts a payload. Sync to bob, who decrypts.
    let pre_encrypted = alice
        .try_encrypt_content(doc.dupe(), &init_ref, &vec![], &init_content)
        .await
        .unwrap();
    let bob_active_agent: Agent<_, _, _, _> = bob.active().lock().await.clone().into();
    let alice_events = alice.static_events_for_agent(&bob_active_agent).await;
    bob.ingest_unsorted_static_events(alice_events.into_values().collect())
        .await;

    let doc_on_bob = bob.get_document(doc_id).await.unwrap();
    let pre_plain = bob
        .try_decrypt_content(doc_on_bob.dupe(), pre_encrypted.encrypted_content())
        .await
        .unwrap();
    assert_eq!(pre_plain, init_content);

    // Phase 3 — revoke bob. The Keyhive revocation drives the CGKA op
    // we need for forward secrecy.
    let bob_identifier = bob.id().into();
    alice
        .revoke_member(
            bob_identifier,
            true, // retain other members
            &Membered::Document(doc_id, doc.dupe()),
        )
        .await
        .unwrap();

    // Phase 4 — alice encrypts post-revoke content. Sync to bob.
    let post_content = b"post-revoke content".to_vec();
    let post_hash = blake3::hash(&post_content);
    let post_ref: [u8; 32] = post_hash.into();
    let post_encrypted = alice
        .try_encrypt_content(
            doc.dupe(),
            &post_ref,
            &vec![init_ref],
            &post_content,
        )
        .await
        .unwrap();

    // bob receives the events too (revocation + new CGKA op).
    let post_events = alice.static_events_for_agent(&bob_active_agent).await;
    bob.ingest_unsorted_static_events(post_events.into_values().collect())
        .await;

    // Phase 5 — assert forward security: bob CANNOT decrypt post-revoke.
    let decrypt_result = bob
        .try_decrypt_content(doc_on_bob.dupe(), post_encrypted.encrypted_content())
        .await;
    assert!(
        decrypt_result.is_err(),
        "bob must NOT be able to decrypt post-revoke content; got {:?}",
        decrypt_result.map(|p| String::from_utf8_lossy(&p).into_owned()),
    );

    // And alice can still decrypt her own pre+post content.
    let alice_re_pre = alice
        .try_decrypt_content(doc.dupe(), pre_encrypted.encrypted_content())
        .await
        .unwrap();
    assert_eq!(alice_re_pre, init_content);
    let alice_re_post = alice
        .try_decrypt_content(doc.dupe(), post_encrypted.encrypted_content())
        .await
        .unwrap();
    assert_eq!(alice_re_post, post_content);
}
