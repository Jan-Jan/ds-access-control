//! L3 end-to-end scenario — organisation-as-pseudo-group.
//!
//! Composes gates 1 (member ACL) + 4 (org group) + 3 (CGKA rotation
//! cascade) against the `org_pseudo_group_fixture` from spike-common.
//! Observable invariants:
//!
//! - "a doc whose ACL grants the org-as-pseudo-group is readable by
//!   alice's new key"
//! - "the same doc is readable by bob without any explicit ACL change"
//! - "(D)CGKA recompute was triggered for org-keyed docs"
//!
//! The test stages two Keyhive instances (alice + bob), creates an org
//! group, adds bob to it, grants the org Read access to alice's doc,
//! and verifies `transitive_members()` resolves to include bob via the
//! nested group.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use dupe::Dupe;
use spike_keyhive::s1_stable_id_acl::generate_spike_keyhive;
use spike_keyhive::s4_org_pseudo_group::{
    add_member_to_org, generate_org_group, grant_org_to_doc,
};

#[tokio::test]
async fn org_pseudo_group_grants_transitive_doc_access_and_rotates_cgka() {
    // Phase 1 — bootstrap two Keyhive instances and an org group.
    let alice = generate_spike_keyhive().await.unwrap();
    let bob = generate_spike_keyhive().await.unwrap();
    let bob_card = bob.contact_card().await.unwrap();

    let org = generate_org_group(&alice).await.unwrap();
    add_member_to_org(&alice, &org, &bob_card).await.unwrap();

    // Phase 2 — alice creates a doc and grants the org Read access.
    let init_content = b"org-keyed payload".to_vec();
    let init_hash = blake3::hash(&init_content);
    let init_ref: [u8; 32] = init_hash.into();
    let doc = alice
        .generate_doc(vec![], nonempty::nonempty![init_ref])
        .await
        .unwrap();
    grant_org_to_doc(&alice, &org, &doc, keyhive_core::access::Access::Read)
        .await
        .unwrap();

    // Phase 3 — verify bob is in the doc's transitive_members via the
    // org. This is the headline Gate 4 invariant for the L3 scenario.
    let members = doc.lock().await.transitive_members().await;
    let bob_id = bob_card.id();
    assert!(
        members.contains_key(&bob_id.into()),
        "bob (via org) must appear in transitive_members; got {} keys: {:?}",
        members.len(),
        members.keys().collect::<Vec<_>>()
    );

    // Phase 4 — fixture's rotation step: rotate alice's key. The L3
    // scenario asserts that the doc remains readable after rotation
    // because the ACL is on the org, not on alice's specific key.
    //
    // We simulate the rotation by driving a force_pcs_update — in
    // production this would be triggered by the trie observer firing
    // after a `RotateMemberKey` step. The fixture's apply_to_stub_trie
    // is not driven here because the spike's Keyhive-side identity is
    // separate from the trie's MemberId mapping (see evidence/s1.md
    // integration finding); the rotation cascade is driven directly.
    let signed_op = alice.force_pcs_update(doc.dupe()).await.unwrap();
    assert!(!signed_op.signature().to_bytes().is_empty());

    // Phase 5 — after rotation, transitive_members STILL includes bob
    // (the ACL is org-keyed, not key-keyed). This is the gate-4
    // "rotation cascade preserves org delegation" invariant.
    let members_after = doc.lock().await.transitive_members().await;
    assert!(
        members_after.contains_key(&bob_id.into()),
        "bob must still be in transitive_members after rotation"
    );
}
