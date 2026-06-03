#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

// L2 test: gate 4 — org-as-pseudo-group principal.
//
// Flow A: doc ACL grants Principal::Org via GroupMember::Group; alice and bob
//         are members of the org group; both have transitive access to the doc.
// Flow C: alice's p2p_member_key rotates; the resolver reflects the new key;
//         effective_member_keys returns alice's NEW key without changing the
//         doc ACL.
//
// Evidence file: spike-p2panda/src/evidence/s4.md

use std::collections::HashSet;

use ed25519_dalek::SigningKey;
use spike_common::identity::{MemberId, OrgKey, P2pMemberKey};
use spike_common::stub_trie::StubTrie;
use spike_p2panda::s4_org_pseudo_group::{
    AuthMemberId, G4GroupState, OrgPseudoGroupAdapter, effective_member_keys,
};
use p2panda_auth::Access;

// ---------------------------------------------------------------------------
// Fixture constants
// ---------------------------------------------------------------------------

/// Alice: MemberId([0xa1; 32]).
const ALICE_ID: MemberId = MemberId([0xa1u8; 32]);
/// Bob:   MemberId([0xb1; 32]).
const BOB_ID: MemberId = MemberId([0xb1u8; 32]);
/// Org manager (synthetic): MemberId([0x07; 32]).
const ORG_MANAGER_ID: MemberId = MemberId([0x07u8; 32]);

/// Org group ID (same namespace as member IDs in this spike).
const ORG_GID: AuthMemberId = AuthMemberId([0x07u8; 32]);
/// Doc group ID.
const DOC_GID: AuthMemberId = AuthMemberId([0x09u8; 32]);
/// Doc manager ID.
const DOC_MANAGER_ID: AuthMemberId = AuthMemberId([0xddu8; 32]);

/// Signing key seed bytes for test keys.
const ALICE_SEED: [u8; 32] = {
    let mut s = [0u8; 32];
    s[0] = 0xa1;
    s
};
const BOB_SEED: [u8; 32] = {
    let mut s = [0u8; 32];
    s[0] = 0xb1;
    s
};
const ORG_SEED: [u8; 32] = {
    let mut s = [0u8; 32];
    s[0] = 0x07;
    s
};
const ALICE_ROTATED_SEED: [u8; 32] = {
    let mut s = [0u8; 32];
    s[0] = 0xa2; // rotated
    s
};

// ---------------------------------------------------------------------------
// Helper: build the p2panda-auth GroupCrdt state for the org-as-pseudo-group
// ---------------------------------------------------------------------------

/// Build the CRDT state with:
///   - ORG group: org_manager (Manage) + alice (Manage) + bob (Manage)
///   - DOC group: doc_manager (Manage) + ORG group (Read)
fn build_org_group_state() -> G4GroupState {
    let alice_auth = AuthMemberId::from(ALICE_ID);
    let bob_auth = AuthMemberId::from(BOB_ID);

    let (state, _doc_gid) = OrgPseudoGroupAdapter::build(
        ORG_GID,
        AuthMemberId::from(ORG_MANAGER_ID),
        &[alice_auth, bob_auth],
        DOC_GID,
        DOC_MANAGER_ID,
        Access::read(),
        0,
    )
    .expect("OrgPseudoGroupAdapter::build should succeed");

    state
}

// ---------------------------------------------------------------------------
// Helper: build a StubTrie with alice and bob registered
// ---------------------------------------------------------------------------

fn build_trie_with_alice_and_bob() -> StubTrie {
    let alice_key = P2pMemberKey(SigningKey::from_bytes(&ALICE_SEED).verifying_key());
    let bob_key = P2pMemberKey(SigningKey::from_bytes(&BOB_SEED).verifying_key());
    let org_key = OrgKey(SigningKey::from_bytes(&ORG_SEED).verifying_key());

    StubTrie::new()
        .add_member(ALICE_ID, alice_key, vec![])
        .add_member(BOB_ID, bob_key, vec![])
        .with_org_key(org_key)
}

// ---------------------------------------------------------------------------
// Flow A: doc ACL grants Principal::Org; alice and bob both have access
// ---------------------------------------------------------------------------

/// Flow A test.
///
/// Verifies:
/// 1. The CRDT state has both alice and bob as transitive members of DOC_GID.
/// 2. `effective_member_keys` resolves both alice's and bob's P2pMemberKey from
///    the trie via the org-nested-group path.
/// 3. Neither alice nor bob was ever directly added to DOC_GID — access is
///    purely via the org pseudo-group.
#[test]
fn flow_a_org_principal_grants_both_members_access() {
    let state = build_org_group_state();
    let trie = build_trie_with_alice_and_bob();

    // 1. CRDT membership resolution: both alice and bob should be transitive members.
    let members = state.members(DOC_GID);
    let member_ids: HashSet<AuthMemberId> = members.iter().map(|(id, _)| *id).collect();

    assert!(
        member_ids.contains(&AuthMemberId::from(ALICE_ID)),
        "alice should be a transitive member of DOC_GID via ORG_GID group"
    );
    assert!(
        member_ids.contains(&AuthMemberId::from(BOB_ID)),
        "bob should be a transitive member of DOC_GID via ORG_GID group"
    );

    // 2. effective_member_keys resolves the key set from the trie.
    let keys = effective_member_keys(&state, DOC_GID, &trie)
        .expect("effective_member_keys should succeed");

    let alice_key = P2pMemberKey(SigningKey::from_bytes(&ALICE_SEED).verifying_key());
    let bob_key = P2pMemberKey(SigningKey::from_bytes(&BOB_SEED).verifying_key());

    assert!(
        keys.contains(&alice_key),
        "alice's P2pMemberKey should be in the effective key set"
    );
    assert!(
        keys.contains(&bob_key),
        "bob's P2pMemberKey should be in the effective key set"
    );
    assert_eq!(
        keys.len(),
        // doc_manager + alice + bob — org_manager is also in the CRDT
        // but NOT in the trie (ORG_MANAGER_ID has no trie entry) → skipped.
        // DOC_MANAGER_ID is also not in trie → skipped.
        2,
        "exactly alice and bob should appear in effective_member_keys (org_manager and doc_manager are not in trie)"
    );

    println!("Flow A: effective key set has {} keys (alice + bob)", keys.len());
}

// ---------------------------------------------------------------------------
// Flow C: alice's p2p_member_key rotates; alice's NEW key is in the effective set
// ---------------------------------------------------------------------------

/// Flow C test.
///
/// Verifies:
/// 1. Before rotation: alice's key K1 is in the effective set.
/// 2. After rotating alice's key to K2 in the trie:
///    - The doc ACL (CRDT state) is unchanged — no ACL mutation needed.
///    - `effective_member_keys` now returns K2 (not K1) for alice.
/// 3. The key change is tracked via the resolver, not via a CRDT operation.
#[test]
fn flow_c_org_principal_tracks_alice_rotation() {
    let state = build_org_group_state();
    let trie = build_trie_with_alice_and_bob();

    let alice_key_k1 = P2pMemberKey(SigningKey::from_bytes(&ALICE_SEED).verifying_key());
    let alice_key_k2 = P2pMemberKey(SigningKey::from_bytes(&ALICE_ROTATED_SEED).verifying_key());

    // Before rotation: K1 should be present.
    let keys_before = effective_member_keys(&state, DOC_GID, &trie)
        .expect("effective_member_keys should succeed before rotation");
    assert!(
        keys_before.contains(&alice_key_k1),
        "alice's K1 should be in the effective set before rotation"
    );
    assert!(
        !keys_before.contains(&alice_key_k2),
        "alice's K2 should NOT be in the effective set before rotation"
    );

    // Rotate alice's key in the trie (simulating a trie write).
    // The CRDT state is NOT modified — this is the "no ACL mutation" property.
    let trie_after_rotation = trie.stub_rotate_member_key(&ALICE_ID, alice_key_k2);

    // After rotation: K2 should be present; K1 should be gone.
    let keys_after = effective_member_keys(&state, DOC_GID, &trie_after_rotation)
        .expect("effective_member_keys should succeed after rotation");
    assert!(
        keys_after.contains(&alice_key_k2),
        "alice's K2 should be in the effective set after rotation"
    );
    assert!(
        !keys_after.contains(&alice_key_k1),
        "alice's K1 should NOT be in the effective set after rotation (stale key evicted)"
    );

    // Confirm: the CRDT state still lists alice as a member (by stable ID).
    // The org ACL does not change on key rotation.
    let members_after = state.members(DOC_GID);
    let member_ids_after: HashSet<AuthMemberId> = members_after.iter().map(|(id, _)| *id).collect();
    assert!(
        member_ids_after.contains(&AuthMemberId::from(ALICE_ID)),
        "alice's stable ID should still be a CRDT member after key rotation"
    );

    println!(
        "Flow C: key before={:?} key after={:?}",
        &alice_key_k1.0.as_bytes()[..4],
        &alice_key_k2.0.as_bytes()[..4]
    );
}
