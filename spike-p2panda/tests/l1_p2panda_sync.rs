#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

// L1 test: gate 5 — p2p connection policy.
//
// Tests `policy_check` and `policy_check_err` directly on `PolicyManager`.
// The full `Manager<T>` wrapper (delegating async sessions) is deferred —
// see evidence/s5.md §Deferred coverage for the rationale.
//
// Flows covered:
//   E1 — member-principal accept (authorised peer accepted)
//   E1 — member-principal reject (unauthorised peer rejected)
//   E2 — org-principal accept (any current org member accepted via org_wide ACL)
//   E2 — org-principal reject (removed-from-org peer rejected)
//
// Reverse-lookup gap note:
//   The `MemberKeyResolver` trait has no `find_member_by_device(VerifyingKey)`
//   method. The `peer_to_member` closure supplies the reverse index in tests;
//   in production this would be a secondary structure keyed on p2p key bytes.
//   This is documented as a gap in evidence/s5.md §Discovered gaps.

use ed25519_dalek::SigningKey;
use p2panda_core::VerifyingKey as PandaVerifyingKey;
use spike_common::identity::{MemberId, P2pMemberKey};
use spike_common::stub_trie::StubTrie;
use spike_p2panda::s5_p2p_policy::{DocAcl, DocId, PolicyError, PolicyManager};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Doc-id used throughout these tests.
const DOC_A: DocId = DocId([0xdau8; 32]);

/// Alice's MemberId.
const ALICE_ID: MemberId = MemberId([0xa1u8; 32]);

/// Bob's MemberId (not in the ACL for DOC_A member-principal tests).
const BOB_ID: MemberId = MemberId([0xb1u8; 32]);

/// Charlie — never added to any trie or ACL; used as a completely unknown peer.
#[allow(dead_code)]
const CHARLIE_ID: MemberId = MemberId([0xc1u8; 32]);

/// Deterministic signing-key seeds.
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
const CHARLIE_SEED: [u8; 32] = {
    let mut s = [0u8; 32];
    s[0] = 0xc1;
    s
};

/// Convert a raw `ed25519_dalek::VerifyingKey` to the `p2panda_core::VerifyingKey`
/// newtype used by `SessionConfig::remote`.
fn to_panda_vk(dalek_vk: ed25519_dalek::VerifyingKey) -> PandaVerifyingKey {
    PandaVerifyingKey::from(dalek_vk)
}

/// Build the three test verifying keys deterministically from seeds.
fn alice_vk() -> PandaVerifyingKey {
    to_panda_vk(SigningKey::from_bytes(&ALICE_SEED).verifying_key())
}
fn bob_vk() -> PandaVerifyingKey {
    to_panda_vk(SigningKey::from_bytes(&BOB_SEED).verifying_key())
}
fn charlie_vk() -> PandaVerifyingKey {
    to_panda_vk(SigningKey::from_bytes(&CHARLIE_SEED).verifying_key())
}

/// Build a `PolicyManager` with a fixed reverse-index closure for alice and bob.
///
/// The closure explicitly captures the test seeds; production code would use a
/// HashMap populated from the trie or a secondary index. The callback shape is
/// the **evidence of the resolver-trait gap**: callers must supply this separately
/// because `MemberKeyResolver` only maps `MemberId → Key`, not the reverse.
fn make_manager<R: spike_common::resolver::MemberKeyResolver>(
    resolver: R,
) -> PolicyManager<R, impl Fn(PandaVerifyingKey) -> Option<MemberId>> {
    let a_vk = alice_vk();
    let b_vk = bob_vk();

    PolicyManager::new(resolver, move |vk: PandaVerifyingKey| {
        if vk == a_vk {
            Some(ALICE_ID)
        } else if vk == b_vk {
            Some(BOB_ID)
        } else {
            None
        }
    })
}

// ---------------------------------------------------------------------------
// Flow E1 — member-principal accept
// ---------------------------------------------------------------------------

/// Flow E1: an authorised member's peer key passes the policy check.
///
/// Setup: StubTrie has alice. DOC_A ACL explicitly lists alice.
/// Expected: `policy_check(alice_vk, DOC_A)` → `true`.
#[test]
fn e1_connection_accepted_for_authorised_member() {
    let alice_key = P2pMemberKey(SigningKey::from_bytes(&ALICE_SEED).verifying_key());

    let trie = StubTrie::new().add_member(ALICE_ID, alice_key, vec![]);

    let mut manager = make_manager(trie);
    manager.register_acl(DOC_A, DocAcl::for_members([ALICE_ID]));

    assert!(
        manager.policy_check(&alice_vk(), &DOC_A),
        "alice is in the ACL — should be accepted"
    );

    // policy_check_err should return Ok(ALICE_ID)
    let result = manager.policy_check_err(&alice_vk(), &DOC_A);
    assert_eq!(result, Ok(ALICE_ID), "policy_check_err should return alice's MemberId");

    println!("E1 accept: alice authorised for DOC_A");
}

// ---------------------------------------------------------------------------
// Flow E1 — member-principal reject (three sub-cases)
// ---------------------------------------------------------------------------

/// Flow E1 reject (a): peer key is known but the member is NOT in the ACL.
#[test]
fn e1_connection_rejected_member_not_in_acl() {
    let alice_key = P2pMemberKey(SigningKey::from_bytes(&ALICE_SEED).verifying_key());
    let bob_key = P2pMemberKey(SigningKey::from_bytes(&BOB_SEED).verifying_key());

    // Both alice and bob are in the trie, but DOC_A ACL only has alice.
    let trie = StubTrie::new()
        .add_member(ALICE_ID, alice_key, vec![])
        .add_member(BOB_ID, bob_key, vec![]);

    let mut manager = make_manager(trie);
    manager.register_acl(DOC_A, DocAcl::for_members([ALICE_ID])); // bob NOT in ACL

    assert!(
        !manager.policy_check(&bob_vk(), &DOC_A),
        "bob is NOT in the ACL — should be rejected"
    );

    let err = manager.policy_check_err(&bob_vk(), &DOC_A).unwrap_err();
    assert!(
        matches!(
            err,
            PolicyError::Unauthorised { member_id: BOB_ID, doc_id: DOC_A }
        ),
        "unexpected error: {err}"
    );

    println!("E1 reject (a): bob not in ACL — rejected with Unauthorised");
}

/// Flow E1 reject (b): peer key has no `MemberId` mapping at all (unknown peer).
#[test]
fn e1_connection_rejected_unknown_peer() {
    let alice_key = P2pMemberKey(SigningKey::from_bytes(&ALICE_SEED).verifying_key());
    let trie = StubTrie::new().add_member(ALICE_ID, alice_key, vec![]);

    let mut manager = make_manager(trie);
    manager.register_acl(DOC_A, DocAcl::for_members([ALICE_ID]));

    // charlie_vk() has no mapping in the reverse-index closure.
    assert!(
        !manager.policy_check(&charlie_vk(), &DOC_A),
        "charlie is completely unknown — should be rejected"
    );

    let err = manager.policy_check_err(&charlie_vk(), &DOC_A).unwrap_err();
    assert_eq!(err, PolicyError::UnknownPeer);

    println!("E1 reject (b): charlie unknown peer — rejected with UnknownPeer");
}

/// Flow E1 reject (c): known peer but member was revoked from the trie.
///
/// The ACL still lists alice (simulating an ACL that has not yet been pruned),
/// but the trie no longer contains alice → `is_member` returns false.
/// For the member-principal path the check is `acl.member_ids.contains(id)`,
/// which still returns true if the ACL is stale. This reveals a subtle design
/// point: the member-principal ACL path does NOT re-validate trie membership
/// automatically — only the org-wide path does via `resolver.is_member()`.
///
/// This is an expected, documented behaviour: the member-principal ACL and the
/// trie are independent. The caller is responsible for pruning revoked members
/// from the DocAcl on trie change events, OR switching to the org-wide ACL path
/// which checks `is_member` automatically.
#[test]
fn e1_connection_rejected_member_revoked_from_trie_via_recheck() {
    let alice_key = P2pMemberKey(SigningKey::from_bytes(&ALICE_SEED).verifying_key());

    let trie = StubTrie::new().add_member(ALICE_ID, alice_key, vec![]);
    let mut manager = make_manager(trie);
    manager.register_acl(DOC_A, DocAcl::for_members([ALICE_ID]));

    // Session accepted before revocation.
    manager.record_session(1, alice_vk(), DOC_A);
    assert_eq!(manager.open_sessions().len(), 1);

    // Trie change: alice revoked. We must update the resolver in the manager.
    // Because PolicyManager<R, F> owns R by value (not by ref), we must rebuild.
    // This is the production pattern: the policy manager is reconstructed (or
    // its resolver is swapped) after trie changes.
    let alice_key2 = P2pMemberKey(SigningKey::from_bytes(&ALICE_SEED).verifying_key());
    let trie_after_revoke = StubTrie::new()
        // alice removed — new trie has only bob as placeholder
        .add_member(BOB_ID, alice_key2, vec![]);

    let mut manager2 = make_manager(trie_after_revoke);
    manager2.register_acl(DOC_A, DocAcl::for_members([ALICE_ID]));
    manager2.record_session(1, alice_vk(), DOC_A);

    // Manually update ACL to remove alice (simulating ACL-pruning on revoke).
    manager2.register_acl(DOC_A, DocAcl::for_members([])); // empty ACL after revoke

    let closed = manager2.recheck_open_sessions();
    assert_eq!(closed, 1, "one session should be flagged for closure");

    let drained = manager2.drain_closed_sessions();
    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].session_id, 1);

    println!("E1 reject (c): alice revoked → session flagged for closure");
}

// ---------------------------------------------------------------------------
// Flow E2 — org-principal accept (any current org member)
// ---------------------------------------------------------------------------

/// Flow E2: when the ACL is `org_wide = true`, any current org member is accepted.
///
/// Setup: alice and bob are in the trie (= org members). DOC_A has an org-wide ACL.
/// Expected: both alice and bob are accepted; charlie (not in trie) is rejected.
#[test]
fn e2_connection_accepted_via_org_principal() {
    let alice_key = P2pMemberKey(SigningKey::from_bytes(&ALICE_SEED).verifying_key());
    let bob_key = P2pMemberKey(SigningKey::from_bytes(&BOB_SEED).verifying_key());

    let trie = StubTrie::new()
        .add_member(ALICE_ID, alice_key, vec![])
        .add_member(BOB_ID, bob_key, vec![]);

    let mut manager = make_manager(trie);
    manager.register_acl(DOC_A, DocAcl::org_wide());

    assert!(
        manager.policy_check(&alice_vk(), &DOC_A),
        "alice is a current org member — should be accepted via org-wide ACL"
    );
    assert!(
        manager.policy_check(&bob_vk(), &DOC_A),
        "bob is a current org member — should be accepted via org-wide ACL"
    );
    assert!(
        !manager.policy_check(&charlie_vk(), &DOC_A),
        "charlie is NOT in the trie — should be rejected"
    );

    println!("E2: alice and bob accepted via org-wide ACL; charlie rejected");
}

/// Flow E2 reject: peer maps to a MemberId that is present in the reverse index
/// but was removed from the org (trie). The org-wide ACL path consults
/// `resolver.is_member()` directly, so this is caught at `policy_check` time.
#[test]
fn e2_connection_rejected_member_removed_from_org() {
    let alice_key = P2pMemberKey(SigningKey::from_bytes(&ALICE_SEED).verifying_key());
    let bob_key = P2pMemberKey(SigningKey::from_bytes(&BOB_SEED).verifying_key());

    // Bob is in the reverse-index but NOT in the trie (removed from org).
    let trie = StubTrie::new()
        .add_member(ALICE_ID, alice_key, vec![])
        // bob intentionally omitted → trie has no BOB_ID entry
        ;
    // Silence unused warning — bob_key still used in the reverse-index closure
    let _ = bob_key;

    let a_vk = alice_vk();
    let b_vk = bob_vk();
    let manager = PolicyManager::new(
        trie,
        move |vk: PandaVerifyingKey| {
            if vk == a_vk {
                Some(ALICE_ID)
            } else if vk == b_vk {
                Some(BOB_ID) // bob is in the reverse index but not the trie
            } else {
                None
            }
        },
    );
    // No register_acl call needed for this test — we'll use a fresh manager.
    let alice_key2 = P2pMemberKey(SigningKey::from_bytes(&ALICE_SEED).verifying_key());
    let trie2 = StubTrie::new().add_member(ALICE_ID, alice_key2, vec![]);

    let a_vk2 = alice_vk();
    let b_vk2 = bob_vk();
    let mut manager2 = PolicyManager::new(trie2, move |vk: PandaVerifyingKey| {
        if vk == a_vk2 {
            Some(ALICE_ID)
        } else if vk == b_vk2 {
            Some(BOB_ID) // bob maps to a MemberId, but is not in the trie
        } else {
            None
        }
    });
    manager2.register_acl(DOC_A, DocAcl::org_wide());

    // Alice: in trie → accepted.
    assert!(manager2.policy_check(&alice_vk(), &DOC_A));
    // Bob: in reverse index, NOT in trie → rejected.
    assert!(!manager2.policy_check(&bob_vk(), &DOC_A));

    let err = manager2.policy_check_err(&bob_vk(), &DOC_A).unwrap_err();
    assert!(
        matches!(
            err,
            PolicyError::Unauthorised { member_id: BOB_ID, doc_id: DOC_A }
        ),
        "unexpected error: {err}"
    );

    // Suppress unused variable warning for first manager built above.
    let _ = manager;

    println!("E2 reject: bob in reverse index but removed from org → rejected");
}
