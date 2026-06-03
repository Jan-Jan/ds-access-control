#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

// L2 test: gate 5 — Flows F1 and F2 (session termination on trie change).
//
// F1 — Member-principal: session opened for alice; alice revoked → session
//      flagged for closure on next `recheck_open_sessions()` call.
//
// F2 — Org-principal: alice and bob have open sessions via org-wide ACL;
//      alice is removed from the org (trie) → only alice's session is flagged;
//      bob's session is unchanged.
//
// Design note — pull model:
//   The `StubTrie` is pull-only (no push notifications). `PolicyManager` therefore
//   exposes `recheck_open_sessions()` which the caller invokes after a trie change.
//   This simulates the minimal hook the Phase 3 integration layer must provide.
//   A reactive push-based model (trie → policy manager callback) is documented as
//   a gap in evidence/s5.md §Discovered gaps.
//
// Design note — async session close deferred:
//   Sending `ToSync::Close` to a real p2panda-sync session requires `async` +
//   an inner `Manager<T>` reference. This spike tests the *flagging* logic only;
//   the actual `.close()` call is deferred. See evidence/s5.md §Deferred coverage.

use ed25519_dalek::SigningKey;
use p2panda_core::VerifyingKey as PandaVerifyingKey;
use spike_common::identity::{MemberId, P2pMemberKey};
use spike_common::stub_trie::StubTrie;
use spike_p2panda::s5_p2p_policy::{DocAcl, DocId, PolicyManager};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const DOC_A: DocId = DocId([0xdau8; 32]);

const ALICE_ID: MemberId = MemberId([0xa1u8; 32]);
const BOB_ID: MemberId = MemberId([0xb1u8; 32]);

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

fn alice_panda_vk() -> PandaVerifyingKey {
    PandaVerifyingKey::from(SigningKey::from_bytes(&ALICE_SEED).verifying_key())
}
fn bob_panda_vk() -> PandaVerifyingKey {
    PandaVerifyingKey::from(SigningKey::from_bytes(&BOB_SEED).verifying_key())
}

/// Build a `PolicyManager` with a reverse-index closure covering alice and bob.
fn make_manager_ab<R: spike_common::resolver::MemberKeyResolver>(
    resolver: R,
) -> PolicyManager<R, impl Fn(PandaVerifyingKey) -> Option<MemberId>> {
    let a_vk = alice_panda_vk();
    let b_vk = bob_panda_vk();
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
// Flow F1 — member-principal: session terminated on revocation
// ---------------------------------------------------------------------------

/// Flow F1: alice has an open member-principal session for DOC_A.
/// After alice is revoked from the trie + ACL, `recheck_open_sessions` flags her
/// session for closure.
#[test]
fn f1_terminate_session_on_member_revocation() {
    let alice_key = P2pMemberKey(SigningKey::from_bytes(&ALICE_SEED).verifying_key());
    let bob_key = P2pMemberKey(SigningKey::from_bytes(&BOB_SEED).verifying_key());

    // Initial state: alice and bob both authorised.
    let trie = StubTrie::new()
        .add_member(ALICE_ID, alice_key, vec![])
        .add_member(BOB_ID, bob_key, vec![]);

    let mut manager = make_manager_ab(trie.clone());
    manager.register_acl(DOC_A, DocAcl::for_members([ALICE_ID, BOB_ID]));

    // Open sessions for both alice and bob.
    manager.record_session(1, alice_panda_vk(), DOC_A);
    manager.record_session(2, bob_panda_vk(), DOC_A);
    assert_eq!(manager.open_sessions().len(), 2);

    // Verify both sessions are accepted at this point.
    assert!(manager.policy_check(&alice_panda_vk(), &DOC_A));
    assert!(manager.policy_check(&bob_panda_vk(), &DOC_A));

    // Trie change: alice is revoked.
    // Phase 3 pattern: policy manager is reconstructed with the updated resolver.
    // In production, the policy manager would hold a `Arc<RwLock<Trie>>` or similar
    // live reference; here we rebuild with a new StubTrie.
    let trie_after_revoke = trie.stub_revoke(&ALICE_ID);
    let alice_key2 = P2pMemberKey(SigningKey::from_bytes(&ALICE_SEED).verifying_key());
    let bob_key2 = P2pMemberKey(SigningKey::from_bytes(&BOB_SEED).verifying_key());
    let trie_after_revoke = trie_after_revoke
        .stub_revoke(&ALICE_ID) // ensure alice is gone (idempotent)
        ;
    let _ = (alice_key2, bob_key2); // suppress unused warnings

    let mut manager2 = make_manager_ab(trie_after_revoke);
    // ACL also updated to remove alice (member-principal path requires caller to prune ACL).
    manager2.register_acl(DOC_A, DocAcl::for_members([BOB_ID]));

    // Re-add the sessions to the new manager (simulates session state transfer).
    manager2.record_session(1, alice_panda_vk(), DOC_A);
    manager2.record_session(2, bob_panda_vk(), DOC_A);

    // Fire trie-change event (manual, pull model).
    let newly_closed = manager2.recheck_open_sessions();
    assert_eq!(newly_closed, 1, "exactly one session should be flagged (alice's)");

    // Verify which sessions are flagged.
    let sessions = manager2.open_sessions();
    let alice_session = sessions.iter().find(|s| s.session_id == 1).expect("session 1 exists");
    let bob_session = sessions.iter().find(|s| s.session_id == 2).expect("session 2 exists");

    assert!(alice_session.should_close, "alice's session should be flagged for closure");
    assert!(!bob_session.should_close, "bob's session should NOT be flagged");

    // Drain and verify.
    let closed = manager2.drain_closed_sessions();
    assert_eq!(closed.len(), 1);
    assert_eq!(closed[0].session_id, 1);
    assert_eq!(manager2.open_sessions().len(), 1, "only bob's session remains");

    println!(
        "F1: alice revoked → session {} flagged; bob session {} unchanged",
        closed[0].session_id,
        manager2.open_sessions()[0].session_id,
    );
}

/// Flow F1 variant: calling `recheck_open_sessions` twice does not
/// double-count already-flagged sessions.
#[test]
fn f1_recheck_idempotent_on_already_flagged_sessions() {
    let alice_key = P2pMemberKey(SigningKey::from_bytes(&ALICE_SEED).verifying_key());
    let trie = StubTrie::new().add_member(ALICE_ID, alice_key, vec![]);
    // ACL is empty — alice is not in the ACL, so policy check fails immediately.
    let mut manager = make_manager_ab(trie);
    manager.register_acl(DOC_A, DocAcl::for_members([]));
    manager.record_session(99, alice_panda_vk(), DOC_A);

    let first = manager.recheck_open_sessions();
    assert_eq!(first, 1);

    // Second recheck: the session is already flagged; should return 0.
    let second = manager.recheck_open_sessions();
    assert_eq!(second, 0, "already-flagged sessions must not be double-counted");

    println!("F1 idempotent: recheck returns 0 on already-flagged sessions");
}

// ---------------------------------------------------------------------------
// Flow F2 — org-principal: only the removed member's session is terminated
// ---------------------------------------------------------------------------

/// Flow F2: alice and bob have open sessions via an org-wide ACL.
/// Alice is removed from the org (trie).
/// `recheck_open_sessions` flags alice's session but leaves bob's intact.
#[test]
fn f2_terminate_org_session_on_member_removal() {
    let alice_key = P2pMemberKey(SigningKey::from_bytes(&ALICE_SEED).verifying_key());
    let bob_key = P2pMemberKey(SigningKey::from_bytes(&BOB_SEED).verifying_key());

    let trie = StubTrie::new()
        .add_member(ALICE_ID, alice_key, vec![])
        .add_member(BOB_ID, bob_key, vec![]);

    let mut manager = make_manager_ab(trie.clone());
    manager.register_acl(DOC_A, DocAcl::org_wide());

    // Open sessions for both.
    manager.record_session(10, alice_panda_vk(), DOC_A);
    manager.record_session(20, bob_panda_vk(), DOC_A);

    // Both accepted before removal.
    assert!(manager.policy_check(&alice_panda_vk(), &DOC_A));
    assert!(manager.policy_check(&bob_panda_vk(), &DOC_A));

    // Trie change: alice removed from the org.
    let trie_after_removal = trie.stub_revoke(&ALICE_ID);

    // Rebuild manager with updated resolver (same pattern as F1).
    let mut manager2 = make_manager_ab(trie_after_removal);
    manager2.register_acl(DOC_A, DocAcl::org_wide()); // org-wide — no ACL pruning needed

    // Transfer sessions.
    manager2.record_session(10, alice_panda_vk(), DOC_A);
    manager2.record_session(20, bob_panda_vk(), DOC_A);

    // org-wide path: alice not in trie anymore → policy_check returns false.
    assert!(!manager2.policy_check(&alice_panda_vk(), &DOC_A));
    assert!(manager2.policy_check(&bob_panda_vk(), &DOC_A));

    let newly_closed = manager2.recheck_open_sessions();
    assert_eq!(newly_closed, 1, "only alice's session should be flagged");

    let sessions = manager2.open_sessions();
    let alice_s = sessions.iter().find(|s| s.session_id == 10).unwrap();
    let bob_s = sessions.iter().find(|s| s.session_id == 20).unwrap();
    assert!(alice_s.should_close, "alice's session should be flagged");
    assert!(!bob_s.should_close, "bob's session should be unchanged");

    let closed = manager2.drain_closed_sessions();
    assert_eq!(closed.len(), 1);
    assert_eq!(closed[0].session_id, 10);

    println!(
        "F2: alice removed from org → session {} flagged; bob session {} unchanged",
        closed[0].session_id,
        manager2.open_sessions()[0].session_id,
    );
}

/// Flow F2 variant: all org members removed → all sessions flagged.
#[test]
fn f2_all_sessions_terminated_when_org_emptied() {
    let alice_key = P2pMemberKey(SigningKey::from_bytes(&ALICE_SEED).verifying_key());
    let bob_key = P2pMemberKey(SigningKey::from_bytes(&BOB_SEED).verifying_key());

    let trie = StubTrie::new()
        .add_member(ALICE_ID, alice_key, vec![])
        .add_member(BOB_ID, bob_key, vec![]);

    // After removal of both.
    let trie_empty = trie.stub_revoke(&ALICE_ID).stub_revoke(&BOB_ID);

    let mut manager = make_manager_ab(trie_empty);
    manager.register_acl(DOC_A, DocAcl::org_wide());
    manager.record_session(10, alice_panda_vk(), DOC_A);
    manager.record_session(20, bob_panda_vk(), DOC_A);

    let newly_closed = manager.recheck_open_sessions();
    assert_eq!(newly_closed, 2, "both sessions should be flagged when org is empty");

    println!("F2 variant: both sessions flagged when org is emptied");
}
