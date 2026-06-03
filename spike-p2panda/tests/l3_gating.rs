#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! L3 scenario: gating end-to-end.
//!
//! See `spike-common/scenarios/gating.md` for the human-readable spec.
//!
//! **Substitutions exercised:** gate 1 (stable-ID ACL via `DocAcl::for_members`),
//! gate 5 (p2p connection policy — `PolicyManager::policy_check`,
//! `recheck_open_sessions`, session termination flagging).
//!
//! ## Scenario summary
//!
//! 1. alice and bob each hold open sync sessions for a doc whose ACL grants both.
//! 2. bob is revoked from the trie (via the `gating_fixture` step).
//! 3. The trie-change observer fires — simulated by rebuilding `PolicyManager`
//!    with the updated trie and calling `recheck_open_sessions`.
//!
//! ## Observable assertions (from gating.md)
//!
//! - "an open p2p sync session from bob's device is terminated within the
//!   test's timeout" → `bob_session.should_close == true` after `recheck_open_sessions`.
//! - "a fresh sync attempt from bob's device is rejected by the conn policy" →
//!   `policy_check(&bob_vk, &doc)` returns `false` post-revocation.
//! - "alice's session remains open" → `alice_session.should_close == false`.
//!
//! ## Simplification note
//!
//! The "latency to terminate" observable (noted in gating.md as a gap-matrix
//! `notes` field) is not measurable in a synchronous unit test. The spike records
//! this as a deferred gap: actual async close (ToSync::Close via Manager<T>
//! session_handle) is documented in `evidence/s5.md §Deferred coverage`.

use ed25519_dalek::SigningKey;
use p2panda_core::VerifyingKey as PandaVerifyingKey;
use spike_common::identity::{MemberId, P2pMemberKey};
use spike_common::resolver::MemberKeyResolver;
use spike_common::scenarios::gating_fixture;
use spike_common::stub_trie::StubTrie;
use spike_p2panda::s5_p2p_policy::{DocAcl, DocId, PolicyManager};

// ---------------------------------------------------------------------------
// Test constants (mirror gating_fixture seeds)
// ---------------------------------------------------------------------------

const DOC_D: DocId = DocId([0xddu8; 32]);

// alice: MemberId([0xa1; 32]), key seed 0xa2
const ALICE_ID: MemberId = MemberId([0xa1u8; 32]);
// bob: MemberId([0xb1; 32]), key seed 0xb2
const BOB_ID: MemberId = MemberId([0xb1u8; 32]);

fn sk(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

fn alice_vk() -> PandaVerifyingKey {
    PandaVerifyingKey::from(sk(0xa2).verifying_key())
}
fn bob_vk() -> PandaVerifyingKey {
    PandaVerifyingKey::from(sk(0xb2).verifying_key())
}

/// Build a `PolicyManager` whose reverse-lookup closure covers alice and bob
/// using the fixture key seeds (0xa2 / 0xb2).
fn make_policy_manager<R: MemberKeyResolver>(
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
// L3 gating test
// ---------------------------------------------------------------------------

/// L3 gating scenario end-to-end.
///
/// Observable assertions from `gating.md`:
/// 1. "an open p2p sync session from bob's device is terminated within the
///    test's timeout" → `bob_session.should_close == true`.
/// 2. "a fresh sync attempt from bob's device is rejected by the conn policy
///    before the handshake completes" → `policy_check(&bob_vk, &doc) == false`.
/// 3. "alice's session remains open" → `alice_session.should_close == false`.
///
/// Gate-1 side-assertion:
/// - `DocAcl::for_members` reflects the fixture's ACL grant; bob's
///   `MemberId` is removed from the ACL on revocation (member-principal path).
#[test]
fn gating_scenario_end_to_end() {
    let f = gating_fixture();
    assert_eq!(f.name, "gating");

    // ---- Initial state: build trie from fixture ----
    let trie_before = f.bootstrap_stub_trie();

    // Confirm both alice and bob are in the trie.
    assert!(trie_before.is_member(&ALICE_ID), "alice must be in trie before revocation");
    assert!(trie_before.is_member(&BOB_ID), "bob must be in trie before revocation");

    // Verify fixture key seeds match the verifying keys used in the reverse-lookup
    // closure. The fixture seeds alice with P2pMemberKey(sk(0xa2).verifying_key()).
    let alice_key_from_trie = trie_before.p2p_member_key(&ALICE_ID).unwrap();
    let expected_alice_vk = sk(0xa2).verifying_key();
    assert_eq!(
        alice_key_from_trie.0.as_bytes(),
        expected_alice_vk.as_bytes(),
        "alice's trie key must match the fixture seed 0xa2"
    );

    let bob_key_from_trie = trie_before.p2p_member_key(&BOB_ID).unwrap();
    let expected_bob_vk = sk(0xb2).verifying_key();
    assert_eq!(
        bob_key_from_trie.0.as_bytes(),
        expected_bob_vk.as_bytes(),
        "bob's trie key must match the fixture seed 0xb2"
    );

    // ---- Set up: PolicyManager + open sessions for DOC_D ----
    let alice_p2p_key = P2pMemberKey(sk(0xa2).verifying_key());
    let bob_p2p_key = P2pMemberKey(sk(0xb2).verifying_key());
    let trie_with_keys = StubTrie::new()
        .add_member(ALICE_ID, alice_p2p_key, vec![])
        .add_member(BOB_ID, bob_p2p_key, vec![]);

    let mut manager_before = make_policy_manager(trie_with_keys.clone());
    manager_before.register_acl(DOC_D, DocAcl::for_members([ALICE_ID, BOB_ID]));

    // Open sessions: alice = session 1, bob = session 2.
    manager_before.record_session(1, alice_vk(), DOC_D);
    manager_before.record_session(2, bob_vk(), DOC_D);
    assert_eq!(manager_before.open_sessions().len(), 2);

    // Both sessions accepted before revocation (pre-condition).
    assert!(
        manager_before.policy_check(&alice_vk(), &DOC_D),
        "[pre-revocation] alice must be accepted by policy"
    );
    assert!(
        manager_before.policy_check(&bob_vk(), &DOC_D),
        "[pre-revocation] bob must be accepted by policy"
    );

    // ---- Apply fixture step: RevokeMember(bob) ----
    // The fixture drives a trie change; we apply it via apply_to_stub_trie.
    // Note: apply_to_stub_trie operates on the fixture's canonical trie,
    // not the manually-built one above. We derive the post-revocation trie
    // from the canonical fixture to stay aligned with the spec.
    let trie_after = f.apply_to_stub_trie(f.bootstrap_stub_trie());

    assert!(!trie_after.is_member(&BOB_ID), "bob must NOT be in trie after revocation");
    assert!(trie_after.is_member(&ALICE_ID), "alice must remain in trie after revocation");

    // Fixture expected_final: 1 member.
    assert_eq!(f.expected_final.member_count, 1);

    // ---- Trie-change observer fires: rebuild PolicyManager with updated trie.
    //      The member-principal path requires the ACL to also be pruned
    //      (documented in l2_g5.rs; org-wide path does not need this step). ----
    let trie_after_with_keys = trie_with_keys.stub_revoke(&BOB_ID);
    let mut manager_after = make_policy_manager(trie_after_with_keys);
    // ACL updated: remove bob (member-principal path).
    manager_after.register_acl(DOC_D, DocAcl::for_members([ALICE_ID]));

    // Transfer open sessions to the new manager (simulates session-state continuity).
    manager_after.record_session(1, alice_vk(), DOC_D);
    manager_after.record_session(2, bob_vk(), DOC_D);

    // ---- Fire trie-change → recheck_open_sessions ----
    let newly_flagged = manager_after.recheck_open_sessions();

    // Observable 1: bob's session flagged for termination.
    assert_eq!(newly_flagged, 1, "[gating] exactly one session (bob's) must be flagged");

    let sessions = manager_after.open_sessions();
    let alice_session = sessions.iter().find(|s| s.session_id == 1).expect("alice session");
    let bob_session = sessions.iter().find(|s| s.session_id == 2).expect("bob session");

    assert!(
        bob_session.should_close,
        "[gating] bob's session must be flagged should_close after revocation"
    );
    // Observable 3: alice's session remains open.
    assert!(
        !alice_session.should_close,
        "[gating] alice's session must NOT be flagged after bob's revocation"
    );

    // Observable 2: fresh connection attempt by bob is rejected.
    let bob_fresh_accepted = manager_after.policy_check(&bob_vk(), &DOC_D);
    assert!(
        !bob_fresh_accepted,
        "[gating] fresh sync attempt by bob must be rejected by conn policy"
    );

    // Alice's fresh connection is still accepted.
    assert!(
        manager_after.policy_check(&alice_vk(), &DOC_D),
        "[gating] alice's fresh connection attempt must still be accepted"
    );

    // Drain and verify.
    let closed = manager_after.drain_closed_sessions();
    assert_eq!(closed.len(), 1);
    assert_eq!(closed[0].session_id, 2, "session 2 (bob) must be in the drained list");
    assert_eq!(manager_after.open_sessions().len(), 1, "only alice's session remains");

    println!(
        "L3 gating: bob session {} flagged + rejected; alice session {} unchanged.",
        closed[0].session_id,
        manager_after.open_sessions()[0].session_id,
    );
}
