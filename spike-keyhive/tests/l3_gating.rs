//! L3 end-to-end scenario — gating (p2p connection policy on revoke).
//!
//! Composes gates 1 (member ACL) + 5 (PolicyManager session model)
//! against the `gating_fixture` from spike-common. Observable invariants:
//!
//! - "an open p2p sync session from bob's device is terminated within
//!   the test's timeout"
//! - "a fresh sync attempt from bob's device is rejected by the conn
//!   policy"
//! - "alice's session remains open"
//!
//! Since Keyhive has no published transport at the pin, the spike's
//! PolicyManager is the in-process stand-in: a `SessionState::Open`
//! session against the trie's pre-revoke state, then `Flagged` after
//! `recheck_open_sessions` is fired post-revoke, and rejection of new
//! sessions for the same peer.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use spike_common::resolver::MemberKeyResolver;
use spike_common::scenarios::gating_fixture;
use spike_keyhive::adapter::IdAdapter;
use spike_keyhive::s5_p2p_policy::{PolicyError, PolicyManager, SessionState};

#[test]
fn gating_terminates_revoked_session_and_rejects_new_attempts() {
    // Phase 1 — bootstrap from the fixture.
    let fixture = gating_fixture();
    let trie_pre = fixture.bootstrap_stub_trie();
    let alice = fixture.initial.members[0].id;
    let bob = fixture.initial.members[1].id;

    let adapter = IdAdapter::new();
    let alice_vk = adapter.resolve(&trie_pre, &alice).unwrap();
    let bob_vk = adapter.resolve(&trie_pre, &bob).unwrap();

    // Phase 2 — both alice and bob open sessions before any revoke.
    // Use `is_member` as the authorised-check stand-in.
    let policy = PolicyManager::new();
    let alice_session = policy
        .authorise_session(
            &adapter,
            &trie_pre,
            &alice_vk,
            "doc-shared",
            |r, id| r.is_member(id),
        )
        .expect("alice authorised");
    let bob_session = policy
        .authorise_session(
            &adapter,
            &trie_pre,
            &bob_vk,
            "doc-shared",
            |r, id| r.is_member(id),
        )
        .expect("bob authorised");
    assert_eq!(policy.session_state(alice_session), Some(SessionState::Open));
    assert_eq!(policy.session_state(bob_session), Some(SessionState::Open));
    assert_eq!(policy.open_session_count(), 2);

    // Phase 3 — apply the fixture's revocation step.
    let trie_post = fixture.apply_to_stub_trie(trie_pre);

    // Phase 4 — recheck flags bob's session, not alice's. This is the
    // push-style termination Keyhive's MembershipListener::on_revocation
    // would drive in production.
    let flagged = policy.recheck_open_sessions(&trie_post, |r, id| r.is_member(id));
    assert_eq!(flagged, 1);
    assert_eq!(
        policy.session_state(alice_session),
        Some(SessionState::Open),
        "alice's session must stay open"
    );
    assert_eq!(
        policy.session_state(bob_session),
        Some(SessionState::Flagged),
        "bob's session must be flagged after revoke"
    );

    // Phase 5 — a fresh authorise attempt from bob must be rejected.
    let err = policy
        .authorise_session(
            &adapter,
            &trie_post,
            &bob_vk,
            "doc-shared",
            |r, id| r.is_member(id),
        )
        .expect_err("post-revoke bob must be rejected");
    assert!(matches!(err, PolicyError::Unauthorised(_, _)));

    // Phase 6 — alice can still open new sessions.
    let alice_second = policy
        .authorise_session(
            &adapter,
            &trie_post,
            &alice_vk,
            "doc-shared",
            |r, id| r.is_member(id),
        )
        .expect("alice still authorised");
    assert_eq!(policy.session_state(alice_second), Some(SessionState::Open));
}
