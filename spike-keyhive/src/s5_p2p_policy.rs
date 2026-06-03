//! Gate 5 substitution: P2P connection policy via in-process session stub.
//!
//! Keyhive does not ship a transport at the pinned revision (Beelay is
//! not yet published). The spike implements an in-process
//! [`PolicyManager`] that:
//!
//! - Holds a `HashMap<SessionId, SessionRecord>`.
//! - Accepts or rejects new sessions via
//!   [`authorise_session`](PolicyManager::authorise_session), consulting
//!   the [`IdAdapter`](crate::adapter::IdAdapter) for reverse lookup.
//! - On a trie-change event, walks all open sessions via
//!   [`recheck_open_sessions`](PolicyManager::recheck_open_sessions)
//!   and flags those whose peer is no longer authorised.
//!
//! In Phase 3 the recheck would be driven push-style by Keyhive's
//! `MembershipListener::on_revocation` — the listener cannot block the
//! revocation, but it CAN trigger session termination immediately, which
//! is materially better than p2panda's pull-based recheck cadence.

use std::collections::HashMap;
use std::sync::Mutex;

use ed25519_dalek::VerifyingKey;
use spike_common::identity::MemberId;
use spike_common::resolver::MemberKeyResolver;

use crate::adapter::IdAdapter;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Open,
    Flagged,
}

#[derive(Debug, Clone)]
pub struct SessionRecord {
    pub peer_vk: VerifyingKey,
    pub member_id: Option<MemberId>,
    pub doc_label: &'static str,
    pub state: SessionState,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("peer {0:?} is unknown to the adapter (cold lookup)")]
    UnknownPeer(VerifyingKey),
    #[error("member {0:?} is not authorised for doc {1:?}")]
    Unauthorised(MemberId, &'static str),
}

/// In-process session model with push-driven revocation rechecks.
pub struct PolicyManager {
    sessions: Mutex<HashMap<SessionId, SessionRecord>>,
    next_id: Mutex<u64>,
}

impl PolicyManager {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            next_id: Mutex::new(1),
        }
    }

    /// E1/E2: authorise a session-open attempt from `peer_vk` against
    /// `doc_label`. Returns `Ok(SessionId)` on accept.
    pub fn authorise_session<R: MemberKeyResolver>(
        &self,
        adapter: &IdAdapter,
        resolver: &R,
        peer_vk: &VerifyingKey,
        doc_label: &'static str,
        authorised_check: impl Fn(&R, &MemberId) -> bool,
    ) -> Result<SessionId, PolicyError> {
        let member_id = adapter
            .member_id_for(peer_vk)
            .ok_or(PolicyError::UnknownPeer(*peer_vk))?;
        if !authorised_check(resolver, &member_id) {
            return Err(PolicyError::Unauthorised(member_id, doc_label));
        }
        let mut next_id = self.next_id.lock().unwrap_or_else(|e| e.into_inner());
        let id = SessionId(*next_id);
        *next_id += 1;
        drop(next_id);
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.insert(
            id,
            SessionRecord {
                peer_vk: *peer_vk,
                member_id: Some(member_id),
                doc_label,
                state: SessionState::Open,
            },
        );
        Ok(id)
    }

    /// F1/F2: walk all open sessions; flag those whose member is no
    /// longer authorised. Returns the number flagged.
    pub fn recheck_open_sessions<R: MemberKeyResolver>(
        &self,
        resolver: &R,
        authorised_check: impl Fn(&R, &MemberId) -> bool,
    ) -> usize {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let mut count = 0;
        for record in sessions.values_mut() {
            if record.state != SessionState::Open {
                continue;
            }
            let Some(member_id) = record.member_id else {
                continue;
            };
            if !authorised_check(resolver, &member_id) {
                record.state = SessionState::Flagged;
                count += 1;
            }
        }
        count
    }

    pub fn session_state(&self, id: SessionId) -> Option<SessionState> {
        self.sessions
            .lock().unwrap_or_else(|e| e.into_inner())
            .get(&id)
            .map(|r| r.state)
    }

    pub fn open_session_count(&self) -> usize {
        self.sessions
            .lock().unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|r| r.state == SessionState::Open)
            .count()
    }
}

impl Default for PolicyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spike_common::scenarios::revocation_fixture;

    #[test]
    fn authorise_session_accepts_known_authorised_member() {
        let fixture = revocation_fixture();
        let trie = fixture.bootstrap_stub_trie();
        let adapter = IdAdapter::new();
        let alice = fixture.initial.members[0].id;
        let alice_vk = adapter.resolve(&trie, &alice).unwrap();

        let policy = PolicyManager::new();
        let id = policy
            .authorise_session(&adapter, &trie, &alice_vk, "doc-1", |r, id| r.is_member(id))
            .expect("alice in trie + is_member");
        assert_eq!(policy.session_state(id), Some(SessionState::Open));
    }

    #[test]
    fn authorise_session_rejects_cold_peer() {
        let fixture = revocation_fixture();
        let trie = fixture.bootstrap_stub_trie();
        let adapter = IdAdapter::new();
        let policy = PolicyManager::new();

        // VerifyingKey never resolved through the adapter — cold lookup.
        let cold_signer = ed25519_dalek::SigningKey::from_bytes(&[0xfe; 32]);
        let cold_vk = cold_signer.verifying_key();
        let err = policy
            .authorise_session(&adapter, &trie, &cold_vk, "doc-1", |r, id| r.is_member(id))
            .unwrap_err();
        assert!(matches!(err, PolicyError::UnknownPeer(_)));
    }

    #[test]
    fn authorise_session_rejects_unauthorised_known_member() {
        let fixture = revocation_fixture();
        let trie = fixture.bootstrap_stub_trie();
        let adapter = IdAdapter::new();
        let alice = fixture.initial.members[0].id;
        let alice_vk = adapter.resolve(&trie, &alice).unwrap();

        let policy = PolicyManager::new();
        // Authorised-check returns false unconditionally → reject.
        let err = policy
            .authorise_session(&adapter, &trie, &alice_vk, "doc-x", |_, _| false)
            .unwrap_err();
        assert!(matches!(err, PolicyError::Unauthorised(_, _)));
    }

    #[test]
    fn recheck_flags_sessions_for_revoked_member() {
        let fixture = revocation_fixture();
        let trie = fixture.bootstrap_stub_trie();
        let adapter = IdAdapter::new();
        let alice = fixture.initial.members[0].id;
        let alice_vk = adapter.resolve(&trie, &alice).unwrap();

        let policy = PolicyManager::new();
        let id = policy
            .authorise_session(&adapter, &trie, &alice_vk, "doc-1", |r, id| r.is_member(id))
            .unwrap();
        assert_eq!(policy.session_state(id), Some(SessionState::Open));

        // Trie revokes alice; the recheck must flag her session.
        let post = trie.stub_revoke(&alice);
        let flagged = policy.recheck_open_sessions(&post, |r, id| r.is_member(id));
        assert_eq!(flagged, 1);
        assert_eq!(policy.session_state(id), Some(SessionState::Flagged));
        assert_eq!(policy.open_session_count(), 0);
    }

    #[test]
    fn recheck_is_idempotent_on_already_flagged_sessions() {
        let fixture = revocation_fixture();
        let trie = fixture.bootstrap_stub_trie();
        let adapter = IdAdapter::new();
        let alice = fixture.initial.members[0].id;
        let alice_vk = adapter.resolve(&trie, &alice).unwrap();

        let policy = PolicyManager::new();
        policy
            .authorise_session(&adapter, &trie, &alice_vk, "doc-1", |r, id| r.is_member(id))
            .unwrap();
        let post = trie.stub_revoke(&alice);

        let first = policy.recheck_open_sessions(&post, |r, id| r.is_member(id));
        let second = policy.recheck_open_sessions(&post, |r, id| r.is_member(id));
        assert_eq!(first, 1);
        assert_eq!(second, 0); // already flagged → no second flag
    }
}
