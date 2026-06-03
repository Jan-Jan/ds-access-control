//! Gate 5 substitution: peer-to-peer connection policy.
//!
//! See `evidence/s5.md` for findings.
//!
//! ## Design
//!
//! The ODS design's §Key changes #5 requires that p2p connections are gated on
//! trie membership. `p2panda-sync::Manager<T>` is the session-establishment entry
//! point, and `SessionConfig<T>::remote: VerifyingKey` is available at that moment.
//!
//! ## Approach: Option C — closure-based reverse index
//!
//! `PolicyManager<R, F>` wraps a `MemberKeyResolver` (`R`) and a
//! `peer_to_member: F` closure (`F: Fn(VerifyingKey) -> Option<MemberId>`).
//! The closure is provided by the caller (test) and performs the reverse lookup
//! (VerifyingKey → MemberId) that is *not* present in the `MemberKeyResolver`
//! trait. The friction of having to supply this closure is itself evidence: it
//! reveals a gap in the resolver trait shape (see `evidence/s5.md §Discovered gaps`).
//!
//! ## What is NOT implemented here
//!
//! A full `impl Manager<T> for PolicyManager` would require RPIT (return-position
//! impl Trait) compatibility with the concrete `Manager<T>` trait, plus async
//! machinery for `session_handle` and `subscribe`. This is disproportionate to the
//! spike's goals — the `Manager<T>` trait uses RPIT on all three methods, which
//! requires `impl Trait` in trait position (Rust ≥1.75 stable) but still needs
//! wrapper types per associated type. The spike wraps `policy_check` only and
//! documents the deferred `Manager<T>` wrapper coverage in `evidence/s5.md`.
//!
//! ## Flow mapping
//!
//! | Flow | Description                                      | Implemented |
//! |------|--------------------------------------------------|-------------|
//! | E1   | Member-principal accept/reject at session open   | `policy_check` + direct test |
//! | E2   | Org-principal accept (any org member)            | `policy_check` + direct test |
//! | F1   | Terminate session on member revocation           | `recheck_open_sessions` test |
//! | F2   | Terminate org session on member removal          | `recheck_open_sessions` test |

use std::collections::HashMap;

use p2panda_core::VerifyingKey;
use spike_common::identity::MemberId;
use spike_common::resolver::MemberKeyResolver;

// ---------------------------------------------------------------------------
// DocId — opaque document identifier for the policy check
// ---------------------------------------------------------------------------

/// Opaque document / space identifier. In production this maps to a SpaceId or
/// LogId; here it is a simple 32-byte array to keep the spike free of p2panda-spaces
/// generics (which pull in heavy tokio dependencies and inflate the test surface).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DocId(pub [u8; 32]);

// ---------------------------------------------------------------------------
// DocAcl — the access-control list consulted by policy_check
// ---------------------------------------------------------------------------

/// Lightweight ACL for a single document. In production this is driven by the
/// `p2panda-auth` GroupCrdtState or similar; in the spike it is a plain set of
/// authorised `MemberId`s plus a boolean flag for org-wide access.
///
/// A peer is authorised if:
/// 1. The ACL has `org_wide = true` AND the peer maps to any current org member, OR
/// 2. The ACL's `member_ids` set contains the peer's `MemberId`.
#[derive(Clone, Debug, Default)]
pub struct DocAcl {
    /// Individual member IDs with explicit access.
    pub member_ids: std::collections::HashSet<MemberId>,
    /// When `true`, every current org member (as returned by the resolver) has access.
    pub org_wide: bool,
}

impl DocAcl {
    /// Create an ACL that grants access only to the listed individual members.
    pub fn for_members(ids: impl IntoIterator<Item = MemberId>) -> Self {
        Self {
            member_ids: ids.into_iter().collect(),
            org_wide: false,
        }
    }

    /// Create an ACL that grants access to all current org members (org-as-pseudo-group).
    pub fn org_wide() -> Self {
        Self {
            member_ids: Default::default(),
            org_wide: true,
        }
    }
}

// ---------------------------------------------------------------------------
// SessionRecord — tracks open sessions for Flow F1 / F2
// ---------------------------------------------------------------------------

/// A record of an open sync session. Held by `PolicyManager` and checked on
/// every `recheck_open_sessions` call.
#[derive(Clone, Debug)]
pub struct SessionRecord {
    pub session_id: u64,
    pub remote_peer: VerifyingKey,
    pub doc_id: DocId,
    /// Set to `true` by `recheck_open_sessions` when the session should be
    /// terminated. The caller is responsible for actually closing the p2panda
    /// session handle (because `session_handle(id).close()` requires async +
    /// access to the inner Manager — tracked as a gap in `evidence/s5.md`).
    pub should_close: bool,
}

// ---------------------------------------------------------------------------
// PolicyManager — wraps a resolver + reverse-lookup closure
// ---------------------------------------------------------------------------

/// Wraps a [`MemberKeyResolver`] with a p2p connection policy.
///
/// `R` — the `MemberKeyResolver` implementation (typically `StubTrie` in tests,
/// the real trie adapter in production).
///
/// `F` — a closure `Fn(VerifyingKey) -> Option<MemberId>` that maps a raw p2panda
/// peer key to the application's `MemberId`. This is the **spike-side reverse index**:
/// the resolver trait does not expose this direction (it only maps `MemberId → Key`),
/// so the caller must supply the reverse mapping. See §Discovered gaps in the
/// evidence file.
pub struct PolicyManager<R, F> {
    resolver: R,
    peer_to_member: F,
    doc_acls: HashMap<DocId, DocAcl>,
    open_sessions: Vec<SessionRecord>,
}

impl<R, F> PolicyManager<R, F>
where
    R: MemberKeyResolver,
    F: Fn(VerifyingKey) -> Option<MemberId>,
{
    /// Construct a new `PolicyManager`.
    ///
    /// `resolver` — live trie resolver.
    /// `peer_to_member` — reverse-lookup closure (see type-level docs for the gap note).
    pub fn new(resolver: R, peer_to_member: F) -> Self {
        Self {
            resolver,
            peer_to_member,
            doc_acls: HashMap::new(),
            open_sessions: Vec::new(),
        }
    }

    /// Register an ACL for a document. Replaces any existing ACL for `doc_id`.
    pub fn register_acl(&mut self, doc_id: DocId, acl: DocAcl) {
        self.doc_acls.insert(doc_id, acl);
    }

    /// Check whether `remote_peer` is authorised to open a session for `doc_id`.
    ///
    /// Returns `true` if authorised, `false` otherwise.
    ///
    /// ## Logic
    ///
    /// 1. Reverse-look up the peer's `MemberId` via the caller-supplied closure.
    ///    If no `MemberId` maps to `remote_peer`, the peer is unknown → reject.
    /// 2. If the doc ACL has `org_wide = true`, accept iff the resolved `MemberId`
    ///    is a current org member (`resolver.is_member`).
    /// 3. Otherwise, accept iff the resolved `MemberId` is in the ACL's explicit
    ///    member set.
    ///
    /// This is a **synchronous** check against the current resolver state, which
    /// is pull-only. A post-open window exists between connection acceptance and
    /// the next `recheck_open_sessions` call (documented as a gap in `evidence/s5.md`).
    pub fn policy_check(&self, remote_peer: &VerifyingKey, doc_id: &DocId) -> bool {
        // Step 1: reverse-lookup.
        let member_id = match (self.peer_to_member)(*remote_peer) {
            Some(id) => id,
            None => return false,
        };

        // Step 2/3: ACL check.
        match self.doc_acls.get(doc_id) {
            None => false, // No ACL registered → deny by default.
            Some(acl) => {
                if acl.org_wide {
                    self.resolver.is_member(&member_id)
                } else {
                    acl.member_ids.contains(&member_id)
                }
            }
        }
    }

    /// Record an accepted session. Called by the wrapper after `policy_check` returns `true`.
    ///
    /// Returns `Ok(session_id)`. In a full `Manager<T>` wrapper this would also
    /// delegate to the inner manager's `session()` method; that delegation is
    /// deferred (see `evidence/s5.md §Deferred coverage`).
    pub fn record_session(
        &mut self,
        session_id: u64,
        remote_peer: VerifyingKey,
        doc_id: DocId,
    ) {
        self.open_sessions.push(SessionRecord {
            session_id,
            remote_peer,
            doc_id,
            should_close: false,
        });
    }

    /// Re-evaluate every open session against the current resolver state.
    ///
    /// Any session whose peer is no longer authorised has its `should_close` flag
    /// set to `true`. The caller must then actually close the p2panda session handle
    /// (async + inner Manager access — tracked as a gap).
    ///
    /// This is the **pull model** for Flow F1 / F2: the caller invokes this method
    /// after each trie-change event. The `StubTrie` has no push mechanism, so the
    /// policy manager cannot observe changes reactively. See `evidence/s5.md
    /// §Discovered gaps: trie push notification`.
    ///
    /// Returns the number of sessions newly flagged for closure.
    pub fn recheck_open_sessions(&mut self) -> usize {
        // Collect (session_id, remote_peer, doc_id) tuples to avoid holding a
        // mutable borrow on `self.open_sessions` while calling `policy_check`
        // (which borrows `self` immutably for the resolver + doc_acls fields).
        let checks: Vec<(u64, VerifyingKey, DocId)> = self
            .open_sessions
            .iter()
            .filter(|r| !r.should_close)
            .map(|r| (r.session_id, r.remote_peer, r.doc_id))
            .collect();

        let mut newly_closed = 0;
        for (session_id, remote_peer, doc_id) in checks {
            if !self.policy_check(&remote_peer, &doc_id) {
                if let Some(record) = self
                    .open_sessions
                    .iter_mut()
                    .find(|r| r.session_id == session_id)
                {
                    record.should_close = true;
                    newly_closed += 1;
                }
            }
        }
        newly_closed
    }

    /// Return a slice of all currently tracked session records.
    pub fn open_sessions(&self) -> &[SessionRecord] {
        &self.open_sessions
    }

    /// Drain sessions flagged for closure and return them. Useful for tests that
    /// need to verify which sessions were terminated.
    pub fn drain_closed_sessions(&mut self) -> Vec<SessionRecord> {
        let mut closed = Vec::new();
        let mut i = 0;
        while i < self.open_sessions.len() {
            if self.open_sessions[i].should_close {
                closed.push(self.open_sessions.remove(i));
            } else {
                i += 1;
            }
        }
        closed
    }
}

// ---------------------------------------------------------------------------
// PolicyError — returned when policy_check denies a session
// ---------------------------------------------------------------------------

/// Error returned when the policy manager rejects a session-open request.
#[derive(Debug, PartialEq, Eq)]
pub enum PolicyError {
    /// The peer's `VerifyingKey` did not map to any known `MemberId`.
    UnknownPeer,
    /// The peer's `MemberId` is not authorised for the requested document.
    Unauthorised { member_id: MemberId, doc_id: DocId },
    /// No ACL is registered for the requested document.
    NoAcl { doc_id: DocId },
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::UnknownPeer => write!(f, "peer key not in reverse index"),
            PolicyError::Unauthorised { member_id, doc_id } => write!(
                f,
                "member {:?} is not authorised for doc {:?}",
                member_id, doc_id
            ),
            PolicyError::NoAcl { doc_id } => {
                write!(f, "no ACL registered for doc {:?}", doc_id)
            }
        }
    }
}

impl std::error::Error for PolicyError {}

impl<R, F> PolicyManager<R, F>
where
    R: MemberKeyResolver,
    F: Fn(VerifyingKey) -> Option<MemberId>,
{
    /// Checked variant of `policy_check` — returns a `PolicyError` describing the
    /// rejection reason instead of a plain `false`.
    pub fn policy_check_err(
        &self,
        remote_peer: &VerifyingKey,
        doc_id: &DocId,
    ) -> Result<MemberId, PolicyError> {
        let member_id = (self.peer_to_member)(*remote_peer).ok_or(PolicyError::UnknownPeer)?;

        match self.doc_acls.get(doc_id) {
            None => Err(PolicyError::NoAcl { doc_id: *doc_id }),
            Some(acl) => {
                if acl.org_wide {
                    if self.resolver.is_member(&member_id) {
                        Ok(member_id)
                    } else {
                        Err(PolicyError::Unauthorised {
                            member_id,
                            doc_id: *doc_id,
                        })
                    }
                } else if acl.member_ids.contains(&member_id) {
                    Ok(member_id)
                } else {
                    Err(PolicyError::Unauthorised {
                        member_id,
                        doc_id: *doc_id,
                    })
                }
            }
        }
    }
}
