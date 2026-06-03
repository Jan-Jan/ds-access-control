//! Gate 4 substitution: organisation-as-pseudo-group principal.
//!
//! See `evidence/s4.md` for findings.
//!
//! ## Design
//!
//! The ODS design's §Key changes #2 requires: **"any current member acts as the
//! org"**. `p2panda-auth` models nested groups via `GroupMember::Group(ID)`, which
//! is the closest existing concept. This module wraps that variant into an
//! `OrgPseudoGroupAdapter` and provides `effective_member_keys` to resolve the
//! effective key set for a doc-group that has the org as a nested-group member.
//!
//! ## Structural layout
//!
//! ```text
//! doc_group (GroupCrdtState)
//!   └── GroupMember::Group(ORG_GID)   ← the org pseudo-group
//!         ├── GroupMember::Individual(alice_id)
//!         └── GroupMember::Individual(bob_id)
//! ```
//!
//! `GroupCrdtState::members(doc_group_id)` auto-resolves this tree and returns
//! `[(alice_id, access), (bob_id, access)]`. No manual walk needed for membership
//! queries at the `p2panda-auth` layer.
//!
//! `effective_member_keys` performs the additional step of translating those
//! `SpikeMemberId` values to `P2pMemberKey`s via a `MemberKeyResolver`.
//!
//! ## Limitation at p2panda-spaces
//!
//! `Group::add` / `Space::add` in `p2panda-spaces` accept only `ActorId`, not a
//! `GroupMember::Group(ID)`. The org-as-pseudo-group concept is therefore reachable
//! only via the `p2panda-auth` CRDT directly — bypassing the spaces integration
//! layer. See `evidence/s4.md §L1 — p2panda-spaces` for the salvage plan.
//!
//! ## Constraint: Org groups cannot have Manage access
//!
//! `GroupCrdt::validate` at 41559b0 rejects `GroupMember::Group` with
//! `Access::manage()` (returns `ManagerGroupsNotAllowed`). The org pseudo-group
//! must therefore be added with `Access::read()` or `Access::write()` — not
//! `Access::manage()`. This is expected and acceptable for the ODS use-case
//! (the org grants read/write access to the doc; individual managers hold
//! `Manage` access via their `Individual` membership entries).

use std::collections::HashSet;

use p2panda_auth::Access;
use p2panda_auth::group::{GroupAction, GroupCrdt, GroupCrdtState, GroupMember};
use p2panda_auth::group::resolver::StrongRemove;
use p2panda_auth::traits::{IdentityHandle, Operation, OperationId};
use serde::{Deserialize, Serialize};
use spike_common::identity::{MemberId, P2pMemberKey};
use spike_common::resolver::{MemberKeyResolver, ResolverError};

// ---------------------------------------------------------------------------
// Re-export SpikeMemberId from the auth tests — define it here for s4 use
// ---------------------------------------------------------------------------

/// A local newtype over `[u8; 32]` with the same representation as
/// `spike_common::MemberId`. Required by the orphan rule: `IdentityHandle` is
/// foreign and `MemberId` is foreign; `AuthMemberId` is local.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AuthMemberId(pub [u8; 32]);

impl IdentityHandle for AuthMemberId {}

impl std::fmt::Display for AuthMemberId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AuthMemberId({:02x}{:02x}..)", self.0[0], self.0[1])
    }
}

impl From<MemberId> for AuthMemberId {
    fn from(m: MemberId) -> Self {
        Self(m.0)
    }
}

impl From<AuthMemberId> for MemberId {
    fn from(a: AuthMemberId) -> Self {
        MemberId(a.0)
    }
}

// ---------------------------------------------------------------------------
// Minimal operation type for the p2panda-auth CRDT (no async, no networking)
// ---------------------------------------------------------------------------

/// Simple monotonic operation ID — sufficient for in-memory CRDT sequencing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AuthOpId(pub u32);

impl OperationId for AuthOpId {}

impl std::fmt::Display for AuthOpId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AuthOpId({})", self.0)
    }
}

/// Minimal operation that carries exactly what the auth CRDT needs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthOp {
    pub id: AuthOpId,
    pub author: AuthMemberId,
    pub dependencies: Vec<AuthOpId>,
    pub group_id: AuthMemberId,
    pub action: GroupAction<AuthMemberId, ()>,
}

impl Operation<AuthMemberId, AuthOpId, ()> for AuthOp {
    fn id(&self) -> AuthOpId {
        self.id
    }
    fn author(&self) -> AuthMemberId {
        self.author
    }
    fn dependencies(&self) -> Vec<AuthOpId> {
        self.dependencies.clone()
    }
    fn group_id(&self) -> AuthMemberId {
        self.group_id
    }
    fn action(&self) -> GroupAction<AuthMemberId, ()> {
        self.action.clone()
    }
}

// ---------------------------------------------------------------------------
// Type aliases for the gate-4 CRDT
// ---------------------------------------------------------------------------

/// CRDT state type used throughout gate 4.
pub type G4GroupState = GroupCrdtState<AuthMemberId, AuthOpId, AuthOp, ()>;

/// CRDT type used throughout gate 4.
pub type G4GroupCrdt = GroupCrdt<
    AuthMemberId,
    AuthOpId,
    AuthOp,
    (),
    StrongRemove<AuthMemberId, AuthOpId, AuthOp, ()>,
>;

// ---------------------------------------------------------------------------
// OrgPseudoGroupAdapter — a builder that sets up the nested-group ACL
// ---------------------------------------------------------------------------

/// Builds a `G4GroupState` representing the org-as-pseudo-group pattern:
///
/// ```text
/// doc_group
///   └── GroupMember::Group(org_gid)
///         ├── GroupMember::Individual(alice_id)
///         └── GroupMember::Individual(bob_id)
/// ```
///
/// Usage:
/// ```ignore
/// let (state, doc_gid) = OrgPseudoGroupAdapter::build(
///     org_gid, org_manager, org_members, doc_group_manager, org_access
/// ).unwrap();
/// ```
pub struct OrgPseudoGroupAdapter;

impl OrgPseudoGroupAdapter {
    /// Build a `G4GroupState` with:
    /// - An org group (`org_gid`) managed by `org_manager` with `org_members` as individual members.
    /// - A doc group (`doc_gid`) managed by `doc_manager` with the org group as a nested member.
    ///
    /// `org_access`: the access level granted to the org group inside the doc group.
    /// Must NOT be `Access::manage()` — the CRDT rejects manager groups.
    ///
    /// Returns `(state, doc_gid)`.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        org_gid: AuthMemberId,
        org_manager: AuthMemberId,
        org_members: &[AuthMemberId],
        doc_gid: AuthMemberId,
        doc_manager: AuthMemberId,
        org_access: Access<()>,
        op_id_start: u32,
    ) -> Result<(G4GroupState, AuthMemberId), Box<dyn std::error::Error>> {
        let mut state = G4GroupCrdt::init();
        let mut op_id = op_id_start;

        // Op 0: org_manager creates the org group with themselves as manager.
        let create_org = AuthOp {
            id: AuthOpId(op_id),
            author: org_manager,
            dependencies: vec![],
            group_id: org_gid,
            action: GroupAction::Create {
                initial_members: vec![(GroupMember::Individual(org_manager), Access::manage())],
            },
        };
        state = G4GroupCrdt::process(state, &create_org)?;
        let mut prev = vec![AuthOpId(op_id)];
        op_id += 1;

        // Add each org_member to the org group.
        for member_id in org_members {
            let add_op = AuthOp {
                id: AuthOpId(op_id),
                author: org_manager,
                dependencies: prev.clone(),
                group_id: org_gid,
                action: GroupAction::Add {
                    member: GroupMember::Individual(*member_id),
                    access: Access::manage(),
                },
            };
            state = G4GroupCrdt::process(state, &add_op)?;
            prev = vec![AuthOpId(op_id)];
            op_id += 1;
        }

        // Doc manager creates the doc group.
        let create_doc = AuthOp {
            id: AuthOpId(op_id),
            author: doc_manager,
            dependencies: prev.clone(),
            group_id: doc_gid,
            action: GroupAction::Create {
                initial_members: vec![(GroupMember::Individual(doc_manager), Access::manage())],
            },
        };
        state = G4GroupCrdt::process(state, &create_doc)?;
        prev = vec![AuthOpId(op_id)];
        op_id += 1;

        // Doc manager adds the org group as a nested member of the doc group.
        let add_org = AuthOp {
            id: AuthOpId(op_id),
            author: doc_manager,
            dependencies: prev,
            group_id: doc_gid,
            action: GroupAction::Add {
                member: GroupMember::Group(org_gid),
                access: org_access,
            },
        };
        state = G4GroupCrdt::process(state, &add_org)?;

        Ok((state, doc_gid))
    }
}

// ---------------------------------------------------------------------------
// effective_member_keys — walk nested groups + resolve keys via MemberKeyResolver
// ---------------------------------------------------------------------------

/// Error returned when resolving effective member keys.
#[derive(Debug)]
pub enum EffectiveKeyError {
    Resolver(ResolverError),
}

impl std::fmt::Display for EffectiveKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EffectiveKeyError::Resolver(e) => write!(f, "resolver error: {}", e),
        }
    }
}

impl std::error::Error for EffectiveKeyError {}

impl From<ResolverError> for EffectiveKeyError {
    fn from(e: ResolverError) -> Self {
        EffectiveKeyError::Resolver(e)
    }
}

/// Walk the nested-group hierarchy of `doc_gid` in `state` and resolve each
/// `GroupMember::Individual` member to their current `P2pMemberKey` via `resolver`.
///
/// `GroupCrdtState::members()` auto-resolves nested groups and returns only
/// individual `(AuthMemberId, Access<()>)` pairs. This function then calls the
/// resolver for each `AuthMemberId` to produce the current live key set.
///
/// Members unknown to the resolver (e.g. recently removed from the trie) are
/// silently skipped. This matches the "no stale key" invariant: if the trie
/// does not recognise a member, that member has no current key and should not
/// appear in the effective set.
///
/// ## Why this function is needed
///
/// `GroupCrdtState::members()` returns stable `AuthMemberId` values, NOT keys.
/// The actual keys live in the trie. This function bridges the CRDT layer to the
/// key layer, which is the Phase 3 org-pseudo-group adapter's core responsibility.
pub fn effective_member_keys<R: MemberKeyResolver>(
    state: &G4GroupState,
    doc_gid: AuthMemberId,
    resolver: &R,
) -> Result<HashSet<P2pMemberKey>, EffectiveKeyError> {
    // members() auto-resolves nested groups — returns flat (ID, Access) pairs.
    let members = state.members(doc_gid);
    let mut keys = HashSet::new();

    for (member_id, _access) in members {
        let spike_id = MemberId::from(member_id);
        match resolver.p2p_member_key(&spike_id) {
            Ok(key) => {
                keys.insert(key);
            }
            Err(ResolverError::UnknownMember(_)) => {
                // Member no longer in trie — skip (correct: no stale key).
            }
            Err(e) => return Err(EffectiveKeyError::Resolver(e)),
        }
    }

    Ok(keys)
}
