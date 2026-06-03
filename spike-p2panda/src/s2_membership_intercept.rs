//! Gate 2 substitution: library-native membership-mutation interception.
//!
//! Spec §Key changes #3: the trie is the sole write authority for member/device
//! key state. Library-native mutation entry points (`Groups::add`, `Groups::remove`,
//! `Groups::promote`, `Groups::demote`, `Group::add`, `Group::remove`,
//! `Space::add`, `Space::remove`) must be intercepted so application code cannot
//! bypass the trie.
//!
//! ## p2panda-auth layer — `BlockingGroups<Inner>` (IMPLEMENTABLE)
//!
//! The `Groups` trait (`p2panda_auth::traits::Groups`) is `pub` with no sealed
//! mechanism. An external `BlockingGroups<Inner>` can implement it and return
//! `Err(InterceptError::MutationBlocked)` for every mutation method. Read-only
//! queries are on the separate `GroupMembership` trait and are unaffected.
//!
//! This is the clean `TraitImpl` salvage for gate 2 at the auth layer.
//!
//! ## p2panda-spaces layer — store intercept (HARD gap)
//!
//! The `AuthStore<C>` trait is in `pub mod traits` and its method signatures use
//! `AuthGroupState<C>` (= `GroupCrdtState<ActorId, OperationId, AuthMessage<C>, C>`).
//! `AuthGroupState` and `AuthMessage<C>` live in `mod types` / `mod auth` which are
//! both private modules — not re-exported from `p2panda_spaces`. An external impl of
//! `AuthStore<C>` cannot name the parameter type and therefore **cannot be written
//! outside the crate**. This is a Hard gap at the spaces-store layer.
//!
//! Confirmed at compile time: attempting `use p2panda_spaces::types::AuthGroupState`
//! gives `error[E0603]: module 'types' is private`.
//!
//! `Forge` trait secondary intercept: `Forge::forge` takes `SpacesArgs<ID, C>` which
//! IS publicly re-exported (`pub use message::SpacesArgs`), so a `BlockingForge`
//! wrapper is syntactically possible. However it intercepts message forging, not the
//! ACL state write — it would prevent the message from being created but not block the
//! `set_auth` call that the spaces layer may issue before calling `forge`.
//!
//! See `evidence/s2.md` for the full gap analysis and gate-2 gap-matrix row.

use std::fmt;

use p2panda_auth::Access;
use p2panda_auth::group::GroupMember;
use p2panda_auth::traits::{Conditions, Groups, IdentityHandle, OperationId};

// ---------------------------------------------------------------------------
// Shared error type
// ---------------------------------------------------------------------------

/// Error returned by any intercepted mutation.
#[derive(Debug, PartialEq, Eq)]
pub enum InterceptError<E: fmt::Debug> {
    /// The mutation was blocked by the trie-gate policy.
    MutationBlocked,
    /// The inner implementation returned an error.
    Inner(E),
}

impl<E: fmt::Debug + fmt::Display> fmt::Display for InterceptError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InterceptError::MutationBlocked => {
                write!(f, "membership mutation blocked: trie is the sole write authority")
            }
            InterceptError::Inner(e) => write!(f, "inner error: {e}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display + std::error::Error + 'static> std::error::Error
    for InterceptError<E>
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            InterceptError::MutationBlocked => None,
            InterceptError::Inner(e) => Some(e),
        }
    }
}

// ---------------------------------------------------------------------------
// BlockingGroups — p2panda-auth layer intercept
// ---------------------------------------------------------------------------

/// Wraps an `Inner: Groups<…>` and returns `Err(InterceptError::MutationBlocked)`
/// for every mutation method (`create`, `add`, `remove`, `promote`, `demote`,
/// `receive_from_remote`).
///
/// Read-only queries are on the separate `GroupMembership` trait and are NOT
/// affected — pass the inner impl directly to any `GroupMembership`-bounded call.
///
/// This is the `TraitImpl` salvage for the p2panda-auth layer of gate 2.
/// Confirmed compiling and testable; see `tests/l1_p2panda_auth_intercept.rs`.
pub struct BlockingGroups<Inner> {
    _inner: Inner,
}

impl<Inner> BlockingGroups<Inner> {
    /// Wraps `inner`; all mutation calls will be blocked.
    pub fn new(inner: Inner) -> Self {
        Self { _inner: inner }
    }
}

impl<ID, OP, M, C, Inner> Groups<ID, OP, M, C> for BlockingGroups<Inner>
where
    ID: IdentityHandle,
    OP: OperationId,
    M: fmt::Debug,
    C: Conditions,
    Inner: Groups<ID, OP, M, C>,
    Inner::Error: fmt::Debug,
{
    type Error = InterceptError<Inner::Error>;

    fn create(
        &mut self,
        _initial_members: Vec<(GroupMember<ID>, Access<C>)>,
    ) -> Result<M, Self::Error> {
        Err(InterceptError::MutationBlocked)
    }

    fn receive_from_remote(&mut self, _remote_operation: M) -> Result<(), Self::Error> {
        Err(InterceptError::MutationBlocked)
    }

    fn add(
        &mut self,
        _group_id: ID,
        _adder: ID,
        _added: ID,
        _access: Access<C>,
    ) -> Result<M, Self::Error> {
        Err(InterceptError::MutationBlocked)
    }

    fn remove(&mut self, _group_id: ID, _remover: ID, _removed: ID) -> Result<M, Self::Error> {
        Err(InterceptError::MutationBlocked)
    }

    fn promote(
        &mut self,
        _group_id: ID,
        _promoter: ID,
        _promoted: ID,
        _access: Access<C>,
    ) -> Result<M, Self::Error> {
        Err(InterceptError::MutationBlocked)
    }

    fn demote(
        &mut self,
        _group_id: ID,
        _demoter: ID,
        _demoted: ID,
        _access: Access<C>,
    ) -> Result<M, Self::Error> {
        Err(InterceptError::MutationBlocked)
    }
}
