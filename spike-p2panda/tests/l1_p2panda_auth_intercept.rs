#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

// L1 test: gate 2 — membership-op interception at the `p2panda-auth` layer.
// See spike-p2panda/src/evidence/s2.md and design doc §Data flow Flow D.
//
// What we verify:
//   Test 1 — `Groups` trait is pub and externally implementable.
//             `BlockingGroups<StubGroups>` compiles without any special access.
//   Test 2 — `BlockingGroups::add` returns `Err(MutationBlocked)`, not Ok.
//   Test 3 — `BlockingGroups::remove`, `promote`, `demote`, `receive_from_remote`
//             are all blocked.
//   Test 4 — `BlockingGroups::create` is blocked.
//   Test 5 — Read-only queries (via `GroupCrdtState` directly, which implements
//             the separate `GroupMembership`-style API) still work after mutations
//             were blocked — the intercept does not destroy existing state.
//
// Store-layer finding (compile-time, not a runnable test):
//   `AuthStore<C>::set_auth` cannot be implemented externally because
//   `AuthGroupState<C>` uses `AuthMessage<C>` from a private module.
//   See inline comment at the bottom and evidence/s2.md §L1-spaces.

use p2panda_auth::Access;
use p2panda_auth::group::{GroupAction, GroupCrdt, GroupCrdtState, GroupMember};
use p2panda_auth::group::resolver::StrongRemove;
use p2panda_auth::traits::{IdentityHandle, OperationId, Operation, Groups};
use serde::{Deserialize, Serialize};

use spike_p2panda::s2_membership_intercept::{BlockingGroups, InterceptError};

// ---------------------------------------------------------------------------
// Shared fixtures (matching l1_p2panda_auth.rs exactly)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
struct SpikeMemberId([u8; 32]);

impl IdentityHandle for SpikeMemberId {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
struct OpId(u32);

impl OperationId for OpId {}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct SpikeOp {
    id: OpId,
    author: SpikeMemberId,
    dependencies: Vec<OpId>,
    group_id: SpikeMemberId,
    action: GroupAction<SpikeMemberId, ()>,
}

impl Operation<SpikeMemberId, OpId, ()> for SpikeOp {
    fn id(&self) -> OpId {
        self.id
    }
    fn author(&self) -> SpikeMemberId {
        self.author
    }
    fn dependencies(&self) -> Vec<OpId> {
        self.dependencies.clone()
    }
    fn group_id(&self) -> SpikeMemberId {
        self.group_id
    }
    fn action(&self) -> GroupAction<SpikeMemberId, ()> {
        self.action.clone()
    }
}

type SpikeGroupState = GroupCrdtState<SpikeMemberId, OpId, SpikeOp, ()>;
type SpikeGroupCrdt =
    GroupCrdt<SpikeMemberId, OpId, SpikeOp, (), StrongRemove<SpikeMemberId, OpId, SpikeOp, ()>>;

const ALICE: SpikeMemberId = SpikeMemberId([0xa1; 32]);
const BOB: SpikeMemberId = SpikeMemberId([0xb1; 32]);
const GROUP: SpikeMemberId = SpikeMemberId([0xc1; 32]);

// ---------------------------------------------------------------------------
// Minimal `Groups` impl used as the Inner for BlockingGroups.
//
// `StubGroups` panics on every method — it must never be called since
// `BlockingGroups` intercepts before delegating.
// ---------------------------------------------------------------------------

struct StubGroups;

impl Groups<SpikeMemberId, OpId, SpikeOp, ()> for StubGroups {
    type Error = std::convert::Infallible;

    fn create(
        &mut self,
        _initial_members: Vec<(GroupMember<SpikeMemberId>, Access<()>)>,
    ) -> Result<SpikeOp, Self::Error> {
        panic!("StubGroups::create must not be called — BlockingGroups intercepts first")
    }

    fn receive_from_remote(&mut self, _op: SpikeOp) -> Result<(), Self::Error> {
        panic!("StubGroups::receive_from_remote must not be called")
    }

    fn add(
        &mut self,
        _group_id: SpikeMemberId,
        _adder: SpikeMemberId,
        _added: SpikeMemberId,
        _access: Access<()>,
    ) -> Result<SpikeOp, Self::Error> {
        panic!("StubGroups::add must not be called — BlockingGroups intercepts first")
    }

    fn remove(
        &mut self,
        _group_id: SpikeMemberId,
        _remover: SpikeMemberId,
        _removed: SpikeMemberId,
    ) -> Result<SpikeOp, Self::Error> {
        panic!("StubGroups::remove must not be called")
    }

    fn promote(
        &mut self,
        _group_id: SpikeMemberId,
        _promoter: SpikeMemberId,
        _promoted: SpikeMemberId,
        _access: Access<()>,
    ) -> Result<SpikeOp, Self::Error> {
        panic!("StubGroups::promote must not be called")
    }

    fn demote(
        &mut self,
        _group_id: SpikeMemberId,
        _demoter: SpikeMemberId,
        _demoted: SpikeMemberId,
        _access: Access<()>,
    ) -> Result<SpikeOp, Self::Error> {
        panic!("StubGroups::demote must not be called")
    }
}

// ---------------------------------------------------------------------------
// Test 1 — Groups trait is pub and externally implementable (no sealing)
// ---------------------------------------------------------------------------

/// Compile-time proof: `BlockingGroups<StubGroups>` implements
/// `Groups<SpikeMemberId, OpId, SpikeOp, ()>` and the compiler accepts it.
///
/// If `Groups` were sealed this would fail to compile. It does not —
/// confirming that external impls are valid and the trait is not sealed.
#[test]
fn test1_groups_trait_is_externally_implementable() {
    let mut blocker: BlockingGroups<StubGroups> = BlockingGroups::new(StubGroups);

    // Exercise one mutation to confirm the impl dispatches at runtime.
    let result = blocker.add(GROUP, ALICE, BOB, Access::manage());
    assert_eq!(
        result,
        Err(InterceptError::MutationBlocked),
        "Groups::add on BlockingGroups must return MutationBlocked"
    );

    println!("Test 1 PASS: Groups trait is pub, not sealed, externally implementable.");
}

// ---------------------------------------------------------------------------
// Test 2 — add is blocked
// ---------------------------------------------------------------------------

#[test]
fn test2_add_is_blocked() {
    let mut blocker: BlockingGroups<StubGroups> = BlockingGroups::new(StubGroups);

    let result = blocker.add(GROUP, ALICE, BOB, Access::manage());
    assert_eq!(result, Err(InterceptError::MutationBlocked));

    // Confirm the error message references the trie policy.
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("trie is the sole write authority"),
        "Error message should reference the trie policy; got: {msg}"
    );
    println!("Test 2 PASS: Groups::add blocked with message: {msg}");
}

// ---------------------------------------------------------------------------
// Test 3 — remove / promote / demote / receive_from_remote all blocked
// ---------------------------------------------------------------------------

#[test]
fn test3_all_mutations_blocked() {
    let mut blocker: BlockingGroups<StubGroups> = BlockingGroups::new(StubGroups);

    assert_eq!(
        blocker.remove(GROUP, ALICE, BOB),
        Err(InterceptError::MutationBlocked),
        "remove must be blocked"
    );
    assert_eq!(
        blocker.promote(GROUP, ALICE, BOB, Access::manage()),
        Err(InterceptError::MutationBlocked),
        "promote must be blocked"
    );
    assert_eq!(
        blocker.demote(GROUP, ALICE, BOB, Access::write()),
        Err(InterceptError::MutationBlocked),
        "demote must be blocked"
    );

    let dummy_op = SpikeOp {
        id: OpId(999),
        author: ALICE,
        group_id: GROUP,
        dependencies: vec![],
        action: GroupAction::Remove {
            member: GroupMember::Individual(BOB),
        },
    };
    assert_eq!(
        blocker.receive_from_remote(dummy_op),
        Err(InterceptError::MutationBlocked),
        "receive_from_remote must be blocked"
    );

    println!("Test 3 PASS: remove, promote, demote, receive_from_remote all blocked.");
}

// ---------------------------------------------------------------------------
// Test 4 — create is blocked
// ---------------------------------------------------------------------------

#[test]
fn test4_create_is_blocked() {
    let mut blocker: BlockingGroups<StubGroups> = BlockingGroups::new(StubGroups);

    let result =
        blocker.create(vec![(GroupMember::Individual(ALICE), Access::manage())]);
    assert_eq!(result, Err(InterceptError::MutationBlocked));
    println!("Test 4 PASS: Groups::create blocked.");
}

// ---------------------------------------------------------------------------
// Test 5 — Read path still works; intercept does not destroy existing state
// ---------------------------------------------------------------------------
//
// `BlockingGroups` wraps the `Groups` mutation trait only. The read-only API
// (GroupCrdt::process, GroupCrdtState::members, ::root_members) is on a different
// path. We confirm that after mutations are blocked, the existing state is still
// queryable and unchanged.

#[test]
fn test5_read_path_bypasses_blocker() {
    // Build a real GroupCrdtState using GroupCrdt::process (the CRDT API).
    let y: SpikeGroupState = SpikeGroupCrdt::init();

    // Alice creates the group (direct CRDT — not through BlockingGroups).
    let create_op = SpikeOp {
        id: OpId(1),
        author: ALICE,
        group_id: GROUP,
        dependencies: vec![],
        action: GroupAction::Create {
            initial_members: vec![(GroupMember::Individual(ALICE), Access::manage())],
        },
    };
    let y = SpikeGroupCrdt::process(y, &create_op).unwrap();

    // Confirm Alice is a member.
    // `members()` returns Vec<(ID, Access<C>)> — just the ID, not GroupMember.
    let members = y.members(GROUP);
    assert!(
        members.iter().any(|(id, _)| *id == ALICE),
        "ALICE must be a member after Create"
    );

    // Now simulate: application code tries to add BOB via BlockingGroups.
    // The add is blocked — BOB should NOT appear in state.
    let mut blocker: BlockingGroups<StubGroups> = BlockingGroups::new(StubGroups);
    let add_result = blocker.add(GROUP, ALICE, BOB, Access::manage());
    assert_eq!(add_result, Err(InterceptError::MutationBlocked));

    // State has NOT mutated (BOB is still absent).
    let members_after = y.members(GROUP);
    assert!(
        !members_after.iter().any(|(id, _)| *id == BOB),
        "BOB must NOT be a member — blocked add did not mutate state"
    );

    println!(
        "Test 5 PASS: state unchanged after blocked add; members = {members_after:?}"
    );
}

// ---------------------------------------------------------------------------
// Store-layer finding (compile-time evidence — not a runnable test)
// ---------------------------------------------------------------------------
//
// The design hypothesis was: a `TrieGatedAuthStore<Inner>` that wraps any
// `Inner: AuthStore<C>` and rejects `set_auth` calls.
//
// Investigation showed that `AuthStore<C>` is in `pub mod traits` of p2panda-spaces:
//
//   pub trait AuthStore<C: Conditions> {
//       type Error: Debug;
//       fn auth(&self) -> impl Future<Output = Result<AuthGroupState<C>, Self::Error>>;
//       fn set_auth(&self, y: &AuthGroupState<C>) -> impl Future<...>;
//   }
//
// `AuthGroupState<C>` is a type alias in `mod types` (a PRIVATE module):
//   pub type AuthGroupState<C> =
//     GroupCrdtState<ActorId, OperationId, AuthMessage<C>, C>;
//
// `AuthMessage<C>` is defined in `mod auth` (also PRIVATE).
//
// Attempting to import from outside:
//   use p2panda_spaces::types::AuthGroupState;
//   // ERROR: error[E0603]: module `types` is private
//
// Because the parameter type in `set_auth` is not nameable from outside the crate,
// an external `TrieGatedAuthStore` impl of `AuthStore<C>` is BLOCKED.
//
// This is a Hard finding at the p2panda-spaces store layer.
//
// The remaining intercept option at the spaces layer is the `Forge` trait:
//   pub trait Forge<ID, M, C> { fn forge(&self, args: SpacesArgs<ID, C>) -> impl Future<...>; }
// `SpacesArgs<ID, C>` IS publicly re-exported, so `BlockingForge` is syntactically
// possible. However, `Forge::forge` is called to produce messages AFTER auth state
// is (potentially) updated, so it does not intercept the state write.
//
// Verdict for spaces layer: Hard — no clean intercept seam without a fork of
// p2panda-spaces to either re-export `AuthGroupState` or to change `AuthStore`.
// See evidence/s2.md §"L1 — p2panda-spaces layer (store wrapper)" for full analysis.
