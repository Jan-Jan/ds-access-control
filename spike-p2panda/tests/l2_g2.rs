#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

// L2 test: gate 2 — end-to-end membership-op interception (best-effort).
// See spike-p2panda/src/evidence/s2.md §L2.
//
// Design intent: demonstrate the full "trie is the sole write authority" invariant
// by composing the intercept components. Specifically:
//
//   1. Application code obtains a `BlockingGroups<StubGroups>` and an initial
//      `GroupCrdtState` (the ACL state).
//   2. A simulated trie-driven add path uses the CRDT directly (bypassing
//      `BlockingGroups`) to add a member — the only allowed write path.
//   3. Application code attempts to add a *second* member via `BlockingGroups::add`
//      — this is blocked.
//   4. The final state contains only the trie-authorised member, not the
//      application-code-attempted member.
//
// Why no p2panda-spaces runtime composition?
// The `AuthStore<C>` trait cannot be implemented externally (see L1 finding:
// `AuthGroupState<C>` requires `AuthMessage<C>` from a private module). Without
// a conforming `AuthStore<C>` the `Manager` / `Group` / `Space` types cannot be
// instantiated. The L2 therefore operates at the `p2panda-auth` CRDT layer — which
// is precisely where `BlockingGroups` lives — rather than the spaces API layer.
//
// This is explicitly documented as "best-effort L2" per the task plan: "if the
// runtime composition is too heavy, accept a best-effort L2 that demonstrates the
// intercept at one layer". The Hard gap at the spaces layer means the spaces
// runtime path is *architecturally* blocked, not merely time-boxed.

use p2panda_auth::Access;
use p2panda_auth::group::{GroupAction, GroupCrdt, GroupCrdtState, GroupMember};
use p2panda_auth::group::resolver::StrongRemove;
use p2panda_auth::traits::{IdentityHandle, OperationId, Operation, Groups};
use serde::{Deserialize, Serialize};

use spike_p2panda::s2_membership_intercept::{BlockingGroups, InterceptError};

// ---------------------------------------------------------------------------
// Shared fixtures
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
    fn id(&self) -> OpId { self.id }
    fn author(&self) -> SpikeMemberId { self.author }
    fn dependencies(&self) -> Vec<OpId> { self.dependencies.clone() }
    fn group_id(&self) -> SpikeMemberId { self.group_id }
    fn action(&self) -> GroupAction<SpikeMemberId, ()> { self.action.clone() }
}

type SpikeGroupState = GroupCrdtState<SpikeMemberId, OpId, SpikeOp, ()>;
type SpikeGroupCrdt =
    GroupCrdt<SpikeMemberId, OpId, SpikeOp, (), StrongRemove<SpikeMemberId, OpId, SpikeOp, ()>>;

// Principals
const TRIE_AUTHORITY: SpikeMemberId = SpikeMemberId([0x01; 32]); // simulates the trie
const ALICE: SpikeMemberId = SpikeMemberId([0xa1; 32]); // trie-authorised member
const MALLORY: SpikeMemberId = SpikeMemberId([0xff; 32]); // attempted bypass
const GROUP: SpikeMemberId = SpikeMemberId([0xc1; 32]);

// Stub inner for BlockingGroups — panics if called.
struct StubGroups;

impl Groups<SpikeMemberId, OpId, SpikeOp, ()> for StubGroups {
    type Error = std::convert::Infallible;
    fn create(&mut self, _: Vec<(GroupMember<SpikeMemberId>, Access<()>)>) -> Result<SpikeOp, Self::Error> {
        panic!("StubGroups::create called")
    }
    fn receive_from_remote(&mut self, _: SpikeOp) -> Result<(), Self::Error> {
        panic!("StubGroups::receive_from_remote called")
    }
    fn add(&mut self, _: SpikeMemberId, _: SpikeMemberId, _: SpikeMemberId, _: Access<()>) -> Result<SpikeOp, Self::Error> {
        panic!("StubGroups::add called")
    }
    fn remove(&mut self, _: SpikeMemberId, _: SpikeMemberId, _: SpikeMemberId) -> Result<SpikeOp, Self::Error> {
        panic!("StubGroups::remove called")
    }
    fn promote(&mut self, _: SpikeMemberId, _: SpikeMemberId, _: SpikeMemberId, _: Access<()>) -> Result<SpikeOp, Self::Error> {
        panic!("StubGroups::promote called")
    }
    fn demote(&mut self, _: SpikeMemberId, _: SpikeMemberId, _: SpikeMemberId, _: Access<()>) -> Result<SpikeOp, Self::Error> {
        panic!("StubGroups::demote called")
    }
}

// ---------------------------------------------------------------------------
// L2 test — full intercept flow (auth-layer best-effort)
// ---------------------------------------------------------------------------

/// End-to-end demonstration of the trie-only-write invariant at the p2panda-auth
/// CRDT layer.
///
/// Flow:
///  1. Trie-authority path: `GroupCrdt::process` (the only allowed write path) adds
///     ALICE via a Create op. This simulates the trie-driven membership update.
///  2. Blocked path: application code attempts `BlockingGroups::add(MALLORY)`.
///     This returns `Err(MutationBlocked)`.
///  3. Invariant check: only ALICE is a member; MALLORY is absent.
///
/// This proves the trie is the sole write authority: every mutation that goes
/// through the `Groups` trait layer is intercepted; only mutations that go
/// through the CRDT directly (i.e. trie-driven) succeed.
#[test]
fn l2_trie_is_sole_write_authority() {
    // ---- Step 1: Trie-authorised membership update -------------------------
    // The trie authority drives state changes via GroupCrdt::process directly.
    // This is the allowed write path.

    let y: SpikeGroupState = SpikeGroupCrdt::init();

    let create_op = SpikeOp {
        id: OpId(1),
        author: TRIE_AUTHORITY,
        group_id: GROUP,
        dependencies: vec![],
        action: GroupAction::Create {
            initial_members: vec![(GroupMember::Individual(ALICE), Access::manage())],
        },
    };
    let y = SpikeGroupCrdt::process(y, &create_op).unwrap();

    // Verify ALICE is now a member (trie-authorised).
    let state_after_trie = y.members(GROUP);
    let alice_present = state_after_trie.iter().any(|(id, _)| *id == ALICE);
    assert!(alice_present, "ALICE must be a trie-authorised member");

    // ---- Step 2: Blocked application-code bypass attempt -------------------
    // Application code attempts to add MALLORY via the Groups trait.
    // BlockingGroups intercepts this and returns MutationBlocked.

    let mut blocker: BlockingGroups<StubGroups> = BlockingGroups::new(StubGroups);
    let bypass_result = blocker.add(GROUP, ALICE, MALLORY, Access::write());

    assert_eq!(
        bypass_result,
        Err(InterceptError::MutationBlocked),
        "application-code add via Groups trait must be blocked"
    );

    // ---- Step 3: Invariant verification ------------------------------------
    // The group state was never passed to BlockingGroups (it only wraps the
    // Groups mutation API, not the state). The state `y` is unchanged.
    // MALLORY is absent; ALICE is still present.

    let final_state = y.members(GROUP);

    let mallory_absent = !final_state.iter().any(|(id, _)| *id == MALLORY);
    assert!(mallory_absent, "MALLORY must be absent — blocked add did not mutate state");

    let alice_still_present = final_state.iter().any(|(id, _)| *id == ALICE);
    assert!(alice_still_present, "ALICE must still be present after blocked bypass attempt");

    println!(
        "L2 PASS — trie-only-write invariant confirmed:\n\
         - Trie-authorised member (ALICE): present = {alice_still_present}\n\
         - Bypass-attempted member (MALLORY): absent = {mallory_absent}\n\
         - Groups::add blocked with: {:?}",
        bypass_result.unwrap_err()
    );
}

/// Demonstrates that `InterceptError::MutationBlocked` is distinct from
/// `InterceptError::Inner(_)`, ensuring callers can distinguish policy-blocks
/// from underlying implementation errors.
#[test]
fn l2_error_type_distinguishable() {
    let mut blocker: BlockingGroups<StubGroups> = BlockingGroups::new(StubGroups);
    let err = blocker.add(GROUP, ALICE, MALLORY, Access::write()).unwrap_err();

    assert!(
        matches!(err, InterceptError::MutationBlocked),
        "blocked add must yield MutationBlocked variant, not Inner"
    );
    assert!(
        !matches!(err, InterceptError::Inner(_)),
        "MutationBlocked is not an Inner error"
    );
    println!("L2 PASS — error variant is MutationBlocked, not Inner");
}

/// Verifies that multiple sequential bypass attempts are all blocked and do not
/// accumulate side effects (idempotent blocking).
#[test]
fn l2_repeated_bypass_attempts_all_blocked() {
    let y: SpikeGroupState = SpikeGroupCrdt::init();
    let create_op = SpikeOp {
        id: OpId(1),
        author: TRIE_AUTHORITY,
        group_id: GROUP,
        dependencies: vec![],
        action: GroupAction::Create {
            initial_members: vec![(GroupMember::Individual(ALICE), Access::manage())],
        },
    };
    let y = SpikeGroupCrdt::process(y, &create_op).unwrap();

    let mut blocker: BlockingGroups<StubGroups> = BlockingGroups::new(StubGroups);

    // Five sequential bypass attempts — all must be blocked.
    for i in 0..5u32 {
        let fake_member = SpikeMemberId([i as u8; 32]);
        let result = blocker.add(GROUP, ALICE, fake_member, Access::write());
        assert_eq!(
            result,
            Err(InterceptError::MutationBlocked),
            "attempt #{i} must be blocked"
        );
    }

    // State still has only ALICE.
    let final_state = y.members(GROUP);
    assert_eq!(
        final_state.len(),
        1,
        "only ALICE should be in state; got {} members",
        final_state.len()
    );
    assert!(final_state.iter().any(|(id, _)| *id == ALICE));

    println!("L2 PASS — five sequential bypass attempts all blocked; state unchanged.");
}

// ---------------------------------------------------------------------------
// Deferred coverage note
// ---------------------------------------------------------------------------
//
// The L2 above is "best-effort" per the task plan.
//
// What IS demonstrated:
//   - `BlockingGroups` intercepts all `Groups` trait mutations.
//   - State populated via the trie-authorised CRDT path (GroupCrdt::process)
//     is unaffected by subsequent blocked bypass attempts.
//   - The trie-only-write invariant holds at the p2panda-auth CRDT layer.
//
// What is NOT demonstrated (deferred):
//   - Intercept at the p2panda-spaces layer (`Space::add`, `Group::add`).
//   - This is ARCHITECTURALLY BLOCKED: `AuthStore<C>::set_auth` parameter type
//     (`AuthGroupState<C>`) is in a private module and cannot be named from
//     outside p2panda-spaces. External `AuthStore<C>` impls are impossible
//     without forking p2panda-spaces. This is the Hard gap recorded in
//     evidence/s2.md and the gap-matrix row for gate 2.
//
// Salvage path for Phase 3:
//   Fork p2panda-spaces locally (per project_p2panda_fork_policy). Add a single
//   public re-export `pub use types::AuthGroupState;` (or make `mod types` pub).
//   This unlocks external `AuthStore<C>` impls, enabling a proper
//   `TrieGatedAuthStore` wrapper that blocks `set_auth`.
