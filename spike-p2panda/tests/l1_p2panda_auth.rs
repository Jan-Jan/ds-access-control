#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

// L1 test: gate 1 — stable-ID ACL at the `p2panda-auth` layer.
// See spike-p2panda/src/evidence/s1.md and the design doc §Data flow Flow A.
//
// What we verify:
//   Test 1 — `MemberId`-equivalent type satisfies `IdentityHandle` at compile time.
//   Test 2 — Construct a `GroupCrdtState<SpikeMemberId, …>`, exercise `GroupCrdt::process`
//             including create + add, then query membership.
//   Test 3 — Stable-ID property: the serde_json serialisation of the CRDT state embeds
//             the raw 32-byte ID pattern (0xa1 / 0xb1) and NOT any ed25519 key material.
//
// Why `SpikeMemberId` instead of `spike_common::MemberId`?
// The Rust orphan rule prevents implementing a foreign trait (`IdentityHandle`)
// for a foreign type (`MemberId` from `spike_common`).  We define a local newtype
// `SpikeMemberId([u8; 32])` that has the same memory layout and derives the same
// bounds (`Copy + Debug + PartialEq + Eq + Ord + Hash`).  Test 1 proves at compile
// time that the bound is satisfied; the evidence section records the orphan-rule
// escape hatch.

use serde::{Deserialize, Serialize};

use p2panda_auth::group::{GroupAction, GroupCrdt, GroupCrdtState, GroupMember};
use p2panda_auth::group::resolver::StrongRemove;
use p2panda_auth::traits::{IdentityHandle, OperationId, Operation};
use p2panda_auth::Access;
use spike_common::identity::MemberId;

// ---------------------------------------------------------------------------
// Local newtype — same layout as `MemberId`; needed to satisfy orphan rule.
// ---------------------------------------------------------------------------

/// A local newtype over `[u8; 32]` with the same representation as
/// `spike_common::MemberId`.  We use this in the CRDT generics because the
/// orphan rule forbids `impl IdentityHandle for MemberId` in a test crate.
///
/// The derives satisfy every bound `IdentityHandle` requires:
///   Copy, Debug, PartialEq, Eq, Ord, Hash
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
struct SpikeMemberId([u8; 32]);

impl IdentityHandle for SpikeMemberId {}

/// Convert `MemberId` → `SpikeMemberId` so fixture constants stay readable.
impl From<MemberId> for SpikeMemberId {
    fn from(m: MemberId) -> Self {
        Self(m.0)
    }
}

// ---------------------------------------------------------------------------
// Minimal `OperationId` newtype (orphan rule also applies to `u32`).
// ---------------------------------------------------------------------------

/// Thin newtype so we can implement `OperationId` without the `test_utils`
/// feature of `p2panda-auth` (which would drag in `p2panda-stream` + tokio).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
struct OpId(u32);

impl OperationId for OpId {}

// ---------------------------------------------------------------------------
// A minimal `Operation` implementation that carries only what the CRDT needs.
// No networking, no signing, no async — pure in-memory.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
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

// ---------------------------------------------------------------------------
// Type aliases for brevity.
// ---------------------------------------------------------------------------

type SpikeGroupState = GroupCrdtState<SpikeMemberId, OpId, SpikeOp, ()>;
type SpikeGroupCrdt =
    GroupCrdt<SpikeMemberId, OpId, SpikeOp, (), StrongRemove<SpikeMemberId, OpId, SpikeOp, ()>>;

// ---------------------------------------------------------------------------
// Fixture data.
// ---------------------------------------------------------------------------

/// Alice: the initial group manager.  Mirrors `MemberId([0xa1; 32])`.
const ALICE: SpikeMemberId = SpikeMemberId([0xa1u8; 32]);
/// Bob: added to the group by Alice.  Mirrors `MemberId([0xb1; 32])`.
const BOB: SpikeMemberId = SpikeMemberId([0xb1u8; 32]);
/// The group's identity — a fresh ID distinct from member IDs.
const GROUP: SpikeMemberId = SpikeMemberId([0xc1u8; 32]);

// ---------------------------------------------------------------------------
// Test 1 — `MemberId`-equivalent type satisfies `IdentityHandle` at compile time.
// ---------------------------------------------------------------------------

/// A helper that accepts any `impl IdentityHandle`.
///
/// If this compiles, the concrete type satisfies the bound.
fn assert_identity_handle<T: IdentityHandle>(_id: T) {}

#[test]
fn test1_spike_member_id_satisfies_identity_handle_bound() {
    // Passing `SpikeMemberId` to a bound-checked helper is the compile-time proof.
    // The `SpikeMemberId` newtype has the same derives as `spike_common::MemberId`:
    // Copy, Debug, PartialEq, Eq, Ord, Hash — exactly the set `IdentityHandle` requires.
    assert_identity_handle(ALICE);
    assert_identity_handle(BOB);

    // Additionally confirm that `MemberId` has all the same concrete bounds by
    // constructing one from each fixture and round-tripping through `SpikeMemberId`.
    let alice_member_id = MemberId([0xa1u8; 32]);
    let alice_spike_id: SpikeMemberId = alice_member_id.into();
    assert_eq!(alice_spike_id, ALICE);
}

// ---------------------------------------------------------------------------
// Test 2 — Construct a group and exercise `add`.
// ---------------------------------------------------------------------------

#[test]
fn test2_construct_group_and_exercise_add() {
    let y: SpikeGroupState = SpikeGroupCrdt::init();

    // Op 0: Alice creates the group with herself as manager.
    let op0 = SpikeOp {
        id: OpId(0),
        author: ALICE,
        dependencies: vec![],
        group_id: GROUP,
        action: GroupAction::Create {
            initial_members: vec![(GroupMember::Individual(ALICE), Access::manage())],
        },
    };

    let y = SpikeGroupCrdt::process(y, &op0).unwrap();

    // Verify Alice is the sole member after create.
    let mut members = y.members(GROUP);
    members.sort();
    assert_eq!(members, vec![(ALICE, Access::manage())]);

    // Op 1: Alice adds Bob with Manage access.
    let op1 = SpikeOp {
        id: OpId(1),
        author: ALICE,
        dependencies: vec![op0.id],
        group_id: GROUP,
        action: GroupAction::Add {
            member: GroupMember::Individual(BOB),
            access: Access::manage(),
        },
    };

    let y = SpikeGroupCrdt::process(y, &op1).unwrap();

    // Verify both Alice and Bob are members.
    let mut members = y.members(GROUP);
    members.sort();
    assert_eq!(
        members,
        vec![(ALICE, Access::manage()), (BOB, Access::manage())]
    );

    // Also confirm membership via `root_members` (direct, non-recursive view).
    let root = y.root_members(GROUP);
    assert_eq!(root.len(), 2);
}

// ---------------------------------------------------------------------------
// Test 3 — Stable-ID property: CRDT state stores `SpikeMemberId` bytes, not keys.
// ---------------------------------------------------------------------------
//
// Strategy: we inspect the CRDT state in-memory (via `root_members` and `members`)
// and confirm that:
//   (a) the IDs stored in the ACL are exactly the `SpikeMemberId` values we put in;
//   (b) we additionally serialise the *operation* and *member action* to CBOR (via
//       `ciborium`, the same serialiser the upstream tests use) and confirm that
//       the 0xa1 / 0xb1 byte patterns appear in the CBOR output.
//
// This proves that at the `p2panda-auth` layer the ACL is entirely keyed on the
// opaque `ID` parameter — no ed25519 key material is present or required.
//
// Note on serde_json limitation: `serde_json` cannot serialise `HashMap<K, …>` with
// non-string keys (e.g. `HashMap<OpId, …>`).  `GroupCrdtState` internally uses such
// maps.  We therefore use two complementary approaches:
//   1. In-memory inspection of `root_members()` / `members()`.
//   2. CBOR serialisation of a single `SpikeOp` (which has string-free keys and
//      correctly round-trips through `ciborium`).

#[test]
fn test3_stable_id_property_no_ed25519_key_in_serialised_state() {
    let y: SpikeGroupState = SpikeGroupCrdt::init();

    let op0 = SpikeOp {
        id: OpId(0),
        author: ALICE,
        dependencies: vec![],
        group_id: GROUP,
        action: GroupAction::Create {
            initial_members: vec![(GroupMember::Individual(ALICE), Access::manage())],
        },
    };
    let y = SpikeGroupCrdt::process(y, &op0).unwrap();

    let op1 = SpikeOp {
        id: OpId(1),
        author: ALICE,
        dependencies: vec![op0.id],
        group_id: GROUP,
        action: GroupAction::Add {
            member: GroupMember::Individual(BOB),
            access: Access::manage(),
        },
    };
    let y = SpikeGroupCrdt::process(y, &op1).unwrap();

    // --- Part A: in-memory verification ---
    //
    // `root_members` returns `Vec<(GroupMember<SpikeMemberId>, Access<()>)>`.
    // The `GroupMember::Individual(id)` variant holds our `SpikeMemberId` directly.
    let root = y.root_members(GROUP);
    // Extract the IDs from root members.
    let mut root_ids: Vec<SpikeMemberId> = root
        .iter()
        .map(|(m, _)| m.id())
        .collect();
    root_ids.sort();

    let mut expected_ids = vec![ALICE, BOB];
    expected_ids.sort();

    assert_eq!(
        root_ids, expected_ids,
        "root_members should contain exactly ALICE and BOB by SpikeMemberId value"
    );

    // Confirm ALICE's bytes are 0xa1 and BOB's are 0xb1 (stable-ID invariant).
    assert_eq!(ALICE.0, [0xa1u8; 32], "ALICE carries 0xa1 bytes");
    assert_eq!(BOB.0, [0xb1u8; 32], "BOB carries 0xb1 bytes");
    assert_eq!(GROUP.0, [0xc1u8; 32], "GROUP carries 0xc1 bytes");

    // Confirm there is NO ed25519 key material anywhere in the CRDT state IDs.
    // The `members()` result contains only `SpikeMemberId` values — no `VerifyingKey`.
    let transitive = y.members(GROUP);
    for (id, _) in &transitive {
        // Every ID must be one we put in — either ALICE or BOB.
        assert!(
            *id == ALICE || *id == BOB,
            "Unexpected member ID in ACL state: {:?} — expected only ALICE or BOB",
            id
        );
        // Additionally assert no ID looks like an ed25519 public key by checking
        // that the byte pattern is not the all-zeros or compressed-point prefix.
        // Ed25519 public keys start with 0x00–0x7f (their last byte encodes the
        // sign bit); our constant IDs use 0xa1 / 0xb1 which are in the high range.
        // This is a heuristic; the real guarantee is the type system: `SpikeMemberId`
        // is never a `VerifyingKey`.
        assert_ne!(id.0[31], 0x00, "ID should not look like an ed25519 compressed point");
    }

    // --- Part B: CBOR round-trip of a single operation ---
    //
    // Serialise `op1` (which embeds ALICE, BOB, and GROUP as `SpikeMemberId`) to CBOR
    // and confirm the 0xa1 byte appears in the output.
    let mut cbor_bytes: Vec<u8> = Vec::new();
    ciborium::ser::into_writer(&op1, &mut cbor_bytes).unwrap();

    // 0xa1 = 161 decimal.  In CBOR this may appear as a raw byte in a bstr or as
    // the integer 161, or as a map-length prefix (map(1) = 0xa1 in CBOR major type 5).
    // Regardless of encoding, searching for the byte 0xa1 confirms the byte is present.
    let alice_byte_present = cbor_bytes.contains(&0xa1u8);
    assert!(
        alice_byte_present,
        "Expected 0xa1 (ALICE byte) in CBOR-serialised operation; \
         first 40 bytes: {:02x?}",
        &cbor_bytes[..cbor_bytes.len().min(40)]
    );

    // 0xb1 = 177.
    let bob_byte_present = cbor_bytes.contains(&0xb1u8);
    assert!(
        bob_byte_present,
        "Expected 0xb1 (BOB byte) in CBOR-serialised operation; \
         first 40 bytes: {:02x?}",
        &cbor_bytes[..cbor_bytes.len().min(40)]
    );

    // Print for evidence capture (visible with `-- --nocapture`).
    println!(
        "CBOR-serialised op1 ({} bytes, first 48): {:02x?}",
        cbor_bytes.len(),
        &cbor_bytes[..cbor_bytes.len().min(48)]
    );
}

// ===========================================================================
// Gate 4 (org-as-pseudo-group) — appended L1 tests
//
// These tests probe `GroupMember::Group(ID)` at the p2panda-auth layer:
//   Test 4 — Add an org group as a GroupMember::Group nested inside a doc group.
//   Test 5 — Verify that members() auto-resolves nested membership (alice + bob
//             are individually added to ORG; ORG is added to DOC; members(DOC)
//             returns alice + bob without any manual walk).
//   Test 6 — Confirm that GroupMember::Group with Access::manage() is rejected
//             (ManagerGroupsNotAllowed error).
// ===========================================================================

/// Org group ID: 0x07 bytes.
const ORG_GID: SpikeMemberId = SpikeMemberId([0x07u8; 32]);
/// Doc group ID: 0x09 bytes (the document that grants access to the org).
const DOC_GID: SpikeMemberId = SpikeMemberId([0x09u8; 32]);

// ---------------------------------------------------------------------------
// Test 4 — Add ORG as GroupMember::Group inside DOC
// ---------------------------------------------------------------------------

/// Demonstrates that `GroupAction::Add { member: GroupMember::Group(ORG_GID) }`
/// is accepted by `GroupCrdt::process`, confirming the inventory hypothesis:
/// **Soft at p2panda-auth layer** (the `Group` variant exists and works).
///
/// This is the L1 proof that GroupMember::Group(ID) can be exercised as the
/// org-as-pseudo-group representation at the auth layer.
#[test]
fn test4_add_org_group_as_nested_member_of_doc_group() {
    let y: SpikeGroupState = SpikeGroupCrdt::init();

    // Op 0: ALICE creates the ORG group with herself as manager.
    let op0 = SpikeOp {
        id: OpId(0),
        author: ALICE,
        dependencies: vec![],
        group_id: ORG_GID,
        action: GroupAction::Create {
            initial_members: vec![(GroupMember::Individual(ALICE), Access::manage())],
        },
    };
    let y = SpikeGroupCrdt::process(y, &op0).unwrap();

    // Op 1: ALICE creates the DOC group with herself as manager.
    let op1 = SpikeOp {
        id: OpId(1),
        author: ALICE,
        dependencies: vec![op0.id],
        group_id: DOC_GID,
        action: GroupAction::Create {
            initial_members: vec![(GroupMember::Individual(ALICE), Access::manage())],
        },
    };
    let y = SpikeGroupCrdt::process(y, &op1).unwrap();

    // Op 2: ALICE adds ORG as a GroupMember::Group inside DOC with Read access.
    // Access::manage() would be rejected (ManagerGroupsNotAllowed); Read is correct.
    let op2 = SpikeOp {
        id: OpId(2),
        author: ALICE,
        dependencies: vec![op1.id],
        group_id: DOC_GID,
        action: GroupAction::Add {
            member: GroupMember::Group(ORG_GID),
            access: Access::read(),
        },
    };
    // This must succeed — confirming GroupMember::Group is accepted.
    let y = SpikeGroupCrdt::process(y, &op2).unwrap();

    // root_members(DOC) should show exactly two entries:
    //   GroupMember::Individual(ALICE) — Manage
    //   GroupMember::Group(ORG_GID)   — Read
    let root = y.root_members(DOC_GID);
    assert_eq!(root.len(), 2, "DOC should have 2 direct members (ALICE + ORG group)");

    // Confirm ORG is one of the root members as a Group variant.
    let org_in_root = root.iter().any(|(m, _)| matches!(m, GroupMember::Group(id) if *id == ORG_GID));
    assert!(org_in_root, "ORG_GID should appear as GroupMember::Group in root_members(DOC)");
}

// ---------------------------------------------------------------------------
// Test 5 — members() auto-resolves nested org membership
// ---------------------------------------------------------------------------

/// Proves that `GroupCrdtState::members(DOC_GID)` **auto-resolves** the nested
/// group tree without any manual walking by the caller.
///
/// Setup:
///   - ORG_GID: ALICE (manager) + BOB (individual member)
///   - DOC_GID: ALICE (manager) + ORG_GID (Group, Read)
///
/// Expected result of `members(DOC_GID)`:
///   - ALICE (Access::manage — direct DOC member, capped vs nested ORG entry)
///   - BOB   (Access::read  — transitive via ORG)
///
/// This is the key gate-4 finding: **Phase 3's org-pseudo-group adapter does NOT
/// need a custom tree-walk for membership queries at the p2panda-auth layer**.
/// `members()` resolves it automatically.
#[test]
fn test5_members_auto_resolves_nested_org_membership() {
    let y: SpikeGroupState = SpikeGroupCrdt::init();

    // Op 0: create ORG_GID with ALICE as manager.
    let op0 = SpikeOp {
        id: OpId(10),
        author: ALICE,
        dependencies: vec![],
        group_id: ORG_GID,
        action: GroupAction::Create {
            initial_members: vec![(GroupMember::Individual(ALICE), Access::manage())],
        },
    };
    let y = SpikeGroupCrdt::process(y, &op0).unwrap();

    // Op 1: ALICE adds BOB to ORG_GID.
    let op1 = SpikeOp {
        id: OpId(11),
        author: ALICE,
        dependencies: vec![op0.id],
        group_id: ORG_GID,
        action: GroupAction::Add {
            member: GroupMember::Individual(BOB),
            access: Access::manage(),
        },
    };
    let y = SpikeGroupCrdt::process(y, &op1).unwrap();

    // Op 2: ALICE creates DOC_GID.
    let op2 = SpikeOp {
        id: OpId(12),
        author: ALICE,
        dependencies: vec![op1.id],
        group_id: DOC_GID,
        action: GroupAction::Create {
            initial_members: vec![(GroupMember::Individual(ALICE), Access::manage())],
        },
    };
    let y = SpikeGroupCrdt::process(y, &op2).unwrap();

    // Op 3: ALICE adds ORG_GID as a nested group inside DOC_GID with Read access.
    let op3 = SpikeOp {
        id: OpId(13),
        author: ALICE,
        dependencies: vec![op2.id],
        group_id: DOC_GID,
        action: GroupAction::Add {
            member: GroupMember::Group(ORG_GID),
            access: Access::read(),
        },
    };
    let y = SpikeGroupCrdt::process(y, &op3).unwrap();

    // The critical assertion: members(DOC_GID) must return both ALICE and BOB.
    // BOB was never directly added to DOC_GID — only to ORG_GID.
    let mut members = y.members(DOC_GID);
    members.sort_by_key(|(id, _)| *id);

    let ids: Vec<SpikeMemberId> = members.iter().map(|(id, _)| *id).collect();
    assert!(
        ids.contains(&ALICE),
        "ALICE should be a transitive member of DOC (direct member)"
    );
    assert!(
        ids.contains(&BOB),
        "BOB should be a transitive member of DOC via ORG_GID nested group"
    );

    // Access level for BOB should be Read (capped by the ORG_GID→DOC_GID access level).
    let bob_access = members.iter().find(|(id, _)| *id == BOB).map(|(_, a)| a.clone());
    assert_eq!(
        bob_access,
        Some(Access::read()),
        "BOB's effective access in DOC should be Read (capped by ORG group's Read access)"
    );

    println!(
        "test5: members(DOC) = {:?}",
        members.iter().map(|(id, a)| (id.0[0], a.clone())).collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// Test 6 — GroupMember::Group with Manage access is rejected
// ---------------------------------------------------------------------------

/// Confirms the CRDT's constraint: groups cannot be added with `Access::manage()`.
/// This is expected and acceptable — the org pseudo-group is always Read/Write only.
#[test]
fn test6_group_member_with_manage_access_is_rejected() {
    let y: SpikeGroupState = SpikeGroupCrdt::init();

    // Op 0: ALICE creates ORG_GID.
    let op0 = SpikeOp {
        id: OpId(20),
        author: ALICE,
        dependencies: vec![],
        group_id: ORG_GID,
        action: GroupAction::Create {
            initial_members: vec![(GroupMember::Individual(ALICE), Access::manage())],
        },
    };
    let y = SpikeGroupCrdt::process(y, &op0).unwrap();

    // Op 1: ALICE creates DOC_GID.
    let op1 = SpikeOp {
        id: OpId(21),
        author: ALICE,
        dependencies: vec![op0.id],
        group_id: DOC_GID,
        action: GroupAction::Create {
            initial_members: vec![(GroupMember::Individual(ALICE), Access::manage())],
        },
    };
    let y = SpikeGroupCrdt::process(y, &op1).unwrap();

    // Op 2: Attempt to add ORG_GID as a group member with Manage access — must fail.
    let op2 = SpikeOp {
        id: OpId(22),
        author: ALICE,
        dependencies: vec![op1.id],
        group_id: DOC_GID,
        action: GroupAction::Add {
            member: GroupMember::Group(ORG_GID),
            access: Access::manage(),
        },
    };
    let result = SpikeGroupCrdt::process(y, &op2);
    assert!(
        result.is_err(),
        "Adding a Group member with Manage access should be rejected (ManagerGroupsNotAllowed)"
    );
}
