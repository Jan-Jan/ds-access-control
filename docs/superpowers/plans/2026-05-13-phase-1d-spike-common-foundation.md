# Phase 1.d Library Qualification — `spike-common` Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Spec:** [`docs/superpowers/specs/2026-05-13-ods-phase-1d-library-qualification-design.md`](../specs/2026-05-13-ods-phase-1d-library-qualification-design.md) (commit `057e936`).

**Goal:** Build the `spike-common` Rust crate that defines the shared contract both library spikes adhere to (identity types, `MemberKeyResolver` trait, `StubTrie` implementation, scenario fixtures, gap matrix types, and the `gap-update` binary), plus empty placeholder crates for `spike-keyhive` and `spike-p2panda` so the cargo workspace is well-formed and ready for the per-library implementation plans that follow this one.

**Architecture:** A workspace at the project root containing four members: existing `org-members`, new `spike-common` (Apache-2.0 library + binary, `no_std + alloc` capable, matches `org-members` build configurations), and two empty placeholder crates `spike-keyhive` and `spike-p2panda` (GPL-3.0) that will be filled in by follow-up plans. `spike-common` types are intentionally re-defined locally rather than imported from `org-members` so the spike is isolated from `org-members` evolution and the resolver trait surface is evaluated on its own merits as a Phase 3 design input. The `gap-update` binary is `std`-only (`required-features = ["std"]`) so the library crate's WASM build is not encumbered by JSON tooling.

**Tech Stack:** Rust 2021 edition, MSRV 1.81 (matches `org-members`). Dependencies: `ed25519-dalek` 2.x with `alloc + serde` features; `hashbrown` 0.15 with `default-hasher` for `no_std` HashMap; `serde` 1.x + `postcard` 1.x for `no_std` serialization; `thiserror` 2.x for error types; `serde_json` (binary only) for the gap-matrix JSON output. No async.

**Out of scope for this plan:**
- Per-library substitution work in `spike-keyhive` and `spike-p2panda` (covered by two follow-up plans, written after sub-crate inventory is done).
- The actual L1/L2/L3 tests against either library (those live in the spike crates themselves).
- Any modification of `org-members` (Phase 1.a; out of scope per spec §Out of scope).

**Follow-up plans (not part of this one, written after this lands):**
1. `spike-keyhive` per-gate plan — written after Keyhive sub-crate inventory step completes.
2. `spike-p2panda` per-gate plan — written after p2panda sub-crate inventory step completes.

---

## File structure produced by this plan

```
2-tier-access-control/
├── Cargo.toml                            [NEW] workspace root
├── org-members/                          [existing — unchanged]
├── spike-common/                         [NEW]
│   ├── Cargo.toml
│   ├── README.md
│   ├── scenarios/                        markdown specs (siblings to src/)
│   │   ├── revocation.md
│   │   ├── gating.md
│   │   └── org_pseudo_group.md
│   ├── src/
│   │   ├── lib.rs
│   │   ├── identity.rs
│   │   ├── resolver.rs
│   │   ├── stub_trie.rs
│   │   ├── scenarios.rs
│   │   ├── report.rs
│   │   └── bin/
│   │       └── gap-update.rs
│   └── tests/
│       ├── stub_trie_integration.rs
│       ├── fixtures_integration.rs
│       └── report_integration.rs
├── spike-keyhive/                        [NEW — placeholder only]
│   ├── Cargo.toml
│   └── src/
│       └── lib.rs                        // crate-level docs only; no impls yet
└── spike-p2panda/                        [NEW — placeholder only]
    ├── Cargo.toml
    └── src/
        └── lib.rs                        // crate-level docs only; no impls yet
```

---

### Task 1: Create worktree

**Files:** none modified directly; worktree skill creates the branch.

- [ ] **Step 1: Invoke the worktree skill**

Invoke `superpowers:using-git-worktrees` at execution time to create branch `worktree-spike-phase-1d` from `master`. All subsequent tasks happen inside that worktree.

- [ ] **Step 2: Verify worktree state**

Run: `git status && git rev-parse --abbrev-ref HEAD`
Expected: on branch `worktree-spike-phase-1d`, clean working tree, HEAD at commit `057e936` (the spec commit) or newer.

---

### Task 2: Workspace + placeholder crates

**Files:**
- Create: `Cargo.toml` (workspace root)
- Create: `spike-common/Cargo.toml`
- Create: `spike-common/src/lib.rs`
- Create: `spike-common/README.md`
- Create: `spike-keyhive/Cargo.toml`
- Create: `spike-keyhive/src/lib.rs`
- Create: `spike-p2panda/Cargo.toml`
- Create: `spike-p2panda/src/lib.rs`

- [ ] **Step 1: Create the workspace root `Cargo.toml`**

```toml
[workspace]
resolver = "2"
members = [
    "org-members",
    "spike-common",
    "spike-keyhive",
    "spike-p2panda",
]

[workspace.package]
edition = "2021"
rust-version = "1.81"

[workspace.lints.clippy]
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
```

- [ ] **Step 2: Verify `org-members` still builds inside the workspace**

Run: `cargo build -p org-members && cargo test -p org-members`
Expected: PASS. Workspace inheritance is opt-in; existing `org-members/Cargo.toml` is unaffected.

- [ ] **Step 3: Create `spike-common/Cargo.toml`**

```toml
[package]
name = "spike-common"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license = "Apache-2.0"
description = "Shared contract for ODS Phase 1.d library-qualification spikes"

[features]
default = ["std", "serde"]
std = ["serde?/std", "postcard?/use-std", "ed25519-dalek/std"]
serde = ["dep:serde", "dep:postcard", "ed25519-dalek/serde"]

[dependencies]
ed25519-dalek = { version = "2", default-features = false, features = ["alloc"] }
hashbrown = { version = "0.15", default-features = false, features = ["default-hasher", "inline-more"] }
serde = { version = "1", default-features = false, features = ["derive", "alloc"], optional = true }
postcard = { version = "1", default-features = false, features = ["alloc"], optional = true }
thiserror = { version = "2", default-features = false }

# binary-only deps (std), gated by required-features
serde_json = { version = "1", optional = true }

[[bin]]
name = "gap-update"
path = "src/bin/gap-update.rs"
required-features = ["std", "serde", "dep:serde_json"]

[lints]
workspace = true

[dev-dependencies]
proptest = "1"
serde_json = "1"
```

Note: `dep:serde_json` as a `required-features` doesn't work directly in older Cargo — if Cargo complains, replace `required-features = ["std", "serde", "dep:serde_json"]` with `required-features = ["std", "serde", "json"]` and add a `json = ["dep:serde_json"]` entry to `[features]`. We can adjust at execution time based on Cargo's response.

- [ ] **Step 4: Create `spike-common/src/lib.rs`**

```rust
//! Shared contract for ODS Phase 1.d library-qualification spikes.
//!
//! Defines: identity types, the `MemberKeyResolver` trait, an in-memory
//! `StubTrie` implementation, scenario fixtures, and the gap matrix
//! types used to score Keyhive and p2panda against the six gates.
//!
//! See `docs/superpowers/specs/2026-05-13-ods-phase-1d-library-qualification-design.md`
//! for the full design.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod identity;
pub mod report;
pub mod resolver;
pub mod scenarios;
pub mod stub_trie;
```

- [ ] **Step 5: Create `spike-common/README.md`**

```markdown
# spike-common

Shared contract for the ODS Phase 1.d library-qualification spikes.

This crate defines the contract that both `spike-keyhive` and `spike-p2panda`
implement against. See the design at
`docs/superpowers/specs/2026-05-13-ods-phase-1d-library-qualification-design.md`
for the full picture.

## Build configurations

```
cargo build && cargo test                                                  # default
cargo check --no-default-features                                          # bare no_std
cargo check --no-default-features --features serde                         # no_std + serde
cargo check --no-default-features --features serde --target wasm32-unknown-unknown
```

## Binary

`cargo run --bin gap-update` updates `docs/phase-1d/gap-matrix.{md,json}`
from the latest test-result fingerprints.
```

- [ ] **Step 6: Create empty placeholder crates `spike-keyhive` and `spike-p2panda`**

`spike-keyhive/Cargo.toml`:
```toml
[package]
name = "spike-keyhive"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license = "GPL-3.0-only"
description = "Phase 1.d qualification spike for the Keyhive (Ink & Switch) local-first stack"
publish = false

[dependencies]
spike-common = { path = "../spike-common" }

[lints]
workspace = true
```

`spike-keyhive/src/lib.rs`:
```rust
//! Phase 1.d qualification spike for the Keyhive (Ink & Switch) local-first stack.
//!
//! See the parent design at
//! `docs/superpowers/specs/2026-05-13-ods-phase-1d-library-qualification-design.md`.
//!
//! This crate is currently a placeholder. The per-gate substitution modules
//! will be filled in by the follow-up implementation plan that runs after
//! the Keyhive sub-crate inventory step (Task 1 of the follow-up plan).

#![cfg_attr(not(feature = "std"), no_std)]
```

`spike-p2panda/Cargo.toml` and `spike-p2panda/src/lib.rs`: same shape, substitute "p2panda" for "Keyhive" in name/description/docs.

- [ ] **Step 7: Verify workspace builds**

Run: `cargo check --workspace`
Expected: success, no warnings, three new crates compile.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml spike-common/ spike-keyhive/ spike-p2panda/
git commit -m "feat(phase-1d): workspace + placeholder spike crates

Adds the root cargo workspace, spike-common scaffolding (no impls yet),
and empty placeholder crates for spike-keyhive and spike-p2panda."
```

---

### Task 3: Identity types

**Files:**
- Create: `spike-common/src/identity.rs`

The five identity types are pure value types. We write them and a single round-trip serialization test. Full TDD is overkill for plain data; one assertion confirms the `Serialize`/`Deserialize` derivations work.

- [ ] **Step 1: Write the failing test**

Add to bottom of `spike-common/src/identity.rs` (file does not yet exist; create it with just the test first):

```rust
#[cfg(test)]
#[cfg(feature = "serde")]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn member_id_postcard_roundtrip() {
        let id = MemberId([7u8; 32]);
        let bytes = postcard::to_allocvec(&id).unwrap();
        let back: MemberId = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn p2p_member_key_postcard_roundtrip() {
        let signing = SigningKey::from_bytes(&[3u8; 32]);
        let key = P2pMemberKey(signing.verifying_key());
        let bytes = postcard::to_allocvec(&key).unwrap();
        let back: P2pMemberKey = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(key, back);
    }

    #[test]
    fn principal_postcard_roundtrip() {
        let m = Principal::Member(MemberId([1u8; 32]));
        let o = Principal::Org;
        for p in [m, o] {
            let bytes = postcard::to_allocvec(&p).unwrap();
            let back: Principal = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(p, back);
        }
    }

    #[test]
    fn epoch_ordering() {
        assert!(Epoch(0) < Epoch(1));
        assert!(Epoch(u64::MAX) > Epoch(u64::MAX - 1));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p spike-common --lib identity`
Expected: FAIL with compile errors (types don't exist).

- [ ] **Step 3: Implement the identity types above the test module**

Prepend to `spike-common/src/identity.rs`:

```rust
//! Identity types shared by both spikes.
//!
//! These mirror the `org-members` type shapes but are re-defined locally
//! so the spike is isolated from `org-members` evolution. PII-free; no
//! handles.

use ed25519_dalek::VerifyingKey;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// 32-byte immutable member identifier. SMT key on the trie side; opaque
/// principal on the library side.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MemberId(pub [u8; 32]);

/// Member-as-a-group key (ed25519 verifying key). The "member" public key
/// the local-first library uses when granting access to a `Principal::Member`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct P2pMemberKey(pub VerifyingKey);

/// Per-device verifying key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct P2pDeviceKey(pub VerifyingKey);

/// Organisation-as-a-pseudo-group key (ed25519 verifying key).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OrgKey(pub VerifyingKey);

/// Monotonic epoch counter for trie/CGKA versioning.
#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Epoch(pub u64);

/// Opaque principal type. The library can only dereference these via
/// `MemberKeyResolver`. This is the type-system half of the substitution-1
/// enforcement (the other half is the no-direct-cache invariant in Flow B).
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Principal {
    Member(MemberId),
    Org,
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p spike-common --lib identity`
Expected: PASS — 4 tests.

- [ ] **Step 5: Verify clippy + no_std + WASM build**

Run, expecting success on each:
```bash
cargo clippy -p spike-common -- -D warnings
cargo check -p spike-common --no-default-features
cargo check -p spike-common --no-default-features --features serde
cargo check -p spike-common --no-default-features --features serde --target wasm32-unknown-unknown
```

If the WASM target is not installed, run `rustup target add wasm32-unknown-unknown` first.

- [ ] **Step 6: Commit**

```bash
git add spike-common/src/identity.rs spike-common/src/lib.rs
git commit -m "feat(spike-common): identity types

MemberId, P2pMemberKey, P2pDeviceKey, OrgKey, Epoch, Principal.
Serde + postcard roundtrip tests."
```

---

### Task 4: `ResolverError` + `MemberKeyResolver` trait

**Files:**
- Create: `spike-common/src/resolver.rs`

- [ ] **Step 1: Write the trait and error type (no test yet; trait alone has no behaviour to test)**

Create `spike-common/src/resolver.rs`:

```rust
//! The `MemberKeyResolver` trait — the spike's contract with the trie.
//!
//! Both spikes resolve every `Principal` through this trait. The library's
//! internal `Principal -> Key` cache (if any) must be a derived view of
//! this trait, never authoritative. See the design's Flow B.

use alloc::vec::Vec;

use crate::identity::{Epoch, MemberId, OrgKey, P2pDeviceKey, P2pMemberKey};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ResolverError {
    #[error("member not in trie: {0:?}")]
    UnknownMember(MemberId),

    #[error("member has no current p2p key (isolated state)")]
    IsolatedMember,

    #[error("org key not set")]
    OrgKeyUnset,
}

pub trait MemberKeyResolver {
    /// Current member-as-a-group key for `id`, or an error if the member
    /// is not in the trie / is isolated.
    fn p2p_member_key(&self, id: &MemberId) -> Result<P2pMemberKey, ResolverError>;

    /// Current organisation-as-a-pseudo-group key.
    fn org_key(&self) -> Result<OrgKey, ResolverError>;

    /// Currently-authorised devices for `id`. Empty vec is a valid
    /// observation (the member is isolated); the resolver does not turn
    /// this into an error.
    fn current_devices(&self, id: &MemberId) -> Result<Vec<P2pDeviceKey>, ResolverError>;

    /// IDs of all current members of the organisation. Used by Flow E2/F2
    /// (org-as-pseudo-group p2p auth) to fan out across the org.
    fn org_member_ids(&self) -> Vec<MemberId>;

    fn is_member(&self, id: &MemberId) -> bool;

    fn epoch(&self) -> Epoch;
}
```

- [ ] **Step 2: Run check to confirm it compiles**

Run: `cargo check -p spike-common && cargo clippy -p spike-common -- -D warnings`
Expected: success.

- [ ] **Step 3: Commit**

```bash
git add spike-common/src/resolver.rs spike-common/src/lib.rs
git commit -m "feat(spike-common): MemberKeyResolver trait + ResolverError"
```

---

### Task 5: `StubTrie`

**Files:**
- Create: `spike-common/src/stub_trie.rs`
- Create: `spike-common/tests/stub_trie_integration.rs`

TDD here — behavior matters and there are non-trivial mutation semantics (isolation, revocation, org-key rotation).

- [ ] **Step 1: Write the failing integration test**

Create `spike-common/tests/stub_trie_integration.rs`:

```rust
use ed25519_dalek::SigningKey;
use spike_common::identity::{MemberId, P2pDeviceKey, P2pMemberKey};
use spike_common::resolver::{MemberKeyResolver, ResolverError};
use spike_common::stub_trie::StubTrie;

fn make_signing(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

#[test]
fn fresh_member_has_key_and_devices() {
    let alice = MemberId([1u8; 32]);
    let alice_p2p = P2pMemberKey(make_signing(2).verifying_key());
    let alice_dev_1 = P2pDeviceKey(make_signing(3).verifying_key());

    let trie = StubTrie::new()
        .add_member(alice, alice_p2p, alloc::vec![alice_dev_1]);

    assert!(trie.is_member(&alice));
    assert_eq!(trie.p2p_member_key(&alice).unwrap(), alice_p2p);
    assert_eq!(trie.current_devices(&alice).unwrap(), alloc::vec![alice_dev_1]);
    assert_eq!(trie.epoch().0, 1);
}

#[test]
fn unknown_member_lookup_errors() {
    let trie = StubTrie::new();
    let ghost = MemberId([99u8; 32]);
    assert_eq!(trie.p2p_member_key(&ghost), Err(ResolverError::UnknownMember(ghost)));
}

#[test]
fn revoke_member_removes_keys_and_bumps_epoch() {
    let alice = MemberId([1u8; 32]);
    let alice_p2p = P2pMemberKey(make_signing(2).verifying_key());
    let trie = StubTrie::new().add_member(alice, alice_p2p, alloc::vec![]);
    let epoch_before = trie.epoch().0;

    let trie = trie.stub_revoke(&alice);

    assert!(!trie.is_member(&alice));
    assert_eq!(trie.p2p_member_key(&alice), Err(ResolverError::UnknownMember(alice)));
    assert!(trie.epoch().0 > epoch_before);
}

#[test]
fn org_key_set_then_rotated() {
    use spike_common::identity::OrgKey;
    let initial = OrgKey(make_signing(10).verifying_key());
    let rotated = OrgKey(make_signing(11).verifying_key());

    let trie = StubTrie::new().with_org_key(initial);
    assert_eq!(trie.org_key().unwrap(), initial);

    let trie = trie.stub_rotate_org_key(rotated);
    assert_eq!(trie.org_key().unwrap(), rotated);
}

#[test]
fn isolated_member_returns_empty_device_set() {
    let alice = MemberId([1u8; 32]);
    let alice_p2p = P2pMemberKey(make_signing(2).verifying_key());
    let trie = StubTrie::new().add_member(alice, alice_p2p, alloc::vec![]);

    assert_eq!(trie.current_devices(&alice).unwrap(), alloc::vec::Vec::new());
}

#[test]
fn org_member_ids_enumerates_current_members() {
    let alice = MemberId([1u8; 32]);
    let bob = MemberId([2u8; 32]);
    let trie = StubTrie::new()
        .add_member(alice, P2pMemberKey(make_signing(3).verifying_key()), alloc::vec![])
        .add_member(bob, P2pMemberKey(make_signing(4).verifying_key()), alloc::vec![]);

    let mut ids = trie.org_member_ids();
    ids.sort();
    assert_eq!(ids, alloc::vec![alice, bob]);
}

// The tests use `alloc::vec` even though this is a std integration test,
// to keep the expected idioms aligned with the no_std lib code.
extern crate alloc;
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p spike-common --test stub_trie_integration`
Expected: FAIL with compile errors (StubTrie doesn't exist).

- [ ] **Step 3: Implement `StubTrie`**

Create `spike-common/src/stub_trie.rs`:

```rust
//! In-memory `MemberKeyResolver` implementation used by tests and
//! scenario drivers in both spikes. NOT a real Sparse Merkle Tree —
//! the actual trie lives in `org-members`; this is a fixture-only stub.

use alloc::vec::Vec;
use hashbrown::HashMap;

use crate::identity::{Epoch, MemberId, OrgKey, P2pDeviceKey, P2pMemberKey};
use crate::resolver::{MemberKeyResolver, ResolverError};

#[derive(Clone, Debug, Default)]
pub struct StubTrie {
    members: HashMap<MemberId, MemberEntry>,
    org: Option<OrgKey>,
    epoch: Epoch,
}

#[derive(Clone, Debug)]
struct MemberEntry {
    p2p_key: P2pMemberKey,
    devices: Vec<P2pDeviceKey>,
}

impl StubTrie {
    pub fn new() -> Self {
        Self::default()
    }

    fn bump(mut self) -> Self {
        self.epoch.0 += 1;
        self
    }

    pub fn add_member(
        mut self,
        id: MemberId,
        p2p_key: P2pMemberKey,
        devices: Vec<P2pDeviceKey>,
    ) -> Self {
        self.members.insert(id, MemberEntry { p2p_key, devices });
        self.bump()
    }

    pub fn with_org_key(mut self, key: OrgKey) -> Self {
        self.org = Some(key);
        self.bump()
    }

    // Scenario-driver mutators. These exist solely so test/scenario code
    // can simulate trie changes; production callers would use the real
    // org-members API.

    pub fn stub_revoke(mut self, id: &MemberId) -> Self {
        self.members.remove(id);
        self.bump()
    }

    pub fn stub_rotate_org_key(mut self, key: OrgKey) -> Self {
        self.org = Some(key);
        self.bump()
    }

    pub fn stub_rotate_member_key(mut self, id: &MemberId, key: P2pMemberKey) -> Self {
        if let Some(entry) = self.members.get_mut(id) {
            entry.p2p_key = key;
        }
        self.bump()
    }

    pub fn stub_remove_device(mut self, id: &MemberId, device: &P2pDeviceKey) -> Self {
        if let Some(entry) = self.members.get_mut(id) {
            entry.devices.retain(|d| d != device);
        }
        self.bump()
    }

    pub fn stub_add_device(mut self, id: &MemberId, device: P2pDeviceKey) -> Self {
        if let Some(entry) = self.members.get_mut(id) {
            entry.devices.push(device);
        }
        self.bump()
    }
}

impl MemberKeyResolver for StubTrie {
    fn p2p_member_key(&self, id: &MemberId) -> Result<P2pMemberKey, ResolverError> {
        self.members
            .get(id)
            .map(|e| e.p2p_key)
            .ok_or(ResolverError::UnknownMember(*id))
    }

    fn org_key(&self) -> Result<OrgKey, ResolverError> {
        self.org.ok_or(ResolverError::OrgKeyUnset)
    }

    fn current_devices(&self, id: &MemberId) -> Result<Vec<P2pDeviceKey>, ResolverError> {
        self.members
            .get(id)
            .map(|e| e.devices.clone())
            .ok_or(ResolverError::UnknownMember(*id))
    }

    fn org_member_ids(&self) -> Vec<MemberId> {
        self.members.keys().copied().collect()
    }

    fn is_member(&self, id: &MemberId) -> bool {
        self.members.contains_key(id)
    }

    fn epoch(&self) -> Epoch {
        self.epoch
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p spike-common --test stub_trie_integration`
Expected: PASS — 6 tests.

- [ ] **Step 5: Verify all build configurations**

```bash
cargo clippy -p spike-common -- -D warnings
cargo check -p spike-common --no-default-features --features serde
cargo check -p spike-common --no-default-features --features serde --target wasm32-unknown-unknown
```

Expected: success on each.

- [ ] **Step 6: Commit**

```bash
git add spike-common/src/stub_trie.rs spike-common/src/lib.rs spike-common/tests/stub_trie_integration.rs
git commit -m "feat(spike-common): StubTrie MemberKeyResolver impl

In-memory stub for scenario-driver tests. Mutators: add_member,
with_org_key, stub_revoke, stub_rotate_org_key, stub_rotate_member_key,
stub_remove_device, stub_add_device. Each mutator bumps epoch."
```

---

### Task 6: Scenario types + fixtures

**Files:**
- Create: `spike-common/src/scenarios.rs`
- Create: `spike-common/tests/fixtures_integration.rs`

- [ ] **Step 1: Write the failing fixtures-integration test**

Create `spike-common/tests/fixtures_integration.rs`:

```rust
use spike_common::scenarios::fixtures::{
    GATING_FIXTURE, ORG_PSEUDO_GROUP_FIXTURE, REVOCATION_FIXTURE,
};
use spike_common::scenarios::ScenarioFixture;

fn invariants(f: &ScenarioFixture) {
    assert!(!f.name.is_empty(), "fixture must name itself");
    assert!(!f.initial.members.is_empty(), "fixture starts with at least one member");
    assert!(!f.steps.is_empty(), "fixture has at least one step");
    assert!(
        f.expected_final.observable_assertions.iter().any(|a| !a.is_empty()),
        "fixture has at least one observable assertion",
    );
}

#[test]
fn revocation_fixture_invariants() {
    invariants(&REVOCATION_FIXTURE);
    assert_eq!(REVOCATION_FIXTURE.name, "revocation");
}

#[test]
fn gating_fixture_invariants() {
    invariants(&GATING_FIXTURE);
    assert_eq!(GATING_FIXTURE.name, "gating");
}

#[test]
fn org_pseudo_group_fixture_invariants() {
    invariants(&ORG_PSEUDO_GROUP_FIXTURE);
    assert_eq!(ORG_PSEUDO_GROUP_FIXTURE.name, "org_pseudo_group");
}

#[test]
fn fixture_steps_apply_to_stub_trie() {
    use spike_common::stub_trie::StubTrie;

    // Walks REVOCATION_FIXTURE end-to-end against StubTrie and confirms
    // that observable assertions hold at the end. This is the fixture's
    // sanity-check contract.
    let trie = REVOCATION_FIXTURE.bootstrap_stub_trie();
    let final_trie = REVOCATION_FIXTURE.apply_to_stub_trie(trie);

    // The fixture's expected_final state describes what spikes will assert
    // in their L3 tests. Here we just confirm the trie shape matches.
    assert_eq!(
        final_trie.org_member_ids().len(),
        REVOCATION_FIXTURE.expected_final.member_count,
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p spike-common --test fixtures_integration`
Expected: FAIL with compile errors.

- [ ] **Step 3: Implement the scenarios module**

Create `spike-common/src/scenarios.rs`:

```rust
//! Library-agnostic scenario fixtures and the data types each scenario
//! produces. The fixtures themselves live in the `fixtures` submodule;
//! the *markdown* specs live in `spike-common/scenarios/*.md` and are
//! the human-readable contract.

use alloc::vec::Vec;
use ed25519_dalek::SigningKey;

use crate::identity::{MemberId, OrgKey, P2pDeviceKey, P2pMemberKey};
use crate::stub_trie::StubTrie;

/// A static scenario fixture loaded by both spikes' L3 tests.
#[derive(Clone, Debug)]
pub struct ScenarioFixture {
    pub name: &'static str,
    pub initial: InitialState,
    pub steps: Vec<Step>,
    pub expected_final: ExpectedFinal,
}

#[derive(Clone, Debug)]
pub struct InitialState {
    pub members: Vec<MemberSeed>,
    pub org_key: Option<OrgKey>,
}

#[derive(Clone, Debug)]
pub struct MemberSeed {
    pub label: &'static str,    // alice / bob / jan-jan — for diagnostic logging
    pub id: MemberId,
    pub p2p_key: P2pMemberKey,
    pub devices: Vec<P2pDeviceKey>,
}

#[derive(Clone, Debug)]
pub enum Step {
    RevokeMember { label: &'static str, id: MemberId },
    RemoveDevice { label: &'static str, id: MemberId, device: P2pDeviceKey },
    RotateMemberKey { label: &'static str, id: MemberId, new_key: P2pMemberKey },
    RotateOrgKey { new_key: OrgKey },
    AddMember { seed: MemberSeed },
}

#[derive(Clone, Debug)]
pub struct ExpectedFinal {
    pub member_count: usize,
    /// Free-form observable assertions, one per testable property. Spikes
    /// translate these into library-specific assertions. Documented in the
    /// matching markdown spec.
    pub observable_assertions: Vec<&'static str>,
}

impl ScenarioFixture {
    /// Build a `StubTrie` containing the fixture's initial state.
    pub fn bootstrap_stub_trie(&self) -> StubTrie {
        let mut trie = StubTrie::new();
        for m in &self.initial.members {
            trie = trie.add_member(m.id, m.p2p_key, m.devices.clone());
        }
        if let Some(org) = self.initial.org_key {
            trie = trie.with_org_key(org);
        }
        trie
    }

    /// Apply each step in order to a `StubTrie`.
    pub fn apply_to_stub_trie(&self, mut trie: StubTrie) -> StubTrie {
        for step in &self.steps {
            trie = match step {
                Step::RevokeMember { id, .. } => trie.stub_revoke(id),
                Step::RemoveDevice { id, device, .. } => trie.stub_remove_device(id, device),
                Step::RotateMemberKey { id, new_key, .. } => {
                    trie.stub_rotate_member_key(id, *new_key)
                }
                Step::RotateOrgKey { new_key } => trie.stub_rotate_org_key(*new_key),
                Step::AddMember { seed } => {
                    trie.add_member(seed.id, seed.p2p_key, seed.devices.clone())
                }
            };
        }
        trie
    }
}

pub mod fixtures {
    //! The three static scenario fixtures referenced in §Data flow of the
    //! design doc. Use the canonical org-members handles (alice, bob, jan-jan)
    //! for continuity with org-members' integration tests.

    use alloc::vec;
    use ed25519_dalek::SigningKey;

    use super::*;

    fn sk(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn alice_seed() -> MemberSeed {
        MemberSeed {
            label: "alice",
            id: MemberId([0xa1; 32]),
            p2p_key: P2pMemberKey(sk(0xa2).verifying_key()),
            devices: vec![P2pDeviceKey(sk(0xa3).verifying_key())],
        }
    }

    fn bob_seed() -> MemberSeed {
        MemberSeed {
            label: "bob",
            id: MemberId([0xb1; 32]),
            p2p_key: P2pMemberKey(sk(0xb2).verifying_key()),
            devices: vec![P2pDeviceKey(sk(0xb3).verifying_key())],
        }
    }

    fn org_key_initial() -> OrgKey {
        OrgKey(sk(0x01).verifying_key())
    }

    pub fn revocation_fixture() -> ScenarioFixture {
        let alice = alice_seed();
        let bob = bob_seed();
        let bob_id = bob.id;

        ScenarioFixture {
            name: "revocation",
            initial: InitialState {
                members: vec![alice, bob],
                org_key: Some(org_key_initial()),
            },
            steps: vec![Step::RevokeMember { label: "bob", id: bob_id }],
            expected_final: ExpectedFinal {
                member_count: 1,
                observable_assertions: vec![
                    "bob's device cannot decrypt new doc payloads after revocation",
                    "alice's device can still decrypt the doc",
                    "(D)CGKA has advanced one epoch",
                ],
            },
        }
    }

    pub fn gating_fixture() -> ScenarioFixture {
        let alice = alice_seed();
        let bob = bob_seed();
        let bob_id = bob.id;

        ScenarioFixture {
            name: "gating",
            initial: InitialState {
                members: vec![alice, bob],
                org_key: Some(org_key_initial()),
            },
            steps: vec![Step::RevokeMember { label: "bob", id: bob_id }],
            expected_final: ExpectedFinal {
                member_count: 1,
                observable_assertions: vec![
                    "an open p2p sync session from bob's device is terminated within the test's timeout",
                    "a fresh sync attempt from bob's device is rejected by the conn policy",
                    "alice's session remains open",
                ],
            },
        }
    }

    pub fn org_pseudo_group_fixture() -> ScenarioFixture {
        let alice = alice_seed();
        let bob = bob_seed();
        let alice_id = alice.id;

        ScenarioFixture {
            name: "org_pseudo_group",
            initial: InitialState {
                members: vec![alice, bob],
                org_key: Some(org_key_initial()),
            },
            steps: vec![Step::RotateMemberKey {
                label: "alice",
                id: alice_id,
                new_key: P2pMemberKey(sk(0xaa).verifying_key()),
            }],
            expected_final: ExpectedFinal {
                member_count: 2,
                observable_assertions: vec![
                    "a doc whose ACL grants the org-as-pseudo-group is readable by alice's new key",
                    "the same doc is readable by bob without any explicit ACL change",
                    "(D)CGKA recompute was triggered for org-keyed docs",
                ],
            },
        }
    }

    // Static lazy accessors so tests can do `&REVOCATION_FIXTURE` without
    // re-allocating each access.
    use core::sync::atomic::{AtomicBool, Ordering};

    // Note: we can't use `static REVOCATION_FIXTURE: ScenarioFixture = ...`
    // directly because `Vec`/`SigningKey` aren't const. Function-style
    // accessors are good enough for fixtures; tests call them once.
    pub static REVOCATION_FIXTURE: once_cell::sync::Lazy<ScenarioFixture> =
        once_cell::sync::Lazy::new(revocation_fixture);

    pub static GATING_FIXTURE: once_cell::sync::Lazy<ScenarioFixture> =
        once_cell::sync::Lazy::new(gating_fixture);

    pub static ORG_PSEUDO_GROUP_FIXTURE: once_cell::sync::Lazy<ScenarioFixture> =
        once_cell::sync::Lazy::new(org_pseudo_group_fixture);
}
```

Note on `once_cell`: this requires `std` (or `critical-section`). Add to `spike-common/Cargo.toml`:

```toml
[dependencies]
once_cell = { version = "1", default-features = false, features = ["alloc", "critical-section"] }
critical-section = { version = "1", default-features = false }
```

Actually, simpler: since the fixtures are only used in tests, gate them behind `#[cfg(feature = "std")]` and use plain `once_cell::sync::Lazy`. Add `once_cell = "1"` as a regular dep, and gate the `mod fixtures` behind `#[cfg(feature = "std")]`. This keeps `no_std` builds free of fixtures (which they don't need anyway — fixtures are test-only).

Update `spike-common/src/scenarios.rs` accordingly: wrap the `fixtures` module in `#[cfg(feature = "std")]`. Update `lib.rs` only declares `pub mod scenarios;` — `scenarios` itself conditionally exposes `fixtures`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p spike-common --test fixtures_integration`
Expected: PASS — 4 tests.

- [ ] **Step 5: Verify build matrix**

```bash
cargo clippy -p spike-common -- -D warnings
cargo check -p spike-common --no-default-features --features serde
cargo check -p spike-common --no-default-features --features serde --target wasm32-unknown-unknown
```

Expected: success on each (fixtures are gated behind `std`, so no_std builds don't pull `once_cell`).

- [ ] **Step 6: Commit**

```bash
git add spike-common/src/scenarios.rs spike-common/src/lib.rs spike-common/Cargo.toml spike-common/tests/fixtures_integration.rs
git commit -m "feat(spike-common): scenarios module + three fixtures

ScenarioFixture, Step, ExpectedFinal types. REVOCATION_FIXTURE,
GATING_FIXTURE, ORG_PSEUDO_GROUP_FIXTURE using canonical alice/bob
handles. Fixtures std-gated since they're test-only."
```

---

### Task 7: Scenario markdown specs

**Files:**
- Create: `spike-common/scenarios/revocation.md`
- Create: `spike-common/scenarios/gating.md`
- Create: `spike-common/scenarios/org_pseudo_group.md`

These are documentation, not source. They are the human-readable contract that the `ScenarioFixture` data structs encode in machine-readable form.

- [ ] **Step 1: Write `spike-common/scenarios/revocation.md`**

```markdown
# Revocation scenario

**Purpose:** Exercise gates 1, 3, and a touch of 5 — a member is revoked from
the trie; the (D)CGKA must rotate and the revoked member's devices must
lose access to the doc.

**Initial state:**
- alice (`MemberId([0xa1; 32])`) with one device.
- bob (`MemberId([0xb1; 32])`) with one device.
- Org key set.
- One doc/space `D` whose ACL grants `Principal::Member(alice)` and
  `Principal::Member(bob)`. Both have read+write.

**Steps:**
1. bob is revoked from the trie (`stub_revoke(bob)`).
2. The spike's trie-change observer fires, notifying the library adapter
   that the trie has advanced.

**Observable assertions:**
- bob's device cannot decrypt new doc payloads after revocation.
- alice's device can still decrypt the doc.
- (D)CGKA has advanced one epoch.

**Substitutions exercised:** #1 (stable-ID ACL), #3 (membership-op
interception — bob was removed by the *trie*, not by a library-native
`remove_member` call), #4 (rotation-on-trie-change).
```

- [ ] **Step 2: Write `spike-common/scenarios/gating.md`**

```markdown
# Gating scenario

**Purpose:** Exercise gate 5 (p2p connection policy) for member-as-a-group.

**Initial state:**
- alice and bob (as in revocation).
- Org key set.
- One doc/space `D` whose ACL grants `Principal::Member(alice)` and
  `Principal::Member(bob)`.
- An open p2p sync session for `D` between alice's device and bob's device.

**Steps:**
1. bob is revoked from the trie.
2. Trie-change observer fires.

**Observable assertions:**
- An open p2p sync session from bob's device is terminated within the
  test's timeout (the timeout itself is recorded as a `notes` field in
  the gap matrix; latency to terminate is part of the evidence).
- A fresh sync attempt from bob's device is rejected by the conn policy
  before the handshake completes.
- alice's session remains open.

**Substitutions exercised:** #5 (p2p connection policy), and #4 (the trie
change is what drives termination).
```

- [ ] **Step 3: Write `spike-common/scenarios/org_pseudo_group.md`**

```markdown
# Org-as-pseudo-group scenario

**Purpose:** Exercise gates 1, 3, 4 and the org-keyed paths of 5 — verify
that the organisation-as-pseudo-group principal works as an ACL subject
and that rotating a member's p2p key does not break org-keyed doc access.

**Initial state:**
- alice and bob.
- Org key set.
- One doc/space `D` whose ACL grants the org-as-pseudo-group (single
  `Principal::Org` entry, not per-member entries).
- alice and bob each have read+write via the org membership.

**Steps:**
1. alice's p2p member key is rotated to a new value (`stub_rotate_member_key`).
2. Trie-change observer fires.

**Observable assertions:**
- The doc is readable by alice's new key after rotation.
- The same doc is readable by bob without any explicit ACL change (the
  org-keyed delegation never named alice or bob individually).
- (D)CGKA recompute was triggered for the org-keyed doc.

**Substitutions exercised:** #1 (stable-ID ACL via the `Principal::Org`
subject), #2 (org-as-pseudo-group principal), #4 (rotation-on-trie-change
via the org-keyed path).
```

- [ ] **Step 4: Commit**

```bash
git add spike-common/scenarios/
git commit -m "docs(spike-common): markdown specs for the three scenarios

revocation.md, gating.md, org_pseudo_group.md. These pair with the
ScenarioFixture data structs in src/scenarios.rs and are the
human-readable contract the spikes implement against."
```

---

### Task 8: Gap matrix types

**Files:**
- Create: `spike-common/src/report.rs`

The gap-matrix schema is given verbatim in §Gap matrix and decision rubric / Schema of the design. Implement the types one-to-one with the schema table.

- [ ] **Step 1: Write the failing test inline at the bottom of `report.rs`**

Create `spike-common/src/report.rs` containing only the test module first:

```rust
//! Gap matrix types and renderers. Schema follows the design doc verbatim;
//! see §Gap matrix and decision rubric.

#[cfg(test)]
#[cfg(feature = "serde")]
mod tests {
    use super::*;

    fn sample_entry() -> GapEntry {
        GapEntry {
            library: Library::Keyhive,
            gate: 1,
            sub_flow: SubFlow::A,
            principal: PrincipalKind::Member,
            severity: Severity::Soft,
            failing_subcrate: Some("keyhive_core".into()),
            fix_path: FixPath::TraitImpl,
            fix_effort: Some(Effort::Small),
            phase3_effort: Effort::Medium,
            evidence: alloc::vec!["spike_keyhive::s1_stable_id_acl::test_delegation".into()],
            escape_hatch: None,
            salvage_notes: "keyhive_core::Capability trait is public; impl size ~50 LOC".into(),
            notes: "passed L1, L2 needs a thin adapter".into(),
        }
    }

    #[test]
    fn gap_entry_postcard_roundtrip() {
        let e = sample_entry();
        let bytes = postcard::to_allocvec(&e).unwrap();
        let back: GapEntry = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn gap_matrix_inserts_and_upserts() {
        let mut m = GapMatrix::default();
        m.upsert(sample_entry());
        assert_eq!(m.rows.len(), 1);

        // Same row key (library, gate, sub_flow, principal) -> replace
        let mut e2 = sample_entry();
        e2.severity = Severity::None;
        m.upsert(e2.clone());
        assert_eq!(m.rows.len(), 1);
        assert_eq!(m.rows[0].severity, Severity::None);
    }

    #[test]
    fn library_has_hard_row() {
        let mut m = GapMatrix::default();
        let mut e = sample_entry();
        e.severity = Severity::Hard;
        m.upsert(e);
        assert!(m.has_hard(Library::Keyhive));
        assert!(!m.has_hard(Library::Panda));
    }

    extern crate alloc;
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p spike-common --lib report`
Expected: FAIL with compile errors.

- [ ] **Step 3: Implement the types above the test module**

Prepend to `spike-common/src/report.rs`:

```rust
use alloc::string::String;
use alloc::vec::Vec;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Library {
    Keyhive,
    Panda,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum SubFlow {
    A,
    B,
    C,
    D,
    E1,
    E2,
    F1,
    F2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum PrincipalKind {
    Member,
    Org,
    NA,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Severity {
    Hard,
    Soft,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum FixPath {
    UpstreamPR,
    TraitImpl,
    Fork,
    Replace,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Effort {
    Small,
    Medium,
    Large,
    XL,
}

impl Effort {
    /// Super-linear weighting used in tie-break step 2 and override-on-cost
    /// annotation. `XL` is meant as effective veto, so it gets a very large
    /// number — but it's still finite so totals remain comparable.
    pub fn weight(&self) -> u32 {
        match self {
            Effort::Small => 1,
            Effort::Medium => 3,
            Effort::Large => 9,
            Effort::XL => 81,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct GapEntry {
    pub library: Library,
    pub gate: u8,
    pub sub_flow: SubFlow,
    pub principal: PrincipalKind,
    pub severity: Severity,
    pub failing_subcrate: Option<String>,
    pub fix_path: FixPath,
    pub fix_effort: Option<Effort>,
    pub phase3_effort: Effort,
    pub evidence: Vec<String>,
    pub escape_hatch: Option<String>,
    pub salvage_notes: String,
    pub notes: String,
}

impl GapEntry {
    pub fn row_key(&self) -> RowKey {
        RowKey {
            library: self.library,
            gate: self.gate,
            sub_flow: self.sub_flow,
            principal: self.principal,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RowKey {
    pub library: Library,
    pub gate: u8,
    pub sub_flow: SubFlow,
    pub principal: PrincipalKind,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct GapMatrix {
    pub rows: Vec<GapEntry>,
}

impl GapMatrix {
    pub fn upsert(&mut self, entry: GapEntry) {
        let key = entry.row_key();
        if let Some(existing) = self.rows.iter_mut().find(|r| r.row_key() == key) {
            *existing = entry;
        } else {
            self.rows.push(entry);
        }
    }

    pub fn has_hard(&self, library: Library) -> bool {
        self.rows.iter().any(|r| r.library == library && r.severity == Severity::Hard)
    }

    pub fn soft_count(&self, library: Library) -> usize {
        self.rows.iter().filter(|r| r.library == library && r.severity == Severity::Soft).count()
    }

    /// Total burden = sum of phase3_effort weights over all rows for `library`,
    /// plus sum of fix_effort weights over Hard rows for `library`. Used by
    /// the override-on-cost annotation in the decision doc.
    pub fn total_burden(&self, library: Library) -> u32 {
        let mut total = 0u32;
        for r in self.rows.iter().filter(|r| r.library == library) {
            total += r.phase3_effort.weight();
            if r.severity == Severity::Hard {
                if let Some(fe) = r.fix_effort {
                    total += fe.weight();
                }
            }
        }
        total
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p spike-common --lib report`
Expected: PASS — 3 tests.

- [ ] **Step 5: Verify build matrix**

```bash
cargo clippy -p spike-common -- -D warnings
cargo check -p spike-common --no-default-features --features serde
cargo check -p spike-common --no-default-features --features serde --target wasm32-unknown-unknown
```

Expected: success.

- [ ] **Step 6: Commit**

```bash
git add spike-common/src/report.rs spike-common/src/lib.rs
git commit -m "feat(spike-common): gap matrix types

Library, SubFlow, PrincipalKind, Severity, FixPath, Effort enums.
GapEntry and GapMatrix with upsert / has_hard / soft_count /
total_burden helpers. Schema mirrors the design doc verbatim."
```

---

### Task 9: Markdown + JSON renderers

**Files:**
- Modify: `spike-common/src/report.rs` (add renderer functions)
- Create: `spike-common/tests/report_integration.rs`

- [ ] **Step 1: Write the failing renderer test**

Create `spike-common/tests/report_integration.rs`:

```rust
use spike_common::report::{
    Effort, FixPath, GapEntry, GapMatrix, Library, PrincipalKind, Severity, SubFlow,
};

fn sample_matrix() -> GapMatrix {
    let mut m = GapMatrix::default();
    m.upsert(GapEntry {
        library: Library::Keyhive,
        gate: 0,
        sub_flow: SubFlow::A,
        principal: PrincipalKind::NA,
        severity: Severity::None,
        failing_subcrate: None,
        fix_path: FixPath::None,
        fix_effort: None,
        phase3_effort: Effort::Small,
        evidence: vec!["WASM build matrix in CI".to_string()],
        escape_hatch: None,
        salvage_notes: String::new(),
        notes: "compiles cleanly".to_string(),
    });
    m.upsert(GapEntry {
        library: Library::Panda,
        gate: 1,
        sub_flow: SubFlow::A,
        principal: PrincipalKind::Member,
        severity: Severity::Soft,
        failing_subcrate: Some("p2panda-auth".to_string()),
        fix_path: FixPath::TraitImpl,
        fix_effort: Some(Effort::Small),
        phase3_effort: Effort::Medium,
        evidence: vec!["spike_p2panda::s1::test_member_delegation".to_string()],
        escape_hatch: Some("wrap raw VerifyingKey in our Principal type".to_string()),
        salvage_notes: "p2panda-auth's Subject trait is public".to_string(),
        notes: "passes after thin shim".to_string(),
    });
    m
}

#[test]
fn markdown_render_contains_each_row() {
    let m = sample_matrix();
    let md = spike_common::report::render_markdown(&m);
    assert!(md.contains("Keyhive"), "markdown should mention Keyhive");
    assert!(md.contains("Panda"), "markdown should mention p2panda");
    assert!(md.contains("p2panda-auth"), "failing subcrate should appear");
    assert!(md.contains("TraitImpl"), "fix path should appear");
}

#[test]
fn json_render_roundtrips() {
    let m = sample_matrix();
    let json = spike_common::report::render_json(&m).expect("serialize ok");
    let back: GapMatrix = serde_json::from_str(&json).expect("deserialize ok");
    assert_eq!(m, back);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p spike-common --test report_integration`
Expected: FAIL with `render_markdown`/`render_json` not found.

- [ ] **Step 3: Add the renderer functions to `report.rs`**

Append to `spike-common/src/report.rs`:

```rust
#[cfg(feature = "std")]
pub fn render_markdown(matrix: &GapMatrix) -> String {
    use core::fmt::Write;

    let mut out = String::new();
    let _ = writeln!(out, "# Phase 1.d gap matrix");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| Library | Gate | Flow | Principal | Severity | Subcrate | Fix path | Fix effort | Phase 3 effort | Notes |"
    );
    let _ = writeln!(out, "|---|---|---|---|---|---|---|---|---|---|");
    for r in &matrix.rows {
        let _ = writeln!(
            out,
            "| {:?} | {} | {:?} | {:?} | {:?} | {} | {:?} | {} | {:?} | {} |",
            r.library,
            r.gate,
            r.sub_flow,
            r.principal,
            r.severity,
            r.failing_subcrate.as_deref().unwrap_or(""),
            r.fix_path,
            r.fix_effort.map(|e| format!("{e:?}")).unwrap_or_default(),
            r.phase3_effort,
            r.notes,
        );
    }

    let _ = writeln!(out);
    let _ = writeln!(out, "## Per-library summary");
    let _ = writeln!(out);
    for lib in [Library::Keyhive, Library::Panda] {
        let _ = writeln!(
            out,
            "- **{:?}** — hard: {}, soft: {}, total burden: {}",
            lib,
            matrix.rows.iter().filter(|r| r.library == lib && r.severity == Severity::Hard).count(),
            matrix.soft_count(lib),
            matrix.total_burden(lib),
        );
    }
    out
}

#[cfg(feature = "std")]
pub fn render_json(matrix: &GapMatrix) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(matrix)
}
```

Note `render_json` requires `serde_json` — that's a test/dev-dep already; for the library build we make it optional. Add `serde_json = { version = "1", optional = true }` to the main `[dependencies]` section and gate `render_json` behind `#[cfg(feature = "json")]`. Add a `json = ["dep:serde_json"]` feature to `[features]`. The binary requires this `json` feature already (Task 2 mentioned the `required-features` adjustment).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p spike-common --test report_integration --features json`
Expected: PASS — 2 tests.

- [ ] **Step 5: Verify build matrix**

```bash
cargo clippy -p spike-common -- -D warnings
cargo check -p spike-common --no-default-features --features serde
cargo check -p spike-common --no-default-features --features serde --target wasm32-unknown-unknown
```

Expected: success. The renderer is `std`-gated so `no_std` builds don't fail.

- [ ] **Step 6: Commit**

```bash
git add spike-common/src/report.rs spike-common/tests/report_integration.rs spike-common/Cargo.toml
git commit -m "feat(spike-common): markdown + JSON gap-matrix renderers

render_markdown emits the table seen in the spec. render_json is the
machine-readable counterpart. Both std-gated."
```

---

### Task 10: `gap-update` binary

**Files:**
- Create: `spike-common/src/bin/gap-update.rs`

The binary reads the matrix from `docs/phase-1d/gap-matrix.json` (or starts fresh if absent), accepts a single new `GapEntry` from stdin as JSON, upserts it, and writes both `.json` and `.md` back out.

- [ ] **Step 1: Implement the binary**

Create `spike-common/src/bin/gap-update.rs`:

```rust
//! gap-update — updates docs/phase-1d/gap-matrix.{md,json} from stdin.
//!
//! Usage:
//!   echo '<single GapEntry as JSON>' | cargo run --bin gap-update
//!
//! The entry is upserted into the matrix at docs/phase-1d/gap-matrix.json
//! (loaded fresh if the file doesn't exist). Both .json and .md are rewritten.

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use spike_common::report::{render_json, render_markdown, GapEntry, GapMatrix};

fn main() -> ExitCode {
    let docs_dir: PathBuf = std::env::var("PHASE_1D_DOCS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("docs/phase-1d"));

    if let Err(e) = run(&docs_dir) {
        eprintln!("gap-update failed: {e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn run(docs_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(docs_dir)?;

    let json_path = docs_dir.join("gap-matrix.json");
    let md_path = docs_dir.join("gap-matrix.md");

    let mut matrix: GapMatrix = if json_path.exists() {
        let raw = fs::read_to_string(&json_path)?;
        serde_json::from_str(&raw)?
    } else {
        GapMatrix::default()
    };

    let mut stdin_buf = String::new();
    io::stdin().read_to_string(&mut stdin_buf)?;
    let stdin_trimmed = stdin_buf.trim();

    if stdin_trimmed.is_empty() {
        // No new entry — just re-render the matrix from the existing JSON.
        // Useful for refreshing the markdown after a manual JSON edit.
    } else {
        let entry: GapEntry = serde_json::from_str(stdin_trimmed)?;
        matrix.upsert(entry);
    }

    fs::write(&json_path, render_json(&matrix)?)?;
    fs::write(&md_path, render_markdown(&matrix))?;

    println!(
        "gap-update: wrote {} rows to {} and {}",
        matrix.rows.len(),
        json_path.display(),
        md_path.display(),
    );
    Ok(())
}
```

- [ ] **Step 2: Smoke-test the binary**

Run:
```bash
mkdir -p /tmp/gap-update-test
PHASE_1D_DOCS_DIR=/tmp/gap-update-test cargo run -p spike-common --bin gap-update --features json -- <<'EOF'
{
  "library": "Keyhive",
  "gate": 0,
  "sub_flow": "A",
  "principal": "NA",
  "severity": "None",
  "failing_subcrate": null,
  "fix_path": "None",
  "fix_effort": null,
  "phase3_effort": "Small",
  "evidence": ["smoke test"],
  "escape_hatch": null,
  "salvage_notes": "",
  "notes": "smoke"
}
EOF

ls -la /tmp/gap-update-test
cat /tmp/gap-update-test/gap-matrix.md
```

Expected: both files created, markdown contains the one row.

- [ ] **Step 3: Idempotency check**

Re-run the same command. Expected: still one row in the matrix (upsert, not insert).

- [ ] **Step 4: Commit**

```bash
git add spike-common/src/bin/gap-update.rs spike-common/Cargo.toml
git commit -m "feat(spike-common): gap-update binary

Reads a single GapEntry as JSON from stdin, upserts it into
docs/phase-1d/gap-matrix.json, re-renders both .json and .md.
Idempotent on duplicate row keys."
```

---

### Task 11: Set up `docs/phase-1d/` and seed the gap matrix

**Files:**
- Create: `docs/phase-1d/gap-matrix.md` (initial empty render)
- Create: `docs/phase-1d/gap-matrix.json`
- Create: `docs/phase-1d/subcrate-inventory.md` (template placeholder)

- [ ] **Step 1: Run gap-update with no input to materialise empty matrix files**

```bash
echo "" | cargo run -p spike-common --bin gap-update --features json
ls -la docs/phase-1d/
```

Expected: `docs/phase-1d/gap-matrix.json` (`{"rows":[]}`) and `docs/phase-1d/gap-matrix.md` (table header + per-library summary with all zeros) both present.

- [ ] **Step 2: Create the sub-crate inventory template**

Create `docs/phase-1d/subcrate-inventory.md`:

```markdown
# Phase 1.d sub-crate inventory

Populated by the per-library spike crates during their Task 1
(inventory step) before any gate work begins. Each entry:
`crate name @ pinned rev` — role — relevant API surface — re-exporter.

## Keyhive

_To be filled in by `spike-keyhive`._

## p2panda

_To be filled in by `spike-p2panda`._
```

- [ ] **Step 3: Commit**

```bash
git add docs/phase-1d/
git commit -m "chore(phase-1d): seed gap-matrix and subcrate-inventory docs

Empty initial matrix produced by gap-update. Inventory template
will be filled in by per-library spike plans."
```

---

### Task 12: Workspace-level verification + README

**Files:**
- Modify: `spike-common/README.md` (already exists; add usage example)

- [ ] **Step 1: Run the full build matrix one more time, workspace-wide**

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo check -p spike-common --no-default-features
cargo check -p spike-common --no-default-features --features serde
cargo check -p spike-common --no-default-features --features serde --target wasm32-unknown-unknown
```

Expected: all green. No warnings.

- [ ] **Step 2: Expand `spike-common/README.md` with a usage example**

Append to `spike-common/README.md`:

```markdown
## Example: adding a gap-matrix row from a test

```rust,no_run
use spike_common::report::{
    Effort, FixPath, GapEntry, Library, PrincipalKind, Severity, SubFlow,
};

let entry = GapEntry {
    library: Library::Keyhive,
    gate: 1,
    sub_flow: SubFlow::A,
    principal: PrincipalKind::Member,
    severity: Severity::Soft,
    failing_subcrate: Some("keyhive_core".into()),
    fix_path: FixPath::TraitImpl,
    fix_effort: Some(Effort::Small),
    phase3_effort: Effort::Medium,
    evidence: vec!["my_test_name".into()],
    escape_hatch: None,
    salvage_notes: "Capability trait is public".into(),
    notes: "passes after thin shim".into(),
};

// Then pipe `serde_json::to_string(&entry)?` to `gap-update`'s stdin.
```
```

- [ ] **Step 3: Final commit**

```bash
git add spike-common/README.md
git commit -m "docs(spike-common): usage example in README"
```

---

## Self-review

### Spec coverage

Walking the design doc section-by-section:

- **§Architecture** — workspace + three crates created in Task 2.
- **§Build configurations** — verified in Tasks 3, 5, 6, 8, 9, 12.
- **§Six gates** — table reproduced in design doc; nothing to implement at the foundation level (gates run inside the per-library spikes).
- **§Components — `spike-common`** — `identity` (Task 3), `resolver` (Task 4), `stub_trie` (Task 5), `scenarios` (Task 6), `report` (Tasks 8 + 9). ✓
- **§Components — `spike-keyhive`/`spike-p2panda`** — placeholder crates in Task 2; full implementations deferred to follow-up plans. ✓
- **§Escape-hatch convention** — referenced in `spike-common::report::GapEntry::escape_hatch` field; enforcement (no silent deviations) is a runtime check in the spike code, deferred to follow-up plans.
- **§Data flow A–F2** — markdown specs in Task 7. Code paths live in the per-library spike crates (deferred). ✓
- **§Gap matrix schema** — implemented in Task 8. All fields present.
- **§Sub-crate inventory step** — template in Task 11; populated by follow-up plans.
- **§Layered test pyramid** — L1/L2/L3 test files are inside the per-library spike crates (deferred).
- **§Capability matrix** — encoded in scenario fixtures (Task 6) and markdown specs (Task 7).
- **§Hard-blocker rule / Salvage paths** — rubric encoded in `Severity` + `FixPath` + `Effort` types (Task 8). Application of the rubric is hand-done in the decision doc (Task 11 placeholder).
- **§Tie-break ladder** — `total_burden`, `soft_count`, `has_hard` helpers in `GapMatrix` (Task 8) provide the inputs.
- **§Decision document structure** — written by hand after the spike runs; not part of this foundation plan.
- **§Execution order** — driven by the follow-up plans plus user review checkpoints; not a foundation deliverable.

### Placeholder scan

- No `TBD`/`TODO` left in code.
- No "add appropriate error handling" — concrete `ResolverError` variants are listed in Task 4.
- No "similar to Task N" — each task contains the actual code or text.
- The `Cargo.toml` note in Task 2 about `required-features = [..., "dep:serde_json"]` vs `["..., "json"]` is a real implementation choice the engineer needs to make based on Cargo's behaviour. I made the conservative recommendation: add the `json = ["dep:serde_json"]` feature and reference it. Step 3 of Task 2 includes the `[[bin]] required-features` entry; Step 3 of Task 9 also documents this addition.

### Type consistency

- `MemberId([u8; 32])`, `P2pMemberKey(VerifyingKey)`, `P2pDeviceKey(VerifyingKey)`, `OrgKey(VerifyingKey)`, `Epoch(u64)`, `Principal::{Member, Org}` — used identically in Tasks 3, 4, 5, 6, 7, 8.
- `Severity::{Hard, Soft, None}` (note: `None` shadows `Option::None` syntactically but with `::Severity::None` resolution); used in Task 8 + 9.
- `FixPath::{UpstreamPR, TraitImpl, Fork, Replace, None}` consistent with the spec.
- `MemberKeyResolver` trait methods: `p2p_member_key`, `org_key`, `current_devices`, `org_member_ids`, `is_member`, `epoch`. Consistent between Task 4 (trait) and Task 5 (impl).
- `GapMatrix::{upsert, has_hard, soft_count, total_burden}` — used in Tasks 8 + 9.

No drift identified.

### Scope

This plan produces a working, testable Rust crate (`spike-common`) that the follow-up plans depend on. It is a single coherent deliverable. The workspace also has empty placeholder crates so the workspace cargo manifest is well-formed.

---

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-05-13-phase-1d-spike-common-foundation.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using `executing-plans`, batch execution with checkpoints.

Which approach?
