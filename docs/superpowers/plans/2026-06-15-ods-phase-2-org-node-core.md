# ODS Phase 2.1 — `org-node` core (trust brain) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the pure, network-free trust core of `org-node`: keys, the signed-delta envelope, replay protection, and the verify-against-chain orchestration — everything that decides whether a received membership change may be committed, testable against a mock chain.

**Architecture:** A new workspace library crate `org-node`. It consumes `org-members` for the trie and owns what that crate leaves to the caller: ed25519 signing, the `SignedDeltaEnvelope`, monotonic sequencing, and the verify-against-chain flow (apply delta → recompute root → match against an *independently* read on-chain root). The chain is abstracted behind a `ChainReader` trait so this phase needs no real chain — a `MockChain` drives all tests. Real `on-chain-client`/subxt wiring, iroh transport, and the Tauri/Svelte shell are later phases.

**Tech Stack:** Rust (edition 2021), `org-members` (path dep), `ed25519-dalek` v2, `postcard` (canonical wire), `blake3`, `thiserror` v2, `rand` v0.8 (keygen in tests), `bolero` (fuzz, per repo convention).

**Spec:** [`docs/superpowers/specs/2026-06-15-ods-phase-2-poc-design.md`](../specs/2026-06-15-ods-phase-2-poc-design.md) — §5 (trust spine), §4 (data model), §9 (testing).

---

## File structure

```
org-node/
  Cargo.toml                  # new workspace member
  src/
    lib.rs                    # crate root, re-exports
    error.rs                  # OrgNodeError
    keys.rs                   # SigningKeypair + sign/verify helpers
    ids.rs                    # OrgId (H160 newtype)
    chain.rs                  # ChainReader trait, OrgState, MockChain (test impl)
    envelope.rs               # SignedDeltaEnvelope: transcript, sign, decode, verify-sig
    sequence.rs               # SeqGuard (monotonic parent_seq replay guard)
    verify.rs                 # verify_envelope_against_chain (the crux) + VerifiedUpdate
  tests/
    fuzz_envelope_decode/     # bolero target: postcard decode of envelope
      fuzz_target.rs
      corpus/.gitkeep
      crashes/.gitkeep
    fuzz_verify_against_chain/ # bolero target: verify entry point
      fuzz_target.rs
      corpus/.gitkeep
      crashes/.gitkeep
```

Each `src` file has one responsibility. `verify.rs` is the only place that ties the trie, the chain, the envelope, and the sequence guard together; everything else is a leaf module it composes. Persona/org-record storage and the high-level state machine are intentionally **not** in this phase — they depend on transport/chain decisions and get their own plan.

Workspace `Cargo.toml` already lists members (e.g. `org-members`, `on-chain-client`). Add `org-node` alongside them.

---

## Task 0: Scaffold the `org-node` crate

**Files:**
- Modify: `Cargo.toml` (workspace root — add member)
- Create: `org-node/Cargo.toml`
- Create: `org-node/src/lib.rs`

- [ ] **Step 1: Add the crate to the workspace members list**

Open the root `Cargo.toml` and add `"org-node"` to the `members` array (keep the existing entries; alphabetical-ish placement next to `org-members`).

```toml
members = [
    "org-members",
    "org-node",
    "spike-common",
    "spike-keyhive",
    "spike-p2panda",
]
```

(Match the exact existing list; only add the `"org-node"` line. NOTE: `on-chain`
is a Foundry/Solidity project with no `Cargo.toml`, and `on-chain-client` is a
*self-contained* standalone workspace — neither is a member of the root
workspace, so do not add them here.)

- [ ] **Step 2: Create `org-node/Cargo.toml`**

```toml
[package]
name = "org-node"
version = "0.1.0"
edition = "2021"
rust-version = "1.81"
license = "GPL-3.0-only"
description = "ODS Phase 2 node logic: signing, envelopes, and verify-against-chain over the org-members trie"
publish = false

[dependencies]
org-members = { path = "../org-members", default-features = false, features = ["std", "serde"] }
ed25519-dalek = { version = "2", default-features = false, features = ["alloc"] }
postcard = { version = "1", features = ["alloc", "use-std"] }
serde = { version = "1", features = ["derive"] }
thiserror = { version = "2", default-features = false }
blake3 = "1"

[dev-dependencies]
rand = "0.8"
rand_core = "0.6"
bolero = "0.11"

[lints]
workspace = true
```

> If `cargo build` reports that `[lints] workspace = true` is unknown (no `[workspace.lints]` defined at the root), delete the `[lints]` table from this file and proceed — it is a convenience, not a requirement.

- [ ] **Step 3: Create a minimal `org-node/src/lib.rs`**

```rust
//! ODS Phase 2 node logic. See docs/superpowers/specs/2026-06-15-ods-phase-2-poc-design.md.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod chain;
pub mod envelope;
pub mod error;
pub mod ids;
pub mod keys;
pub mod sequence;
pub mod verify;

pub use error::OrgNodeError;
pub use ids::OrgId;
```

> The `mod` lines reference files not yet created — this will not compile until later tasks add them. That is expected; do not create stub files. Comment out `mod` lines you have not yet implemented if you want green builds between tasks, re-enabling each as its task lands.

- [ ] **Step 4: Verify the workspace recognises the crate**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo metadata --format-version 1 --no-deps | grep -o '"name":"org-node"'`
Expected: prints `"name":"org-node"`

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml org-node/Cargo.toml org-node/src/lib.rs
git commit -m "feat(org-node): scaffold crate as workspace member"
```

---

## Task 1: `OrgNodeError`

**Files:**
- Create: `org-node/src/error.rs`

- [ ] **Step 1: Write `error.rs` with the full error enum**

```rust
//! Typed errors for org-node. Every rejection path in verify-against-chain
//! maps to a distinct variant so the UI can surface *why* a change was rejected.
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OrgNodeError {
    #[error("envelope org_id does not match the expected org")]
    OrgIdMismatch,

    #[error("envelope signature verification failed")]
    BadSignature,

    #[error("stale or replayed parent_seq: got {got}, last seen {last_seen}")]
    StaleSeq { got: u64, last_seen: u64 },

    #[error("envelope delta failed to decode")]
    MalformedDelta,

    #[error("delta base_root does not match the local trie root")]
    DeltaBaseMismatch,

    #[error("no on-chain state found for org")]
    OrgNotOnChain,

    #[error("recomputed root does not match the on-chain root")]
    RootMismatch,

    #[error("on-chain epoch {got} is not newer than the last committed epoch {last}")]
    StaleEpoch { got: u64, last: u64 },

    #[error("chain read failed: {0}")]
    Chain(String),

    #[error("org-members error: {0:?}")]
    Trie(org_members::OrgMembersError),
}

impl From<org_members::OrgMembersError> for OrgNodeError {
    fn from(e: org_members::OrgMembersError) -> Self {
        OrgNodeError::Trie(e)
    }
}
```

- [ ] **Step 2: Build to verify it compiles**

Ensure `mod error;` and `pub use error::OrgNodeError;` are active in `lib.rs` (comment out the not-yet-written modules).
Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo build -p org-node`
Expected: compiles (warnings about unused are fine).

- [ ] **Step 3: Commit**

```bash
git add org-node/src/error.rs org-node/src/lib.rs
git commit -m "feat(org-node): typed OrgNodeError covering every rejection path"
```

---

## Task 2: `OrgId` (H160 newtype)

**Files:**
- Create: `org-node/src/ids.rs`

- [ ] **Step 1: Write the failing test**

Append to `org-node/src/ids.rs`:

```rust
//! OrgId = h160_of(P): the 20-byte contract storage key where an org's
//! OrgState lives. See spec §4.1.
use serde::{Deserialize, Serialize};

/// The 20-byte H160 that keys an org's slot in the OrgRegistry contract.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OrgId(pub [u8; 20]);

impl OrgId {
    pub fn new(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

impl core::fmt::Debug for OrgId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "OrgId(0x")?;
        for b in self.0 {
            write!(f, "{:02x}", b)?;
        }
        write!(f, ")")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_postcard() {
        let id = OrgId::new([7u8; 20]);
        let bytes = postcard::to_allocvec(&id).unwrap();
        let back: OrgId = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn debug_is_hex() {
        let id = OrgId::new([0xab; 20]);
        assert!(format!("{id:?}").starts_with("OrgId(0xabab"));
    }
}
```

- [ ] **Step 2: Run the test to verify it fails (module not wired)**

Enable `mod ids;` and `pub use ids::OrgId;` in `lib.rs`.
Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-node --lib ids::`
Expected: PASS (this task's "test" is self-contained; if `postcard` dev usage errors, confirm `postcard` is a normal dep — it is, per Task 0).

- [ ] **Step 3: Commit**

```bash
git add org-node/src/ids.rs org-node/src/lib.rs
git commit -m "feat(org-node): OrgId H160 newtype with postcard round-trip"
```

---

## Task 3: `SigningKeypair` and sign/verify helpers

**Files:**
- Create: `org-node/src/keys.rs`

- [ ] **Step 1: Write the failing test + implementation**

```rust
//! ed25519 keypairs for members and devices. A device's verifying key is
//! both its P2pDeviceKey (in the trie) and — in a later phase — its iroh
//! NodeId. The member's verifying key is the P2pMemberKey used to sign deltas.
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use org_members::{P2pDeviceKey, P2pMemberKey};

/// An ed25519 keypair held locally. Wraps a dalek SigningKey.
#[derive(Clone)]
pub struct SigningKeypair(SigningKey);

impl SigningKeypair {
    /// Generate from a CSPRNG. (Tests use rand; production wires this to the OS RNG.)
    pub fn generate<R: rand_core::CryptoRng + rand_core::RngCore>(rng: &mut R) -> Self {
        Self(SigningKey::generate(rng))
    }

    /// Reconstruct from the 32-byte secret seed (for persisted keys).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(SigningKey::from_bytes(&seed))
    }

    /// The 32-byte secret seed, for at-rest persistence. Handle as a secret.
    pub fn to_seed(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.0.verifying_key()
    }

    /// As a member-as-a-group key for the trie.
    pub fn member_key(&self) -> P2pMemberKey {
        P2pMemberKey::new(self.verifying_key())
    }

    /// As a device key for the trie / iroh identity.
    pub fn device_key(&self) -> P2pDeviceKey {
        P2pDeviceKey::new(self.verifying_key())
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.0.sign(msg)
    }
}

/// Verify a signature against an already-known verifying key.
pub fn verify(vk: &VerifyingKey, msg: &[u8], sig: &Signature) -> bool {
    vk.verify(msg, sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn sign_verify_round_trip() {
        let kp = SigningKeypair::generate(&mut OsRng);
        let msg = b"hello org";
        let sig = kp.sign(msg);
        assert!(verify(&kp.verifying_key(), msg, &sig));
        assert!(!verify(&kp.verifying_key(), b"tampered", &sig));
    }

    #[test]
    fn seed_round_trip_preserves_key() {
        let kp = SigningKeypair::generate(&mut OsRng);
        let seed = kp.to_seed();
        let kp2 = SigningKeypair::from_seed(seed);
        assert_eq!(kp.verifying_key(), kp2.verifying_key());
    }

    #[test]
    fn member_and_device_keys_wrap_the_verifying_key() {
        let kp = SigningKeypair::generate(&mut OsRng);
        assert_eq!(kp.member_key().as_bytes(), kp.verifying_key().as_bytes());
        assert_eq!(kp.device_key().as_bytes(), kp.verifying_key().as_bytes());
    }
}
```

- [ ] **Step 2: Run the tests**

Enable `mod keys;` in `lib.rs`.
Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-node --lib keys::`
Expected: 3 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add org-node/src/keys.rs org-node/src/lib.rs
git commit -m "feat(org-node): SigningKeypair + sign/verify, mapping to trie key types"
```

---

## Task 4: Chain abstraction — `OrgState`, `ChainReader`, `MockChain`

**Files:**
- Create: `org-node/src/chain.rs`

- [ ] **Step 1: Write the implementation + test**

```rust
//! The chain seen as a read-only oracle. Phase 2.1 uses MockChain; a later
//! phase implements ChainReader over on-chain-client. OrgState mirrors the
//! OrgRegistry slot: (rootHash, orgPubKey, epoch). See spec §4.4.
use std::collections::HashMap;

use org_members::RootHash;

use crate::ids::OrgId;

/// The on-chain state of one org, as stored in the OrgRegistry slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrgState {
    pub root_hash: RootHash,
    pub org_pub_key: [u8; 32],
    pub epoch: u64,
}

/// Read-only access to on-chain org state. The trusted-root oracle: the root
/// returned here MUST come from a path the delta sender does not control.
pub trait ChainReader {
    /// Returns the current OrgState for `org_id`, or None if the slot is empty.
    fn get_org_state(&self, org_id: &OrgId) -> Result<Option<OrgState>, String>;
}

/// In-memory ChainReader for tests. `set` simulates an admin's update().
#[derive(Default, Clone)]
pub struct MockChain {
    slots: HashMap<OrgId, OrgState>,
}

impl MockChain {
    pub fn new() -> Self {
        Self::default()
    }

    /// Simulate an on-chain update() landing for `org_id`.
    pub fn set(&mut self, org_id: OrgId, state: OrgState) {
        self.slots.insert(org_id, state);
    }
}

impl ChainReader for MockChain {
    fn get_org_state(&self, org_id: &OrgId) -> Result<Option<OrgState>, String> {
        Ok(self.slots.get(org_id).copied())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_chain_returns_set_state() {
        let mut chain = MockChain::new();
        let org = OrgId::new([1u8; 20]);
        assert_eq!(chain.get_org_state(&org).unwrap(), None);

        let state = OrgState { root_hash: RootHash::from_bytes([9u8; 32]), org_pub_key: [3u8; 32], epoch: 1 };
        chain.set(org, state);
        assert_eq!(chain.get_org_state(&org).unwrap(), Some(state));
    }
}
```

- [ ] **Step 2: Run the test**

Enable `mod chain;` in `lib.rs`.
Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-node --lib chain::`
Expected: 1 test PASS.

- [ ] **Step 3: Commit**

```bash
git add org-node/src/chain.rs org-node/src/lib.rs
git commit -m "feat(org-node): ChainReader trait, OrgState, and MockChain test oracle"
```

---

## Task 5: `SignedDeltaEnvelope` — transcript, build/sign, decode, verify-sig

**Files:**
- Create: `org-node/src/envelope.rs`

The envelope is the wire form prescribed by the `org-members` README: it binds a postcard-encoded `Delta` to `(org_id, parent_seq)` and signs the three together with the author's member key.

- [ ] **Step 1: Write the implementation + tests**

```rust
//! SignedDeltaEnvelope: the authenticated wire form for a trie change.
//! Transcript signed = org_id (20) ‖ parent_seq LE (8) ‖ delta_bytes.
use ed25519_dalek::{Signature, VerifyingKey};
use org_members::{trie::OrgTrie, hasher::Blake3Hasher, delta::Delta};
use serde::{Deserialize, Serialize};

use crate::error::OrgNodeError;
use crate::ids::OrgId;
use crate::keys::{verify, SigningKeypair};

/// A signed, org-bound, sequence-bound trie delta.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedDeltaEnvelope {
    pub org_id: OrgId,
    pub parent_seq: u64,
    pub delta_bytes: Vec<u8>, // postcard(Delta)
    pub signature: [u8; 64],
}

/// Build the exact byte transcript that gets signed/verified.
fn transcript(org_id: &OrgId, parent_seq: u64, delta_bytes: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(20 + 8 + delta_bytes.len());
    buf.extend_from_slice(org_id.as_bytes());
    buf.extend_from_slice(&parent_seq.to_le_bytes());
    buf.extend_from_slice(delta_bytes);
    buf
}

impl SignedDeltaEnvelope {
    /// Author side: encode `delta`, bind it to (org, seq), and sign with `author`.
    pub fn build(
        org_id: OrgId,
        parent_seq: u64,
        delta: &Delta,
        author: &SigningKeypair,
    ) -> Result<Self, OrgNodeError> {
        let delta_bytes = postcard::to_allocvec(delta).map_err(|_| OrgNodeError::MalformedDelta)?;
        let sig = author.sign(&transcript(&org_id, parent_seq, &delta_bytes));
        Ok(Self { org_id, parent_seq, delta_bytes, signature: sig.to_bytes() })
    }

    /// Decode the inner Delta from postcard bytes (no signature check).
    pub fn decode_delta(&self) -> Result<Delta, OrgNodeError> {
        postcard::from_bytes(&self.delta_bytes).map_err(|_| OrgNodeError::MalformedDelta)
    }

    /// Verify the signature against a *known* member verifying key.
    /// Does NOT check org_id/seq/root — that is verify.rs's job.
    pub fn verify_signature(&self, author_member_key: &VerifyingKey) -> bool {
        let sig = Signature::from_bytes(&self.signature);
        verify(author_member_key, &transcript(&self.org_id, self.parent_seq, &self.delta_bytes), &sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::{admit_member_delta, genesis_trie, member, NodeFixture};
    use rand::rngs::OsRng;

    #[test]
    fn build_then_verify_signature_succeeds() {
        let admin = SigningKeypair::generate(&mut OsRng);
        let (delta, _new_trie) = admit_member_delta(&admin);
        let org = OrgId::new([5u8; 20]);
        let env = SignedDeltaEnvelope::build(org, 1, &delta, &admin).unwrap();
        assert!(env.verify_signature(&admin.verifying_key()));
    }

    #[test]
    fn wrong_key_fails_signature() {
        let admin = SigningKeypair::generate(&mut OsRng);
        let other = SigningKeypair::generate(&mut OsRng);
        let (delta, _) = admit_member_delta(&admin);
        let env = SignedDeltaEnvelope::build(OrgId::new([5u8; 20]), 1, &delta, &admin).unwrap();
        assert!(!env.verify_signature(&other.verifying_key()));
    }

    #[test]
    fn tampering_with_org_id_breaks_signature() {
        let admin = SigningKeypair::generate(&mut OsRng);
        let (delta, _) = admit_member_delta(&admin);
        let mut env = SignedDeltaEnvelope::build(OrgId::new([5u8; 20]), 1, &delta, &admin).unwrap();
        env.org_id = OrgId::new([6u8; 20]);
        assert!(!env.verify_signature(&admin.verifying_key()));
    }

    #[test]
    fn decode_delta_round_trips() {
        let admin = SigningKeypair::generate(&mut OsRng);
        let (delta, _) = admit_member_delta(&admin);
        let env = SignedDeltaEnvelope::build(OrgId::new([5u8; 20]), 1, &delta, &admin).unwrap();
        assert_eq!(env.decode_delta().unwrap(), delta);
    }

    // Silence unused-import warnings for fixtures used by later tasks.
    #[allow(unused_imports)]
    use {genesis_trie as _g, member as _m, NodeFixture as _F};
    type _T = OrgTrie<Blake3Hasher>;
}
```

> This test references `crate::test_fixtures` — a shared test helper created in Task 6, Step 1. Implement Task 6 Step 1 *before* running this task's tests, or temporarily stub the fixtures. The two tasks are paired; the fixtures live in one place to stay DRY.

- [ ] **Step 2: Run the tests (after Task 6 Step 1 fixtures exist)**

Enable `mod envelope;` in `lib.rs`.
Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-node --lib envelope::`
Expected: 4 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add org-node/src/envelope.rs org-node/src/lib.rs
git commit -m "feat(org-node): SignedDeltaEnvelope — transcript, build/sign, decode, verify-sig"
```

---

## Task 6: Shared test fixtures + `SeqGuard`

**Files:**
- Create: `org-node/src/test_fixtures.rs`
- Create: `org-node/src/sequence.rs`

- [ ] **Step 1: Create shared test fixtures**

These give every test crate a deterministic genesis trie and an "admit a member" delta built from the real `org-members` API (`genesis` → `add_member` → `recalculate()`).

`org-node/src/test_fixtures.rs`:

```rust
//! Shared deterministic fixtures for org-node tests. Only compiled under test.
#![cfg(test)]
use org_members::delta::Delta;
use org_members::hasher::Blake3Hasher;
use org_members::trie::OrgTrie;
use org_members::{MemberId, MemberLeaf, P2pDeviceKey, P2pMemberKey};

use crate::keys::SigningKeypair;

pub type Trie = OrgTrie<Blake3Hasher>;

/// Bundles a member's keys + a stable id for building leaves.
pub struct NodeFixture {
    pub keypair: SigningKeypair,
    pub device: SigningKeypair,
    pub id: MemberId,
}

/// Build a MemberLeaf from a fixture with a fixed handle/name.
pub fn member(fix: &NodeFixture, handle: &str) -> MemberLeaf {
    MemberLeaf::new(
        fix.id,
        handle,
        fix.keypair.member_key(),
        "Test",
        "User",
        vec![fix.device.device_key()],
    )
    .unwrap()
}

/// A genesis trie containing a single admin member (id = [1u8;32]).
pub fn genesis_trie(admin: &SigningKeypair, admin_device: &SigningKeypair) -> Trie {
    let admin_fix = NodeFixture {
        keypair: admin.clone(),
        device: admin_device.clone(),
        id: MemberId::new([1u8; 32]),
    };
    let leaf = member(&admin_fix, "admin");
    let (trie, _delta) = Trie::genesis(vec![leaf]).unwrap().recalculate().unwrap();
    trie
}

/// Build the "admit member B (id=[2u8;32])" delta against a genesis trie
/// authored by `admin`. Returns (delta, new_trie). `admin` doubles as the
/// admin device for fixture simplicity.
pub fn admit_member_delta(admin: &SigningKeypair) -> (Delta, Trie) {
    let base = genesis_trie(admin, admin);
    let b_member = SigningKeypair::from_seed([2u8; 32]);
    let b_device = SigningKeypair::from_seed([3u8; 32]);
    let b_fix = NodeFixture { keypair: b_member, device: b_device, id: MemberId::new([2u8; 32]) };
    let leaf = member(&b_fix, "bob");
    let (new_trie, delta) = base.add_member(leaf).unwrap().recalculate().unwrap();
    (delta, new_trie)
}

/// Helper exposing P2p key types so envelope tests can name them.
#[allow(dead_code)]
pub fn _key_types() -> (P2pMemberKey, P2pDeviceKey) {
    let k = SigningKeypair::from_seed([9u8; 32]);
    (k.member_key(), k.device_key())
}
```

Add to `lib.rs` (so test modules can reach it):

```rust
#[cfg(test)]
mod test_fixtures;
```

- [ ] **Step 2: Write the `SeqGuard` test + implementation**

`org-node/src/sequence.rs`:

```rust
//! Monotonic replay guard for envelope parent_seq. The trie's base_root gives
//! natural protection while history moves forward; SeqGuard defends the edge
//! case where a root recurs (add-then-remove). See org-members README §4.
use crate::error::OrgNodeError;

/// Tracks the highest parent_seq committed for one org.
#[derive(Clone, Copy, Debug, Default)]
pub struct SeqGuard {
    last_seen: u64,
}

impl SeqGuard {
    /// Starts at 0 (no envelope committed; genesis is seq 0).
    pub fn new() -> Self {
        Self { last_seen: 0 }
    }

    pub fn from_last_seen(last_seen: u64) -> Self {
        Self { last_seen }
    }

    pub fn last_seen(&self) -> u64 {
        self.last_seen
    }

    /// Accept `seq` only if strictly greater than the last seen. Does not mutate.
    pub fn check(&self, seq: u64) -> Result<(), OrgNodeError> {
        if seq > self.last_seen {
            Ok(())
        } else {
            Err(OrgNodeError::StaleSeq { got: seq, last_seen: self.last_seen })
        }
    }

    /// Commit `seq` as the new high-water mark (call only after a full accept).
    pub fn advance(&mut self, seq: u64) {
        if seq > self.last_seen {
            self.last_seen = seq;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_equal_and_lower_seq() {
        let g = SeqGuard::from_last_seen(5);
        assert!(g.check(6).is_ok());
        assert_eq!(g.check(5), Err(OrgNodeError::StaleSeq { got: 5, last_seen: 5 }));
        assert_eq!(g.check(4), Err(OrgNodeError::StaleSeq { got: 4, last_seen: 5 }));
    }

    #[test]
    fn advance_moves_high_water_mark_forward_only() {
        let mut g = SeqGuard::new();
        g.advance(3);
        assert_eq!(g.last_seen(), 3);
        g.advance(2); // ignored
        assert_eq!(g.last_seen(), 3);
    }
}
```

- [ ] **Step 3: Run fixtures + sequence tests**

Enable `mod sequence;` in `lib.rs`.
Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-node --lib sequence::`
Expected: 2 tests PASS. Then run the Task 5 envelope tests now that fixtures exist:
Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-node --lib envelope::`
Expected: 4 tests PASS.

- [ ] **Step 4: Commit**

```bash
git add org-node/src/test_fixtures.rs org-node/src/sequence.rs org-node/src/lib.rs
git commit -m "feat(org-node): shared test fixtures + SeqGuard replay protection"
```

---

## Task 7: `verify_envelope_against_chain` — the crux

**Files:**
- Create: `org-node/src/verify.rs`

This composes everything: signature, org binding, sequence, delta decode, base-root match, apply, and the **independent** on-chain root match. The on-chain root comes from `ChainReader`, never from the envelope.

- [ ] **Step 1: Write the implementation**

```rust
//! verify-against-chain: the single security property of the PoC. A received
//! envelope is committed only if applying its delta reproduces a root that
//! independently matches the on-chain root at a newer epoch. See spec §5.2.
use ed25519_dalek::VerifyingKey;
use org_members::hasher::Blake3Hasher;
use org_members::trie::OrgTrie;

use crate::chain::ChainReader;
use crate::envelope::SignedDeltaEnvelope;
use crate::error::OrgNodeError;
use crate::ids::OrgId;
use crate::sequence::SeqGuard;

pub type Trie = OrgTrie<Blake3Hasher>;

/// Inputs that pin what the receiver already trusts about the org.
pub struct VerifyContext<'a> {
    /// The org we expect this envelope to be for.
    pub expected_org_id: OrgId,
    /// The author's member key, learned out-of-band / from the trie.
    pub author_member_key: &'a VerifyingKey,
    /// Replay guard for this org.
    pub seq_guard: SeqGuard,
    /// The last on-chain epoch this receiver has already committed (0 if none).
    pub last_committed_epoch: u64,
}

/// The result of a successful verification: the new committed trie and the
/// advanced guards. Caller persists these atomically.
pub struct VerifiedUpdate {
    pub trie: Trie,
    pub seq_guard: SeqGuard,
    pub epoch: u64,
}

/// Verify an envelope against the local trie and an independent chain oracle.
///
/// Order is security-critical: cheap authenticity checks first, chain read and
/// root match last. Returns the committed trie or a typed rejection; never
/// panics, never mutates `local_trie`.
pub fn verify_envelope_against_chain<C: ChainReader>(
    local_trie: &Trie,
    envelope: &SignedDeltaEnvelope,
    ctx: &VerifyContext<'_>,
    chain: &C,
) -> Result<VerifiedUpdate, OrgNodeError> {
    // 1. Org binding.
    if envelope.org_id != ctx.expected_org_id {
        return Err(OrgNodeError::OrgIdMismatch);
    }
    // 2. Authenticity — before touching delta bytes.
    if !envelope.verify_signature(ctx.author_member_key) {
        return Err(OrgNodeError::BadSignature);
    }
    // 3. Replay.
    ctx.seq_guard.check(envelope.parent_seq)?;
    // 4. Decode the delta (typed error on malformed/non-canonical wire form).
    let delta = envelope.decode_delta()?;
    // 5. Base-root must match the local trie (apply_delta also checks this, but
    //    we surface the specific error before doing work).
    if delta.base_root() != &local_trie.root_hash()? {
        return Err(OrgNodeError::DeltaBaseMismatch);
    }
    // 6. Apply → candidate.
    let candidate = local_trie.apply_delta(&delta)?;
    // 7. Independent trusted root + epoch from the chain.
    let on_chain = chain
        .get_org_state(&ctx.expected_org_id)
        .map_err(OrgNodeError::Chain)?
        .ok_or(OrgNodeError::OrgNotOnChain)?;
    if on_chain.epoch <= ctx.last_committed_epoch {
        return Err(OrgNodeError::StaleEpoch { got: on_chain.epoch, last: ctx.last_committed_epoch });
    }
    // 8. The decisive check: recomputed root must equal the on-chain root.
    let committed = candidate
        .verify_against(&on_chain.root_hash)
        .map_err(|_| OrgNodeError::RootMismatch)?;

    let mut seq_guard = ctx.seq_guard;
    seq_guard.advance(envelope.parent_seq);
    Ok(VerifiedUpdate { trie: committed, seq_guard, epoch: on_chain.epoch })
}
```

Add `pub use verify::{verify_envelope_against_chain, VerifyContext, VerifiedUpdate};` to `lib.rs` and enable `mod verify;`.

- [ ] **Step 2: Write the happy-path test**

Append to `verify.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{MockChain, OrgState};
    use crate::keys::SigningKeypair;
    use crate::test_fixtures::{admit_member_delta, genesis_trie};
    use org_members::RootHash;

    fn setup() -> (SigningKeypair, OrgId, Trie, SignedDeltaEnvelope, RootHash) {
        let admin = SigningKeypair::from_seed([1u8; 32]);
        let local = genesis_trie(&admin, &admin); // receiver's mirror (epoch 1 state)
        let (delta, new_trie) = admit_member_delta(&admin);
        let org = OrgId::new([5u8; 20]);
        let env = SignedDeltaEnvelope::build(org, 2, &delta, &admin).unwrap();
        let new_root = new_trie.root_hash().unwrap();
        (admin, org, local, env, new_root)
    }

    #[test]
    fn happy_path_commits_when_root_matches_chain() {
        let (admin, org, local, env, new_root) = setup();
        let mut chain = MockChain::new();
        chain.set(org, OrgState { root_hash: new_root, org_pub_key: [0u8; 32], epoch: 2 });
        let ctx = VerifyContext {
            expected_org_id: org,
            author_member_key: &admin.verifying_key(),
            seq_guard: SeqGuard::from_last_seen(1),
            last_committed_epoch: 1,
        };
        let out = verify_envelope_against_chain(&local, &env, &ctx, &chain).unwrap();
        assert_eq!(out.epoch, 2);
        assert_eq!(out.seq_guard.last_seen(), 2);
        assert_eq!(out.trie.root_hash().unwrap(), new_root);
    }
}
```

- [ ] **Step 3: Run the happy-path test**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-node --lib verify::tests::happy_path`
Expected: PASS.

- [ ] **Step 4: Add a test per rejection path**

Append inside the same `mod tests`:

```rust
    #[test]
    fn rejects_wrong_org_id() {
        let (admin, org, local, env, _) = setup();
        let chain = MockChain::new();
        let ctx = VerifyContext {
            expected_org_id: OrgId::new([0xff; 20]),
            author_member_key: &admin.verifying_key(),
            seq_guard: SeqGuard::from_last_seen(1),
            last_committed_epoch: 1,
        };
        assert_eq!(verify_envelope_against_chain(&local, &env, &ctx, &chain), Err(OrgNodeError::OrgIdMismatch));
        let _ = org;
    }

    #[test]
    fn rejects_bad_signature() {
        let (_admin, org, local, env, _) = setup();
        let imposter = SigningKeypair::from_seed([0xaa; 32]);
        let chain = MockChain::new();
        let ctx = VerifyContext {
            expected_org_id: org,
            author_member_key: &imposter.verifying_key(),
            seq_guard: SeqGuard::from_last_seen(1),
            last_committed_epoch: 1,
        };
        assert_eq!(verify_envelope_against_chain(&local, &env, &ctx, &chain), Err(OrgNodeError::BadSignature));
    }

    #[test]
    fn rejects_stale_seq() {
        let (admin, org, local, env, new_root) = setup();
        let mut chain = MockChain::new();
        chain.set(org, OrgState { root_hash: new_root, org_pub_key: [0u8; 32], epoch: 2 });
        let ctx = VerifyContext {
            expected_org_id: org,
            author_member_key: &admin.verifying_key(),
            seq_guard: SeqGuard::from_last_seen(2), // env.parent_seq == 2, not > 2
            last_committed_epoch: 1,
        };
        assert_eq!(
            verify_envelope_against_chain(&local, &env, &ctx, &chain),
            Err(OrgNodeError::StaleSeq { got: 2, last_seen: 2 })
        );
    }

    #[test]
    fn rejects_when_org_absent_from_chain() {
        let (admin, org, local, env, _) = setup();
        let chain = MockChain::new(); // empty
        let ctx = VerifyContext {
            expected_org_id: org,
            author_member_key: &admin.verifying_key(),
            seq_guard: SeqGuard::from_last_seen(1),
            last_committed_epoch: 1,
        };
        assert_eq!(verify_envelope_against_chain(&local, &env, &ctx, &chain), Err(OrgNodeError::OrgNotOnChain));
    }

    #[test]
    fn rejects_root_mismatch_when_chain_root_differs() {
        let (admin, org, local, env, _new_root) = setup();
        let mut chain = MockChain::new();
        // Attacker-influenced delta but honest chain root that does NOT match.
        chain.set(org, OrgState { root_hash: RootHash::from_bytes([0xde; 32]), org_pub_key: [0u8; 32], epoch: 2 });
        let ctx = VerifyContext {
            expected_org_id: org,
            author_member_key: &admin.verifying_key(),
            seq_guard: SeqGuard::from_last_seen(1),
            last_committed_epoch: 1,
        };
        assert_eq!(verify_envelope_against_chain(&local, &env, &ctx, &chain), Err(OrgNodeError::RootMismatch));
    }

    #[test]
    fn rejects_stale_epoch() {
        let (admin, org, local, env, new_root) = setup();
        let mut chain = MockChain::new();
        chain.set(org, OrgState { root_hash: new_root, org_pub_key: [0u8; 32], epoch: 1 });
        let ctx = VerifyContext {
            expected_org_id: org,
            author_member_key: &admin.verifying_key(),
            seq_guard: SeqGuard::from_last_seen(1),
            last_committed_epoch: 1, // chain epoch 1 is not newer
        };
        assert_eq!(
            verify_envelope_against_chain(&local, &env, &ctx, &chain),
            Err(OrgNodeError::StaleEpoch { got: 1, last: 1 })
        );
    }
```

- [ ] **Step 5: Run all verify tests**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-node --lib verify::`
Expected: 7 tests PASS (1 happy + 6 rejection).

- [ ] **Step 6: Commit**

```bash
git add org-node/src/verify.rs org-node/src/lib.rs
git commit -m "feat(org-node): verify_envelope_against_chain + full rejection-path coverage"
```

---

## Task 8: Fuzz target — envelope decode

**Files:**
- Create: `org-node/tests/fuzz_envelope_decode/fuzz_target.rs`
- Create: `org-node/tests/fuzz_envelope_decode/corpus/.gitkeep`
- Create: `org-node/tests/fuzz_envelope_decode/crashes/.gitkeep`

Follow the repo's bolero pattern (see `on-chain-client/tests/fuzz_*`). The decoder must never panic on arbitrary bytes.

- [ ] **Step 1: Inspect the existing bolero pattern to mirror it exactly**

Run: `sed -n '1,40p' on-chain-client/tests/fuzz_decode_org_state/fuzz_target.rs`
Expected: shows the `bolero::check!()` harness shape used in this repo. Mirror its structure (per-target directory, `TypeGenerator`/byte-slice driver, `cargo test` integration) in the new target.

- [ ] **Step 2: Write the fuzz target**

```rust
//! Fuzz: SignedDeltaEnvelope postcard decode must never panic on arbitrary bytes.
use org_node::envelope::SignedDeltaEnvelope;

fn main() {
    bolero::check!().for_each(|bytes: &[u8]| {
        // Decoding arbitrary bytes as an envelope, then (if it parses) decoding
        // the inner delta, must only ever return Ok/Err — never panic.
        if let Ok(env) = postcard::from_bytes::<SignedDeltaEnvelope>(bytes) {
            let _ = env.decode_delta();
        }
    });
}
```

> `envelope` must be a public module (`pub mod envelope;` in `lib.rs` — it already is per Task 0) and `SignedDeltaEnvelope::decode_delta` public (it is per Task 5). If `postcard` is not visible to the test, add `postcard = { version = "1", features = ["alloc","use-std"] }` to `[dev-dependencies]`.

- [ ] **Step 3: Add the gitkeep files and run the fuzz target briefly**

```bash
touch org-node/tests/fuzz_envelope_decode/corpus/.gitkeep org-node/tests/fuzz_envelope_decode/crashes/.gitkeep
```

Run (short bounded run, like the repo's fuzz-in-CI usage):
`CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-node --test fuzz_envelope_decode`
Expected: builds and runs without a crash/panic (bolero's default `cargo test` mode replays the corpus; empty corpus passes trivially).

- [ ] **Step 4: Commit**

```bash
git add org-node/tests/fuzz_envelope_decode/
git commit -m "test(org-node): fuzz envelope postcard decode (no-panic)"
```

---

## Task 9: Fuzz target — verify entry point

**Files:**
- Create: `org-node/tests/fuzz_verify_against_chain/fuzz_target.rs`
- Create: `org-node/tests/fuzz_verify_against_chain/corpus/.gitkeep`
- Create: `org-node/tests/fuzz_verify_against_chain/crashes/.gitkeep`

Fuzz the whole verify path: arbitrary envelope bytes against a fixed, honestly-built local trie + chain. The property: the function returns `Ok`/`Err` and never panics, and any `Ok` result's trie root equals the chain root it was checked against.

- [ ] **Step 1: Write the fuzz target**

```rust
//! Fuzz: verify_envelope_against_chain must never panic on a malformed envelope,
//! and any accepted update must match the on-chain root.
use org_node::chain::{MockChain, OrgState};
use org_node::envelope::SignedDeltaEnvelope;
use org_node::ids::OrgId;
use org_node::keys::SigningKeypair;
use org_node::sequence::SeqGuard;
use org_node::verify::{verify_envelope_against_chain, VerifyContext};
use org_members::hasher::Blake3Hasher;
use org_members::trie::OrgTrie;
use org_members::{MemberId, MemberLeaf};

fn fixed_trie(admin: &SigningKeypair) -> OrgTrie<Blake3Hasher> {
    let leaf = MemberLeaf::new(
        MemberId::new([1u8; 32]),
        "admin",
        admin.member_key(),
        "T",
        "U",
        vec![admin.device_key()],
    )
    .unwrap();
    let (trie, _) = OrgTrie::<Blake3Hasher>::genesis(vec![leaf]).unwrap().recalculate().unwrap();
    trie
}

fn main() {
    let admin = SigningKeypair::from_seed([1u8; 32]);
    let local = fixed_trie(&admin);
    let org = OrgId::new([5u8; 20]);
    let mut chain = MockChain::new();
    chain.set(org, OrgState { root_hash: local.root_hash().unwrap(), org_pub_key: [0u8; 32], epoch: 9 });
    let vk = admin.verifying_key();

    bolero::check!().for_each(|bytes: &[u8]| {
        if let Ok(env) = postcard::from_bytes::<SignedDeltaEnvelope>(bytes) {
            let ctx = VerifyContext {
                expected_org_id: org,
                author_member_key: &vk,
                seq_guard: SeqGuard::from_last_seen(0),
                last_committed_epoch: 0,
            };
            if let Ok(out) = verify_envelope_against_chain(&local, &env, &ctx, &chain) {
                // Any accepted update must equal the chain root it verified against.
                assert_eq!(out.trie.root_hash().unwrap(), chain.get_org_state(&org).unwrap().unwrap().root_hash);
            }
        }
    });
}
```

> This requires `chain`, `ids`, `keys`, `sequence`, `verify` modules to be `pub` (per Task 0 they are). `org-members` must be a dev-dependency of `org-node` so the test can name its types — add to `[dev-dependencies]`: `org-members = { path = "../org-members", features = ["std","serde"] }`.

- [ ] **Step 2: Add gitkeeps and run**

```bash
touch org-node/tests/fuzz_verify_against_chain/corpus/.gitkeep org-node/tests/fuzz_verify_against_chain/crashes/.gitkeep
```

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-node --test fuzz_verify_against_chain`
Expected: builds and runs without panic.

- [ ] **Step 3: Commit**

```bash
git add org-node/tests/fuzz_verify_against_chain/ org-node/Cargo.toml
git commit -m "test(org-node): fuzz verify-against-chain entry point (no-panic + root invariant)"
```

---

## Task 10: Crate-wide green + clippy gate + README

**Files:**
- Create: `org-node/README.md`

- [ ] **Step 1: Full test run**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-node`
Expected: all unit + fuzz-harness tests PASS.

- [ ] **Step 2: Clippy gate (mirror the repo's lib gate)**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo clippy -p org-node --lib -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic`
Expected: no warnings. (Lib code must avoid `unwrap`/`expect`/`panic`; tests may use them freely.)

- [ ] **Step 3: Write `org-node/README.md`**

```markdown
# org-node

ODS Phase 2 node logic — the trust brain that sits above `org-members`.

This crate owns what `org-members` deliberately leaves to the caller: ed25519
signing, the `SignedDeltaEnvelope` wire form, monotonic replay protection, and
the **verify-against-chain** flow.

## The one property

`verify_envelope_against_chain` commits a received membership change only if,
after checking org binding + signature + sequence, applying the delta to the
local trie reproduces a root that **independently** matches the on-chain root
(read via `ChainReader`) at a newer epoch. The delta and the trusted root must
travel different trust paths.

## Status (Phase 2.1)

Pure core, no network/chain. The chain is abstracted behind `ChainReader`;
`MockChain` drives tests. Later phases wire `on-chain-client`/subxt (reads +
writes), iroh transport, persona/org persistence, and the Tauri/Svelte shell.

## Layout

- `keys.rs` — `SigningKeypair`; maps to `P2pMemberKey`/`P2pDeviceKey`.
- `ids.rs` — `OrgId` (= `h160_of(P)`).
- `chain.rs` — `ChainReader`, `OrgState`, `MockChain`.
- `envelope.rs` — `SignedDeltaEnvelope` (transcript = org_id ‖ parent_seq ‖ delta).
- `sequence.rs` — `SeqGuard`.
- `verify.rs` — `verify_envelope_against_chain` + `VerifyContext`/`VerifiedUpdate`.
```

- [ ] **Step 4: Commit**

```bash
git add org-node/README.md
git commit -m "docs(org-node): README — the verify-against-chain property and layout"
```

---

## Self-review notes (author check — already applied)

- **Spec coverage:** §5.1 envelope → Task 5; §5.2 verify-against-chain → Task 7; §5.4 epoch freshness → Task 7 (StaleEpoch); §4.1 OrgId/keys → Tasks 2–3; §9 fuzz (hard rule) → Tasks 8–9. Persona/org-record storage (§4.2–4.5), iroh auth (§5.3), chain wiring (§3.2), and the Tauri/Svelte shell (§3.1) are explicitly out of this phase and tracked for follow-up plans.
- **Type consistency:** `verify_envelope_against_chain`, `VerifyContext`, `VerifiedUpdate`, `SignedDeltaEnvelope::{build,decode_delta,verify_signature}`, `SeqGuard::{check,advance,from_last_seen,last_seen}`, `ChainReader::get_org_state`, `OrgState{root_hash,org_pub_key,epoch}`, `OrgId::{new,as_bytes}`, `SigningKeypair::{generate,from_seed,to_seed,verifying_key,member_key,device_key,sign}` are used consistently across tasks.
- **Real `org-members` API:** `OrgTrie::<Blake3Hasher>::genesis`, `.recalculate() -> (Self, Delta)`, `.add_member`, `.root_hash()`, `.apply_delta(&Delta) -> CandidateTrie`, `CandidateTrie::verify_against(&RootHash) -> OrgTrie`, `Delta::base_root()`, `MemberLeaf::new`, `MemberId::new`, `P2pMemberKey::new`, `P2pDeviceKey::new` — all verified against the crate source.
- **Build constraint:** every cargo invocation uses `CARGO_HOME=/tmp/cargo_home_fuzz` (read-only `~/.cargo`).

## Follow-up phases (separate plans)
1. **2.2 chain integration** — `ChainReader` over `on-chain-client`; subxt write path (`update()` via threshold-1 proxy); genesis ceremony; chopsticks integration test.
2. **2.3 transport** — iroh node (`NodeId = P2pDeviceKey`), authenticated channel, envelope + `org_secret_key` delivery; two-node integration test driving stories 1→5.
3. **2.4 shell** — persona/org persistence (encrypted at rest), Tauri commands/events, SvelteKit screens, two-instance demo.
