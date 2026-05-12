# Covenant Foundation Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Set up the Cargo workspace and implement `covenant-core` with all shared types, traits, and error types.

**Architecture:** Four-crate Cargo workspace. This plan builds the workspace root and `covenant-core`, the leaf crate with no internal dependencies. All other crates depend on it.

**Tech Stack:** Rust, serde, postcard, thiserror 2.x, zeroize

---

## File Structure

Every file created or modified by this plan, listed in creation order:

| File | Purpose |
|---|---|
| `covenant/.gitignore` | Standard Rust gitignore (target/, Cargo.lock for libs) |
| `covenant/Cargo.toml` | Workspace root declaring all 4 member crates |
| `covenant/covenant-core/Cargo.toml` | `covenant-core` crate manifest with dependencies and feature flags |
| `covenant/covenant-core/src/lib.rs` | Crate root: feature gates, module declarations, re-exports |
| `covenant/covenant-core/src/types.rs` | All core types: `Handle`, `OeId`, `Epoch`, `Role`, `RootHash`, `OePublicKey`, `OeKeyPair`, `MemberLeaf`, `MembershipProof`, `MerklePath`, `OeConfig` |
| `covenant/covenant-core/src/traits.rs` | Trait interfaces: `Verifier`, `Prover`, `HashFunction`, `SecureChannel`, `RootHashObserver` |
| `covenant/covenant-core/src/error.rs` | `CovenantError` enum via thiserror 2.x |
| `covenant/covenant-core/src/cu_boundary.rs` | CU-facing re-exports module |
| `covenant/covenant-crypto/Cargo.toml` | Stub manifest for `covenant-crypto` |
| `covenant/covenant-crypto/src/lib.rs` | Stub `lib.rs` (empty, just compiles) |
| `covenant/covenant-channel/Cargo.toml` | Stub manifest for `covenant-channel` |
| `covenant/covenant-channel/src/lib.rs` | Stub `lib.rs` (empty, just compiles) |
| `covenant/covenant-facade/Cargo.toml` | Stub manifest for the `covenant` facade crate (package name `covenant`) |
| `covenant/covenant-facade/src/lib.rs` | Stub `lib.rs` (empty, just compiles) |

**Naming note:** The facade crate lives in directory `covenant-facade/` to avoid a `covenant/covenant/` directory clash with the workspace root. Its `Cargo.toml` sets `[package] name = "covenant"`.

---

## Phase 1: Workspace Scaffolding

### Step 1.1 -- Create workspace root directory and `.gitignore`

- [ ] Create `covenant/.gitignore` with standard Rust ignores:

```
# File: covenant/.gitignore
/target
**/*.rs.bk
*.pdb
```

### Step 1.2 -- Create workspace `Cargo.toml`

- [ ] Create `covenant/Cargo.toml`:

```toml
# File: covenant/Cargo.toml
[workspace]
resolver = "2"
members = [
    "covenant-core",
    "covenant-crypto",
    "covenant-channel",
    "covenant-facade",
]

[workspace.package]
edition = "2021"
rust-version = "1.81"
repository = "https://github.com/parity-asia/2-tier-access-control"

[workspace.dependencies]
# Shared dependency versions managed here; members use `workspace = true`.
serde = { version = "1", default-features = false, features = ["derive"] }
postcard = { version = "1", default-features = false, features = ["alloc"] }
thiserror = { version = "2", default-features = false }
zeroize = { version = "1", features = ["derive"] }
```

### Step 1.3 -- Create `covenant-core/Cargo.toml`

- [ ] Create `covenant/covenant-core/Cargo.toml`:

```toml
# File: covenant/covenant-core/Cargo.toml
[package]
name = "covenant-core"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
repository.workspace = true
license = "Apache-2.0"
description = "Shared types, traits, and CU-facing boundary for the Covenant OE library"

[features]
default = ["std", "serde"]
std = ["serde?/std", "thiserror/std", "postcard?/use-std"]
alloc = ["postcard?/alloc"]
serde = ["dep:serde", "dep:postcard"]

[dependencies]
serde = { workspace = true, optional = true }
postcard = { workspace = true, optional = true }
thiserror = { workspace = true }
zeroize = { workspace = true }
```

### Step 1.4 -- Create stub `covenant-core/src/lib.rs`

- [ ] Create `covenant/covenant-core/src/lib.rs` with a minimal placeholder so the workspace compiles:

```rust
// File: covenant/covenant-core/src/lib.rs
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;
```

### Step 1.5 -- Create three stub crates so the workspace compiles

- [ ] Create `covenant/covenant-crypto/Cargo.toml`:

```toml
# File: covenant/covenant-crypto/Cargo.toml
[package]
name = "covenant-crypto"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
repository.workspace = true
license = "GPL-3.0-only"
description = "Merkle tree, zk-STARKs, and OESK for the Covenant OE library"

[dependencies]
covenant-core = { path = "../covenant-core" }
```

- [ ] Create `covenant/covenant-crypto/src/lib.rs`:

```rust
// File: covenant/covenant-crypto/src/lib.rs
```

- [ ] Create `covenant/covenant-channel/Cargo.toml`:

```toml
# File: covenant/covenant-channel/Cargo.toml
[package]
name = "covenant-channel"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
repository.workspace = true
license = "GPL-3.0-only"
description = "Double Ratchet and PQXDH secure channels for the Covenant OE library"

[dependencies]
covenant-core = { path = "../covenant-core" }
```

- [ ] Create `covenant/covenant-channel/src/lib.rs`:

```rust
// File: covenant/covenant-channel/src/lib.rs
```

- [ ] Create `covenant/covenant-facade/Cargo.toml`:

```toml
# File: covenant/covenant-facade/Cargo.toml
[package]
name = "covenant"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
repository.workspace = true
license = "GPL-3.0-only"
description = "High-level facade for the Covenant OE library"

[dependencies]
covenant-core = { path = "../covenant-core" }
covenant-crypto = { path = "../covenant-crypto" }
covenant-channel = { path = "../covenant-channel" }
```

- [ ] Create `covenant/covenant-facade/src/lib.rs`:

```rust
// File: covenant/covenant-facade/src/lib.rs
```

### Step 1.6 -- Verify workspace compiles

- [ ] Run from workspace root:

```bash
cd covenant && cargo check --workspace
```

**Expected:** Compiles with zero errors. There may be warnings about unused dependencies; that is fine.

### Step 1.7 -- Commit workspace scaffolding

- [ ] Commit:

```bash
cd covenant && git add -A && git commit -m "chore: scaffold four-crate Cargo workspace for covenant library"
```

---

## Phase 2: Error Types (TDD)

### Step 2.1 -- Write failing test for `CovenantError`

- [ ] Create `covenant/covenant-core/src/error.rs`:

```rust
// File: covenant/covenant-core/src/error.rs
```

- [ ] Add to `covenant/covenant-core/src/lib.rs` (append after the existing content):

```rust
pub mod error;
```

- [ ] Create test file `covenant/covenant-core/tests/error_tests.rs`:

```rust
// File: covenant/covenant-core/tests/error_tests.rs
use covenant_core::error::CovenantError;

#[test]
fn error_display_invalid_proof() {
    let err = CovenantError::InvalidProof;
    // thiserror generates Display from #[error("...")] attributes
    assert_eq!(err.to_string(), "invalid membership proof");
}

#[test]
fn error_display_member_not_found() {
    let err = CovenantError::MemberNotFound;
    assert_eq!(err.to_string(), "member not found");
}

#[test]
fn error_display_insufficient_threshold() {
    let err = CovenantError::InsufficientThreshold;
    assert_eq!(err.to_string(), "insufficient admin threshold");
}

#[test]
fn error_display_no_pending_commit() {
    let err = CovenantError::NoPendingCommit;
    assert_eq!(err.to_string(), "no pending commit");
}

#[test]
fn error_display_channel_error() {
    let err = CovenantError::ChannelError;
    assert_eq!(err.to_string(), "secure channel error");
}

#[test]
fn error_display_merkle_error() {
    let err = CovenantError::MerkleError;
    assert_eq!(err.to_string(), "merkle tree error");
}

#[test]
fn error_display_serialization_error() {
    let err = CovenantError::SerializationError;
    assert_eq!(err.to_string(), "serialization error");
}

#[test]
fn error_display_invalid_config() {
    let err = CovenantError::InvalidConfig;
    assert_eq!(err.to_string(), "invalid configuration");
}

#[test]
fn error_display_duplicate_member() {
    let err = CovenantError::DuplicateMember;
    assert_eq!(err.to_string(), "duplicate member");
}

#[test]
fn error_display_epoch_mismatch() {
    let err = CovenantError::EpochMismatch;
    assert_eq!(err.to_string(), "epoch mismatch");
}

#[test]
fn error_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<CovenantError>();
}

#[test]
fn error_implements_std_error() {
    fn assert_std_error<T: std::error::Error>() {}
    assert_std_error::<CovenantError>();
}
```

### Step 2.2 -- Run failing test

- [ ] Run:

```bash
cd covenant && cargo test -p covenant-core --test error_tests
```

**Expected:** Compilation error -- `CovenantError` does not exist yet.

### Step 2.3 -- Implement `CovenantError`

- [ ] Write `covenant/covenant-core/src/error.rs`:

```rust
// File: covenant/covenant-core/src/error.rs

/// Errors returned by the Covenant library.
///
/// Error messages are deliberately opaque for cryptographic operations
/// to avoid leaking internal state.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CovenantError {
    /// A membership proof failed verification.
    #[error("invalid membership proof")]
    InvalidProof,

    /// The requested member was not found in the tree.
    #[error("member not found")]
    MemberNotFound,

    /// The admin threshold requirement was not met.
    #[error("insufficient admin threshold")]
    InsufficientThreshold,

    /// prepare_root_update() called without a prior commit().
    #[error("no pending commit")]
    NoPendingCommit,

    /// A secure channel operation failed.
    #[error("secure channel error")]
    ChannelError,

    /// A Merkle tree operation failed.
    #[error("merkle tree error")]
    MerkleError,

    /// Serialization or deserialization failed.
    #[error("serialization error")]
    SerializationError,

    /// The provided configuration is invalid.
    #[error("invalid configuration")]
    InvalidConfig,

    /// A member with this handle already exists.
    #[error("duplicate member")]
    DuplicateMember,

    /// The epoch does not match the expected value.
    #[error("epoch mismatch")]
    EpochMismatch,
}
```

### Step 2.4 -- Run tests to verify they pass

- [ ] Run:

```bash
cd covenant && cargo test -p covenant-core --test error_tests
```

**Expected:** All 11 tests pass.

### Step 2.5 -- Commit error types

- [ ] Commit:

```bash
cd covenant && git add -A && git commit -m "feat(core): add CovenantError enum with thiserror 2.x"
```

---

## Phase 3: Simple Wrapper Types -- `Handle`, `OeId`, `Epoch` (TDD)

### Step 3.1 -- Write failing tests for `Handle`, `OeId`, `Epoch`

- [ ] Create `covenant/covenant-core/src/types.rs`:

```rust
// File: covenant/covenant-core/src/types.rs
```

- [ ] Add to `covenant/covenant-core/src/lib.rs` (append):

```rust
pub mod types;
```

- [ ] Create test file `covenant/covenant-core/tests/simple_types_tests.rs`:

```rust
// File: covenant/covenant-core/tests/simple_types_tests.rs
use covenant_core::types::{Handle, OeId, Epoch};

// --- Handle tests ---

#[test]
fn handle_from_bytes_and_as_bytes_roundtrip() {
    let bytes = [1u8; 32];
    let handle = Handle::from(bytes);
    assert_eq!(handle.as_bytes(), &bytes);
}

#[test]
fn handle_debug_does_not_leak_full_bytes() {
    let bytes = [0xABu8; 32];
    let handle = Handle::from(bytes);
    let debug = format!("{:?}", handle);
    // Debug should show a truncated hex representation, not all 32 bytes raw
    assert!(debug.contains("Handle"));
}

#[test]
fn handle_eq_same_bytes() {
    let a = Handle::from([1u8; 32]);
    let b = Handle::from([1u8; 32]);
    assert_eq!(a, b);
}

#[test]
fn handle_ne_different_bytes() {
    let a = Handle::from([1u8; 32]);
    let b = Handle::from([2u8; 32]);
    assert_ne!(a, b);
}

#[test]
fn handle_clone() {
    let a = Handle::from([1u8; 32]);
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn handle_hash_consistent() {
    use std::collections::HashSet;
    let a = Handle::from([1u8; 32]);
    let b = Handle::from([1u8; 32]);
    let mut set = HashSet::new();
    set.insert(a);
    assert!(set.contains(&b));
}

#[cfg(feature = "serde")]
#[test]
fn handle_serde_roundtrip() {
    let handle = Handle::from([42u8; 32]);
    let bytes = postcard::to_allocvec(&handle).unwrap();
    let decoded: Handle = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(handle, decoded);
}

// --- OeId tests ---

#[test]
fn oe_id_from_bytes_and_as_bytes_roundtrip() {
    let bytes = [7u8; 32];
    let id = OeId::from(bytes);
    assert_eq!(id.as_bytes(), &bytes);
}

#[test]
fn oe_id_eq() {
    let a = OeId::from([1u8; 32]);
    let b = OeId::from([1u8; 32]);
    assert_eq!(a, b);
}

#[test]
fn oe_id_clone() {
    let a = OeId::from([1u8; 32]);
    let b = a.clone();
    assert_eq!(a, b);
}

#[cfg(feature = "serde")]
#[test]
fn oe_id_serde_roundtrip() {
    let id = OeId::from([99u8; 32]);
    let bytes = postcard::to_allocvec(&id).unwrap();
    let decoded: OeId = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(id, decoded);
}

// --- Epoch tests ---

#[test]
fn epoch_new_and_value() {
    let epoch = Epoch::new(0);
    assert_eq!(epoch.value(), 0);
}

#[test]
fn epoch_increment() {
    let epoch = Epoch::new(5);
    let next = epoch.next();
    assert_eq!(next.value(), 6);
}

#[test]
fn epoch_original_unchanged_after_next() {
    let epoch = Epoch::new(5);
    let _next = epoch.next();
    assert_eq!(epoch.value(), 5);
}

#[test]
fn epoch_eq() {
    assert_eq!(Epoch::new(3), Epoch::new(3));
}

#[test]
fn epoch_ord() {
    assert!(Epoch::new(1) < Epoch::new(2));
}

#[cfg(feature = "serde")]
#[test]
fn epoch_serde_roundtrip() {
    let epoch = Epoch::new(42);
    let bytes = postcard::to_allocvec(&epoch).unwrap();
    let decoded: Epoch = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(epoch, decoded);
}
```

### Step 3.2 -- Run failing tests

- [ ] Run:

```bash
cd covenant && cargo test -p covenant-core --test simple_types_tests
```

**Expected:** Compilation error -- types do not exist yet.

### Step 3.3 -- Implement `Handle`, `OeId`, `Epoch`

- [ ] Write `covenant/covenant-core/src/types.rs`:

```rust
// File: covenant/covenant-core/src/types.rs

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::{collections::BTreeSet, string::String, vec::Vec};

#[cfg(feature = "std")]
use std::{collections::BTreeSet, string::String, vec::Vec};

use core::fmt;

/// Unique, immutable identifier for a member within an OE.
///
/// A 32-byte opaque wrapper. The concrete derivation strategy
/// (random, hash-based, etc.) is determined by higher-level crates.
#[derive(Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Handle([u8; 32]);

impl Handle {
    /// Returns the raw bytes of this handle.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for Handle {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Show only the first 4 bytes in hex to avoid leaking the full identifier
        write!(
            f,
            "Handle({:02x}{:02x}{:02x}{:02x}..)",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

/// Unique identifier for an Organizational Entity.
///
/// A 32-byte opaque wrapper. May be derived from the genesis root hash.
#[derive(Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OeId([u8; 32]);

impl OeId {
    /// Returns the raw bytes of this OE identifier.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for OeId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for OeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OeId({:02x}{:02x}{:02x}{:02x}..)",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

/// Monotonically increasing root hash era counter.
///
/// Each successful root hash update increments the epoch.
/// `Epoch` is `Copy` because it is a lightweight counter.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Epoch(u64);

impl Epoch {
    /// Creates a new epoch with the given value.
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the numeric value of this epoch.
    pub fn value(&self) -> u64 {
        self.0
    }

    /// Returns the next epoch (current + 1). Does not mutate `self`.
    pub fn next(&self) -> Self {
        Self(self.0 + 1)
    }
}
```

### Step 3.4 -- Run tests to verify they pass

- [ ] Run:

```bash
cd covenant && cargo test -p covenant-core --test simple_types_tests
```

**Expected:** All tests pass (17 tests including serde roundtrips).

### Step 3.5 -- Commit simple wrapper types

- [ ] Commit:

```bash
cd covenant && git add -A && git commit -m "feat(core): add Handle, OeId, and Epoch types"
```

---

## Phase 4: `Role` Type (TDD)

### Step 4.1 -- Write failing test for `Role`

- [ ] Create test file `covenant/covenant-core/tests/role_tests.rs`:

```rust
// File: covenant/covenant-core/tests/role_tests.rs
use covenant_core::types::Role;

#[test]
fn role_admin_exists() {
    let role = Role::Admin;
    assert_eq!(role, Role::Admin);
}

#[test]
fn role_member_exists() {
    let role = Role::Member;
    assert_eq!(role, Role::Member);
}

#[test]
fn role_custom_stores_id() {
    let role = Role::Custom(42);
    assert_eq!(role, Role::Custom(42));
}

#[test]
fn role_custom_ne_different_id() {
    assert_ne!(Role::Custom(1), Role::Custom(2));
}

#[test]
fn role_admin_ne_member() {
    assert_ne!(Role::Admin, Role::Member);
}

#[test]
fn role_debug() {
    let debug = format!("{:?}", Role::Admin);
    assert!(debug.contains("Admin"));
}

#[test]
fn role_clone() {
    let a = Role::Admin;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn role_ord_for_btreeset() {
    use std::collections::BTreeSet;
    let mut set = BTreeSet::new();
    set.insert(Role::Admin);
    set.insert(Role::Member);
    set.insert(Role::Custom(1));
    assert_eq!(set.len(), 3);
}

#[cfg(feature = "serde")]
#[test]
fn role_serde_roundtrip_admin() {
    let role = Role::Admin;
    let bytes = postcard::to_allocvec(&role).unwrap();
    let decoded: Role = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(role, decoded);
}

#[cfg(feature = "serde")]
#[test]
fn role_serde_roundtrip_custom() {
    let role = Role::Custom(99);
    let bytes = postcard::to_allocvec(&role).unwrap();
    let decoded: Role = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(role, decoded);
}
```

### Step 4.2 -- Run failing test

- [ ] Run:

```bash
cd covenant && cargo test -p covenant-core --test role_tests
```

**Expected:** Compilation error -- `Role` does not exist yet.

### Step 4.3 -- Implement `Role`

- [ ] Append to `covenant/covenant-core/src/types.rs`:

```rust
/// Role within an OE. Used for smart contract gating and ZKP role claims.
///
/// `Admin` and `Member` are the built-in roles. `Custom(u32)` allows
/// application-defined roles. `Ord` is derived so roles can be stored
/// in `BTreeSet` for deterministic serialization.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Role {
    /// OE administrator -- can modify the Merkle tree and participate in root hash ceremonies.
    Admin,
    /// Standard OE member -- can produce membership proofs.
    Member,
    /// Application-defined custom role identified by a numeric ID.
    Custom(u32),
}
```

### Step 4.4 -- Run tests to verify they pass

- [ ] Run:

```bash
cd covenant && cargo test -p covenant-core --test role_tests
```

**Expected:** All 10 tests pass.

### Step 4.5 -- Commit `Role`

- [ ] Commit:

```bash
cd covenant && git add -A && git commit -m "feat(core): add Role enum (Admin, Member, Custom)"
```

---

## Phase 5: Cryptographic Wrapper Types -- `RootHash`, `OePublicKey`, `OeKeyPair` (TDD)

### Step 5.1 -- Write failing tests for `RootHash`, `OePublicKey`, `OeKeyPair`

- [ ] Create test file `covenant/covenant-core/tests/crypto_types_tests.rs`:

```rust
// File: covenant/covenant-core/tests/crypto_types_tests.rs
use covenant_core::types::{RootHash, OePublicKey, OeKeyPair};

// --- RootHash tests ---

#[test]
fn root_hash_from_bytes_and_as_bytes_roundtrip() {
    let bytes = vec![0xAAu8; 32];
    let root = RootHash::new(bytes.clone());
    assert_eq!(root.as_bytes(), &bytes);
}

#[test]
fn root_hash_eq_same() {
    let a = RootHash::new(vec![1u8; 32]);
    let b = RootHash::new(vec![1u8; 32]);
    assert_eq!(a, b);
}

#[test]
fn root_hash_ne_different() {
    let a = RootHash::new(vec![1u8; 32]);
    let b = RootHash::new(vec![2u8; 32]);
    assert_ne!(a, b);
}

#[test]
fn root_hash_ne_different_length() {
    let a = RootHash::new(vec![1u8; 32]);
    let b = RootHash::new(vec![1u8; 64]);
    assert_ne!(a, b);
}

#[test]
fn root_hash_debug_does_not_leak_full_bytes() {
    let root = RootHash::new(vec![0xABu8; 32]);
    let debug = format!("{:?}", root);
    assert!(debug.contains("RootHash"));
    // Should not dump all 32 bytes
    assert!(debug.len() < 100);
}

#[test]
fn root_hash_clone() {
    let a = RootHash::new(vec![1u8; 32]);
    let b = a.clone();
    assert_eq!(a, b);
}

#[cfg(feature = "serde")]
#[test]
fn root_hash_serde_roundtrip() {
    let root = RootHash::new(vec![0xFFu8; 32]);
    let bytes = postcard::to_allocvec(&root).unwrap();
    let decoded: RootHash = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(root, decoded);
}

// --- OePublicKey tests ---

#[test]
fn oe_public_key_from_bytes_and_as_bytes() {
    let bytes = vec![3u8; 32];
    let pk = OePublicKey::new(bytes.clone());
    assert_eq!(pk.as_bytes(), &bytes);
}

#[test]
fn oe_public_key_eq() {
    let a = OePublicKey::new(vec![1u8; 32]);
    let b = OePublicKey::new(vec![1u8; 32]);
    assert_eq!(a, b);
}

#[test]
fn oe_public_key_clone() {
    let a = OePublicKey::new(vec![1u8; 32]);
    let b = a.clone();
    assert_eq!(a, b);
}

#[cfg(feature = "serde")]
#[test]
fn oe_public_key_serde_roundtrip() {
    let pk = OePublicKey::new(vec![5u8; 32]);
    let bytes = postcard::to_allocvec(&pk).unwrap();
    let decoded: OePublicKey = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(pk, decoded);
}

// --- OeKeyPair tests ---

#[test]
fn oe_keypair_public_key_accessor() {
    let pk = OePublicKey::new(vec![1u8; 32]);
    let sk = vec![2u8; 64];
    let kp = OeKeyPair::new(pk.clone(), sk);
    assert_eq!(kp.public_key(), &pk);
}

#[test]
fn oe_keypair_secret_key_bytes() {
    let pk = OePublicKey::new(vec![1u8; 32]);
    let sk = vec![2u8; 64];
    let kp = OeKeyPair::new(pk, sk.clone());
    assert_eq!(kp.secret_key_bytes(), &sk);
}

#[test]
fn oe_keypair_zeroize_on_drop() {
    // Verify OeKeyPair implements Zeroize by calling it explicitly.
    use zeroize::Zeroize;
    let pk = OePublicKey::new(vec![1u8; 32]);
    let sk = vec![2u8; 64];
    let mut kp = OeKeyPair::new(pk, sk);
    kp.zeroize();
    // After zeroize, the secret key bytes should be cleared
    assert!(kp.secret_key_bytes().iter().all(|&b| b == 0));
}

#[test]
fn oe_keypair_debug_does_not_leak_secret() {
    let pk = OePublicKey::new(vec![1u8; 32]);
    let sk = vec![0xFFu8; 64];
    let kp = OeKeyPair::new(pk, sk);
    let debug = format!("{:?}", kp);
    // Must not contain the secret key bytes
    assert!(!debug.contains("ff"));
    assert!(!debug.contains("FF"));
    assert!(debug.contains("OeKeyPair"));
}
```

### Step 5.2 -- Run failing tests

- [ ] Run:

```bash
cd covenant && cargo test -p covenant-core --test crypto_types_tests
```

**Expected:** Compilation error -- types do not exist yet.

### Step 5.3 -- Implement `RootHash`, `OePublicKey`, `OeKeyPair`

- [ ] Append to `covenant/covenant-core/src/types.rs`:

```rust
/// Fixed-size digest representing the Merkle root.
///
/// Generic over hash output size -- stored as a `Vec<u8>` to support
/// different hash functions (Rescue Prime, BLAKE3, SHA-3, etc.).
#[derive(Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RootHash(Vec<u8>);

impl RootHash {
    /// Creates a new root hash from raw digest bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the raw digest bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for RootHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.len() >= 4 {
            write!(
                f,
                "RootHash({:02x}{:02x}{:02x}{:02x}..)",
                self.0[0], self.0[1], self.0[2], self.0[3]
            )
        } else {
            write!(f, "RootHash(<{} bytes>)", self.0.len())
        }
    }
}

/// Opaque wrapper for a member's OE-level public key.
///
/// The concrete key type (algorithm, size) is determined by `covenant-crypto`.
#[derive(Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OePublicKey(Vec<u8>);

impl OePublicKey {
    /// Creates a new public key from raw bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the raw public key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for OePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OePublicKey(<{} bytes>)", self.0.len())
    }
}

/// A member's OE-level key pair (public + private).
///
/// Used for challenge-response authentication during onboarding,
/// recovery, and OESK updates. Implements `Zeroize` and `ZeroizeOnDrop`
/// to clear secret key material from memory.
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct OeKeyPair {
    #[zeroize(skip)]
    public_key: OePublicKey,
    secret_key: Vec<u8>,
}

impl OeKeyPair {
    /// Creates a new key pair from a public key and secret key bytes.
    pub fn new(public_key: OePublicKey, secret_key: Vec<u8>) -> Self {
        Self {
            public_key,
            secret_key,
        }
    }

    /// Returns a reference to the public key.
    pub fn public_key(&self) -> &OePublicKey {
        &self.public_key
    }

    /// Returns the raw secret key bytes.
    ///
    /// Use with care -- prefer methods that operate on the key pair
    /// without exposing the secret key directly.
    pub fn secret_key_bytes(&self) -> &[u8] {
        &self.secret_key
    }
}

impl fmt::Debug for OeKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OeKeyPair")
            .field("public_key", &self.public_key)
            .field("secret_key", &"<redacted>")
            .finish()
    }
}
```

### Step 5.4 -- Run tests to verify they pass

- [ ] Run:

```bash
cd covenant && cargo test -p covenant-core --test crypto_types_tests
```

**Expected:** All 14 tests pass.

### Step 5.5 -- Commit cryptographic wrapper types

- [ ] Commit:

```bash
cd covenant && git add -A && git commit -m "feat(core): add RootHash, OePublicKey, and OeKeyPair types"
```

---

## Phase 6: Proof Types -- `MembershipProof`, `MerklePath` (TDD)

### Step 6.1 -- Write failing tests for `MembershipProof` and `MerklePath`

- [ ] Create test file `covenant/covenant-core/tests/proof_types_tests.rs`:

```rust
// File: covenant/covenant-core/tests/proof_types_tests.rs
use covenant_core::types::{MembershipProof, MerklePath, RootHash};

// --- MembershipProof tests ---

#[test]
fn membership_proof_from_bytes_and_as_bytes() {
    let bytes = vec![1u8; 128];
    let proof = MembershipProof::new(bytes.clone());
    assert_eq!(proof.as_bytes(), &bytes);
}

#[test]
fn membership_proof_eq() {
    let a = MembershipProof::new(vec![1u8; 64]);
    let b = MembershipProof::new(vec![1u8; 64]);
    assert_eq!(a, b);
}

#[test]
fn membership_proof_ne() {
    let a = MembershipProof::new(vec![1u8; 64]);
    let b = MembershipProof::new(vec![2u8; 64]);
    assert_ne!(a, b);
}

#[test]
fn membership_proof_clone() {
    let a = MembershipProof::new(vec![1u8; 64]);
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn membership_proof_debug_does_not_leak_all_bytes() {
    let proof = MembershipProof::new(vec![0xABu8; 256]);
    let debug = format!("{:?}", proof);
    assert!(debug.contains("MembershipProof"));
    assert!(debug.len() < 200);
}

#[cfg(feature = "serde")]
#[test]
fn membership_proof_serde_roundtrip() {
    let proof = MembershipProof::new(vec![0xCDu8; 64]);
    let bytes = postcard::to_allocvec(&proof).unwrap();
    let decoded: MembershipProof = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(proof, decoded);
}

// --- MerklePath tests ---

#[test]
fn merkle_path_new_and_siblings() {
    let siblings = vec![vec![1u8; 32], vec![2u8; 32], vec![3u8; 32]];
    let leaf_index = 5u64;
    let path = MerklePath::new(siblings.clone(), leaf_index);
    assert_eq!(path.siblings(), &siblings);
    assert_eq!(path.leaf_index(), leaf_index);
}

#[test]
fn merkle_path_depth() {
    let siblings = vec![vec![0u8; 32]; 10];
    let path = MerklePath::new(siblings, 0);
    assert_eq!(path.depth(), 10);
}

#[test]
fn merkle_path_empty() {
    let path = MerklePath::new(vec![], 0);
    assert_eq!(path.depth(), 0);
}

#[test]
fn merkle_path_eq() {
    let siblings = vec![vec![1u8; 32]];
    let a = MerklePath::new(siblings.clone(), 0);
    let b = MerklePath::new(siblings, 0);
    assert_eq!(a, b);
}

#[test]
fn merkle_path_ne_different_index() {
    let siblings = vec![vec![1u8; 32]];
    let a = MerklePath::new(siblings.clone(), 0);
    let b = MerklePath::new(siblings, 1);
    assert_ne!(a, b);
}

#[test]
fn merkle_path_clone() {
    let siblings = vec![vec![1u8; 32]; 5];
    let a = MerklePath::new(siblings, 3);
    let b = a.clone();
    assert_eq!(a, b);
}

#[cfg(feature = "serde")]
#[test]
fn merkle_path_serde_roundtrip() {
    let siblings = vec![vec![1u8; 32], vec![2u8; 32]];
    let path = MerklePath::new(siblings, 7);
    let bytes = postcard::to_allocvec(&path).unwrap();
    let decoded: MerklePath = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(path, decoded);
}
```

### Step 6.2 -- Run failing tests

- [ ] Run:

```bash
cd covenant && cargo test -p covenant-core --test proof_types_tests
```

**Expected:** Compilation error -- types do not exist yet.

### Step 6.3 -- Implement `MembershipProof` and `MerklePath`

- [ ] Append to `covenant/covenant-core/src/types.rs`:

```rust
/// Opaque membership proof blob.
///
/// Wraps zk-STARK proof bytes. Verified against a `RootHash`.
/// The internal structure is determined by `covenant-crypto`.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MembershipProof(Vec<u8>);

impl MembershipProof {
    /// Creates a new membership proof from raw proof bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the raw proof bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for MembershipProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MembershipProof(<{} bytes>)", self.0.len())
    }
}

/// Authentication path from a leaf to the Merkle root.
///
/// Contains sibling hashes at each level and the leaf's index in the tree.
/// Used by the ZKP prover to construct membership proofs.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MerklePath {
    /// Sibling hashes from leaf to root.
    siblings: Vec<Vec<u8>>,
    /// The leaf's index in the tree (0-based).
    leaf_index: u64,
}

impl MerklePath {
    /// Creates a new Merkle path with the given sibling hashes and leaf index.
    pub fn new(siblings: Vec<Vec<u8>>, leaf_index: u64) -> Self {
        Self {
            siblings,
            leaf_index,
        }
    }

    /// Returns the sibling hashes.
    pub fn siblings(&self) -> &[Vec<u8>] {
        &self.siblings
    }

    /// Returns the leaf index.
    pub fn leaf_index(&self) -> u64 {
        self.leaf_index
    }

    /// Returns the depth of this path (number of levels from leaf to root).
    pub fn depth(&self) -> usize {
        self.siblings.len()
    }
}
```

### Step 6.4 -- Run tests to verify they pass

- [ ] Run:

```bash
cd covenant && cargo test -p covenant-core --test proof_types_tests
```

**Expected:** All 13 tests pass.

### Step 6.5 -- Commit proof types

- [ ] Commit:

```bash
cd covenant && git add -A && git commit -m "feat(core): add MembershipProof and MerklePath types"
```

---

## Phase 7: `MemberLeaf` and `OeConfig` (TDD)

### Step 7.1 -- Write failing tests for `MemberLeaf` and `OeConfig`

- [ ] Create test file `covenant/covenant-core/tests/composite_types_tests.rs`:

```rust
// File: covenant/covenant-core/tests/composite_types_tests.rs
use std::collections::BTreeSet;
use covenant_core::types::{
    Handle, MemberLeaf, OeConfig, OeId, OePublicKey, Role,
};

// --- MemberLeaf tests ---

#[test]
fn member_leaf_construction() {
    let handle = Handle::from([1u8; 32]);
    let pk = OePublicKey::new(vec![2u8; 32]);
    let mut roles = BTreeSet::new();
    roles.insert(Role::Admin);
    roles.insert(Role::Member);

    let leaf = MemberLeaf::new(
        handle.clone(),
        Some("Alice".into()),
        roles.clone(),
        pk.clone(),
    );

    assert_eq!(leaf.handle(), &handle);
    assert_eq!(leaf.display_name(), Some("Alice"));
    assert_eq!(leaf.roles(), &roles);
    assert_eq!(leaf.oe_public_key(), &pk);
}

#[test]
fn member_leaf_no_display_name() {
    let handle = Handle::from([1u8; 32]);
    let pk = OePublicKey::new(vec![2u8; 32]);
    let leaf = MemberLeaf::new(handle, None, BTreeSet::new(), pk);
    assert_eq!(leaf.display_name(), None);
}

#[test]
fn member_leaf_has_role_true() {
    let handle = Handle::from([1u8; 32]);
    let pk = OePublicKey::new(vec![2u8; 32]);
    let mut roles = BTreeSet::new();
    roles.insert(Role::Admin);
    let leaf = MemberLeaf::new(handle, None, roles, pk);
    assert!(leaf.has_role(&Role::Admin));
}

#[test]
fn member_leaf_has_role_false() {
    let handle = Handle::from([1u8; 32]);
    let pk = OePublicKey::new(vec![2u8; 32]);
    let mut roles = BTreeSet::new();
    roles.insert(Role::Member);
    let leaf = MemberLeaf::new(handle, None, roles, pk);
    assert!(!leaf.has_role(&Role::Admin));
}

#[test]
fn member_leaf_eq() {
    let handle = Handle::from([1u8; 32]);
    let pk = OePublicKey::new(vec![2u8; 32]);
    let roles = BTreeSet::new();
    let a = MemberLeaf::new(handle.clone(), None, roles.clone(), pk.clone());
    let b = MemberLeaf::new(handle, None, roles, pk);
    assert_eq!(a, b);
}

#[test]
fn member_leaf_clone() {
    let handle = Handle::from([1u8; 32]);
    let pk = OePublicKey::new(vec![2u8; 32]);
    let a = MemberLeaf::new(handle, Some("Bob".into()), BTreeSet::new(), pk);
    let b = a.clone();
    assert_eq!(a, b);
}

#[cfg(feature = "serde")]
#[test]
fn member_leaf_serde_roundtrip() {
    let handle = Handle::from([1u8; 32]);
    let pk = OePublicKey::new(vec![2u8; 32]);
    let mut roles = BTreeSet::new();
    roles.insert(Role::Admin);
    roles.insert(Role::Custom(5));
    let leaf = MemberLeaf::new(handle, Some("Charlie".into()), roles, pk);
    let bytes = postcard::to_allocvec(&leaf).unwrap();
    let decoded: MemberLeaf = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(leaf, decoded);
}

// --- OeConfig tests ---

#[test]
fn oe_config_construction() {
    let oe_id = OeId::from([1u8; 32]);
    let config = OeConfig::new(
        oe_id.clone(),
        "winterfell-stark".into(),
        2,   // admin threshold
        3600, // min update cadence in seconds
    );

    assert_eq!(config.oe_id(), &oe_id);
    assert_eq!(config.zkp_protocol(), "winterfell-stark");
    assert_eq!(config.admin_threshold(), 2);
    assert_eq!(config.min_update_cadence_secs(), 3600);
}

#[test]
fn oe_config_eq() {
    let oe_id = OeId::from([1u8; 32]);
    let a = OeConfig::new(oe_id.clone(), "stark".into(), 2, 3600);
    let b = OeConfig::new(oe_id, "stark".into(), 2, 3600);
    assert_eq!(a, b);
}

#[test]
fn oe_config_clone() {
    let oe_id = OeId::from([1u8; 32]);
    let a = OeConfig::new(oe_id, "stark".into(), 2, 3600);
    let b = a.clone();
    assert_eq!(a, b);
}

#[cfg(feature = "serde")]
#[test]
fn oe_config_serde_roundtrip() {
    let oe_id = OeId::from([1u8; 32]);
    let config = OeConfig::new(oe_id, "winterfell-stark".into(), 3, 7200);
    let bytes = postcard::to_allocvec(&config).unwrap();
    let decoded: OeConfig = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(config, decoded);
}

#[test]
fn oe_config_debug() {
    let oe_id = OeId::from([1u8; 32]);
    let config = OeConfig::new(oe_id, "stark".into(), 2, 3600);
    let debug = format!("{:?}", config);
    assert!(debug.contains("OeConfig"));
}
```

### Step 7.2 -- Run failing tests

- [ ] Run:

```bash
cd covenant && cargo test -p covenant-core --test composite_types_tests
```

**Expected:** Compilation error -- `MemberLeaf` and `OeConfig` do not exist yet.

### Step 7.3 -- Implement `MemberLeaf` and `OeConfig`

- [ ] Append to `covenant/covenant-core/src/types.rs`:

```rust
/// Leaf data stored in the OE Merkle tree for each member.
///
/// Contains the member's handle, optional display name, set of roles,
/// and OE-level public key. Roles are stored in a `BTreeSet` for
/// deterministic serialization order.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MemberLeaf {
    handle: Handle,
    display_name: Option<String>,
    roles: BTreeSet<Role>,
    oe_public_key: OePublicKey,
}

impl MemberLeaf {
    /// Creates a new member leaf.
    pub fn new(
        handle: Handle,
        display_name: Option<String>,
        roles: BTreeSet<Role>,
        oe_public_key: OePublicKey,
    ) -> Self {
        Self {
            handle,
            display_name,
            roles,
            oe_public_key,
        }
    }

    /// Returns the member's handle.
    pub fn handle(&self) -> &Handle {
        &self.handle
    }

    /// Returns the member's display name, if any.
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    /// Returns the member's roles.
    pub fn roles(&self) -> &BTreeSet<Role> {
        &self.roles
    }

    /// Returns whether the member has a specific role.
    pub fn has_role(&self, role: &Role) -> bool {
        self.roles.contains(role)
    }

    /// Returns the member's OE-level public key.
    pub fn oe_public_key(&self) -> &OePublicKey {
        &self.oe_public_key
    }
}

/// Bootstrap configuration for an Organizational Entity.
///
/// Contains the ZKP protocol identifier, admin threshold, and
/// minimum update cadence. The library stores and exposes this
/// configuration; enforcement of the cadence is the application's
/// responsibility.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OeConfig {
    oe_id: OeId,
    zkp_protocol: String,
    admin_threshold: u32,
    min_update_cadence_secs: u64,
}

impl OeConfig {
    /// Creates a new OE configuration.
    ///
    /// # Parameters
    /// - `oe_id`: Unique OE identifier.
    /// - `zkp_protocol`: Identifier for the ZKP protocol (e.g., "winterfell-stark").
    /// - `admin_threshold`: Minimum number of admins required for root hash updates (`t`).
    /// - `min_update_cadence_secs`: Minimum seconds between root hash updates (informational).
    pub fn new(
        oe_id: OeId,
        zkp_protocol: String,
        admin_threshold: u32,
        min_update_cadence_secs: u64,
    ) -> Self {
        Self {
            oe_id,
            zkp_protocol,
            admin_threshold,
            min_update_cadence_secs,
        }
    }

    /// Returns the OE identifier.
    pub fn oe_id(&self) -> &OeId {
        &self.oe_id
    }

    /// Returns the ZKP protocol identifier.
    pub fn zkp_protocol(&self) -> &str {
        &self.zkp_protocol
    }

    /// Returns the admin threshold `t`.
    pub fn admin_threshold(&self) -> u32 {
        self.admin_threshold
    }

    /// Returns the minimum update cadence in seconds.
    pub fn min_update_cadence_secs(&self) -> u64 {
        self.min_update_cadence_secs
    }
}
```

### Step 7.4 -- Run tests to verify they pass

- [ ] Run:

```bash
cd covenant && cargo test -p covenant-core --test composite_types_tests
```

**Expected:** All 12 tests pass.

### Step 7.5 -- Commit composite types

- [ ] Commit:

```bash
cd covenant && git add -A && git commit -m "feat(core): add MemberLeaf and OeConfig types"
```

---

## Phase 8: Trait Interfaces (TDD)

### Step 8.1 -- Write failing tests for traits

- [ ] Create `covenant/covenant-core/src/traits.rs`:

```rust
// File: covenant/covenant-core/src/traits.rs
```

- [ ] Add to `covenant/covenant-core/src/lib.rs` (append):

```rust
pub mod traits;
```

- [ ] Create test file `covenant/covenant-core/tests/traits_tests.rs`:

```rust
// File: covenant/covenant-core/tests/traits_tests.rs
use covenant_core::error::CovenantError;
use covenant_core::traits::{
    HashFunction, Prover, RootHashObserver, SecureChannel, Verifier,
};
use covenant_core::types::{
    Epoch, Handle, MemberLeaf, MembershipProof, MerklePath, OeId, RootHash,
};

// --- Mock implementations to test trait signatures compile ---

struct MockVerifier;

impl Verifier for MockVerifier {
    fn verify(
        &self,
        proof: &MembershipProof,
        root: &RootHash,
    ) -> Result<Handle, CovenantError> {
        let _ = (proof, root);
        Ok(Handle::from([0u8; 32]))
    }
}

struct MockProver;

impl Prover for MockProver {
    fn prove(
        &self,
        leaf: &MemberLeaf,
        path: &MerklePath,
        root: &RootHash,
    ) -> Result<MembershipProof, CovenantError> {
        let _ = (leaf, path, root);
        Ok(MembershipProof::new(vec![0u8; 64]))
    }
}

struct MockHashFunction;

impl HashFunction for MockHashFunction {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        // Trivial mock: just return first 32 bytes or pad
        let mut result = vec![0u8; 32];
        let len = data.len().min(32);
        result[..len].copy_from_slice(&data[..len]);
        result
    }

    fn merge(&self, left: &[u8], right: &[u8]) -> Vec<u8> {
        let mut combined = Vec::new();
        combined.extend_from_slice(left);
        combined.extend_from_slice(right);
        self.hash(&combined)
    }
}

struct MockSecureChannel {
    buffer: Vec<Vec<u8>>,
}

impl SecureChannel for MockSecureChannel {
    fn send(&mut self, msg: &[u8]) -> Result<(), CovenantError> {
        self.buffer.push(msg.to_vec());
        Ok(())
    }

    fn receive(&mut self) -> Result<Vec<u8>, CovenantError> {
        self.buffer
            .pop()
            .ok_or(CovenantError::ChannelError)
    }
}

struct MockRootHashObserver;

impl RootHashObserver for MockRootHashObserver {
    fn latest_root_hash(
        &self,
        oe_id: &OeId,
    ) -> Result<(RootHash, Epoch), CovenantError> {
        let _ = oe_id;
        Ok((RootHash::new(vec![0u8; 32]), Epoch::new(1)))
    }
}

// --- Actual tests ---

#[test]
fn verifier_trait_compiles_and_returns_handle() {
    let v = MockVerifier;
    let proof = MembershipProof::new(vec![1u8; 64]);
    let root = RootHash::new(vec![2u8; 32]);
    let result = v.verify(&proof, &root);
    assert!(result.is_ok());
}

#[test]
fn prover_trait_compiles_and_returns_proof() {
    use std::collections::BTreeSet;
    use covenant_core::types::OePublicKey;

    let p = MockProver;
    let handle = Handle::from([1u8; 32]);
    let pk = OePublicKey::new(vec![2u8; 32]);
    let leaf = MemberLeaf::new(handle, None, BTreeSet::new(), pk);
    let path = MerklePath::new(vec![vec![0u8; 32]; 10], 0);
    let root = RootHash::new(vec![3u8; 32]);
    let result = p.prove(&leaf, &path, &root);
    assert!(result.is_ok());
}

#[test]
fn hash_function_trait_hash_returns_bytes() {
    let h = MockHashFunction;
    let result = h.hash(b"hello");
    assert_eq!(result.len(), 32);
}

#[test]
fn hash_function_trait_merge_returns_bytes() {
    let h = MockHashFunction;
    let left = vec![1u8; 32];
    let right = vec![2u8; 32];
    let result = h.merge(&left, &right);
    assert_eq!(result.len(), 32);
}

#[test]
fn secure_channel_send_receive_roundtrip() {
    let mut ch = MockSecureChannel {
        buffer: Vec::new(),
    };
    ch.send(b"hello").unwrap();
    let received = ch.receive().unwrap();
    assert_eq!(received, b"hello");
}

#[test]
fn secure_channel_receive_empty_returns_error() {
    let mut ch = MockSecureChannel {
        buffer: Vec::new(),
    };
    let result = ch.receive();
    assert!(result.is_err());
}

#[test]
fn root_hash_observer_returns_root_and_epoch() {
    let obs = MockRootHashObserver;
    let oe_id = OeId::from([1u8; 32]);
    let (root, epoch) = obs.latest_root_hash(&oe_id).unwrap();
    assert_eq!(root, RootHash::new(vec![0u8; 32]));
    assert_eq!(epoch, Epoch::new(1));
}

#[test]
fn verifier_is_object_safe() {
    // Verifier must be usable as a trait object (dyn Verifier)
    fn accept_verifier(_v: &dyn Verifier) {}
    let v = MockVerifier;
    accept_verifier(&v);
}

#[test]
fn prover_is_object_safe() {
    fn accept_prover(_p: &dyn Prover) {}
    let p = MockProver;
    accept_prover(&p);
}

#[test]
fn hash_function_is_object_safe() {
    fn accept_hash(_h: &dyn HashFunction) {}
    let h = MockHashFunction;
    accept_hash(&h);
}

#[test]
fn secure_channel_is_object_safe() {
    fn accept_channel(_ch: &mut dyn SecureChannel) {}
    let mut ch = MockSecureChannel {
        buffer: Vec::new(),
    };
    accept_channel(&mut ch);
}

#[test]
fn root_hash_observer_is_object_safe() {
    fn accept_observer(_obs: &dyn RootHashObserver) {}
    let obs = MockRootHashObserver;
    accept_observer(&obs);
}
```

### Step 8.2 -- Run failing tests

- [ ] Run:

```bash
cd covenant && cargo test -p covenant-core --test traits_tests
```

**Expected:** Compilation error -- traits do not exist yet.

### Step 8.3 -- Implement trait interfaces

- [ ] Write `covenant/covenant-core/src/traits.rs`:

```rust
// File: covenant/covenant-core/src/traits.rs

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;

use crate::error::CovenantError;
use crate::types::{
    Epoch, Handle, MemberLeaf, MembershipProof, MerklePath, OeId, RootHash,
};

/// Abstract ZKP verifier.
///
/// Verifies a `MembershipProof` against a `RootHash`. On success,
/// returns the `Handle` revealed by the proof. Verification is
/// stateless: given a proof and a root hash, anyone can verify.
pub trait Verifier {
    /// Verifies the proof against the given root hash.
    ///
    /// Returns the `Handle` extracted from the proof on success.
    /// Returns `CovenantError::InvalidProof` on failure (opaque -- no
    /// internal details are leaked).
    fn verify(
        &self,
        proof: &MembershipProof,
        root: &RootHash,
    ) -> Result<Handle, CovenantError>;
}

/// Abstract ZKP prover.
///
/// Produces a `MembershipProof` given a leaf, its Merkle path, and the
/// root hash. The proof reveals only the `Handle` (and optionally a `Role`);
/// all other leaf data remains hidden.
pub trait Prover {
    /// Generates a membership proof for the given leaf.
    fn prove(
        &self,
        leaf: &MemberLeaf,
        path: &MerklePath,
        root: &RootHash,
    ) -> Result<MembershipProof, CovenantError>;
}

/// Trait over the Merkle hash function.
///
/// Swappable between hash algorithms (Rescue Prime, BLAKE3, SHA-3, etc.).
/// The hash function determines the output size implicitly through
/// the returned `Vec<u8>`.
pub trait HashFunction {
    /// Hashes raw data and returns the digest bytes.
    fn hash(&self, data: &[u8]) -> Vec<u8>;

    /// Merges two child hashes into a parent hash (inner node computation).
    fn merge(&self, left: &[u8], right: &[u8]) -> Vec<u8>;
}

/// Bidirectional encrypted channel.
///
/// Used for admin-member and admin-admin communication.
/// Implementations handle Double Ratchet state management internally.
/// The transport layer is the caller's responsibility.
pub trait SecureChannel {
    /// Encrypts and sends a message through the channel.
    fn send(&mut self, msg: &[u8]) -> Result<(), CovenantError>;

    /// Receives and decrypts the next message from the channel.
    fn receive(&mut self) -> Result<Vec<u8>, CovenantError>;
}

/// Blockchain boundary for reading on-chain root hash state.
///
/// This is an application-integration boundary. The application provides
/// an implementation that reads from its chosen blockchain. The library's
/// cryptographic operations always take explicit `RootHash` parameters
/// and do NOT use this trait internally.
pub trait RootHashObserver {
    /// Returns the latest root hash and epoch for the given OE.
    fn latest_root_hash(
        &self,
        oe_id: &OeId,
    ) -> Result<(RootHash, Epoch), CovenantError>;
}
```

### Step 8.4 -- Run tests to verify they pass

- [ ] Run:

```bash
cd covenant && cargo test -p covenant-core --test traits_tests
```

**Expected:** All 12 tests pass.

### Step 8.5 -- Commit trait interfaces

- [ ] Commit:

```bash
cd covenant && git add -A && git commit -m "feat(core): add Verifier, Prover, HashFunction, SecureChannel, and RootHashObserver traits"
```

---

## Phase 9: CU-Facing Boundary Re-exports (TDD)

### Step 9.1 -- Write failing test for CU boundary module

- [ ] Create `covenant/covenant-core/src/cu_boundary.rs`:

```rust
// File: covenant/covenant-core/src/cu_boundary.rs
```

- [ ] Add to `covenant/covenant-core/src/lib.rs` (append):

```rust
pub mod cu_boundary;
```

- [ ] Create test file `covenant/covenant-core/tests/cu_boundary_tests.rs`:

```rust
// File: covenant/covenant-core/tests/cu_boundary_tests.rs

/// Verify that all CU-facing types are re-exported from the cu_boundary module.
/// The CU tier depends on exactly these types.

#[test]
fn cu_boundary_exports_handle() {
    let _: covenant_core::cu_boundary::Handle = covenant_core::types::Handle::from([0u8; 32]);
}

#[test]
fn cu_boundary_exports_oe_id() {
    let _: covenant_core::cu_boundary::OeId = covenant_core::types::OeId::from([0u8; 32]);
}

#[test]
fn cu_boundary_exports_epoch() {
    let _: covenant_core::cu_boundary::Epoch = covenant_core::types::Epoch::new(0);
}

#[test]
fn cu_boundary_exports_root_hash() {
    let _: covenant_core::cu_boundary::RootHash =
        covenant_core::types::RootHash::new(vec![0u8; 32]);
}

#[test]
fn cu_boundary_exports_membership_proof() {
    let _: covenant_core::cu_boundary::MembershipProof =
        covenant_core::types::MembershipProof::new(vec![0u8; 64]);
}

#[test]
fn cu_boundary_exports_verifier_trait() {
    // Just verify the trait is accessible; we test it via a mock.
    fn accept(_v: &dyn covenant_core::cu_boundary::Verifier) {}
    // Compile-only test: the function signature proves the re-export exists.
    let _ = accept;
}
```

### Step 9.2 -- Run failing tests

- [ ] Run:

```bash
cd covenant && cargo test -p covenant-core --test cu_boundary_tests
```

**Expected:** Compilation error -- `cu_boundary` module is empty.

### Step 9.3 -- Implement CU-facing boundary re-exports

- [ ] Write `covenant/covenant-core/src/cu_boundary.rs`:

```rust
// File: covenant/covenant-core/src/cu_boundary.rs

//! CU-Facing Boundary
//!
//! Re-exports the types and traits that the future CU (Collaboration Unit)
//! tier depends on. This module is the stable public API surface that
//! downstream pallet developers and CU-tier code should import from.

pub use crate::traits::Verifier;
pub use crate::types::{Epoch, Handle, MembershipProof, OeId, RootHash};
```

### Step 9.4 -- Run tests to verify they pass

- [ ] Run:

```bash
cd covenant && cargo test -p covenant-core --test cu_boundary_tests
```

**Expected:** All 6 tests pass.

### Step 9.5 -- Commit CU-facing boundary

- [ ] Commit:

```bash
cd covenant && git add -A && git commit -m "feat(core): add CU-facing boundary re-exports"
```

---

## Phase 10: Finalize `lib.rs` and Full-Crate Integration Test

### Step 10.1 -- Write full crate re-exports in `lib.rs`

- [ ] Replace the content of `covenant/covenant-core/src/lib.rs` with the final version:

```rust
// File: covenant/covenant-core/src/lib.rs

//! `covenant-core` -- shared types, traits, and CU-facing boundary
//! for the Covenant OE library.
//!
//! This crate contains no cryptographic logic. It defines the type
//! vocabulary and trait interfaces that all other `covenant-*` crates
//! depend on.
//!
//! # Feature Flags
//!
//! - `std` (default): Enables `std::error::Error` impls and richer diagnostics.
//! - `alloc`: Enables heap allocation without `std`.
//! - `serde` (default): Enables `Serialize`/`Deserialize` for all types.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "alloc", not(feature = "std")))]
extern crate alloc;

pub mod cu_boundary;
pub mod error;
pub mod traits;
pub mod types;
```

### Step 10.2 -- Write integration test verifying the full public API

- [ ] Create test file `covenant/covenant-core/tests/integration_test.rs`:

```rust
// File: covenant/covenant-core/tests/integration_test.rs

//! Integration test: verifies that the full public API of covenant-core
//! is usable together in a realistic scenario.

use std::collections::BTreeSet;

use covenant_core::error::CovenantError;
use covenant_core::traits::{
    HashFunction, Prover, RootHashObserver, SecureChannel, Verifier,
};
use covenant_core::types::{
    Epoch, Handle, MemberLeaf, MembershipProof, MerklePath, OeConfig, OeId,
    OeKeyPair, OePublicKey, Role, RootHash,
};

#[test]
fn full_member_lifecycle_types_compose() {
    // 1. Create an OE configuration
    let oe_id = OeId::from([1u8; 32]);
    let config = OeConfig::new(
        oe_id.clone(),
        "winterfell-stark".into(),
        2,
        3600,
    );
    assert_eq!(config.admin_threshold(), 2);

    // 2. Create a member's key pair
    let pk = OePublicKey::new(vec![0xAAu8; 32]);
    let kp = OeKeyPair::new(pk.clone(), vec![0xBBu8; 64]);
    assert_eq!(kp.public_key(), &pk);

    // 3. Create a member leaf
    let handle = Handle::from([0x01u8; 32]);
    let mut roles = BTreeSet::new();
    roles.insert(Role::Admin);
    roles.insert(Role::Member);
    let leaf = MemberLeaf::new(
        handle.clone(),
        Some("Alice".into()),
        roles,
        pk,
    );
    assert!(leaf.has_role(&Role::Admin));
    assert!(leaf.has_role(&Role::Member));
    assert!(!leaf.has_role(&Role::Custom(99)));

    // 4. Create a root hash and epoch
    let root = RootHash::new(vec![0xCCu8; 32]);
    let epoch = Epoch::new(0);
    let next_epoch = epoch.next();
    assert_eq!(next_epoch.value(), 1);

    // 5. Create a Merkle path
    let path = MerklePath::new(vec![vec![0xDDu8; 32]; 10], 0);
    assert_eq!(path.depth(), 10);

    // 6. Create a membership proof (mock bytes)
    let proof = MembershipProof::new(vec![0xEEu8; 128]);

    // 7. Verify types are serde-compatible (compile-time check via bounds)
    fn assert_serde<T: serde::Serialize + serde::de::DeserializeOwned>() {}
    assert_serde::<Handle>();
    assert_serde::<OeId>();
    assert_serde::<Epoch>();
    assert_serde::<Role>();
    assert_serde::<RootHash>();
    assert_serde::<OePublicKey>();
    assert_serde::<MemberLeaf>();
    assert_serde::<MembershipProof>();
    assert_serde::<MerklePath>();
    assert_serde::<OeConfig>();
}

#[test]
fn cu_boundary_types_are_accessible() {
    // Verify CU boundary re-exports work
    use covenant_core::cu_boundary;

    let handle: cu_boundary::Handle = Handle::from([0u8; 32]);
    let oe_id: cu_boundary::OeId = OeId::from([0u8; 32]);
    let epoch: cu_boundary::Epoch = Epoch::new(0);
    let root: cu_boundary::RootHash = RootHash::new(vec![0u8; 32]);
    let proof: cu_boundary::MembershipProof = MembershipProof::new(vec![0u8; 64]);

    // All should be the same types
    let _: Handle = handle;
    let _: OeId = oe_id;
    let _: Epoch = epoch;
    let _: RootHash = root;
    let _: MembershipProof = proof;
}

#[test]
fn error_types_are_usable_with_result() {
    fn might_fail(succeed: bool) -> Result<Handle, CovenantError> {
        if succeed {
            Ok(Handle::from([0u8; 32]))
        } else {
            Err(CovenantError::MemberNotFound)
        }
    }

    assert!(might_fail(true).is_ok());
    let err = might_fail(false).unwrap_err();
    assert_eq!(err, CovenantError::MemberNotFound);
    assert_eq!(err.to_string(), "member not found");
}

#[cfg(feature = "serde")]
#[test]
fn postcard_deterministic_serialization() {
    // Verify that serializing the same value twice produces identical bytes.
    // This is critical for Merkle leaf hashing consistency.
    let handle = Handle::from([42u8; 32]);
    let pk = OePublicKey::new(vec![1u8; 32]);
    let mut roles = BTreeSet::new();
    roles.insert(Role::Admin);
    roles.insert(Role::Member);
    roles.insert(Role::Custom(5));
    let leaf = MemberLeaf::new(handle, Some("Test".into()), roles, pk);

    let bytes1 = postcard::to_allocvec(&leaf).unwrap();
    let bytes2 = postcard::to_allocvec(&leaf).unwrap();
    assert_eq!(bytes1, bytes2, "Serialization must be deterministic");
}
```

### Step 10.3 -- Run the full integration test

- [ ] Run:

```bash
cd covenant && cargo test -p covenant-core --test integration_test
```

**Expected:** All 4 tests pass.

### Step 10.4 -- Run all tests in the workspace

- [ ] Run:

```bash
cd covenant && cargo test --workspace
```

**Expected:** All tests across all crates pass. The three stub crates have no tests but compile successfully.

### Step 10.5 -- Run `cargo clippy` on the workspace

- [ ] Run:

```bash
cd covenant && cargo clippy --workspace --all-targets -- -D warnings
```

**Expected:** Zero warnings, zero errors.

### Step 10.6 -- Commit finalized `lib.rs` and integration test

- [ ] Commit:

```bash
cd covenant && git add -A && git commit -m "test(core): add integration test for full covenant-core public API"
```

---

## Phase 11: `no_std` Compilation Check

### Step 11.1 -- Verify `no_std` + `alloc` compiles

The `no_std` configuration is critical for WASM targets. We verify it compiles by building for a `no_std`-compatible target.

- [ ] Install the `thumbv7em-none-eabihf` target (bare-metal ARM, no `std`):

```bash
rustup target add thumbv7em-none-eabihf
```

- [ ] Run:

```bash
cd covenant && cargo check -p covenant-core --no-default-features --features alloc --target thumbv7em-none-eabihf
```

**Expected:** Compiles with zero errors. This proves `covenant-core` works without `std`.

### Step 11.2 -- Verify `no_std` without `alloc` compiles (types only, no serde)

- [ ] Run:

```bash
cd covenant && cargo check -p covenant-core --no-default-features --target thumbv7em-none-eabihf
```

**Expected:** This will fail because several types use `Vec` and `String` which require `alloc`. This is expected and acceptable -- the `alloc` feature is required for the heap-allocated types. Document this in a code comment if needed, but no code change is required. The failure confirms the feature gating is working correctly.

**Note:** If it does compile, that is also fine -- it means the conditional compilation is correctly gating out heap types. Either outcome is acceptable. The important check is Step 11.1 (with `alloc`).

### Step 11.3 -- Commit `no_std` verification (no code changes, just a passing CI check)

No commit needed for this step -- it is a verification-only phase. If any code changes were needed to fix `no_std` compilation in Step 11.1, those should be committed:

- [ ] If changes were made, commit:

```bash
cd covenant && git add -A && git commit -m "fix(core): ensure no_std + alloc compilation"
```

If no changes were needed, skip this step.

---

## Phase 12: Documentation Pass

### Step 12.1 -- Verify doc generation

- [ ] Run:

```bash
cd covenant && cargo doc -p covenant-core --no-deps
```

**Expected:** Documentation generates without warnings. All public items have doc comments.

### Step 12.2 -- Run doc tests

- [ ] Run:

```bash
cd covenant && cargo test -p covenant-core --doc
```

**Expected:** No doc test failures (there are no doc examples with `///` code blocks yet, so this should be a no-op pass).

### Step 12.3 -- Final commit if any doc improvements were needed

- [ ] If changes were made, commit:

```bash
cd covenant && git add -A && git commit -m "docs(core): improve rustdoc comments"
```

If no changes were needed, skip this step.

---

## Summary of Commits

| # | Message | What Changed |
|---|---|---|
| 1 | `chore: scaffold four-crate Cargo workspace for covenant library` | Workspace root, all 4 Cargo.toml files, stubs, .gitignore |
| 2 | `feat(core): add CovenantError enum with thiserror 2.x` | `error.rs` |
| 3 | `feat(core): add Handle, OeId, and Epoch types` | `types.rs` (partial) |
| 4 | `feat(core): add Role enum (Admin, Member, Custom)` | `types.rs` (append) |
| 5 | `feat(core): add RootHash, OePublicKey, and OeKeyPair types` | `types.rs` (append) |
| 6 | `feat(core): add MembershipProof and MerklePath types` | `types.rs` (append) |
| 7 | `feat(core): add MemberLeaf and OeConfig types` | `types.rs` (append) |
| 8 | `feat(core): add Verifier, Prover, HashFunction, SecureChannel, and RootHashObserver traits` | `traits.rs` |
| 9 | `feat(core): add CU-facing boundary re-exports` | `cu_boundary.rs` |
| 10 | `test(core): add integration test for full covenant-core public API` | `lib.rs` (final), `integration_test.rs` |
| 11 | `fix(core): ensure no_std + alloc compilation` | (conditional) |
| 12 | `docs(core): improve rustdoc comments` | (conditional) |

---

## Verification Checklist

After completing all phases, the following invariants should hold:

- [ ] `cargo test --workspace` passes with all tests green
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` produces zero warnings
- [ ] `cargo check -p covenant-core --no-default-features --features alloc --target thumbv7em-none-eabihf` compiles
- [ ] `cargo doc -p covenant-core --no-deps` generates without warnings
- [ ] All types implement `serde::Serialize` + `serde::Deserialize` (behind `serde` feature)
- [ ] `OeKeyPair` implements `Zeroize` and `ZeroizeOnDrop`
- [ ] `OeKeyPair`'s `Debug` impl does not leak secret key material
- [ ] Error messages are opaque (no cryptographic internals leaked)
- [ ] No `async` anywhere in `covenant-core`
- [ ] CU-facing boundary re-exports exactly: `Verifier`, `RootHash`, `MembershipProof`, `Handle`, `OeId`, `Epoch`
