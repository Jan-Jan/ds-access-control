# `org-members` Library Design

**Component:** Organisation Members Binary Sparse Merkle Trie
**Language:** Rust (WASM-compilable)
**Scope:** Off-chain trie library -- no on-chain submission, no ZKPs, no secure channels, no org key pair
**Date:** 2026-05-07
**Supersedes:** `docs/superpowers/specs/2026-03-13-covenant-library-design.md`

## Overview

`org-members` is a Rust library implementing an immutable binary Sparse Merkle Tree (SMT) for managing organisation membership. It provides:

- A depth-256 SMT keyed on member handle bits, with stable positions across add/remove
- Member leaves containing handle, name, surname, Keyhive `group_pk`, and a depth-2 device sub-trie
- Immutable path-copying mutations (`upsert`, `delete`) with lazy hash computation via `OnceLock`
- A `recalculate()` function that fills all pending hashes in one bottom-up pass
- Merkle deltas for efficient distribution of trie changes
- Type-state `CandidateTrie` enforcing verification before acceptance
- Pluggable hash function with Poseidon over Pallas field as default (future Halo2 ZKP compatibility)

The library is blockchain-agnostic. It produces root hashes and deltas; the caller handles on-chain submission. It is designed for `no_std` + `alloc` and compiles to `wasm32-unknown-unknown`.

## Crate Architecture

Single crate. No workspace split -- ZKPs, secure channels, and on-chain logic are out of scope.

```
org-members/
  Cargo.toml
  src/
    lib.rs             # crate root, feature gates, re-exports
    types.rs           # Handle, RootHash, MemberLeaf, DeviceKey
    trie.rs            # OrgTrie: immutable SMT, querying, diff
    node.rs            # Node type with OnceLock<[u8; 32]> hash
    delta.rs           # Delta, CandidateTrie (type-state)
    hasher.rs          # TrieHasher trait, PoseidonHasher, domain separation
    device_trie.rs     # Depth-2 device sub-trie computation
    error.rs           # OrgMembersError enum
    normalize.rs       # NFC Unicode normalization helpers
  tests/
    ...
```

## Data Model

### Sparse Merkle Tree (depth 256)

The main trie is a **binary Sparse Merkle Tree** with conceptual depth 256 (matching the 256-bit handle). Each handle's bits determine its path from root to leaf -- positions are stable across add/remove operations.

**Why SMT over sorted-array tree:**

- **Stable positions.** Adding/removing a member does not shift other members' positions. Existing membership proofs remain valid.
- **Efficient deltas.** A delta for adding one member is one leaf change; the receiver rehashes one path (256 hashes). A sorted-array tree would shift ~N/2 positions, requiring a full rebuild.
- **ZKP forward-compatibility.** Future ZKP circuits can prove membership with a fixed-depth (256) path traversal. No variable-length proofs or position-dependent circuits.

**Storage:** Only non-default nodes are stored. A node is "default" if its entire subtree contains no real leaves. Default hashes are precomputed once per level:

```
default_hash[0] = hash_member_leaf(EMPTY_SENTINEL_BYTES)
default_hash[i] = hash_member_node(default_hash[i-1], default_hash[i-1])
```

For 1000 members, approximately 247,000 non-default internal nodes exist (~7.9 MB).

**Empty sentinel:** `hash_member_leaf(b"EMPTY_SENTINEL_ORG_MEMBERS_V1")`. This is a nothing-up-my-sleeve value that cannot collide with any valid member leaf hash because the preimage is not a valid serialized `MemberLeaf`. The handle `[0u8; 32]` is reserved/forbidden to prevent any edge-case collision.

### Node Representation

Each node uses `OnceLock<[u8; 32]>` for lazy, write-once hash computation. Structural sharing between trie versions uses `Arc<Node>`.

```rust
use std::sync::{Arc, OnceLock};

struct Node {
    hash: OnceLock<[u8; 32]>,
    kind: NodeKind,
}

enum NodeKind {
    Internal { left: Arc<Node>, right: Arc<Node> },
    Leaf { member: MemberLeaf },
    Empty,  // sentinel -- hash is precomputed at construction
}
```

**Why `OnceLock` + `Arc`:**

- `OnceLock` provides interior mutability for exactly one write. No dirty tracking needed -- an unset `OnceLock` **is** the indicator that the hash needs computation.
- `Arc` enables structural sharing: unchanged subtrees from the previous trie are shared by reference. Only nodes along a modified path are newly allocated (with empty `OnceLock`).
- `OnceLock` makes `Node` `Sync`, so `Arc<Node>` is `Send + Sync`. This doesn't restrict downstream consumers to single-threaded use, and enables potential parallelization of `recalculate()` on native (e.g., via rayon). On WASM without threads, atomics compile to regular loads/stores -- no real overhead.
- The atomic overhead of `OnceLock` (one CAS on write, one atomic load on read) is negligible compared to a Poseidon hash (~50us).

### Member Leaf

```rust
pub struct MemberLeaf {
    handle: Handle,           // [u8; 32], unique, immutable, PII
    name: String,             // NFC-normalized at construction
    surname: String,          // NFC-normalized at construction
    group_pk: [u8; 32],       // Keyhive group public key
    devices: DeviceSlots,     // depth-2 sub-trie (max 4 devices)
}
```

**Canonical byte encoding** (for hashing):

```
[handle:              32 bytes, raw]
[name_len:            4 bytes LE u32] [name: UTF-8 bytes]
[surname_len:         4 bytes LE u32] [surname: UTF-8 bytes]
[group_pk:            32 bytes, raw]
[device_sub_trie_root: 32 bytes, raw (Pallas LE)]
```

All multi-byte integers are little-endian (matching Pallas Fp canonical encoding and WASM native byte order). Variable-length strings use explicit 4-byte LE length prefixes. NFC normalization is applied at construction time (`MemberLeaf::new()`), not at hash time.

This byte sequence is hashed with `hash_member_leaf()` (domain-separated).

**`Debug` impl redacts all PII fields:**

```
MemberLeaf { handle: [REDACTED], name: [REDACTED], surname: [REDACTED],
             group_pk: <32 bytes>, devices: 2 }
```

### Device Sub-Trie (depth 2)

Each member has a fixed depth-2 binary Merkle tree for devices (max 4 slots). Each device is identified by its `ed25519_pk: [u8; 32]`.

```rust
pub struct DeviceSlots {
    slots: [Option<[u8; 32]>; 4],  // ed25519 public keys, sorted
}
```

The sub-trie root is computed bottom-up using device-domain-separated hashing:

```
Level 0 (leaves): hash_device_leaf(ed25519_pk) or device_default_hash[0]
Level 1:          hash_device_node(child_left, child_right)
Level 2 (root):   hash_device_node(child_left, child_right)
```

Device default sentinel: `hash_device_leaf(b"EMPTY_SENTINEL_ORG_MEMBERS_DEVICE_V1")`.

Devices within a member are assigned to slots by sorted order of their `ed25519_pk` bytes. This ensures deterministic slot assignment regardless of insertion order.

**Future ZKP compatibility:** This structure enables two composable proofs:
1. **Device proof:** prove `ed25519_pk` is in the device sub-trie (depth-2 path)
2. **Membership proof:** prove the member leaf (containing the device sub-trie root) is in the main trie (depth-256 path)

## Hash Trait

Four domain-separated static methods. Static (no `&self`) because Poseidon parameters are compile-time constants -- enables monomorphization with zero overhead.

```rust
pub trait TrieHasher: Clone + Send + Sync {
    /// Hash a serialized member leaf (domain: MEMBER_LEAF).
    fn hash_member_leaf(data: &[u8]) -> [u8; 32];

    /// Hash two child node hashes into a parent (domain: MEMBER_NODE).
    fn hash_member_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32];

    /// Hash a device public key (domain: DEVICE_LEAF).
    fn hash_device_leaf(data: &[u8]) -> [u8; 32];

    /// Hash two device child hashes into a parent (domain: DEVICE_NODE).
    fn hash_device_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32];
}
```

**Why 4 separate methods instead of a domain parameter:** Compile-time domain safety. Calling the wrong domain function is a type error, not a runtime bug. This also maps 1:1 to future Halo2 circuit gadgets, where each domain becomes a distinct gadget with baked-in constants.

**Not object-safe** (static methods have no `self` receiver). The trie is generic: `OrgTrie<H: TrieHasher>`. Monomorphization provides zero-cost abstraction.

### Poseidon Configuration (Default: `PoseidonHasher`)

- **Field:** Pallas base field (Fp, ~255-bit prime). Pallas is the native scalar field for Halo2 circuits on the Vesta curve.
- **Width:** t=3 (2 inputs + 1 capacity element) for node hashing; sponge mode for variable-length leaf data.
- **S-box:** x^5 (invertible over Pallas Fp since gcd(5, p-1)=1).
- **Rounds:** RF=8 full rounds (4 before, 4 after partial rounds), RP=56 partial rounds. 128-bit security per Poseidon paper recommendations for ~255-bit prime at width 3.
- **Domain separation:** Capacity element initialized to a domain constant before absorbing input:
  - `DOMAIN_MEMBER_LEAF = Fp::from(1)`
  - `DOMAIN_MEMBER_NODE = Fp::from(2)`
  - `DOMAIN_DEVICE_LEAF = Fp::from(3)`
  - `DOMAIN_DEVICE_NODE = Fp::from(4)`
- **Byte-to-field conversion:** Input bytes split into 31-byte chunks (248 bits < 255 bits, so every chunk is a valid Fp element via LE interpretation). Final chunk zero-padded. Length prefix (original byte length as Fp) prepended. Chunks absorbed two at a time (rate = 2). Output is a single Fp element (32 bytes canonical LE).
- **Crate:** `halo2_gadgets::poseidon` or the standalone `poseidon` crate using `pasta_curves::Fp`. These provide both native evaluation and in-circuit Halo2 gadgets from the same parameter set, guaranteeing hash consistency between off-chain and on-circuit.

## Mutation Model

Mutations use **immutable path-copying with lazy hash computation**:

1. `upsert()` / `delete()` create **new nodes along the affected path**. The new nodes have empty `OnceLock` hashes. Unchanged subtrees are shared via `Arc<Node>` -- those nodes already have populated hashes from a previous `recalculate()`.
2. Multiple mutations can be chained. Each one path-copies from the current root, creating new nodes with empty hashes along the affected path.
3. `recalculate()` walks the trie bottom-up, filling every empty `OnceLock` in one pass. Returns the trie (now with all hashes populated) and a delta.

```rust
// Start from an existing trie (all hashes populated)
let trie = trie.upsert(alice_leaf);       // new path nodes with empty OnceLock
let trie = trie.upsert(bob_leaf);         // same -- shares structure with above
let trie = trie.delete(&charlie_handle);  // marks charlie's path with empty nodes

// All leaves are correct, but some path hashes are unpopulated
let (trie, delta) = trie.recalculate()?;
// Now all OnceLock hashes are filled; root_hash() works
```

**Why this model:**

- **No dirty tracking.** An unset `OnceLock` is the indicator. No separate dirty-bit or dirty-set.
- **Immutability preserved.** Each `upsert`/`delete` returns a new trie. The previous trie is untouched (its `OnceLock` hashes remain populated). Safe for rollback: just drop the new trie.
- **Batch-friendly.** Multiple mutations accumulate cheaply (just path-copies). All hash computation is deferred to one `recalculate()` call, which can be optimized (batch bottom-up, potentially parallelized on native).
- **Natural API.** No builder pattern, no consumed-self ceremony. Just chain operations and recalculate when ready.

## Public API

### Core Types

```rust
/// 32-byte opaque member identifier. Unique within an org. PII -- redacted in Debug.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Handle(pub(crate) [u8; 32]);

/// Merkle root hash. 32-byte Poseidon output.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RootHash(pub(crate) [u8; 32]);
```

### OrgTrie

```rust
impl<H: TrieHasher> OrgTrie<H> {
    // --- Construction ---

    /// Creates a genesis trie from initial members.
    /// Inserts each member then calls recalculate() internally.
    pub fn genesis(members: Vec<MemberLeaf>) -> Result<Self, OrgMembersError>;

    // --- Querying (requires hashes to be populated) ---

    /// Returns the root hash. Panics if recalculate() has not been called
    /// since the last mutation.
    pub fn root_hash(&self) -> RootHash;

    /// Returns true if all hashes are populated (recalculate has been called).
    pub fn is_calculated(&self) -> bool;

    pub fn member_count(&self) -> usize;
    pub fn contains(&self, handle: &Handle) -> bool;
    pub fn get(&self, handle: &Handle) -> Option<&MemberLeaf>;
    pub fn members(&self) -> impl Iterator<Item = &MemberLeaf> + '_;

    // --- Mutations (return new trie via path-copying) ---

    /// Inserts a new member or replaces an existing one at the same handle.
    /// Returns a new trie with empty OnceLock hashes along the affected path.
    pub fn upsert(&self, leaf: MemberLeaf) -> Result<Self, OrgMembersError>;

    /// Removes a member. Returns a new trie with the leaf position set to empty
    /// and empty OnceLock hashes along the affected path.
    pub fn delete(&self, handle: &Handle) -> Result<Self, OrgMembersError>;

    // --- Hash computation ---

    /// Walks the trie bottom-up, filling every empty OnceLock hash.
    /// Returns the trie (now fully hashed) and a delta capturing all changes
    /// since the last recalculate().
    pub fn recalculate(&self) -> Result<(Self, Delta), OrgMembersError>;

    // --- Delta application ---

    /// Applies a received delta. Returns CandidateTrie (must verify before use).
    /// Fails immediately if delta.base_root != self.root_hash().
    pub fn apply_delta(&self, delta: &Delta) -> Result<CandidateTrie<H>, OrgMembersError>;

    // --- Long-offline catch-up ---

    /// Computes the delta that transforms `old` into `self`.
    /// Both tries must have populated hashes.
    /// Walks both tries comparing subtree hashes; short-circuits on match.
    pub fn diff_from(&self, old: &OrgTrie<H>) -> Delta;

    // --- Serialization (includes all internal node hashes) ---

    pub fn to_bytes(&self) -> Result<Vec<u8>, OrgMembersError>;
    pub fn from_bytes(data: &[u8]) -> Result<Self, OrgMembersError>;
}
```

### CandidateTrie (Type-State)

```rust
/// Result of apply_delta(). Cannot query members -- can only verify or drop.
/// This compile-time guarantee prevents using unverified trie state.
pub struct CandidateTrie<H: TrieHasher> { /* private */ }

impl<H: TrieHasher> CandidateTrie<H> {
    /// The root hash of the candidate (for logging/comparison before verifying).
    pub fn root_hash(&self) -> RootHash;

    /// Verifies root hash matches expected value (e.g., from on-chain).
    /// On success, consumes self and returns verified OrgTrie.
    /// On failure, consumes self and returns error.
    pub fn verify_against(self, expected_root: &RootHash)
        -> Result<OrgTrie<H>, OrgMembersError>;
}
```

`CandidateTrie` has **no** member query methods. The only useful operation is `verify_against()`. Dropping silently discards the candidate.

### Delta

```rust
/// A set of changes anchored to a specific base trie root.
#[derive(Clone)]
pub struct Delta {
    base_root: RootHash,
    removed: Vec<Handle>,
    upserted: Vec<MemberLeaf>,
}

impl Delta {
    pub fn base_root(&self) -> &RootHash;
    pub fn removed(&self) -> &[Handle];
    pub fn upserted(&self) -> &[MemberLeaf];
    pub fn is_empty(&self) -> bool;

    pub fn to_bytes(&self) -> Result<Vec<u8>, OrgMembersError>;
    pub fn from_bytes(data: &[u8]) -> Result<Self, OrgMembersError>;
}
```

The delta does **not** contain a `new_root`. The receiver recomputes the root independently after applying -- never trusts an embedded root claim.

**Both creation flows produce the same format:**
- `recalculate()`: captures all mutations since the last recalculate as removed handles + upserted leaves.
- `diff_from()`: walks both tries comparing subtree hashes; emits handles present only in old as removed, leaves that differ or are only in new as upserted.

### MemberLeaf

```rust
impl MemberLeaf {
    /// Constructs a new member leaf. Name and surname are NFC-normalized.
    pub fn new(
        handle: Handle,
        name: &str,
        surname: &str,
        group_pk: [u8; 32],
        devices: Vec<[u8; 32]>,  // ed25519 public keys
    ) -> Result<Self, OrgMembersError>;

    pub fn handle(&self) -> &Handle;
    pub fn name(&self) -> &str;
    pub fn surname(&self) -> &str;
    pub fn group_pk(&self) -> &[u8; 32];
    pub fn devices(&self) -> &[[u8; 32]];       // sorted
    pub fn has_device(&self, ed25519_pk: &[u8; 32]) -> bool;
    pub fn device_count(&self) -> usize;
}
```

`MemberLeaf::new()` enforces invariants:
- NFC-normalizes name and surname
- Sorts device keys lexicographically
- Rejects handle `[0u8; 32]` (reserved for empty sentinel)
- Rejects more than 4 devices
- Rejects empty device list (member must have at least one device)

## Security Invariants

| ID | Invariant | Attack Prevented |
|---|---|---|
| SI-1 | Unique handle per trie | Duplicate-handle identity hijack |
| SI-2 | Handle bits determine leaf position (SMT) | Position instability, proof invalidation on add/remove |
| SI-3 | Immutable path-copying (mutations return new trie) | TOCTOU bugs between hash computation and consumption |
| SI-4 | Delta base binding (`base_root` must match current trie) | Wrong-base delta substitution attack |
| SI-5 | Device sub-trie depth bound (fixed at 2, max 4) | Resource exhaustion via unbounded device tree |
| SI-6 | Empty sentinel is domain-hashed nothing-up-my-sleeve value | Existential forgery via sentinel collision |
| SI-7 | Handle `[0u8; 32]` reserved/forbidden | Edge-case sentinel collision |
| SI-8 | NFC normalization at construction time | Cross-platform hash divergence from Unicode form differences |
| SI-9 | All PII (handle, name, surname) redacted in Debug/Display | PII leakage through logs |
| SI-10 | Deterministic serialization (postcard, LE integers, sorted devices) | Cross-platform root hash divergence |
| SI-11 | Domain-separated hashing (4 domains) | Second-preimage node/leaf confusion attacks |
| SI-12 | Receiver recomputes root (never trusts delta's claim) | Malicious delta with falsified root hash |

### Delta Verification Flow

When applying a received delta:

1. **Base hash match.** `delta.base_root == current_trie.root_hash()`. Reject immediately otherwise.
2. **Apply mutations.** For each removed handle, path-copy to empty leaf. For each upserted leaf, validate invariants and path-copy to new leaf.
3. **Recalculate.** Fill all empty `OnceLock` hashes bottom-up.
4. **Return CandidateTrie.** Caller must verify `candidate.root_hash()` against the on-chain root hash via `verify_against()`.

### Serialization Security

- **postcard** for canonical binary format. Never self-describing formats for hash input.
- **NFC normalization** applied once at `MemberLeaf::new()`. All stored strings are already NFC.
- **Sorted device keys** within each member. Deterministic slot assignment.
- **Cross-platform test vectors** in CI: known leaf data -> known serialized bytes -> known hashes, verified across x86_64, aarch64, wasm32.

## Error Types

```rust
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OrgMembersError {
    #[error("duplicate handle")]
    DuplicateHandle,

    #[error("handle not found")]
    HandleNotFound,

    #[error("reserved handle")]
    ReservedHandle,

    #[error("duplicate device")]
    DuplicateDevice,

    #[error("device not found")]
    DeviceNotFound,

    #[error("device slots full (max 4)")]
    DeviceSlotsFull,

    #[error("member must have at least one device")]
    EmptyDeviceList,

    #[error("delta base root mismatch")]
    DeltaBaseMismatch,

    #[error("verification failed")]
    VerificationFailed,

    #[error("serialization error")]
    SerializationError,

    #[error("hashes not calculated")]
    HashesNotCalculated,
}
```

Error messages are deliberately opaque -- no handles, names, or internal state in the error string.

## Performance

### Incremental Operations (Normal Path)

| Operation | Hash count | Estimated WASM time |
|---|---|---|
| upsert 1 member | 0 (deferred to recalculate) | <1ms |
| delete 1 member | 0 (deferred to recalculate) | <1ms |
| recalculate after 1 change | ~259 (256 path + 3 device) | ~39ms |
| recalculate after 10 changes | ~2,590 | ~389ms |

### Full Rebuild (Infrequent)

| Operation | Hash count | Estimated WASM time |
|---|---|---|
| Genesis (1000 members) | ~250,000 | ~37s |
| Deserialize from bytes | 0 (hashes loaded from serialized state) | <100ms |

Genesis is a one-time cost, acceptable for an operation run on server/native. Deserialization avoids rehashing by persisting all internal node hashes. On native, `recalculate()` can potentially be parallelized via rayon (enabled by `OnceLock` + `Arc`).

### Diff (Long-Offline Catch-Up)

Walking two tries comparing subtree hashes. Short-circuits on matching subtrees (32-byte memcmp, ~1ns each). No hashing performed during diff -- only comparisons. Even worst-case (all 1000 members differ) completes in microseconds.

### Memory

| Component | Size (1000 members) |
|---|---|
| Member leaf data | ~180 KB |
| Non-default internal node hashes (247K x 32 bytes) | ~7.9 MB |
| Device sub-trie data | ~128 KB |
| Arc/OnceLock overhead | ~4 MB |
| **Total** | **~12.2 MB** |

Acceptable for WASM.

## Feature Flags

| Feature | Effect |
|---|---|
| `std` (default) | `std::error::Error` impls, `OnceLock` from std |
| `alloc` | Heap allocation without `std` |
| `serde` (default) | Serialization support via serde + postcard |
| `wasm` | WASM-specific optimizations |

## Dependencies

| Crate | Purpose | WASM impact |
|---|---|---|
| `pasta_curves` | Pallas field arithmetic for Poseidon | ~80 KB |
| Poseidon impl (TBD: `halo2_gadgets`, `neptune`, or hand-rolled) | Default hasher over Pallas | included in pasta |
| `serde` + `postcard` | Deterministic binary serialization | ~15 KB |
| `unicode-normalization` | NFC for name/surname | ~40 KB |
| `thiserror` 2.x | Error type derivation | minimal |

**Not needed:** `getrandom` (no key generation), `zeroize` (no secret key material in this library), `x25519-dalek` (org key pair out of scope).

**Estimated WASM bundle (gzipped): ~100-130 KB.**

## Merkle Path Structure (Future ZKP Support)

Not implemented in this phase, but the trie structure supports extracting authentication paths for future ZKP circuits.

### Member Merkle Path

```rust
pub struct MemberMerklePath {
    handle: Handle,                // determines path bits
    siblings: [[u8; 32]; 256],     // one sibling hash per level
}
```

Verification: start with `h = hash_member_leaf(encode(leaf))`, then for each level i (0 = leaf level, 255 = root): if `handle_bit[i]` is 0, `h = hash_member_node(h, siblings[i])`, else `h = hash_member_node(siblings[i], h)`. Final `h` must equal the root hash.

### Device Merkle Path (Two-Level)

```rust
pub struct DeviceMerklePath {
    // Level 1: device in sub-trie
    device_slot: u8,                // 0..3
    device_siblings: [[u8; 32]; 2], // depth-2 sub-trie
    // Level 2: member in main trie
    member_path: MemberMerklePath,
}
```

Verify device segment yields device sub-trie root, confirm it matches the `device_sub_trie_root` in the member leaf encoding, then verify member segment yields the org root. Enables future ZKP proof: "this ed25519 public key belongs to a member of this org."

## Design Decisions Log

| Decision | Choice | Rationale |
|---|---|---|
| Crate structure | Single crate | ZKPs, channels, on-chain all out of scope. No consumers needing license-split types yet. |
| Trie type | Binary Sparse Merkle Tree, depth 256 | Handle-bit keying gives stable positions. Critical for ZKP forward-compat and efficient deltas. |
| Node hashing | `OnceLock<[u8; 32]>` (lazy, write-once) | No dirty tracking needed. Unset OnceLock is the indicator. Immutable after set. |
| Structural sharing | `Arc<Node>` | Enables path-copying without cloning entire trie. OnceLock makes Node Sync, so Arc works. |
| OnceLock over OnceCell | Thread-safe at negligible cost | Atomic CAS/load negligible vs Poseidon hash. Doesn't restrict consumers to single-threaded. Enables parallel recalculate on native. |
| Mutation model | `upsert()`/`delete()` return new trie; `recalculate()` fills hashes | No builder pattern. Natural chaining. Batch-friendly: defer all hashing to one call. |
| Hash function | Pluggable trait, Poseidon/Pallas default | Future Halo2 ZKP compatibility. Off-chain hashes match on-circuit hashes. |
| Hash trait methods | 4 static methods (no &self) | Compile-time domain safety. Maps 1:1 to circuit gadgets. |
| Domain separation | 4 domains via Poseidon capacity element | Prevents second-preimage attacks across trie levels. |
| Device sub-trie | Depth-2 binary tree, max 4 devices | Members typically have 1-2 devices. Fixed depth enables predictable ZKP circuit. |
| Device slot assignment | Sorted by ed25519_pk bytes | Deterministic regardless of insertion order. |
| Empty sentinel | Domain-hashed NUMS value | Cannot collide with valid leaf data. |
| CandidateTrie type-state | No query methods, only verify_against() or drop | Compile-time enforcement of "verify before accept". |
| Delta format | base_root + removed + upserted, no new_root | Receiver recomputes root independently. |
| Handle as PII | Redacted in Debug/Display | Handle identifies a person within the org. |
| Serialization | postcard (deterministic, no_std, compact) | Critical for cross-platform Merkle hash consistency. |
| Unicode normalization | NFC at MemberLeaf::new() | Consistent bytes for hashing regardless of platform. |
| Name fields | Separate name + surname | Per design requirement. |
| Roles | Not in trie | Admin status determined by on-chain multisig. |
| Org key pair | Not in scope | Deferred. Library is purely the trie data structure. |
| Genesis perf | Accept ~37s WASM; serialize full state to avoid rebuilds | One-time cost. Deserialization loads cached hashes. Normal ops are incremental. |

## Known Limitations

| Limitation | Impact | Follow-Up |
|---|---|---|
| Genesis of 1000 members is ~37s in WASM | Slow initial creation in browser | Run genesis on server/native; distribute serialized trie. Or parallelize recalculate() with rayon on native. |
| ~12 MB memory for 1000 members | Non-trivial for constrained environments | Acceptable for desktop/mobile WASM. Could compress with path-shortcutting if needed. |
| No Merkle path extraction API | Cannot generate ZKP proofs yet | Planned for ZKP phase. Trie structure already supports it. |
| Poseidon crate choice not finalized | Dependency risk | Evaluate `halo2_gadgets::poseidon`, `neptune`, `light-poseidon` during implementation. |
| No `no_std`/WASM compilation verification | Feature flags untested | Add cargo check for wasm32-unknown-unknown and thumbv7em-none-eabihf during implementation. |
| 256 siblings per Merkle proof | Large proof size (8 KB) | Most siblings are default hashes and can be compressed. Address in ZKP phase. |
