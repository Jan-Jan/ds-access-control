# Covenant Library Design

**Component:** OE (Organizational Entity) -- Tier 1 of the Two-Tier Access Control system
**Language:** Rust
**Scope:** Off-chain only, blockchain-agnostic
**Date:** 2026-03-13

## Overview

`covenant` is a Rust library implementing the Organizational Entity (OE) tier of the Two-Tier Blockchain Mediated Local-First Access Control system. It provides:

- Off-chain Merkle tree management for OE membership
- zk-STARK membership proofs (via Winterfell)
- Serializable artifacts for on-chain proxy multisig consensus on root hash updates
- Double Ratchet with PQXDH for secure admin-member channels
- Public types and traits for the future CU (Collaboration Unit) tier to depend on

The library is blockchain-agnostic. It produces serializable artifacts (genesis data, root update proposals, commit confirmations) that the caller submits to their chosen blockchain. Polkadot-specific integration will be added later as a separate layer.

## Crate Architecture

Four crates in a Cargo workspace, following Approach B (responsibility-grouped):

```
covenant/
  Cargo.toml              # workspace root
  covenant-core/          # types, traits, CU boundary       (Apache-2.0)
  covenant-crypto/        # Merkle tree, zk-STARKs, OESK       (GPL-3.0)
  covenant-channel/       # Double Ratchet, PQXDH             (GPL-3.0)
  covenant/               # high-level facade                 (GPL-3.0)
```

### Dependency Graph

```
covenant (facade)
  |-- covenant-core
  |-- covenant-crypto
  |     \-- covenant-core
  \-- covenant-channel
        \-- covenant-core
```

No cycles. `covenant-crypto` and `covenant-channel` are independent of each other.

## Crate 1: `covenant-core` (Apache-2.0)

Shared types, traits, and the CU-facing boundary. Contains no cryptographic logic.

### Core Types

- **`Handle`** -- unique, immutable identifier for a member within an OE (opaque wrapper).
- **`MemberLeaf`** -- leaf data: `{ handle: Handle, display_name: Option<String>, roles: Set<Role>, oe_public_key: OePublicKey }`.
- **`Role`** -- enum or opaque identifier for smart contract roles (e.g. `Admin`, `Member`, custom).
- **`RootHash`** -- fixed-size digest representing the Merkle root (generic over hash output size).
- **`MembershipProof`** -- opaque proof blob verified against a `RootHash` (wraps zk-STARK proof bytes).
- **`MerklePath`** -- authentication path (sibling hashes from leaf to root) for ZKP construction.
- **`OeConfig`** -- bootstrap configuration: ZKP protocol identifier, admin threshold `t`, minimum update cadence.
- **`OeId`** -- unique OE identifier (could be derived from genesis root hash).
- **`Epoch`** -- monotonically increasing root hash era counter.
- **`OePublicKey`** -- opaque wrapper for a member's OE-level public key. Concrete key type is determined by `covenant-crypto`.
- **`OeKeyPair`** -- a member's OE-level key pair (public + private). Used for challenge-response authentication during onboarding, recovery, and OESK updates. The member's `OePublicKey` is stored in their `MemberLeaf`; the private key is held only by the member. Concrete key types are determined by `covenant-crypto`.

### Trait Interfaces

- **`Verifier`** -- abstract ZKP verifier: `fn verify(proof: &MembershipProof, root: &RootHash) -> Result<VerifiedClaim>`.
- **`Prover`** -- abstract ZKP prover: `fn prove(leaf: &MemberLeaf, path: &MerklePath, root: &RootHash) -> Result<MembershipProof>`.
- **`HashFunction`** -- trait over the Merkle hash (swappable between Rescue Prime, BLAKE3, SHA-3, etc.).
- **`SecureChannel`** -- bidirectional encrypted channel: `fn send(&mut self, msg: &[u8]) -> Result<()>`, `fn receive(&mut self) -> Result<Vec<u8>>`.
- **`RootHashObserver`** -- blockchain boundary: `fn latest_root_hash(oe_id: &OeId) -> Result<(RootHash, Epoch)>`. Caller provides the implementation. **Note:** this trait is an application-integration boundary for learning about on-chain state. It is NOT used internally by cryptographic operations, which always take explicit `RootHash` parameters.

### CU-Facing Boundary

The future CU/OEValidityGate tier depends on: `Verifier`, `RootHash`, `MembershipProof`, `Handle`, `OeId`, `Epoch`.

### Type Placement

Types live in the crate that owns their semantics:

| Type | Crate | Rationale |
|---|---|---|
| `Handle`, `MemberLeaf`, `Role`, `RootHash`, `MembershipProof`, `MerklePath`, `OeConfig`, `OeId`, `Epoch`, `OePublicKey`, `OeKeyPair` | `covenant-core` | Shared types, no crypto logic |
| `MerkleDelta`, `CandidateTree` | `covenant-crypto` | Produced by Merkle tree operations |
| `OeSecretKey` | `covenant-crypto` | Shared group key, contains key material |
| `RootUpdateProposal`, `GenesisArtifact`, `AdminView`, `MemberView`, `MemberUpdate`, `OeskUpdateResult`, `OeBootstrapConfig` | `covenant` (facade) | Orchestration types composing lower crates |

### Error Types

`CovenantError` enum: `InvalidProof`, `MemberNotFound`, `InsufficientThreshold`, `ChannelError`, `MerkleError`, `NoPendingCommit`, etc. Derived via `thiserror 2.x`.

### Design Constraints

- All types implement `serde::Serialize` / `Deserialize`.
- All types are `no_std`-compatible with optional `std` feature flag.
- No async in core.

## Crate 2: `covenant-crypto` (GPL-3.0)

OE-specific cryptographic operations. Depends on `covenant-core`.

### Merkle Tree

Thin immutable wrapper over `winter-crypto::MerkleTree`:

- The tree is an **immutable data type**. Each commit produces a new tree instance; the previous tree is untouched. This enables rollback by simply discarding a candidate tree if a delta from another admin is rejected (compromised admin, different delta settled upon).
- Internally stores a `Vec<MemberLeaf>` of leaves. Mutations accumulate via a builder, then a single `commit()` rebuilds the `winter_crypto::MerkleTree` and produces a `MerkleDelta`.
- Hash function is pluggable via the `HashFunction` trait. Default: **Rescue Prime** (STARK-friendly, dramatically reduces in-circuit proving cost). BLAKE3 provided for non-ZKP uses.
- Leaves are serialized deterministically (canonical byte encoding via `postcard`) before hashing.
- Supports batched mutations: multiple adds, updates, and removes accumulate before a single commit produces one `MerkleDelta`.

**API:**

```rust
// Batch mutations via builder (tree is immutable)
let builder = tree.derive();
builder.add_member(leaf);
builder.update_member(handle, updates);
builder.remove_member(handle);
let (new_tree, delta) = builder.commit()?;
// `tree` is unchanged; `new_tree` is the new snapshot

// Apply a delta from another admin (produces candidate for review)
let candidate_tree = current_tree.apply_delta(&delta)?;
// Accept: current_tree = candidate_tree;
// Reject: drop candidate_tree, current_tree untouched

// Rollback is implicit: don't swap

// Generate authentication path for a member
let path: MerklePath = tree.path_for(&handle)?;

// Root hash of this snapshot
let root: RootHash = tree.root_hash();
```

**Privacy enforcement:** `tree.path_for(handle)` returns only the authentication path for that member. No public API for leaf enumeration. Full tree access requires `AdminView`.

**`MerkleDelta`:** captures the full diff (all adds, updates, removes since last commit). This is what admins distribute to other admins during the update process.

### zk-STARK Module (via Winterfell)

Implements `Prover` and `Verifier` traits from `covenant-core`.

**AIR circuit proves:** "I know a `MemberLeaf` and a `MerklePath` such that hashing the leaf and walking the path produces the claimed `RootHash`, and the leaf contains the claimed `Handle` (and optionally a claimed `Role`)."

- Proof reveals only `Handle` and optionally `Role`. All other leaf data remains hidden.
- Circuit parameterized by tree depth. Maximum supported depth: 16 (65,536 leaves). Recommended default: 10 (1,024 leaves), sufficient for the proposal's 1,000-member scalability target. Deeper trees increase proving cost linearly with depth.
- Verification is stateless: given a `MembershipProof` and a `RootHash`, anyone can verify.
- **Explicit root hash binding:** proofs are always generated and verified against an explicitly provided `RootHash`. No implicit "current" root.
- **Future work (deferred to Polkadot integration layer):** hard-derivation proofs where the circuit proves "I know an OE private key such that (a) its public key is a valid leaf, and (b) hard-deriving it with a path produces a given child public key." This would require an extended AIR circuit.

### On-Chain Consensus (Out of Scope)

Admin consensus for root hash updates is handled by a **standard proxy multisig** on-chain (the same methodology used for Polkadot DAOs). This is entirely the application's/blockchain layer's responsibility -- `covenant` does not implement threshold signing. The library produces serializable artifacts (`RootUpdateProposal`) that admins verify off-chain, then approve via the on-chain multisig.

The proxy allows the multisig accounts to be updated, meaning admin set changes are a **two-step process**: (1) update the Merkle tree (root hash ceremony), and (2) update the multisig member accounts on-chain. Step 2 is blockchain-specific and outside covenant's scope.

### OESK Generation

The OE Secret Key (OESK) is a **shared group secret key** distributed to all members for OE-wide encryption. It is distinct from `OeKeyPair`, which is a **per-member asymmetric key pair** used for challenge-response authentication.

- `generate_oesk() -> OeSecretKey` -- cryptographically secure random generation.
- `OeSecretKey` zeroizes on drop via `zeroize` crate.
- **Verification:** receiving admins verify the OESK is well-formed by checking correct length for the cipher suite. Ensuring all admins receive the *same* OESK relies on the trust established via pairwise SecureChannel -- a malicious proposer sending different OESKs to different admins would be detected when members report inconsistencies, and the other admins exclude the malicious admin and re-run the ceremony (per the source proposal's documented mitigation).

### Design Constraints

- All secret key types implement `Zeroize` and `ZeroizeOnDrop`.
- `no_std` compatible with `alloc`. WASM-friendly (Winterfell supports WASM, Rescue Prime is pure arithmetic).

## Crate 3: `covenant-channel` (GPL-3.0)

Secure pairwise channels for admin-to-admin and admin-to-member communication. Depends only on `covenant-core`. Implements the Double Ratchet and PQXDH against the published Signal specifications using permissive low-level crypto crates.

### Double Ratchet

- Symmetric-key ratchet (sending/receiving chains) combined with a DH ratchet.
- Each ratchet step produces a unique message key (forward secrecy per message).
- AEAD cipher: ChaCha20-Poly1305 or AES-256-GCM (both WASM-friendly).

### PQXDH (Post-Quantum Extended Diffie-Hellman)

- **Preferred** over X3DH as the key agreement for session initialization.
- Hybrid key agreement: classical X25519 + post-quantum ML-KEM-768 (Kyber768). If either primitive holds, the session is secure.
- Behind a `KeyAgreement` trait so internals can evolve.
- **Disclaimer:** a fully post-quantum Double Ratchet would require replacing the X25519-based ratchet keys with a PQ KEM, but no practical implementation exists. PQXDH is underspecified and will be addressed in its own design doc.

### Session Management

```rust
Session::initiate(our_identity, their_public) -> (Session, InitialMessage)
Session::respond(our_identity, our_bundle, initial) -> Session
session.send(plaintext) -> EncryptedMessage
session.receive(msg) -> Vec<u8>
```

- Serializable for persistence across restarts (application handles encrypted-at-rest storage).
- Handles out-of-order delivery (skipped message key window).

### Pre-Key Bundles

- Members publish pre-key bundles (identity key + signed pre-key + optional one-time pre-keys) for asynchronous session establishment.
- Storage/distribution is the caller's responsibility.

### Boundary

This crate does NOT handle transport, bundle distribution, or session persistence. It encrypts/decrypts and manages ratchet state. Implements `SecureChannel` from `covenant-core`.

### Design Constraints

- `no_std` compatible with `alloc`. WASM-friendly.
- All key material implements `Zeroize` / `ZeroizeOnDrop`.

## Crate 4: `covenant` Facade (GPL-3.0)

High-level ergonomic API for application developers. Composes all three lower crates.

### Bootstrapping

```rust
Oe::bootstrap(config: OeBootstrapConfig) -> Result<(Oe, GenesisArtifact)>
```

Takes initial admin members, threshold `t`, ZKP protocol config, minimum update cadence. Builds the initial Merkle tree, generates the first OESK, and produces a `GenesisArtifact` for on-chain submission. The `GenesisArtifact` contains: the genesis root hash, `OeConfig` (ZKP protocol identifier, threshold `t`, minimum update cadence), and a well-formedness ZKP proving the bootstrapper's admin membership against the genesis root hash (per the proposal). The application is responsible for submitting the `GenesisArtifact` on-chain and setting up the proxy multisig with the initial admin accounts. Returns an `Oe` handle.

### Admin Operations (require `AdminView`)

```rust
// Batch mutations locally
oe.add_member(leaf: MemberLeaf) -> Result<()>
oe.update_member(handle: &Handle, updates: MemberUpdate) -> Result<()>
oe.remove_member(handle: &Handle) -> Result<()>

// Commit all pending mutations into a single delta + new tree
oe.commit() -> Result<(MerkleDelta, RootHash)>

// Discard pending mutations
oe.rollback() -> Result<()>

// Apply delta from another admin (produces candidate for review)
oe.apply_delta(delta: &MerkleDelta) -> Result<CandidateTree>
```

**Root hash update ceremony:**

A single proposing admin drives the ceremony. Security comes from the on-chain proxy multisig: a single admin can propose anything, but the root hash only updates once a threshold of admins approve on-chain.

```rust
// Step 1 - Proposing admin: Prepare proposal.
// Must be called AFTER commit(). Returns Err(NoPendingCommit) if no
// commit has been made since the last finalize/rollback.
// Generates a new OESK.
oe.prepare_root_update(
    current_root: &RootHash,
) -> Result<RootUpdateProposal>
// RootUpdateProposal contains: new_root, MerkleDelta, and new OESK.
// The proposer distributes the full RootUpdateProposal to other
// admins via SecureChannel (pairwise Double Ratchet), then submits
// the new_root to the on-chain proxy multisig for approval.

// Step 2 - Each receiving admin: Verify proposal.
// Independently verifies:
//   - The MerkleDelta is well-formed
//   - The delta is against the current root (not the proposed one),
//     preventing a malicious admin from replacing other admins
//   - The resulting root matches the proposed new_root
//   - The new OESK is well-formed
// If satisfied, the admin approves the new_root on-chain via
// proxy multisig (outside covenant's scope).
oe.verify_proposal(
    proposal: &RootUpdateProposal,
    current_root: &RootHash,
) -> Result<()>

// Step 3 - After on-chain multisig threshold reached: Finalize locally.
// Each admin applies the verified proposal to their local state.
oe.finalize_update(
    proposal: &RootUpdateProposal,
) -> Result<()>
// Updates the local Merkle tree, stores the new OESK, and
// increments the epoch. The on-chain proxy multisig handles
// updating the root hash on the smart contract.
```

After finalization, every admin who received the proposal holds the full OESK (it was distributed as part of the `RootUpdateProposal`). Any admin can then distribute the OESK and Merkle paths to members.

**Admin set changes** are a two-step process, in this order:
1. Update the Merkle tree via the normal ceremony above, approved by the **current** admin set via the **current** multisig.
2. Update the multisig member accounts on-chain via the proxy, also authorized by the **current** (old) admin set.

Step 2 is blockchain-specific and outside covenant's scope. If step 1 completes but step 2 fails, the system is in a degraded but safe state: the old multisig can still operate, and new admins have Merkle tree membership but no multisig authority until step 2 completes.

### Authentication Model

The library uses two authentication mechanisms, chosen based on what the verifier has access to:

- **Challenge-response (admin verifying anyone):** the admin has the full Merkle tree and can look up any member's `OePublicKey` by `Handle`. Verification is: admin sends a random challenge, the member/admin signs it with their OE private key, admin verifies the signature against the stored public key. This is exactly as secure as a ZKP in this context -- both anchor to "this person holds the private key for a public key in the tree committed to by this root hash" -- but the ZKP's privacy property (hiding which leaf) is irrelevant when the admin already knows the handle and has the tree.

- **ZKP (non-admin verifying anyone):** the verifier only has a `RootHash`, not the tree. The prover demonstrates membership (and optionally a role) without revealing other leaf data. Used for: member verifying an admin's role, CU-tier gating, smart contract authorization.

This gives one unified auth mechanism per context rather than two interchangeable routes. Challenge-response is recommended for all admin-facing interactions (onboarding, recovery, OESK updates). Human approval is recommended for onboarding and recovery flows (the admin confirms the handle/identity out-of-band before initiating the protocol).

### Member Onboarding

After a new member is added to the tree and the root hash update completes, the admin distributes the member's initial data. The new member cannot yet produce a ZKP (no `MerklePath`), so authentication uses challenge-response:

1. New member contacts an admin over `SecureChannel`, identifies by `Handle`.
2. Admin looks up `Handle` in current tree, retrieves stored `OePublicKey`.
3. Admin sends random challenge; member signs with OE private key; admin verifies.
4. Admin sends: `MerklePath` + `OESK`.

```rust
// New member receives initial data after being added to the OE
member.onboard(
    admin_channel: &mut impl SecureChannel,
    own_handle: &Handle,
    own_keypair: &OeKeyPair,
) -> Result<MemberView>

// Admin handles the onboarding request
admin.handle_onboard_request(
    channel: &mut impl SecureChannel,
    requester_handle: &Handle,
    current_root: &RootHash,
) -> Result<()>
```

### Admin Recovery and Promotion

An admin who lost all data (except their key pair), or a member newly promoted to admin, needs the full admin state. The flow is identical to member onboarding but with more data transferred:

1. Same challenge-response authentication (admin looks up handle, verifies signature).
2. Admin sends: full Merkle tree + root hash history + OESK.
   (No separate `MerklePath` -- the recipient can derive it from the full tree.)

```rust
// Recovering admin or newly promoted admin receives full state
AdminView::receive_admin_state(
    channel: &mut impl SecureChannel,
    own_handle: &Handle,
    own_keypair: &OeKeyPair,
) -> Result<AdminView>

// Helping admin handles the request
admin.handle_admin_state_request(
    channel: &mut impl SecureChannel,
    requester_handle: &Handle,
    current_root: &RootHash,
) -> Result<()>
// Verifies requester has Admin role in the current tree before sending.
```

### Member Operations (require `MemberView`)

```rust
// Explicit root hash in all proof operations
member.prove_membership(root: &RootHash) -> Result<MembershipProof>
member.prove_role(role: &Role, root: &RootHash) -> Result<MembershipProof>

// OESK request after root hash update.
// The member must have already observed the new root hash on-chain
// (via RootHashObserver or equivalent) before calling this.
// Admin verifies member via challenge-response (admin has tree).
// Member verifies admin via ZKP against new root (member has only root hash).
// On success, admin sends: new OESK + updated MerklePath.
member.request_oesk_update(
    admin_channel: &mut impl SecureChannel,
    known_root: &RootHash,   // member's current (now-old) root hash
    new_root: &RootHash,     // newly observed on-chain root hash
) -> Result<OeskUpdateResult>
// OeskUpdateResult contains: new OeSecretKey + new MerklePath

member.current_epoch() -> Epoch
member.merkle_path() -> &MerklePath
// merkle_path() returns the member's current stored path, which is
// updated as a side effect of request_oesk_update() or onboard().
```

### Root Hash History

```rust
oe.root_hash_history() -> &[(Epoch, RootHash)]
oe.is_known_root(root: &RootHash) -> bool
```

Only the current full tree is kept. Past root hashes are retained for verifying proofs from long-offline members.

### Minimum Update Cadence

`OeConfig` stores the minimum update cadence. This is **informational metadata** -- the library stores it and exposes it, but enforcement is the application's responsibility (the application monitors elapsed time and initiates updates). The library provides:

```rust
oe.config() -> &OeConfig  // includes min_update_cadence
oe.last_update_epoch() -> Epoch
```

### Blockchain Boundary

`covenant` does NOT submit transactions. It produces serializable artifacts (`GenesisArtifact`, `RootUpdateProposal`) that the application uses for on-chain submission via its own chain integration (including proxy multisig approval). The `RootHashObserver` trait is how the application tells `covenant` about on-chain state. `RootHashObserver` is an application-integration boundary; the library's cryptographic operations always take explicit `RootHash` parameters.

### Async

- `async` API for channel-involving operations (OESK distribution, member updates). Uses native async trait methods (stable since Rust 1.75, well within MSRV of 1.81+).
- Pure computation (Merkle ops, ZKP generation) remains synchronous.

### Persistence

- `Oe`, `AdminView`, `MemberView` are serializable.
- `oe.export() -> Result<Vec<u8>>` and `Oe::import(data: &[u8]) -> Result<Oe>` for state persistence.
- Application handles encrypted-at-rest storage.

## Security Invariants

- **Admin authority anchored to current root:** the MerkleDelta in a `RootUpdateProposal` must be against the **current** root hash (not the proposed one), preventing a malicious admin from replacing other admins. Each receiving admin independently verifies this before approving the new root hash on-chain via proxy multisig.
- **Threshold consensus via proxy multisig:** a single admin cannot finalize a root hash update alone. At least `t` admins must independently verify the delta and OESK off-chain, then approve the new root hash on-chain via proxy multisig. The multisig updates the root hash only once the threshold is reached.
- **Threshold validity:** `1 < t <= n` enforced at `OeBootstrapConfig` construction.
- **Admin role gating:** admin operations only available through `AdminView` (type-state pattern).
- **Key zeroization:** all secret key types implement `Zeroize` / `ZeroizeOnDrop`.
- **No leaf enumeration:** `MerkleTree` public API does not expose leaf iteration. `AdminView` required for full access.
- **Proof binding:** `MembershipProof` is always bound to a specific `RootHash`, explicitly provided by the caller.
- **Opaque cryptographic errors:** failures return `InvalidProof` / `VerificationFailed`, never detailed diagnostics.
- **Error messages never leak secret material.**
- **Acceptable risk (threshold loss):** if enough admins lose their keys such that the multisig threshold can no longer be met, root hash updates become impossible. A new OE must be created from scratch.

## Serialization

- All wire types use `serde` with `postcard` (compact, `no_std`, deterministic). Deterministic serialization is critical for Merkle leaf hashing consistency across platforms.
- JSON serialization behind a `json` feature flag for debugging and interop.

## Feature Flags

| Feature | Effect |
|---|---|
| `std` (default) | `std::error::Error` impls, richer diagnostics |
| `alloc` | Heap allocation without `std` |
| `serde` (default) | Serialization support |
| `json` | JSON serialization (debugging/interop) |
| `wasm` | WASM-specific optimizations (e.g. `getrandom/js`) |

## Key Dependencies

| Dependency | Used by | Purpose |
|---|---|---|
| `winterfell` / `winter-crypto` | `covenant-crypto` | zk-STARK proving/verification, Merkle tree base |
| `thiserror` 2.x | all crates | Error type derivation (`no_std`, derive-only) |
| `x25519-dalek` | `covenant-channel` | Classical DH for Double Ratchet |
| `ml-kem` | `covenant-channel` | Post-quantum KEM for hybrid PQXDH |
| `chacha20poly1305` | `covenant-channel` | AEAD encryption for ratchet messages |
| `serde` / `postcard` | all crates | Canonical binary serialization |
| `zeroize` | `covenant-crypto`, `covenant-channel` | Secret key memory safety |

## MSRV

Latest stable Rust at time of development (minimum 1.81 for `thiserror` 2.x `no_std` support).

## Licensing

| Crate | License | Rationale |
|---|---|---|
| `covenant-core` | Apache-2.0 | Types/traits only. Permissive so pallet developers and CU-tier code can depend on it. |
| `covenant-crypto` | GPL-3.0 | Cryptographic implementations. Matches Polkadot client convention. |
| `covenant-channel` | GPL-3.0 | Protocol implementation. Same rationale. |
| `covenant` | GPL-3.0 | Depends on GPL crates, so GPL propagates. |

## Design Decisions Log

| Decision | Choice | Rationale |
|---|---|---|
| Scope | Tier 1 (OE) only | CU tier is a separate concern; OE is independently useful for on-chain activities. |
| Blockchain coupling | Agnostic (trait boundary) | Polkadot specifics layered on later. |
| ZKP system | zk-STARKs first (Winterfell) | Quantum resistance from the start; off-chain so proof size doesn't matter yet. |
| Merkle hash | Rescue Prime (default) | STARK-friendly; dramatically reduces in-circuit proving cost. |
| Merkle tree library | Thin wrapper over `winter-crypto` | Zero new dependencies; hash-aligned with STARK proofs; `no_std`/WASM. |
| Merkle tree mutability | Immutable | Simplifies rollback: discard candidate tree if delta rejected. |
| Admin consensus | On-chain proxy multisig (out of scope) | Same methodology as Polkadot DAOs. Covenant produces artifacts; application handles multisig. Simpler than FROST: no DKG, no signing rounds, no key share management. OESK distributed directly via Double Ratchet. Admin set changes are two-step: update Merkle tree, then update multisig accounts via proxy. |
| Secure channels | Implement from Signal specs | AGPL-3.0 `libsignal` would infect downstream. Implement against open specs with permissive crypto crates. |
| Error handling | `thiserror` 2.x | `no_std`, library-oriented, already in Polkadot SDK workspace. |
| Root hash in proofs | Explicit parameter | No blockchain link yet; avoids implicit state; simplifies old-root proofs. |
| Admin authority | Current root hash for proposals; proxy multisig for finalization | Delta must be against current root (prevents admin from replacing others). On-chain multisig threshold prevents single compromised admin from finalizing. |
| Leaf name field | `display_name: Option<String>` | Changed from proposal's "name and surname" for internationalization (Japanese, Chinese, Portuguese, and other naming conventions don't fit a first/last split). Optional because the `Handle` is the authoritative identifier; some OEs may not require display names. |
| Minimum update cadence | Informational metadata | Library stores and exposes it; application enforces timing. |
| Hard derivation proofs | Deferred to Polkadot integration layer | Requires Polkadot-specific key derivation; circuit extension needed. |
| Async trait implementation | Native async-in-trait (Rust 1.75+) | Avoids `async-trait` crate's boxing overhead; within MSRV. |
| Authentication model | Challenge-response for admin-facing, ZKP for non-admin-facing | When an admin is the verifier they have the full tree, so ZKP's privacy property adds nothing. One mechanism per context avoids unnecessary complexity. |
| Member onboarding | Challenge-response then data transfer | New members can't construct ZKPs (no MerklePath yet). Admin already verified their public key by adding them to the tree. |
| Admin recovery/promotion | Same flow as member onboarding, more data | Unified pattern: challenge-response auth, then transfer data appropriate to role. Admin receives full tree + history + OESK; no separate MerklePath needed (derived from full tree). Admin set changes also require updating multisig accounts on-chain (two-step). |
| PQXDH over X3DH | PQXDH preferred | Post-quantum hybrid key agreement preferred for Double Ratchet session initialization. Fully PQ Double Ratchet not yet practical; PQXDH itself underspecified (separate design doc). |
