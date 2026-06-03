# `spike-keyhive` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Spec:** [`docs/superpowers/specs/2026-05-13-ods-phase-1d-library-qualification-design.md`](../specs/2026-05-13-ods-phase-1d-library-qualification-design.md).
**Inventory:** [`docs/phase-1d/subcrate-inventory.md`](../../phase-1d/subcrate-inventory.md) — `## Keyhive` section.
**Foundation:** [`docs/superpowers/plans/2026-05-13-phase-1d-spike-common-foundation.md`](2026-05-13-phase-1d-spike-common-foundation.md) (already executed; provides `spike-common` and the empty `spike-keyhive` placeholder).
**Companion spike:** [`2026-05-21-spike-p2panda-gates.md`](2026-05-21-spike-p2panda-gates.md) — same six-gate shape; refer to that plan for the proven workflow and gap-matrix conventions.

**Goal:** Exercise the six Phase 1.d substitution gates against Keyhive (`keyhive_crypto`, `beekem`, `keyhive_core` pinned at commit `a2876f3c79d89c9dd0c5e9f84802611c716fe27e`) by filling in the `spike-keyhive` crate with one module per gate, supported by L1 (per sub-crate), L2 (per gate, integrated) and L3 (per scenario) tests. Score each capability into the gap matrix via the `gap-update` binary as gates complete.

**Architecture:** The spike code follows Keyhive's native shapes. Keyhive's `Agent`/`Identifier`/`IndividualId`/`GroupId` types are **concrete newtypes over `ed25519_dalek::VerifyingKey` — not generic in ID** (the opposite of p2panda-auth's `GroupMember<ID>` generic). The spike's central pattern is a **call-site adapter**: every public Keyhive call that takes a principal ID is wrapped to first resolve `MemberId → VerifyingKey` via the `MemberKeyResolver`, then pass the resolved key into the library. A stable `MemberId → VerifyingKey` mapping is maintained for the duration of a single member identity (rotations create a new mapping entry; the adapter then drives a CGKA update). Per-gate `evidence/sN.md` files document the API touchpoints exactly as in `spike-p2panda`.

**Tech Stack:** Rust 2021 edition (MSRV 1.81 from workspace). Cargo git deps on Keyhive commit `a2876f3c79d89c9dd0c5e9f84802611c716fe27e`. Tokio for async (Keyhive's `AsyncSigner` and `Keyhive` top-level type expect a futures-aware runtime; `keyhive_core` already pulls `tokio` + `futures` unconditionally — that's a Gate 0 finding). No new shared abstractions in `spike-common` — that crate is frozen as the contract.

**Review checkpoint:** Per the design's §Priority discovery target, **the gate-1 checkpoint is the most important** stop in this plan. After Task 5 completes (gate 1 L1+L2 + gap-matrix update), the implementor must pause and report findings to the user. Continuation of gates 2–5 depends on what gate 1 reveals about the `Identifier`/`MemberId` adapter feasibility.

**Out of scope:**
- Re-running `spike-p2panda` (already complete).
- The final decision document (hand-written after both spike crates complete all gates).
- The `spike-keyhive` decision document (separate follow-up after this plan).
- The `spike-comparison.html` head-to-head report (separate follow-up after both decision docs).
- Any production hardening of the spike code.

---

## File structure produced by this plan

```
spike-keyhive/
├── Cargo.toml                            [modify — add keyhive deps]
├── src/
│   ├── lib.rs                            [modify — declare modules]
│   ├── adapter.rs                        [NEW] MemberId↔VerifyingKey mapping cache
│   ├── s1_stable_id_acl.rs               [NEW] gate 1
│   ├── s2_membership_intercept.rs        [NEW] gate 2
│   ├── s3_cgka_rotation.rs               [NEW] gate 3
│   ├── s4_org_pseudo_group.rs            [NEW] gate 4
│   ├── s5_p2p_policy.rs                  [NEW] gate 5
│   └── evidence/                         (markdown — included via include_str!)
│       ├── s0_wasm.md
│       ├── s1.md
│       ├── s2.md
│       ├── s3.md
│       ├── s4.md
│       └── s5.md
└── tests/
    ├── l1_keyhive_crypto.rs              [NEW] per-sub-crate L1
    ├── l1_beekem.rs                      [NEW]
    ├── l1_keyhive_core.rs                [NEW]
    ├── l2_g1.rs ... l2_g5.rs             [NEW] per-gate integrated
    ├── l3_revocation.rs                  [NEW] end-to-end scenario
    ├── l3_gating.rs                      [NEW]
    └── l3_org_pseudo_group.rs            [NEW]
```

---

## Task 0: Read the inventory and design before starting

Every implementer subagent dispatched against this plan **must** first:
- Read `docs/phase-1d/subcrate-inventory.md` (especially the `## Keyhive` section).
- Read the relevant `Flow` from §Data flow of the design doc (§Data flow lists Flows A–F2 with which gates they belong to).
- Skim the inventory's "Gate-by-gate first-impressions hypotheses" for their specific gate before writing code, so they can confirm or refute each hypothesis as an L1 outcome.
- Read the corresponding gate in `spike-p2panda/src/evidence/sN.md` to understand the comparison frame. The aim of `spike-keyhive` is not to reproduce p2panda's findings but to record Keyhive's *independently* under the same rubric. Where Keyhive's gap-matrix outcome differs from p2panda's, note it.

This is a discovery exercise, not a code-translation exercise. The L1 sub-crate tests exist to *localise* the substitution: if a hypothesis is wrong, the gap-matrix entry should record the actual finding.

---

## Task 1: Pin Keyhive deps and verify compile

**Files:**
- Modify: `spike-keyhive/Cargo.toml`
- Modify: `spike-keyhive/src/lib.rs`

- [ ] **Step 1: Update `spike-keyhive/Cargo.toml`**

Replace the existing `[dependencies]` section with:

```toml
[dependencies]
spike-common = { path = "../spike-common" }
ed25519-dalek = { version = "2", default-features = false, features = ["alloc"] }

keyhive_crypto = { git = "https://github.com/inkandswitch/keyhive", rev = "a2876f3c79d89c9dd0c5e9f84802611c716fe27e", default-features = false }
beekem         = { git = "https://github.com/inkandswitch/keyhive", rev = "a2876f3c79d89c9dd0c5e9f84802611c716fe27e", default-features = false }
keyhive_core   = { git = "https://github.com/inkandswitch/keyhive", rev = "a2876f3c79d89c9dd0c5e9f84802611c716fe27e" }

tokio = { version = "1", features = ["rt", "rt-multi-thread", "macros", "sync"] }
futures = "0.3"

[dev-dependencies]
serde_json = "1"
```

Note: `spike-keyhive` cannot stay `no_std` because `keyhive_core` pulls `tokio` and `futures` unconditionally. Gate 0 will record that. Remove any `#![cfg_attr(not(feature = "std"), no_std)]` attribute from `spike-keyhive/src/lib.rs` if present and replace it with a comment explaining why.

- [ ] **Step 2: Update `spike-keyhive/src/lib.rs`**

Replace the file contents with:

```rust
//! Phase 1.d qualification spike for the Keyhive local-first stack.
//!
//! Pinned at commit `a2876f3c` (main, 2026-05-22). See
//! [`docs/phase-1d/subcrate-inventory.md`](../../docs/phase-1d/subcrate-inventory.md)
//! for the sub-crate map and pinned dependency block.
//!
//! Not `no_std`: keyhive_core pulls `tokio` + `futures` through
//! unconditional default features. This is recorded as a gate-0
//! finding rather than worked around.

pub mod adapter;
pub mod s1_stable_id_acl;
pub mod s2_membership_intercept;
pub mod s3_cgka_rotation;
pub mod s4_org_pseudo_group;
pub mod s5_p2p_policy;

#[doc = include_str!("evidence/s0_wasm.md")]
pub mod evidence_s0 {}

#[doc = include_str!("evidence/s1.md")]
pub mod evidence_s1 {}

#[doc = include_str!("evidence/s2.md")]
pub mod evidence_s2 {}

#[doc = include_str!("evidence/s3.md")]
pub mod evidence_s3 {}

#[doc = include_str!("evidence/s4.md")]
pub mod evidence_s4 {}

#[doc = include_str!("evidence/s5.md")]
pub mod evidence_s5 {}
```

Create empty stubs for each `sN_*.rs` and `evidence/sN.md` file plus `adapter.rs`:

```rust
// src/adapter.rs
//! MemberId ↔ VerifyingKey mapping cache.
//!
//! Keyhive's `Identifier`, `IndividualId`, and `GroupId` are concrete
//! newtypes over `ed25519_dalek::VerifyingKey`. Stable-ID ACL is
//! implemented as a call-site adapter that resolves `MemberId` →
//! `VerifyingKey` via the `MemberKeyResolver` at every Keyhive API
//! boundary, caching the mapping for the duration of one identity.
//! See `evidence/s1.md`.
```

```rust
// src/sN_xxx.rs (one of five)
//! Gate N substitution. See `evidence/sN.md` for findings.
```

```markdown
<!-- src/evidence/sN.md -->
# Gate N evidence
_To be populated by Task N+1._
```

- [ ] **Step 3: First compile**

```bash
cargo check -p spike-keyhive
```

Expected: success. Cargo fetches the Keyhive git deps (may take a minute on first run). If there are unresolvable version conflicts, **stop and escalate** — that's the pin date being too old or too new, or a transitive-dep collision with `spike-p2panda` in the workspace.

If a workspace-level dep collision arises (e.g., `ed25519-dalek` version mismatch between p2panda and Keyhive), record it as a finding in `evidence/s0_wasm.md` and proceed with whichever pin range resolves; do NOT update spike-common's `Cargo.toml`.

- [ ] **Step 4: Commit**

```bash
git add spike-keyhive/Cargo.toml spike-keyhive/src/
git commit --no-gpg-sign -m "feat(spike-keyhive): pin keyhive deps and scaffold gate modules

Pinned at commit a2876f3c of github.com/inkandswitch/keyhive. Five
gate modules + adapter module + six evidence markdown stubs. Crate
is not no_std because keyhive_core pulls tokio + futures; that's
recorded as a gate-0 finding."
```

---

## Task 2: Gate 0 — WASM / no_std verification

**Goal:** Determine which subset of Keyhive crates compiles to `wasm32-unknown-unknown` under `no_std + alloc + serde` (or close approximation). Per the inventory hypothesis: `keyhive_crypto` and `beekem` *should* compile; `keyhive_core` and `keyhive_wasm` won't (the latter requires the full wasm-bindgen toolchain anyway).

**Files:**
- Modify: `spike-keyhive/src/evidence/s0_wasm.md`
- Modify: `docs/phase-1d/gate-0-results.md` (append a Keyhive section to the existing file from spike-p2panda)

- [ ] **Step 1: Run the WASM build matrix and capture results**

Try compiling subsets in order, recording success/failure for each:

```bash
# Add wasm target if not already
rustup target add wasm32-unknown-unknown

# Try the full crate (expected: fail via keyhive_core)
cargo check -p spike-keyhive --target wasm32-unknown-unknown 2>&1 | tee /tmp/wasm-kh-full.log

# Try keyhive_crypto + beekem alone via a scratch sub-crate or a
# temporary feature flag that excludes keyhive_core from dependencies.
# Document the exact mechanism used.
```

The actual procedure depends on how cleanly individual crates can be isolated. The implementer should record exactly which `cargo check` invocation they ran for each crate subset.

For `keyhive_crypto`:
```bash
cargo new --lib /tmp/kh-crypto-wasm-probe
# Add keyhive_crypto = { git = ..., rev = "a2876f3c...", default-features = false } to deps
cd /tmp/kh-crypto-wasm-probe && cargo check --target wasm32-unknown-unknown
```

Repeat for `beekem` alone. If either fails, capture the dep chain causing the failure (e.g., `chacha20poly1305` defaulting to `std`).

- [ ] **Step 2: Append findings to `docs/phase-1d/gate-0-results.md`**

Add a `## Keyhive` section listing: for each Keyhive sub-crate, the WASM compile result (`success`, `fails-stdlib-dep`, `fails-trait-bound`, etc.) with a snippet of the error if applicable, and which dep chain is blocking.

- [ ] **Step 3: Update `spike-keyhive/src/evidence/s0_wasm.md`**

Summarise the findings in 1–2 paragraphs.

- [ ] **Step 4: Emit gap-matrix entries via `gap-update`**

One entry per Keyhive sub-crate (three entries: `keyhive_crypto`, `beekem`, `keyhive_core`; skip `keyhive_wasm` since it's only relevant if we drive the wasm-bindgen layer). Each entry has:
- `library: "Keyhive"`
- `gate: 0`
- `sub_flow: "A"` (gate 0 has no sub-flows; use A as a placeholder)
- `principal: "NA"`
- `severity`: `"None"` if WASM compiles, `"Soft"` if a clean salvage path exists, `"Hard"` if the crate genuinely cannot be brought to WASM.
- `failing_subcrate`: the crate name itself (e.g. `"keyhive_core"`).
- `fix_path`: `"Fork"` if the issue is a feature-gate that would require an upstream patch (per the fork-locally policy we cannot upstream); `"TraitImpl"` if we'd write a no_std-clean trait impl as a salvage; `"Replace"` otherwise.
- `fix_effort`, `phase3_effort`: implementor's estimate.
- `evidence`: pointer to `docs/phase-1d/gate-0-results.md` and the relevant `cargo check` invocation.
- `notes`: the specific dep chain that blocked compile, e.g. `"tokio + futures (unconditional in keyhive_core)"`.

Pipe each entry as JSON to `cargo run -p spike-common --bin gap-update --features json`.

- [ ] **Step 5: Commit**

```bash
git add spike-keyhive/src/evidence/s0_wasm.md docs/phase-1d/gate-0-results.md docs/phase-1d/gap-matrix.{md,json}
git commit --no-gpg-sign -m "feat(spike-keyhive): gate 0 WASM/no_std verification

Three gap-matrix rows: one per Keyhive sub-crate
(keyhive_crypto, beekem, keyhive_core). See
docs/phase-1d/gate-0-results.md §Keyhive for the per-crate build
matrix output."
```

---

## Task 3: Gate 1 L1 — Stable-ID ACL probe at `keyhive_core` (priority discovery)

**Goal:** Verify whether `keyhive_core::Keyhive::add_member()` and `revoke_member()` can be driven from `MemberId`. The hypothesis is **Hard**: `Identifier`, `IndividualId`, and `GroupId` are concrete newtypes over `VerifyingKey`, not generic; the only viable salvage is a call-site adapter that resolves `MemberId → VerifyingKey` immediately before each call.

**Files:**
- Create: `spike-keyhive/tests/l1_keyhive_core.rs`
- Modify: `spike-keyhive/src/adapter.rs` (the mapping cache)

- [ ] **Step 1: Confirm the Identifier surface at the pin**

Read `keyhive_core/src/principal/identifier.rs`, `keyhive_core/src/principal/agent.rs`, `keyhive_core/src/principal/individual/id.rs`, and `keyhive_core/src/principal/group/id.rs` at the pinned SHA via raw GitHub URLs (e.g., `https://raw.githubusercontent.com/inkandswitch/keyhive/a2876f3c79d89c9dd0c5e9f84802611c716fe27e/keyhive_core/src/principal/identifier.rs`). Capture:
- Is `Identifier` a tuple struct around `ed25519_dalek::VerifyingKey` with public construction (`pub struct Identifier(pub VerifyingKey)`) or private (`pub(crate)`)?
- Same for `IndividualId` and `GroupId`.
- What methods does `Keyhive::add_member` take? Is it `add_member(member: Agent<...>, doc: DocumentId, access: Access)` or different at this pin?

Document the verified signatures in `evidence/s1.md` under "Verified API surface".

- [ ] **Step 2: Implement the mapping cache in `adapter.rs`**

```rust
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use ed25519_dalek::VerifyingKey;
use spike_common::identity::{MemberId, P2pMemberKey};
use spike_common::resolver::MemberKeyResolver;

/// Stable mapping from `MemberId` to the `VerifyingKey` Keyhive needs at
/// every call site. The cache is populated on first lookup and refreshed
/// when the trie reports a rotation (gate 3 will drive that).
#[derive(Clone, Default)]
pub struct IdAdapter {
    mapping: Arc<Mutex<HashMap<MemberId, VerifyingKey>>>,
}

impl IdAdapter {
    pub fn new() -> Self { Self::default() }

    /// Resolve a `MemberId` to its current `VerifyingKey`, populating
    /// the cache if missing. Returns `None` if the resolver doesn't
    /// know the member.
    pub fn resolve<R: MemberKeyResolver>(
        &self,
        resolver: &R,
        id: &MemberId,
    ) -> Option<VerifyingKey> {
        // Implementer: refresh on every call (the cache is for
        // bookkeeping, not authority — the trie is authoritative).
        let key = resolver.p2p_member_key(id)?;
        let vk: VerifyingKey = /* convert P2pMemberKey -> VerifyingKey */;
        let mut m = self.mapping.lock().unwrap();
        m.insert(*id, vk);
        Some(vk)
    }

    /// Invalidate a `MemberId`'s cached key, e.g. after a trie
    /// rotation. The next `resolve` call re-reads from the trie.
    pub fn invalidate(&self, id: &MemberId) {
        self.mapping.lock().unwrap().remove(id);
    }

    /// Reverse lookup — only valid for `MemberId`s already in the cache.
    pub fn member_id_for(&self, vk: &VerifyingKey) -> Option<MemberId> {
        let m = self.mapping.lock().unwrap();
        m.iter().find_map(|(mid, k)| (k == vk).then_some(*mid))
    }
}
```

Add unit tests inline (`#[cfg(test)] mod tests { ... }`) for the basic cache behaviour against a `StubTrie`.

- [ ] **Step 3: Write the L1 test**

Create `tests/l1_keyhive_core.rs` that exercises `keyhive_core` *directly*. The test should:

(a) **Concreteness probe.** Attempt to write a function generic over `ID` that hands `MemberId` into `Keyhive::add_member` — confirm via compile error that the type system rejects this. Capture the rustc error message verbatim into `evidence/s1.md`.

(b) **Adapter-driven addition.** Build a `StubTrie` with alice + bob. Construct a `Keyhive<...>` with default generics (use `tokio::runtime` for the async path). Resolve alice's `MemberId` to a `VerifyingKey` via the adapter. Construct an `Agent::Individual(alice_id, ...)` from the resolved key. Call `Keyhive::add_member(alice_agent, doc_id, Access::Edit)` and verify it succeeds.

(c) **Read-back.** Query the document's membership and verify alice is present.

```rust
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use spike_common::identity::MemberId;
use spike_common::scenarios::revocation_fixture;
use spike_keyhive::adapter::IdAdapter;
// ... keyhive_core imports

#[tokio::test]
async fn keyhive_core_identifier_is_concrete() {
    // Compile-time evidence (the test body confirms the call-site
    // adapter is required; the rustc error from probe (a) goes in
    // evidence/s1.md as a separate text block).
    let f = revocation_fixture();
    let trie = f.bootstrap_stub_trie();
    let adapter = IdAdapter::new();
    let alice_vk = adapter
        .resolve(&trie, &f.alice_member_id())
        .expect("alice in trie");
    // ... build Keyhive, call add_member with alice_vk-derived Agent
}
```

- [ ] **Step 4: Run the test**

```bash
cargo test -p spike-keyhive --test l1_keyhive_core
```

If it passes: gate 1 at the L1 layer is salvageable via call-site adapter — record as `Hard` (the principal type is hardwired) with `fix_path = TraitImpl` (the adapter is a wrapper, not a fork).

If it fails to compile or panics at runtime, capture the failure mode verbatim into `evidence/s1.md`.

- [ ] **Step 5: Update `spike-keyhive/src/evidence/s1.md`**

Document:
- The verified Identifier/IndividualId/GroupId signatures at the pin.
- The rustc error from probe (a) confirming concreteness.
- The adapter shape (link to `adapter.rs`).
- Whether `add_member` succeeded when given a resolver-derived `Agent`.
- Open question: how does Keyhive serialise the member identity inside its delegation log? If `Identifier` is serialised verbatim (as `[u8; 32]` raw key bytes), a `MemberId` rotation invalidates the delegation entry — same friction p2panda has at the spaces layer.

- [ ] **Step 6: Emit gap-matrix entries for gate 1 L1**

One entry:
- `library: "Keyhive"`, `gate: 1`, `sub_flow: "A"`, `principal: "Member"`.
- `failing_subcrate: "keyhive_core"`.
- `severity: "Hard"` (per concreteness).
- `fix_path: "TraitImpl"` (the adapter is implemented in `spike-keyhive/src/adapter.rs`).
- `fix_effort: "Small"` (the adapter is ~30 lines).
- `phase3_effort`: implementor estimate.
- `notes`: cite the rustc error + the adapter file.

- [ ] **Step 7: Commit**

```bash
git add spike-keyhive/src/adapter.rs spike-keyhive/tests/l1_keyhive_core.rs spike-keyhive/src/evidence/s1.md docs/phase-1d/gap-matrix.{md,json}
git commit --no-gpg-sign -m "feat(spike-keyhive): gate 1 L1 — stable-ID ACL via call-site adapter

IdAdapter maps MemberId to VerifyingKey via the StubTrie resolver
on every call. L1 confirms Keyhive's Identifier is concrete (NOT
generic in ID) and verifies the adapter unblocks add_member at the
keyhive_core layer."
```

---

## Task 4: Gate 1 L1 — Stable-ID rotation tracking probe

**Goal:** Verify whether Keyhive's delegation log tracks subsequent key rotations once a member's initial `VerifyingKey` has been written. This is the real test for stable-ID ACL: rotating `alice_id`'s key in the trie should NOT require rewriting the delegation log. If Keyhive serialises the raw `VerifyingKey` into the delegation, the stored ACL is stale after rotation — the same failure mode p2panda exhibits at the spaces layer.

**Files:**
- Modify: `spike-keyhive/tests/l1_keyhive_core.rs` (add a second test)

- [ ] **Step 1: Write the rotation-tracking test**

```rust
#[tokio::test]
async fn keyhive_delegation_does_not_track_trie_rotation() {
    // Setup: alice + bob in trie; doc grants alice via the adapter.
    // Take a snapshot of the delegation log's serialised form (or
    // the agent fetched from the document).
    //
    // Rotate alice's p2p_member_key in the StubTrie.
    //
    // Query the document's effective access for alice:
    //   - If Keyhive re-resolves via the adapter, alice still has access.
    //   - If Keyhive uses a cached VerifyingKey, alice still has access
    //     under her OLD key — but the on-wire encrypted blob is now
    //     encrypted to the wrong key (forward-secrecy concern, gate 3).
    //
    // Record whichever behaviour the library exhibits.
}
```

The test does NOT need to assert a specific outcome; it should *observe* and record the outcome in `evidence/s1.md`. The gap-matrix severity for Flow C (rotation) is set by what was observed.

- [ ] **Step 2: Run and record**

```bash
cargo test -p spike-keyhive --test l1_keyhive_core keyhive_delegation_does_not_track_trie_rotation
```

- [ ] **Step 3: Update `spike-keyhive/src/evidence/s1.md`**

Add an "Rotation tracking" subsection capturing whether the delegation log holds the raw `VerifyingKey` or re-queries the adapter on access checks.

- [ ] **Step 4: Emit a second gap-matrix entry**

A second row for Flow A under Member principal is unnecessary if Task 3's row already covered it. Instead, take the observed rotation behaviour as input to Tasks 5 (L2) and 7 (gate 3); no new row here unless the rotation behaviour reveals a Gate 1 severity escalation beyond what Task 3 recorded.

- [ ] **Step 5: Commit (or fold into Task 5)**

If a code change was made beyond the test, commit it. Otherwise fold this evidence update into Task 5's commit. If committing standalone:

```bash
git add spike-keyhive/tests/l1_keyhive_core.rs spike-keyhive/src/evidence/s1.md
git commit --no-gpg-sign -m "feat(spike-keyhive): gate 1 L1 — rotation-tracking probe

Observes whether Keyhive's delegation log holds raw VerifyingKey
or re-queries the adapter on access checks. Records the behaviour
in evidence/s1.md as input to gate-3 rotation strategy."
```

---

## Task 5: Gate 1 L2 — Integrated stable-ID ACL flow

**Goal:** Run Flow A (Delegation) through the most representative composed path: a doc whose ACL grants `Principal::Member(alice)`, with the spike adapter materialising the key via the resolver at every Keyhive call. This is L2 — using normal Keyhive composition.

**Files:**
- Create: `spike-keyhive/src/s1_stable_id_acl.rs`
- Create: `spike-keyhive/tests/l2_g1.rs`

- [ ] **Step 1: Implement the substitution in `s1_stable_id_acl.rs`**

The module exposes a `MemberAclWrapper<R: MemberKeyResolver>` that:
- Holds an `Arc<Keyhive<...>>` (the underlying Keyhive instance) plus an `IdAdapter`.
- Exposes `grant(principal: Principal, doc: DocumentId, access: KeyhiveAccess)` and `revoke(principal: Principal, doc: DocumentId)` whose signatures accept `spike_common::identity::Principal` rather than `Agent`.
- Internally resolves `Principal::Member(id)` → `Agent::Individual(adapter.resolve(id))` and dispatches to `keyhive.add_member` / `keyhive.revoke_member`.

The wrapper does NOT touch internal Keyhive state directly; it uses only public API.

- [ ] **Step 2: Write the L2 test**

The test:
- Boots a `StubTrie` with alice + bob (each with one device key).
- Creates a Keyhive document via the wrapper.
- Grants `Principal::Member(alice)` and `Principal::Member(bob)` `Access::Edit`.
- Confirms `keyhive.transitive_members(doc_id)` (or equivalent) returns both alice's and bob's `VerifyingKey`s.
- Confirms that the keys returned ARE the current ones in the trie (`adapter.resolve(&trie, &alice_id)`).

- [ ] **Step 3: Run the test**

```bash
cargo test -p spike-keyhive --test l2_g1
```

- [ ] **Step 4: Update `spike-keyhive/src/evidence/s1.md`**

Add an L2 section: what code shape worked, what escape hatches were needed, link to `s1_stable_id_acl.rs`.

- [ ] **Step 5: Emit gap-matrix entries**

Update the existing gate-1 entry (upsert by row key) with the L2 outcome. The L2 outcome is unlikely to downgrade the severity from `Hard` (the concreteness of `Identifier` doesn't change), but the `fix_effort` may be sharpened.

- [ ] **Step 6: Commit**

```bash
git add spike-keyhive/src/s1_stable_id_acl.rs spike-keyhive/tests/l2_g1.rs spike-keyhive/src/evidence/s1.md docs/phase-1d/gap-matrix.{md,json}
git commit --no-gpg-sign -m "feat(spike-keyhive): gate 1 L2 — integrated stable-ID ACL flow

MemberAclWrapper wraps Keyhive so Principal maps to the current
VerifyingKey via the IdAdapter at every grant/revoke call. L2
verifies Flow A end-to-end with two members."
```

---

## **PAUSE: Gate-1 review checkpoint**

At this point, before continuing to gate 2:

- All gate-1 L1 + L2 work is committed.
- The gap matrix has gate-1 rows for `keyhive_core` (Flow A, principal Member).
- Stop and report findings to the user.

The report should include:
- Pass/fail summary for L1 (per sub-crate) and L2 (integrated).
- The severity of any `Hard` rows and the proposed salvage path (call-site adapter is the expected outcome).
- An effort estimate for the salvage (if any), grounded in the L1 friction observed.
- A go/no-go recommendation for the remaining gates: if gate 1 looked unfixable (e.g., serialisation hardwiring beyond what the adapter can handle), gates 2–5 may pivot to a different approach.
- Comparison framing: how does the gate-1 outcome compare to p2panda's? (p2panda: Hard at p2panda-spaces with TraitImpl salvage; expect Keyhive to look similar but with a tighter adapter.)

Do not advance to Task 6 without user confirmation.

---

## Task 6: Gate 2 — Library-native membership-mutation interception

**Goal:** Verify that `keyhive_core::Keyhive::{add_member, revoke_member, generate_group}` mutation entry points can be either disabled or routed through the trie-driven path. Hypothesis: `Soft` via custom `CiphertextStore` / `DelegationStore` impls (the `MembershipListener` is post-fact, so it's an audit seam, not an intercept seam).

**Files:**
- Create: `spike-keyhive/src/s2_membership_intercept.rs`
- Create: `spike-keyhive/tests/l2_g2.rs`
- Modify: `spike-keyhive/src/evidence/s2.md`

- [ ] **Step 1: Identify the mutation entry points in Keyhive**

Read `keyhive_core/src/keyhive.rs` and the membership-related modules. List every public method that mutates ACL state in `evidence/s2.md`:
- `Keyhive::add_member(member, doc, access)`
- `Keyhive::revoke_member(member, doc)`
- `Keyhive::generate_group(...)`
- `Keyhive::generate_doc(...)`
- Any `Agent` / `Document` / `Group` direct mutators that bypass `Keyhive`.

- [ ] **Step 2: L1 probe — `MembershipListener` is post-fact**

Write a small probe (inline in the L2 test file or as a unit test in `s2_membership_intercept.rs`) that implements `MembershipListener` and records the order of events. Trigger `add_member` and confirm that the listener fires *after* the delegation has been persisted in the local store. This confirms the intercept-via-listener path is observability, not blocking.

- [ ] **Step 3: L2 — Custom store-bound `Keyhive`**

Implement a `BlockingCiphertextStore<Inner>` (and `BlockingDelegationStore<Inner>` if the public Keyhive API is generic enough to accept a custom delegation store; if not, document the gap) that wraps the inner Keyhive default store and:
- Has a `mode: Open` flag flipped by trie-resolver code paths.
- When `mode = Closed` (default), refuses to persist writes — returns an error from `store_*` operations.
- When `mode = Open`, delegates to the inner store.

The wrapper around `Keyhive` toggles `mode = Open`, calls `add_member`, then flips back. Any caller that touches `Keyhive::add_member` outside this flow gets a store-level rejection.

Build the L2 test:
- Two `Keyhive` instances backed by the blocking store.
- An "application caller" tries to call `add_member` directly without going through the wrapper. Verify the store rejects the write.
- The wrapper calls `add_member` through the gate. Verify the write succeeds.

- [ ] **Step 4: Update `s2.md` + emit gap-matrix entries**

One row for sub-flow `D` (membership-op interception). Principal: `NA`. Severity: per outcome.

Expected: `Soft`, `fix_path: TraitImpl`, `fix_effort: Small-Medium`.

- [ ] **Step 5: Commit**

```bash
git add spike-keyhive/src/s2_membership_intercept.rs spike-keyhive/tests/l2_g2.rs spike-keyhive/src/evidence/s2.md docs/phase-1d/gap-matrix.{md,json}
git commit --no-gpg-sign -m "feat(spike-keyhive): gate 2 — membership-op interception

BlockingCiphertextStore wraps Keyhive's store and refuses writes
unless the trie-driven wrapper has opened the gate. MembershipListener
is confirmed post-fact (audit only)."
```

---

## Task 7: Gate 3 — CGKA rotation on trie key change

**Goal:** Verify Flows B (CGKA compute) and C (CGKA recompute on rotation) work via `beekem::Cgka::{add, update}` driven by the resolver. Hypothesis: `Soft` with `fix_effort = Medium`. BeeKEM's O(log n) cost is a strong asymptotic advantage; the spike confirms the rotation seam is reachable from a trie-driven path.

**Files:**
- Create: `spike-keyhive/src/s3_cgka_rotation.rs`
- Create: `spike-keyhive/tests/l1_beekem.rs`
- Create: `spike-keyhive/tests/l2_g3.rs`
- Modify: `spike-keyhive/src/evidence/s3.md`

- [ ] **Step 1: L1 — exercise `beekem::Cgka::add` directly**

Build a `Cgka` at the BeeKEM layer with alice as the founder. The constructor at the pin is approximately `Cgka::new(owner_id, owner_pk, signer)` — verify the exact signature at `https://raw.githubusercontent.com/inkandswitch/keyhive/a2876f3c79d89c9dd0c5e9f84802611c716fe27e/beekem/src/cgka.rs`.

Add bob via `cgka.add(bob_id, bob_pk, &signer)`. Verify the op is produced. Apply the op back to a *second* `Cgka` instance representing bob's view (via the public op-application API; verify the method name at the pin).

- [ ] **Step 2: L1 — exercise `beekem::Cgka::update` (rotation)**

Call `cgka.update(new_share_key, &signer)` to rotate the group secret. Verify a new `PcsKey` is generated and that decryption from the *old* `PcsKey` no longer works.

Forward-secrecy invariant: the new group secret cannot be derived from the old one without the rotating member's contribution. This is BeeKEM's guarantee, not the spike's claim.

- [ ] **Step 3: L1 — implement a resolver-driven `force_pcs_update` helper**

Write a function in `s3_cgka_rotation.rs`:

```rust
pub async fn rotate_member_in_doc<R: MemberKeyResolver, F: AsyncSigner<...>>(
    keyhive: &Keyhive<...>,
    adapter: &IdAdapter,
    resolver: &R,
    member: &MemberId,
    doc: DocumentId,
    signer: &F,
) -> Result<(), KeyhiveError> {
    // Invalidate the adapter's cache for this member.
    adapter.invalidate(member);
    // Resolve the new p2p_member_key.
    let new_vk = adapter.resolve(resolver, member)
        .ok_or(KeyhiveError::UnknownMember)?;
    // Drive Keyhive's force_pcs_update equivalent for this doc.
    // (Verify the exact API name at the pin — likely a method on
    //  Document or via Keyhive::force_pcs_update.)
    keyhive.force_pcs_update(doc, signer).await?;
    Ok(())
}
```

- [ ] **Step 4: L2 test — Flow C (recompute on rotation)**

- Set up a 2-member group (alice + bob) in a Keyhive document via the gate-1 wrapper.
- Take a snapshot of the current document's PCS key.
- Rotate alice's `p2p_member_key` in the `StubTrie`.
- Invoke `rotate_member_in_doc(alice, doc)`.
- Verify a fresh PCS key was generated.
- Verify the new secret cannot be derived from alice's old key (forward-secrecy spot-check via BeeKEM's invariant — the test confirms the operation produced a distinct cipher state).

- [ ] **Step 5: Update `s3.md` + emit gap-matrix entries**

Two rows: one for Flow B (`sub_flow = "B"`), one for Flow C (`sub_flow = "C"`). Principal: `"Member"` for both.

Expected: both `Soft`, `fix_path: "TraitImpl"`, `fix_effort: Small-Medium`.

Note the BeeKEM O(log n) advantage in `evidence/s3.md` (vs DCGKA O(n) for p2panda) — this is one of Keyhive's headline differentiators and should be cited explicitly in the eventual comparison report.

- [ ] **Step 6: Commit**

```bash
git add spike-keyhive/src/s3_cgka_rotation.rs spike-keyhive/tests/l1_beekem.rs spike-keyhive/tests/l2_g3.rs spike-keyhive/src/evidence/s3.md docs/phase-1d/gap-matrix.{md,json}
git commit --no-gpg-sign -m "feat(spike-keyhive): gate 3 — CGKA rotation via BeeKEM update

Cgka::add and Cgka::update drive Flow B and C respectively. The
spike's rotate_member_in_doc helper invalidates the adapter cache,
re-resolves via the trie, and calls force_pcs_update. Two gap-matrix
rows recorded."
```

---

## Task 8: Gate 4 — Organisation-as-pseudo-group principal

**Goal:** Verify Flow A and Flow C for `Principal::Org` — exercise the `Agent::Group(GroupId, ...)` first-class variant. Hypothesis: `Soft` overall — the agent model is friendly, but rotation cascade (Flow C) needs a custom listener bridge to drive `force_pcs_update` on every document where the org appears as a member.

**Files:**
- Create: `spike-keyhive/src/s4_org_pseudo_group.rs`
- Create: `spike-keyhive/tests/l2_g4.rs`
- Modify: `spike-keyhive/src/evidence/s4.md`

- [ ] **Step 1: L1 — construct a nested-group ACL at the `keyhive_core` layer**

Build a `Keyhive` instance. Create a group via `keyhive.generate_group(...)`. Add alice and bob as members of that group via `keyhive.add_member` to the group. Then create a document and add the *group's* `Agent::Group(group_id, ...)` as a member of the document with `Access::Edit`.

Verify queries:
- `keyhive.transitive_members(doc_id)` resolves to {alice_vk, bob_vk}.
- Removing alice from the org-group (via `keyhive.revoke_member` against the org-group) updates `transitive_members(doc_id)` to {bob_vk} only.

Capture the API method names verified at the pin in `evidence/s4.md`.

- [ ] **Step 2: L1 — verify org-keyed access via the adapter**

The adapter's `resolve(Principal::Org)` returns a synthetic `org_vk` (the org's stable identity key from `spike_common::identity::OrgKey`). Document the mapping: `MemberId for org = MemberId::ORG_PLACEHOLDER`? Or use a separate `OrgId` from `spike-common`? Check the `spike-common::identity` module for the convention and use whatever's there.

The wrapper from `s4_org_pseudo_group.rs` exposes:
```rust
pub fn grant_org<R: MemberKeyResolver>(
    keyhive: &Keyhive<...>,
    adapter: &IdAdapter,
    resolver: &R,
    org_key: &OrgKey,
    doc: DocumentId,
    access: KeyhiveAccess,
) -> Result<(), KeyhiveError>;
```

- [ ] **Step 3: L2 test — Flow A**

- Create a doc whose ACL grants `Principal::Org` via the wrapper.
- Add alice and bob as members of the org via Keyhive's org-group.
- Verify `transitive_members(doc_id)` returns alice's and bob's current device keys.

- [ ] **Step 4: L2 test — Flow C (rotation cascade)**

- Setup as Flow A.
- Rotate alice's `p2p_member_key` in the StubTrie.
- Trigger the rotation cascade: invalidate the adapter for alice; call `keyhive.force_pcs_update(doc_id, signer)`.
- Verify alice's new key has access to the same doc with no explicit ACL change.

- [ ] **Step 5: L2 test — Flow C (membership change in org)**

- Setup as Flow A.
- Remove alice from the org-group (via `revoke_member` against the org-group).
- Verify alice's key no longer appears in `transitive_members(doc_id)`.
- Verify the doc's CGKA rotated (because forward secrecy requires it when a member leaves).

- [ ] **Step 6: Update `s4.md` + emit gap-matrix entries**

Two rows: `sub_flow = "A"` and `sub_flow = "C"`, principal `"Org"`. Plus a note on the rotation-cascade mechanism (the listener bridge) — record any escape hatches needed (e.g., if the spike has to maintain its own reverse-index from "org → docs that have the org as member").

Expected: both `Soft`, `fix_path: "TraitImpl"`, `fix_effort: Medium`.

This is a likely differentiator vs p2panda, where Gate 4 was `Hard` at the spaces layer. Cite the contrast in `evidence/s4.md`.

- [ ] **Step 7: Commit**

```bash
git add spike-keyhive/src/s4_org_pseudo_group.rs spike-keyhive/tests/l2_g4.rs spike-keyhive/src/evidence/s4.md docs/phase-1d/gap-matrix.{md,json}
git commit --no-gpg-sign -m "feat(spike-keyhive): gate 4 — org-as-pseudo-group via Agent::Group

Agent::Group is first-class; transitive_members resolves nested
groups natively. Rotation cascade driven by adapter invalidation +
force_pcs_update. Two gap-matrix rows for Flow A and Flow C under
the Org principal."
```

---

## Task 9: Gate 5 — P2P connection policy

**Goal:** Verify Flows E1/E2 (session authorise + establish) and F1/F2 (termination on trie change) via `MembershipListener` + a custom transport stub. Hypothesis: `Soft` for both, with the same post-open-window note as p2panda. Keyhive has no published transport crate at this revision, so the spike implements its own minimal session model.

**Files:**
- Create: `spike-keyhive/src/s5_p2p_policy.rs`
- Create: `spike-keyhive/tests/l2_g5.rs`
- Modify: `spike-keyhive/src/evidence/s5.md`

- [ ] **Step 1: Implement a minimal session stub in `s5_p2p_policy.rs`**

Since Keyhive doesn't ship a transport, build the minimum needed to exercise the policy decision points:

```rust
pub struct PolicyManager<R: MemberKeyResolver> {
    resolver: Arc<R>,
    adapter: IdAdapter,
    sessions: Mutex<HashMap<SessionId, SessionRecord>>,
}

pub struct SessionRecord {
    pub peer_vk: VerifyingKey,
    pub member_id: Option<MemberId>,
    pub doc: DocumentId,
    pub state: SessionState, // Open | Flagged
}

impl<R: MemberKeyResolver> PolicyManager<R> {
    /// E1/E2: authorise a session-open attempt from `peer_vk` against doc.
    /// Returns Ok if peer's MemberId is currently authorised; Err otherwise.
    pub fn authorise_session(&self, peer_vk: &VerifyingKey, doc: DocumentId) -> Result<SessionId, PolicyError>;

    /// F1/F2: walk all open sessions and flag those whose peer is no longer
    /// authorised. Called by trie-change observer.
    pub fn recheck_open_sessions(&self) -> usize; // returns count flagged
}
```

The `MembershipListener` impl wired into `Keyhive` fires `recheck_open_sessions()` on every `on_revocation`. This is the spike's "trie-push" equivalent.

- [ ] **Step 2: L1 test — connection accepted for authorised member peer**

Setup: stub trie with alice + bob, both authorised for doc D via the gate-1 wrapper. Call `authorise_session(alice_vk, D)`. Verify Ok + a session record is held.

- [ ] **Step 3: L1 test — connection rejected for unauthorised peer**

Same setup; do NOT authorise charlie. Call `authorise_session(charlie_vk, D)`. Verify Err.

- [ ] **Step 4: L2 test — Flow F1 (termination on trie change)**

Open a session for alice + bob. Revoke alice in the trie. Fire `recheck_open_sessions`. Verify alice's session is flagged; bob's is not.

- [ ] **Step 5: L2 test — Flow E2 + F2 (org-keyed)**

- Setup: doc grants `Principal::Org` (via gate-4's wrapper). alice + bob are org members.
- E2: authorise a session for alice. Verify Ok.
- F2: remove alice from the org. Fire `recheck_open_sessions`. Verify alice's session is flagged.

- [ ] **Step 6: Document the reverse-lookup gap (same as spike-p2panda)**

`PolicyManager` needs to map `peer_vk → MemberId` to check authorisation. The `MemberKeyResolver` trait has no `find_member_by_device(VerifyingKey)` method. The adapter's reverse-lookup helper covers the cached case. Note in `evidence/s5.md` that Phase 3 needs a formal reverse-lookup method on the trie — this is the same gap p2panda recorded, not a Keyhive-specific issue.

- [ ] **Step 7: Update `s5.md` + emit gap-matrix entries**

Four rows: `E1`, `E2`, `F1`, `F2`. Principals: `Member` for E1/F1, `Org` for E2/F2.

Expected: all four `Soft`, `fix_path: "TraitImpl"`, `fix_effort: Small`.

- [ ] **Step 8: Commit**

```bash
git add spike-keyhive/src/s5_p2p_policy.rs spike-keyhive/tests/l2_g5.rs spike-keyhive/src/evidence/s5.md docs/phase-1d/gap-matrix.{md,json}
git commit --no-gpg-sign -m "feat(spike-keyhive): gate 5 — connection policy via custom session stub

PolicyManager + MembershipListener integration. Four gap-matrix rows
(E1/E2/F1/F2). Records the reverse-lookup gap (same as spike-p2panda)
and the in-spike session-stub workaround (no published transport)."
```

---

## Task 10: L3 scenarios — revocation, gating, org_pseudo_group end-to-end

**Goal:** Run the three `ScenarioFixture`s from `spike-common` against the gate-1..5 substitutions in composition.

**Files:**
- Create: `spike-keyhive/tests/l3_revocation.rs`
- Create: `spike-keyhive/tests/l3_gating.rs`
- Create: `spike-keyhive/tests/l3_org_pseudo_group.rs`

- [ ] **Step 1: L3 revocation**

```rust
use spike_common::scenarios::revocation_fixture;

#[tokio::test]
async fn revocation_scenario_end_to_end() {
    let f = revocation_fixture();
    let trie = f.bootstrap_stub_trie();

    // Set up a doc whose ACL grants alice and bob via the gate-1 wrapper.
    // Encrypt a payload before the revocation.
    let pre = /* encrypt under current group secret */;

    // Apply the revocation step.
    let trie = f.apply_to_stub_trie(trie);

    // Trigger CGKA recompute via gate-3's helper.
    /* call rotate_member_in_doc or revoke_member */;

    // Encrypt a new payload after revocation.
    let post = /* encrypt under new group secret */;

    // alice's device decrypts both `pre` and `post`.
    // bob's device decrypts `pre` but NOT `post`.
}
```

If `revoke_member` is the correct call path here (Keyhive's API for removing a member from a doc), use that. Confirm the forward-secrecy invariant via decrypt-attempt failure for bob's post-revoke key on `post`.

- [ ] **Step 2: L3 gating**

Open a session for alice<->bob via gate-5's `PolicyManager`. Apply the gating fixture (revoke bob). Verify the session is flagged within a single `recheck_open_sessions` cycle and a fresh authorise attempt from bob is rejected.

- [ ] **Step 3: L3 org_pseudo_group**

Grant a doc to `Principal::Org` via gate-4's wrapper. Apply the rotation step. Verify alice's new key and bob's key both still have access; verify the doc's PCS key rotated.

- [ ] **Step 4: Emit gap-matrix entries for L3**

For each scenario, one row per (sub-flow, principal) covered. Severity: `None` if scenario passed cleanly, `Soft` if scenario passed via escape hatches, `Hard` if scenario fails outright.

- [ ] **Step 5: Commit**

```bash
git add spike-keyhive/tests/l3_*.rs docs/phase-1d/gap-matrix.{md,json}
git commit --no-gpg-sign -m "feat(spike-keyhive): L3 scenarios end-to-end

Runs revocation, gating, and org_pseudo_group fixtures through the
composed gate-1..5 substitutions. Records the integration-level
gap-matrix rows."
```

---

## Task 11: Final regression sweep and evidence consolidation

**Files:**
- Modify: `spike-keyhive/src/evidence/s{0..5}.md` (final consolidation)
- Modify: `docs/phase-1d/gap-matrix.{md,json}` (final pass)

- [ ] **Step 1: Run the full workspace test suite**

```bash
cargo test --workspace
cargo clippy --workspace --all-features -- -D warnings
cargo clippy --workspace --tests --all-features -- -D warnings
```

Expected: all green. Test count grows by the L1/L2/L3 tests added in spike-keyhive. The p2panda crate's tests must continue to pass — confirm the workspace dep graph hasn't been disrupted by Keyhive's transitive deps.

- [ ] **Step 2: Consolidate evidence files**

Each `evidence/sN.md` should now have:
- Summary of L1 findings.
- Summary of L2 findings.
- Pointer to L3 scenario relevance.
- The final gap-matrix row(s) for that gate, with severities and fix paths.

For `evidence/s0_wasm.md`: ensure the build matrix is recorded.

- [ ] **Step 3: Verify gap-matrix MD/JSON sync**

Manually inspect that every row in `docs/phase-1d/gap-matrix.md` has a matching entry in `docs/phase-1d/gap-matrix.json` (with notes fields populated). The p2panda spike hit a sync gap here; do not repeat it.

- [ ] **Step 4: Update the per-library summary**

The MD file's "Per-library summary" footer should now show concrete numbers for Keyhive (hard, soft, total_burden). Verify the JSON has the matching `library_totals` block.

- [ ] **Step 5: Final commit**

```bash
git add spike-keyhive/src/evidence/ docs/phase-1d/
git commit --no-gpg-sign -m "docs(spike-keyhive): consolidate evidence for all six gates

Each evidence/sN.md now summarises L1+L2+L3 findings and links to
gap-matrix rows. The keyhive per-library decision document is
written in a follow-up step; the head-to-head comparison report
follows after that."
```

---

## Self-review

### Spec coverage

- Gate 0 (Task 2): WASM/no_std verification per sub-crate (keyhive_crypto, beekem, keyhive_core). ✓
- Gate 1 (Tasks 3–5): stable-ID ACL at keyhive_core (concreteness probe, rotation tracking, integrated L2). ✓
- Gate 2 (Task 6): library-native membership-mutation interception via custom store. ✓
- Gate 3 (Task 7): CGKA rotation via BeeKEM `add` / `update`. ✓
- Gate 4 (Task 8): org-as-pseudo-group via `Agent::Group(GroupId, ...)`. ✓
- Gate 5 (Task 9): connection policy via custom session stub + `MembershipListener`. ✓
- L3 scenarios (Task 10): revocation, gating, org_pseudo_group. ✓
- Evidence + gap matrix throughout. ✓
- Gate-1 review checkpoint per the design's §Priority discovery target. ✓

### Placeholder scan

Some task steps say "implementor fills in exact Keyhive types" or "depends on what L1 found". These are NOT placeholders in the writing-plans sense; they reflect the inherent discovery nature of a spike. Each such step is accompanied by enough context (file paths in Keyhive's repo, expected trait/type names, what to capture) that an implementer can proceed without further input. Where the API is fully knowable from the inventory, the plan includes pseudocode.

### Type consistency

- `MemberId`, `Principal`, `P2pMemberKey`, `OrgKey`: used identically to `spike-common`'s definitions throughout.
- `Identifier`, `IndividualId`, `GroupId`, `Agent`, `Keyhive`, `Cgka`, `Access`: used identically to Keyhive's definitions at the pinned SHA.
- Gate numbering (0–5) matches the design and the existing gap-matrix schema.
- Sub-flow labels (A, B, C, D, E1, E2, F1, F2) match `spike-common::report::SubFlow`.

### Scope

The plan covers `spike-keyhive` only. The mandated gate-1 review checkpoint enforces a stop-and-discuss point before committing to gates 2–5. The plan deliberately defers the per-library decision document and the head-to-head comparison (both requiring this spike's complete output plus the already-complete p2panda data) to follow-up artefacts.

---

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-06-01-spike-keyhive-gates.md`.

This plan is executed by `superpowers:subagent-driven-development` per the standard pattern, with one mandatory pause at the gate-1 review checkpoint (after Task 5).
