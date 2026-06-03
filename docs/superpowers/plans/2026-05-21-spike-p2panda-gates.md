# `spike-p2panda` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Spec:** [`docs/superpowers/specs/2026-05-13-ods-phase-1d-library-qualification-design.md`](../specs/2026-05-13-ods-phase-1d-library-qualification-design.md).
**Inventory:** [`docs/phase-1d/subcrate-inventory.md`](../../phase-1d/subcrate-inventory.md) — `## p2panda` section.
**Foundation:** [`docs/superpowers/plans/2026-05-13-phase-1d-spike-common-foundation.md`](2026-05-13-phase-1d-spike-common-foundation.md) (already executed; provides `spike-common` and the empty `spike-p2panda` placeholder).

**Goal:** Exercise the six Phase 1.d substitution gates against p2panda (`p2panda-core`, `-auth`, `-encryption`, `-spaces`, `-net`, `-sync` pinned at commit `41559b0`) by filling in the `spike-p2panda` crate with one module per gate, supported by L1 (per sub-crate), L2 (per gate, integrated) and L3 (per scenario) tests. Score each capability into the gap matrix via the `gap-update` binary as gates complete.

**Architecture:** The spike code follows p2panda's native shapes rather than imposing a uniform adapter. For each gate, the implementor identifies the most surgical hook point (`IdentityRegistry` trait, custom `SpacesStore`, `Manager<T>` wrap, etc.), writes the substitution against the resolver from `spike-common`, then records evidence (passes, gaps, escape hatches) via `gap-update`. Per-gate `evidence/sN.md` files document the API touchpoints.

**Tech Stack:** Rust 2021 edition (MSRV 1.81 from workspace). Cargo git deps on p2panda commit `41559b0dfc2d7d0e9e4fba251ceb7f8094ff8be1`. Tokio for async (p2panda is heavily async). No new shared abstractions in `spike-common` — that crate is already frozen as the contract.

**Review checkpoint:** Per the design's §Priority discovery target, **the gate-1 checkpoint is the most important** stop in this plan. After Task 5 completes (gate 1 L1+L2 + gap-matrix update), the implementor must pause and report findings to the user. Continuation of gates 2–5 depends on what gate 1 reveals about the `ActorId`/`MemberId` substitution feasibility.

**Out of scope:**
- `spike-keyhive` (separate follow-up plan).
- The final decision document (hand-written after both spike crates complete all gates).
- Any production hardening of the spike code.

---

## File structure produced by this plan

```
spike-p2panda/
├── Cargo.toml                            [modify — add p2panda deps]
├── src/
│   ├── lib.rs                            [modify — declare modules]
│   ├── s1_stable_id_acl.rs               [NEW] gate 1
│   ├── s2_membership_intercept.rs        [NEW] gate 2
│   ├── s3_cgka_rotation.rs               [NEW] gate 3
│   ├── s4_org_pseudo_group.rs            [NEW] gate 4
│   ├── s5_p2p_policy.rs                  [NEW] gate 5
│   └── evidence/                         (markdown — included via include_str!)
│       ├── s1.md
│       ├── s2.md
│       ├── s3.md
│       ├── s4.md
│       └── s5.md
└── tests/
    ├── l1_p2panda_core.rs                [NEW] per-sub-crate L1
    ├── l1_p2panda_auth.rs                [NEW]
    ├── l1_p2panda_encryption.rs          [NEW]
    ├── l1_p2panda_spaces.rs              [NEW]
    ├── l1_p2panda_sync.rs                [NEW]
    ├── l2_g0_wasm.rs                     (build-only marker; CI check)
    ├── l2_g1.rs ... l2_g5.rs             [NEW] per-gate integrated
    ├── l3_revocation.rs                  [NEW] end-to-end scenario
    ├── l3_gating.rs                      [NEW]
    └── l3_org_pseudo_group.rs            [NEW]
```

---

## Task 0: Read the inventory and design before starting

Every implementer subagent dispatched against this plan **must** first:
- Read `docs/phase-1d/subcrate-inventory.md` (especially the `## p2panda` section).
- Read the relevant `Flow` from §Data flow of the design doc (§Data flow lists Flows A–F2 with which gates they belong to).
- Skim the inventory's "Gate-by-gate first-impressions hypotheses" for their specific gate before writing code, so they can confirm or refute each hypothesis as an L1 outcome.

This is a discovery exercise, not a code-translation exercise. The L1 sub-crate tests exist to *localise* the substitution: if a hypothesis is wrong, the gap-matrix entry should record the actual finding.

---

## Task 1: Pin p2panda deps and verify compile

**Files:**
- Modify: `spike-p2panda/Cargo.toml`
- Modify: `spike-p2panda/src/lib.rs`

- [ ] **Step 1: Update `spike-p2panda/Cargo.toml`**

Replace the existing `[dependencies]` section with:

```toml
[dependencies]
spike-common = { path = "../spike-common" }
ed25519-dalek = { version = "2", default-features = false, features = ["alloc"] }

p2panda-core       = { git = "https://github.com/p2panda/p2panda", rev = "41559b0dfc2d7d0e9e4fba251ceb7f8094ff8be1", default-features = false }
p2panda-auth       = { git = "https://github.com/p2panda/p2panda", rev = "41559b0dfc2d7d0e9e4fba251ceb7f8094ff8be1", default-features = false, features = ["serde"] }
p2panda-encryption = { git = "https://github.com/p2panda/p2panda", rev = "41559b0dfc2d7d0e9e4fba251ceb7f8094ff8be1", default-features = false, features = ["data_scheme"] }
p2panda-spaces     = { git = "https://github.com/p2panda/p2panda", rev = "41559b0dfc2d7d0e9e4fba251ceb7f8094ff8be1" }
p2panda-net        = { git = "https://github.com/p2panda/p2panda", rev = "41559b0dfc2d7d0e9e4fba251ceb7f8094ff8be1" }
p2panda-sync       = { git = "https://github.com/p2panda/p2panda", rev = "41559b0dfc2d7d0e9e4fba251ceb7f8094ff8be1" }

tokio = { version = "1", features = ["rt", "rt-multi-thread", "macros", "sync"] }

[dev-dependencies]
serde_json = "1"
```

Note: `spike-p2panda` cannot stay `no_std` because p2panda's stack pulls `tokio`. Gate 0 will record that. Remove the `#![cfg_attr(not(feature = "std"), no_std)]` attribute from `spike-p2panda/src/lib.rs` and replace it with a comment explaining why.

- [ ] **Step 2: Update `spike-p2panda/src/lib.rs`**

Replace the file contents with:

```rust
//! Phase 1.d qualification spike for the p2panda local-first stack.
//!
//! Pinned at commit `41559b0` (main, 2026-05-20). See
//! [`docs/phase-1d/subcrate-inventory.md`](../../docs/phase-1d/subcrate-inventory.md)
//! for the sub-crate map and pinned dependency block.
//!
//! Not `no_std`: p2panda pulls `tokio` through the default features of
//! every public crate (`p2panda-spaces`, `p2panda-net`). This is recorded
//! as a gate-0 finding rather than worked around.

pub mod s1_stable_id_acl;
pub mod s2_membership_intercept;
pub mod s3_cgka_rotation;
pub mod s4_org_pseudo_group;
pub mod s5_p2p_policy;

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

Create empty stubs for each `sN_*.rs` and `evidence/sN.md` file:

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
cargo check -p spike-p2panda
```

Expected: success. Cargo fetches the p2panda git deps (may take a minute on first run). If there are unresolvable version conflicts, **stop and escalate** — that's the pin date being too old or too new.

- [ ] **Step 4: Commit**

```bash
git add spike-p2panda/Cargo.toml spike-p2panda/src/
git commit -m "feat(spike-p2panda): pin p2panda deps and scaffold gate modules

Pinned at commit 41559b0 of github.com/p2panda/p2panda. Five gate
modules + five evidence markdown stubs. Crate is not no_std because
p2panda pulls tokio; that's recorded as a gate-0 finding."
```

---

## Task 2: Gate 0 — WASM / no_std verification

**Goal:** Determine which subset of p2panda crates compiles to `wasm32-unknown-unknown` under `no_std + alloc + serde` (or close approximation). Per the inventory hypothesis: `p2panda-encryption` and `p2panda-core` *might* compile; everything else won't.

**Files:**
- Modify: `spike-p2panda/src/evidence/s0_wasm.md` (new — gate 0 has no `sN_*.rs` module)
- Add: `docs/phase-1d/gate-0-results.md` (new — capture the build matrix output)

- [ ] **Step 1: Run the WASM build matrix and capture results**

Try compiling subsets in order, recording success/failure for each:

```bash
# Add wasm target if not already
rustup target add wasm32-unknown-unknown

# Try the full crate (expected: fail)
cargo check -p spike-p2panda --target wasm32-unknown-unknown 2>&1 | tee /tmp/wasm-full.log

# Try a minimal lib that imports only p2panda-core
# (Implementer: create a temporary feature `wasm_min` in spike-p2panda/Cargo.toml
#  that excludes -spaces, -net, -sync, -auth from dependencies; OR create a
#  separate scratch crate. Choose whichever is less invasive; document the choice.)
```

The actual procedure depends on how cleanly individual crates can be isolated. The implementer should record exactly which `cargo check` invocation they ran for each crate subset.

- [ ] **Step 2: Write findings to `docs/phase-1d/gate-0-results.md`**

Capture: for each p2panda sub-crate, the WASM compile result (`success`, `fails-stdlib-dep`, `fails-trait-bound`, etc.) with a snippet of the error if applicable, and which dep chain is blocking.

- [ ] **Step 3: Update `spike-p2panda/src/evidence/s0_wasm.md`**

Summarise the findings in 1–2 paragraphs.

- [ ] **Step 4: Emit gap-matrix entries via `gap-update`**

One entry per p2panda sub-crate (six entries). Each entry has:
- `library: "Panda"`
- `gate: 0`
- `sub_flow: "A"` (gate 0 has no sub-flows; use A as a placeholder)
- `principal: "NA"`
- `severity`: `"None"` if WASM compiles, `"Soft"` if a clean salvage path exists, `"Hard"` if the crate genuinely cannot be brought to WASM.
- `failing_subcrate`: the crate name itself (e.g. `"p2panda-spaces"`).
- `fix_path`: `"UpstreamPR"` if the issue is a one-line `default-features = false` upstream gap; `"TraitImpl"` if we'd write a no_std-clean trait impl as a salvage; `"Fork"` / `"Replace"` otherwise.
- `fix_effort`, `phase3_effort`: implementor's estimate.
- `evidence`: pointer to `docs/phase-1d/gate-0-results.md` and the relevant `cargo check` invocation.
- `notes`: the specific dep chain that blocked compile, e.g. `"tokio (via p2panda-net default features)"`.

Pipe each entry as JSON to `cargo run -p spike-common --bin gap-update --features json`.

- [ ] **Step 5: Commit**

```bash
git add spike-p2panda/src/evidence/s0_wasm.md docs/phase-1d/gate-0-results.md docs/phase-1d/gap-matrix.{md,json}
git commit -m "feat(spike-p2panda): gate 0 WASM/no_std verification

Six gap-matrix rows: one per p2panda sub-crate. See
docs/phase-1d/gate-0-results.md for the per-crate build matrix output."
```

---

## Task 3: Gate 1 L1 — Stable-ID ACL in `p2panda-auth` (priority discovery)

**Goal:** Verify whether `p2panda-auth`'s `GroupMember<ID>` generic can be instantiated with our `MemberId` rather than the library's default `VerifyingKey`. This is the lowest level where stable-ID ACL would live; if it fails here, it definitely fails at the `p2panda-spaces` layer.

**Files:**
- Create: `spike-p2panda/tests/l1_p2panda_auth.rs`

- [ ] **Step 1: Write the L1 test**

Create a test that exercises `p2panda-auth` *directly*, with no use of `p2panda-spaces`. The test should construct a `Group<MemberId, …>` (or whatever the equivalent top-level type is in `p2panda-auth`) using our `MemberId` as the `IdentityHandle`-bound generic, and call `add(adder, added, Access::manage())` followed by a query for `is_member`.

Pseudocode for the test (implementer fills in the exact p2panda-auth types):

```rust
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use spike_common::identity::MemberId;
use p2panda_auth::traits::dgm::{Groups, GroupMembership};
use p2panda_auth::group::GroupMember;
use p2panda_auth::access::Access;
// ... whatever else is needed

// The IdentityHandle bound is `Copy + Debug + PartialEq + Eq + Ord + StdHash`.
// MemberId([u8; 32]) already derives all of these.
// Verify the trait bound is satisfied by trying to use MemberId in place
// of the library's default identity.

#[test]
fn member_id_satisfies_identity_handle() {
    let alice = MemberId([0xa1; 32]);
    let bob = MemberId([0xb1; 32]);

    let group_id = /* construct using MemberId */;
    let mut groups = /* construct Groups impl with MemberId-typed generic */;

    let add_op = groups.add(group_id, alice, bob, Access::manage()).unwrap();
    /* process the op into the group state */;

    assert!(groups.is_member(&group_id, &bob));
}
```

If the type system rejects instantiating the generic with `MemberId`, that fact itself is the result — capture exactly which trait bound failed and where.

- [ ] **Step 2: Run the test**

```bash
cargo test -p spike-p2panda --test l1_p2panda_auth
```

If it compiles and passes: L1 succeeds; gate-1 hypothesis at this layer is `Soft` (Maybe `None` if no escape hatches needed) — note which `IdentityHandle` impl `MemberId` already satisfies.

If it fails to compile: capture the rustc error verbatim. Likely failure modes:
- Some method requires a `Serialize`/`Deserialize` bound that `MemberId` happens to satisfy already (we derive both).
- Some method takes `&self` of a concrete type rather than a generic — that's a `Hard` at this layer.

- [ ] **Step 3: Update `spike-p2panda/src/evidence/s1.md`**

Document:
- Which `p2panda-auth` types/traits were touched.
- Whether `MemberId` satisfied the generic bounds (with `Copy + Debug + PartialEq + Eq + Ord + StdHash`).
- Whether `Group::add` / `Groups::add` accept the generic ID at the call site.
- Any unexpected serialisation surprises.

- [ ] **Step 4: Emit gap-matrix entries for gate 1 L1**

Two entries (one per principal flow exercised — but Flow A "delegation" is principal-conditional, so one for `Member` is enough at L1):
- `library: "Panda"`, `gate: 1`, `sub_flow: "A"`, `principal: "Member"`.

Severity per L1 outcome.

- [ ] **Step 5: Commit**

```bash
git add spike-p2panda/tests/l1_p2panda_auth.rs spike-p2panda/src/evidence/s1.md docs/phase-1d/gap-matrix.{md,json}
git commit -m "feat(spike-p2panda): gate 1 L1 — p2panda-auth stable-ID ACL

Verifies MemberId satisfies the IdentityHandle generic bound and
exercises Groups::add at the p2panda-auth layer. Records L1 finding
in evidence/s1.md and one gap-matrix row."
```

---

## Task 4: Gate 1 L1 — Stable-ID ACL in `p2panda-spaces`

**Goal:** Verify whether `p2panda-spaces::Group::add(member: ActorId, …)` can be invoked with anything other than `ActorId`. This is where the inventory predicts a `Hard`.

**Files:**
- Create: `spike-p2panda/tests/l1_p2panda_spaces.rs`

- [ ] **Step 1: Read the actual `p2panda-spaces` API**

Use `cargo doc -p p2panda-spaces --open` or read the source at `https://github.com/p2panda/p2panda/blob/41559b0/p2panda-spaces/src/group.rs` to confirm the exact signature of `Group::add`. The hypothesis says `Group::add(member: ActorId, access: Access<C>)` — verify this is still the signature at the pinned commit.

- [ ] **Step 2: Write the L1 test that probes for `MemberId` substitution**

Two scenarios:

(a) **Direct substitution attempt.** Construct a `Group<…>` from `p2panda-spaces` and try to pass `MemberId` to `add`. Expected outcome: compile error because the parameter is `ActorId`, not generic.

(b) **`TraitImpl` salvage probe.** Pretend the parameter were `impl Into<ActorId>` or accepted via a custom trait — find a way to *prepare* an `ActorId` from a `MemberId` via the resolver. Implementor writes:

```rust
fn resolve_actor_id(resolver: &impl spike_common::resolver::MemberKeyResolver, id: &MemberId) -> ActorId {
    let key = resolver.p2p_member_key(id).expect("alice in trie");
    // Conversion: ActorId is a newtype over VerifyingKey; key.0 IS a VerifyingKey
    ActorId(key.0)  // Verify exact constructor name — ActorId's inner is pub(crate),
                    // so this likely needs a public constructor or `From<VerifyingKey>`.
}
```

If `ActorId::from(VerifyingKey)` or equivalent isn't public, that itself is a finding.

The test should:
- Build a `StubTrie` with alice + bob.
- Resolve their `ActorId`s via the helper.
- Pass them to `Group::add`.
- Confirm the ACL is built. Then *verify the type-system constraint*: the ACL entries internally store `ActorId`, not `MemberId` — meaning if alice rotates her p2p_member_key, the ACL entry becomes stale. The test should rotate her key in the StubTrie and check that the ACL is now pointing at the OLD key (the substitution failed).

If the failure-to-track-rotation is observable, that's clear evidence the substitution at this layer is `Hard`.

- [ ] **Step 3: Run the test**

```bash
cargo test -p spike-p2panda --test l1_p2panda_spaces
```

- [ ] **Step 4: Update `spike-p2panda/src/evidence/s1.md`**

Add a section to the existing s1.md documenting:
- Whether `ActorId::from(VerifyingKey)` exists or had to be wrapped.
- Confirmation that ACL entries stored at the `p2panda-spaces` layer are `ActorId` (raw key), not stable IDs.
- Whether rotating a member key produces a stale ACL entry (the empirical evidence that gate 1 fails at this layer).

- [ ] **Step 5: Emit gap-matrix entries**

If gate 1 fails at the `p2panda-spaces` layer:
- `library: "Panda"`, `gate: 1`, `sub_flow: "A"`, `principal: "Member"`, `severity: "Hard"`.
- `failing_subcrate: "p2panda-spaces"`.
- `fix_path: "TraitImpl"` (per inventory: salvage by implementing `IdentityRegistry` for the encryption layer and bypassing the spaces ACL serialisation).
- `fix_effort`: estimate from L1 friction.

If it doesn't fail (i.e. spaces silently re-resolves on rotation): `Soft` or `None`. Be precise.

- [ ] **Step 6: Commit**

```bash
git add spike-p2panda/tests/l1_p2panda_spaces.rs spike-p2panda/src/evidence/s1.md docs/phase-1d/gap-matrix.{md,json}
git commit -m "feat(spike-p2panda): gate 1 L1 — p2panda-spaces stable-ID ACL

Probes the ActorId hardwiring at the spaces layer. Records whether
ACL entries track key rotation through the trie or hold stale keys.
Adds gap-matrix row for the spaces failure (if any)."
```

---

## Task 5: Gate 1 L2 — Integrated stable-ID ACL flow

**Goal:** Run Flow A (Delegation) through the most representative composed path: a doc whose ACL grants `Principal::Member(alice)`, with the spike adapter materialising the key via the resolver. This is L2 — using normal p2panda composition.

**Files:**
- Create: `spike-p2panda/src/s1_stable_id_acl.rs`
- Create: `spike-p2panda/tests/l2_g1.rs`

- [ ] **Step 1: Implement the substitution in `s1_stable_id_acl.rs`**

The module exposes:
- A `Principal` -> `ActorId` materialisation helper that takes a `MemberKeyResolver` reference.
- A wrapper around `Manager` or `Space` from `p2panda-spaces` that accepts `spike_common::identity::Principal` instead of `ActorId` and internally materialises via the resolver.

Concrete shape depends on what L1 found. If `ActorId` cannot be reached cleanly, the wrapper writes its own `IdentityRegistry`/`KeyRegistry` and skips `p2panda-spaces` entirely (per the inventory's salvage hypothesis).

- [ ] **Step 2: Write the L2 test**

The test:
- Boots a `StubTrie` with alice + bob (each with one device key).
- Creates a "doc" (space, in p2panda terms) via the wrapper.
- Grants `Principal::Member(alice)` and `Principal::Member(bob)` access.
- Confirms `members()` (or equivalent query) returns both.
- Confirms that the keys materialised in the ACL come *from the resolver*, not from any external pre-computed list — i.e., if the resolver changes alice's key, a subsequent query reflects the new key.

- [ ] **Step 3: Run the test**

```bash
cargo test -p spike-p2panda --test l2_g1
```

- [ ] **Step 4: Update `spike-p2panda/src/evidence/s1.md`**

Add an L2 section: what code shape worked, what escape hatches were needed, link to `s1_stable_id_acl.rs`.

- [ ] **Step 5: Emit gap-matrix entries**

Update the existing gate-1 entries (upsert by row key) with the L2 outcome. If L2 passed via a clean wrapper, severity may downgrade from L1's recorded value.

- [ ] **Step 6: Commit**

```bash
git add spike-p2panda/src/s1_stable_id_acl.rs spike-p2panda/tests/l2_g1.rs spike-p2panda/src/evidence/s1.md docs/phase-1d/gap-matrix.{md,json}
git commit -m "feat(spike-p2panda): gate 1 L2 — integrated stable-ID ACL flow

s1_stable_id_acl wraps p2panda-spaces (or replaces it) so Principal
maps to the current p2p_member_key via the StubTrie resolver. L2
verifies Flow A end-to-end with two members."
```

---

## **PAUSE: Gate-1 review checkpoint**

At this point, before continuing to gate 2:

- All gate-1 L1 + L2 work is committed.
- The gap matrix has gate-1 rows for both `p2panda-auth` and `p2panda-spaces` sub-flows.
- Stop and report findings to the user.

The report should include:
- Pass/fail summary for L1 (per sub-crate) and L2 (integrated).
- The severity of any `Hard` rows and the proposed salvage path.
- An effort estimate for the salvage (if any), grounded in the L1 friction observed.
- A go/no-go recommendation for the remaining gates: if gate 1 looked unfixable, gates 2–5 may pivot to a different approach.

Do not advance to Task 6 without user confirmation.

---

## Task 6: Gate 2 — Library-native membership-mutation interception

**Goal:** Verify that `p2panda-spaces`/`p2panda-auth` mutation entry points (`add_member` / `remove_member` and friends) can be either disabled or routed through the trie-driven path. Hypothesis: `Soft` via custom `SpacesStore + AuthStore` impls.

**Files:**
- Create: `spike-p2panda/src/s2_membership_intercept.rs`
- Create: `spike-p2panda/tests/l1_p2panda_auth_intercept.rs`
- Create: `spike-p2panda/tests/l2_g2.rs`
- Modify: `spike-p2panda/src/evidence/s2.md`

- [ ] **Step 1: Identify the mutation entry points in p2panda**

Read `p2panda-auth/src/traits/dgm.rs` and `p2panda-spaces/src/group.rs`. List every public method that mutates ACL state. The implementer subagent should produce a bullet list in `evidence/s2.md`:
- `Groups::add(group_id, adder, added, access) -> M`
- `Groups::remove(group_id, remover, removed) -> M`
- `Groups::promote(…)`, `Groups::demote(…)`
- `Space::add` / `Space::remove` / `Group::add` / `Group::remove` in spaces

- [ ] **Step 2: L1 test — disabling at the `p2panda-auth` layer**

Try to construct a `Groups` impl that returns an error from `add` (or panics, since we want to detect the call). Verify the impl is reachable via the public trait.

This is the "intercept by trait override" probe: if the trait is `pub` and `add` is overridable, this works. If `Groups` is sealed or its impl is internal, it doesn't.

- [ ] **Step 3: L1 test — disabling at the `p2panda-spaces` layer**

`Space::add` and `Group::add` are concrete methods. They cannot be overridden via trait. The probe: write a custom `SpacesStore + AuthStore + MessageStore` impl that fails / no-ops on writes corresponding to a mutation op. Confirm the failure propagates and blocks the mutation from persisting.

- [ ] **Step 4: L2 test — full intercept flow**

Compose the L1 store wrappers and verify a complete "application code calls `Space::add` → intercepted → returns an error rather than persisting" flow.

- [ ] **Step 5: Update `s2.md` + emit gap-matrix entries**

One row per sub-flow `D` (membership-op interception). Principal: `NA`. Severity: per outcome.

- [ ] **Step 6: Commit**

```bash
git add spike-p2panda/src/s2_membership_intercept.rs spike-p2panda/tests/l1_p2panda_auth_intercept.rs spike-p2panda/tests/l2_g2.rs spike-p2panda/src/evidence/s2.md docs/phase-1d/gap-matrix.{md,json}
git commit -m "feat(spike-p2panda): gate 2 — membership-op interception

Intercepts library-native add/remove at both p2panda-auth (trait
override) and p2panda-spaces (store-wrapper) layers. Records two
gap-matrix rows."
```

---

## Task 7: Gate 3 — (D)CGKA recompute on trie key change

**Goal:** Verify Flows B (CGKA compute) and C (CGKA recompute on rotation) work via `p2panda-encryption`'s `IdentityRegistry` injection. Hypothesis: `Soft` with `fix_effort = Medium`.

**Files:**
- Create: `spike-p2panda/src/s3_cgka_rotation.rs`
- Create: `spike-p2panda/tests/l1_p2panda_encryption.rs`
- Create: `spike-p2panda/tests/l2_g3.rs`
- Modify: `spike-p2panda/src/evidence/s3.md`

- [ ] **Step 1: L1 — implement a resolver-backed `IdentityRegistry`**

Write a struct in `s3_cgka_rotation.rs` that implements `IdentityRegistry<MemberId, Y>` and `PreKeyRegistry<MemberId, LongTermKeyBundle>` from `p2panda-encryption`. Both impls delegate to a `MemberKeyResolver` reference.

`identity_key(y: &Y, id: &MemberId) -> Result<Option<PublicKey>, E>` — call `resolver.p2p_member_key(id)` and convert.

- [ ] **Step 2: L1 test — DCGKA compute over resolved keys**

Test that:
- Build a `Dcgka<MemberId, OperationId, OurPki, …>` with the custom `OurPki`.
- Call `Dcgka::create(…)` with alice as initiator.
- Verify the operation processes successfully and the encryption state is non-empty.

- [ ] **Step 3: L2 test — Flow C (recompute on rotation)**

- Set up a 2-member group (alice + bob) in DCGKA via the resolver-backed registry.
- Take a snapshot of the current group secret.
- Rotate alice's `p2p_member_key` in the `StubTrie`.
- Trigger `Dcgka::update(…)` (or equivalent) with the new key.
- Verify a fresh group secret was generated.
- Verify the new secret cannot be derived from alice's old key.

- [ ] **Step 4: Update `s3.md` + emit gap-matrix entries**

Two rows: one for Flow B (`sub_flow = "B"`), one for Flow C (`sub_flow = "C"`).

- [ ] **Step 5: Commit**

```bash
git add spike-p2panda/src/s3_cgka_rotation.rs spike-p2panda/tests/l1_p2panda_encryption.rs spike-p2panda/tests/l2_g3.rs spike-p2panda/src/evidence/s3.md docs/phase-1d/gap-matrix.{md,json}
git commit -m "feat(spike-p2panda): gate 3 — DCGKA rotation via IdentityRegistry

Resolver-backed IdentityRegistry/PreKeyRegistry implementations.
Verifies CGKA compute (Flow B) and recompute on trie rotation (Flow C).
Two gap-matrix rows recorded."
```

---

## Task 8: Gate 4 — Organisation-as-pseudo-group principal

**Goal:** Verify Flow A and Flow C for `Principal::Org` — exercise the `GroupMember::Group(ID)` variant. Hypothesis: `Soft` at the `p2panda-auth` layer, `Hard` at the `p2panda-spaces` layer.

**Files:**
- Create: `spike-p2panda/src/s4_org_pseudo_group.rs`
- Create: `spike-p2panda/tests/l2_g4.rs`
- Modify: `spike-p2panda/src/evidence/s4.md`

- [ ] **Step 1: L1 — construct a nested-group ACL at the `p2panda-auth` layer**

Build a `Group<MemberId, …>` where one of its members is itself a `GroupMember::Group(org_id)`, with `org_id` representing the organisation. The org group contains alice and bob as `GroupMember::Individual` entries.

Verify queries: `is_member(group_id, alice)` (via nested resolution) returns true.

- [ ] **Step 2: L1 — probe whether `p2panda-spaces` exposes nested groups in `Space::add`**

If `Space::add` only accepts `ActorId` (individual), document that as the failure point. The salvage is to bypass `Space::add` and write ACL entries directly at the `p2panda-auth` layer (a `TraitImpl` of the `AuthStore` that injects `GroupMember::Group(org_id)` entries directly).

- [ ] **Step 3: L2 test — Flow A and C for the org principal**

- Create a doc whose ACL grants `Principal::Org`.
- Verify alice and bob both have access (via nested-group expansion).
- Rotate alice's p2p_member_key.
- Verify alice's new key has access to the same doc, with no explicit ACL change.

- [ ] **Step 4: Update `s4.md` + emit gap-matrix entries**

Rows for `sub_flow = "A"` and `sub_flow = "C"`, principal `"Org"`. Likely two `Hard` rows at the `p2panda-spaces` layer, possibly `Soft` at the `p2panda-auth` layer.

- [ ] **Step 5: Commit**

```bash
git add spike-p2panda/src/s4_org_pseudo_group.rs spike-p2panda/tests/l2_g4.rs spike-p2panda/src/evidence/s4.md docs/phase-1d/gap-matrix.{md,json}
git commit -m "feat(spike-p2panda): gate 4 — org-as-pseudo-group via GroupMember::Group

Builds nested-group ACL at p2panda-auth and verifies org-keyed Flow A
and Flow C. Records spaces-layer Hard rows."
```

---

## Task 9: Gate 5 — P2P connection policy

**Goal:** Verify Flows E1/E2 (session authorise + establish) and F1/F2 (termination on trie change) via `p2panda-sync::Manager` wrapping. Hypothesis: `Soft` for both, with a post-open window note.

**Files:**
- Create: `spike-p2panda/src/s5_p2p_policy.rs`
- Create: `spike-p2panda/tests/l1_p2panda_sync.rs`
- Create: `spike-p2panda/tests/l2_g5.rs`
- Modify: `spike-p2panda/src/evidence/s5.md`

- [ ] **Step 1: L1 — wrap `p2panda-sync::Manager<T>` with a policy check**

Implement a `PolicyManager<M: Manager<T>>` that:
- On `session(config)`: reads `config.remote_peer: VerifyingKey`, looks up the peer's `MemberId` (via reverse lookup — note: this is a *real* concern, since the trie is keyed on `MemberId` not `VerifyingKey`; the spike may need to add a reverse-index helper to `StubTrie` for tests only, OR change the resolver query to "is_authorised(peer_key, principal)").
- Checks whether the peer is currently authorised against the doc/space's ACL via the resolver.
- If authorised: delegates to inner `M::session(config)`.
- If not: returns an error.

The reverse-lookup concern is itself a finding — note it in `evidence/s5.md` and consider adding `MemberKeyResolver::find_member_by_device(...)` if the design intends it. **Don't modify spike-common's trait silently** — that would break the foundation contract. Record the need as a gap.

- [ ] **Step 2: L1 test — connection accepted for authorised peer**

Setup: stub trie with alice + bob, both authorised for doc D. Wrap a fake `Manager<T>` impl that records calls. Open a session with alice's device key as the remote peer. Verify the wrapper called through and the inner manager saw the session config.

- [ ] **Step 3: L1 test — connection rejected for unauthorised peer**

Same setup; revoke alice in the trie; open a session as alice. Verify the wrapper returned an error and the inner manager was NOT called.

- [ ] **Step 4: L2 test — Flow F1 (termination on trie change)**

Open a session as alice (authorised). Watch the wrapper expose a session handle. Revoke alice in the trie and fire a trie-change event. Verify the wrapper called `session_handle.close()` (or equivalent termination API) on the open session.

If the wrapper has no way to *observe* trie changes (the current `StubTrie` is pull-only), document that as a gap — the design's Flow F requires push notification from the trie.

- [ ] **Step 5: L2 test — Flow E2 (org-keyed connection)**

Doc grants `Principal::Org`. Open a session as alice's device (member of org). Verify accepted. Open a session as a non-org peer. Verify rejected.

- [ ] **Step 6: Update `s5.md` + emit gap-matrix entries**

Rows for sub-flows `E1`, `E2`, `F1`, `F2`, each principal-coded.

- [ ] **Step 7: Commit**

```bash
git add spike-p2panda/src/s5_p2p_policy.rs spike-p2panda/tests/l1_p2panda_sync.rs spike-p2panda/tests/l2_g5.rs spike-p2panda/src/evidence/s5.md docs/phase-1d/gap-matrix.{md,json}
git commit -m "feat(spike-p2panda): gate 5 — connection policy via Manager wrap

PolicyManager wraps p2panda-sync::Manager, checking the resolver
before each session. Four gap-matrix rows (E1/E2/F1/F2). Records
the reverse-lookup gap and the trie-push-notification gap."
```

---

## Task 10: L3 scenarios — revocation, gating, org_pseudo_group end-to-end

**Goal:** Run the three `ScenarioFixture`s from `spike-common` against the gate-1..5 substitutions in composition.

**Files:**
- Create: `spike-p2panda/tests/l3_revocation.rs`
- Create: `spike-p2panda/tests/l3_gating.rs`
- Create: `spike-p2panda/tests/l3_org_pseudo_group.rs`

- [ ] **Step 1: L3 revocation**

```rust
use spike_common::scenarios::revocation_fixture;

#[tokio::test]
async fn revocation_scenario_end_to_end() {
    let f = revocation_fixture();
    let trie = f.bootstrap_stub_trie();

    // Set up a doc whose ACL grants alice and bob via spike-p2panda's wrappers.
    // Encrypt a payload before the revocation.
    let pre = /* encrypt under current group secret */;

    // Apply the revocation step.
    let trie = f.apply_to_stub_trie(trie);

    // Trigger CGKA recompute via the trie-change observer.
    /* call into s3_cgka_rotation to refresh */;

    // Encrypt a new payload after revocation.
    let post = /* encrypt under new group secret */;

    // alice's device decrypts both `pre` and `post`.
    // bob's device decrypts `pre` but NOT `post`.
}
```

- [ ] **Step 2: L3 gating**

Open a sync session for alice<->bob. Apply the gating fixture (revoke bob). Verify the session is terminated within the spike's timeout and a fresh attempt from bob is rejected.

- [ ] **Step 3: L3 org_pseudo_group**

Grant a doc to `Principal::Org`. Apply the rotation step. Verify alice's new key and bob's key both still have access.

- [ ] **Step 4: Emit gap-matrix entries for L3**

For each scenario, one row per (sub-flow, principal) covered. Severity: `None` if scenario passed cleanly, `Soft` if scenario passed via escape hatches, `Hard` if scenario fails outright.

- [ ] **Step 5: Commit**

```bash
git add spike-p2panda/tests/l3_*.rs docs/phase-1d/gap-matrix.{md,json}
git commit -m "feat(spike-p2panda): L3 scenarios end-to-end

Runs revocation, gating, and org_pseudo_group fixtures through the
composed gate-1..5 substitutions. Records the integration-level
gap-matrix rows."
```

---

## Task 11: Final regression sweep and evidence consolidation

**Files:**
- Modify: `spike-p2panda/src/evidence/s{1..5}.md` (final consolidation)
- Modify: `docs/phase-1d/gap-matrix.{md,json}` (final pass)

- [ ] **Step 1: Run the full workspace test suite**

```bash
cargo test --workspace
cargo clippy --workspace --all-features -- -D warnings
cargo clippy --workspace --tests --all-features -- -D warnings
```

Expected: all green. Test count grows by the L1/L2/L3 tests added in spike-p2panda.

- [ ] **Step 2: Consolidate evidence files**

Each `evidence/sN.md` should now have:
- Summary of L1 findings.
- Summary of L2 findings.
- Pointer to L3 scenario relevance.
- The final gap-matrix row(s) for that gate, with severities and fix paths.

- [ ] **Step 3: Final commit**

```bash
git add spike-p2panda/src/evidence/ docs/phase-1d/
git commit -m "docs(spike-p2panda): consolidate evidence for all five gates

Each evidence/sN.md now summarises L1+L2+L3 findings and links to
gap-matrix rows. The decision document for Phase 1.d will be drafted
once spike-keyhive completes the same gates."
```

---

## Self-review

### Spec coverage

- Gate 0 (Task 2): WASM/no_std verification per sub-crate. ✓
- Gate 1 (Tasks 3–5): stable-ID ACL at p2panda-auth, then p2panda-spaces, then integrated L2. ✓
- Gate 2 (Task 6): library-native membership-mutation interception. ✓
- Gate 3 (Task 7): DCGKA rotation via IdentityRegistry. ✓
- Gate 4 (Task 8): org-as-pseudo-group via GroupMember::Group. ✓
- Gate 5 (Task 9): connection policy via Manager wrap. ✓
- L3 scenarios (Task 10): revocation, gating, org_pseudo_group. ✓
- Evidence + gap matrix throughout. ✓
- Gate-1 review checkpoint per the design's §Priority discovery target. ✓

### Placeholder scan

Some task steps say "implementor fills in exact p2panda types" or "depends on what L1 found". These are NOT placeholders in the writing-plans sense; they reflect the inherent discovery nature of a spike. Each such step is accompanied by enough context (file paths in p2panda's repo, expected trait/type names, what to capture) that an implementer can proceed without further input. Where the API is fully knowable from the inventory, the plan includes pseudocode.

### Type consistency

- `MemberId`, `Principal`, `P2pMemberKey`, `OrgKey`: used identically to `spike-common`'s definitions throughout.
- `ActorId`, `VerifyingKey`: used identically to p2panda's definitions.
- Gate numbering (0–5) matches the design and the existing gap-matrix schema.
- Sub-flow labels (A, B, C, D, E1, E2, F1, F2) match `spike-common::report::SubFlow`.

### Scope

The plan covers `spike-p2panda` only. The mandated gate-1 review checkpoint enforces a stop-and-discuss point before committing to gates 2–5. The plan deliberately defers the decision document (a hand-written artefact requiring both spikes' data) to a final task that runs after `spike-keyhive` completes its parallel plan.

---

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-05-21-spike-p2panda-gates.md`.

This plan is executed by `superpowers:subagent-driven-development` per the standard pattern, with one mandatory pause at the gate-1 review checkpoint (after Task 5).
