# ODS Phase 1.d — Library qualification decision

**Status:** Final
**Date:** 2026-06-03
**Spike branch:** `worktree-spike-phase-1d`
**Spec:** [`docs/superpowers/specs/2026-05-13-ods-phase-1d-library-qualification-design.md`](../superpowers/specs/2026-05-13-ods-phase-1d-library-qualification-design.md)

This is the consolidated, hand-written decision document for the ODS
Phase 1.d library qualification spike. It supersedes (but does not
replace) the per-library decision drafts
[`spike-keyhive-decision.md`](spike-keyhive-decision.md) and
[`spike-p2panda-decision.md`](spike-p2panda-decision.md), and the
head-to-head [`spike-comparison.html`](spike-comparison.html).

---

## 1. Pick

**Keyhive** (Ink & Switch), pinned at
`a2876f3c79d89c9dd0c5e9f84802611c716fe27e`.

The decisive rubric step is **the hard-blocker count**: Keyhive carries
**1 Hard row** (gate 1, salvaged in-spike via `TraitImpl`); p2panda
carries **5 Hard rows** (gates 0, 1, 2, 4A, 4C — three of which share
a single `pub use` fork in `p2panda-spaces` plus one Large fork of
`p2panda-sync` for WASM).

The override-on-cost annotation confirms the pick: Keyhive's total
burden (22) is lower than p2panda's (32) — a −31 % advantage with
**zero forks required**.

The pick is **conditional**: Phase 3 integration should begin after
Keyhive reaches a tagged `0.1.0` release with at least one external
audit. The spike's pinned alpha (`0.0.0-alpha.3`) is sufficient for
qualification but not for production commitment.

## 2. Disqualifying gaps (p2panda — the not-picked library)

Per the hard-blocker rule (spec §Decision rubric line 260), each `Hard`
row in p2panda's gap matrix is recorded here with its salvage path.
None are showstoppers — every Hard has a bounded fix path — but
together they constitute the reason p2panda lost the rubric.

| Gate | Sub-flow | Failing sub-crate | Cause | Salvage |
|------|----------|-------------------|-------|---------|
| 0 (WASM) | A | `p2panda-sync` | `mio 1.2.0` (std-only I/O poller) reached via `tokio` default features | **Fork** `p2panda-sync`; swap `tokio` for `tokio_with_wasm`. Effort: Large (one-time vendor; per-release re-sync ongoing). |
| 1 (stable-ID ACL) | A | `p2panda-spaces` | `ActorId` is hardwired at the spaces layer; cannot be substituted via type parameter | **TraitImpl** — implement `IdentityRegistry<ActorId, ResolverPki<R>>` and bridge via `materialise_actor_id`. Effort: Small (~40 functional lines). |
| 2 (op interception) | D | `p2panda-spaces` | `AuthGroupState<C>` is in private `mod types`; `AuthStore<C>` cannot be implemented externally (compile error E0603) | **Fork** — add `pub use types::AuthGroupState` to `p2panda-spaces/src/lib.rs`. Effort: Small. |
| 4A (org pseudo-group) | A | `p2panda-spaces` | `Group::add` and `Space::add` accept only `ActorId`, not nested group references; `GroupMember::Group` is the auth-layer escape but the spaces layer doesn't expose it | **Fork** — extend `p2panda-spaces` with `Group::add_nested`. Piggybacks on the gate-2 fork. Effort: Small. |
| 4C (org rotation cascade) | C | `p2panda-spaces` | Same root cause as 4A: spaces-layer `ActorId` hardwiring blocks resolver-driven key updates | **Fork** — resolved by the same `pub use types::AuthGroupState` patch. Effort: Small. |

p2panda's gates 1, 2, 4A and 4C **share a single `pub use` patch** in
`p2panda-spaces/src/lib.rs`. Three of four `Hard` rows are paid for at
once. Only the gate-0 `p2panda-sync` Large fork is independent and
ongoing-maintenance-heavy.

Per the fork-locally policy (memory `project_p2panda_fork_policy`),
upstream PRs are deferred until the spike demonstrates value. If
p2panda becomes the pick in some future re-evaluation, the salvage
plan is documented in §5 below.

## 3. Per-library narrative

### 3.1 Keyhive — substitution shape

**Library shape used.** The spike treats Keyhive as three layered
sub-crates:

- `keyhive_crypto` — primitives (X25519, signing, async signer trait).
- `beekem` — the CGKA tree (`Cgka::add`, `Cgka::update`, `Cgka::remove`).
- `keyhive_core` — principal model, delegation log, document graph,
  `MembershipListener`, `Keyhive::add_member`.

**What worked (positive surprises).**

- **`Agent::Group(GroupId, Arc<Mutex<Group>>)` is a first-class
  variant.** Gate 4 (org-as-pseudo-group) needs no fork — strongest
  single differentiator vs p2panda.
- **`Cgka::add(id, pk, signer)` takes the leaf key directly.** Cleaner
  CGKA substitution seam than p2panda's `IdentityRegistry<ID, Y>`
  trait-thread pattern.
- **`Identifier(pub VerifyingKey)`** has a public field — principal
  construction is direct, no factory boilerplate.
- **`keyhive_core` is WASM-clean.** The Phase 1.d sub-crate inventory
  predicted DEFINITE FAIL on tokio+futures; actual outcome is PASS
  (only the `tokio::sync` slice is reached).
- **`MembershipListener::on_revocation` is a push hook.** Gate 5's
  termination flow is push-based (revocation → listener → recheck);
  p2panda's equivalent is pull-only.
- **BeeKEM is O(log n) per rotation** vs DCGKA's O(n). At ODS scale
  (100–10 000 members) this is 14–700× per rotation, compounding
  under revocation churn.

**What needed work.**

- **Principal-ID concreteness (gate 1, Hard).** `Identifier`,
  `IndividualId`, `GroupId`, `DocumentId` are concrete newtypes over
  `VerifyingKey`; the principal model is not generic in ID. Salvaged
  via the call-site `IdAdapter` (~30 lines, `TraitImpl`).
- **High-level `add_member` requires prekey at add-time (gate 1
  follow-up, resolved architecturally).** Surfaced by the running-code
  milestone: `Keyhive::add_member` needs an `Agent::Individual` whose
  inner `Individual::new` requires a signed `KeyOp`. Resolved by the
  ODS lazy-CGKA design (§3.3 below) — production goes below the
  high-level entry point, never hitting that constraint.
- **MembershipListener is post-fact (gate 2, Soft).** Cannot refuse
  operations. Substitution is containment-via-wrapper (`KeyhiveWrapper`).
- **No published transport (gate 5).** Beelay (Keyhive's planned
  transport) is unpublished at the pin. The spike implements an
  in-process session model.

**Escape hatches taken (each a Phase-3 wiring task).**

1. `IdAdapter` cache for `MemberId ↔ VerifyingKey` reverse-lookup.
2. `KeyhiveWrapper` newtype for containment-via-wrapper interception.
3. In-process `PolicyManager` session model (gate 5).

### 3.2 p2panda — substitution shape (the not-picked alternative)

**Library shape used.** Five sub-crates layered as:

- `p2panda-core` — minimal primitives.
- `p2panda-auth` — `GroupCrdt`, `GroupMember`, the public membership
  CRDT.
- `p2panda-encryption` — `Dcgka`, `KeyRegistry`, `KeyBundle`.
- `p2panda-spaces` — high-level `Manager` over the above. The site of
  most of the Hard rows.
- `p2panda-sync` / `p2panda-net` — transport.

**What worked.**

- **`p2panda-auth` Groups trait is publicly extensible** (gate 2 base
  layer, severity None).
- **`GroupMember::Group` exists at the auth layer** (gate 4A base
  layer, severity None).
- **`IdentityRegistry::identity_key` is a static method** — clean
  ResolverPki escape hatch (gate 1 salvage).
- **`p2panda-encryption` and `p2panda-spaces` are WASM-clean** with
  the consumer-side `getrandom 0.3/wasm_js` pin.

**What didn't.**

- **`ActorId` is hardwired across `p2panda-spaces`** (gates 1, 2, 4A,
  4C — four Hard rows sharing one root cause).
- **`AuthGroupState<C>` is in a private module** — blocks external
  `AuthStore<C>` impls (gate 2).
- **`p2panda-sync` pulls `mio`** via tokio default features — blocks
  WASM (gate 0).
- **Pull-based revocation recheck** (gate 5 F1/F2). Termination is not
  push-driven.

**Escape hatches taken.**

1. `materialise_actor_id` + `ResolverPki<R>` for gate 1.
2. `BlockingGroups<Inner>` wrapper for gate 2 (best-effort; structural
   intercept blocked by private type, deferred runtime).
3. `OrgPseudoGroupAdapter` + `effective_member_keys()` for gate 4.
4. `DocAcl` + `policy_check` + pull-based `recheck_open_sessions` for
   gate 5.

### 3.3 The ODS lazy-CGKA design (cross-cutting)

The single most important spike output beyond the gap matrix is the
**lazy-CGKA / two-tier design commitment** (2026-06-03). It's not a
gate substitution — it's a Phase-3 architectural call surfaced by the
gate-1 running-code milestone.

**The model:**

| Tier | Source of truth | Cadence | Carries |
|------|-----------------|---------|---------|
| ACL  | Trie (on-chain) | Rare — onboarding + rotation/revocation | `(MemberId, VerifyingKey)` |
| CGKA tree | Per-document BeeKEM state | Per-write, per-rotation | x25519 leaf keys (online members only) |

**Why it matters:** both libraries' "add member" convenience APIs
eagerly conflate ACL grant with CGKA placement, which forces the
new member's prekey material on-chain (or into a separate publication
channel) at add-time. The two-tier model descends below those entry
points — `keyhive_core` delegation log + `beekem::Cgka::add` directly
for Keyhive; `GroupCrdt` + `Dcgka::*` directly for p2panda — so the
trie carries only the long-term `VerifyingKey` and CGKA placement
happens when the new member's client comes online.

**Validation:** the L3 lazy-onboarding test
([`spike-keyhive/tests/l3_lazy_onboarding.rs`](../../spike-keyhive/tests/l3_lazy_onboarding.rs))
demonstrates four invariants on first run, no integration finding
surfaced:

1. BeeKEM forward security in the new-member direction
   (pre-onboarding ciphertexts undecryptable by the late-joiner).
2. Post-onboarding decryption works directly.
3. History transfer via re-transmission under the new epoch — bob
   recovers the original pre-onboarding bytes.
4. Alice's view remains consistent across the event.

Full results: [`lazy-cgka-results.md`](lazy-cgka-results.md).

## 4. Risk register for the pick (Keyhive)

Each of Keyhive's 9 `Soft` rows is promoted to a Phase-3 risk with the
gap-matrix `phase3_effort` estimate. None is showstopping.

| # | Gate | Risk | Phase 3 effort | Mitigation |
|---|------|------|----------------|------------|
| R1 | 1 | Delegation log holds raw VerifyingKey; MemberId rotation produces a stale entry without explicit cascade. Lazy-CGKA design (§3.3) reduces but does not eliminate this. | Small | Adapter invalidation + `beekem::Cgka::update` (or `force_pcs_update` at the high level). Trie-change observer wires the cascade. |
| R2 | 2 | Wrapper-as-intercept relies on the wrapper not leaking the inner Keyhive handle. | Small | API hygiene: wrapper is a newtype with a private field; only its trie-driven methods are public. |
| R3 | 3B | `beekem::Cgka::add` requires the caller to derive the leaf key consistently with Keyhive's BeeKEM contract. | Small | Phase 3 documents the derivation. Verified by `l3_lazy_onboarding`. |
| R4 | 3C | Rotation must drive a fresh `PcsKey` per epoch; missing a rotation breaks forward security. | Small | Wired via the trie-change observer; same hook as R1. |
| R5 | 4A | Org-as-pseudo-group cascade requires an org→docs reverse index maintained by spike code. | Small | The wrapper owns the index, populated on every `grant_org` call. |
| R6 | 4C | Same reverse-index as R5, applied to rotation events. Phase 3 effort Medium reflects index-maintenance code paths. | **Medium** | Test coverage in Phase 3 must verify index consistency across concurrent grants + rotations. |
| R7 | 5E1 | Reverse lookup `VerifyingKey → MemberId` only works for cached entries; cold authorisation returns `UnknownPeer`. | Small | Phase 3: add `MemberKeyResolver::find_member_by_device` to `spike-common` (foundation-layer change). |
| R8 | 5E2 | Org-wide P2P policy builds on gate-4 wrapper. No transport-layer post-open window. | Small | Reuse gate-4 reverse-index via wrapper. |
| R9 | 5F1 | Push-based revocation termination via `MembershipListener::on_revocation`. Better than pull, but listener latency is op-propagation-bounded. | Small | Document the propagation-latency envelope; treat sessions as "eventually flagged". |
| R10 | 5F2 | Cascade flow: on org-member change, flag all sessions for all docs where the org has access. | Small | Reuses gate-4 reverse-index (same as R8). |

**Out-of-matrix risks (called out separately):**

| # | Risk | Mitigation |
|---|------|------------|
| R11 | Keyhive is alpha (`0.0.0-alpha.3`); API may break between alphas. | Phase 3 must re-pin to a tagged release before integration; re-run L1 evidence checks against the new pin. |
| R12 | No published transport (Beelay) at the pin. | Phase 3 must either ship a transport bridge or wait for Beelay; the spike's in-process `PolicyManager` stub demonstrates the policy hook works. |
| R13 | The lazy-CGKA design (§3.3) wires below Keyhive's high-level `add_member` API. Phase 3 must validate that `keyhive_core` delegation construction is reachable without materialising an `Individual`. | Spike evidence shows the API surface is reachable; explicit Phase-3 task to validate end-to-end before commitment. |
| R14 | No independent security audit of Keyhive. | Per the conditional pick (§1), Phase 3 begins after at least one external audit completes. |

## 5. Salvage paths for the not-picked library (p2panda)

If a future re-evaluation pivots from Keyhive to p2panda (e.g., Keyhive
fails to mature or an audit surfaces a blocker), the salvage plan
already exists. The plan is documented here so the analysis does not
need to be redone.

**Pre-conditions for a pivot to p2panda:**

- Keyhive fails to ship a tagged `0.1.0` within Phase-3's start
  window.
- OR an external audit of Keyhive surfaces an unfixable architectural
  flaw.
- OR ODS's deployment context shifts in a way that values p2panda's
  maturity over Keyhive's burden advantage.

**Salvage plan (all five Hard rows):**

1. **Gate 0 — fork `p2panda-sync`.** Vendor the crate at the Phase-3
   pin; swap `tokio` for `tokio_with_wasm` in `Cargo.toml`. Estimated
   effort: Large (one-time vendor work; per-release re-sync ongoing).
   Track upstream for a published WASM-compatible fork.
2. **Gates 1, 2, 4A, 4C — single `pub use` patch in `p2panda-spaces`.**
   Add `pub use types::AuthGroupState;` (and possibly
   `pub use auth::AuthMessage;`) to `p2panda-spaces/src/lib.rs`.
   Estimated effort: Small (~5 LOC + a Group::add_nested helper for
   gate 4A).
3. **Per-fork maintenance:** monthly upstream sync, ~half a day per
   release.

**Total p2panda burden** (post-salvage): 32 (as scored). The
post-salvage burden is what the rubric compared against Keyhive's 22,
hence the pick.

The per-library decision draft for the alternative is at
[`spike-p2panda-decision.md`](spike-p2panda-decision.md).

## 6. Gap matrix appendix

The canonical machine-readable matrix is at
[`docs/phase-1d/gap-matrix.json`](gap-matrix.json); the rendered
Markdown is at [`docs/phase-1d/gap-matrix.md`](gap-matrix.md).
Per-library summaries:

- **Keyhive** — hard: 1, soft: 9, total burden: **22**
- **p2panda** — hard: 5, soft: 6, total burden: 32

Burden formula (per spec §"Override-on-cost annotation"):
`total_burden(L) = sum over Soft+Hard rows of L of (phase3_effort + fix_effort)`,
with `Small=1, Medium=3, Large=9`. `None`-severity rows contribute zero.

## 7. Replication instructions

To reproduce the spike's findings from a fresh checkout:

```bash
# Clone, check out the spike branch
git clone https://github.com/Jan-Jan/2-tier-access-control.git
cd 2-tier-access-control
git checkout worktree-spike-phase-1d

# Confirm the pins
grep -E "keyhive_(crypto|core)|beekem" spike-keyhive/Cargo.toml
# Expected: rev = "a2876f3c79d89c9dd0c5e9f84802611c716fe27e"
grep -E "p2panda-(core|auth|encryption|spaces|sync|net)" spike-p2panda/Cargo.toml
# Expected: rev = "41559b0dfc2d7d0e9e4fba251ceb7f8094ff8be1"

# Compile the workspace
cargo build --workspace

# Gate 0 — WASM probes (both libraries)
rustup target add wasm32-unknown-unknown
# See docs/phase-1d/gate-0-results.md for the per-sub-crate probe sequence.

# Spike test suites
cargo test -p spike-common      # 7 tests
cargo test -p spike-keyhive     # 24 tests (18 lib + 2 L2 + 4 L3)
cargo test -p spike-p2panda     # ~70 tests (varies by config)

# Build-matrix
cargo build --workspace
cargo build --workspace --no-default-features
cargo build --workspace --no-default-features --features serde
cargo check --workspace --no-default-features --features serde \
    --target wasm32-unknown-unknown

# Gap matrix regeneration (idempotent — re-renders from the JSON)
cargo run -p spike-common --bin gap-update --features json < /dev/null
# Expected: "wrote 22 rows to docs/phase-1d/gap-matrix.{json,md}"
# Expected per-library summary:
#   Keyhive — hard: 1, soft: 9, total burden: 22
#   Panda   — hard: 5, soft: 6, total burden: 32
```

The spike spans three crates:

- `spike-common/` — foundation contract (Apache-2.0): `MemberKeyResolver`
  trait, scenario fixtures, gap-matrix tooling.
- `spike-keyhive/` — Keyhive evidence (GPL-3.0): 6 gate modules, 24
  tests.
- `spike-p2panda/` — p2panda evidence (GPL-3.0): 6 gate modules,
  ~70 tests.

Substantive narrative reports:

- [`spike-keyhive-decision.md`](spike-keyhive-decision.md) — per-library decision draft.
- [`spike-p2panda-decision.md`](spike-p2panda-decision.md) — per-library decision draft.
- [`spike-comparison.html`](spike-comparison.html) — head-to-head report (HTML).
- [`spike-keyhive-report.html`](spike-keyhive-report.html) / [`spike-p2panda-report.html`](spike-p2panda-report.html) — full per-library findings (HTML).
- [`lazy-cgka-results.md`](lazy-cgka-results.md) — design pivot + L3 outcome summary.
- [`gate-0-results.md`](gate-0-results.md) — WASM probe results.
- [`subcrate-inventory.md`](subcrate-inventory.md) — pre-spike API-evidence inventory.

---

**Decision standing:** Phase 3 of the ODS implementation plan proceeds
on the Keyhive substrate, conditional on the alpha-to-tagged-release
maturity gate (§1). The lazy-CGKA / two-tier design (§3.3) is the
recommended Phase-3 architecture; the spike has demonstrated its
semantics work against the pinned alpha.
