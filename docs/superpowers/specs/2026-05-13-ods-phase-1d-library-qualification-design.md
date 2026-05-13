# ODS Phase 1.d — Local-first library qualification

**Author:** Jan-Jan van der Vyver (<jan-jan@parity.io>)
**Status:** In review
**Created:** 2026-05-13
**Parent design:** [`Organisational Data Sovereignty p1.md`](../../../Organisational%20Data%20Sovereignty%20p1.md), Implementation Plan item 1.iv

## Overview

Phase 1.d selects which local-first library — Keyhive (Ink & Switch) or p2panda — will be substituted into in Phase 3. The decision is grounded in two side-by-side end-to-end spike implementations that exercise the substitutions the ODS design requires, score the friction encountered, and, where a substitution cannot be implemented cleanly, identify which sub-crate would have to be forked, replaced, or trait-implemented around — with an effort estimate per option.

This phase delivers four artefacts:

1. Two Rust spike crates (`spike-keyhive`, `spike-p2panda`) that demonstrate the substitutions in each library's idiomatic shape, retained in the repo as production-quality evidence after the decision.
2. A shared crate (`spike-common`) that defines the contract every spike adheres to: the `MemberKeyResolver` trait, the principal types, the scenario fixtures, the gap matrix schema and renderer.
3. A continuously-updated `docs/phase-1d/gap-matrix.{md,json}` populated by `cargo run --bin gap-update`, scoring each library against twelve capabilities at three levels of test granularity.
4. A hand-written decision document `docs/phase-1d/decision.md` that names the picked library, the disqualifying gaps of the rejected library, and the salvage path for the rejected library so a future audit or pivot has the cost numbers already on the table.

What this phase deliberately does **not** deliver: any actual integration of the picked library into a working ODS stack (that is Phase 3); a browser PWA demo (Phase 2 and 4); the formal model (Phase 1.c); the on-chain component (Phase 1.b); changes to `org-members` (Phase 1.a).

## Scope clarification — three substitutions vs five

The Phase 1.d wording in the parent design names three substitutions to verify:

- **(a)** ACL referencing stable IDs with trie lookup for keys.
- **(b)** X25519 rotation independent of long-term identity.
- **(c)** Interception/resolver for membership-change operations.

These map to spec §Key changes items #1, #4 and #3 respectively. The other two §Key changes items — #2 (organisation-as-pseudo-group) and #5 (peer-to-peer connection policy) — are not explicitly listed in Phase 1.d's text.

Per design discussion on 2026-05-13, scope is expanded: the spike exercises all five substitutions plus a WASM/`no_std` build gate, giving six gates in total. This is recorded here as an explicit scope expansion so the reader understands the spike does more than the spec's three-letter list.

## Architecture

Three new sibling crates in the workspace, on a feature worktree branch `worktree-spike-phase-1d`:

```
2-tier-access-control/
├── org-members/                    [existing — Phase 1.a]
├── on-chain/                       [Phase 1.b — separate work]
├── on-chain-client/                [Phase 1.b — separate work]
├── spike-common/                   [NEW]  Apache-2.0
├── spike-keyhive/                  [NEW]  GPL-3.0
└── spike-p2panda/                  [NEW]  GPL-3.0
```

Dependency graph (no cycles, no dependency on `org-members`):

```
spike-keyhive ─┐
               ├─→ spike-common
spike-p2panda ─┘
```

Neither spike depends on `org-members` directly. The resolver trait in `spike-common` stands in for the trie; the trait surface itself becomes a Phase 3 design input. This isolates spike work from `org-members` evolution and forces the resolver shape to be evaluated on its own merits.

### Build configurations

Both spike crates must compile under, and pass their default-feature tests in, the same three configurations `org-members` already supports:

```
cargo build && cargo test && cargo clippy             # default (std + serde)
cargo check --no-default-features                                          # bare no_std
cargo check --no-default-features --features serde                         # no_std + serde
cargo check --no-default-features --features serde --target wasm32-unknown-unknown
```

The WASM target is **gate 0** — failure here disqualifies the library unless a salvage path can repair it (see §Decision rubric).

Clippy denies the same lints as `org-members`: `clippy::unwrap_used`, `clippy::expect_used`, `clippy::panic`. `unwrap()` is permitted in `tests/` only.

### Six gates

| # | Gate | Maps to parent design | Maps to phase 1.d wording |
|---|---|---|---|
| 0 | WASM/`no_std` compile | `AGENTS.md` hard requirement | — |
| 1 | Stable-ID ACL with trie-lookup resolver | §Key changes #1 | (a) |
| 2 | Library-native membership ops disabled, queries routed | §Key changes #3 | (c) |
| 3 | (D)CGKA / member-as-a-group key rotation driven by trie | §Key changes #4 | (b) |
| 4 | Organisation-as-pseudo-group principal | §Key changes #2 | (scope expansion) |
| 5 | Peer-to-peer connection policy consulting trie | §Key changes #5 | (scope expansion) |

## Components

### `spike-common` (Apache-2.0)

Shared, library-agnostic surface. **No `LibAdapter` trait.** The shared shape is the *contract* with the trie and the *evaluation framework* — never the shape of how each library expresses the substitution. That divergence is the data we collect.

Four modules:

- **`identity`** — `MemberId([u8; 32])`, `P2pMemberKey(ed25519::VerifyingKey)`, `P2pDeviceKey(ed25519::VerifyingKey)`, `OrgKey`, `Epoch`. Same shape as the `org-members` types but defined locally (no cross-crate dependency). PII-free; no handles.

- **`resolver`** — `MemberKeyResolver` trait plus an in-memory `StubTrie` impl backed by `hashbrown::HashMap`. The trait is the spike's contract with the trie:

  ```
  trait MemberKeyResolver {
      fn p2p_member_key(&self, id: &MemberId) -> Result<P2pMemberKey, ResolverError>;
      fn org_key(&self) -> Result<OrgKey, ResolverError>;
      fn current_devices(&self, id: &MemberId) -> Result<Vec<P2pDeviceKey>, ResolverError>;
      fn org_member_ids(&self) -> Vec<MemberId>;
      fn is_member(&self, id: &MemberId) -> bool;
      fn epoch(&self) -> Epoch;
  }
  ```

  `org_member_ids` is required for Flow E2/F2 fan-out (org-pseudo-group p2p auth needs to enumerate the org's current members). `StubTrie` exposes mutators (`stub_revoke`, `stub_rotate_org_key`, `stub_remove_device`, etc.) used only by scenario drivers.

- **`scenarios`** — *specifications*, not parameterized harnesses. Two artefacts per scenario:
  - A markdown spec at `spike-common/scenarios/<name>.md` describing setup, steps, and observable assertions in library-agnostic terms.
  - A `ScenarioFixture` data struct exposed at `spike_common::scenarios::fixtures` that both spikes load. Same inputs, same assertions; the code path through each library is whatever is idiomatic.

  Three fixtures: `REVOCATION_FIXTURE`, `GATING_FIXTURE`, `ORG_PSEUDO_GROUP_FIXTURE`. They use the canonical handle examples from existing `org-members` integration tests (`alice`, `bob`, `jan-jan`) for continuity.

- **`report`** — `GapEntry`, `GapMatrix`, JSON + Markdown renderers, and the `gap-update` binary that walks test output and updates `docs/phase-1d/gap-matrix.{md,json}`.

### `spike-keyhive` (GPL-3.0)

Follows Keyhive's native shapes. Depends on a pinned Keyhive revision (vendored via git rev in `Cargo.toml`; the exact rev is recorded in the decision doc and in `Cargo.lock`).

Module layout:

```
spike-keyhive/
├── src/
│   ├── lib.rs
│   ├── s1_stable_id_acl.rs
│   ├── s2_membership_intercept.rs
│   ├── s3_cgka_rotation.rs
│   ├── s4_org_pseudo_group.rs
│   ├── s5_p2p_policy.rs
│   └── evidence/
│       ├── s1.md
│       ├── s2.md
│       ├── s3.md
│       ├── s4.md
│       └── s5.md
└── tests/
    ├── l1_<subcrate>.rs              one file per sub-crate from the inventory
    ├── l2_g1.rs ... l2_g5.rs         gate 0 has no L2 — it's the CI build matrix
    ├── l3_revocation.rs
    ├── l3_gating.rs
    └── l3_org_pseudo_group.rs
```

Each `evidence/sN.md` documents: which Keyhive primitive was used, the friction encountered, whether disabling/intercepting required a fork patch or trait impl, and the gap-matrix rows it produced.

### `spike-p2panda` (GPL-3.0)

Same module layout as `spike-keyhive`, depending on a pinned p2panda revision (likely the `p2panda-spaces` feature branch — spec §Addendum line 235 notes this is still off `main`). The structural symmetry of the *layout* (not the *code*) is what makes per-gate review easy.

### Escape-hatch convention

If a library's idiomatic shape resists the resolver contract (e.g. async required for a method the trait declares sync, owned vs borrowed key mismatches), the per-spike adapter is allowed to deviate — but only by emitting an explicit `GapEntry` with `escape_hatch = Some(...)`. No silent deviations. The `gap-update` binary fails if any spike module touches a library API marked unstable without a corresponding `GapEntry`.

## Data flow

Every flow is exercised for both **member-as-a-group** (principal = `MemberId`) and **org-as-pseudo-group** (principal = `OrgId`); these are two columns in the capability matrix and scored independently in the gap matrix.

### Flow A — Delegation (gates 1, 4)

Doc/space owner grants an ACL right. The ACL entry stores `Principal::Member(MemberId)` or `Principal::Org(OrgId)`, *not* a raw public key. At use time the library calls `resolver.p2p_member_key(id)` or `resolver.org_key()` to materialise the key.

### Flow B — (D)CGKA computation (gate 3)

The library walks the ACL of the doc/space. For each `Principal` entry, it resolves to a current key via `MemberKeyResolver`, then constructs the (D)CGKA tree from the resolved keys. The library's internal `MemberId → P2pMemberKey` / `OrgId → OrgKey` cache, if any, must be a derived view of the resolver, never authoritative.

### Flow C — (D)CGKA recompute on trie change (gate 3, substitution #4)

A trie change observer notifies the adapter that `P2pMemberKey` for member M rotated, or that `OrgKey` rotated. The adapter triggers the library to recompute (D)CGKA for every doc/space whose ACL references M or the org, producing a new (D)CGKA epoch. Members who lost access in the rotation can no longer derive the new shared key.

### Flow D — Membership-op interception (gate 2)

Application code attempts `library.add_member(...)` / `library.remove_member(...)`. The adapter intercepts. Three possible outcomes recorded in the gap matrix:

- `None` — disabled cleanly via a public extension point or feature flag.
- `Soft` — disabled via fork patch or trait shim; gap entry cites the patch.
- `Hard` — the library exposes no extension point and offers no usable trait; salvage path (see §Decision rubric) records which sub-crate would need to be forked or trait-implemented.

### Flow E1 — Member-as-a-group p2p connection authorise + establish (gate 5)

Peer X requests a sync session for doc/space `D` whose ACL grants member-as-a-group `M`. The conn policy calls `resolver.current_devices(M)`; accepts iff X's `P2pDeviceKey` is in that set. The session is scoped to D; an authorisation for D₁ does not implicitly authorise D₂.

### Flow E2 — Org-as-pseudo-group p2p connection authorise + establish (gate 5)

Peer X requests sync for doc/space `D` whose ACL grants the org-as-pseudo-group. The conn policy calls `resolver.org_member_ids()` then unions `resolver.current_devices(...)` across them. Accepts iff X's `P2pDeviceKey` is in the union. ACL entry is a single `Principal::Org`; the fan-out is the resolver's job.

### Flow F1 — Member-as-a-group p2p connection termination on trie change (gate 5)

Trie change fires. For each open sync session whose doc's ACL references `Principal::Member(M)`, the conn policy re-runs Flow E1's check. Sessions where the remote device is no longer in `current_devices(M)` are dropped via the library's close API. Covers device removal and member off-boarding.

### Flow F2 — Org-as-pseudo-group p2p connection termination on trie change (gate 5)

Trie change fires. For each open sync session whose doc's ACL references `Principal::Org`, the conn policy re-runs Flow E2's check. Drops sessions whose remote device is no longer in the union. Covers org-key rotation (every connection re-evaluates) and individual member departure (only that member's device gets dropped, peers from other members remain).

### Cross-flow invariant

The library never reads or writes `MemberId → P2pMemberKey` / `OrgId → OrgKey` mappings directly. Every key access transits the resolver. Substitutions #1 and #2 are enforced by the type system in `spike-common`: `Principal` is opaque, and only `MemberKeyResolver` can dereference it. A spike that has to bypass this for its library to work has found a `Hard` gap at gate 1 — which we expect to be the most likely failure point (see §Priority discovery target).

## Gap matrix and decision rubric

### Schema

A row per `(library, gate, sub_flow, principal)` tuple, pruned to combinations that apply (e.g. gate 0 WASM has no principal).

| field | type | notes |
|---|---|---|
| `library` | `Keyhive` \| `Panda` | |
| `gate` | `0..5` | 0=WASM, 1=stable-ID ACL, 2=op interception, 3=(D)CGKA, 4=org-pseudo-group, 5=p2p policy |
| `sub_flow` | `A` \| `B` \| `C` \| `D` \| `E1` \| `E2` \| `F1` \| `F2` | flow label from §Data flow |
| `principal` | `Member` \| `Org` \| `NA` | |
| `severity` | `Hard` \| `Soft` \| `None` | `Hard` = needs forking, replacing, or trait-implementing core internals |
| `failing_subcrate` | `Option<CrateId>` | populated from L1 walk for `Hard` and `Soft` rows |
| `fix_path` | `UpstreamPR` \| `TraitImpl` \| `Fork` \| `Replace` \| `None` | see §Salvage paths |
| `fix_effort` | `Small` \| `Medium` \| `Large` \| `XL` | calibrated against `org-members` as `Medium` |
| `phase3_effort` | `Small` \| `Medium` \| `Large` | how much cleanup is in Phase 3 even without forking |
| `evidence` | `Vec<EvidencePointer>` | `crate::module::item` or library `rev:path:line` references |
| `escape_hatch` | `Option<String>` | what the spike did to compensate, if anything |
| `salvage_notes` | `String` | rationale, prior art, dependencies |
| `notes` | `String` | free-form, used in per-library narrative |

### Sub-crate inventory step

Before any gate is run, each spike enumerates its library's sub-crate decomposition and commits it to `docs/phase-1d/subcrate-inventory.md`. Each entry: `crate name @ pinned rev`, role in the library (ACL, CGKA, sync, transport, etc.), public API surface relevant to the gates, and what bigger crate re-exports it. The inventory is the map against which Hard failures get localised. It is populated by the spike — the breakdown is not hard-coded here because both libraries' crate boundaries are still evolving.

### Layered test pyramid

Three levels per gate; a higher-level failure walks down to find the responsible sub-crate.

- **L1 — per sub-crate.** The substitution is exercised against the smallest crate that owns the relevant primitive, with all higher-level crates absent. Tests live as `tests/l1_<subcrate>.rs`, one file per inventory entry. **Dual purpose:** (a) localise where the substitution actually lives, so Hard failures can identify their `failing_subcrate`; (b) sanity-check the test setup — an L1 test that fails for setup reasons (rather than substitution reasons) is immediately visible because no other crate is in the picture.
- **L2 — per gate, integrated.** The substitution exercised through the library's normal composition. Tests live as `tests/l2_g<N>.rs`. Gate 0 (WASM) has no L2 (it's a build-target check).
- **L3 — per scenario.** Revocation / gating / org-pseudo-group end-to-end, each loading a `ScenarioFixture` and asserting the spec's observables. Tests live as `tests/l3_<scenario>.rs`.

A capability is *covered* only if it passes at L1, L2, and L3 where applicable. A capability that passes at L2 but fails at L1 indicates either a setup problem or that the L1 sub-crate boundary was drawn wrong — both are themselves recorded as gap-matrix entries (severity `Soft`, notes explaining which).

### Capability matrix

Twelve capabilities per library. Member and org columns score independently.

| # | Capability | Principal | Exercised by |
|---|---|---|---|
| C0 | Compile to `wasm32-unknown-unknown` under `--no-default-features --features serde` | N/A | gate 0 |
| C1 | Delegate doc/space ACL right to principal | Member | Flow A, gate 1 |
| C2 | Delegate doc/space ACL right to principal | Org | Flow A, gates 1+4 |
| C3 | Compute (D)CGKA correctly with key materialised via resolver | Member | Flow B, gate 3 |
| C4 | Compute (D)CGKA correctly with key materialised via resolver | Org | Flow B, gates 3+4 |
| C5 | Trigger (D)CGKA recompute when trie key for principal rotates | Member | Flow C, gate 3 |
| C6 | Trigger (D)CGKA recompute when trie key for principal rotates | Org | Flow C, gates 3+4 |
| C7 | Authorise + establish p2p sync session against doc/space ACL | Member | Flow E1, gate 5 |
| C8 | Authorise + establish p2p sync session against doc/space ACL | Org | Flow E2, gates 4+5 |
| C9 | Terminate open p2p sync session when trie change revokes authorisation | Member | Flow F1, gate 5 |
| C10 | Terminate open p2p sync session when trie change revokes authorisation | Org | Flow F2, gates 4+5 |
| C11 | Library-native membership-mutation ops are unreachable | N/A | gate 2 |

### Priority discovery target

**C1 and C2 are the highest-risk-of-failure capabilities.** The stable-ID ACL substitution is the deepest decoupling the design asks of either library: both Keyhive and p2panda are built around raw-public-key-as-principal, and replacing that with a stable `MemberId` is exactly what the parent design's §Key changes #1 calls "a significant change to key rotation".

Concretely: the gate-1 review checkpoint (after L1+L2 runs on both libraries) is the most important checkpoint in the lockstep loop. If C1 or C2 fail Hard for either library, the salvage discussion happens *there*, before the spike advances to gate 2, so that the workaround (most likely a `TraitImpl` candidate) can be discussed with empirical data on the table rather than after a multi-week spike is complete.

### Hard-blocker rule (primary rubric)

A gate row scored `Hard` *for any single sub-flow* disqualifies its library as the primary recommendation. The decision document still picks one library — the rubric is hard-blocker, not "no library can ship". The disqualified library is moved to second-tier and accompanied by its salvage path so a future audit or pivot has the numbers already.

The `Hard` severity has a precise three-part meaning, recorded as a checklist in each `Hard` row's `notes`:

1. The library's relevant primitive (ACL/CGKA/group/conn-policy type) is private or sealed against the extension point needed, AND
2. No public trait, callback, or feature flag exposes equivalent behaviour, AND
3. The maintainers have not signalled openness to a patch on the upstream tracker (cite issue/PR).

All three must hold. If (3) fails — maintainers are amenable — the gap is `Soft` with `fix_path = UpstreamPR`, not `Hard`.

### Salvage paths

Every `Hard` (and, where useful, `Soft`) row carries a fix-path recommendation. Preference order, best to worst:

| variant | meaning | preferred when |
|---|---|---|
| `UpstreamPR` | Maintainers will accept a patch; cite issue/PR. | Best case: zero fork burden. |
| `TraitImpl` | The failing sub-crate exposes the relevant behaviour behind a *public trait*; we ship our own crate implementing that trait, and the rest of the library composes against the trait unchanged. We own the impl, not a patched copy of their code. | Best fallback when `UpstreamPR` is unavailable. No upstream merge burden, library's public surface unchanged, often `Small` effort. May let us reuse `org-members` types directly inside the impl. |
| `Fork` | Vendor + patch the existing crate. We own a divergent copy of their code, and carry the upstream merge burden until/unless the patch is upstreamed. | When no usable trait exists at the failure point and the failure is a small surgical change. |
| `Replace` | Write our own crate from scratch. | When no usable trait exists *and* the failure is deep. Highest effort. |

When L1 localises a Hard failure, the spike must run one extra discovery step before recording `fix_path`: **does the failing sub-crate expose the relevant behaviour behind a public trait?** If yes, `fix_path = TraitImpl` with `salvage_notes` citing the trait name and rough surface area. If no, fall through to `Fork` / `Replace`. The discovery step is itself logged in `salvage_notes` so the audit trail shows the search was performed.

Effort cap for `TraitImpl`: default `Small` or `Medium`, never `Large` or `XL`. If the trait surface is so large that the impl approaches `org-members` in size, reclassify as `Replace` and update `fix_effort` accordingly.

### Tie-break ladder (both libraries pass with zero `Hard`)

Applied in strict order; first step that differentiates picks the winner. The deciding step is cited in the decision document.

- **Step 1 — Soft count.** Fewer soft gaps wins.
- **Step 2 — Aggregate phase3_effort.** Super-linear sum (`Small=1, Medium=3, Large=9`) over all `Soft` rows. Lower wins. Penalises one big gap more than several small ones.
- **Step 3 — Audit and maturity.** Per parent design §Addendum line 235: `p2panda-encryption` has an audit scheduled with Radically Open Security; Keyhive does not. Audited surface area wins.
- **Step 4 — CGKA scaling (informational only).** Keyhive's BeeKEM is O(log n) per data object; p2panda-encryption is O(n) (§Addendum line 238). Favours Keyhive at organisational scale beyond ~1k members, *unless* org-as-pseudo-group delegation keeps n small in practice. Reported but does not decide unless the spike produced a benchmark.
- **Step 5 — Escalate to user.** If steps 1–4 fail to differentiate, halt and present both options with full narrative.

### Override-on-cost annotation (separate from the ladder)

The hard-blocker rule decides the **primary** recommendation deterministically. But where one library is "clean" (zero `Hard`) and the other has only one or two `Hard` rows whose `fix_path` is cheap (`UpstreamPR` or `Small`-effort `TraitImpl`), the picked library may actually carry more *total* Phase 3 work than the disqualified library would after salvage. The decision document captures this in its executive summary using a total-burden number:

`total_burden(L) = sum over Soft+Hard rows of L of (phase3_effort + fix_effort)` (with the same `Small=1, Medium=3, Large=9` weighting).

If `total_burden(rejected) < total_burden(picked)`, the executive summary flags the override option explicitly and invites the user to decide. The hard-blocker rule still binds the *spike's* recommendation, but the annotation ensures the user is not surprised by the cost asymmetry.

### Decision document structure

`docs/phase-1d/decision.md`, **hand-written**, seven sections:

1. **Pick** — one paragraph. The chosen library, the rubric step that decided (hard-blocker rule, or tie-break step N), pinned revision.
2. **Disqualifying gaps** — the `Hard` rows from the matrix for the rejected library, or "none" if both passed.
3. **Per-library narrative** — Keyhive and p2panda each get a section: substitution shape used, what worked, what didn't, escape hatches taken.
4. **Risk register for the pick** — every `Soft` row for the chosen library promotes to a risk item with the `phase3_effort` estimate. This is the handoff to Phase 3.
5. **Salvage paths for the not-picked library** — the full fork/replace/`TraitImpl` plan from its `Hard` and significant `Soft` rows: which sub-crate, fix path, effort. So if Phase 3 reconsiders, or a later audit finds a problem in the picked library, the analysis is already done.
6. **Gap matrix appendix** — the auto-rendered `gap-matrix.md` inlined.
7. **Replication instructions** — exact crate revisions, `cargo` invocations, test fixtures used, so an auditor can rerun the spikes.

Section 6 and the bones of 7 are auto-generated by `gap-update` from the matrix; sections 1–5 are hand-written after all six gates are run for both libraries (deliberately *not* drafted mid-spike, to prevent motivated reasoning).

## Execution order

Strict lockstep across the two spike crates:

```
For each gate G in [0, 1, 2, 3, 4, 5]:
    For each library L in [Keyhive, p2panda]:
        If G == 0:
            Run the WASM build matrix for L; gap entry on failure
        Else:
            Run all L1 tests for G in L
            Run all L2 tests for G in L
        Run `cargo run --bin gap-update` to refresh docs/phase-1d/gap-matrix.{md,json}
    Review checkpoint with user:
        - If G == 1: priority discovery checkpoint.
          Discuss any Hard failures of C1/C2 and pick TraitImpl/Fork/Replace
          before advancing.
        - Otherwise: confirm the gap matrix is coherent and no new escape
          hatches were introduced silently.
    For each library L in [Keyhive, p2panda]:
        If L's L1+L2 for G passed in L's idiomatic shape:
            Run all L3 tests for the scenarios that gate G enables in L
        Else:
            Skip L3 for L at this gate. The gap-matrix row already records the
            Hard/Soft severity and the documented salvage path; L3 cannot run
            because the salvage (fork/replace/TraitImpl) is Phase 3 work, not
            part of this spike.
    Refresh the gap matrix
```

The spike **documents** salvage paths for `Hard` rows; it does not **implement** them. Forks, trait-impls, and replacements live in Phase 3. This keeps the spike's wall-clock cost bounded and avoids the spike's recommendation being polluted by salvage work whose effort estimate would be self-justifying.

After all six gates have completed this loop, a final L3 regression sweep is run end-to-end (on whichever scenarios are runnable in each library) before the decision narrative (sections 1–5) is hand-written.

## Risks and open questions

These are recorded here so the implementation plan can address them, not because they are blockers to starting:

- **Sub-crate inventories may shift mid-spike.** Both libraries are pre-1.0 and actively iterating. A pinned revision freezes the inventory for the spike, but the resulting decision is only valid for that revision range. The decision doc records this caveat under §Replication instructions.
- **`p2panda-spaces` is on a feature branch.** Per parent design §Addendum line 235. The spike will pin a specific commit and document the merge status at the time of pinning.
- **Async vs sync mismatch.** Both libraries likely have async APIs in places where the resolver trait is sync. The escape-hatch convention permits the spike to introduce `block_on` / sync wrappers in adapter code; each such wrapper produces a `Soft` gap-matrix entry so the impedance is visible.
- **The "library never authoritatively caches keys" invariant** (cross-flow invariant in §Data flow) is checked structurally where possible (opaque `Principal` type, resolver-only access) and behaviourally otherwise (Flow C asserts that a stale cached key is never accepted after rotation). If a library's internals cache aggressively without a public invalidation hook, this lands at gate 3 as a likely `Hard` or `Soft` row.
- **Connection-termination latency** (Flow F1/F2) — neither library is likely to expose a deterministic "close *now*" primitive; the test assertion is "eventually closed", which the spike measures and reports in `notes`. If a library cannot close inside the τ-window required by the parent design, that is recorded as a `Soft` gap with a Phase 3 risk note.

## Out of scope

- Any actual integration of the picked library into a working ODS stack (Phase 3).
- The browser PWA demo (Phases 2 and 4).
- The TLA+ formal model (Phase 1.c).
- The on-chain component (Phase 1.b).
- Changes to `org-members` (Phase 1.a).
- Performance benchmarks beyond what tie-break step 4 (CGKA scaling) needs (informational only).
- Independent security audit of either library (called out as a separate, downstream activity in the parent design's §Addendum line 236).
- Selection of any post-quantum signature/KEM schemes used by the libraries.
