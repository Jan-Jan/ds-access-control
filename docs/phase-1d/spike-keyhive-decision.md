# ODS Phase 1.d — Keyhive spike decision

**Status:** Decided (per-library qualification; head-to-head with p2panda in `spike-comparison.html`)
**Date:** 2026-06-02 (revised 2026-06-03 after lazy-CGKA design commitment)
**Pinned commit:** `a2876f3c79d89c9dd0c5e9f84802611c716fe27e`
**Detailed findings:** [`spike-keyhive-report.html`](spike-keyhive-report.html)

This document records the per-library decision for Keyhive based on the
ODS Phase 1.d spike. The final head-to-head decision between p2panda
and Keyhive comes after the comparison report
([`spike-comparison.html`](spike-comparison.html) — forthcoming).

---

## 1. Pick

**Keyhive is qualified as a viable Phase 3 substrate, with materially
lower fork burden than p2panda.**

The spike establishes — through direct API-surface evidence at the
pinned SHA — that every substitution the ODS design requires can be
implemented against Keyhive's public APIs without modifying upstream
source. The single Hard row (gate 1's principal-ID concreteness) has
an in-spike `TraitImpl` salvage (`spike-keyhive/src/adapter.rs`,
~30 lines). No gate requires a fork.

Burden numbers (unchanged whether WASM is required or not, because
gate 0 contributes zero):

- **Without WASM** — burden 22. 1 Hard + 9 Soft rows.
- **With WASM** — burden 22 (same). Gate 0 scores `None` — all three
  Keyhive sub-crates compile cleanly to `wasm32-unknown-unknown`.

The mid-spike running-code milestone briefly raised the burden to 24
based on the high-level `Keyhive::add_member` API requiring a signed
`KeyOp`/`ContactCard`. The 2026-06-03 commitment to the **lazy-CGKA /
two-tier design** (see §3.1) renders that finding a footnote about the
convenience API: the production path composes `keyhive_core` delegation
+ `beekem::Cgka` directly and needs only a long-term `VerifyingKey`
from the trie. Burden reverts to the original 22.

This is a per-library qualification, not the final head-to-head pick.
The comparison report `spike-comparison.html` is the right document
for that decision.

## 2. Disqualifying gaps

**None.** No gate produced a finding that disqualifies Keyhive. The
sole Hard row (gate 1) is salvaged in the spike itself; the salvage
path is bounded and well-understood (call-site adapter).

| Gate | Salvage | Effort |
|---|---|---|
| 0 (WASM) | None needed — all three sub-crates pass | — |
| 1 (stable-ID ACL) | `IdAdapter` in `spike-keyhive/src/adapter.rs` | Small |
| 2 (op interception) | Containment-via-wrapper (`KeyhiveWrapper`) | Small |
| 3 (CGKA rotation) | Direct `Cgka::add(id, pk, signer)` injection | Small |
| 4 (org pseudo-group) | `Agent::Group(...)` is first-class; reverse-index in wrapper | Small (fix) / Medium (phase3) |
| 5 (P2P policy) | Custom session stub + `MembershipListener` push events | Small |

## 3. Per-library narrative

### 3.1 Design model — lazy CGKA + two-tier separation

ODS commits to a **two-tier** decomposition that the convenience APIs
of both libraries blur:

| Tier | Source of truth | Cadence | Carries |
|------|-----------------|---------|---------|
| ACL  | Trie (on-chain) | Rare — onboarding + rotation/revocation | `(MemberId, VerifyingKey)` |
| CGKA tree | Per-document BeeKEM state | Per-write, per-rotation | x25519 leaf keys (online members only) |

**Grant.** Alice grants bob ACL access on doc D. The trie records the
delegation against bob's `MemberId`/`VerifyingKey`. No prekey needed.
No CGKA mutation. Bob may be offline.

**Come-online self-add.** When bob next syncs, his client sees the
delegation, fetches doc D's current CGKA state, generates a fresh
x25519 leaf, and commits a self-add to BeeKEM (signed by bob,
verifiable as authorised by alice's delegation).

**History transfer.** Bob asks an already-authorised peer for the
document's history. That peer has the plaintext at-rest and
retransmits it wrapped under the current CGKA epoch. ODS's existing
encryption-at-rest vs encryption-in-transit split makes this safe:
re-transmitting to a co-authorised member does not extend any
privilege beyond what the source peer already had.

**Revocation.** Trie revokes bob's `MemberId`. Existing members commit
a CGKA remove/update; bob's leaf rotates out. Forward security holds
via fresh `PcsKey` on the new epoch.

**Why this matters for the library decision.** Both Keyhive's
`keyhive.add_member(Agent::Individual, ...)` and p2panda's
`manager.add_member(member_id, key_bundle)` eagerly place the new
member in the CGKA tree, which is why both require a prekey at
add-time. The two-tier design descends below those entry points:
`keyhive_core` delegations + `beekem::Cgka::add` composed by the
spike (or by the Phase-3 substitution layer). Both sub-crates are
already direct dependencies of `spike-keyhive`.

This pivot was the resolution of the mid-spike "KeyOp finding": the
high-level API really does require a signed KeyOp, but the ODS design
doesn't go through that API. See
[`spike-keyhive/src/evidence/s1.md`](../../spike-keyhive/src/evidence/s1.md)
for the full lineage.

### 3.2 What worked (positive surprises)

- **`keyhive_core::Agent::Group(GroupId, Arc<Mutex<Group>>)` is a
  first-class variant of `Agent`.** `add_member` accepts ANY `Agent`
  variant with identical call signature. The org-as-pseudo-group flow
  (gate 4) needs no fork at all — strongest single differentiator
  vs p2panda.

- **`beekem::Cgka::add(id, pk, signer)` is the cleanest CGKA
  substitution seam encountered in either spike.** The leaf encryption
  key enters as a direct argument. No generic-trait threading like
  p2panda's `IdentityRegistry<ID, Y>` pattern.

- **`Identifier(pub VerifyingKey)` has a `pub` field.** Spike code
  constructs principals directly with no factory boilerplate — cleaner
  than p2panda's `ActorId(pub(crate) VerifyingKey)`.

- **`keyhive_core` is WASM-clean.** The Phase 1.d sub-crate inventory
  predicted DEFINITE FAIL on tokio + futures; the actual outcome is
  PASS. Keyhive's code paths only reach the wasm32-compatible slice
  of tokio (`tokio::sync` channels/mutexes).

- **`MembershipListener::on_revocation` is a push hook.** Gate 5's
  termination flow is push-based — a revocation propagating through
  `receive_static_event` immediately fires the listener and triggers
  session rechecks. p2panda's equivalent had to be pull-based.

- **BeeKEM is O(log n) per rotation** vs DCGKA's O(n). For
  ODS-scale orgs (100–10 000 members) this is a 14–700× factor per
  rotation, compounding under revocation churn.

### 3.3 What needed work

- **Principal-ID concreteness (gate 1).** `Identifier`, `IndividualId`,
  `GroupId`, `DocumentId` are concrete newtypes over `VerifyingKey` —
  the principal model is not generic in ID. Salvaged via the call-site
  `IdAdapter` that maps `MemberId → VerifyingKey` and refreshes the
  cache + drives CGKA rotation on trie-side key changes.

- **High-level `add_member` requires prekey at add-time (gate 1
  follow-up).** Surfaced by the running-code milestone:
  `Keyhive::add_member` needs an `Agent::Individual(_, Arc<Mutex<Individual>>)`,
  and `Individual::new` needs a signed `KeyOp`. Resolved architecturally
  by the lazy-CGKA design (§3.1) — ODS doesn't go through that API.

- **MembershipListener is post-fact (gate 2).** The listener cannot
  refuse operations. `DelegationStore` and `RevocationStore` are
  concrete struct fields of `Keyhive`, not generic — no custom impl
  possible. Substitution is containment-via-wrapper instead of
  store-level interception.

- **No published transport (gate 5).** Beelay (Keyhive's transport)
  is not yet released at the pin. The spike implements its own
  in-process session model. Phase 3 must either ship its own
  transport bridge or wait for Beelay.

### 3.4 Constraints discovered

- **`Keyhive<F, S, T, P, C, L, R>` has seven type parameters.** Most
  have defaults, but any code holding a typed reference has to commit
  to all seven. Phase 3 should use type aliases per scope.

- **Cgka takes the leaf key directly via `Cgka::add(id, pk, signer)`.**
  Phase 3 must ensure the `MemberId` → `ShareKey` derivation is
  consistent with whatever Keyhive expects internally for tree-leaf
  encryption. The spike treats the ShareKey as derived from the
  trie's `p2p_member_key`; verify this matches BeeKEM's contract.

- **No first-class reverse-lookup.** Both gate 4 (org cascade) and
  gate 5 (peer policy) need `VerifyingKey → MemberId`. The spike
  maintains its own indices; phase 3 should formalise on the
  foundation trait.

### 3.5 Escape hatches taken

1. **`IdAdapter` cache.** Maintains a `HashMap<MemberId, VerifyingKey>`
   keyed by member ID. Phase 3 must handle eviction / staleness;
   the spike's policy is "always re-query on access" but caches the
   result for reverse lookup.

2. **Wrapper-as-intercept (gate 2).** Containment instead of
   refusal. Application code that gets a reference to the wrapper
   has no access to the underlying `Keyhive`. Relies on the wrapper
   not leaking the inner handle.

3. **In-process session stub (gate 5).** `PolicyManager` holds
   sessions in a `Mutex<HashMap<SessionId, SessionRecord>>`. Phase 3
   must replace this with a real transport.

## 4. Risk register for the pick (the Soft rows)

Each `Soft` row in the gap matrix is phase-3 work. None is showstopping.

| # | Risk | Mitigation |
|---|---|---|
| R1 | Gate 1 — delegation log holds raw VerifyingKey; a MemberId rotation produces a stale entry without explicit cascade. | The spike composes adapter invalidation with `keyhive.force_pcs_update(doc)`; phase 3 wires this to the trie-change observer. Under the lazy-CGKA design (§3.1) the rotation drives a fresh leaf via `beekem::Cgka::update` directly. |
| R2 | Gate 2 — wrapper-as-intercept relies on the wrapper not leaking the inner Keyhive handle. | API hygiene: wrapper is a newtype with a private field; only its trie-driven methods are public. |
| R3 | Gate 4C — rotation cascade requires an org→docs reverse index maintained by spike code. | The wrapper owns the index, populated on every `grant_org` call. Test coverage in phase 3 must verify consistency. |
| R4 | Gate 5 — reverse lookup `VerifyingKey → MemberId` only works for cached entries; cold authorisation returns `UnknownPeer`. | Phase 3: add `MemberKeyResolver::find_member_by_device` to spike-common (foundation-layer change). |
| R5 | Keyhive is alpha (`0.0.0-alpha.3`); API may break between alphas. | Re-pin to a tagged release before phase 3 implementation; re-run L1 evidence checks against the new pin. |
| R6 | No published transport (Beelay) at the pin. | Phase 3 must either ship a transport bridge or wait for Beelay; the spike's in-process stub demonstrates the policy hook works. |
| R7 | Lazy-CGKA design relies on `keyhive_core` delegation log + `beekem::Cgka` direct composition. The spike validates the design semantics via Keyhive's high-level `add_member` entry point (L3 `lazy_onboarding`); the Phase-3 production path descends below that entry to let the new member's own client drive the placement. | The mechanism — BeeKEM epoch separation + plaintext re-transmission — is identical under both compositions. Risk reduced to "Phase 3 must wire the lower-level composition"; the design semantics are proven. |

## 5. Salvage paths for any not-picked alternative

The final phase-1.d decision document will record this section after
the comparison report. For now, see
[`spike-comparison.html`](spike-comparison.html) (forthcoming).

## 6. Gap matrix appendix

The canonical machine-readable matrix is at
[`docs/phase-1d/gap-matrix.json`](gap-matrix.json); the rendered
Markdown version (both libraries combined) is at
[`docs/phase-1d/gap-matrix.md`](gap-matrix.md). Full narrative
summaries are in the HTML report
[`spike-keyhive-report.html`](spike-keyhive-report.html) §6.

Headline figures (Keyhive rows only):

- **Without WASM gate:** 1 Hard + 9 Soft = burden 22.
- **With WASM gate:** 1 Hard + 9 Soft + 1 None (gate 0) = burden 22.
- **vs p2panda:** −10 burden, −31 % (Keyhive's WASM total is 22 vs
  p2panda's 32; without WASM 22 vs 20 — slightly higher because
  Keyhive's gate-4 Flow C carries Medium phase3, but no Hard rows
  outside gate 1).

Re-pin since the 2026-06-02 running-code revision (which briefly took
the burden to 24 / −25 %): the lazy-CGKA / two-tier design (§3.1)
reverts gate 1's `phase3_effort` to Small.

## 7. Replication instructions

To reproduce the spike's findings:

```bash
# Clone and enter the worktree
cd /Users/jan-jan/Coding/2-tier-access-control
git checkout worktree-spike-phase-1d   # branch from this spike

# Confirm the Keyhive pin
grep "keyhive_core" spike-keyhive/Cargo.toml
# Expected: rev = "a2876f3c79d89c9dd0c5e9f84802611c716fe27e"

# Confirm the compile
cargo check -p spike-keyhive
# Expected: clean compile against the three Keyhive crates

# Gate 0 — WASM probes
rustup target add wasm32-unknown-unknown
# See docs/phase-1d/gate-0-results.md §Keyhive for the probe sequence:
#  /tmp/wasm-probe-keyhive_crypto/ -- PASS
#  /tmp/wasm-probe-beekem/         -- PASS (with std)
#  /tmp/wasm-probe-keyhive_core/   -- PASS

# Gap matrix
cargo run -p spike-common --bin gap-update --features json
# Expected: 22 rows total (11 Panda + 11 Keyhive); Keyhive summary
#  "hard: 1, soft: 9, total burden: 22"
```

The Keyhive spike spans 4 commits on `worktree-spike-phase-1d`:

- `cef6273` — pin keyhive deps and scaffold gate modules
- `b859d0c` — gate 0 WASM/no_std verification
- `e8db687` — gates 1-5 evidence + gap-matrix entries
- (this commit) — HTML report + per-library decision

---

**Next step.** Comparison report `spike-comparison.html` that
overlays both libraries' gap matrices, followed by the final
Phase 1.d decision document.
