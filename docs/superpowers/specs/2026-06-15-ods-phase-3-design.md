# ODS Phase 3 — Local-first library (Keyhive) substitutions

**Author(s):** Jan-Jan van der Vyver (design captured via brainstorming session)
**Status:** In review
**Created:** 2026-06-15
**Spec for:** Phase 3 of [`Organisational Data Sovereignty p1.md`](../../../Organisational%20Data%20Sovereignty%20p1.md) §"Roadmap" item 3 — "Local-first library substitutions. The five items from *Key changes required*, each with the corresponding Scenarios entry as exit criteria."
**Substrate decision:** [`docs/phase-1d/decision.md`](../../phase-1d/decision.md) — Keyhive picked (conditional).

---

## 1. Overview

Phase 3 replaces the **hand-wired, app-level** access-control logic of the Phase 2
PoC (`org-node`, see [`2026-06-15-ods-phase-2-poc-design.md`](2026-06-15-ods-phase-2-poc-design.md))
with **library-level ACL substitutions** on the Keyhive substrate. It delivers the
five "key changes required" by the ODS design, each mapped to a Phase 1.d spike gate
and an ODS scenario exit-criterion:

1. **Stable identities + trie-lookup key resolution** (gate 1).
2. **Organisation pseudo-group** (gate 4A).
3. **Trie as sole write authority** (gate 2).
4. **Trie-driven CGKA triggers** (gate 3 / 4C).
5. **p2p connection policy** (gate 5).

(ODS canonical numbering; the §4 decomposition keeps these numbers but
re-orders the rows by dependency: 1 → 3 → 4 → 2 → 5.)

This is a **forward design, gated**: the architecture and decomposition are settled
now and each sub-project is specified, but *execution of every sub-project is blocked*
on two preconditions (§7). The single sub-project specified in full here is **item 1**;
items 2–5 are sketched with their interfaces, exit criteria, and carried-over risks,
each to be expanded into its own spec → plan → implementation cycle.

## 2. The gate (preconditions for execution)

Per the Phase 1.d decision (§1, R11, R14) the Keyhive pick is **conditional**. No
sub-project implementation begins until **both** of the following clear:

- **(a) Phase 2 has landed `org-node`** with the resolver/observer seam Phase 3 binds
  to. Phase 3 builds *on* `org-node`; `org-node` is "in review" and unbuilt as of this
  spec.
- **(b) Keyhive has shipped a tagged `0.1.0` with ≥1 external audit**, and `org-acl`
  has been re-pinned from the spike's `0.0.0-alpha.3` to that release. Re-running the
  spike's L1 evidence checks against the new pin is part of item 1's first task (§5.6,
  R13).

Every sub-project plan carries this gate as an unchecked banner at the top; it is the
first thing an executing agent verifies.

## 3. Architecture

### 3.1 Crate topology

A new crate **`org-acl`** (GPL-3.0-only — matching the Keyhive-touching crates) is the
**only** crate in the workspace that names `keyhive_core` / `beekem` / `keyhive_crypto`.
That containment is deliberate: it confines Keyhive's GPL surface behind one boundary
and keeps the door open for the documented p2panda pivot (decision doc §5) without
touching consumers.

```
org-acl/                 # GPL-3.0-only; the Keyhive boundary
  src/
    identity.rs    # OrgId, MemberId, OrgMember, P2pMemberKey, P2pDeviceKey,
                   #   OrgKey, Epoch, Principal  (graduated from spike-common)
    resolver.rs    # MemberKeyResolver trait (graduated) + ContactCard escalation
    adapter.rs     # IdAdapter: OrgMember <-> VerifyingKey cache (non-authoritative)
    wrapper.rs     # KeyhiveWrapper: trie-as-sole-write-authority containment (item 3)
    cgka.rs        # trie-change observer -> rotation cascade (item 4)
    pseudo_group.rs# org-as-pseudo-group + org->docs reverse index (item 2)
    policy.rs      # p2p connection policy over iroh; tau-window/termination (item 5)
  tests/           # L2/L3 scenario tests promoted from spike-keyhive + bolero fuzz
```

- `org-node` (Phase 2) **depends on** `org-acl` and implements `MemberKeyResolver` over
  its per-org trie mirror.
- `spike-common`'s Apache-2.0 contract (`MemberKeyResolver`, `identity::*`, scenario
  fixtures) **graduates into** `org-acl` — re-homed, not re-derived.
- `spike-keyhive`'s three escape hatches (`IdAdapter`, `KeyhiveWrapper`, the in-process
  `PolicyManager`) become the **reference wiring** `org-acl` productionises.
- The `spike-*` crates stay in-tree as frozen Phase 1.d evidence.

### 3.2 Cross-cutting spine — lazy-CGKA two-tier model

Confirmed as the Phase 3 architecture (decision doc §3.3; validated by the spike's
`l3_lazy_onboarding`, four invariants on first run).

| Tier | Source of truth | Cadence | Carries |
|------|-----------------|---------|---------|
| ACL  | Trie (on-chain anchored) | Rare — onboarding + rotation/revocation | stable identity (`OrgMember`), long-term `VerifyingKey` |
| CGKA tree | Per-document BeeKEM state | Per-write, per-rotation | x25519 leaf keys (online members only) |

All five `org-acl` modules descend **below** Keyhive's high-level `add_member`
convenience API (which eagerly conflates ACL grant with CGKA placement and would force
prekey material on-chain at add-time). The trie carries only long-term identity; BeeKEM
placement happens lazily when a member's client first comes online.

### 3.3 The trie-change observer

A single hook — subscribing to the **same epoch-bump signal** `org-node` already uses
for verify-against-chain (Phase 2 §5.4) — drives every reactive path:

- `IdAdapter::invalidate(org_member)` on rotation/revocation (R1).
- `cgka::force_pcs_update(...)` per epoch so a fresh `PcsKey` is derived (R4).
- pseudo-group org→docs reverse-index maintenance (R5/R6).

Commit on **finalised** events only; a reorg that retracts the bump retracts the
trigger (inherited from Phase 2's discipline).

## 4. Decomposition — the five sub-projects (gated)

Dependency-ordered. Each becomes its own spec → plan → implementation cycle.

| # | Sub-project (module) | Depends on | Exit criterion (ODS §Roadmap.3) | Carried spike risks |
|---|---|---|---|---|
| **1** | stable-id ACL + trie-lookup (`identity`, `resolver`, `adapter`) | — | revocation scenario passes; identity-takeover provably blocked | R7, R11, R13 |
| **3** | trie as sole write authority (`wrapper`) | 1 | library-native membership ops unreachable from the API surface | R2; gate-2 was only *Soft* in spike — production must do better |
| **4** | trie-driven CGKA triggers (`cgka`) | 1, 3 | device-removal triggers rotation; org-update triggers org-key rotation | R3, R4, R6 (**Medium** — index consistency under concurrent grant+rotation) |
| **2** | org pseudo-group (`pseudo_group`) | 1, 3 | org-level delegation works for both PRD use cases | R5 |
| **5** | p2p connection policy (`policy`) | 1, 2, 4 | gating + transitive-trust pass, incl. τ-window jitter | R8, R9, R10; rides iroh (transport out of scope) |

**Sequencing: 1 → 3 → 4 → 2 → 5.**
- 3 before 4: rotation cascades flow *through* the write-authority boundary.
- 2 after 4: the org→docs reverse index is shared by 4's cascade and 2's delegation.
- 5 last: it composes 1 + 2 + 4.

**Transport scope.** Phase 3 treats transport as solved by Phase 2's **iroh**
(`NodeId = P2pDeviceKey`). Item 5 implements only the policy/gating layer (admission,
τ-window recheck, transitive-trust, termination) over iroh's authenticated channels.
**Beelay is out of scope** (R12); the spike's in-process `PolicyManager` session model
is the reference for the policy logic, not a transport.

**Formal-model tie-in.** Item 5's τ-window / transitive-trust exit criteria cite the
Phase 1.3 formal-model invariants (Quint model landed `312fe3178`; TLA⁺ τ-window model
in-tree) by name as acceptance properties, rather than re-deriving them.

## 5. Item 1 — stable-id ACL + trie-lookup key resolution (full spec)

### 5.1 Problem

Keyhive's principals (`Identifier`, `IndividualId`, `GroupId`, `DocumentId`) are concrete
newtypes over `ed25519_dalek::VerifyingKey`; the principal model is not generic in ID.
ODS needs the **stable** trie-leaf identity (immutable across key rotation) to be the
ACL identity, with the **rotatable** `VerifyingKey` resolved through the trie on demand.

### 5.2 Identity model

`MemberId` is **only unique within one org's trie**. Therefore the ACL identity is the
**composite** `OrgMember`, and any structure that crosses an org boundary keys on it.

```rust
/// On-chain org slot key — h160_of(P), the pure-proxy-derived H160.
/// Stable across multisig rotation (Phase 2 §4.1). Distinct from OrgKey,
/// the org pseudo-group VerifyingKey stored *inside* the slot.
pub struct OrgId(pub [u8; 20]);

/// 32-byte immutable, org-scoped member identifier (the SMT leaf key).
pub struct MemberId(pub [u8; 32]);

/// The stable ACL identity. Org-scoped MemberId paired with its org.
pub struct OrgMember { pub org: OrgId, pub member: MemberId }

/// Opaque principal. The library obtains a key only via MemberKeyResolver.
pub enum Principal {
    Member(OrgMember),
    Org(OrgId),
}
```

`P2pMemberKey`, `P2pDeviceKey`, `OrgKey` (all `VerifyingKey` newtypes), and `Epoch`
graduate unchanged from `spike-common::identity`.

### 5.3 The resolver contract

`MemberKeyResolver` graduates from `spike-common::resolver` with two changes: a
`ContactCard` method (§5.4) and an org-id accessor. Each impl is **bound to one org's
trie mirror** — forward methods take a bare `MemberId` because the instance fixes the
`OrgId`; `org-node` holds one resolver per org record.

```rust
pub trait MemberKeyResolver {
    /// The org this resolver is bound to. Callers stamp it onto results
    /// promoted into any cross-org structure (IdAdapter, policy layer).
    fn org_id(&self) -> OrgId;

    /// Trie-vouched, Keyhive-ingestible identity proof for `id`.
    /// Required because Individual::new wants a signed KeyOp, not a bare key.
    fn contact_card(&self, id: &MemberId) -> Result<ContactCard, ResolverError>;

    /// Current member-as-a-group key for `id`.
    fn p2p_member_key(&self, id: &MemberId) -> Result<P2pMemberKey, ResolverError>;

    /// Current org pseudo-group key.
    fn org_key(&self) -> Result<OrgKey, ResolverError>;

    /// Currently-authorised devices for `id` (Ok(vec![]) if isolated).
    fn current_devices(&self, id: &MemberId) -> Result<Vec<P2pDeviceKey>, ResolverError>;

    /// Cross-org cold reverse lookup (closes R7): which (org, member) owns
    /// this device key? Resolves cold peers against the trie, not just cache.
    fn find_member_by_device(&self, dev: &P2pDeviceKey) -> Option<OrgMember>;

    fn org_member_ids(&self) -> Vec<MemberId>;
    fn is_member(&self, id: &MemberId) -> bool;
    fn epoch(&self) -> Epoch;
}

pub enum ResolverError {
    UnknownMember(MemberId),   // not in the trie
    NoContactCard(MemberId),   // in the trie but hasn't published a card yet
                               //   (lazy-onboarding "not online yet" state)
    OrgKeyUnset,
}
```

### 5.4 The ContactCard escalation (decisive finding)

The Phase 1.d running-code milestone proved that resolving `MemberId → VerifyingKey` is
**not** sufficient to drive Keyhive: `Individual::new(initial_op: KeyOp)` requires a
*signed* `KeyOp`, and `add_member` wants an `Agent::Individual(id, Arc<Mutex<Individual>>)`
obtained via `keyhive.receive_contact_card(&card)`. Therefore:

- The **trie publishes (or signs-on-demand) each member's `ContactCard`**; the resolver
  serves it via `contact_card(&MemberId)`.
- The spike's in-memory `ContactCardForge` (`spike-keyhive::s1_stable_id_acl`) is the
  stand-in this productionises.

This is the one interface change item 1 pushes back onto `org-node` / `org-members` (the
resolver impl, and thus the contact-card index, lives on `org-node`'s trie mirror).

### 5.5 Two-halves enforcement

- **Type-system half.** ACL entries reference the opaque `Principal` — never a raw key.
  The only way to obtain a key is through the resolver.
- **Invariant half ("Flow B").** No code path reads a `VerifyingKey` for a `Principal`
  except through the resolver. `IdAdapter`'s cache is explicitly a *derived view*:
  `resolve()` always re-queries the resolver and overwrites the entry; the cache is
  never authoritative. Documented as a crate invariant and asserted by test
  (`rotation_via_resolve_picks_up_new_key`, promoted).

`IdAdapter` maps `OrgMember → VerifyingKey` and reverse `VerifyingKey → OrgMember`, so the
same `MemberId` value under two `OrgId`s never aliases. `invalidate(org_member)` is
called by the trie-change observer (§3.3) on rotation/revocation.

### 5.6 Data flow

**Admit + resolve:**
1. A member's client publishes its signed `ContactCard` (via the org-node transport /
   Phase 2 Story 2 out-of-band blob).
2. The trie records `MemberId → ContactCard`; `contact_card` serves it.
3. ACL grant: `KeyhiveWrapper` (item 3) calls `resolver.contact_card(id)` →
   `receive_contact_card` → `add_member(Agent::Individual(...))`, below the eager
   convenience path.
4. Key use / verify: every Keyhive boundary resolves `Principal::Member(org_member)` →
   current `VerifyingKey` via `IdAdapter::resolve(resolver, id)`.

**R13 go/no-go (first executable task, after the §2 gate clears):** confirm against the
re-pinned Keyhive `0.1.0` that `keyhive_core` delegation construction is reachable below
`add_member` without materialising an `Individual`. If it fails, the substrate decision
re-opens before any further item-1 work.

### 5.7 Exit criteria (ODS Roadmap.3 item 1)

- **Revocation passes.** Member removed from trie ⇒ `contact_card` / `p2p_member_key`
  return `UnknownMember` ⇒ resolver-gated key lookups fail ⇒ no ciphertext is encryptable
  to the revoked principal; the observer has fired `invalidate`. (Promoted from
  `l3_revocation`.)
- **Identity-takeover provably blocked.** Because the ACL binds to `OrgMember` and keys
  are resolved *only* live through the trie, an attacker presenting a rotated/forged
  `VerifyingKey` the trie does not vouch for resolves to nothing — the stale/forged key
  is never authoritative.

### 5.8 Error handling

`ResolverError::{UnknownMember, NoContactCard, OrgKeyUnset}` surfaced distinctly.
`NoContactCard` (in trie, not yet online) is *not* a security failure — it is the
lazy-onboarding pending state and must be distinguishable from `UnknownMember` (not a
member). Cold reverse-lookup miss is `Option::None`, not an error.

## 6. Testing (item 1)

Matches repo conventions — tested + fuzzed library crate.

### 6.1 Unit tests (adapted from `spike-keyhive::adapter` + `s1_stable_id_acl`)
- `IdAdapter`: resolve populates cache; resolve-unknown → `None`; `invalidate` drops
  entry; `resolve` always re-queries (rotation picks up new key); `member_id_for` warm
  hit / cold miss — all keyed on `OrgMember`.
- **No cross-org aliasing:** the same `MemberId` under two distinct `OrgId`s resolves to
  distinct entries and never collides.
- Resolver contract: `contact_card` round-trips a Keyhive-ingestible card;
  `NoContactCard` vs `UnknownMember` distinguished; `find_member_by_device` resolves a
  cold peer to the correct `OrgMember`.

### 6.2 Scenario / L3 acceptance tests (the exit criteria)
- Revocation (promoted from `l3_revocation`) — §5.7.
- Identity-takeover blocked — the type-system + Flow-B invariants asserted as a test,
  not documented as a comment.

### 6.3 Fuzz (AGENTS.md hard rule) — bolero, mirroring the `on-chain-client` pattern
Two targets in `org-acl/tests/`, `harness = false`, default `cargo test` lane on stable +
`cargo bolero` deep lane on nightly; committed corpus + `crashes/` regression dir.
- `fuzz_contact_card_resolve` — never-panic on arbitrary bytes deserialized as a
  `ContactCard` at the resolver boundary (cards arrive over untrusted transport).
- `fuzz_orgmember_codec` — round-trip / never-panic on `OrgMember` / `Principal` postcard
  codec (the cross-org key that indexes everything must never mis-parse into a colliding
  key).

### 6.4 Formal-model tie-in
Item 1's revocation / identity-takeover properties map to the Phase 1.3 model's
transitive-trust acceptance rules and the members-trie ↔ substrate sync contract; the
plan cites the specific Quint/TLA⁺ invariant names as acceptance properties.

## 7. Simplifications & scope boundaries

| # | Boundary | Rationale / future |
|---|---|---|
| P1 | Execution gated on Phase 2 `org-node` + Keyhive `0.1.0`+audit (§2) | Conditional pick; forward design only |
| P2 | Transport = iroh from Phase 2; Beelay out of scope | R12; item 5 is policy-layer only |
| P3 | One resolver instance per org record; forward methods org-implicit | Matches Phase 2 one-persona-per-org |
| P4 | Items 2–5 sketched, not fully specified here | Each gets its own spec → plan cycle |
| P5 | One device per persona assumed (inherited from Phase 2 S14) | Device-level sub-trie flows later |

## 8. Workflow / merge

- Work in a git worktree with `commit.gpgsign false` (per AGENTS.md).
- Squash-merge to master as a single user-signed commit at the end of each sub-project.
- `~/.cargo` is read-only in this environment; fetch via `CARGO_HOME=/tmp/cargo_home_fuzz`.

## 9. References
- [`Organisational Data Sovereignty p1.md`](../../../Organisational%20Data%20Sovereignty%20p1.md) — roadmap; "Key changes required"; Scenarios (exit criteria).
- [`docs/phase-1d/decision.md`](../../phase-1d/decision.md) — Keyhive pick (conditional); risk register R1–R14; lazy-CGKA §3.3; p2panda salvage §5.
- [`2026-06-15-ods-phase-2-poc-design.md`](2026-06-15-ods-phase-2-poc-design.md) — `org-node`; iroh transport; verify-against-chain; S5 (deferred substitutions).
- `spike-common/src/{resolver,identity}.rs` — graduating contract.
- `spike-keyhive/src/{adapter,s1_stable_id_acl}.rs` — reference wiring for item 1.
- `on-chain-client/README.md` §Fuzzing — the bolero pattern item 1's fuzz targets follow.
