# Quint Model of the ODS Phase 1 Protocol

**Author(s):** [Jan-Jan van der Vyver](mailto:jan-jan@parity.io)
**Status:** In review
**Created:** 2026-06-15
**Last Updated:** 2026-06-15

## Overview

This spec describes a [Quint](https://quint.sh) model of the Organisational Data
Sovereignty (ODS) Phase 1 protocol, built around the `org-members` crate. The
model is a **distributed-protocol** model: it treats the crate's
`apply_delta(...).verify_against(...)` contract as one atomic step and surrounds
it with the on-chain anchor, admin proposals, member-local views, the p2p
network, abstract secret distribution, and an active adversary. It checks four
properties — revocation safety, replay/fork safety, the transitive-trust τ
window, and convergence — against a four-class adversary.

The model is structured in three Quint modules plus a Rust model-based-testing
(MBT) harness that replays the membership core against the real `org-members`
crate. It serves three purposes simultaneously: a checkable statement of the
protocol's safety claims, an executable companion to the prose design
([`Organisational Data Sovereignty p1.md`](../../../Organisational%20Data%20Sovereignty%20p1.md)),
and a conformance oracle for the crate.

### Relationship to prior work

A TLA+ design ([`2026-03-13-tlaplus-formal-model-design.md`](2026-03-13-tlaplus-formal-model-design.md))
predates the `org-members` crate and sketched a two-tier model in TLA+/Apalache.
This spec supersedes it for Phase 1: it targets the protocol as it was actually
built (the crate's canonical-form contract is now a fixed, tested artifact rather
than a modeled unknown), uses Quint instead of raw TLA+ (same Apalache backend,
but with an executable simulator and a first-class Rust MBT bridge), and scopes
itself to the membership/access-control protocol of Phase 1 rather than both
tiers. The TLA+ doc remains the reference for the broader two-tier vision.

## Context & Goals

**Goals:**

- A distributed-protocol model in Quint that mirrors the ODS p1 design and the
  `org-members` crate's contract, checkable with `quint verify` (Apalache,
  bounded) and `quint run` (simulator).
- Four protocol properties checked against a four-class adversary (below).
- A `quint-connect` MBT harness that replays the membership-core model against
  the real `org-members` Rust crate, giving empirical confidence that the
  model's central abstraction (snapshot-as-root) matches the implementation.
- The model doubles as executable design documentation: each scenario from the
  design doc's §Scenarios is a named `quint run`.
- CI integration: `quint typecheck` and `quint run` on every push; bounded
  `quint verify` on a manual/nightly lane.

**Non-Goals:**

- Modeling the SMT / Merkle mechanics (node structure, hashing, inclusion
  proofs). These are implementation mechanics, covered by the crate's own tests,
  and deliberately abstracted away (see §Central abstraction).
- Modeling cryptographic primitives. Signatures and key derivation are assumed
  sound; the adversary attacks timing, ordering, and authority, never forges
  crypto.
- Modeling CGKA internals (path secrets, tree operations). CGKA is modeled as
  abstract epoch-stamped tokens distributed to knowledge sets. Keyhive's CGKA
  was validated separately in Phase 1.d.
- True temporal liveness with fairness. Convergence is expressed as a
  bounded-safety quiescence property plus simulator witnesses (see §Properties).
- Replaying protocol-layer traces against Rust. There is no Rust protocol
  implementation yet (Phase 2 / Keyhive integration). The MBT harness replays
  only the membership core; it extends to the protocol layer when that lands.

## Central abstraction: snapshot-as-root

The single most important modeling decision: **a `RootHash` is modeled as the
canonical trie snapshot itself** (`MemberId -> Leaf`).

The SMT exists in the crate to make state *commitments* compact and verifiable.
Assuming hash collision-resistance (standard for protocol specs), the root hash
is injective on trie content, so the model can represent a root by the content
it commits to. Then:

- "root A == root B" becomes structural map equality.
- The model never builds Merkle nodes, never hashes, never models proofs. This
  removes `smt.rs`, `node.rs`, and `hasher.rs` from the model's scope **by
  design** — they are implementation mechanics, not protocol behavior.
- The **root-revisit replay case** (add-then-remove returning to a prior root)
  falls out for free: two points in history with equal member maps are genuinely
  indistinguishable in the model, exactly as they are to the real crate. This is
  the foundation of replay/fork safety §10's natural-protection caveat.

The MBT harness (§MBT) empirically validates this abstraction: it checks that
the real crate's `root_hash()` equality classes coincide with the model's
`Snapshot` equality classes over generated traces.

## Architecture

```
quint/
  membership.qnt        -- pure functional core mirroring org-members
  protocol.qnt          -- distributed ODS p1 state machine (imports membership)
  ods_instances.qnt     -- instances, named scenario runs, property wiring
  README.md             -- how to typecheck/run/verify; property meanings; caveats
org-members/tests/
  mbt_conformance.rs     -- quint-connect driver: membership traces vs. real crate
```

`quint/` is a top-level directory (sibling to `org-members/`, `spike-*/`)
because the model spans the whole protocol, not just the crate.

### `membership.qnt` — the functional core

A pure-definition module (no state machine), imported by both the protocol layer
and the MBT harness, so there is a single source of truth for membership
semantics shared between "what we test against Rust" and "what the protocol
assumes the crate does."

**Types** (mirroring `types.rs`, abstracted):

```quint
type MemberId = str                      // small symbolic ids: "alice", "bob"
type Key = { owner: str, gen: int }      // a key = who minted it + rotation counter
type Leaf = {
  id: MemberId, handle: str, skeleton: str,
  name: str, surname: str,
  pKey: Key, devices: Set[Key]           // |devices| <= MAX_DEVICES = 4
}
type Snapshot = MemberId -> Leaf         // the trie; doubles as RootHash
type Delta = { baseRoot: Snapshot, removed: Set[MemberId], upserted: Set[Leaf] }
```

Two abstractions to call out:

1. **Keys are `(owner, generation)` pairs, not bytes.** Rotation bumps `gen`.
   This lets the protocol layer express "revoked insider still holds gen-3 key"
   and "compromised member key" with no crypto.
2. **Confusables become a `skeleton` field.** The UTS#39 pipeline collapses to:
   each handle carries a skeleton, and uniqueness is checked on skeletons. Two
   distinct handles are declared confusable by giving them equal skeletons —
   enough to model the H-3 class of attacks without Unicode.

**Operations** — one `pure def` per crate API entry, same names, returning a
`Result`-like sum type (`Ok(Snapshot) | Err(reason)`): `genesis`, `addMember`,
`deleteMember`, `updateHandle`, `updateNameSurname`, `rotateP2pKey`,
`addP2pDevice`, `deleteP2pDevice`, `emergencyIsolateMember`,
`calculateDelta(old, new)`, and `applyDelta(snapshot, delta)`.

`applyDelta` encodes the **canonical-form acceptance predicate** from `delta.rs`:

- `removed ⊆ base` (no stale removals)
- every upsert is an observable change vs. current state at that id (no no-ops)
- `removed` and `upserted` are disjoint
- `delta.baseRoot` matches the snapshot it is applied to
- post-state skeletons are unique (confusable check)
- device caps hold (`|devices| <= MAX_DEVICES`)

Byte-level wire ordering ("strictly increasing by `MemberId`") is **not**
modeled: sets already canonicalize order, and the sortedness check is a wire-form
concern owned by the crate and its Rust tests.

**Module-level laws** (checked in the protocol layer and a small standalone
harness):

- skeleton uniqueness across the snapshot
- device count ≤ `MAX_DEVICES` for every leaf
- round-trip: `applyDelta(s, calculateDelta(s, s')) == Ok(s')` — the
  canonical-form invariant at this abstraction level.

### `protocol.qnt` — the distributed state machine

Imports `membership.qnt`.

**State variables:**

```quint
// On-chain (the trusted anchor; single global)
var chain: { root: Snapshot, epoch: int, orgKey: Key }

// Per honest member's local belief
var local: MemberId -> { root: Snapshot, epoch: int, orgKey: Key, lastChecked: int }

// Network: in-flight messages, an unordered set of uniquely-tagged envelopes
// so duplicates / reorders / drops are all expressible
var network: Set[Envelope]

// Knowledge sets — who holds which secret token (abstract crypto)
var knows: Key -> Set[Principal]          // orgKey gen -> principals holding it
var doKnows: DataObjId -> Set[Principal]  // current CGKA token holders per data object

// Adversary bookkeeping
var revoked: Set[Principal]               // members/devices removed from the trie
var clock: int                            // logical time for the τ window
```

`Envelope` is a sum type: `OnChainUpdate`, `DeltaMsg(Delta)`,
`OrgSecretMsg(Key)`, `WriteOp(DataObjId, author: Key, epoch: int)`. Each carries
a unique tag so the network adversary can duplicate and reorder freely.

**Honest actions** (guarded `action`s, each a possible step):

- `adminProposeUpdate` — a threshold-`t` set of admins agree a new snapshot;
  computes `calculateDelta`, bumps the chain epoch, mints a new `orgKey`
  generation, posts an `OnChainUpdate` and seeds `DeltaMsg` / `OrgSecretMsg`
  into the network addressed to current members only.
- `memberObserveChain` — a member reads `chain` (sets `lastChecked = clock`) and
  learns whether it is behind.
- `memberFetchAndApply` — consumes a `DeltaMsg` matching its local root, runs
  `applyDelta`, then `verify_against(chain.root)` — **atomic, mirroring the
  crate's `apply_delta(...).verify_against(...)` contract.** On success advances
  `local`; on root mismatch, drops the delta.
- `memberReceiveOrgSecret` — adds the member to `knows[newOrgKey]` iff it is
  still a member in the chain root.
- `cgkaRotate` / `dataObjectWrite` / `dataObjectRead` — mint and distribute CGKA
  tokens per design §8–9 triggers; reads check token membership.
- `networkDeliver` / `networkDrop` / `networkDuplicate` — the network adversary.
- `tick` — advance `clock`.

**Adversary actions** (the four classes):

- *Network adversary* — `networkDeliver` / `networkDrop` / `networkDuplicate`
  above. Delays, reorders, duplicates, and selectively drops messages. Offline
  members are the special case of indefinitely delayed delivery. No forging.
- *Revoked insider* — `revokedReplayDelta` (re-inject an old delta or secret),
  `revokedAttemptWrite` (emit a `WriteOp` with a stale key), `revokedAttemptRead`.
  Keeps old keys and secrets, stays online, actively tries to keep collaborating.
- *Below-threshold rogue admins (≤ t−1)* — `rogueProposeDelta`: sign and gossip a
  well-formed `DeltaMsg` p2p **without** a matching `OnChainUpdate`. Tests that
  off-chain delta distribution cannot bypass the on-chain anchor.
- *Compromised member key* — `compromiseKey`: add an attacker principal to
  `knows` for a *current* member's key; downstream attempts use it. Models
  identity-takeover and exercises the "stable identities + trie-mediated
  rotation" claim from the design's key-changes section.

Every adversary action produces only well-formed, signature-valid messages. The
model attacks **timing, ordering, and authority**, never crypto soundness.

## Properties

All four are checkable names wired in `ods_instances.qnt`.

### 1. Revocation safety (invariant)

For every revoked principal `p` and data object `obj`, once `obj` is "settled" —
every honest member's `local.epoch == chain.epoch` and CGKA has rotated for
`obj` — `p` holds no current token and no honest member accepts a write authored
by `p`'s revoked key:

```
settled(obj) implies
  (revoked ∩ doKnows[currentToken(obj)] == {}
   ∧ every accepted WriteOp on obj has author ∈ currentMembers(chain.root))
```

The core security claim. Must survive the revoked-insider and network
adversaries.

### 2. Replay / fork safety (invariant)

Two honest members at the same epoch never hold different roots, and no member
ever advances to a root that was never an on-chain root:

```
∀ honest m1, m2 : m1.local.epoch == m2.local.epoch implies m1.local.root == m2.local.root
∀ honest m      : m.local.root ∈ { historical chain roots }
```

The root-revisit case is covered for free (§Central abstraction). The
rogue-admin `DeltaMsg` path must never make an honest member's accepted root
diverge from an on-chain-anchored one; `verify_against(chain.root)` is the
enforcement point, and this property checks the rogue path cannot defeat it.

### 3. Transitive-trust τ window (invariant, policy-parameterised)

A member only accepts a tainted write (one authored by a since-revoked
principal) while inside its own staleness window:

```
∀ accepted WriteOp w authored by revoked principal p, accepted by honest m :
  (m.clock - m.lastChecked) < TAU
```

Two policy variants as boolean constants:

- `PAUSE_ON_LEARN` — a member drops collaboration the instant it observes a chain
  change. Expected to collapse the taint window to in-flight messages only
  (design §10.a.iii).
- `MAX_AGE` — the τ bound on staleness since the last on-chain check
  (design §10.a.iv).

The model checks the design's §10 claims hold under each policy. Requires the
`clock` / `lastChecked` machinery.

### 4. Convergence (bounded-safety quiescence + simulator witness)

Expressed as quiescence rather than temporal `eventually`, to stay robust under
Apalache (see caveat below):

```
(no deliverable DeltaMsg / OrgSecretMsg exists for any behind member
   ∧ no pending adminProposeUpdate)
   implies ∀ honest online m : m.local.root == chain.root
```

Backed by `quint run` witness runs asserting the quiescent converged state is
*reachable* and that members do advance — giving both "can't get stuck wrong"
(safety) and "does make progress" (witness).

**Liveness caveat.** Apalache (behind `quint verify`) is strong on safety and
invariants but painful for temporal liveness with fairness. This model
deliberately expresses convergence as bounded-safety quiescence plus simulator
witnesses rather than true temporal `eventually`. This is a known, accepted
limitation, documented in `quint/README.md`.

### Instances and scenarios

`ods_instances.qnt` defines small instances —
`MEMBERS = {alice, bob, carol}`, `ADMINS = {a1, a2}`, `t = 2`, `TAU = 3`, one or
two data objects — and one named `run` per design-doc §Scenario: revocation,
gating-while-fired, A&C window jitter, SKU window, all-devices-stolen. Each
property is checked on the smallest instance that exercises it (e.g.
replay-safety does not need the τ clock).

## Model-based testing (MBT)

`org-members/tests/mbt_conformance.rs`, using `quint-connect` 0.1.2 (Informal
Systems, Apache-2.0).

- **Trace source:** `quint run quint/membership.qnt --mbt --n-traces=N
  --out-itf=...` — the membership core only, whose actions map 1:1 onto the crate
  API, so ITF replay is clean.
- **Driver:** maintains a real `OrgTrie<Blake3>` and, for each trace step,
  matches `mbt::actionTaken` to a crate call:
  - `addMember` → `add_member`, `deleteMember` → `delete_member`,
    `updateHandle` → `update_handle`, `updateNameSurname` →
    `update_name_surname`, `rotateP2pKey` → `rotate_p2p_key`, `addP2pDevice` /
    `deleteP2pDevice`, `emergencyIsolateMember`, and `applyDelta` →
    `apply_delta(...).verify_against(...)`.
  - **Symbol mapping:** the model's symbolic `MemberId = "alice"` and
    `Key = {owner, gen}` are deterministically expanded to real 32-byte ids and
    ed25519 keys via a fixture table seeded once per run, so the same symbol
    always maps to the same bytes.
- **Conformance assertions:**
  1. The crate's `Result` agrees with the model's `Ok`/`Err` at every step.
  2. After each step, the crate's `root_hash()` equality classes match the
     model's `Snapshot` equality classes (two steps the model calls equal-root
     produce equal real root hashes, and vice-versa). This is the empirical
     check that the snapshot-as-root abstraction is sound.

The harness does not replay protocol-layer traces against Rust — there is no
Rust protocol yet. When the Phase 2 / Keyhive integration lands, the same
harness extends to it.

## Tooling & CI

- `quint typecheck` on all three `.qnt` files — fast, on every push.
- `quint test` / `quint run` on the named scenario runs and property witnesses —
  on every push.
- `quint verify` (Apalache, bounded) on the four properties at the small
  instance — **manual / nightly lane**, not every push (Apalache is slow and
  JVM-heavy; mirrors how the wasm32 lane is already isolated).
- `cargo test --test mbt_conformance` gated behind a feature or `#[ignore]`
  unless `quint` is on `PATH`, so ordinary `cargo test` stays hermetic.
- `quint/README.md`: how to run each command, what each property means, and the
  standing caveats (liveness-as-quiescence; crypto assumed sound; SMT/Merkle
  mechanics out of scope by design).

## Testing strategy

The model *is* a test artifact, but it has its own correctness obligations:

- **Sanity / vacuity:** each property is paired with at least one `run` that
  reaches a non-trivial state where the property is non-vacuously true (e.g. a
  trace where a revocation actually happens and settles), so a property is never
  "passing" only because its precondition is never met.
- **Negative controls:** deliberately broken variants (e.g. a
  `memberFetchAndApply` that skips `verify_against`) must produce a
  counterexample for replay/fork safety. These live as commented or
  feature-gated mutants referenced in the README, demonstrating the properties
  have teeth.
- **MBT divergence is a failure:** any disagreement between the crate and the
  membership model fails CI and is treated as either a model bug or a crate bug,
  resolved before merge.

## Phasing

The layered structure permits incremental delivery, each milestone small:

1. **Membership core + MBT** — `membership.qnt`, the round-trip law, and
   `mbt_conformance.rs`. Validates the central abstraction against the real crate
   first.
2. **Protocol safety** — `protocol.qnt` with the network and revoked-insider and
   rogue-admin adversaries; revocation safety and replay/fork safety.
3. **τ-window and convergence** — add the `clock` machinery, the compromised-key
   adversary, the τ policies, and the quiescence/witness convergence checks.
   **Also fold in the abstract-root remodel** (see below).

### Abstract-root remodel (deferred from Milestone 2)

Milestone 2's `protocol.qnt` carries full trie `Snapshot` maps in three places at
once — `chain.root`, every `local[m].root`, and inside every network envelope
(`DeltaMsg(Delta)` holds `baseRoot: Snapshot` + `Set[Leaf]`). The Quint simulator
handles this fine (thousands of samples), but Apalache's symbolic encoding of
"sets of records containing maps of records containing sets" explodes past **2
unrolled steps** (depth 2 verifies in ~10s; depth 3+ does not terminate). So
`quint verify` currently gives a genuine but shallow (≤2-step) bounded proof, and
the CI `apalache` job is pinned to `--max-steps=2` for that reason.

To make Apalache verification tractable at useful depths, push the
snapshot-as-root abstraction **all the way into the protocol layer**: represent a
root as an opaque token (e.g. an `int` id or a free-typed root handle) in
`chain`/`local`/`Delta`, and keep the rich `Snapshot`/`Leaf` semantics confined to
`membership.qnt` (already covered by the simulator + the MBT conformance harness).
The protocol layer reasons only about root *identity* and *anchoring* — which is
all `forkSafety`/`revocationSafety` need (they compare roots for equality and check
chain-anchoring, never inspect leaf contents). This shrinks the protocol state
dramatically and should let `quint verify` reach the depths the simulator already
explores. Treat the membership↔protocol boundary (an abstraction function from a
concrete `Snapshot` to its abstract root id) as the thing the MBT layer pins down.

## Open questions

None blocking. The liveness-as-quiescence approach and the snapshot-as-root
abstraction are accepted design decisions, not unknowns. Instance sizes for
`quint verify` may need tuning once Apalache runtimes are measured on the actual
properties; this is an empirical knob, not a design risk.
