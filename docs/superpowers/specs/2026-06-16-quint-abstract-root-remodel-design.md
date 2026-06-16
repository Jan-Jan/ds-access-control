# Quint Abstract-Root Remodel of `protocol.qnt` — Design

**Author(s):** [Jan-Jan van der Vyver](mailto:jan-jan@parity.io)
**Status:** In review
**Created:** 2026-06-16
**Last Updated:** 2026-06-16

## Overview

This is a focused refactor of `quint/protocol.qnt` (the Milestone-2 distributed
protocol model). It replaces the full trie `Snapshot` maps carried in protocol
state with **opaque integer root tokens** plus a side-table mapping each token to
its member-set. The goal is to make Apalache `quint verify` tractable beyond
2 unrolled steps while preserving the two safety properties (`forkSafety`,
`revocationSafety`) and the `revokedExcludedFromOrgSecret` lemma.

It addendum-extends the parent design,
[`2026-06-15-quint-protocol-model-design.md`](2026-06-15-quint-protocol-model-design.md),
specifically the "Abstract-root remodel (deferred from Milestone 2)" subsection of
its §Phasing. It is sequenced **before Milestone 3**, so the τ-window / convergence
work builds on the lighter, verifiable representation.

## Problem

Milestone 2's `protocol.qnt` carries full `Snapshot` maps (`MemberId -> Leaf`,
where `Leaf` nests `Set[Key]`) in three places simultaneously: `chain.root`, every
`local[m].root`, and inside every network envelope (`DeltaMsg(Delta)` holds
`baseRoot: Snapshot` and `Set[Leaf]`). Apalache symbolically encodes all of it
("sets of records containing maps of records containing sets"), and unrolling the
transition relation explodes past 2 steps:

| `--max-steps` | Apalache result |
|---|---|
| 1 | `[ok]` ~6s |
| 2 | `[ok]` ~10–13s |
| 3+ | does not terminate (killed) |

The simulator (`quint run --invariant`) handles the rich model fine over thousands
of samples, but Apalache — the only path to an actual bounded *proof* — is capped
at a shallow depth. The protocol's two properties never inspect leaf contents; they
only compare roots for **equality** and check chain **anchoring**, and
`revocationSafety` needs each root's **member-set**. So the full `Snapshot` is more
information than the protocol layer uses.

## Central decision: roots as fresh monotonic int tokens

A root is modeled as an opaque `int` id minted from a counter (`nextRoot`), with a
global side-table `rootMembers: int -> Set[str]` giving each root's member-set.

- **Faithfulness within reachable space.** Real hashing gives equal-content ⇒
  equal-root. Fresh ids do *not* (two equal member-sets reached by different paths
  get different ids). This matters only for the "root-revisit" case (returning to a
  prior member-set). In Milestones 2 and 3 the only membership change is member
  **removal** (monotonically shrinking member-sets), so no two reachable roots
  share a member-set — content-collision never occurs, and fresh ids are faithful
  over the reachable state space. **This is a documented modeling assumption**;
  if a future milestone adds member re-addition (which could revisit a member-set),
  the assumption must be revisited (e.g. switch to content-derived ids then).
- **Why not content-derived ids?** They preserve revisit-equality exactly but
  reintroduce member-set encoding into protocol state — partially undoing the
  blow-up reduction. Rejected for M2/M3 because removal-only makes it unnecessary.
- **Why not uninterpreted types + axioms?** Most abstract, but Quint's support for
  uninterpreted types with axioms is thin; high tool-fighting risk. Rejected.

`membership.qnt` is **not touched**. Its rich `Snapshot`/`Leaf`/`applyDelta`
canonical-form semantics remain the single source of truth and stay validated by
the simulator and the MBT conformance harness (`org-members/tests/mbt_conformance.rs`).
The Snapshot↔root relationship that the protocol now abstracts away is exactly what
the MBT layer already pins down empirically (root-hash equality classes).

## Module strategy: replace `protocol.qnt`

`protocol.qnt` is rewritten in place (not duplicated into a parallel module). One
protocol model, Apalache-verifiable at depth, with the M2 properties re-verified.
Milestone 3 builds directly on it. A parallel concrete+abstract pair was rejected
to avoid drift and double-maintenance as M3 grows.

## State representation

```quint
type ChainState = { epoch: int, root: int, orgGen: int }
type LocalView  = { epoch: int, root: int, orgGen: int }

type Envelope =
  | OnChainUpdate(ChainState)
  | DeltaMsg({ base: int, result: int })   // root-id transition (no Snapshot)
  | OrgSecretMsg({ gen: int, epoch: int })
  | WriteOp({ obj: str, author: Key, epoch: int })
type TaggedEnv = { tag: int, env: Envelope }

var chain: ChainState
var local: str -> LocalView
var network: Set[TaggedEnv]
var rootMembers: int -> Set[str]          // root id -> member set (the side-table)
var nextRoot: int                         // fresh-id counter for root tokens
var orgKnows: int -> Set[str]             // org-key gen -> holders (unchanged)
var objToken: str -> { id: int, epoch: int }  // CGKA token per object (unchanged)
var tokenKnows: int -> Set[str]           // CGKA token id -> holders (unchanged)
var revoked: Set[str]
var acceptedWrites: Set[{ obj: str, author: Key, epoch: int }]
var nextTag: int
```

`Key` (`{owner: str, gen: int}`) is still imported from `membership` for the
`WriteOp` author and the org/CGKA machinery; no `Snapshot`/`Leaf`/`Delta` types
are used in the protocol layer.

`init`: genesis root id `0`, `rootMembers = Map(0 -> MEMBERS)`, `nextRoot = 1`, all
members' `local.root = 0`, `chain = {epoch: 0, root: 0, orgGen: 0}`, the rest as in
M2.

## Actions

Same set and the same three adversary classes as M2; only the data manipulated
changes.

- **`adminProposeRemoval`** — pick `victim ∈ rootMembers[chain.root]`; mint
  `newRoot = nextRoot`; `rootMembers[newRoot] = rootMembers[chain.root] \ {victim}`;
  advance `chain` to `{epoch+1, root: newRoot, orgGen+1}`; `nextRoot += 1`; add
  `victim` to `revoked`; seed `OnChainUpdate(newChain)` + `DeltaMsg({base:
  chain.root, result: newRoot})` + `OrgSecretMsg({gen, epoch})`. Guard
  `rootMembers[chain.root].size() > 1` (never empty the org).
- **`memberFetchAndApply`** — consume a `DeltaMsg d` with `d.base ==
  local[m].root`; adopt **iff `d.result == chain.root`** (set `local[m] = {epoch:
  chain.epoch, root: d.result, orgGen: local[m].orgGen}`); else no-op. This is the
  on-chain anchor check (`verify_against`), now an int equality.
- **`memberReceiveOrgSecret`** — only `m ∈ rootMembers[chain.root]` is added to
  `orgKnows[gen]`.
- **`cgkaRotate`** — `objToken[obj] = {id: nextTag, epoch: chain.epoch}`,
  `tokenKnows[nextTag] = rootMembers[chain.root]`, `nextTag += 1`. (Token ids and
  root ids both draw from `nextTag`/`nextRoot`; they are separate counters and
  separate maps, so no collision concern.)
- **`dataObjectWrite`** — current member appends an accepted write at `chain.epoch`.
- **`networkDrop` / `networkDuplicate`** — unchanged.
- **`rogueProposeDelta`** — mint a fresh id `r = nextRoot` for a rogue member-set
  (`rootMembers[r] = rootMembers[chain.root] \ {victim}`), bump `nextRoot`, and
  gossip `DeltaMsg({base: chain.root, result: r})` with **no** `OnChainUpdate`.
  Since `r ≠ chain.root`, honest members drop it — the anchor defense holds.
- **`revokedReplay` / `revokedAttemptWrite`** — unchanged in intent; writes still
  gated on `rootMembers[chain.root]` membership.

**Faithfulness note (documented):** with fresh ids, a rogue proposing exactly the
chain's next member-set still gets a distinct id and is therefore *ineffective*
rather than coincidentally accepted. Honest members converge on the chain's id via
the legitimate path, so `forkSafety` is unaffected; the attack that matters
(off-chain delta to an unauthorized state) is still defeated by the `== chain.root`
gate.

## Properties

Same meaning as M2; the only change is reading the member-set from `rootMembers`
instead of `Snapshot.keys()`.

```quint
pure def membersOf(rm: int -> Set[str], r: int): Set[str] = rm.get(r)

val forkSafety =
  honestMembers.forall(m1 => honestMembers.forall(m2 =>
    (local.get(m1).epoch == local.get(m2).epoch)
      implies (local.get(m1).root == local.get(m2).root)))

pure def isSettled(obj: str, ch: ChainState, lv: str -> LocalView,
                   tok: str -> { id: int, epoch: int }): bool =
  and {
    membersOf(rootMembers, ch.root).forall(m => lv.get(m).epoch == ch.epoch),
    tok.get(obj).epoch >= ch.epoch,
  }

val revocationSafety =
  OBJECTS.forall(obj =>
    isSettled(obj, chain, local, objToken) implies and {
      tokenKnows.get(objToken.get(obj).id).intersect(revoked) == Set(),
      acceptedWrites.forall(w =>
        (w.obj == obj and w.epoch == chain.epoch)
          implies membersOf(rootMembers, chain.root).contains(w.author.owner)),
    })

val revokedExcludedFromOrgSecret =
  (chain.orgGen > 0)
    implies (getOrEmpty(orgKnows, chain.orgGen).intersect(revoked) == Set())
```

> `isSettled` references the global `rootMembers` directly inside its body (rather
> than taking it as a parameter), since there is a single global table. Keep the
> other params for symmetry with the M2 signature, or simplify to a no-arg `val` —
> the implementer picks whichever typechecks cleanly and reads best, documenting
> the choice. The *meaning* is fixed: settled = current members caught up AND the
> object's token was rotated at/after the current epoch.

## Acceptance criteria

1. **Simulator parity:** `forkSafety`, `revocationSafety`, and
   `revokedExcludedFromOrgSecret` each pass `quint run --invariant` at
   `--max-steps≈16 --max-samples≈5000` (matching M2).
2. **Reachability preserved:** the three `ods_instances.qnt` vacuity witnesses
   still find violations (i.e. the target states remain reachable), updated to read
   `rootMembers` where they referenced `.keys()`.
3. **Deeper Apalache verify — the point of the remodel:** re-run the depth sweep;
   `forkSafety` and `revocationSafety` must `quint verify` cleanly at a depth where
   the M2 model timed out. **Target ≥ 5 steps**; the final task records the new
   practical ceiling (and raises the CI `apalache` job's `--max-steps` to it).
4. **Negative controls still bite:** dropping the `== chain.root` gate breaks
   `forkSafety`; leaking a CGKA token to revoked members breaks `revocationSafety`.
   Both produce counterexamples (simulator and, where fast enough, Apalache).
5. **No collateral damage:** `membership.qnt`, `membership_mbt.qnt`, and the MBT
   harness are unchanged; M1 stays green.

## Non-goals

- No change to `membership.qnt` or the MBT harness.
- No new properties or adversaries (those are Milestone 3).
- No content-derived or uninterpreted root identity (removal-only makes fresh ids
  sufficient; revisit on re-addition if a later milestone introduces it).

## Testing strategy

Incremental, mirroring the M2 build: rewrite `protocol.qnt` section by section
(state → actions → properties → adversaries), re-running the relevant invariant
after each step so a regression is caught immediately. Then update
`ods_instances.qnt`'s witnesses, run the Apalache depth sweep to find and record
the new ceiling, exercise the negative controls, and bump CI. The README's
"Protocol layer" + Apalache paragraphs are updated to the new depth and to note the
abstract-root representation.

## Open questions

None blocking. The fresh-id faithfulness assumption (valid under removal-only) is
the one explicitly-recorded modeling decision; it is revisited only if a future
milestone introduces member re-addition.
