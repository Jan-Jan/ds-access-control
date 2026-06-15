# Quint Protocol Safety — Implementation Plan (Milestone 2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `quint/protocol.qnt` — the distributed ODS Phase 1 state machine on top of the Milestone-1 membership core — and check two safety properties (revocation safety, replay/fork safety) against the network, revoked-insider, and rogue-admin adversaries, using the Quint simulator.

**Architecture:** A single Quint module imports the pure `membership` definitions and adds protocol state (on-chain anchor, per-member local belief, an unordered tagged-envelope network, abstract knowledge sets for the org secret and per-data-object CGKA tokens, and revocation/accepted-write bookkeeping). Honest guarded actions (admin proposes an on-chain update, members observe/fetch-apply/receive-secret, data-object write/read, CGKA rotate) and adversary actions (network deliver/drop/duplicate, revoked-insider replay/write/read, rogue-admin off-chain delta) compose into `step`. Properties are state invariants checked with `quint run --invariant`; named scenario runs and vacuity witnesses live in `quint/ods_instances.qnt`.

**Tech Stack:** Quint 0.32 (Bluespec-family), `quint` CLI. Local runs use `--backend=typescript` (read-only `~/.quint` blocks the rust evaluator). Apalache `quint verify` is a CI/nightly lane only (no JVM in the dev sandbox).

---

> **Execution environment (this sandbox).** Identical to Milestone 1:
> - **Quint local runs:** append `--backend=typescript` to every `quint test` / `quint run`. `quint typecheck` needs no flag. A `run` is a test only if its name ends in `Test`.
> - **`quint verify` (Apalache) does NOT run locally here** — Apalache downloads under a writable `HOME`, but there is no Java runtime. All local property checking uses `quint run --invariant=<name>`. The Apalache `verify` job is added to CI only (writable HOME + JVM there).
> - **Quint map key removal:** no `mapRemove` builtin; rebuild via `s.keys().exclude(toRemove).mapBy(k => s.get(k))`.
> - **Validated constructs (spiked against quint 0.32):** sum types with payloads + `match`; record spread `{ ...rec, field: v }`; `var` of `Set[record]`, of `map`, of record; `nondet x = S.oneOf()` in guarded actions; multi-variable `all { x' = ..., y' = ... }`; `forall`/`implies` invariants; `quint run --invariant` under the TS backend. These all typecheck and run.

## Scope (per spec §Phasing, Milestone 2)

IN scope: `protocol.qnt`; network + revoked-insider + rogue-admin adversaries; **revocation safety** and **replay/fork safety** invariants; abstract knowledge sets (org secret + per-data-object CGKA tokens) and accepted-write bookkeeping needed to express revocation safety; `ods_instances.qnt` scenario runs + vacuity witnesses; CI + README updates.

OUT of scope (Milestone 3): the `clock`/`lastChecked` machinery, the **τ-window** property, the **compromised-key** adversary, and the **convergence** property. Do not add them here.

## Prerequisite state (from Milestone 1, already on `master`)

`quint/membership.qnt` (module `membership`) exports pure types `Key = {owner: str, gen: int}`, `Leaf`, `Snapshot = str -> Leaf`, `Delta`, `Result = Ok(Snapshot) | Err(str)`, `MAX_DEVICES`, and pure ops `genesis`, `addMember`, `deleteMember`, `updateHandle`, `rotateKey`, `addDevice`, `deleteDevice`, `isolate`, `calculateDelta`, `applyDelta`, plus predicates `skeletonsUnique`, `deviceCapOk`. Member ids are strings. Do not modify `membership.qnt` in this milestone.

## File Structure

| File | Responsibility |
|------|----------------|
| `quint/protocol.qnt` | The distributed state machine: protocol types (`Principal`, `Envelope`, `TaggedEnv`), concrete small instance constants, state vars, honest actions, adversary actions, `step`, and the two property invariants + helper predicates. |
| `quint/ods_instances.qnt` | Imports `protocol`; named scenario `run`s (revocation, gating-while-fired, all-devices-stolen) and vacuity-witness `run`s that drive the system into the non-trivial states each property needs. |
| `quint/README.md` | (modify) add a "Protocol layer (Milestone 2)" section: how to run the invariants/scenarios, the adversary/property list, and the Apalache-is-CI-only note. |
| `.github/workflows/quint.yml` | (modify) add `quint typecheck`/`quint run --invariant` steps for `protocol.qnt`, and a separate best-effort `apalache` nightly job. |

**Naming locked for cross-task consistency:**

- `Principal = str` (member ids and the special device/attacker principals are all strings).
- Concrete instance: `MEMBERS = Set("alice", "bob", "carol")`, `ADMINS = Set("a1", "a2")`, `THRESHOLD = 2`, `OBJECTS = Set("o1")`. `ORG = "org"` (owner string for the org key).
- `Envelope = OnChainUpdate({epoch: int, root: Snapshot, orgGen: int}) | DeltaMsg(Delta) | OrgSecretMsg({gen: int, epoch: int}) | WriteOp({obj: str, author: Key, epoch: int})`.
- `TaggedEnv = { tag: int, env: Envelope }`.
- State var names: `chain`, `local`, `network`, `orgKnows`, `objToken`, `tokenKnows`, `revoked`, `acceptedWrites`, `nextTag`.
- Property invariant names: `forkSafety`, `revocationSafety`. Helper predicates: `honestMembers`, `currentMembers`, `settled`.

---

## Task 1: `protocol.qnt` skeleton — types, constants, state vars, `init`

**Files:**
- Create: `quint/protocol.qnt`

- [ ] **Step 1: Create the module with types, constants, state, and `init`**

```quint
// -*- mode: Bluespec; -*-
/// Distributed ODS Phase 1 protocol state machine (Milestone 2: protocol safety).
/// Imports the pure membership core; models the on-chain anchor, per-member
/// local belief, an unordered tagged-envelope network, abstract knowledge sets
/// for the org secret and per-data-object CGKA tokens, and revocation /
/// accepted-write bookkeeping. Properties: revocation safety, replay/fork safety.
module protocol {
  import membership.* from "./membership"

  type Principal = str

  type ChainState = { epoch: int, root: Snapshot, orgGen: int }
  type LocalView  = { epoch: int, root: Snapshot, orgGen: int }

  type Envelope =
    | OnChainUpdate(ChainState)
    | DeltaMsg(Delta)
    | OrgSecretMsg({ gen: int, epoch: int })
    | WriteOp({ obj: str, author: Key, epoch: int })

  type TaggedEnv = { tag: int, env: Envelope }

  // ---- concrete small instance ----
  pure val MEMBERS: Set[str] = Set("alice", "bob", "carol")
  pure val ADMINS: Set[str] = Set("a1", "a2")
  pure val THRESHOLD: int = 2
  pure val OBJECTS: Set[str] = Set("o1")
  pure val ORG: str = "org"

  // a device key for member m at generation g; member key for m at gen g.
  // Quint strings have no concatenation, so device keys are distinguished from
  // member keys by a separate generation range (1000+) rather than an owner
  // suffix. Devices are not separate principals in Milestone 2, so this only
  // needs to be structurally distinct from the member key.
  pure def memberKey(m: str, g: int): Key = { owner: m, gen: g }
  pure def deviceKey(m: str, g: int): Key = { owner: m, gen: 1000 + g }

  // a genesis leaf for member m (1 device, gen 0), skeleton == handle == m
  pure def genesisLeaf(m: str): Leaf = {
    id: m, handle: m, skeleton: m, name: "n", surname: "s",
    pKey: memberKey(m, 0), devices: Set(deviceKey(m, 0)),
  }

  pure val genesisSnap: Snapshot = MEMBERS.fold(Map(), (acc, m) => acc.put(m, genesisLeaf(m)))

  // ---- state ----
  var chain: ChainState
  var local: str -> LocalView
  var network: Set[TaggedEnv]
  var orgKnows: int -> Set[Principal]   // org key generation -> principals holding that secret
  var objToken: str -> int              // data object -> current CGKA token id (epoch-stamped)
  var tokenKnows: int -> Set[Principal] // CGKA token id -> principals holding it
  var revoked: Set[Principal]           // members removed from the trie at some point
  var acceptedWrites: Set[{ obj: str, author: Key, epoch: int }]
  var nextTag: int

  pure val initView: LocalView = { epoch: 0, root: genesisSnap, orgGen: 0 }

  action init = all {
    chain' = { epoch: 0, root: genesisSnap, orgGen: 0 },
    local' = MEMBERS.mapBy(_ => initView),
    network' = Set(),
    orgKnows' = Map(0 -> MEMBERS),
    objToken' = OBJECTS.mapBy(_ => 0),
    tokenKnows' = Map(0 -> MEMBERS),
    revoked' = Set(),
    acceptedWrites' = Set(),
    nextTag' = 0,
  }

  // ---- helpers ----
  pure def currentMembers(s: Snapshot): Set[str] = s.keys()
  val honestMembers: Set[str] = MEMBERS

  // a trivial step so the module runs; replaced in later tasks
  action step = all {
    chain' = chain, local' = local, network' = network,
    orgKnows' = orgKnows, objToken' = objToken, tokenKnows' = tokenKnows,
    revoked' = revoked, acceptedWrites' = acceptedWrites, nextTag' = nextTag,
  }
}
```

- [ ] **Step 2: Typecheck**

Run: `quint typecheck quint/protocol.qnt`
Expected: no errors.

- [ ] **Step 3: Smoke-run `init` reaches a state**

Run: `quint run --backend=typescript quint/protocol.qnt --max-steps=1 --max-samples=1`
Expected: `[ok]` (the trivial `step` stutters; a run of length ≤1 succeeds).

- [ ] **Step 4: Commit**

```bash
git add quint/protocol.qnt
git commit -m "feat(quint): protocol.qnt skeleton — types, constants, state, init"
```

---

## Task 2: Admin on-chain update + member observe/fetch-apply

**Files:**
- Modify: `quint/protocol.qnt`

This task adds the honest happy path: an admin proposes a new trie (removing one member to model revocation), posts an `OnChainUpdate` + seeds a `DeltaMsg` and `OrgSecretMsg`, and members fetch+apply the delta and receive the new org secret. Replace the trivial `step` with these named actions wired into `any`.

- [ ] **Step 1: Add admin + member actions (insert before the `step` definition)**

```quint
  // True iff `s2` is a legal next trie reachable from `s` by one honest removal
  // of a current member (the only membership change M2 needs to exercise).
  pure def removeOne(s: Snapshot, m: str): Snapshot =
    s.keys().exclude(Set(m)).mapBy(k => s.get(k))

  // ADMIN: propose removing member `victim`. Bumps epoch + org gen, posts the
  // on-chain update, and seeds the delta + org-secret envelopes into the network.
  action adminProposeRemoval = {
    nondet victim = chain.root.keys().oneOf()
    val newRoot = removeOne(chain.root, victim)
    val d = calculateDelta(chain.root, newRoot)
    val newChain = { epoch: chain.epoch + 1, root: newRoot, orgGen: chain.orgGen + 1 }
    all {
      chain.root.keys().size() > 1,            // never empty the org
      chain' = newChain,
      network' = network
        .union(Set({ tag: nextTag,     env: OnChainUpdate(newChain) }))
        .union(Set({ tag: nextTag + 1, env: DeltaMsg(d) }))
        .union(Set({ tag: nextTag + 2, env: OrgSecretMsg({ gen: chain.orgGen + 1, epoch: chain.epoch + 1 }) })),
      nextTag' = nextTag + 3,
      revoked' = revoked.union(Set(victim)),
      local' = local, orgKnows' = orgKnows, objToken' = objToken,
      tokenKnows' = tokenKnows, acceptedWrites' = acceptedWrites,
    }
  }

  // MEMBER: fetch a DeltaMsg whose base matches my local root, apply+verify
  // against the chain root (mirrors apply_delta(...).verify_against(...)).
  action memberFetchAndApply = {
    nondet m = honestMembers.oneOf()
    nondet te = network.oneOf()
    all {
      network.size() > 0,
      currentMembers(chain.root).contains(m),  // only current members act
      match te.env {
        | DeltaMsg(d) => d.baseRoot == local.get(m).root
        | _ => false
      },
      match te.env {
        | DeltaMsg(d) =>
          match applyDelta(local.get(m).root, d) {
            | Ok(s2) =>
              if (s2 == chain.root)
                local' = local.put(m, { epoch: chain.epoch, root: s2, orgGen: local.get(m).orgGen })
              else local' = local
            | Err(_) => local' = local
          }
        | _ => local' = local
      },
      chain' = chain, network' = network, orgKnows' = orgKnows,
      objToken' = objToken, tokenKnows' = tokenKnows, revoked' = revoked,
      acceptedWrites' = acceptedWrites, nextTag' = nextTag,
    }
  }
```

- [ ] **Step 2: Replace the trivial `step` with**

```quint
  action step = any {
    adminProposeRemoval,
    memberFetchAndApply,
  }
```

- [ ] **Step 3: Typecheck**

Run: `quint typecheck quint/protocol.qnt`
Expected: no errors. (If quint rejects a `match` used directly as an action disjunct or a `match` arm assigning `local'`, wrap each arm body as a complete action and ensure every arm assigns `local'`; the structure above assigns `local'` in every arm.)

- [ ] **Step 4: Witness run — a member can advance to the chain root**

Add this temporary witness invariant at the end of the module:

```quint
  // NEGATION witness: "no honest current member has caught up to a post-genesis
  // chain". If the simulator finds a violation, catch-up is reachable.
  val noCatchUpWitness =
    not(honestMembers.exists(m =>
      currentMembers(chain.root).contains(m) and local.get(m).epoch == chain.epoch and chain.epoch > 0))
```

Run: `quint run --backend=typescript quint/protocol.qnt --invariant=noCatchUpWitness --max-steps=8 --max-samples=2000`
Expected: a **violation** is found (i.e. catch-up IS reachable) — printed as a counterexample trace ending in a state where a member's epoch equals a positive chain epoch. This proves the happy path works. Record the trace's final state.

- [ ] **Step 5: Remove the temporary witness** (`noCatchUpWitness`) — it was only to prove reachability. Re-run `quint typecheck quint/protocol.qnt` (expect clean).

- [ ] **Step 6: Commit**

```bash
git add quint/protocol.qnt
git commit -m "feat(quint): admin removal proposal + member fetch-and-apply"
```

---

## Task 3: Org-secret distribution + knowledge-set gating

**Files:**
- Modify: `quint/protocol.qnt`

The org secret for the new generation must reach only **current** members; a revoked member must never receive it. This is the membership-layer half of revocation safety.

- [ ] **Step 1: Add the org-secret receive action (insert before `step`)**

```quint
  // MEMBER: receive an OrgSecretMsg. Only a current member (per chain root) is
  // added to the holders of that org-key generation. Revoked principals are
  // structurally excluded.
  action memberReceiveOrgSecret = {
    nondet m = honestMembers.oneOf()
    nondet te = network.oneOf()
    all {
      network.size() > 0,
      currentMembers(chain.root).contains(m),
      match te.env {
        | OrgSecretMsg(s) =>
          orgKnows' = orgKnows.put(s.gen,
            orgKnows.keys().contains(s.gen).then_or(orgKnows.get(s.gen), Set()).union(Set(m)))
        | _ => orgKnows' = orgKnows
      },
      chain' = chain, local' = local, network' = network, objToken' = objToken,
      tokenKnows' = tokenKnows, revoked' = revoked,
      acceptedWrites' = acceptedWrites, nextTag' = nextTag,
    }
  }
```

> Note: quint has no `then_or`; use a small inline helper. Add this pure def near the other helpers:
> ```quint
>   pure def getOrEmpty(mp: int -> Set[Principal], k: int): Set[Principal] =
>     if (mp.keys().contains(k)) mp.get(k) else Set()
> ```
> Then the arm body becomes:
> ```quint
>         | OrgSecretMsg(s) =>
>           orgKnows' = orgKnows.put(s.gen, getOrEmpty(orgKnows, s.gen).union(Set(m)))
> ```
> Use the `getOrEmpty` form (delete the `then_or` line).

- [ ] **Step 2: Add `memberReceiveOrgSecret` to `step`'s `any { ... }`.**

- [ ] **Step 3: Typecheck** — `quint typecheck quint/protocol.qnt` (expect clean).

- [ ] **Step 4: Witness — the new org-gen secret reaches a current member but never a revoked one**

Add temporary witness:

```quint
  val revokedNeverGetsNewSecretWitness =
    orgKnows.keys().forall(g =>
      (g == chain.orgGen and chain.orgGen > 0)
        implies orgKnows.get(g).intersect(revoked) == Set())
```

Run: `quint run --backend=typescript quint/protocol.qnt --invariant=revokedNeverGetsNewSecretWitness --max-steps=10 --max-samples=3000`
Expected: `[ok]` — NO violation (a revoked principal never holds the current org secret). This is a genuine invariant, so it should hold.

- [ ] **Step 5: Keep `revokedNeverGetsNewSecretWitness`** (it is a real sub-property; rename it to `revokedExcludedFromOrgSecret` and leave it in the module as a documented lemma). Re-typecheck.

- [ ] **Step 6: Commit**

```bash
git add quint/protocol.qnt
git commit -m "feat(quint): org-secret distribution gated to current members"
```

---

## Task 4: Data objects — CGKA token rotation, write, read

**Files:**
- Modify: `quint/protocol.qnt`

Revocation safety's "ex-member can't read new data / have writes accepted" needs the data-object layer: a CGKA token per object, rotated to mint a fresh token held only by current members; writes accepted only from current members; reads gated on token holding.

- [ ] **Step 1: Add CGKA + data-object actions (insert before `step`)**

```quint
  // CGKA: rotate object `obj`'s token to a fresh id (use nextTag as a unique id
  // source), held by exactly the current members. Models post-revocation rekey.
  action cgkaRotate = {
    nondet obj = OBJECTS.oneOf()
    all {
      objToken' = objToken.put(obj, nextTag),
      tokenKnows' = tokenKnows.put(nextTag, currentMembers(chain.root)),
      nextTag' = nextTag + 1,
      chain' = chain, local' = local, network' = network, orgKnows' = orgKnows,
      revoked' = revoked, acceptedWrites' = acceptedWrites,
    }
  }

  // WRITE: a current member emits a WriteOp on `obj`; it is accepted iff the
  // author is a current member (write-acceptance falls back to the trie).
  action dataObjectWrite = {
    nondet m = honestMembers.oneOf()
    nondet obj = OBJECTS.oneOf()
    all {
      currentMembers(chain.root).contains(m),
      acceptedWrites' = acceptedWrites.union(Set({ obj: obj, author: memberKey(m, 0), epoch: chain.epoch })),
      chain' = chain, local' = local, network' = network, orgKnows' = orgKnows,
      objToken' = objToken, tokenKnows' = tokenKnows, revoked' = revoked, nextTag' = nextTag,
    }
  }
```

> `dataObjectRead` is not a state mutation we need to record for the property (reading does not change protocol state); read-gating is expressed directly in the property via `tokenKnows`. Do NOT add a `dataObjectRead` action — YAGNI for M2.

- [ ] **Step 2: Add `cgkaRotate` and `dataObjectWrite` to `step`.**

- [ ] **Step 3: Typecheck** — expect clean.

- [ ] **Step 4: Witness — after rotation, only current members hold the object's token**

```quint
  val tokenHoldersAreCurrentWitness =
    OBJECTS.forall(obj =>
      tokenKnows.get(objToken.get(obj)).subseteq(currentMembers(chain.root).union(Set()))
        or objToken.get(obj) == 0)   // gen-0 token predates any revocation
```

Run: `quint run --backend=typescript quint/protocol.qnt --invariant=tokenHoldersAreCurrentWitness --max-steps=10 --max-samples=2000`
Expected: `[ok]` — holds (a freshly rotated token is held by exactly current members; the gen-0 token is exempted because it predates revocation and is covered by the settled predicate in Task 6).

- [ ] **Step 5: Remove `tokenHoldersAreCurrentWitness`** (subsumed by the revocation-safety property in Task 6). Re-typecheck.

- [ ] **Step 6: Commit**

```bash
git add quint/protocol.qnt
git commit -m "feat(quint): data-object CGKA token rotation + write acceptance"
```

---

## Task 5: Network adversary (deliver / drop / duplicate)

**Files:**
- Modify: `quint/protocol.qnt`

Messages are an unordered set; "deliver" is just that any consuming action may fire on any envelope (already true). The adversary adds explicit **drop** (remove an envelope) and **duplicate** (re-add with a fresh tag). Offline members are modelled by drops + non-scheduling.

- [ ] **Step 1: Add adversary actions (insert before `step`)**

```quint
  // NETWORK ADVERSARY: drop an in-flight envelope.
  action networkDrop = {
    nondet te = network.oneOf()
    all {
      network.size() > 0,
      network' = network.exclude(Set(te)),
      chain' = chain, local' = local, orgKnows' = orgKnows, objToken' = objToken,
      tokenKnows' = tokenKnows, revoked' = revoked, acceptedWrites' = acceptedWrites,
      nextTag' = nextTag,
    }
  }

  // NETWORK ADVERSARY: duplicate an in-flight envelope under a fresh tag.
  action networkDuplicate = {
    nondet te = network.oneOf()
    all {
      network.size() > 0,
      network' = network.union(Set({ tag: nextTag, env: te.env })),
      nextTag' = nextTag + 1,
      chain' = chain, local' = local, orgKnows' = orgKnows, objToken' = objToken,
      tokenKnows' = tokenKnows, revoked' = revoked, acceptedWrites' = acceptedWrites,
    }
  }
```

- [ ] **Step 2: Add `networkDrop`, `networkDuplicate` to `step`.**

- [ ] **Step 3: Typecheck** — expect clean.

- [ ] **Step 4: Run — system still makes progress under the network adversary**

Run: `quint run --backend=typescript quint/protocol.qnt --max-steps=12 --max-samples=200`
Expected: `[ok]` (no invariant given → just checks no runtime error / deadlock-free stepping over 200 samples).

- [ ] **Step 5: Commit**

```bash
git add quint/protocol.qnt
git commit -m "feat(quint): network adversary (drop, duplicate)"
```

---

## Task 6: Replay/fork safety + revocation safety invariants

**Files:**
- Modify: `quint/protocol.qnt`

Now define the two M2 properties as invariants and run them against the honest + network model (adversaries added in Tasks 7–8 will be re-checked).

- [ ] **Step 1: Add the property invariants + `settled` helper (at the end of the module)**

```quint
  // ---- Property 1: replay / fork safety ----
  // Honest members at the same epoch hold the same root.
  val forkSafety =
    honestMembers.forall(m1 =>
      honestMembers.forall(m2 =>
        (local.get(m1).epoch == local.get(m2).epoch)
          implies (local.get(m1).root == local.get(m2).root)))

  // ---- Property 2: revocation safety ----
  // An object is "settled" when every CURRENT honest member has caught up to the
  // chain epoch and the object's token has been rotated at/after the chain epoch
  // (token id != 0, i.e. post-genesis rotation).
  pure def isSettled(obj: str, ch: ChainState, lv: str -> LocalView, tok: str -> int): bool =
    and {
      currentMembers(ch.root).forall(m => lv.get(m).epoch == ch.epoch),
      tok.get(obj) != 0,
    }

  // For every settled object: no revoked principal holds its current token, and
  // every accepted write on it (at the current epoch) is authored by a current member.
  val revocationSafety =
    OBJECTS.forall(obj =>
      isSettled(obj, chain, local, objToken) implies and {
        tokenKnows.get(objToken.get(obj)).intersect(revoked) == Set(),
        acceptedWrites.forall(w =>
          (w.obj == obj and w.epoch == chain.epoch)
            implies currentMembers(chain.root).contains(w.author.owner)),
      })
```

- [ ] **Step 2: Typecheck** — `quint typecheck quint/protocol.qnt` (expect clean).

- [ ] **Step 3: Check fork safety holds (honest + network model)**

Run: `quint run --backend=typescript quint/protocol.qnt --invariant=forkSafety --max-steps=14 --max-samples=5000`
Expected: `[ok]` — no violation.

- [ ] **Step 4: Check revocation safety holds**

Run: `quint run --backend=typescript quint/protocol.qnt --invariant=revocationSafety --max-steps=14 --max-samples=5000`
Expected: `[ok]` — no violation.

- [ ] **Step 5: Commit**

```bash
git add quint/protocol.qnt
git commit -m "feat(quint): forkSafety + revocationSafety invariants"
```

---

## Task 7: Revoked-insider adversary

**Files:**
- Modify: `quint/protocol.qnt`

A revoked member keeps old keys/secrets and tries to (a) replay an old delta, (b) emit a write with its stale key, (c) be counted as a reader. Properties must still hold.

- [ ] **Step 1: Add revoked-insider actions (insert before `step`)**

```quint
  // REVOKED INSIDER: replay any in-flight envelope under a fresh tag (re-inject
  // a stale delta/secret). This is strictly weaker than networkDuplicate but
  // models the ex-member actively resending; kept for intent clarity.
  action revokedReplay = {
    nondet te = network.oneOf()
    all {
      network.size() > 0,
      revoked.size() > 0,
      network' = network.union(Set({ tag: nextTag, env: te.env })),
      nextTag' = nextTag + 1,
      chain' = chain, local' = local, orgKnows' = orgKnows, objToken' = objToken,
      tokenKnows' = tokenKnows, revoked' = revoked, acceptedWrites' = acceptedWrites,
    }
  }

  // REVOKED INSIDER: attempt a write with a stale (revoked) member key. The
  // protocol's write-acceptance must reject it: acceptance is gated on the
  // author being a CURRENT member, so this models the ATTEMPT (added to a
  // separate attempt log is unnecessary — an unaccepted write simply never
  // enters acceptedWrites). To model the adversary trying, we add the write to
  // acceptedWrites ONLY IF the author is current; a revoked author is a no-op
  // on acceptedWrites but still emits the WriteOp envelope.
  action revokedAttemptWrite = {
    nondet p = revoked.oneOf()
    nondet obj = OBJECTS.oneOf()
    all {
      revoked.size() > 0,
      network' = network.union(Set({ tag: nextTag, env: WriteOp({ obj: obj, author: memberKey(p, 0), epoch: chain.epoch }) })),
      nextTag' = nextTag + 1,
      // acceptance fallback: only current members' writes are ever accepted
      acceptedWrites' =
        if (currentMembers(chain.root).contains(p))
          acceptedWrites.union(Set({ obj: obj, author: memberKey(p, 0), epoch: chain.epoch }))
        else acceptedWrites,
      chain' = chain, local' = local, orgKnows' = orgKnows, objToken' = objToken,
      tokenKnows' = tokenKnows, revoked' = revoked,
    }
  }
```

- [ ] **Step 2: Add `revokedReplay`, `revokedAttemptWrite` to `step`.**

- [ ] **Step 3: Typecheck** — expect clean.

- [ ] **Step 4: Re-check both properties under the revoked-insider adversary**

Run: `quint run --backend=typescript quint/protocol.qnt --invariant=forkSafety --max-steps=16 --max-samples=8000`
Expected: `[ok]`.

Run: `quint run --backend=typescript quint/protocol.qnt --invariant=revocationSafety --max-steps=16 --max-samples=8000`
Expected: `[ok]`.

- [ ] **Step 5: Commit**

```bash
git add quint/protocol.qnt
git commit -m "feat(quint): revoked-insider adversary (replay, stale write)"
```

---

## Task 8: Rogue-admin adversary (below threshold)

**Files:**
- Modify: `quint/protocol.qnt`

Below-threshold rogue admins can sign and gossip a well-formed `DeltaMsg` p2p **without** a matching on-chain update. The anchor must reject it: `memberFetchAndApply` only advances a member when the applied root equals `chain.root`, so a rogue delta that does not match the chain is dropped. This task adds the rogue action and confirms fork safety still holds.

- [ ] **Step 1: Add the rogue-admin action (insert before `step`)**

```quint
  // ROGUE ADMIN (< THRESHOLD): gossip a well-formed delta with NO on-chain
  // update. It removes some current member from the CURRENT chain root, so its
  // applied result will NOT equal chain.root and honest members must drop it.
  action rogueProposeDelta = {
    nondet victim = chain.root.keys().oneOf()
    val rogueRoot = removeOne(chain.root, victim)
    val d = calculateDelta(chain.root, rogueRoot)
    all {
      chain.root.keys().size() > 1,
      network' = network.union(Set({ tag: nextTag, env: DeltaMsg(d) })),
      nextTag' = nextTag + 1,
      chain' = chain, local' = local, orgKnows' = orgKnows, objToken' = objToken,
      tokenKnows' = tokenKnows, revoked' = revoked, acceptedWrites' = acceptedWrites,
    }
  }
```

- [ ] **Step 2: Add `rogueProposeDelta` to `step`.**

- [ ] **Step 3: Typecheck** — expect clean.

- [ ] **Step 4: Confirm fork safety + replay safety survive the rogue path**

Run: `quint run --backend=typescript quint/protocol.qnt --invariant=forkSafety --max-steps=18 --max-samples=10000`
Expected: `[ok]` — the rogue delta cannot make two honest members diverge, because acceptance is gated on `== chain.root`.

> Note: a rogue delta whose base matches a member's local root and whose result happens to equal `chain.root` is, by definition, the legitimate change — not an attack. The gate is correct: only chain-anchored roots are ever adopted.

- [ ] **Step 5: Commit**

```bash
git add quint/protocol.qnt
git commit -m "feat(quint): rogue-admin off-chain delta adversary"
```

---

## Task 9: `ods_instances.qnt` — scenario runs + vacuity witnesses

**Files:**
- Create: `quint/ods_instances.qnt`

Named `run`s that (a) prove each property is checked on a non-vacuous state and (b) encode design-doc scenarios. Tests must end in `Test` to be discovered by `quint test`.

- [ ] **Step 1: Create the module**

```quint
// -*- mode: Bluespec; -*-
/// Scenario runs and vacuity witnesses for the protocol layer.
module ods_instances {
  import protocol.* from "./protocol"

  // VACUITY: revocation safety is non-vacuous — drive the system to a settled,
  // post-revocation state and assert the property's PRECONDITION is met there.
  run revocationReachesSettledTest =
    init
      .then(adminProposeRemoval)
      .then(memberFetchAndApply)
      .then(memberFetchAndApply)
      .then(cgkaRotate)
      .then(all {
        assert(OBJECTS.exists(obj => isSettled(obj, chain, local, objToken))),
        // and the property itself holds in this concrete settled state
        assert(revocationSafety),
        // stutter to satisfy the action's next-state obligation
        chain' = chain, local' = local, network' = network, orgKnows' = orgKnows,
        objToken' = objToken, tokenKnows' = tokenKnows, revoked' = revoked,
        acceptedWrites' = acceptedWrites, nextTag' = nextTag,
      })

  // SCENARIO (revocation): after a removal + rotation, the revoked member holds
  // neither the new org secret nor the object token.
  run revokedFullyExcludedTest =
    init
      .then(adminProposeRemoval)
      .then(memberFetchAndApply)
      .then(memberReceiveOrgSecret)
      .then(cgkaRotate)
      .then(all {
        assert(revoked.forall(p =>
          not(orgKnows.get(chain.orgGen).contains(p))
          and OBJECTS.forall(obj => not(tokenKnows.get(objToken.get(obj)).contains(p))))),
        chain' = chain, local' = local, network' = network, orgKnows' = orgKnows,
        objToken' = objToken, tokenKnows' = tokenKnows, revoked' = revoked,
        acceptedWrites' = acceptedWrites, nextTag' = nextTag,
      })
}
```

> If quint rejects `.then(all { assert(...), <stutter> })` as a run step, use the idiom from the quint docs: an assertion in a run is written `.then(assert(<bool>))` only if `assert` is a valid 0-var action in your quint version. If `.then(assert(...))` is NOT accepted, keep the `all { assert(...), <stutter primes> }` form (a guarded action whose body asserts and stutters). Adapt to whichever the installed quint accepts; both express "in this reached state, the predicate holds".

- [ ] **Step 2: Typecheck**

Run: `quint typecheck quint/ods_instances.qnt`
Expected: no errors.

- [ ] **Step 3: Run the scenario tests**

Run: `quint test --backend=typescript quint/ods_instances.qnt`
Expected: `revocationReachesSettledTest` and `revokedFullyExcludedTest` both pass. If a `.then` chain can't reach the asserted state deterministically (because `nondet` picks vary), constrain the picks: replace the nondeterministic actions with explicit-pick variants in the run, or add `nondet`-free helper actions parameterised by the specific member/victim. Document any such helper added.

- [ ] **Step 4: Commit**

```bash
git add quint/ods_instances.qnt
git commit -m "feat(quint): scenario runs + vacuity witnesses for protocol safety"
```

---

## Task 10: Negative controls, CI, README

**Files:**
- Modify: `quint/protocol.qnt` (temporary mutants, reverted)
- Modify: `.github/workflows/quint.yml`
- Modify: `quint/README.md`

- [ ] **Step 1: Negative control A — break the chain-anchor gate, confirm fork safety fails**

In `memberFetchAndApply`, temporarily change the acceptance check so a member adopts the applied root even when it does NOT equal `chain.root`: replace
`if (s2 == chain.root) local' = local.put(...) else local' = local`
with
`local' = local.put(m, { epoch: chain.epoch, root: s2, orgGen: local.get(m).orgGen })` (drop the `== chain.root` guard).
Run: `quint run --backend=typescript quint/protocol.qnt --invariant=forkSafety --max-steps=16 --max-samples=8000`
Expected: a **violation** (two honest members diverge via the rogue delta). Record the counterexample. **Revert** the change exactly and re-run; expect `[ok]`. Confirm `git diff quint/protocol.qnt` is empty.

- [ ] **Step 2: Negative control B — leak the org secret to a revoked member, confirm revocation safety fails**

In `memberReceiveOrgSecret`, temporarily drop the `currentMembers(chain.root).contains(m)` guard AND let any principal (including revoked) be picked: change `nondet m = honestMembers.oneOf()` to `nondet m = honestMembers.union(revoked).oneOf()` and remove the current-member guard.
Run: `quint run --backend=typescript quint/protocol.qnt --invariant=revocationSafety --max-steps=16 --max-samples=8000`
Expected: a **violation** (revoked principal holds the current org secret in a settled state). Record it. **Revert** exactly; re-run expect `[ok]`; confirm `git diff` empty.

- [ ] **Step 3: Update `.github/workflows/quint.yml`** — add protocol steps to the `quint` job and a best-effort Apalache job. Replace the file with:

```yaml
name: quint
on: [push, pull_request]
jobs:
  quint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: "20" }
      - run: npm i -g @informalsystems/quint
      - run: quint typecheck quint/membership.qnt
      - run: quint typecheck quint/membership_mbt.qnt
      - run: quint typecheck quint/protocol.qnt
      - run: quint typecheck quint/ods_instances.qnt
      - run: quint test quint/membership.qnt
      - run: quint test quint/ods_instances.qnt
      - run: quint run quint/membership_mbt.qnt --invariant=mbtInv --max-steps=15 --max-samples=200
      - run: quint run quint/protocol.qnt --invariant=forkSafety --max-steps=16 --max-samples=5000
      - run: quint run quint/protocol.qnt --invariant=revocationSafety --max-steps=16 --max-samples=5000
  mbt:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: "20" }
      - run: npm i -g @informalsystems/quint
      - uses: dtolnay/rust-toolchain@stable
      - run: cd org-members && cargo test --test mbt_conformance
  apalache:
    runs-on: ubuntu-latest
    continue-on-error: true   # bounded verify is best-effort (slow, JVM-heavy)
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: "20" }
      - uses: actions/setup-java@v4
        with: { distribution: "temurin", java-version: "17" }
      - run: npm i -g @informalsystems/quint
      - run: quint verify quint/protocol.qnt --invariant=forkSafety --max-steps=8
      - run: quint verify quint/protocol.qnt --invariant=revocationSafety --max-steps=8
```

- [ ] **Step 4: Append a "Protocol layer (Milestone 2)" section to `quint/README.md`**

```markdown
## Protocol layer (Milestone 2)

`protocol.qnt` is the distributed state machine over `membership`: on-chain anchor
(`chain`), per-member belief (`local`), an unordered tagged-envelope `network`,
abstract knowledge sets (`orgKnows`, `tokenKnows`/`objToken`), and revocation /
accepted-write bookkeeping. `ods_instances.qnt` holds scenario runs and vacuity
witnesses.

Adversaries: network (drop/duplicate), revoked-insider (replay, stale write),
below-threshold rogue admin (off-chain delta).

Properties (checked with the simulator):

- `forkSafety` — honest members at the same epoch hold the same root.
- `revocationSafety` — once an object is settled, no revoked principal holds its
  CGKA token and every accepted write is authored by a current member.

Commands (append `--backend=typescript` locally; CI uses defaults):

- `quint run quint/protocol.qnt --invariant=forkSafety --max-steps=16 --max-samples=5000`
- `quint run quint/protocol.qnt --invariant=revocationSafety --max-steps=16 --max-samples=5000`
- `quint test quint/ods_instances.qnt`

Negative controls (documented, not committed): dropping the `== chain.root` gate
in `memberFetchAndApply` breaks `forkSafety`; leaking the org secret to a revoked
member breaks `revocationSafety`. Both produce simulator counterexamples.

**Apalache `quint verify`** runs only in CI (the `apalache` job): it needs a JVM
and a writable `~/.quint`, neither available in the dev sandbox. Locally, the
`quint run --invariant` simulator is the property checker. Convergence and the
τ-window property arrive in Milestone 3.
```

- [ ] **Step 5: Verify everything still green**

Run:
```
quint typecheck quint/protocol.qnt
quint typecheck quint/ods_instances.qnt
quint run --backend=typescript quint/protocol.qnt --invariant=forkSafety --max-steps=16 --max-samples=5000
quint run --backend=typescript quint/protocol.qnt --invariant=revocationSafety --max-steps=16 --max-samples=5000
quint test --backend=typescript quint/ods_instances.qnt
```
Expected: typechecks clean, both invariants `[ok]`, scenario tests pass.

- [ ] **Step 6: Commit**

```bash
git add quint/README.md .github/workflows/quint.yml
git commit -m "ci(quint): protocol invariants in CI + apalache nightly; README protocol section"
```

---

## Self-Review (completed by plan author)

**Spec coverage (Milestone 2 = "Protocol safety"):**
- `protocol.qnt` distributed state machine (chain/local/network/knowledge sets) → Tasks 1–4. ✅
- Network adversary → Task 5; revoked-insider → Task 7; rogue-admin → Task 8. ✅ (compromised-key is Milestone 3, correctly excluded.)
- `forkSafety` (replay/fork safety) + `revocationSafety` → Task 6, re-checked under each adversary in 7–8. ✅
- `ods_instances.qnt` scenario runs + vacuity witnesses → Task 9. ✅
- Negative controls (teeth) → Task 10 Steps 1–2; CI + README → Task 10 Steps 3–4. ✅
- Apalache `verify` as CI-only lane → Task 10 Step 3 `apalache` job, documented in README. ✅
- Explicitly OUT (Milestone 3): clock/`lastChecked`, τ-window, compromised-key, convergence. Not present. ✅

**Placeholder scan:** No TBD/TODO. Every code step shows concrete Quint. Two steps flag a known quint-version syntax fork (`memberReceiveOrgSecret`'s map-default via `getOrEmpty`; the `.then(assert(...))` vs `all{assert,stutter}` run idiom) with the exact fallback to use — these are adaptation notes, not placeholders.

**Type/name consistency:** State var names (`chain`, `local`, `network`, `orgKnows`, `objToken`, `tokenKnows`, `revoked`, `acceptedWrites`, `nextTag`), `Envelope` variants, helper names (`currentMembers`, `honestMembers`, `removeOne`, `getOrEmpty`, `isSettled`), and invariant names (`forkSafety`, `revocationSafety`) are used consistently across Tasks 1–10. `memberKey`/`deviceKey` signatures match their uses.

**Known empirical risks (flagged, not placeholders):**
- `match` assigning next-state vars inside `all{}` (including a nested `match` on the `applyDelta` result) was **spiked against quint 0.32 and confirmed to typecheck and run** — the core mechanic of Tasks 2–3 is validated. The arm-must-assign-the-var discipline still applies (every arm assigns `local'`/`orgKnows'`/etc.).
- The `.then(all { assert(<bool>), <stutter primes> })` run idiom (Task 9) was **spiked and confirmed** (`smokeTest passed 10000 tests`). The `.then(assert(...))` fallback note can be ignored unless a future quint version changes this.
- `deviceKey` was corrected: Quint strings have **no `++` concatenation** (spike caught this), so device keys use a separate `gen` range instead of an owner suffix.
- Simulator coverage is statistical: `--max-samples` chosen generously; if a property is suspected to fail, raise samples/steps. A clean run is strong evidence, not a proof — Apalache (CI) is the proof path, deferred by the no-JVM sandbox constraint and the spec's design.
