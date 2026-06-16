# Quint Abstract-Root Remodel — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite `quint/protocol.qnt` to represent roots as opaque `int` tokens plus a `rootMembers` side-table (instead of full trie `Snapshot` maps), so Apalache `quint verify` is tractable at depth ≥5, while the two safety properties and the org-secret lemma still hold.

**Architecture:** Single-module in-place rewrite of `protocol.qnt`. Protocol state becomes ints + small string-sets (`chain.root: int`, `local[m].root: int`, `rootMembers: int -> Set[str]`, `nextRoot`), envelopes carry `{base, result}` int transitions, the member-set is read from `rootMembers`, and the on-chain anchor is an int equality. `membership.qnt`, `membership_mbt.qnt`, and the MBT harness are untouched. Properties keep their M2 meaning.

**Tech Stack:** Quint 0.32. Local simulator runs use `--backend=typescript`. Apalache `quint verify` needs JVM + writable `$HOME`: locally use `HOME=/tmp/fakehome JAVA_HOME=$(/usr/libexec/java_home) PATH=$JAVA_HOME/bin:$PATH` with the Bash sandbox disabled; in CI it's the `apalache` job.

---

> **Spec:** `docs/superpowers/specs/2026-06-16-quint-abstract-root-remodel-design.md`.
>
> **Validated by spike (quint 0.32 + Apalache 0.56.1):** the abstract representation
> typechecks, the simulator passes `forkSafety`, and **Apalache verifies `forkSafety`
> at `--max-steps=5` in ~6s** (the concrete M2 model timed out at depth 3). Depth 10
> was the next wall in the reduced spike. So depth ≥5 (the acceptance target) is
> achievable; the full model's exact ceiling is measured in Task 3.
>
> **Environment recipe (local Apalache):**
> ```
> export HOME=/tmp/fakehome
> export JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-26.jdk/Contents/Home
> export PATH="$JAVA_HOME/bin:$PATH"
> ```
> Run Apalache commands with the Bash sandbox disabled. Simulator (`quint run`/`quint
> test`) needs only `--backend=typescript`, no special env.

## Scope

IN: rewrite `protocol.qnt` (state, actions, adversaries, properties) to abstract
roots; update `ods_instances.qnt` witnesses; measure and record the Apalache depth
ceiling; negative controls; raise CI `apalache --max-steps`; update README.

OUT: any change to `membership.qnt` / `membership_mbt.qnt` / the MBT harness; new
properties or adversaries (Milestone 3); content-derived root ids (removal-only
makes fresh ids sufficient — see spec).

## File Structure

| File | Change |
|------|--------|
| `quint/protocol.qnt` | **Rewritten in place** — Task 1 replaces the whole file. |
| `quint/ods_instances.qnt` | Witnesses updated for the new `isSettled` arity — Task 2. |
| `.github/workflows/quint.yml` | `apalache` job `--max-steps` raised to the measured ceiling — Task 5. |
| `quint/README.md` | Protocol + Apalache paragraphs updated — Task 5. |

**Naming (unchanged from M2 except the new bits):** state vars `chain`, `local`,
`network`, `rootMembers`, `nextRoot`, `orgKnows`, `objToken`, `tokenKnows`,
`revoked`, `acceptedWrites`, `nextTag`. Helpers `membersOf`, `honestMembers`,
`getOrEmpty`, `memberKey`, `isSettled`. Properties `forkSafety`, `revocationSafety`,
`revokedExcludedFromOrgSecret`. `isSettled` takes `rootMembers` as a parameter
(`rm`) for symmetry with its other args.

---

## Task 1: Rewrite `protocol.qnt` with abstract roots

**Files:**
- Modify (full replace): `quint/protocol.qnt`

- [ ] **Step 1: Replace the ENTIRE contents of `quint/protocol.qnt` with:**

```quint
// -*- mode: Bluespec; -*-
/// Distributed ODS Phase 1 protocol state machine (Milestone 2: protocol safety),
/// abstract-root representation: roots are opaque int tokens with a `rootMembers`
/// side-table, so Apalache `quint verify` is tractable at depth. The rich
/// Snapshot/Leaf/applyDelta semantics live in membership.qnt (simulator + MBT).
///
/// Faithfulness assumption (see spec): fresh monotonic root ids are faithful while
/// membership only ever SHRINKS (removals), so no two reachable roots share a
/// member-set. Revisit this if a future milestone adds member re-addition.
module protocol {
  import membership.* from "./membership"

  type Principal = str
  type ChainState = { epoch: int, root: int, orgGen: int }
  type LocalView  = { epoch: int, root: int, orgGen: int }

  type Envelope =
    | OnChainUpdate(ChainState)
    | DeltaMsg({ base: int, result: int })
    | OrgSecretMsg({ gen: int, epoch: int })
    | WriteOp({ obj: str, author: Key, epoch: int })
  type TaggedEnv = { tag: int, env: Envelope }

  // ---- concrete small instance ----
  pure val MEMBERS: Set[str] = Set("alice", "bob", "carol")
  pure val ADMINS: Set[str] = Set("a1", "a2")
  pure val THRESHOLD: int = 2
  pure val OBJECTS: Set[str] = Set("o1")
  pure val ORG: str = "org"

  pure def memberKey(m: str, g: int): Key = { owner: m, gen: g }

  // ---- state ----
  var chain: ChainState
  var local: str -> LocalView
  var network: Set[TaggedEnv]
  var rootMembers: int -> Set[str]      // root id -> member set
  var nextRoot: int                     // fresh-id counter for root tokens
  var orgKnows: int -> Set[Principal]   // org-key gen -> holders
  var objToken: str -> { id: int, epoch: int }  // object -> current CGKA token
  var tokenKnows: int -> Set[Principal] // CGKA token id -> holders
  var revoked: Set[Principal]
  var acceptedWrites: Set[{ obj: str, author: Key, epoch: int }]
  var nextTag: int

  pure val initView: LocalView = { epoch: 0, root: 0, orgGen: 0 }

  action init = all {
    chain' = { epoch: 0, root: 0, orgGen: 0 },
    local' = MEMBERS.mapBy(_ => initView),
    network' = Set(),
    rootMembers' = Map(0 -> MEMBERS),
    nextRoot' = 1,
    orgKnows' = Map(0 -> MEMBERS),
    objToken' = OBJECTS.mapBy(_ => { id: 0, epoch: 0 }),
    tokenKnows' = Map(0 -> MEMBERS),
    revoked' = Set(),
    acceptedWrites' = Set(),
    nextTag' = 0,
  }

  // ---- helpers ----
  pure def membersOf(rm: int -> Set[str], r: int): Set[str] = rm.get(r)
  val honestMembers: Set[str] = MEMBERS
  pure def getOrEmpty(mp: int -> Set[Principal], k: int): Set[Principal] =
    if (mp.keys().contains(k)) mp.get(k) else Set()

  // ADMIN: propose removing `victim`. Mints a fresh root id, records its member
  // set, advances the chain, and seeds on-chain update + delta + org secret.
  action adminProposeRemoval = {
    nondet victim = membersOf(rootMembers, chain.root).oneOf()
    val nr = nextRoot
    val newChain = { epoch: chain.epoch + 1, root: nr, orgGen: chain.orgGen + 1 }
    all {
      membersOf(rootMembers, chain.root).size() > 1,
      rootMembers' = rootMembers.put(nr, membersOf(rootMembers, chain.root).exclude(Set(victim))),
      nextRoot' = nr + 1,
      chain' = newChain,
      network' = network
        .union(Set({ tag: nextTag,     env: OnChainUpdate(newChain) }))
        .union(Set({ tag: nextTag + 1, env: DeltaMsg({ base: chain.root, result: nr }) }))
        .union(Set({ tag: nextTag + 2, env: OrgSecretMsg({ gen: chain.orgGen + 1, epoch: chain.epoch + 1 }) })),
      nextTag' = nextTag + 3,
      revoked' = revoked.union(Set(victim)),
      local' = local, orgKnows' = orgKnows, objToken' = objToken,
      tokenKnows' = tokenKnows, acceptedWrites' = acceptedWrites,
    }
  }

  // MEMBER: fetch a DeltaMsg whose base matches my local root id, and adopt its
  // result iff it equals the chain root id (the on-chain anchor check).
  action memberFetchAndApply = {
    nondet m = honestMembers.oneOf()
    nondet te = network.oneOf()
    all {
      network.size() > 0,
      membersOf(rootMembers, chain.root).contains(m),
      local' = match te.env {
        | DeltaMsg(d) =>
          if (d.base == local.get(m).root and d.result == chain.root)
            local.put(m, { epoch: chain.epoch, root: d.result, orgGen: local.get(m).orgGen })
          else local
        | _ => local
      },
      chain' = chain, network' = network, orgKnows' = orgKnows,
      objToken' = objToken, tokenKnows' = tokenKnows, revoked' = revoked,
      acceptedWrites' = acceptedWrites, nextTag' = nextTag,
      rootMembers' = rootMembers, nextRoot' = nextRoot,
    }
  }

  // MEMBER: receive an OrgSecretMsg; only a current member is added to holders.
  action memberReceiveOrgSecret = {
    nondet m = honestMembers.oneOf()
    nondet te = network.oneOf()
    all {
      network.size() > 0,
      membersOf(rootMembers, chain.root).contains(m),
      orgKnows' = match te.env {
        | OrgSecretMsg(s) => orgKnows.put(s.gen, getOrEmpty(orgKnows, s.gen).union(Set(m)))
        | _ => orgKnows
      },
      chain' = chain, local' = local, network' = network, objToken' = objToken,
      tokenKnows' = tokenKnows, revoked' = revoked,
      acceptedWrites' = acceptedWrites, nextTag' = nextTag,
      rootMembers' = rootMembers, nextRoot' = nextRoot,
    }
  }

  // CGKA: rotate object token to a fresh id held by current members, stamped with
  // the current epoch.
  action cgkaRotate = {
    nondet obj = OBJECTS.oneOf()
    all {
      objToken' = objToken.put(obj, { id: nextTag, epoch: chain.epoch }),
      tokenKnows' = tokenKnows.put(nextTag, membersOf(rootMembers, chain.root)),
      nextTag' = nextTag + 1,
      chain' = chain, local' = local, network' = network, orgKnows' = orgKnows,
      revoked' = revoked, acceptedWrites' = acceptedWrites,
      rootMembers' = rootMembers, nextRoot' = nextRoot,
    }
  }

  // WRITE: a current member's write is accepted (authorship gated on membership).
  action dataObjectWrite = {
    nondet m = honestMembers.oneOf()
    nondet obj = OBJECTS.oneOf()
    all {
      membersOf(rootMembers, chain.root).contains(m),
      acceptedWrites' = acceptedWrites.union(Set({ obj: obj, author: memberKey(m, 0), epoch: chain.epoch })),
      chain' = chain, local' = local, network' = network, orgKnows' = orgKnows,
      objToken' = objToken, tokenKnows' = tokenKnows, revoked' = revoked, nextTag' = nextTag,
      rootMembers' = rootMembers, nextRoot' = nextRoot,
    }
  }

  // NETWORK ADVERSARY: drop an envelope.
  action networkDrop = {
    nondet te = network.oneOf()
    all {
      network.size() > 0,
      network' = network.exclude(Set(te)),
      chain' = chain, local' = local, orgKnows' = orgKnows, objToken' = objToken,
      tokenKnows' = tokenKnows, revoked' = revoked, acceptedWrites' = acceptedWrites,
      nextTag' = nextTag, rootMembers' = rootMembers, nextRoot' = nextRoot,
    }
  }

  // NETWORK ADVERSARY: duplicate an envelope under a fresh tag.
  action networkDuplicate = {
    nondet te = network.oneOf()
    all {
      network.size() > 0,
      network' = network.union(Set({ tag: nextTag, env: te.env })),
      nextTag' = nextTag + 1,
      chain' = chain, local' = local, orgKnows' = orgKnows, objToken' = objToken,
      tokenKnows' = tokenKnows, revoked' = revoked, acceptedWrites' = acceptedWrites,
      rootMembers' = rootMembers, nextRoot' = nextRoot,
    }
  }

  // REVOKED INSIDER: replay an in-flight envelope under a fresh tag.
  action revokedReplay = {
    nondet te = network.oneOf()
    all {
      network.size() > 0,
      revoked.size() > 0,
      network' = network.union(Set({ tag: nextTag, env: te.env })),
      nextTag' = nextTag + 1,
      chain' = chain, local' = local, orgKnows' = orgKnows, objToken' = objToken,
      tokenKnows' = tokenKnows, revoked' = revoked, acceptedWrites' = acceptedWrites,
      rootMembers' = rootMembers, nextRoot' = nextRoot,
    }
  }

  // REVOKED INSIDER: attempt a write with a stale key; never accepted (gated on
  // current membership), but still emits the WriteOp envelope.
  action revokedAttemptWrite = {
    nondet p = revoked.oneOf()
    nondet obj = OBJECTS.oneOf()
    all {
      revoked.size() > 0,
      network' = network.union(Set({ tag: nextTag, env: WriteOp({ obj: obj, author: memberKey(p, 0), epoch: chain.epoch }) })),
      nextTag' = nextTag + 1,
      acceptedWrites' =
        if (membersOf(rootMembers, chain.root).contains(p))
          acceptedWrites.union(Set({ obj: obj, author: memberKey(p, 0), epoch: chain.epoch }))
        else acceptedWrites,
      chain' = chain, local' = local, orgKnows' = orgKnows, objToken' = objToken,
      tokenKnows' = tokenKnows, revoked' = revoked,
      rootMembers' = rootMembers, nextRoot' = nextRoot,
    }
  }

  // ROGUE ADMIN (< THRESHOLD): gossip a delta to a fresh (off-chain) root with no
  // on-chain update. Its result id != chain.root, so honest members drop it.
  action rogueProposeDelta = {
    nondet victim = membersOf(rootMembers, chain.root).oneOf()
    val r = nextRoot
    all {
      membersOf(rootMembers, chain.root).size() > 1,
      rootMembers' = rootMembers.put(r, membersOf(rootMembers, chain.root).exclude(Set(victim))),
      nextRoot' = r + 1,
      network' = network.union(Set({ tag: nextTag, env: DeltaMsg({ base: chain.root, result: r }) })),
      nextTag' = nextTag + 1,
      chain' = chain, local' = local, orgKnows' = orgKnows, objToken' = objToken,
      tokenKnows' = tokenKnows, revoked' = revoked, acceptedWrites' = acceptedWrites,
    }
  }

  action step = any {
    adminProposeRemoval,
    memberFetchAndApply,
    memberReceiveOrgSecret,
    cgkaRotate,
    dataObjectWrite,
    networkDrop,
    networkDuplicate,
    revokedReplay,
    revokedAttemptWrite,
    rogueProposeDelta,
  }

  // ---- Property 1: replay / fork safety ----
  val forkSafety =
    honestMembers.forall(m1 =>
      honestMembers.forall(m2 =>
        (local.get(m1).epoch == local.get(m2).epoch)
          implies (local.get(m1).root == local.get(m2).root)))

  // ---- Property 2: revocation safety ----
  pure def isSettled(obj: str, ch: ChainState, lv: str -> LocalView,
                     tok: str -> { id: int, epoch: int }, rm: int -> Set[str]): bool =
    and {
      membersOf(rm, ch.root).forall(m => lv.get(m).epoch == ch.epoch),
      tok.get(obj).epoch >= ch.epoch,
    }

  val revocationSafety =
    OBJECTS.forall(obj =>
      isSettled(obj, chain, local, objToken, rootMembers) implies and {
        tokenKnows.get(objToken.get(obj).id).intersect(revoked) == Set(),
        acceptedWrites.forall(w =>
          (w.obj == obj and w.epoch == chain.epoch)
            implies membersOf(rootMembers, chain.root).contains(w.author.owner)),
      })

  // ---- Lemma: revoked never holds the current org secret ----
  val revokedExcludedFromOrgSecret =
    (chain.orgGen > 0)
      implies (getOrEmpty(orgKnows, chain.orgGen).intersect(revoked) == Set())
}
```

- [ ] **Step 2: Typecheck**

Run: `quint typecheck quint/protocol.qnt`
Expected: no errors.

- [ ] **Step 3: Check all three invariants on the simulator**

```
quint run --backend=typescript quint/protocol.qnt --invariant=forkSafety --max-steps=16 --max-samples=5000
quint run --backend=typescript quint/protocol.qnt --invariant=revocationSafety --max-steps=16 --max-samples=5000
quint run --backend=typescript quint/protocol.qnt --invariant=revokedExcludedFromOrgSecret --max-steps=16 --max-samples=5000
```
Expected: each `[ok] No violation found`. If any reports a violation, do NOT weaken the property — capture the counterexample, analyze whether it's a transcription error vs a real modeling change, and report BLOCKED.

- [ ] **Step 4: Commit**

```bash
git add quint/protocol.qnt
git commit -m "feat(quint): abstract-root remodel of protocol.qnt (int root tokens + rootMembers)"
```

---

## Task 2: Update `ods_instances.qnt` witnesses for the new `isSettled` arity

**Files:**
- Modify: `quint/ods_instances.qnt`

The only break is the `isSettled` call in `settledWithRevocationReachable`, which
now takes a 5th argument (`rootMembers`). The other two witnesses don't reference
`rootMembers` and need no change.

- [ ] **Step 1: Read the current file**

Run: `cat quint/ods_instances.qnt` — confirm the three witnesses and which references `isSettled`.

- [ ] **Step 2: Update the `isSettled` call**

Change the call in `settledWithRevocationReachable` from
`isSettled(o, chain, local, objToken)` to
`isSettled(o, chain, local, objToken, rootMembers)`.
Leave `membersCanDifferReachable` and `revokedFullyExcludedReachable` unchanged
(they reference `local`, `orgKnows`, `tokenKnows`, `objToken`, `revoked`, `chain` —
all still present and unchanged in type).

- [ ] **Step 3: Typecheck**

Run: `quint typecheck quint/ods_instances.qnt`
Expected: no errors. (If `revokedFullyExcludedReachable` or any witness references a
removed name, update it minimally to the `rootMembers`-based equivalent and note it
— but per the design only the `isSettled` arity should change.)

- [ ] **Step 4: Confirm the three witnesses still find violations (reachability preserved)**

```
quint run --backend=typescript quint/ods_instances.qnt --invariant=settledWithRevocationReachable --max-steps=16 --max-samples=8000
quint run --backend=typescript quint/ods_instances.qnt --invariant=membersCanDifferReachable --max-steps=10 --max-samples=3000
quint run --backend=typescript quint/ods_instances.qnt --invariant=revokedFullyExcludedReachable --max-steps=16 --max-samples=8000
```
Expected: each finds a `[violation]` (= target state reachable). Also sanity:
`quint run --backend=typescript quint/ods_instances.qnt --invariant=forkSafety --max-steps=10 --max-samples=1000` → `[ok]`.

If a witness no longer finds a violation within budget, raise `--max-samples` to
20000; if still none, report it (do not fake).

- [ ] **Step 5: Commit**

```bash
git add quint/ods_instances.qnt
git commit -m "feat(quint): update vacuity witnesses for abstract-root isSettled arity"
```

---

## Task 3: Measure the Apalache verification ceiling

**Files:** none (measurement only; results recorded in the task report and used in Task 5).

This is the acceptance check that justifies the whole remodel.

- [ ] **Step 1: Set the local Apalache environment** (each command below assumes these are exported and the Bash sandbox is disabled):

```
export HOME=/tmp/fakehome
export JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-26.jdk/Contents/Home
export PATH="$JAVA_HOME/bin:$PATH"
```
Confirm `java -version` prints a JDK (17+), and `ls $HOME/.quint` shows `apalache-dist-*` (already downloaded).

- [ ] **Step 2: Verify `forkSafety` at depth 5 (the acceptance floor)**

Run (sandbox disabled): `quint verify quint/protocol.qnt --invariant=forkSafety --max-steps=5`
Expected: `[ok] No violation found` within ~30s. **This is the pass/fail bar — depth 5 must succeed.** If it does NOT (timeout/error), report BLOCKED: the remodel has not achieved its goal and needs investigation (e.g. the `network` set or `local` map, not the former Snapshots, may be the remaining cost).

- [ ] **Step 3: Verify `revocationSafety` at depth 5**

Run: `quint verify quint/protocol.qnt --invariant=revocationSafety --max-steps=5`
Expected: `[ok]`. (May be slower than forkSafety; allow a few minutes.)

- [ ] **Step 4: Probe the ceiling — try depth 7, then 10**

For `D` in 7 then 10: `timeout 300 quint verify quint/protocol.qnt --invariant=forkSafety --max-steps=$D` (sandbox disabled; `pkill -f apalache.jar` between runs). Record which depths complete (`[ok]`) and which time out. The **highest depth that completes within ~5 min** is the "ceiling"; record it.

- [ ] **Step 5: Record the result**

In the task report, state: depth-5 forkSafety/revocationSafety results (must be `[ok]`), and the measured ceiling D\* (highest completing depth). No commit (measurement only). This D\* feeds Task 5's CI setting (`--max-steps = min(D*, 6)` to keep CI runtime bounded).

---

## Task 4: Negative controls (teeth)

**Files:**
- Modify (temporary, reverted): `quint/protocol.qnt`

- [ ] **Step 1: Control A — break the anchor gate, confirm `forkSafety` fails**

In `memberFetchAndApply`, temporarily change the adopt condition so it drops the
chain-anchor check: replace
```
          if (d.base == local.get(m).root and d.result == chain.root)
```
with
```
          if (d.base == local.get(m).root)
```
(adopt any base-matching delta, even a rogue/off-chain one). Run:
`quint run --backend=typescript quint/protocol.qnt --invariant=forkSafety --max-steps=16 --max-samples=8000`
Expected: `[violation]` (two honest members diverge via the rogue delta). Record the
seed. **Revert exactly** and confirm `git diff quint/protocol.qnt` is empty and
`forkSafety` is `[ok]` again.

- [ ] **Step 2: Control B — leak a token to revoked, confirm `revocationSafety` fails**

In `cgkaRotate`, temporarily change
```
      tokenKnows' = tokenKnows.put(nextTag, membersOf(rootMembers, chain.root)),
```
to
```
      tokenKnows' = tokenKnows.put(nextTag, membersOf(rootMembers, chain.root).union(revoked)),
```
Run: `quint run --backend=typescript quint/protocol.qnt --invariant=revocationSafety --max-steps=16 --max-samples=8000`
Expected: `[violation]` (a revoked principal holds a settled object's token). Record
the seed. **Revert exactly**; confirm `git diff quint/protocol.qnt` empty and
`revocationSafety` `[ok]`.

- [ ] **Step 3: No commit** (both mutants reverted; the file must be byte-identical to Task 1's commit). Confirm `git status --porcelain quint/protocol.qnt` is empty.

---

## Task 5: Raise CI Apalache depth + update README

**Files:**
- Modify: `.github/workflows/quint.yml`
- Modify: `quint/README.md`

- [ ] **Step 1: Raise the `apalache` job depth**

In `.github/workflows/quint.yml`, change all three `quint verify ... --max-steps=2`
lines in the `apalache` job to `--max-steps=5` (or, if Task 3 found the ceiling D\*
< 5, use D\*; if comfortably higher, cap at 6 to bound CI runtime). Update the
explanatory comment above them to reflect the abstract-root representation, e.g.:

```yaml
      # Abstract-root representation (roots are int tokens, not Snapshot maps) makes
      # bounded verify tractable to ~depth 5–6 in CI (was depth 2 with the concrete
      # model). Deeper than the simulator is not the goal; the simulator covers
      # breadth. See the abstract-root remodel design spec.
      - run: quint verify quint/protocol.qnt --invariant=forkSafety --max-steps=5
      - run: quint verify quint/protocol.qnt --invariant=revocationSafety --max-steps=5
      - run: quint verify quint/protocol.qnt --invariant=revokedExcludedFromOrgSecret --max-steps=5
```

- [ ] **Step 2: Update `quint/README.md`**

In the "Protocol layer (Milestone 2)" section, update the Apalache paragraph to
state the new reality. Replace the existing `**Apalache \`quint verify\`**` paragraph
with:

```markdown
**Apalache `quint verify`** runs in CI (the `apalache` job) and locally with a JVM.
`protocol.qnt` uses an **abstract-root representation** — roots are opaque `int`
tokens with a `rootMembers: int -> Set[str]` side-table, not full trie `Snapshot`
maps (the rich Snapshot/Leaf semantics live in `membership.qnt`, validated by the
simulator + MBT). This keeps the protocol state small enough for Apalache to verify
`forkSafety`/`revocationSafety` to ~depth 5–6 (the concrete-Snapshot model topped
out at depth 2). The simulator (`quint run --invariant`) still covers greater
breadth. Roots are fresh monotonic ids, which is faithful while membership only
shrinks (removals) — revisit if a later milestone adds member re-addition.
Convergence and the τ-window property arrive in Milestone 3.
```

Also add one line to the "Commands" list noting local Apalache needs
`HOME`/`JAVA_HOME` set (per the plan's environment recipe).

- [ ] **Step 3: Verify the workflow YAML is well-formed and the local commands pass**

Run:
```
quint typecheck quint/protocol.qnt
quint run --backend=typescript quint/protocol.qnt --invariant=forkSafety --max-steps=16 --max-samples=5000
```
Expected: clean + `[ok]`. (YAML: visually confirm 6-space-indented `- run:` steps under the `apalache` job; PyYAML may be unavailable.)

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/quint.yml quint/README.md
git commit -m "ci(quint): raise apalache verify depth for abstract-root model; update README"
```

---

## Self-Review (completed by plan author)

**Spec coverage:**
- Abstract int-token roots + `rootMembers` side-table, `protocol.qnt` rewritten in place → Task 1. ✅
- Actions/adversaries transformed (member-set via `rootMembers`, anchor as int equality, rogue mints fresh off-chain root) → Task 1. ✅
- Properties preserved (`forkSafety`, `revocationSafety` with `isSettled(..., rootMembers)`, lemma) → Task 1; simulator parity checked. ✅
- Witnesses updated + reachability preserved → Task 2. ✅
- **Apalache verify ≥5 (the point of the remodel)** → Task 3 (depth-5 is the pass/fail bar; ceiling measured). ✅
- Negative controls → Task 4; CI depth raised + README → Task 5. ✅
- `membership.qnt` / MBT untouched (no task modifies them) → scope honored. ✅

**Placeholder scan:** none. Task 1 supplies the complete file; every run command is concrete with an expected result. The CI depth uses the measured D\* with an explicit cap rule.

**Type/name consistency:** `chain`/`local`/`rootMembers`/`nextRoot`/`objToken`(`{id,epoch}`)/`tokenKnows`/`orgKnows`/`revoked`/`acceptedWrites`/`nextTag` are assigned in EVERY action (checked: each `all{}` lists all 11 vars). `isSettled` is defined with the `rm` parameter and called with `rootMembers` in both `revocationSafety` (Task 1) and `settledWithRevocationReachable` (Task 2). `memberKey`/`membersOf`/`getOrEmpty`/`honestMembers` defined before use.

**Known empirical risks (validated where it counts):**
- The core representation + depth-5 Apalache tractability was **spiked and confirmed** (6s at depth 5). The full model adds org/CGKA/write/adversary actions; if its depth-5 verify is slower than the spike, Task 3 allows a few minutes and records the real ceiling; depth 5 succeeding is the bar.
- Every action must assign all 11 state vars or quint errors on an unassigned var — the Task-1 file was written to assign all of them in each `all{}`; if quint flags a missing prime, add the `var' = var` stutter for that one (mechanical).
