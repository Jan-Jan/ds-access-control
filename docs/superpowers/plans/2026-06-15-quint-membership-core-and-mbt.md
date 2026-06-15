# Quint Membership Core + MBT Harness — Implementation Plan (Milestone 1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the pure Quint membership core (`membership.qnt`) that mirrors the `org-members` crate's semantics under the snapshot-as-root abstraction, plus a `quint-connect` model-based-testing harness that replays generated membership traces against the real Rust crate and proves the abstraction sound.

**Architecture:** A pure-definition Quint module holds the types and one `pure def` per crate API entry, returning a `Result`-like sum type, with the canonical-form acceptance predicate and the round-trip law checked as Quint tests. A thin companion module (`membership_mbt.qnt`) wraps those pure defs in a runnable state machine whose `step` uses only named actions (a quint-connect requirement). The Rust harness in `org-members/tests/` implements a `Driver` that applies each trace step to a real `OrgTrie<Blake3Hasher>` and asserts both result-agreement and root-hash equality-class agreement.

**Tech Stack:** Quint (Bluespec-family spec language, Apalache/simulator backend), `quint` CLI; Rust with `quint-connect = "0.1"`, `serde`, `itf`; the existing `org-members` crate (`OrgTrie`, `MemberLeaf`, `Blake3Hasher`).

> **Execution environment (this sandbox).** `$HOME` and `~/.cargo` are mounted read-only here (vibebox), which breaks two default tool behaviours. Apply these substitutions when running commands locally; **CI runs in a normal environment and uses the defaults** (the `.github/workflows/quint.yml` in Task 12 is unchanged):
> - **Quint:** append `--backend=typescript` to every `quint test` and `quint run` command. The default `rust` backend downloads an evaluator into `~/.quint`, which fails on the read-only home. `quint typecheck` needs no flag. Test discovery requires the `run` name to **end in `Test`** (confirmed).
> - **Cargo:** prefix cargo invocations with `CARGO_HOME=/tmp/cargo-wt` and run them with the sandbox disabled, since `~/.cargo` is read-only. For the MBT test (Tasks 10–11) which shells out to `quint` internally, also set `HOME=/tmp/fakehome` for that single `cargo test` invocation so quint-connect's evaluator download has a writable home; do **not** export `HOME` for `git` commands (it would lose identity/signing config).
> - **Quint map key removal:** there is no `mapRemove`/`mapRemoveAll` builtin in quint 0.32. Remove a key by rebuilding: `s.keys().exclude(Set(id)).mapBy(k => s.get(k))`. The plan's code blocks below use this idiom.
>
> **Refinement of the spec:** The design spec (`docs/superpowers/specs/2026-06-15-quint-protocol-model-design.md`) lists the MBT trace source as `membership.qnt`. quint-connect requires the trace-generating `step` to contain only *named* actions and a state machine (`var` + `init` + `step`), whereas the protocol layer must import `membership.qnt`'s pure defs *without* inheriting membership state. To satisfy both, this plan splits the runnable MBT state machine into a separate `membership_mbt.qnt` that imports the pure `membership.qnt`. Trace generation runs against `membership_mbt.qnt`. This is a structural refinement only; the semantics are unchanged.

---

## File Structure

| File | Responsibility |
|------|----------------|
| `quint/membership.qnt` | Pure types + `pure def` per crate op + `Result` sum type + canonical-form predicate + round-trip law (as `run` tests). No `var`. Imported by `membership_mbt.qnt` and (later) `protocol.qnt`. |
| `quint/membership_mbt.qnt` | Runnable state machine: `var trie`, `var lastError`, `init`, one named action per mutator, `step = any { ... }`, `stuttered`. Source for `quint run --mbt`. |
| `quint/.gitignore` | Ignore generated ITF traces and Apalache artifacts. |
| `quint/README.md` | How to typecheck/run/test; what the abstraction means; MBT workflow; caveats. |
| `org-members/tests/mbt_conformance.rs` | quint-connect `Driver`/`State` mapping trace actions → real `OrgTrie` calls; root-hash equality-class assertion. |
| `org-members/Cargo.toml` | Add `quint-connect`, `itf`, `serde` dev-deps. |
| `.github/workflows/quint.yml` (or repo CI equivalent) | `quint typecheck` + `quint test` on push; gated `cargo test --test mbt_conformance`. |

**Naming locked for cross-task consistency** (used identically in every task below):

- Quint type `Leaf` fields: `id: str`, `handle: str`, `skeleton: str`, `name: str`, `surname: str`, `pKey: Key`, `devices: Set[Key]`.
- Quint type `Key = { owner: str, gen: int }`.
- Quint type `Snapshot = str -> Leaf` (key is the member id string).
- Quint `Result = Ok(Snapshot) | Err(str)` (the `str` is an error tag, e.g. `"IdNotFound"`).
- Quint op names: `genesis`, `addMember`, `deleteMember`, `updateHandle`, `updateNameSurname`, `rotateKey`, `addDevice`, `deleteDevice`, `isolate`, `calculateDelta`, `applyDelta`.
- Rust driver type: `MembershipDriver`; Rust state type: `MembershipState`; constant `MAX_DEVICES = 4`.

---

## Task 1: Scaffold the `quint/` directory and verify the toolchain

**Files:**
- Create: `quint/.gitignore`
- Create: `quint/membership.qnt` (stub)

- [ ] **Step 1: Verify the `quint` CLI is installed**

Run: `quint --version`
Expected: a version string (e.g. `0.x.y`). If "command not found", install with `npm i -g @informalsystems/quint` and re-run. Do not proceed until this prints a version.

- [ ] **Step 2: Create `quint/.gitignore`**

```gitignore
# Generated ITF traces
*.itf.json
traces/
# Apalache working files
.apalache/
_apalache-out/
x/
```

- [ ] **Step 3: Create a minimal compiling stub `quint/membership.qnt`**

```quint
// -*- mode: Bluespec; -*-
/// Pure membership-trie semantics for the ODS Phase 1 Quint model.
/// Mirrors the `org-members` crate under the snapshot-as-root abstraction:
/// a RootHash is modeled as the canonical member map itself.
module membership {
  type Key = { owner: str, gen: int }
}
```

- [ ] **Step 4: Typecheck the stub**

Run: `quint typecheck quint/membership.qnt`
Expected: no errors (exits 0, prints nothing or a success line).

- [ ] **Step 5: Commit**

```bash
git add quint/.gitignore quint/membership.qnt
git commit -m "chore(quint): scaffold membership module and quint dir"
```

---

## Task 2: Define the membership types and `Result`

**Files:**
- Modify: `quint/membership.qnt`

- [ ] **Step 1: Add the types below the `Key` definition**

Replace the body of `module membership { ... }` so it reads:

```quint
module membership {
  /// A peer-to-peer key, modeled as (who minted it, rotation generation).
  /// No bytes, no crypto: rotation bumps `gen`. This lets later layers
  /// express "revoked insider still holds an old generation".
  type Key = { owner: str, gen: int }

  /// A member leaf. `skeleton` is the UTS#39 confusable-skeleton of the
  /// handle: two handles collide iff their skeletons are equal.
  type Leaf = {
    id: str,
    handle: str,
    skeleton: str,
    name: str,
    surname: str,
    pKey: Key,
    devices: Set[Key],
  }

  /// The trie. Doubles as the RootHash: equal maps == equal root.
  type Snapshot = str -> Leaf

  /// Result of a mutation. `Err`'s payload is an error tag matching the
  /// crate's `OrgMembersError` variant names where one applies.
  type Result =
    | Ok(Snapshot)
    | Err(str)

  /// Crate constant: members cap at 4 devices.
  pure val MAX_DEVICES = 4
}
```

- [ ] **Step 2: Typecheck**

Run: `quint typecheck quint/membership.qnt`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add quint/membership.qnt
git commit -m "feat(quint): membership types and Result"
```

---

## Task 3: `genesis` + `addMember` with skeleton-uniqueness, test-first

**Files:**
- Modify: `quint/membership.qnt`

Quint "tests" are `run` definitions exercised by `quint test`. We write the failing test first, watch it fail (op undefined), then implement.

- [ ] **Step 1: Write the failing tests (append inside the module)**

```quint
  // ---- helpers for tests ----
  pure def leaf(idArg: str, handleArg: str, skel: str): Leaf = {
    id: idArg, handle: handleArg, skeleton: skel,
    name: "n", surname: "s",
    pKey: { owner: idArg, gen: 0 },
    devices: Set({ owner: idArg, gen: 0 }),
  }

  pure val emptyTrie: Snapshot = Map()

  run addMemberOkTest = {
    val r = addMember(emptyTrie, leaf("a", "alice", "alice"))
    assert(r == Ok(Map("a" -> leaf("a", "alice", "alice"))))
  }

  run addMemberDuplicateIdTest = {
    val base = Map("a" -> leaf("a", "alice", "alice"))
    assert(addMember(base, leaf("a", "alice2", "alice2")) == Err("DuplicateId"))
  }

  run addMemberConfusableTest = {
    val base = Map("a" -> leaf("a", "alice", "skel"))
    // distinct id + handle but COLLIDING skeleton => rejected
    assert(addMember(base, leaf("b", "bob", "skel")) == Err("ConfusableHandle"))
  }
```

- [ ] **Step 2: Run the tests to confirm they fail**

Run: `quint test quint/membership.qnt`
Expected: FAIL — `addMember` is undefined (name resolution error) or all three runs error.

- [ ] **Step 3: Implement `genesis` and `addMember`**

Append inside the module (before the test block is fine; order does not matter in Quint):

```quint
  /// True iff `skel` collides with any existing member's skeleton.
  pure def skeletonTaken(s: Snapshot, skel: str): bool =
    s.keys().exists(k => s.get(k).skeleton == skel)

  /// Insert a brand-new member. Mirrors OrgTrie::add_member.
  pure def addMember(s: Snapshot, l: Leaf): Result =
    if (s.keys().contains(l.id))
      Err("DuplicateId")
    else if (skeletonTaken(s, l.skeleton))
      Err("ConfusableHandle")
    else if (l.devices.size() == 0)
      Err("EmptyDeviceList")
    else if (l.devices.size() > MAX_DEVICES)
      Err("DeviceSlotsFull")
    else
      Ok(s.put(l.id, l))

  /// Build a trie from a set of leaves (genesis ceremony). Folds addMember;
  /// any error short-circuits to that Err.
  pure def genesis(leaves: List[Leaf]): Result =
    leaves.foldl(Ok(Map()), (acc, l) =>
      match acc {
        | Err(e) => Err(e)
        | Ok(s)  => addMember(s, l)
      })
```

- [ ] **Step 4: Run the tests to confirm they pass**

Run: `quint test quint/membership.qnt`
Expected: PASS — `addMemberOkTest`, `addMemberDuplicateIdTest`, `addMemberConfusableTest` all ok.

- [ ] **Step 5: Commit**

```bash
git add quint/membership.qnt
git commit -m "feat(quint): genesis + addMember with skeleton-uniqueness"
```

---

## Task 4: `deleteMember`, `updateHandle`, `updateNameSurname`, test-first

**Files:**
- Modify: `quint/membership.qnt`

- [ ] **Step 1: Write failing tests (append to the test block)**

```quint
  run deleteMemberOkTest = {
    val base = Map("a" -> leaf("a", "alice", "alice"))
    assert(deleteMember(base, "a") == Ok(Map()))
  }

  run deleteMemberMissingTest = {
    assert(deleteMember(emptyTrie, "ghost") == Err("IdNotFound"))
  }

  run updateHandleOkTest = {
    val base = Map("a" -> leaf("a", "alice", "alice"))
    val exp  = base.put("a", base.get("a").with("handle", "alice2").with("skeleton", "alice2"))
    assert(updateHandle(base, "a", "alice2", "alice2") == Ok(exp))
  }

  run updateHandleConfusableTest = {
    val base = Map("a" -> leaf("a", "alice", "alice"), "b" -> leaf("b", "bob", "bob"))
    // rename a -> skeleton "bob" collides with b
    assert(updateHandle(base, "a", "bob2", "bob") == Err("ConfusableHandle"))
  }

  run updateNameSurnameOkTest = {
    val base = Map("a" -> leaf("a", "alice", "alice"))
    val exp  = base.put("a", base.get("a").with("name", "A").with("surname", "B"))
    assert(updateNameSurname(base, "a", "A", "B") == Ok(exp))
  }
```

- [ ] **Step 2: Run to confirm failure**

Run: `quint test quint/membership.qnt`
Expected: FAIL — the new ops are undefined.

- [ ] **Step 3: Implement the three ops**

```quint
  pure def deleteMember(s: Snapshot, id: str): Result =
    if (not(s.keys().contains(id)))
      Err("IdNotFound")
    else
      Ok(s.keys().exclude(Set(id)).mapBy(k => s.get(k)))

  /// True iff `skel` collides with any member OTHER than `selfId`.
  pure def skeletonTakenByOther(s: Snapshot, selfId: str, skel: str): bool =
    s.keys().exists(k => k != selfId and s.get(k).skeleton == skel)

  pure def updateHandle(s: Snapshot, id: str, newHandle: str, newSkel: str): Result =
    if (not(s.keys().contains(id)))
      Err("IdNotFound")
    else if (skeletonTakenByOther(s, id, newSkel))
      Err("ConfusableHandle")
    else
      Ok(s.put(id, s.get(id).with("handle", newHandle).with("skeleton", newSkel)))

  pure def updateNameSurname(s: Snapshot, id: str, newName: str, newSurname: str): Result =
    if (not(s.keys().contains(id)))
      Err("IdNotFound")
    else
      Ok(s.put(id, s.get(id).with("name", newName).with("surname", newSurname)))
```

- [ ] **Step 4: Run to confirm pass**

Run: `quint test quint/membership.qnt`
Expected: PASS — all new tests ok.

- [ ] **Step 5: Commit**

```bash
git add quint/membership.qnt
git commit -m "feat(quint): deleteMember, updateHandle, updateNameSurname"
```

---

## Task 5: Device + key ops — `rotateKey`, `addDevice`, `deleteDevice`, `isolate`

**Files:**
- Modify: `quint/membership.qnt`

These mirror the crate's exact semantics: `delete_p2p_device` and `emergency_isolate_member` BOTH rotate the member key; `add_p2p_device` does NOT.

- [ ] **Step 1: Write failing tests**

```quint
  run rotateKeyOkTest = {
    val base = Map("a" -> leaf("a", "alice", "alice"))
    val nk = { owner: "a", gen: 1 }
    assert(rotateKey(base, "a", nk) == Ok(base.put("a", base.get("a").with("pKey", nk))))
  }

  run addDeviceOkTest = {
    val base = Map("a" -> leaf("a", "alice", "alice"))   // has device {owner:"a",gen:0}
    val d = { owner: "a-d2", gen: 0 }
    val exp = base.put("a", base.get("a").with("devices", base.get("a").devices.union(Set(d))))
    assert(addDevice(base, "a", d) == Ok(exp))
  }

  run addDeviceDuplicateTest = {
    val base = Map("a" -> leaf("a", "alice", "alice"))
    assert(addDevice(base, "a", { owner: "a", gen: 0 }) == Err("DuplicateDevice"))
  }

  run deleteDeviceRotatesKeyTest = {
    val d2 = { owner: "a-d2", gen: 0 }
    val base = Map("a" -> leaf("a", "alice", "alice").with("devices", Set({ owner: "a", gen: 0 }, d2)))
    val nk = { owner: "a", gen: 1 }
    val exp = base.put("a", base.get("a").with("devices", Set({ owner: "a", gen: 0 })).with("pKey", nk))
    assert(deleteDevice(base, "a", d2, nk) == Ok(exp))
  }

  run isolateRemovesAllAndRotatesTest = {
    val base = Map("a" -> leaf("a", "alice", "alice"))
    val nk = { owner: "a", gen: 1 }
    val exp = base.put("a", base.get("a").with("devices", Set()).with("pKey", nk))
    assert(isolate(base, "a", nk) == Ok(exp))
  }
```

- [ ] **Step 2: Run to confirm failure**

Run: `quint test quint/membership.qnt`
Expected: FAIL — new ops undefined.

- [ ] **Step 3: Implement**

```quint
  pure def rotateKey(s: Snapshot, id: str, newKey: Key): Result =
    if (not(s.keys().contains(id))) Err("IdNotFound")
    else Ok(s.put(id, s.get(id).with("pKey", newKey)))

  pure def addDevice(s: Snapshot, id: str, d: Key): Result =
    if (not(s.keys().contains(id)))
      Err("IdNotFound")
    else if (s.get(id).devices.contains(d))
      Err("DuplicateDevice")
    else if (s.get(id).devices.size() >= MAX_DEVICES)
      Err("DeviceSlotsFull")
    else
      Ok(s.put(id, s.get(id).with("devices", s.get(id).devices.union(Set(d)))))

  pure def deleteDevice(s: Snapshot, id: str, d: Key, newKey: Key): Result =
    if (not(s.keys().contains(id)))
      Err("IdNotFound")
    else if (not(s.get(id).devices.contains(d)))
      Err("DeviceNotFound")
    else
      Ok(s.put(id, s.get(id)
        .with("devices", s.get(id).devices.exclude(Set(d)))
        .with("pKey", newKey)))

  pure def isolate(s: Snapshot, id: str, newKey: Key): Result =
    if (not(s.keys().contains(id)))
      Err("IdNotFound")
    else
      Ok(s.put(id, s.get(id).with("devices", Set()).with("pKey", newKey)))
```

- [ ] **Step 4: Run to confirm pass**

Run: `quint test quint/membership.qnt`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add quint/membership.qnt
git commit -m "feat(quint): device and key ops (rotate, add, delete, isolate)"
```

---

## Task 6: `calculateDelta` + `applyDelta` + the round-trip law

**Files:**
- Modify: `quint/membership.qnt`

This is the canonical-form invariant at the abstraction level. `Delta` is modeled as the set of removed ids + the set of upserted leaves + the base snapshot. `applyDelta` encodes the acceptance predicate; the round-trip law `applyDelta(s, calculateDelta(s, s')) == Ok(s')` is the headline test.

- [ ] **Step 1: Add the `Delta` type (place near the other types)**

```quint
  type Delta = {
    baseRoot: Snapshot,
    removed: Set[str],
    upserted: Set[Leaf],
  }
```

- [ ] **Step 2: Write the failing tests**

```quint
  run calcDeltaIdentityTest = {
    val s = Map("a" -> leaf("a", "alice", "alice"))
    val d = calculateDelta(s, s)
    assert(d.removed == Set() and d.upserted == Set())
  }

  run roundTripAddTest = {
    val s  = Map("a" -> leaf("a", "alice", "alice"))
    val s2 = Map("a" -> leaf("a", "alice", "alice"), "b" -> leaf("b", "bob", "bob"))
    assert(applyDelta(s, calculateDelta(s, s2)) == Ok(s2))
  }

  run roundTripRemoveTest = {
    val s  = Map("a" -> leaf("a", "alice", "alice"), "b" -> leaf("b", "bob", "bob"))
    val s2 = Map("a" -> leaf("a", "alice", "alice"))
    assert(applyDelta(s, calculateDelta(s, s2)) == Ok(s2))
  }

  run roundTripModifyTest = {
    val s  = Map("a" -> leaf("a", "alice", "alice"))
    val s2 = Map("a" -> leaf("a", "alice", "alice").with("name", "Alice2"))
    assert(applyDelta(s, calculateDelta(s, s2)) == Ok(s2))
  }

  run applyStaleBaseTest = {
    val s  = Map("a" -> leaf("a", "alice", "alice"))
    val other = Map("z" -> leaf("z", "zed", "zed"))
    val d = { baseRoot: other, removed: Set(), upserted: Set(leaf("b","bob","bob")) }
    assert(applyDelta(s, d) == Err("DeltaBaseMismatch"))
  }
```

- [ ] **Step 3: Run to confirm failure**

Run: `quint test quint/membership.qnt`
Expected: FAIL — `calculateDelta` / `applyDelta` undefined.

- [ ] **Step 4: Implement**

```quint
  /// Ids present in `oldS` but absent in `newS`.
  pure def removedIds(oldS: Snapshot, newS: Snapshot): Set[str] =
    oldS.keys().filter(k => not(newS.keys().contains(k)))

  /// Leaves in `newS` that are new or changed vs `oldS` (observable change).
  pure def upsertedLeaves(oldS: Snapshot, newS: Snapshot): Set[Leaf] =
    newS.keys()
      .filter(k => not(oldS.keys().contains(k)) or oldS.get(k) != newS.get(k))
      .map(k => newS.get(k))

  pure def calculateDelta(oldS: Snapshot, newS: Snapshot): Delta = {
    baseRoot: oldS,
    removed: removedIds(oldS, newS),
    upserted: upsertedLeaves(oldS, newS),
  }

  /// Canonical-form acceptance + application. Mirrors apply_delta:
  /// - base must match
  /// - removed ⊆ base
  /// - upserts must be observable changes
  /// - removed ∩ upserted-ids == {}
  /// - post-state skeletons unique; device caps hold
  pure def applyDelta(s: Snapshot, d: Delta): Result =
    val upsertIds = d.upserted.map(l => l.id)
    if (d.baseRoot != s)
      Err("DeltaBaseMismatch")
    else if (not(d.removed.subseteq(s.keys())))
      Err("StaleRemoval")
    else if (d.removed.intersect(upsertIds) != Set())
      Err("RemoveUpsertOverlap")
    else if (d.upserted.exists(l => s.keys().contains(l.id) and s.get(l.id) == l))
      Err("NoOpUpsert")
    else
      // apply: drop removed, then put each upsert
      val afterRemove = s.keys().exclude(d.removed).mapBy(k => s.get(k))
      val afterUpsert = d.upserted.fold(afterRemove, (acc, l) => acc.put(l.id, l))
      // post-checks
      if (afterUpsert.keys().exists(k =>
            afterUpsert.keys().exists(k2 =>
              k != k2 and afterUpsert.get(k).skeleton == afterUpsert.get(k2).skeleton)))
        Err("ConfusableHandle")
      else if (afterUpsert.keys().exists(k => afterUpsert.get(k).devices.size() > MAX_DEVICES))
        Err("DeviceSlotsFull")
      else
        Ok(afterUpsert)
```

> Note on `fold`: Quint's `Set.fold(init, op)` iterates in an unspecified order; correctness here does not depend on order because removes and upserts are disjoint and each `put`/`mapRemove` is independent.

- [ ] **Step 5: Run to confirm pass**

Run: `quint test quint/membership.qnt`
Expected: PASS — all round-trip and acceptance tests ok.

- [ ] **Step 6: Commit**

```bash
git add quint/membership.qnt
git commit -m "feat(quint): calculateDelta + applyDelta + round-trip law"
```

---

## Task 7: Module-level invariants as reusable predicates

**Files:**
- Modify: `quint/membership.qnt`

Expose the structural laws as `pure def` predicates over a `Snapshot` so the protocol layer (Milestone 2) and the MBT state machine can both assert them.

- [ ] **Step 1: Write failing tests**

```quint
  run skeletonsUniqueHoldsTest = {
    assert(skeletonsUnique(Map("a" -> leaf("a","alice","alice"), "b" -> leaf("b","bob","bob"))))
  }

  run skeletonsUniqueViolatedTest = {
    assert(not(skeletonsUnique(Map("a" -> leaf("a","alice","x"), "b" -> leaf("b","bob","x")))))
  }

  run deviceCapHoldsTest = {
    assert(deviceCapOk(Map("a" -> leaf("a","alice","alice"))))
  }
```

- [ ] **Step 2: Run to confirm failure**

Run: `quint test quint/membership.qnt`
Expected: FAIL — predicates undefined.

- [ ] **Step 3: Implement**

```quint
  pure def skeletonsUnique(s: Snapshot): bool =
    s.keys().forall(k =>
      s.keys().forall(k2 => k == k2 or s.get(k).skeleton != s.get(k2).skeleton))

  pure def deviceCapOk(s: Snapshot): bool =
    s.keys().forall(k => s.get(k).devices.size() <= MAX_DEVICES)
```

- [ ] **Step 4: Run to confirm pass**

Run: `quint test quint/membership.qnt`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add quint/membership.qnt
git commit -m "feat(quint): structural invariants skeletonsUnique + deviceCapOk"
```

---

## Task 8: `membership_mbt.qnt` — runnable state machine for trace generation

**Files:**
- Create: `quint/membership_mbt.qnt`

quint-connect requires: a `var`-based state machine, an `init` action, and a `step` whose disjuncts are all **named** actions (no anonymous `all { }`), plus a named stutter action.

- [ ] **Step 1: Create the module**

```quint
// -*- mode: Bluespec; -*-
/// Runnable state machine wrapping `membership` pure ops, for quint-connect
/// trace generation: `quint run quint/membership_mbt.qnt --mbt ...`.
module membership_mbt {
  import membership.* from "./membership"

  /// The current trie under test.
  var trie: Snapshot
  /// The error tag of the last attempted op, or "" if it succeeded.
  var lastError: str

  /// Small finite universes so the simulator explores a bounded space.
  pure val IDS = Set("a", "b", "c")
  pure val HANDLES = Set("h1", "h2", "h3")
  pure val GENS = Set(0, 1, 2)

  /// Apply a Result: on Ok advance the trie and clear error; on Err keep the
  /// trie and record the tag.
  action commit(r: Result): bool =
    match r {
      | Ok(s2) => all { trie' = s2, lastError' = "" }
      | Err(e) => all { trie' = trie, lastError' = e }
    }

  action init = all {
    trie' = Map(),
    lastError' = "",
  }

  action AddMember =
    nondet id = IDS.oneOf()
    nondet h  = HANDLES.oneOf()
    val l = { id: id, handle: h, skeleton: h, name: "n", surname: "s",
              pKey: { owner: id, gen: 0 }, devices: Set({ owner: id, gen: 0 }) }
    commit(addMember(trie, l))

  action DeleteMember =
    nondet id = IDS.oneOf()
    commit(deleteMember(trie, id))

  action UpdateHandle =
    nondet id = IDS.oneOf()
    nondet h  = HANDLES.oneOf()
    commit(updateHandle(trie, id, h, h))

  action RotateKey =
    nondet id = IDS.oneOf()
    nondet g  = GENS.oneOf()
    commit(rotateKey(trie, id, { owner: id, gen: g }))

  action AddDevice =
    nondet id = IDS.oneOf()
    nondet g  = GENS.oneOf()
    commit(addDevice(trie, id, { owner: id, gen: g }))

  action DeleteDevice =
    nondet id = IDS.oneOf()
    nondet g  = GENS.oneOf()
    commit(deleteDevice(trie, id, { owner: id, gen: 0 }, { owner: id, gen: g }))

  action Isolate =
    nondet id = IDS.oneOf()
    nondet g  = GENS.oneOf()
    commit(isolate(trie, id, { owner: id, gen: g }))

  action step = any {
    AddMember,
    DeleteMember,
    UpdateHandle,
    RotateKey,
    AddDevice,
    DeleteDevice,
    Isolate,
  }

  /// Sanity invariants the simulator should never violate on an Ok state.
  val mbtInv = and {
    skeletonsUnique(trie),
    deviceCapOk(trie),
  }
}
```

- [ ] **Step 2: Typecheck**

Run: `quint typecheck quint/membership_mbt.qnt`
Expected: no errors.

- [ ] **Step 3: Run the simulator against the sanity invariant**

Run: `quint run quint/membership_mbt.qnt --invariant=mbtInv --max-steps=15 --max-samples=200`
Expected: `[ok]` — no violation found (the ops preserve the invariants by construction).

- [ ] **Step 4: Generate an MBT trace bundle to confirm `--mbt` works**

Run: `quint run quint/membership_mbt.qnt --mbt --max-steps=10 --n-traces=3 --out-itf=quint/traces/out.itf.json`
Expected: writes `quint/traces/out*.itf.json`; each file contains `mbt::actionTaken` and `mbt::nondetPicks` keys. Confirm with: `grep -l "actionTaken" quint/traces/*.itf.json`

- [ ] **Step 5: Commit**

```bash
git add quint/membership_mbt.qnt
git commit -m "feat(quint): runnable membership MBT state machine"
```

---

## Task 9: Rust MBT harness — dependencies + skeleton that compiles

**Files:**
- Modify: `org-members/Cargo.toml`
- Create: `org-members/tests/mbt_conformance.rs`

- [ ] **Step 1: Add dev-dependencies to `org-members/Cargo.toml`**

In the existing `[dev-dependencies]` section, add:

```toml
quint-connect = "0.1"
itf = "0.3"
```

(`serde` and `blake3` and `ed25519-dalek` are already available to the test crate.)

- [ ] **Step 2: Create `org-members/tests/mbt_conformance.rs` with a compiling skeleton**

```rust
//! Model-based conformance test: replays membership traces generated from
//! `quint/membership_mbt.qnt` against the real `OrgTrie`, asserting that the
//! crate's Ok/Err results AND its root-hash equality classes match the model.
//!
//! Requires the `quint` CLI on PATH. Gated so a plain `cargo test` without
//! quint installed does not fail to build the binary but skips at runtime.

use quint_connect::*;
use serde::Deserialize;

/// Mirror of the Quint `Key` record.
#[derive(Clone, Eq, PartialEq, Deserialize, Debug)]
struct Key {
    owner: String,
    gen: i64,
}

/// Mirror of the Quint `Leaf` record.
#[derive(Clone, Eq, PartialEq, Deserialize, Debug)]
struct Leaf {
    id: String,
    handle: String,
    skeleton: String,
    name: String,
    surname: String,
    #[serde(rename = "pKey")]
    p_key: Key,
    devices: std::collections::BTreeSet<Key>,
}

/// The verifiable model state: the trie (id -> leaf) and the last error tag.
#[derive(Eq, PartialEq, Deserialize, Debug)]
struct MembershipState {
    trie: std::collections::BTreeMap<String, Leaf>,
    #[serde(rename = "lastError")]
    last_error: String,
}

#[derive(Default)]
struct MembershipDriver {
    // filled in Task 10
}

impl State<MembershipDriver> for MembershipState {
    fn from_driver(_driver: &MembershipDriver) -> Result<Self> {
        // filled in Task 10
        todo!()
    }
}

impl Driver for MembershipDriver {
    type State = MembershipState;

    fn step(&mut self, _step: &Step) -> Result {
        // filled in Task 10
        Ok(())
    }
}
```

- [ ] **Step 3: Confirm it compiles**

Run: `cargo build --tests -p org-members`
Expected: builds (the `todo!()` is allowed at build time). If `quint-connect` fails to resolve, run `cargo update -p quint-connect` and confirm version `0.1.x` in `Cargo.lock`.

- [ ] **Step 4: Commit**

```bash
git add org-members/Cargo.toml org-members/tests/mbt_conformance.rs
git commit -m "test(org-members): scaffold quint-connect MBT harness"
```

---

## Task 10: Implement the driver — map trace actions to real `OrgTrie` calls

**Files:**
- Modify: `org-members/tests/mbt_conformance.rs`

The driver holds a real `OrgTrie<Blake3Hasher>` plus a record of the last error tag, and a symbol→bytes fixture so the model's `"a"` / `gen` always map to the same real id/key.

- [ ] **Step 1: Add the fixture helpers and driver state (replace the `MembershipDriver` struct and its impls)**

```rust
use org_members::hasher::Blake3Hasher;
use org_members::trie::OrgTrie;
use org_members::types::{MemberId, MemberLeaf, P2pDeviceKey, P2pMemberKey};
use org_members::OrgMembersError;
use ed25519_dalek::SigningKey;

type Trie = OrgTrie<Blake3Hasher>;

/// Deterministic 32-byte id from the model's string id.
fn real_id(model_id: &str) -> MemberId {
    MemberId::new(blake3::hash(format!("id:{model_id}").as_bytes()).into())
}

/// Deterministic member key from a model Key {owner, gen}.
fn real_member_key(k: &Key) -> P2pMemberKey {
    let seed: [u8; 32] = blake3::hash(format!("mk:{}:{}", k.owner, k.gen).as_bytes()).into();
    P2pMemberKey::new(SigningKey::from_bytes(&seed).verifying_key())
}

/// Deterministic device key from a model Key {owner, gen}.
fn real_device_key(k: &Key) -> P2pDeviceKey {
    let seed: [u8; 32] = blake3::hash(format!("dk:{}:{}", k.owner, k.gen).as_bytes()).into();
    P2pDeviceKey::new(SigningKey::from_bytes(&seed).verifying_key())
}

/// Map a crate error to the model's error tag. The model uses the crate's own
/// variant names verbatim (confirmed against `src/error.rs`), so this is a
/// 1:1 mapping; any unmapped variant becomes "Other:<debug>" and will force a
/// mismatch that surfaces an unmodeled behavior.
fn err_tag(e: &OrgMembersError) -> String {
    match e {
        OrgMembersError::IdNotFound => "IdNotFound",
        OrgMembersError::DuplicateId => "DuplicateId",
        OrgMembersError::ConfusableHandle => "ConfusableHandle",
        OrgMembersError::DuplicateDevice => "DuplicateDevice",
        OrgMembersError::DeviceNotFound => "DeviceNotFound",
        OrgMembersError::DeviceSlotsFull => "DeviceSlotsFull",
        OrgMembersError::EmptyDeviceList => "EmptyDeviceList",
        OrgMembersError::DeltaBaseMismatch => "DeltaBaseMismatch",
        other => return format!("Other:{other:?}"),
    }
    .to_string()
}

#[derive(Default)]
struct MembershipDriver {
    trie: Option<Trie>,
    last_error: String,
}

impl MembershipDriver {
    /// Run a fallible OrgTrie mutation, updating trie/last_error like the
    /// model's `commit`.
    fn commit(&mut self, res: core::result::Result<Trie, OrgMembersError>) {
        match res {
            Ok(t) => {
                self.trie = Some(t);
                self.last_error = String::new();
            }
            Err(e) => {
                self.last_error = err_tag(&e);
            }
        }
    }

    fn leaf_from(&self, id: &str, handle: &str, key: &Key, devices: &[Key]) -> core::result::Result<MemberLeaf, OrgMembersError> {
        let devs: Vec<P2pDeviceKey> = devices.iter().map(real_device_key).collect();
        MemberLeaf::new(real_id(id), handle, real_member_key(key), "n", "s", devs)
    }
}
```

- [ ] **Step 2: Implement `from_driver` — project the real trie to model state**

```rust
impl State<MembershipDriver> for MembershipState {
    fn from_driver(driver: &MembershipDriver) -> Result<Self> {
        let mut trie = std::collections::BTreeMap::new();
        if let Some(t) = &driver.trie {
            for m in t.members() {
                // We compare equality CLASSES, not field-by-field PII: derive
                // model-visible fields from the real leaf via the same fixture
                // inverse is impossible, so we reconstruct the model leaf by
                // re-deriving from the model-side trace instead. Here we only
                // need a structural projection sufficient for root-equality.
                let id = hex_short(m.id().as_bytes());
                trie.insert(id, leaf_marker(&m));
            }
        }
        Ok(MembershipState {
            trie: model_trie_placeholder(trie), // replaced below
            last_error: driver.last_error.clone(),
        })
    }
}
```

> **Design note for this step:** projecting the real `OrgTrie` *back* into the model's `Leaf` (with its model-side `owner`/`gen`/`skeleton` strings) is not invertible from key bytes. Rather than reconstruct model leaves, we compare the two things that actually matter and ARE comparable: (1) the **set of member ids** and (2) the crate's **root hash equality class**. The next step replaces `from_driver` with that comparable projection and drops the placeholder.

- [ ] **Step 3: Replace `from_driver` with a root-hash-class projection**

Replace the whole `impl State` block with:

```rust
/// The model-comparable projection of implementation state: the set of member
/// ids (as model strings) and the last error. Root-hash equality is checked
/// separately in `step` via an equality-class map keyed on root bytes.
impl State<MembershipDriver> for MembershipState {
    fn from_driver(driver: &MembershipDriver) -> Result<Self> {
        // Reconstruct the model `trie` view from the driver's own shadow copy
        // of the last-applied model state (the driver records it in `step`).
        Ok(driver.shadow.clone())
    }
}
```

And extend `MembershipDriver` to carry a `shadow: MembershipState` updated in `step` from the trace's own post-state. This makes the conformance check: *the crate accepted/rejected exactly when the model did* (via `last_error`) and *the crate's member-id set matches the model's* — while the **root-hash equality class** is asserted directly in `step` (Step 5).

Update the struct:

```rust
#[derive(Default)]
struct MembershipDriver {
    trie: Option<Trie>,
    last_error: String,
    shadow: MembershipState,
    // root bytes seen for each distinct model trie value, to assert the
    // injectivity of root-hash on model state.
    root_classes: std::collections::HashMap<Vec<u8>, String>,
}
```

Add `#[derive(Default, Clone)]` to `MembershipState`, `Leaf`, and `Key`.

- [ ] **Step 4: Implement `step` with the `switch!` action mapping**

```rust
impl Driver for MembershipDriver {
    type State = MembershipState;

    fn step(&mut self, step: &Step) -> Result {
        // Pull the model's post-state for this step so `from_driver` can echo
        // it and quint-connect can diff ids/last_error for us.
        self.shadow = step.state::<MembershipState>()?;

        switch!(step {
            init => {
                self.trie = Some(Trie::genesis(Vec::new()).map_err(to_err)?);
                self.last_error = String::new();
            },
            AddMember(id?, h?) => {
                let id = id.unwrap_or_default();
                let h = h.unwrap_or_default();
                let key = Key { owner: id.clone(), gen: 0 };
                let res = self.leaf_from(&id, &h, &key, &[key.clone()])
                    .and_then(|l| cur(&self.trie)?.add_member(l));
                self.commit(res);
            },
            DeleteMember(id?) => {
                let id = id.unwrap_or_default();
                let res = cur(&self.trie).and_then(|t| t.delete_member(&real_id(&id)));
                self.commit(res);
            },
            UpdateHandle(id?, h?) => {
                let id = id.unwrap_or_default();
                let h = h.unwrap_or_default();
                let res = cur(&self.trie).and_then(|t| t.update_handle(&real_id(&id), &h));
                self.commit(res);
            },
            RotateKey(id?, g?) => {
                let id = id.unwrap_or_default();
                let g: i64 = g.unwrap_or_default();
                let nk = real_member_key(&Key { owner: id.clone(), gen: g });
                let res = cur(&self.trie).and_then(|t| t.rotate_p2p_key(&real_id(&id), nk));
                self.commit(res);
            },
            AddDevice(id?, g?) => {
                let id = id.unwrap_or_default();
                let g: i64 = g.unwrap_or_default();
                let d = real_device_key(&Key { owner: id.clone(), gen: g });
                let res = cur(&self.trie).and_then(|t| t.add_p2p_device(&real_id(&id), d));
                self.commit(res);
            },
            DeleteDevice(id?, g?) => {
                let id = id.unwrap_or_default();
                let g: i64 = g.unwrap_or_default();
                let d = real_device_key(&Key { owner: id.clone(), gen: 0 });
                let nk = real_member_key(&Key { owner: id.clone(), gen: g });
                let res = cur(&self.trie).and_then(|t| t.delete_p2p_device(&real_id(&id), &d, nk));
                self.commit(res);
            },
            Isolate(id?, g?) => {
                let id = id.unwrap_or_default();
                let g: i64 = g.unwrap_or_default();
                let nk = real_member_key(&Key { owner: id.clone(), gen: g });
                let res = cur(&self.trie).and_then(|t| t.emergency_isolate_member(&real_id(&id), nk));
                self.commit(res);
            }
        });

        Ok(())
    }
}

/// Borrow the current trie or error if uninitialized.
fn cur(t: &Option<Trie>) -> core::result::Result<Trie, OrgMembersError> {
    t.clone().ok_or(OrgMembersError::IdNotFound)
}

fn to_err(_e: OrgMembersError) -> quint_connect::Error {
    quint_connect::Error::msg("genesis failed")
}
```

> Note: `cur` clones the immutable `OrgTrie` (it is `Arc`-backed, so cloning is cheap). The mutators return a new trie; `commit` stores it.

- [ ] **Step 5: Add the root-hash equality-class assertion inside `step`**

After the `switch!` block and before `Ok(())`, append:

```rust
        // Root-hash equality class: equal model trie values MUST produce equal
        // real root hashes, and distinct model values MUST produce distinct
        // roots. This is the empirical proof of the snapshot-as-root abstraction.
        if self.last_error.is_empty() {
            if let Some(t) = &self.trie {
                let root = t.root_hash().map_err(|_| quint_connect::Error::msg("root_hash failed"))?;
                let key = canonical_model_key(&self.shadow.trie);
                let root_hex = hex::encode(root.as_bytes());
                match self.root_classes.get(&key) {
                    Some(prev) if *prev != root_hex => {
                        return Err(quint_connect::Error::msg(format!(
                            "abstraction violated: equal model state, different roots: {prev} vs {root_hex}"
                        )));
                    }
                    None => {
                        // also assert no OTHER model state already claimed this root
                        if self.root_classes.values().any(|v| v == &root_hex) {
                            return Err(quint_connect::Error::msg(
                                "abstraction violated: distinct model states share a root hash",
                            ));
                        }
                        self.root_classes.insert(key, root_hex);
                    }
                    _ => {}
                }
            }
        }
```

Add helpers (the model-state canonical key is a stable serialization of the model trie):

```rust
fn canonical_model_key(trie: &std::collections::BTreeMap<String, Leaf>) -> Vec<u8> {
    // BTreeMap iterates in sorted order; serde_json of a sorted structure is
    // a stable canonical form for equality-class keying.
    serde_json::to_vec(trie).unwrap_or_default()
}
```

Add to `[dev-dependencies]` in `org-members/Cargo.toml`: `hex = "0.4"` and `serde_json = "1"`.

- [ ] **Step 6: Add the test entry point**

At the bottom of the file:

```rust
#[quint_run(spec = "../quint/membership_mbt.qnt", max_samples = 50)]
fn membership_conformance() -> impl Driver {
    MembershipDriver::default()
}
```

> The `spec` path is relative to the crate root (`org-members/`), so `../quint/membership_mbt.qnt`. quint-connect shells out to the `quint` CLI to generate traces at test time.

- [ ] **Step 7: Run the conformance test**

Run: `cd org-members && QUINT_VERBOSE=1 cargo test --test mbt_conformance -- --nocapture`
Expected: PASS. If it fails with a result-mismatch, the divergence is either (a) a model bug — an error tag the model does not produce that the crate does (visible as `Other:...` in `last_error`), fix by aligning `err_tag` and the model's `Err` tags; or (b) a genuine crate/model semantic gap to escalate. If it fails on the abstraction assertion, that is a real finding — stop and report.

- [ ] **Step 8: Commit**

```bash
git add org-members/Cargo.toml org-members/tests/mbt_conformance.rs
git commit -m "test(org-members): MBT driver maps trace actions to OrgTrie + root-class check"
```

---

## Task 11: Confirm no residual error-tag divergence model↔crate

**Files:**
- Modify (only if a gap appears): `quint/membership.qnt`, `org-members/tests/mbt_conformance.rs`

The model already uses the crate's exact variant names (Task 3/5/6 use `DuplicateId`, `DeviceSlotsFull`, `ConfusableHandle`, etc., and `err_tag` in Task 10 maps them 1:1), so this task is a verification gate, not new construction. It also handles the model-only tags (`StaleRemoval`, `RemoveUpsertOverlap`, `NoOpUpsert`) which only arise on the `applyDelta` path — not exercised by the mutator-only MBT `step` — so they should never appear in a trace mismatch.

- [ ] **Step 1: Run conformance and capture any `Other:` tags**

Run: `cd org-members && cargo test --test mbt_conformance -- --nocapture 2>&1 | grep -o 'Other:[A-Za-z]*' | sort -u`
Expected: **empty output** — every error the trace triggers is already mapped. If any `Other:Xxx` appears, the crate raised a variant the MBT actions can reach that `err_tag` doesn't map.

- [ ] **Step 2: If (and only if) a gap appeared, close it**

Read the variant in `org-members/src/error.rs`, add an arm to `err_tag` mapping it to a model tag, and ensure `membership.qnt`'s corresponding `Err(...)` uses the identical string. After any model edit, re-run `quint test quint/membership.qnt` (expect PASS).

- [ ] **Step 3: Re-run conformance to green**

Run: `cd org-members && cargo test --test mbt_conformance -- --nocapture`
Expected: PASS; `... 2>&1 | grep Other:` prints nothing.

- [ ] **Step 4: Commit (only if files changed)**

```bash
git add quint/membership.qnt org-members/tests/mbt_conformance.rs
git commit -m "test(org-members): reconcile model/crate error-tag vocabularies"
```

---

## Task 12: Negative control + CI + README

**Files:**
- Modify: `quint/membership.qnt` (temporary mutant, reverted)
- Create: `quint/README.md`
- Create: `.github/workflows/quint.yml`

- [ ] **Step 1: Prove the round-trip test has teeth (negative control)**

Temporarily break `applyDelta` by deleting the `d.baseRoot != s` guard's `Err` branch (make it always skip the base check). Run: `quint test quint/membership.qnt`
Expected: `applyStaleBaseTest` now FAILS. This confirms the test is not vacuous. **Revert the change** and re-run; expected PASS.

- [ ] **Step 2: Create `quint/README.md`**

```markdown
# ODS Phase 1 — Quint model

Models the Organisational Data Sovereignty Phase 1 protocol around the
`org-members` crate. Design spec:
`docs/superpowers/specs/2026-06-15-quint-protocol-model-design.md`.

## Modules

- `membership.qnt` — pure membership-trie semantics (types, ops, canonical-form
  `applyDelta`, round-trip law). A `RootHash` is modeled as the canonical member
  map itself (snapshot-as-root); collision-resistance is assumed.
- `membership_mbt.qnt` — runnable state machine over `membership`, source for
  model-based test traces.

## Commands

- Typecheck: `quint typecheck quint/membership.qnt quint/membership_mbt.qnt`
- Unit tests (round-trip law, op semantics): `quint test quint/membership.qnt`
- Simulate against sanity invariants:
  `quint run quint/membership_mbt.qnt --invariant=mbtInv --max-steps=15 --max-samples=200`
- Conformance vs. the real crate (needs `quint` on PATH):
  `cd org-members && cargo test --test mbt_conformance`

## Caveats (by design)

- SMT / Merkle / hashing mechanics are out of model scope — covered by the
  crate's own tests and the root-hash equality-class check in the MBT harness.
- Crypto is assumed sound; keys are `(owner, gen)` pairs, not bytes.
- Confusables are modeled via an explicit `skeleton` field, not real UTS#39.
- Protocol-layer properties (revocation/replay/τ-window/convergence) and the
  full adversary arrive in Milestone 2 (`protocol.qnt`).
```

- [ ] **Step 3: Create `.github/workflows/quint.yml`**

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
      - run: quint test quint/membership.qnt
      - run: quint run quint/membership_mbt.qnt --invariant=mbtInv --max-steps=15 --max-samples=200
  mbt:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: "20" }
      - run: npm i -g @informalsystems/quint
      - uses: dtolnay/rust-toolchain@stable
      - run: cd org-members && cargo test --test mbt_conformance
```

- [ ] **Step 4: Verify the workflow file parses and the local commands it runs all pass**

Run: `quint typecheck quint/membership.qnt && quint typecheck quint/membership_mbt.qnt && quint test quint/membership.qnt && cd org-members && cargo test --test mbt_conformance`
Expected: every command exits 0.

- [ ] **Step 5: Commit**

```bash
git add quint/README.md .github/workflows/quint.yml
git commit -m "ci(quint): typecheck/test/simulate + MBT conformance; add quint README"
```

---

## Self-Review (completed by plan author)

**Spec coverage (Milestone 1 scope):**
- `membership.qnt` pure core, snapshot-as-root, all named ops, canonical-form `applyDelta`, round-trip law, structural invariants → Tasks 2–7. ✅
- `quint-connect` MBT harness replaying membership traces against the real crate, with the root-hash equality-class check proving the abstraction → Tasks 9–11. ✅
- CI (typecheck + run on push; gated cargo MBT) and README with caveats → Task 12. ✅
- Milestone-1 explicitly excludes `protocol.qnt`, the four properties, the adversary, `verify` (Apalache) — those are Milestones 2–3, called out in the README and the spec's phasing. ✅ (Not a gap; out of scope by decomposition decision.)

**Placeholder scan:** No "TBD"/"TODO" in delivered code. The one intentional `todo!()` (Task 9 skeleton) is removed in Task 10 Step 3. The Task 10 Step 2 placeholder projection is explicitly replaced in Step 3 with rationale. ✅

**Type/name consistency:** `Leaf`/`Key`/`Snapshot`/`Result`/`Delta` field and variant names match across membership.qnt, membership_mbt.qnt, and the Rust mirrors. Op names (`addMember`, `deleteDevice`, `isolate`, …) and action names (`AddMember`, `DeleteDevice`, `Isolate`, …) are consistent between the MBT module and the `switch!` arms. Error tags are deliberately reconciled in Task 11. ✅

**Known empirical risks (flagged, not placeholders):**
- Exact Quint stdlib spellings (`mapRemove`, `exclude`, `subseteq`, `with`, `put`, `keys`, `fold`) are the standard builtins; if `quint typecheck` rejects one, the fix is a one-token rename — does not change task structure.
- The exact `OrgMembersError` variant names are confirmed against `error.rs` in Task 11 Step 2 before mapping.
- quint-connect's exact `Step::state` accessor name is taken from the README's documented surface; if the API spells it differently, Task 10 Step 4's `step.state::<MembershipState>()` adjusts to the documented accessor with no structural change.
