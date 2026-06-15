// -*- mode: Bluespec; -*-
/// Pure membership-trie semantics for the ODS Phase 1 Quint model.
/// Mirrors the `org-members` crate under the snapshot-as-root abstraction:
/// a RootHash is modeled as the canonical member map itself.
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

  type Delta = {
    baseRoot: Snapshot,
    removed: Set[str],
    upserted: Set[Leaf],
  }

  /// Crate constant: members cap at 4 devices.
  pure val MAX_DEVICES = 4

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

  /// Build a trie from a list of leaves (genesis ceremony). Folds addMember;
  /// any error short-circuits to that Err.
  pure def genesis(leaves: List[Leaf]): Result =
    leaves.foldl(Ok(Map()), (acc, l) =>
      match acc {
        | Err(e) => Err(e)
        | Ok(s)  => addMember(s, l)
      })

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
    assert(addMember(base, leaf("b", "bob", "skel")) == Err("ConfusableHandle"))
  }

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
    assert(updateHandle(base, "a", "bob2", "bob") == Err("ConfusableHandle"))
  }

  run updateNameSurnameOkTest = {
    val base = Map("a" -> leaf("a", "alice", "alice"))
    val exp  = base.put("a", base.get("a").with("name", "A").with("surname", "B"))
    assert(updateNameSurname(base, "a", "A", "B") == Ok(exp))
  }

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

  run rotateKeyOkTest = {
    val base = Map("a" -> leaf("a", "alice", "alice"))
    val nk = { owner: "a", gen: 1 }
    assert(rotateKey(base, "a", nk) == Ok(base.put("a", base.get("a").with("pKey", nk))))
  }

  run addDeviceOkTest = {
    val base = Map("a" -> leaf("a", "alice", "alice"))
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
  /// base must match; removed subseteq base; upserts observable; removed/upserted
  /// disjoint; post-state skeletons unique; device caps hold.
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
      val afterRemove = s.keys().exclude(d.removed).mapBy(k => s.get(k))
      val afterUpsert = d.upserted.fold(afterRemove, (acc, l) => acc.put(l.id, l))
      if (afterUpsert.keys().exists(k =>
            afterUpsert.keys().exists(k2 =>
              k != k2 and afterUpsert.get(k).skeleton == afterUpsert.get(k2).skeleton)))
        Err("ConfusableHandle")
      else if (afterUpsert.keys().exists(k => afterUpsert.get(k).devices.size() > MAX_DEVICES))
        Err("DeviceSlotsFull")
      else
        Ok(afterUpsert)

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

  pure def skeletonsUnique(s: Snapshot): bool =
    s.keys().forall(k =>
      s.keys().forall(k2 => k == k2 or s.get(k).skeleton != s.get(k2).skeleton))

  pure def deviceCapOk(s: Snapshot): bool =
    s.keys().forall(k => s.get(k).devices.size() <= MAX_DEVICES)

  run skeletonsUniqueHoldsTest = {
    assert(skeletonsUnique(Map("a" -> leaf("a","alice","alice"), "b" -> leaf("b","bob","bob"))))
  }

  run skeletonsUniqueViolatedTest = {
    assert(not(skeletonsUnique(Map("a" -> leaf("a","alice","x"), "b" -> leaf("b","bob","x")))))
  }

  run deviceCapHoldsTest = {
    assert(deviceCapOk(Map("a" -> leaf("a","alice","alice"))))
  }
}
