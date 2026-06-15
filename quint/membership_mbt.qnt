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
