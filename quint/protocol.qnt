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
  var objToken: str -> { id: int, epoch: int }  // data object -> current CGKA token (id + epoch minted)
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
    objToken' = OBJECTS.mapBy(_ => { id: 0, epoch: 0 }),
    tokenKnows' = Map(0 -> MEMBERS),
    revoked' = Set(),
    acceptedWrites' = Set(),
    nextTag' = 0,
  }

  // ---- helpers ----
  pure def currentMembers(s: Snapshot): Set[str] = s.keys()
  val honestMembers: Set[str] = MEMBERS

  pure def getOrEmpty(mp: int -> Set[Principal], k: int): Set[Principal] =
    if (mp.keys().contains(k)) mp.get(k) else Set()

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

  // MEMBER: receive an OrgSecretMsg. Only a current member (per chain root) is
  // added to the holders of that org-key generation. Revoked principals are
  // structurally excluded.
  action memberReceiveOrgSecret = {
    nondet m = honestMembers.oneOf()
    nondet te = network.oneOf()
    all {
      network.size() > 0,
      currentMembers(chain.root).contains(m),
      orgKnows' = match te.env {
        | OrgSecretMsg(s) => orgKnows.put(s.gen, getOrEmpty(orgKnows, s.gen).union(Set(m)))
        | _ => orgKnows
      },
      chain' = chain, local' = local, network' = network, objToken' = objToken,
      tokenKnows' = tokenKnows, revoked' = revoked,
      acceptedWrites' = acceptedWrites, nextTag' = nextTag,
    }
  }

  // CGKA: rotate object `obj`'s token to a fresh id (use nextTag as a unique id
  // source), held by exactly the current members. Models post-revocation rekey.
  action cgkaRotate = {
    nondet obj = OBJECTS.oneOf()
    all {
      objToken' = objToken.put(obj, { id: nextTag, epoch: chain.epoch }),
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

  // REVOKED INSIDER: replay any in-flight envelope under a fresh tag (re-inject
  // a stale delta/secret). Models the ex-member actively resending.
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
  // protocol's write-acceptance is gated on the author being a CURRENT member,
  // so a revoked author is a no-op on acceptedWrites but still emits the WriteOp.
  action revokedAttemptWrite = {
    nondet p = revoked.oneOf()
    nondet obj = OBJECTS.oneOf()
    all {
      revoked.size() > 0,
      network' = network.union(Set({ tag: nextTag, env: WriteOp({ obj: obj, author: memberKey(p, 0), epoch: chain.epoch }) })),
      nextTag' = nextTag + 1,
      acceptedWrites' =
        if (currentMembers(chain.root).contains(p))
          acceptedWrites.union(Set({ obj: obj, author: memberKey(p, 0), epoch: chain.epoch }))
        else acceptedWrites,
      chain' = chain, local' = local, orgKnows' = orgKnows, objToken' = objToken,
      tokenKnows' = tokenKnows, revoked' = revoked,
    }
  }

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

  // LEMMA: a revoked principal never holds the CURRENT org-key generation secret.
  val revokedExcludedFromOrgSecret =
    (chain.orgGen > 0)
      implies (getOrEmpty(orgKnows, chain.orgGen).intersect(revoked) == Set())

  // ---- Property 1: replay / fork safety ----
  // Honest members at the same epoch hold the same root.
  val forkSafety =
    honestMembers.forall(m1 =>
      honestMembers.forall(m2 =>
        (local.get(m1).epoch == local.get(m2).epoch)
          implies (local.get(m1).root == local.get(m2).root)))

  // ---- Property 2: revocation safety ----
  // An object is "settled" when every CURRENT honest member has caught up to the
  // chain epoch AND the object's CGKA token has been rotated AT/AFTER the current
  // epoch (i.e. a rekey has occurred since the latest revocation). The epoch-stamp
  // is essential: a token minted at an earlier epoch may still hold now-revoked
  // members — that pre-rekey window is the transitive-trust τ-window (Milestone 3),
  // NOT a revocation-safety violation. Using only `id != 0` would conflate the two
  // and make the property fail spuriously (a removal need not force a same-step rekey).
  pure def isSettled(obj: str, ch: ChainState, lv: str -> LocalView,
                     tok: str -> { id: int, epoch: int }): bool =
    and {
      currentMembers(ch.root).forall(m => lv.get(m).epoch == ch.epoch),
      tok.get(obj).epoch >= ch.epoch,
    }

  // For every settled object: no revoked principal holds its current token, and
  // every accepted write on it (at the current epoch) is authored by a current member.
  val revocationSafety =
    OBJECTS.forall(obj =>
      isSettled(obj, chain, local, objToken) implies and {
        tokenKnows.get(objToken.get(obj).id).intersect(revoked) == Set(),
        acceptedWrites.forall(w =>
          (w.obj == obj and w.epoch == chain.epoch)
            implies currentMembers(chain.root).contains(w.author.owner)),
      })
}
