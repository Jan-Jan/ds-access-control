// -*- mode: Bluespec; -*-
/// Vacuity witnesses and scenario checks for the protocol layer. Reachability
/// is demonstrated via witness invariants: each `...Reachable` value is FALSE
/// exactly in a target state, so `quint run --invariant=<it>` finding a
/// VIOLATION proves that state is reachable (the counterexample IS the witness).
module ods_instances {
  import protocol.* from "./protocol"

  // WITNESS 1 — revocationSafety is non-vacuous: a SETTLED object coexists with
  // a non-empty `revoked` set. (Violation => such a state is reachable.)
  val settledWithRevocationReachable =
    not(OBJECTS.exists(o => isSettled(o, chain, local, objToken, rootMembers)) and revoked != Set())

  // WITNESS 2 — forkSafety is non-trivial: two honest members can sit at
  // DIFFERENT epochs (so the implication's antecedent is exercised, not vacuous).
  val membersCanDifferReachable =
    not(honestMembers.exists(m1 => honestMembers.exists(m2 =>
      local.get(m1).epoch != local.get(m2).epoch)))

  // WITNESS 3 — a revoked member is fully excluded post-rotation: there is a
  // reachable state where some principal is revoked AND holds neither the
  // current org secret nor any object's current token.
  val revokedFullyExcludedReachable =
    not(revoked.exists(p =>
      not(getOrEmpty(orgKnows, chain.orgGen).contains(p))
      and OBJECTS.forall(o => not(tokenKnows.get(objToken.get(o).id).contains(p)))
      and chain.orgGen > 0))
}
