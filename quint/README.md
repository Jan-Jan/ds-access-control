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

> In a normal environment the default `rust` backend is used. In a sandbox where
> `$HOME` is read-only (so the Quint rust evaluator cannot be fetched to
> `~/.quint`), append `--backend=typescript` to `quint test`/`quint run`.

- Typecheck: `quint typecheck quint/membership.qnt quint/membership_mbt.qnt`
- Unit tests (round-trip law, op semantics): `quint test quint/membership.qnt`
- Simulate against sanity invariants:
  `quint run quint/membership_mbt.qnt --invariant=mbtInv --max-steps=15 --max-samples=200`
- Conformance vs. the real crate (needs `quint` on PATH):
  `cd org-members && cargo test --test mbt_conformance`

## Sandbox cargo recipe

This repo's dev sandbox mounts `~/.cargo` and `$HOME` read-only. To run the MBT
conformance test locally:

```
cd org-members
HOME=/tmp/fakehome RUSTUP_HOME=$HOME/.rustup CARGO_HOME=/tmp/cargo-wt \
  cargo test --test mbt_conformance -- --nocapture
```

(`HOME=/tmp/fakehome` gives quint-connect a writable home for its evaluator;
`CARGO_HOME=/tmp/cargo-wt` avoids the read-only cargo cache. CI uses the
defaults.)

## Caveats (by design)

- SMT / Merkle / hashing mechanics are out of model scope — covered by the
  crate's own tests and the root-hash equality-class check in the MBT harness.
- Crypto is assumed sound; keys are `(owner, gen)` pairs, not bytes.
- Confusables are modeled via an explicit `skeleton` field, not real UTS#39.
- Protocol-layer properties (revocation/replay/τ-window/convergence) and the
  full adversary arrive in Milestone 2 (`protocol.qnt`).

## Protocol layer (Milestone 2)

`protocol.qnt` is the distributed state machine over `membership`: on-chain anchor
(`chain`), per-member belief (`local`), an unordered tagged-envelope `network`,
abstract knowledge sets (`orgKnows`, `tokenKnows`/`objToken`), and revocation /
accepted-write bookkeeping. `ods_instances.qnt` holds vacuity-witness invariants.

Adversaries: network (drop/duplicate), revoked-insider (replay, stale write),
below-threshold rogue admin (off-chain delta).

Properties (checked with the simulator):

- `forkSafety` — honest members at the same epoch hold the same root.
- `revocationSafety` — once an object is settled (current members caught up AND
  its CGKA token was rotated at/after the current epoch), no revoked principal
  holds its token and every accepted current-epoch write is by a current member.
  The epoch-stamped "settled" precondition deliberately excludes the pre-rekey
  transitive-trust window (that is the Milestone-3 τ-window, not a violation).

Commands (append `--backend=typescript` locally; CI uses defaults):

- `quint run quint/protocol.qnt --invariant=forkSafety --max-steps=16 --max-samples=5000`
- `quint run quint/protocol.qnt --invariant=revocationSafety --max-steps=16 --max-samples=5000`
- vacuity witnesses: `quint run quint/ods_instances.qnt --invariant=settledWithRevocationReachable ...` (finds a counterexample = the target state is reachable).

Negative controls (documented, not committed): dropping the `== chain.root` gate
in `memberFetchAndApply` breaks `forkSafety`; leaking a CGKA token to revoked
members in `cgkaRotate` breaks `revocationSafety`. Both produce simulator
counterexamples.

**Apalache `quint verify`** runs in CI (the `apalache` job) and locally with a JVM.
`protocol.qnt` uses an **abstract-root representation** — roots are opaque `int`
tokens with a `rootMembers: int -> Set[str]` side-table, not full trie `Snapshot`
maps (the rich Snapshot/Leaf semantics live in `membership.qnt`, validated by the
simulator + MBT). This keeps the protocol state small enough for Apalache to verify
`forkSafety`/`revocationSafety`/`revokedExcludedFromOrgSecret` to depth ~5-6 (the
concrete-Snapshot model topped out at depth 2). The simulator (`quint run
--invariant`) still covers greater breadth. Roots are fresh monotonic ids, faithful
while membership only shrinks (removals) — revisit if a later milestone adds member
re-addition. Convergence and the τ-window property arrive in Milestone 3.

Local Apalache run (outside CI) needs a JVM and a writable `$HOME`:
`HOME=/tmp/fakehome JAVA_HOME=$(/usr/libexec/java_home) PATH=$JAVA_HOME/bin:$PATH quint verify quint/protocol.qnt --invariant=forkSafety --max-steps=5`.
