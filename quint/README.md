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
