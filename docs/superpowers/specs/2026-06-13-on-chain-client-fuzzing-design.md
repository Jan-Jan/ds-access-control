# on-chain-client decoder fuzzing — design

**Date:** 2026-06-13
**Status:** approved (design); spec under review
**Crate:** `on-chain-client` (ODS Phase 1.b, Stage 2 — landed on master at `ecb38e6`)

## Motivation

`AGENTS.md` carries a sticky rule: **"Always include fuzz testing."** Stage 2
shipped without it. The natural targets are the functions that turn *untrusted
chain bytes* into typed values — they form a trust boundary: bytes arrive from a
chain endpoint (potentially a malicious or buggy node, a forked/divergent
runtime, or a non-Solidity contract emitting look-alike events) and must be
decoded without panicking, aborting, or over-allocating.

The crate's decoders are written defensively (explicit length checks, bounded
slicing, no `unwrap`/`expect`/`panic` — enforced by the `--lib` clippy gate).
Fuzzing turns that intended invariant into a continuously-checked one.

## Scope

Two functions, both reached through the crate's **public** decoder path
(`decode::dispatch::for_runtime(spec_version) -> &dyn Decoder`):

- `Decoder::parse_revive_event(&[u8]) -> Result<Option<Event>, DecodeError>` —
  SCALE-decodes the payload of `pallet_revive::Event::ContractEmitted`
  (`contract: H160`, `data: Vec<u8>`, `topics: Vec<H256>`). The two `Vec`
  decodes from arbitrary bytes are the highest-value target (unbounded length
  prefixes, allocation behaviour, topic/data cross-checks).
- `Decoder::decode_org_state(&[u8]) -> Result<OrgState, DecodeError>` — parses
  96 concatenated bytes (3 × 32-byte EVM slots) into `OrgState`.

`h160_of([u8;32])` is **explicitly out of scope**: a fixed-width input with no
fallible slicing and effectively no panic surface; the existing unit tests cover
its two branches.

Targets are reached only via the public `for_runtime` path — never the
`pub(super)` `DECODER` static — so we fuzz exactly what production callers
(`OrgRegistryClient::get_org_state`, the follow-subscription decode loop) see.

## Targets

Three bolero targets. bolero keys a target's committed corpus/regression files
to a dedicated test **binary** (`harness = false`), so each target is its own
directory `tests/<target>/fuzz_target.rs` with sibling `corpus/` and `crashes/`
dirs and a `[[test]]` entry in `Cargo.toml`. Each `fuzz_target.rs` is a small
`fn main()` that calls `bolero::check!()`. The three targets:

### 1. `fuzz_parse_revive_event` — raw bytes, never-panic

Input: arbitrary `&[u8]`. Resolve the decoder via `for_runtime`, call
`parse_revive_event`, discard the result. The property is *liveness*: any
`&[u8]` produces `Ok(_)` / `Err(_)` / `Ok(None)` — never a panic, abort, or
unbounded allocation. (bolero/libFuzzer surface a panic as a test failure / a
crash file.)

### 2. `fuzz_decode_org_state` — raw bytes, never-panic

Input: arbitrary `&[u8]`. Same shape as #1 against `decode_org_state`. Exercises
the length guard (96-byte requirement), the epoch-overflow check on the high 24
bytes, and the slot copies.

### 3. `fuzz_event_round_trip` — structured, inverse property

Input: a `bolero::TypeGenerator`-derived `EventShape` enum that can only
describe a *structurally valid* event:

```text
enum EventShape {
    Genesis { contract: [u8;20], admin: [u8;20], root: [u8;32], key: [u8;32] },
    Update  { contract: [u8;20], admin: [u8;20], epoch: u64,
              root: [u8;32], key: [u8;32], prev_root: [u8;32] },
}
```

The target encodes the shape into a canonical `ContractEmitted` SCALE payload
(the same construction the unit tests use: `contract.encode_to` ||
`data.encode_to` || `topics.encode_to`, with Solidity-style left-padded address
topics and big-endian `uint256` epoch), decodes it back via `parse_revive_event`,
and asserts the decoded `Event` equals the `Event` the shape represents. This is
a **differential / inverse** check: it fails if the decoder ever stops being the
exact inverse of the documented on-chain encoding (e.g. a field-order or
padding regression). Because inputs are valid by construction, any non-`Some(eq)`
outcome is a real bug, not malformed input.

The encoder helper (`encode_contract_emitted`) lives in the test file, mirroring
the contract's ABI; it is *independent* of the decoder so the round trip is a
genuine cross-check rather than a tautology.

## Structure & dependencies

Layout (one directory per target, bolero's canonical form):

```
on-chain-client/
  Cargo.toml                       # +3 [[test]] entries, +1 dev-dep
  tests/
    fuzz_parse_revive_event/
      fuzz_target.rs               # fn main { check!().for_each(|b: &[u8]| ...) }
      corpus/                      # committed seed inputs
      crashes/.gitkeep             # regression seeds land here
    fuzz_decode_org_state/
      fuzz_target.rs
      corpus/
      crashes/.gitkeep
    fuzz_event_round_trip/
      fuzz_target.rs               # EventShape + encoder + decode + assert
      corpus/.gitkeep
      crashes/.gitkeep
```

- Each `fuzz_target.rs` is a `harness = false` test binary, so it is **outside**
  the `--lib` clippy gate (`README.md:154`) and may panic/`unwrap` freely —
  which is how bolero signals a failure. Plain `cargo test` runs each binary's
  `main()` (corpus replay + a bounded batch of generated inputs); a panic →
  non-zero exit → failed test.
- New `[dev-dependencies]`:
  - `bolero = "0.13"` — ships its own `TypeGenerator` derive (re-exported), so
    the structured round-trip target needs no separate `arbitrary` crate. Runs
    on stable for the default lane; drives libFuzzer/AFL under `cargo-bolero` on
    nightly.
  - `parity-scale-codec = { version = "3", default-features = false, features =
    ["derive"] }` — already a library dependency, but integration-test crates
    can't see the library's *normal* deps, so the round-trip encoder and the
    corpus regenerator need it declared dev-side too. Test-only; does not change
    the library's runtime dependency set.
  - `tiny-keccak = { version = "2", default-features = false, features =
    ["keccak"] }` — same dev-side re-declaration. The round-trip target and the
    regenerator derive the two event-signature topic hashes from their canonical
    Solidity signature strings (`keccak256("GenesisInitialized(...)")`), rather
    than hardcoding the decoder's `pub(super)` constants — an independent
    derivation that also guards against ABI drift.
- New `[[test]]` entries (one per target), e.g.:

  ```toml
  [[test]]
  name = "fuzz_parse_revive_event"
  path = "tests/fuzz_parse_revive_event/fuzz_target.rs"
  harness = false
  ```

- No change to the library crate's dependency set or feature flags. The decoders
  compile in every feature config (`no_std + alloc`); the targets pull in no
  subxt/client machinery.

## Corpus seeding

bolero reads seed inputs from each target's `corpus/` dir and regression inputs
from its `crashes/` dir. For the two raw-byte targets we commit seed files so the
default run starts from structure-valid bytes and mutates outward:

- `fuzz_parse_revive_event`: a valid `GenesisInitialized` payload, a valid
  `RootUpdated` payload, an empty-topics (`log0`) payload, a wrong-topic-count
  payload, a bad-address-padding payload, a trailing-bytes payload.
- `fuzz_decode_org_state`: a valid 96-byte blob (epoch = 7), a `u64::MAX`-epoch
  blob, an epoch-overflow blob, a 95-byte (wrong-length) blob.

Corpus files for these two targets are raw decoder-input bytes, so they are
produced by a committed, `#[ignore]`d regenerator test
(`tests/regenerate_corpus.rs`) that encodes the fixtures and writes the files —
executable documentation of how each seed was produced and a one-command way to
rebuild them if the contract ABI changes (`cargo test --test regenerate_corpus
-- --ignored`). The round-trip target's input is the generator's raw driver
bytes (not a serialised `EventShape`), so it ships with an empty `corpus/`
(`.gitkeep`) and relies on generated inputs. Every `crashes/` dir starts empty
(`.gitkeep`); any crash found in a deep run is committed there as a permanent
regression seed.

## Run story

- **Default / CI** — a bare `cargo test` builds and runs all three
  `harness = false` target binaries on **stable Rust**: each replays its
  committed corpus plus a bounded batch of generated inputs, with no nightly
  toolchain and no extra CI wiring. (A single target can also be run directly:
  `cargo test --test fuzz_parse_revive_event`.) This is the always-on regression
  gate that satisfies the AGENTS.md rule.
- **Deep fuzzing (on demand)** — coverage-guided multi-hour runs use
  `cargo install cargo-bolero` then
  `cargo bolero test fuzz_parse_revive_event --engine libfuzzer` (nightly).
  New crashes land in that target's `crashes/` dir and become regression seeds
  for the default lane.

## Documentation

- `on-chain-client/README.md` gains a short **Fuzzing** section: the three
  targets, the two run modes, and the corpus/crashes layout. (The crate has no
  crate-level `AGENTS.md`; the README is the discovery point.)

## Testing & acceptance

- `cargo test` runs and passes all three target binaries (and each is runnable
  individually via `cargo test --test <target>`).
- The existing suite stays green: `cargo test` (default features) and the
  `--lib` clippy deny-gate (`-D clippy::unwrap_used -D clippy::expect_used
  -D clippy::panic`) — the new dev-deps and test file must not regress either.
- A deliberate fault-injection sanity check during implementation: temporarily
  break the decoder (e.g. drop the trailing-bytes guard) and confirm a target
  fails / produces a crash file, then revert. This proves the harness actually
  bites. (Not committed; a one-off during development.)

## Non-goals

- No nightly toolchain requirement for the default lane.
- No fuzzing of the subxt/client/transport layer (I/O-bound, not a pure decode
  boundary).
- No `h160_of` target (see Scope).
- No new CI pipeline; the gate is the existing `cargo test`.

## Workflow / merge

- Work in a git worktree with `commit.gpgsign false` (per AGENTS.md).
- Squash-merge to master as a single user-signed commit at the end.
