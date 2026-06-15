# `on-chain-client/` — ODS Phase 1.b Stage 2

Read-only Rust client for the `OrgRegistry` contract deployed via
`pallet-revive` on Asset Hub. Companion to `on-chain/` (the Solidity
contract, Foundry tests, and chopsticks deploy harness).

## How the system works (high level)

Each organisation has state in two places:

1. **On-chain.** A single `OrgRegistry` contract on Asset Hub serves
   every org. It's a `mapping(address => OrgState)` keyed on the H160 of
   the org's pure proxy `P`. `OrgState` is `(rootHash, orgPubKey, epoch)`
   — the SMT root from `org-members`, the org's signing key, and a
   monotonic compare-and-swap counter that rejects stale updates.
2. **Off-chain.** The full membership trie (in `org-members`). The
   on-chain root anchors what off-chain state is canonical at any moment.

The contract is multi-tenant: anyone can claim a slot by calling
`update(...)` from their own pure proxy; only that proxy can write to
that slot from then on. Rotating the proxy's controlling multisig
`M(signers, threshold)` leaves `P` (and therefore the slot key)
untouched.

This crate is the **reader half**. A consumer (the Phase 2 PWA, a CI
follower, an indexer) imports `on-chain-client`, opens a transport
(smoldot in the browser, jsonrpsee against chopsticks in tests), points
it at the deployed contract's H160, and:

- Calls `OrgRegistryClient::get_org_state(admin, at)` for an org's
  current state at the latest finalised block (or any specific block).
- Calls `OrgRegistryClient::subscribe(admin)` to stream `BestBlockEvent`
  / `FinalisedEvent` / `Reorged` notifications. Best-block events are
  optimistic (a cue to start off-chain p2p delta exchange); finalised
  events are when local state should be committed.

The write half — actually submitting `update(...)` extrinsics — is **out
of scope** for this crate. Admins use `polkadot.js` or `subxt` directly
until Phase 2.

## How to deploy the contract

Deployment lives in the sibling `on-chain/` directory. The Stage 1 gate
script forks Paseo Asset Hub via chopsticks, deploys `OrgRegistry`, and
verifies the on-chain code hash matches the locally compiled blob:

```bash
cd ../on-chain
./scripts/chopsticks-sanity.sh
# Logs: OK — Stage 1 chopsticks sanity passed.
# The deployed contract H160 is the `contract` field of the
# `revive.Instantiated` event logged at step [5/5].
```

For live Paseo (not just a fork), the same `pallet-revive`
`instantiateWithCode` flow is used via polkadot.js or subxt. The
resolc-compiled bytecode is the artifact this client points at; the ABI
is pinned at `../on-chain/abi/OrgRegistry.json`. See
[`../on-chain/README.md`](../on-chain/README.md) for the contract build,
ABI re-pin, and chopsticks harness details, and
[`../on-chain/POST_POC.md`](../on-chain/POST_POC.md) for the
mainnet-readiness roadmap (UUPS proxy, cross-org composition, PQ
migration).

## Status

**Stage 2 complete** (subxt-native client per the
[subxt-commitment amendment](../docs/superpowers/specs/2026-06-04-ods-phase-1b-stage2-subxt-commitment-design.md)).
One transport stack (subxt 0.50.1), verified state reads via
`ReviveApi::get_storage`, merged best/finalised `subscribe` with reorg
detection, the full Scenario A/B/C + OrgId-invariant matrix, and a native
light-client smoke test (passed live).

| Deliverable | Where | Status |
|---|---|---|
| Public types (`OrgAdmin`, `OnChainRootHash`, `OrgPubKey`, `Epoch`, `OrgState`, `Event`, `SubscribedEvent`) | `src/types.rs`, `src/state.rs` | ✅ |
| Runtime-version-gated storage + event decoders (`spec_version 2_002_002`) | `src/decode/` | ✅ |
| `OrgRegistryClient::get_org_state` via `ReviveApi::get_storage` runtime API | `src/client.rs` | ✅ |
| `OrgRegistryClient::subscribe` — merged best + finalised lanes, `Reorged` detection | `src/client.rs` | ✅ |
| `h160_of(P)` mapping (lib; fixture-pinned) | `src/h160.rs` | ✅ |
| `verify_root_against_chain` helper | `src/verify.rs` | ✅ |
| Test harness — chopsticks fork, multisig derivation, pure-proxy + swap, submit | `tests/common/` | ✅ |
| Scenario A — per-org isolation + best/finalised ordering | `tests/two_orgs_one_watcher.rs`, `tests/scenario_a_full.rs` | ✅ |
| Scenario B — full off-chain genesis ceremony | `tests/off_chain_genesis_ceremony.rs` | ✅ |
| Scenario C — reorg cancels proposed (chopsticks-divergence-aware) | `tests/reorg_cancels_proposed.rs` | ✅ |
| OrgId invariant in isolation | `tests/p_address_is_orgid.rs` | ✅ |
| Native light-client smoke test (passed live: `spec_version 2002002`, finalised block, 18.5 s) | `tests/smoldot_smoke.rs` | ✅ |

Deliberately deferred: threshold>1 `as_multi` multisig ceremony (threshold-1
via `as_multi_threshold_1` is pinned); the wasm32 *browser* smoldot lane
(blocked upstream in subxt 0.50.1 — see the feature matrix).

## Layout

- `src/types.rs` — `OrgAdmin`, `OnChainRootHash`, `OrgPubKey`, `Epoch`.
- `src/state.rs` — `OrgState`, `Event`, `BlockHash`, `BlockRef`, `SubscribedEvent`.
- `src/client.rs` — `OrgRegistryClient` reading surface (subxt-based; backend chosen by caller — `LegacyBackend` in tests, `ChainHeadBackend`/light-client in production). `get_org_state` reads via the `ReviveApi::get_storage` runtime API; `subscribe` merges a best lane (gap-fill by number + parent-hash reorg detection) and a finalised lane (monotonic).
- `src/decode/` — runtime-version-gated storage + event decoders. `dispatch::for_runtime(spec_version)` selects the right `&'static dyn Decoder`; one decoder per pinned Paseo AH runtime version. Solidity event signatures locked against ABI drift by a recompute-and-compare test.
- `src/h160.rs` — `h160_of(P)` mapping mirroring pallet-revive (fixture-tested).
- `src/verify.rs` — `verify_root_against_chain` helper.

## Feature matrix

| Build command | Effect |
|---|---|
| `cargo build` | `default = ["dev-rpc"]` — std + subxt over jsonrpsee (chopsticks integration tests). |
| `cargo build --no-default-features` | `no_std + alloc` — types + verifier only; no transport. |
| `cargo build --no-default-features --features smoldot` | std + subxt's embedded smoldot light client (PWA / live smoke). Native host only. |
| `cargo build --target wasm32-unknown-unknown --features smoldot` | **BLOCKED UPSTREAM** — subxt 0.50.1's `web` lane requires `jsonrpsee-wasm-client 0.24.11`, unpublished on crates.io; cross-target feature unification forces it even via a target-split. Re-assess on a subxt bump. See Cargo.toml note. |

The `dev-rpc` feature is the integration-test path against a chopsticks
fork (subxt over jsonrpsee). The `smoldot` feature is the production path
for the PWA and the live-Paseo smoke test (subxt's embedded smoldot light
client) — it builds and runs on a **native host**. The wasm32-browser
build of the smoldot lane is blocked upstream within subxt 0.50.1 (see the
feature-matrix row above and the Cargo.toml note); it is a re-assess
trigger, not a hand-rolled workaround.

## Quickstart

```bash
# Default build (std + subxt over jsonrpsee — chopsticks integration tests):
cargo build

# no_std build (types + verifier only):
cargo build --no-default-features

# smoldot light-client transport (native host — PWA / live smoke):
cargo build --no-default-features --features smoldot

# Full integration suite (auto-spawns chopsticks; run sequentially because
# the tests share fixed port 8000 — pkill clears any stale chopsticks first):
pkill -f "chopsticks.*--config" 2>/dev/null; cargo test --features dev-rpc -- --test-threads=1

# Live-Paseo light-client smoke test (#[ignore]d; needs public internet,
# verifies the live AH runtime matches the pinned decoder + a finalized
# block arrives over smoldot):
cargo test --no-default-features --features smoldot --test smoldot_smoke \
  -- --ignored --nocapture
```

## CI matrix

The jobs run, exactly:

```bash
cargo build --no-default-features
cargo build --no-default-features --features smoldot
cargo clippy --all-features --lib -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic
cargo test --features dev-rpc -- --test-threads=1
cargo test --no-default-features --features smoldot --test smoldot_smoke -- --ignored   # smoke job, allowed-flaky / needs internet
```

The clippy gate applies to lib code only (`--lib`); test code may use
`unwrap`/`expect` freely. The smoke job needs public internet and is
allowed-flaky (it also trips deliberately if the live AH runtime upgrades
past the pinned `spec_version 2_002_002`).

## Fuzzing

The untrusted-byte decoders are fuzzed with [bolero](https://crates.io/crates/bolero).
Three targets live under `tests/<target>/fuzz_target.rs`:

| Target | Checks |
| --- | --- |
| `fuzz_parse_revive_event` | `parse_revive_event` never panics on arbitrary bytes |
| `fuzz_decode_org_state` | `decode_org_state` never panics on arbitrary bytes |
| `fuzz_event_round_trip` | `parse_revive_event` is the exact inverse of the on-chain encoding (structured inputs) |

**Default lane (stable, CI):** the targets are `harness = false` binaries, so a
plain `cargo test` runs each one — replaying its committed `corpus/` seeds plus
a bounded batch of generated inputs. No nightly toolchain required. Run one
target directly with `cargo test --test fuzz_parse_revive_event`.

**Deep fuzzing (nightly, on demand):**

```bash
cargo install cargo-bolero
cargo bolero test fuzz_parse_revive_event --engine libfuzzer   # coverage-guided
```

Any crash is written to the target's `crashes/` dir; commit it there as a
permanent regression seed.

**Corpus seeds** for the two byte targets are produced by an `#[ignore]`d
regenerator — rebuild them after a contract ABI change with:

```bash
cargo test --test regenerate_corpus -- --ignored
```

## See also

- [`../on-chain/README.md`](../on-chain/README.md) — Solidity contract,
  Foundry tests, chopsticks sanity gate.
- [`../on-chain/POST_POC.md`](../on-chain/POST_POC.md) — pre-mainnet
  roadmap; UUPS migration rationale.
- [`../docs/superpowers/specs/2026-05-13-ods-phase-1b-design.md`](../docs/superpowers/specs/2026-05-13-ods-phase-1b-design.md)
  — full Phase 1.b design (§3 covers this crate's public surface).
- [`../docs/superpowers/specs/2026-06-04-ods-phase-1b-stage2-subxt-commitment-design.md`](../docs/superpowers/specs/2026-06-04-ods-phase-1b-stage2-subxt-commitment-design.md)
  — the subxt-commitment amendment (transport rationale).
- [`../docs/superpowers/plans/2026-06-04-ods-phase-1b-stage2-subxt-completion.md`](../docs/superpowers/plans/2026-06-04-ods-phase-1b-stage2-subxt-completion.md)
  — the Stage 2 completion plan (task-by-task; the work in the Status table above).
- [`../docs/superpowers/plans/2026-05-28-ods-phase-1b-stage2-rust-client.md`](../docs/superpowers/plans/2026-05-28-ods-phase-1b-stage2-rust-client.md)
  — the original task-by-task plan (Tasks 5–10 superseded by the completion plan).
- [`../docs/superpowers/plans/2026-06-04-ods-phase-1b-stage2-handoff.md`](../docs/superpowers/plans/2026-06-04-ods-phase-1b-stage2-handoff.md)
  — superseded handoff snapshot; kept for its "Critical technical notes".
