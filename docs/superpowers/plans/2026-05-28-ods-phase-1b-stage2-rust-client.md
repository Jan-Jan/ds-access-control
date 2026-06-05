# ODS Phase 1.b Stage 2 — `on-chain-client` Rust crate

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Spec:** [`docs/superpowers/specs/2026-05-13-ods-phase-1b-design.md`](../specs/2026-05-13-ods-phase-1b-design.md) §3 and §5.2.

**Predecessor plan:** [Stage 1](2026-05-13-ods-phase-1b-stage1-solidity.md). Stage 1's gate (forge tests + chopsticks-Paseo sanity) is green; the contract bytecode hash is pinned in `on-chain/abi/OrgRegistry.json` and verified against `pallet-revive`'s `PristineCode`.

**Goal:** Deliver the `on-chain-client` Rust crate that reads `OrgRegistry` state and subscribes to its events on a chopsticks-forked Paseo Asset Hub (default `dev-rpc` / WS transport) and on a live Paseo Asset Hub (the smoldot smoke test). Gate is a green integration-test matrix covering Scenarios A/B/C plus the OrgId invariant and the smoldot smoke test.

**Architecture:** A standalone Rust crate at `on-chain-client/` exposing:
- Named types mirroring the on-chain struct (`OrgAdmin`, `OnChainRootHash`, `OrgPubKey`, `Epoch`, `OrgState`, `Event`, `BlockRef`, `SubscribedEvent`).
- An `Rpc` trait abstracting the transport (`chain_head_storage`, `chain_head_follow`, `runtime_version`) with two concrete impls: `WsRpc` (jsonrpsee, default) and `SmoldotRpc` (browser-WASM-capable, behind a `smoldot` feature).
- `OrgRegistryClient<R: Rpc>` with `get_org_state(admin, at)` and `subscribe(admin)` returning a `Stream<Item = SubscribedEvent>`.
- A `verify_root_against_chain` helper closing the loop with `org_members::CandidateTrie::verify_against`.

**Tech Stack:** Rust 2024 edition, `no_std + alloc` aspirational for the types + verifier (with `std` gated behind a default `client` feature for the transports). Dependencies pinned for reproducibility: `jsonrpsee` (WS RPC), `smoldot-light` (browser/server-WASM-capable light-client), `parity-scale-codec` (SCALE decoding), `subxt-signer` only in tests for keypairs, `tokio` (runtime), `futures` (streams), `hex`, `keccak-asm` or `tiny-keccak` (H160 keccak), `blake2` (storage-key hashing in pallet-revive paths where applicable).

**Out of scope for this plan:**
- Submission helpers (`update(...)` is signed and dispatched off-crate, via `polkadot.js` / `subxt`, exactly as in Stage 1).
- `org-members` changes. The verifier helper just closes the loop with the existing public API.
- Solidity view functions for cross-contract reads — that's a V2 decision per `on-chain/POST_POC.md`.
- Mainnet runtime support. Only Paseo Asset Hub at the pinned runtime version produced by Stage 1.

**Follow-up plan:** None at the time of writing. Phase 1.c (PWA integration) would be the natural next step after Stage 2's gate is green.

---

## File structure produced by this plan

```
2-tier-access-control/
├── org-members/                                       [existing — unchanged]
├── on-chain/                                          [existing — unchanged]
├── docs/                                              [existing — unchanged]
└── on-chain-client/                                   [NEW]
    ├── Cargo.toml                                     features: dev-rpc (default), smoldot
    ├── README.md                                      build / test / smoldot-smoke quickstart
    ├── .gitignore                                     target/, .cargo-cache/
    ├── src/
    │   ├── lib.rs                                     re-exports; pub use of modules
    │   ├── types.rs                                   OrgAdmin / OnChainRootHash / OrgPubKey / Epoch
    │   ├── state.rs                                   OrgState, Event, BlockRef, SubscribedEvent
    │   ├── rpc/
    │   │   ├── mod.rs                                 Rpc trait + HeadEvent + RuntimeVersion
    │   │   ├── ws.rs                                  WsRpc (jsonrpsee, dev-rpc feature)
    │   │   └── smoldot.rs                             SmoldotRpc (smoldot feature)
    │   ├── decode/
    │   │   ├── mod.rs                                 runtime-version-gated dispatch
    │   │   ├── v_paseo_ah_1004001.rs                  decoder for the pinned runtime version
    │   │   └── fixtures/                              raw storage + event byte fixtures
    │   ├── client.rs                                  OrgRegistryClient<R> + get_org_state + subscribe
    │   ├── h160.rs                                    h160_of(P) mapping (mirrors pallet-revive)
    │   └── verify.rs                                  verify_root_against_chain helper
    └── tests/
        ├── common/                                    test harness (see Task 6)
        │   ├── mod.rs
        │   ├── multisig.rs                            pseudo-account derivation
        │   ├── h160_mapper.rs                         fixture-pinned h160_of
        │   ├── swap_proxy.rs                          pallet-proxy rotation helper
        │   ├── chopsticks_fork.rs                     spin up chopsticks, return RPC URL + handle
        │   └── chopsticks_reorg.rs                    fork-then-reorg helper
        ├── 00_chopsticks_sanity.rs                    confirms harness can spin up a fork
        ├── two_orgs_one_watcher.rs                    Scenario A
        ├── off_chain_genesis_ceremony.rs              Scenario B
        ├── reorg_cancels_proposed.rs                  Scenario C
        ├── p_address_is_orgid.rs                      H160(P) invariant fixture test
        └── smoldot_smoke.rs                           live-Paseo smoke (feature = smoldot)
```

After the plan completes the repo also has these git-level outputs:
- A tag `v0.2.0-on-chain-client-stage2` on the gate-passing commit.
- A second tag `v0.2.0-stage2-smoldot-ok` once the smoldot smoke test goes green against live Paseo (which can lag if Paseo's RPC is flaky).

---

## Working-directory and toolchain prerequisites

**Worktree:** continue in the existing `worktree-phase-1b-stage1-solidity` worktree, or branch a fresh one — both work. Stage 2 has no Solidity-side dependencies beyond the pinned ABI at `on-chain/abi/OrgRegistry.json`.

**Tools the executor must have available:**

```bash
rustc --version              # >= 1.85 (Rust 2024 edition)
cargo --version
node --version               # >= 20.x (for the chopsticks harness)
npm --version
# chopsticks deps are reused from on-chain/scripts/node_modules; no fresh install needed.
```

Smoldot itself is a Rust dep — no separate install. The smoldot smoke test connects to the live Paseo AH endpoint pinned in Stage 1 (`wss://asset-hub-paseo-rpc.n.dwellir.com`).

---

## Task 1 — Initialise the `on-chain-client` crate

**Goal:** lay down a buildable crate with the feature matrix and module layout, but no real logic yet.

**Files:**
- Create: `on-chain-client/Cargo.toml`
- Create: `on-chain-client/.gitignore`
- Create: `on-chain-client/src/lib.rs`
- Create: `on-chain-client/src/types.rs`
- Create: `on-chain-client/src/state.rs`
- Create stubs for `rpc/mod.rs`, `decode/mod.rs`, `client.rs`, `h160.rs`, `verify.rs`.

**Cargo features:**
- `default = ["dev-rpc"]`
- `dev-rpc` — pulls `jsonrpsee` and `tokio`. The WS path used by integration tests.
- `smoldot` — pulls `smoldot-light`. The browser-WASM path used by the smoke test and the future PWA.
- `no-std` (or no feature flag at all if `default` is sufficient) — types + `verify` compile with `#![no_std]` + `alloc`. CI matrix asserts this.

**Gate:** `cargo build`, `cargo build --no-default-features --features smoldot`, `cargo build --no-default-features` all succeed. `cargo clippy` clean with `unwrap_used`, `expect_used`, `panic` denied in lib code (per `org-members` precedent).

---

## Task 2 — Public types (`types.rs`, `state.rs`)

**Goal:** all named types from spec §3 ("Public types"), with `From`/`Into` between `OnChainRootHash` and `org_members::RootHash` (byte-for-byte).

**Implementations:**
- `OrgAdmin([u8; 20])`, `OnChainRootHash([u8; 32])`, `OrgPubKey([u8; 32])`, `Epoch(u64)` — newtypes around fixed-size byte arrays. Derive `Clone`, `Copy`, `Debug`, `PartialEq`, `Eq`, `Hash`. No `Display` until callers ask for one.
- `OrgState { root_hash, org_pub_key, epoch }`.
- `Event::Genesis { admin, root_hash, org_pub_key }` and `Event::Update { admin, epoch, root_hash, org_pub_key, prev_root_hash }`.
- `BlockRef { hash: BlockHash, number: u64 }`.
- `SubscribedEvent::{ BestBlockEvent, Reorged, FinalisedEvent }` — exact shape from spec §3, with best/finalised carrying `(Event, BlockRef)` and Reorged carrying `BlockRef`.

**Tests:** trivial round-trip serialisation tests for the conversion to `org_members::RootHash`. Not yet runtime-decoded — that's Task 4.

**Gate:** unit tests pass; `cargo doc --no-deps` produces no warnings.

---

## Task 3 — `Rpc` trait + `WsRpc` implementation

**Goal:** abstract the transport so the same `OrgRegistryClient` can run over jsonrpsee (tests) and smoldot (production / smoke test).

**Trait surface** (spec §"Transport abstraction"):

```rust
pub trait Rpc {
    async fn chain_head_storage(&self, block: BlockHash, key: &[u8])
        -> Result<Option<Vec<u8>>, Error>;
    async fn chain_head_follow(&self) -> impl Stream<Item = HeadEvent>;
    async fn runtime_version(&self) -> Result<RuntimeVersion, Error>;
}
```

**WsRpc:**
- Uses `jsonrpsee::ws_client::WsClient`.
- Speaks `chainHead_v1_*` (the unstable group). Cope with the names changing — the Stage 2 commit pins the exact method names to whatever Paseo's RPC exposes at implementation time, documented in the design doc Open Items.
- `chain_head_follow` returns a `Stream<HeadEvent>` decoded from the `chainHead_v1_follow` subscription. `HeadEvent` enumerates `NewBlock`, `BestBlockChanged`, `Finalized`, `Stop` (renaming/stabilisation deferred to Task 10).

**Gate:** unit tests that exercise `WsRpc` against a chopsticks fork running on `127.0.0.1:PORT`, covering `runtime_version` and a single `chain_head_storage` round-trip. Reuse `on-chain/scripts/chopsticks-sanity.sh`'s harness for fork startup — call it from a `tests/common/chopsticks_fork.rs` helper that returns the RPC URL.

---

## Task 4 — Storage + event decoders (runtime-version-gated)

**Goal:** turn raw bytes (storage values, event blobs) into the typed `OrgState` and `Event`, gated behind a `runtime-vN` cargo feature.

**Structure:**
- `decode::v_paseo_ah_<runtime_version>::storage::org_state(bytes) -> Result<OrgState, DecodeError>`.
- `decode::v_paseo_ah_<runtime_version>::events::parse_revive_event(event_bytes) -> Result<Option<Event>, DecodeError>` — `None` for events emitted by other contracts or other pallets.
- `decode::dispatch::for_runtime(runtime_version: u32) -> &'static dyn Decoder` — selects the right decoder. Unknown versions return a `DecodeError::UnsupportedRuntime`.

**Fixtures:**
- `decode/fixtures/org_state_v1.bin` — raw 96 bytes (32+32+32) captured from a chopsticks-forked Paseo deploy.
- `decode/fixtures/event_genesis_v1.bin` and `event_update_v1.bin` — raw event topic + data blobs.
- One fixture test per decoder. The fixture files are regenerated by a `cargo run --bin capture-fixtures` helper that talks to a running chopsticks fork.

**Gate:** all fixture tests pass; the `DecodeError::UnsupportedRuntime` path is reached when given a fake runtime version.

---

## Task 5 — `OrgRegistryClient::{get_org_state, subscribe}`

**Goal:** the two public reading APIs from spec §"Client surface", glueing `Rpc` + decoders.

- `get_org_state(admin, at)` — computes the pallet-revive storage key for `orgs[admin]`, calls `chain_head_storage`, decodes. Returns `Ok(None)` for empty storage (never-written slot).
- `subscribe(admin)` — opens a `chain_head_follow`, filters events by indexed-admin-topic if `admin` is `Some`, yields `BestBlockEvent` and `FinalisedEvent`; emits `Reorged { discarded }` when the follow reports a discarded best block.

**Storage-key derivation:** mirrors the `pallet-revive` mapping for contract storage. Fixture-tested against bytes captured from chopsticks (Task 4's fixtures cover this).

**Gate:** Scenario A passes (two orgs, one watcher; both best-block and finalised emissions observed; events arrive in the expected order). Scenario C passes (reorg of a best block yields a `Reorged` notification, no spurious `FinalisedEvent` for the discarded block).

---

## Task 6 — Test harness `common/` module

**Goal:** primitives shared by Scenarios A/B/C and the OrgId invariant test.

**Modules:**
- `common::multisig` — derives the pseudo-account `M(signers, threshold)` and the pure proxy `P` controlled by it. Includes `multisig_dispatch` which auto-selects `as_multi` vs `as_multi_threshold_1` (spec Open Items §threshold-1 multisig handling).
- `common::h160_mapper` — `h160_of(account_id_32) -> [u8; 20]` mirroring pallet-revive's mapping. Fixture-pinned (Risk #5 in the spec).
- `common::swap_proxy` — submits a `proxy.add_proxy` + `proxy.remove_proxy` pair to rotate `M(...)` while leaving `P` stable. Used in Scenarios B and C.
- `common::chopsticks_fork` — `spawn_fork(config_path) -> ChopsticksHandle`. Wraps `on-chain/scripts/chopsticks-sanity.sh`'s startup logic. Includes the HTTP pre-warm probe added in Stage 1.
- `common::chopsticks_reorg` — `induce_reorg(handle, depth) -> ...` using chopsticks's `dev_setHead` / `dev_newBlock` JSON-RPC ext.

**Gate:** `00_chopsticks_sanity.rs` test passes (just spins a fork up and down). No real-chain dependencies inside the harness — Scenarios A/B/C all run against the local fork only.

---

## Task 7 — Integration scenarios A/B/C + OrgId invariant

**Scenario A — `two_orgs_one_watcher.rs`** (spec §5.2):
- Spin up a fork. Two pure proxies `P_a`, `P_b` controlled by distinct multisigs.
- Each org submits a genesis `update(...)`. Watcher subscribes with `admin = None`.
- Assert: both `GenesisInitialized` events arrive, indexed-admin topic matches `h160_of(P_a)` / `h160_of(P_b)`, ordering is per block.
- `P_a` submits a second `update(...)`. Assert: `RootUpdated` arrives with `epoch=2`, `prevRootHash` matches the genesis root.
- Run a parallel watcher with `admin = Some(h160_of(P_a))`. Assert: it only sees A's events.

**Scenario B — `off_chain_genesis_ceremony.rs`** (spec §5.2):
- A pure proxy `P` exists, but no `update(...)` has been called yet.
- Admin set rotates via `swap_proxy` — `M(...)` changes but `P` doesn't.
- The new multisig submits genesis. Assert: `msg.sender == h160_of(P)` still, the new admin set is invisible to the contract, the genesis event lands with the right indexed admin.

**Scenario C — `reorg_cancels_proposed.rs`** (spec §5.2):
- Submit an `update(...)`, observed at the best-block tip but not yet finalised.
- Induce a reorg that discards the block containing it.
- Assert: watcher receives `Reorged { discarded: <that block> }` and no `FinalisedEvent` for it. The state slot read via `get_org_state(admin, at = None)` (latest finalised) is unchanged.

**`p_address_is_orgid.rs`:**
- Deterministic fixture: given a known multisig pseudo-account → pure-proxy account, assert `h160_of(P)` matches the expected 20-byte value. The fixture pins what `pallet-revive` actually returns; protects against the mapping function drifting.

**Gate:** all four tests pass under `cargo test --features dev-rpc` against the chopsticks-Paseo fork. CI green.

---

## Task 8 — `SmoldotRpc` implementation

**Goal:** the production transport. Same `Rpc` trait surface; differs only in how the WS connection is established (smoldot's embedded light client vs. jsonrpsee's external WS).

**Approach:**
- Use `smoldot-light` crate. Initialise with the Paseo Asset Hub chain spec (committed under `src/rpc/smoldot/chainspec_paseo_ah.json`).
- The `chainHead_v1_*` group is exposed by smoldot as JSON-RPC methods over its in-process channel.
- All decoding is the same as `WsRpc` — only the transport differs.

**Gate:** crate builds with `cargo build --no-default-features --features smoldot`. No runtime test yet (that's Task 9).

---

## Task 9 — Smoldot smoke test (`smoldot_smoke.rs`)

**Goal:** end-to-end sanity that `SmoldotRpc` works against the live Paseo AH endpoint (no chopsticks).

**Steps:**
- Initialise `SmoldotRpc` with the pinned chainspec.
- Read the on-chain code hash for the previously-deployed `OrgRegistry` (if one is live on Paseo) OR just `runtime_version()` if no live deployment yet — confirms the transport reads finalised state successfully.
- Subscribe to `chain_head_follow`, wait for one `Finalized` notification (typically <30s).
- Disconnect cleanly.

**Gate:** test passes (or is `#[ignore]`-marked with a doc note if Paseo's public RPC is flaky on the CI run). The flag is the *combination* of dev-rpc Scenarios A/B/C passing AND smoldot smoke passing — never just one. Both confirm reorg semantics match.

---

## Task 10 — Pin concrete versions in design doc + README

**Goal:** convert the spec's "Open items" to "Resolved" entries.

**Updates to `docs/superpowers/specs/2026-05-13-ods-phase-1b-design.md`:**
- Pinned runtime version (Paseo AH at implementation time).
- Pinned WSS endpoint (probably unchanged from Stage 1).
- Pinned `chainHead_v1_*` method names as smoldot/jsonrpsee see them.
- CI matrix entries (`cargo test --features dev-rpc` default; `--features smoldot` for the smoke job).

**Updates to `on-chain-client/README.md`:**
- Quickstart for `cargo test`, the smoldot smoke command, and the feature matrix.

**Updates to top-level `README.md` / `AGENTS.md` if they mention Stage 2.**

**Gate:** spec Open Items list is empty (or only contains items genuinely deferred). Tag `v0.2.0-on-chain-client-stage2`.

---

## Stage 2 gate (must all pass before Phase 1.c starts)

- `cargo build` and `cargo build --no-default-features` succeed; `cargo build --no-default-features --features smoldot` succeeds.
- `cargo clippy --all-features -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic` clean in lib code.
- `cargo test --features dev-rpc` passes Scenarios A, B, C, the OrgId invariant, and `00_chopsticks_sanity.rs`.
- `cargo test --features smoldot --test smoldot_smoke` passes (or is documented as flaky against live-Paseo and re-run until green within a defined window).
- Spec §"Open items" reduced to zero or only deliberate deferrals.
- Commit tagged `v0.2.0-on-chain-client-stage2`.

---

## Sequencing notes

Tasks 1-2 are foundational and independent of the chopsticks/smoldot transports — start there. Task 3 (`WsRpc`) needs a running chopsticks fork for its tests, so the harness piece of Task 6 (`common::chopsticks_fork`) is its prerequisite. The rest of Task 6 (multisig, swap_proxy, etc.) is only needed by Scenarios A-C, so it can be deferred until Task 5 is structurally complete.

Tasks 4 and 5 are sequential (5 depends on 4's decoders). Tasks 8 and 9 can be done in parallel with Task 7 once Task 5 is green, since they only swap the transport.

If Stage 1's Foundry tests surface a needed contract change after Stage 2 has started, treat it as stop-the-world for the client crate: revise the contract, re-pin the ABI, then continue Stage 2 from where it was (the decoders in Task 4 are usually the only client-side code that needs to track ABI changes).

---

## Risks (carried forward from spec)

The risk table in the spec applies unchanged. Items most likely to bite during implementation:

| # | Risk | Where it shows up |
|---|---|---|
| 1 | `pallet-revive` storage layout / account mapping / event format changes | Decoders in Task 4; storage-key derivation in Task 5 |
| 3 | Smoldot's `chainHead_v1_*` group is unstable | `WsRpc` and `SmoldotRpc` in Tasks 3 + 8; mitigation is the `Rpc` trait |
| 5 | `h160_of` drifts from pallet-revive | `common::h160_mapper` fixture + `p_address_is_orgid.rs` in Tasks 6 + 7 |
| 8 | Chopsticks reorg semantics vs. real Paseo | Scenario C in Task 7 vs. smoke test in Task 9 |
