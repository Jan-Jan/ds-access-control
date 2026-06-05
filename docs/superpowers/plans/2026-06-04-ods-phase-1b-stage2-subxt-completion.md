# ODS Phase 1.b Stage 2 completion — subxt-native client

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the `on-chain-client` crate per the approved subxt-commitment amendment — one transport stack (subxt), verified state reads via `ReviveApi::get_storage`, working subscribe over an explicit `LegacyBackend`, the full Scenario A/B/C + OrgId-invariant matrix, and a subxt light-client smoke test.

**Architecture:** `OrgRegistryClient` wraps a caller-supplied `subxt::OnlineClient<PolkadotConfig>`; backend choice lives at the edges (tests build `LegacyBackend` because chopsticks only fully supports the legacy RPC group; production uses `ChainHeadBackend`/light-client). Our own code is limited to the typed surface, the Solidity-ABI decoders, `h160_of`, and the verifier.

**Tech Stack:** Rust 2024, subxt 0.50.1 (pinned), chopsticks fork of Paseo Asset Hub (`spec_version 2_002_002`), tokio integration tests.

**Spec:** [`../specs/2026-06-04-ods-phase-1b-stage2-subxt-commitment-design.md`](../specs/2026-06-04-ods-phase-1b-stage2-subxt-commitment-design.md) (the amendment) layered on [`../specs/2026-05-13-ods-phase-1b-design.md`](../specs/2026-05-13-ods-phase-1b-design.md) §3 + §5.2.

**Supersedes:** Tasks 5–10 of [`2026-05-28-ods-phase-1b-stage2-rust-client.md`](2026-05-28-ods-phase-1b-stage2-rust-client.md). Read [`2026-06-04-ods-phase-1b-stage2-handoff.md`](2026-06-04-ods-phase-1b-stage2-handoff.md) §"Critical technical notes" before starting — the subxt 0.50 API quirks and chopsticks landmines listed there all still apply.

---

## Standing rules for every task

- Working directory: `/Users/jan-jan/Coding/2-tier-access-control/.claude/worktrees/phase-1b-stage1-solidity/on-chain-client` unless stated otherwise.
- Test command (chopsticks uses fixed port 8000, so always serial):
  ```bash
  pkill -f "chopsticks.*--config" 2>/dev/null
  cargo test --features dev-rpc -- --test-threads=1
  ```
- Lib clippy gate (lib code only; tests may use `expect`/`unwrap` freely):
  ```bash
  cargo clippy --all-features --lib -- -D warnings \
    -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic
  ```
- GPG: commits in this worktree are unsigned (`commit.gpgsign false` via worktree config — see AGENTS.md). Just `git commit`.
- subxt 0.50 dynamic-API quirks (verified, do not re-litigate): `api.tx()` is async and the result must be `mut`; `OnlineClient` exposes `storage()`/`events()`/`runtime_apis()`/`spec_version()` only via `ClientAtBlock` (`api.at_current_block().await?` / `api.at_block(H256(...)).await?`); event name accessor is `event.event_name()`; `StorageValue` exposes `.bytes()`/`.decode_as::<T>()`.
- Dynamic-API string mismatches (pallet/call/field names) fail loudly at runtime with a subxt error — when one fires, dump the metadata (`at.metadata()`) and fix the string; never guess silently.

---

## File structure after this plan

```
on-chain-client/
├── Cargo.toml                  ← reworked features: client / dev-rpc / smoldot
├── chainspecs/
│   ├── paseo.raw.json          ← NEW (Task 10) relay chainspec
│   └── asset-hub-paseo.raw.json← NEW (Task 10) parachain chainspec
├── src/
│   ├── lib.rs                  ← `rpc` module removed; `client` gated on feature "client"
│   ├── types.rs                ← unchanged
│   ├── state.rs                ← unchanged
│   ├── decode/                 ← unchanged
│   ├── client.rs               ← from_client ctor; runtime-API get_org_state; Reorged+Finalised in subscribe
│   ├── h160.rs                 ← production h160_of (moved from tests/common)
│   └── verify.rs               ← unchanged stub (out of scope here)
└── tests/
    ├── common/
    │   ├── mod.rs              ← + conn, multisig, proxy modules
    │   ├── conn.rs             ← NEW legacy_client() helper
    │   ├── chopsticks_fork.rs  ← unchanged
    │   ├── chopsticks_reorg.rs ← unchanged
    │   ├── h160_mapper.rs      ← becomes thin re-export of crate::h160
    │   ├── submit.rs           ← + build_revive_call_value (shared with multisig path)
    │   ├── multisig.rs         ← NEW multi_account_id + threshold-1 dispatch
    │   └── proxy.rs            ← NEW create_pure / rotate / proxied submit / fund
    ├── 00_chopsticks_sanity.rs ← WsRpc round-trip → raw jsonrpsee round-trip
    ├── scenario_a_full.rs      ← renamed from scenario_a_lite.rs; subscribe + state read
    ├── two_orgs_one_watcher.rs ← NEW Scenario A (spec §5.2)
    ├── off_chain_genesis_ceremony.rs ← NEW Scenario B
    ├── reorg_cancels_proposed.rs     ← NEW Scenario C
    ├── p_address_is_orgid.rs   ← NEW OrgId invariant
    └── smoldot_smoke.rs        ← NEW (feature = smoldot, #[ignore])
DELETED: src/rpc/{mod.rs,trait_def.rs,ws.rs}, tests/rpc_ws.rs
```

---

## Task 1 — Delete the hand-rolled transport stack

**Files:**
- Delete: `src/rpc/mod.rs`, `src/rpc/trait_def.rs`, `src/rpc/ws.rs`, `tests/rpc_ws.rs`
- Modify: `src/lib.rs`, `Cargo.toml`, `tests/00_chopsticks_sanity.rs`

- [ ] **Step 1: Delete the files**

```bash
git rm -r src/rpc tests/rpc_ws.rs
```

- [ ] **Step 2: Remove the module from `src/lib.rs`**

Remove the line `pub mod rpc;` and update the doc-comment's build-modes list. New lib.rs:

```rust
//! Read-only client for the `OrgRegistry` contract on Asset Hub via
//! `pallet-revive`. See the design at
//! `docs/superpowers/specs/2026-05-13-ods-phase-1b-design.md` (§3 covers
//! this crate's public surface; §5.2 lists the integration test scenarios
//! that gate Stage 2) as amended by
//! `docs/superpowers/specs/2026-06-04-ods-phase-1b-stage2-subxt-commitment-design.md`
//! (single transport stack: subxt).
//!
//! Build modes:
//!
//! - `default = ["dev-rpc"]`: std + subxt over jsonrpsee. Used by
//!   integration tests against a chopsticks fork.
//! - `--no-default-features`: `no_std + alloc`. Types, decoders and
//!   verifier only; no client available.
//! - `--no-default-features --features smoldot`: std + subxt's smoldot
//!   light client. Used by the Phase 1.c PWA and the live-Paseo smoke test.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "client")]
pub mod client;
pub mod decode;
pub mod h160;
pub mod state;
pub mod types;
pub mod verify;

pub use crate::state::{BlockHash, BlockRef, Event, OrgState, SubscribedEvent};
pub use crate::types::{Epoch, OnChainRootHash, OrgAdmin, OrgPubKey};

#[cfg(feature = "client")]
pub use crate::client::{ClientError, OrgRegistryClient, SubscribedEventStream};
```

- [ ] **Step 3: Rework `Cargo.toml`**

Replace the `[features]`, `[dependencies]` and `[dev-dependencies]` sections wholesale. Key moves: lib keeps only `parity-scale-codec`, `tiny-keccak`, `futures-core`, `futures-util`, `subxt`; everything test-only (`jsonrpsee`, `tokio`, `serde_json`, `hex`, `subxt-signer`, `libc`, `blake2`) becomes a dev-dependency; subxt becomes target-specific so the wasm32 lane can use `web` instead of `native`.

```toml
# Self-contained workspace declaration. The repo root has a workspace
# Cargo.toml (Phase 1.d landed `org-members`, `spike-*` as members);
# without this empty `[workspace]` cargo walks up to that root and
# refuses to build us because we're not listed as a member. We're
# intentionally outside that workspace — Phase 1.b ships as a separate
# unit and this crate has different lint/edition settings.
[workspace]

[package]
name = "on-chain-client"
version = "0.1.0"
edition = "2024"
rust-version = "1.85"
license = "GPL-3.0-only"
description = "Read-only client for the OrgRegistry contract deployed via pallet-revive on Asset Hub."

[features]
default = ["dev-rpc"]
# `std` is an explicit feature so the client feature can opt into it.
# Without `std`, the crate compiles as `no_std + alloc` — types, decoders
# and verifier only.
std = []
# The subxt-based OrgRegistryClient. Transport-agnostic: callers hand in
# an OnlineClient built on whatever backend fits (LegacyBackend for
# chopsticks tests, ChainHeadBackend / light-client for production).
client = ["std", "dep:futures-core", "dep:futures-util", "dep:subxt"]
# Test/dev profile: client over subxt's jsonrpsee WS transport.
dev-rpc = ["client"]
# Production/PWA profile: client over subxt's embedded smoldot light
# client (per the 2026-06-04 amendment, this replaced the hand-rolled
# SmoldotRpc).
smoldot = ["client", "subxt/light-client"]

[dependencies]
# SCALE decoder for pallet-revive event payloads. no_std + alloc compatible
# by default — the decoder module compiles in every feature config.
parity-scale-codec = { version = "3", default-features = false, features = ["derive"] }
# Keccak-256 for Solidity event signatures + storage-slot derivation
# (mapping(address => OrgState) keys are keccak(abi.encode(...))), and
# for pallet-revive's AccountId32 → H160 mapping in `h160`.
# Pure-Rust + no_std-compatible.
tiny-keccak = { version = "2", default-features = false, features = ["keccak"] }
futures-core = { version = "0.3", default-features = false, features = ["alloc"], optional = true }
futures-util = { version = "0.3", default-features = false, features = ["std"], optional = true }

# subxt powers the entire client: backend/transport, metadata-aware
# storage + event access, runtime-API calls (ReviveApi::get_storage),
# and (behind `smoldot`) the embedded light client. Feature sets differ
# per target: native hosts get the jsonrpsee WS transport; wasm32 gets
# the browser (`web`) platform. The `light-client` feature is layered on
# by our `smoldot` feature for either target.
[target.'cfg(not(target_arch = "wasm32"))'.dependencies]
subxt = { version = "0.50", default-features = false, features = ["native", "jsonrpsee"], optional = true }

[target.'cfg(target_arch = "wasm32")'.dependencies]
subxt = { version = "0.50", default-features = false, features = ["web"], optional = true }

[dev-dependencies]
# Test-only deps. Integration tests are all `#![cfg(feature = "dev-rpc")]`
# and run on native hosts only.
jsonrpsee = { version = "0.26", default-features = false, features = ["ws-client", "http-client"] }
tokio = { version = "1", default-features = false, features = ["rt", "rt-multi-thread", "macros", "sync", "time", "process"] }
serde_json = { version = "1", default-features = false, features = ["alloc"] }
hex = { version = "0.4", default-features = false, features = ["alloc"] }
subxt-signer = { version = "0.50", default-features = false, features = ["sr25519", "subxt"] }
# blake2b-256 for pallet-multisig pseudo-account derivation in
# tests/common/multisig.rs.
blake2 = "0.10"
# libc is used by the chopsticks_fork harness to put the chopsticks
# subprocess in its own process group (setsid in pre_exec) and tear it
# down with killpg in Drop — chopsticks forks a worker process and
# SIGKILLing only the parent orphans the worker.
libc = "0.2"

[lints.clippy]
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
```

Note: `src/client.rs` is currently gated `#[cfg(feature = "dev-rpc")]` via lib.rs — Step 2's lib.rs already re-gates it on `client`. No change inside client.rs needed for this task.

- [ ] **Step 4: Rewire `tests/00_chopsticks_sanity.rs` off WsRpc**

Replace the WsRpc round-trip with a raw jsonrpsee call — the point of the test is "fork up, RPC answering, fork down", not our (now deleted) transport:

```rust
//! Stage 2 Task 6 gate. Confirms the test harness can spin a
//! chopsticks-Paseo fork up, talk to it, and shut it down cleanly.
//! Numeric `00_` prefix keeps it ordered first under `cargo test`
//! reporting so a broken fork shows here before downstream tests fail
//! for confusing reasons.

#![cfg(feature = "dev-rpc")]

mod common;

use common::chopsticks_fork::spawn_fork;
use jsonrpsee::core::client::ClientT;
use jsonrpsee::rpc_params;
use jsonrpsee::ws_client::WsClientBuilder;
use serde_json::Value;

#[tokio::test]
async fn fork_spawns_and_serves_rpc() {
    let fork = spawn_fork().await.expect("spawn chopsticks fork");

    let client = WsClientBuilder::default()
        .build(&fork.ws_url)
        .await
        .expect("ws connect");
    let rv: Value = client
        .request("state_getRuntimeVersion", rpc_params![])
        .await
        .expect("state_getRuntimeVersion");
    let spec_version = rv
        .get("specVersion")
        .and_then(Value::as_u64)
        .expect("specVersion field");
    assert!(spec_version > 0, "spec_version was zero");
    // Dropping `fork` here kills chopsticks; no explicit cleanup needed.
}
```

- [ ] **Step 5: Build matrix + clippy + tests**

```bash
cargo build                                                        # default = dev-rpc
cargo build --no-default-features                                  # no_std types+decode+verify
cargo clippy --all-features --lib -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic
pkill -f "chopsticks.*--config" 2>/dev/null
cargo test --features dev-rpc -- --test-threads=1
```

Expected: all green. (`--features smoldot` is NOT expected to build yet — `subxt/light-client` needs Task 10's chainspecs for its test but the build itself should work; try `cargo build --no-default-features --features smoldot` and note the result in the commit message either way.)

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "refactor(on-chain-client): delete hand-rolled transport stack (amendment Task 1)"
```

---

## Task 2 — Backend policy: `from_client` ctor + legacy-backend test helper

The root cause of the old subscribe flakiness: `OnlineClient::from_url` builds a `CombinedBackend` (chainHead_v1 + legacy mixed) and chopsticks' partial v2 RPC support breaks it silently. Fix: client takes a ready-made `OnlineClient`; tests construct it over `LegacyBackend` explicitly.

**Files:**
- Modify: `src/client.rs` (replace `connect`)
- Create: `tests/common/conn.rs`
- Modify: `tests/common/mod.rs`, `tests/scenario_a_lite.rs`

- [ ] **Step 1: Replace `OrgRegistryClient::connect` with `from_client` in `src/client.rs`**

Delete the `connect` method and put this in its place (same impl block):

```rust
    /// Wrap an already-connected subxt client for the given contract
    /// address. Resolves the runtime version through metadata and pins
    /// the matching decoder — fails fast with `UnsupportedRuntime` if
    /// the version isn't in `decode::dispatch`.
    ///
    /// Backend choice is the caller's: tests use an explicit
    /// `LegacyBackend` (chopsticks fully supports the legacy RPC group
    /// but only part of the v2 `chainHead`/`transactionWatch` groups,
    /// which silently breaks subxt's default `CombinedBackend`);
    /// production uses `ChainHeadBackend` or the smoldot light client.
    pub async fn from_client(
        api: OnlineClient<PolkadotConfig>,
        contract: [u8; 20],
    ) -> Result<Self, ClientError> {
        let at = api
            .at_current_block()
            .await
            .map_err(|e| ClientError::Subxt(format!("at_current_block: {e}")))?;
        let spec_version = at.spec_version();
        let decoder = dispatch::for_runtime(spec_version)
            .map_err(|_| ClientError::UnsupportedRuntime { spec_version })?;

        Ok(Self {
            api,
            contract,
            decoder,
            spec_version,
        })
    }
```

Also update the module doc-comment at the top of client.rs: delete the paragraph mentioning the `Rpc` trait / `WsRpc` ("The [`Rpc` trait][crate::rpc::Rpc] + [`WsRpc`]... one connection per client.") and the "Open items" bullet about `ContractInfoOf`/`ContractStorage` storage path naming (it becomes obsolete in Task 3); replace with one line: "Backend policy and the ReviveApi-based state read are per the 2026-06-04 subxt-commitment amendment."

- [ ] **Step 2: Create `tests/common/conn.rs`**

```rust
//! Build subxt `OnlineClient`s for tests. Always over an explicit
//! `LegacyBackend`: chopsticks fully implements the legacy RPC group
//! (it targets polkadot.js) but only part of the v2 groups — e.g.
//! `transactionWatch_v1_submitAndWatch` is missing — which silently
//! breaks subxt's default `CombinedBackend` (stream_best_blocks yields
//! zero items). Never use `OnlineClient::from_url` against chopsticks.

use std::sync::Arc;

use subxt::OnlineClient;
use subxt::backend::LegacyBackend;
use subxt::config::PolkadotConfig;

pub async fn legacy_client(
    ws_url: &str,
) -> Result<OnlineClient<PolkadotConfig>, Box<dyn std::error::Error>> {
    let rpc_client = subxt::rpcs::RpcClient::from_insecure_url(ws_url).await?;
    let backend: LegacyBackend<PolkadotConfig> = LegacyBackend::builder().build(rpc_client);
    let api = OnlineClient::from_backend(Arc::new(backend)).await?;
    Ok(api)
}
```

- [ ] **Step 3: Register the module in `tests/common/mod.rs`**

Add `pub mod conn;` to the module list.

- [ ] **Step 4: Rewire `tests/scenario_a_lite.rs` to the new construction**

Replace the `OrgRegistryClient::connect(...)` call and the second ad-hoc `OnlineClient::from_url(...)` connection with one legacy-backend client used for both:

```rust
    let api = common::conn::legacy_client(&fork.ws_url).await.expect("legacy client");
    let _client = OrgRegistryClient::from_client(api.clone(), contract)
        .await
        .expect("client construct");
```

and further down, where the test currently reconnects (`let api = OnlineClient::<PolkadotConfig>::from_url(...)`), delete the reconnect and reuse `api`. Remove the now-unused `use subxt::OnlineClient;` / `use subxt::config::PolkadotConfig;` imports if the compiler flags them.

Also rewire `tests/common/submit.rs::submit_update` to take the client instead of a URL — change the signature and connection lines:

```rust
pub async fn submit_update(
    api: &OnlineClient<PolkadotConfig>,
    signer: &Keypair,
    contract_h160: [u8; 20],
    new_root_hash: [u8; 32],
    new_org_pub_key: [u8; 32],
    expected_epoch: u128,
) -> Result<String, SubmitError> {
    let calldata = build_update_calldata(new_root_hash, new_org_pub_key, expected_epoch);
    // (delete the OnlineClient::from_url block — caller provides `api`)
```

and update the call site in scenario_a_lite.rs: `submit_update(&api, &alice, contract, root_hash, org_pub_key, 0)`.

- [ ] **Step 5: Run the suite**

```bash
pkill -f "chopsticks.*--config" 2>/dev/null
cargo test --features dev-rpc -- --test-threads=1
```

Expected: all green (scenario_a_lite still passes — it reads events at a pinned block hash, now over the legacy backend).

- [ ] **Step 6: Clippy + commit**

```bash
cargo clippy --all-features --lib -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic
git add -A
git commit -m "feat(on-chain-client): explicit LegacyBackend construction; from_client ctor"
```

---

## Task 3 — `get_org_state` via `ReviveApi::get_storage` + Scenario A-full

Verified on the live runtime (metadata v15): `ReviveApi::get_storage(address: H160, key: [u8; 32]) -> Result<Option<Vec<u8>>, ContractAccessError>`. This replaces the dead `Revive::ContractStorage` storage-map read.

**Files:**
- Modify: `src/client.rs` (`read_contract_slot`, `ClientError`)
- Rename + extend: `tests/scenario_a_lite.rs` → `tests/scenario_a_full.rs`

- [ ] **Step 1: Write the failing test — rename and extend the scenario**

```bash
git mv tests/scenario_a_lite.rs tests/scenario_a_full.rs
```

Then rewrite the file. Changes from the lite version: (a) events are read via `client.subscribe(None)` instead of the manual per-block fetch — this also closes the handoff's Deferral B verification; (b) after the event assertion, `get_org_state` must return the genesis state. Full new test body:

```rust
//! Scenario-A-full: single-org end-to-end over the legacy backend.
//! Extends the old A-lite (event observation at a pinned block) with:
//!
//! - `subscribe()` driving the event observation (verifies subxt's
//!   block stream actually works over the explicit LegacyBackend —
//!   the old CombinedBackend silently yielded zero items against
//!   chopsticks).
//! - `get_org_state` returning the genesis state via the
//!   `ReviveApi::get_storage` runtime API (per the 2026-06-04
//!   amendment; pallet-revive keeps contract slots in a per-contract
//!   child trie, so there is no storage map to read).
//!
//! Multisig + pure-proxy scenarios layer on top in later tasks.

#![cfg(feature = "dev-rpc")]

mod common;

use std::process::Command;
use std::time::Duration;

use common::chopsticks_fork::spawn_fork;
use common::chopsticks_reorg::mine_block;
use common::conn::legacy_client;
use common::h160_mapper::h160_of;
use common::submit::submit_update;
use futures_util::StreamExt;
use on_chain_client::{
    Epoch, Event, OnChainRootHash, OrgAdmin, OrgPubKey, OrgRegistryClient, OrgState,
    SubscribedEvent,
};
use subxt_signer::sr25519::dev;

#[tokio::test]
async fn single_org_genesis_event_and_state() {
    let fork = spawn_fork().await.expect("spawn fork");

    let contract = deploy_org_registry();
    eprintln!("deployed OrgRegistry at 0x{}", hex::encode(contract));

    let api = legacy_client(&fork.ws_url).await.expect("legacy client");
    let client = OrgRegistryClient::from_client(api.clone(), contract)
        .await
        .expect("client construct");

    let alice = dev::alice();
    let alice_h160 = h160_of(alice.public_key().0);
    let admin = OrgAdmin(alice_h160);

    // Never-written slot reads as None before genesis.
    let pre = client.get_org_state(admin, None).await.expect("pre-genesis read");
    assert_eq!(pre, None, "state should be empty before genesis");

    let mut stream = client.subscribe(None).await.expect("subscribe");

    let root_hash = [0xaau8; 32];
    let org_pub_key = [0xbbu8; 32];
    submit_update(&api, &alice, contract, root_hash, org_pub_key, 0)
        .await
        .expect("submit update");
    let new_best = mine_block(&fork).await.expect("mine_block");
    eprintln!("mined block: {new_best}");

    // The stream should yield the genesis event from the freshly-mined
    // best block. Timeout guards against the old silent-empty-stream
    // failure mode.
    let evt = tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await
        .expect("timed out waiting for subscribed event")
        .expect("stream ended")
        .expect("stream item error");
    let SubscribedEvent::BestBlockEvent { event, at } = evt else {
        panic!("expected BestBlockEvent, got {evt:?}");
    };
    eprintln!("event at block #{} ({:?})", at.number, at.hash);
    assert_eq!(
        event,
        Event::Genesis {
            admin,
            root_hash: OnChainRootHash(root_hash),
            org_pub_key: OrgPubKey(org_pub_key),
        },
        "decoded Genesis event should match submitted update",
    );

    // State read via ReviveApi::get_storage: genesis writes epoch 1.
    let state = client
        .get_org_state(admin, None)
        .await
        .expect("get_org_state")
        .expect("state should exist after genesis");
    assert_eq!(
        state,
        OrgState {
            root_hash: OnChainRootHash(root_hash),
            org_pub_key: OrgPubKey(org_pub_key),
            epoch: Epoch(1),
        },
    );
}
```

Keep the existing `deploy_org_registry()` helper function at the bottom of the file unchanged.

- [ ] **Step 2: Run it to verify it fails for the right reason**

```bash
pkill -f "chopsticks.*--config" 2>/dev/null
cargo test --features dev-rpc --test scenario_a_full -- --nocapture
```

Expected: FAIL inside `get_org_state` — a subxt error mentioning `ContractStorage` not found in metadata (the old dead read path).

- [ ] **Step 3: Replace `read_contract_slot` with the runtime-API call**

In `src/client.rs`, replace the entire `read_contract_slot` method body:

```rust
    async fn read_contract_slot(
        &self,
        slot: &[u8; 32],
        at: Option<BlockHash>,
    ) -> Result<Option<Vec<u8>>, ClientError> {
        // pallet-revive keeps contract slot values in a per-contract
        // child trie — there is no runtime storage map to read. The
        // supported read path is the `ReviveApi::get_storage(address,
        // key)` runtime API (verified present on Paseo AH 2_002_002):
        // it returns Ok(Some(bytes)) / Ok(None) for an existing
        // contract, and Err(ContractAccessError) if `address` has no
        // contract. We surface that Err as ClientError::Subxt — callers
        // construct the client with a known-deployed contract address,
        // so it indicates a wiring bug, not an empty slot.
        let at_block = match at {
            Some(h) => self
                .api
                .at_block(subxt_block_ref(h))
                .await
                .map_err(|e| ClientError::Subxt(format!("at_block: {e}")))?,
            None => self
                .api
                .at_current_block()
                .await
                .map_err(|e| ClientError::Subxt(format!("at_current_block: {e}")))?,
        };

        let args = (
            Value::from_bytes(self.contract.as_slice()),
            Value::from_bytes(slot.as_slice()),
        );
        let payload = subxt::dynamic::runtime_api_call::<_, Result<Option<Vec<u8>>, Value>>(
            "ReviveApi",
            "get_storage",
            args,
        );
        let result = at_block
            .runtime_apis()
            .call(payload)
            .await
            .map_err(|e| ClientError::Subxt(format!("ReviveApi::get_storage: {e}")))?;
        match result {
            Ok(maybe_bytes) => Ok(maybe_bytes),
            Err(access_error) => Err(ClientError::Subxt(format!(
                "ContractAccessError from ReviveApi::get_storage: {access_error:?}"
            ))),
        }
    }
```

Notes for the implementer:
- `subxt::dynamic::runtime_api_call` is the re-export of `subxt::runtime_apis::dynamic` (payload constructor). The turbofish pins `ReturnType = Result<Option<Vec<u8>>, Value>`; `Result`/`Option`/`Vec<u8>` all implement `DecodeAsType`, and the error arm decodes the runtime's `ContractAccessError` enum into an untyped `Value` so we don't have to mirror its variants.
- If type inference rejects `(Value, Value)` as `ArgsType` (it must implement `IntoEncodableValues`), fall back to decoding the whole return as `Value` and pattern-matching variant names `Ok`/`Err`/`Some`/`None` — note it in the commit message if so.
- Delete the now-unused `ClientError::PalletStorageItemMissing` variant and its `Display` arm (nothing returns it after this change; the crate is unreleased so no compat concern).

- [ ] **Step 4: Run the scenario to verify it passes**

```bash
pkill -f "chopsticks.*--config" 2>/dev/null
cargo test --features dev-rpc --test scenario_a_full -- --nocapture
```

Expected: PASS — both the subscribe-driven event assertion and the `OrgState { epoch: Epoch(1), .. }` read.

- [ ] **Step 5: Full suite + clippy**

```bash
pkill -f "chopsticks.*--config" 2>/dev/null
cargo test --features dev-rpc -- --test-threads=1
cargo clippy --all-features --lib -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic
```

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(on-chain-client): get_org_state via ReviveApi::get_storage; scenario A-full green"
```

---

## Task 4 — Promote `h160_of` from test harness to lib

Scenario B / the invariant test make `h160_of` part of the *verification* story (OrgId == `h160_of(P)`), and Phase 1.c will need it from the lib. The implementation already exists in `tests/common/h160_mapper.rs`; `src/h160.rs` is a stub.

**Files:**
- Modify: `src/h160.rs` (replace stub with the implementation + unit tests from `tests/common/h160_mapper.rs`)
- Modify: `tests/common/h160_mapper.rs` (reduce to a re-export)

- [ ] **Step 1: Move the implementation**

Copy the entire contents of `tests/common/h160_mapper.rs` (doc comments, `EVM_FALLBACK_MARK`, `h160_of`, the three unit tests) into `src/h160.rs`, replacing the stub. The code is already lib-grade (no unwrap/expect/panic outside `#[cfg(test)]`).

- [ ] **Step 2: Reduce `tests/common/h160_mapper.rs` to**

```rust
//! Re-export of the lib's pallet-revive AccountId32 → H160 mapping, kept
//! so existing test imports stay stable.

pub use on_chain_client::h160::h160_of;
```

- [ ] **Step 3: Export from lib.rs**

Add to the re-export block in `src/lib.rs`:

```rust
pub use crate::h160::h160_of;
```

- [ ] **Step 4: Build, test, clippy, commit**

```bash
cargo build --no-default-features          # h160 must stay no_std
pkill -f "chopsticks.*--config" 2>/dev/null
cargo test --features dev-rpc -- --test-threads=1
cargo clippy --all-features --lib -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic
git add -A
git commit -m "feat(on-chain-client): promote h160_of to lib (src/h160.rs)"
```

---

## Task 5 — Test harness: multisig module

Implements `multi_account_id` derivation + threshold-1 multisig dispatch + an account-funding helper. The derivation prefix `b"modlpy/utilisuba"` has been stable for years but the handoff mandates an *empirical* pin: the integration test funds the derived address and dispatches through it — if the derivation were wrong, the dispatch would fail with insufficient funds.

Scope note (document in Task 12): only the threshold-1 dispatch path (`Multisig.as_multi_threshold_1`) is implemented. The spec's open item on threshold>1 `as_multi` ceremonies is deferred — Scenarios B and the invariant only need "the admin *set* changes while P stays stable", which threshold-1 multisigs with disjoint signer sets exercise fully.

**Files:**
- Create: `tests/common/multisig.rs`
- Modify: `tests/common/mod.rs`, `tests/common/submit.rs`

- [ ] **Step 1: Extract a reusable `RuntimeCall`-value builder in `tests/common/submit.rs`**

The multisig and proxy paths need to *wrap* a `Revive.call` rather than submit it top-level. Add this function to submit.rs (above `submit_update`), and refactor `submit_update` to use it:

```rust
use subxt::ext::scale_value::Composite;

/// Build the `RuntimeCall::Revive(Call::call { .. })` enum value that
/// invokes `OrgRegistry.update(...)` — usable both as a top-level
/// extrinsic (`dynamic::tx("Revive", "call", args)` unwraps it) and as
/// the inner call of `Multisig.as_multi_threshold_1` / `Proxy.proxy`.
pub fn revive_update_runtime_call(
    contract_h160: [u8; 20],
    new_root_hash: [u8; 32],
    new_org_pub_key: [u8; 32],
    expected_epoch: u128,
) -> Value {
    let calldata = build_update_calldata(new_root_hash, new_org_pub_key, expected_epoch);
    let h160_bytes: Vec<Value> = contract_h160
        .iter()
        .map(|b| Value::u128(u128::from(*b)))
        .collect();
    Value::variant(
        "Revive",
        Composite::unnamed(vec![Value::variant(
            "call",
            Composite::named(vec![
                ("dest".to_string(), Value::unnamed_composite(h160_bytes)),
                ("value".to_string(), Value::u128(0)),
                (
                    "gas_limit".to_string(),
                    Value::named_composite([
                        ("ref_time", Value::u128(u128::from(WEIGHT_REF_TIME))),
                        ("proof_size", Value::u128(u128::from(WEIGHT_PROOF_SIZE))),
                    ]),
                ),
                (
                    "storage_deposit_limit".to_string(),
                    Value::u128(STORAGE_DEPOSIT_LIMIT),
                ),
                ("data".to_string(), Value::from_bytes(calldata)),
            ]),
        )]),
    )
}
```

(`Composite` variant-construction details may need adjusting to scale_value 0.x's exact constructors — `Value::variant(name, Composite)` and the `Composite::named`/`unnamed` constructors exist in the version subxt 0.50 re-exports; if names differ the compiler will say so. The existing `submit_update` keeps its current `dynamic::tx("Revive", "call", call_args)` form — do NOT rewrite it through this builder; the builder is additive.)

- [ ] **Step 2: Create `tests/common/multisig.rs`**

```rust
//! pallet-multisig helpers: pseudo-account derivation + threshold-1
//! dispatch. The derivation is pinned EMPIRICALLY by
//! `multisig_dispatch_executes_from_derived_account` below (Task 5 gate):
//! we fund the derived address and dispatch a transfer *from* it via
//! `as_multi_threshold_1` — a wrong derivation means the funded account
//! and the dispatch origin differ, and the transfer fails with
//! insufficient funds.
//!
//! Threshold-1 only: see the scope note in the Stage 2 completion plan.

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use parity_scale_codec::Encode;
use subxt::OnlineClient;
use subxt::config::PolkadotConfig;
use subxt::dynamic::{self, Value};
use subxt::ext::scale_value::Composite;
use subxt_signer::sr25519::Keypair;

use super::submit::SubmitError;

/// pallet-multisig pseudo-account: `blake2_256(scale_encode((
/// b"modlpy/utilisuba", sorted_signers, threshold)))`. Mirrors
/// `pallet_multisig::Pallet::multi_account_id`.
pub fn multi_account_id(signers: &[[u8; 32]], threshold: u16) -> [u8; 32] {
    let mut sorted: Vec<[u8; 32]> = signers.to_vec();
    sorted.sort();
    let entropy = (b"modlpy/utilisuba", sorted, threshold).encode();
    blake2_256(&entropy)
}

fn blake2_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("32 is a valid blake2b output size");
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("output buffer is the declared size");
    out
}

/// Submit `call` from the 1-of-N multisig formed by `signer` +
/// `other_signatories` via `Multisig.as_multi_threshold_1`. The dispatch
/// origin inside `call` is `multi_account_id(all_signers, 1)`.
/// Does NOT mine — caller drives `dev_newBlock` (chopsticks is manual).
pub async fn dispatch_threshold_1(
    api: &OnlineClient<PolkadotConfig>,
    signer: &Keypair,
    other_signatories: &[[u8; 32]],
    call: Value,
) -> Result<(), SubmitError> {
    let others: Vec<Value> = other_signatories
        .iter()
        .map(|id| Value::from_bytes(id.as_slice()))
        .collect();
    let tx = dynamic::tx(
        "Multisig",
        "as_multi_threshold_1",
        vec![Value::unnamed_composite(others), call],
    );
    let mut tx_client = api
        .tx()
        .await
        .map_err(|e| SubmitError::Subxt(format!("tx_client: {e}")))?;
    tx_client
        .sign_and_submit_then_watch_default(&tx, signer)
        .await
        .map_err(|e| SubmitError::Subxt(format!("as_multi_threshold_1 submit: {e}")))?;
    Ok(())
}

/// Transfer `amount` plancks from `from` to the 32-byte account `dest`
/// via `Balances.transfer_keep_alive`. Used to fund multisig pseudo-
/// accounts and pure proxies (existential deposit + fees + revive
/// storage deposits). Does NOT mine.
pub async fn fund(
    api: &OnlineClient<PolkadotConfig>,
    from: &Keypair,
    dest: [u8; 32],
    amount: u128,
) -> Result<(), SubmitError> {
    let dest_value = Value::variant(
        "Id",
        Composite::unnamed(vec![Value::from_bytes(dest.as_slice())]),
    );
    let tx = dynamic::tx(
        "Balances",
        "transfer_keep_alive",
        vec![dest_value, Value::u128(amount)],
    );
    let mut tx_client = api
        .tx()
        .await
        .map_err(|e| SubmitError::Subxt(format!("tx_client: {e}")))?;
    tx_client
        .sign_and_submit_then_watch_default(&tx, from)
        .await
        .map_err(|e| SubmitError::Subxt(format!("transfer submit: {e}")))?;
    Ok(())
}

/// 100 PAS (Paseo AH uses 10 decimals). Generous budget for existential
/// deposit + fees + pallet-revive storage deposits in scenario tests.
pub const FUND_AMOUNT: u128 = 1_000_000_000_000;
```

- [ ] **Step 3: Register in `tests/common/mod.rs`**

Add `pub mod multisig;` to the module list.

- [ ] **Step 4: Write the empirical-pin integration test**

Create `tests/01_multisig_sanity.rs`:

```rust
//! Task 5 gate: empirical pin of the pallet-multisig pseudo-account
//! derivation. Funds `multi_account_id({alice, bob}, 1)` and then has
//! alice dispatch a transfer FROM that multisig via as_multi_threshold_1.
//! If our derivation diverged from the runtime's, the funded account and
//! the dispatch origin would differ and the inner transfer would fail
//! with insufficient funds — asserted via the post-state balances.

#![cfg(feature = "dev-rpc")]

mod common;

use common::chopsticks_fork::spawn_fork;
use common::chopsticks_reorg::mine_block;
use common::conn::legacy_client;
use common::multisig::{FUND_AMOUNT, dispatch_threshold_1, fund, multi_account_id};
use subxt::dynamic::Value;
use subxt::ext::scale_value::Composite;
use subxt_signer::sr25519::dev;

#[tokio::test]
async fn multisig_dispatch_executes_from_derived_account() {
    let fork = spawn_fork().await.expect("spawn fork");
    let api = legacy_client(&fork.ws_url).await.expect("legacy client");

    let alice = dev::alice();
    let bob = dev::bob();
    let charlie_account: [u8; 32] = dev::charlie().public_key().0;
    let signers = [alice.public_key().0, bob.public_key().0];
    let multi = multi_account_id(&signers, 1);
    eprintln!("multisig account: 0x{}", hex::encode(multi));

    fund(&api, &alice, multi, FUND_AMOUNT).await.expect("fund multisig");
    mine_block(&fork).await.expect("mine fund block");

    // Inner call: transfer 10 PAS from the multisig to charlie.
    let transfer_amount: u128 = 100_000_000_000;
    let inner = Value::variant(
        "Balances",
        Composite::unnamed(vec![Value::variant(
            "transfer_keep_alive",
            Composite::named(vec![
                (
                    "dest".to_string(),
                    Value::variant(
                        "Id",
                        Composite::unnamed(vec![Value::from_bytes(
                            charlie_account.as_slice(),
                        )]),
                    ),
                ),
                ("value".to_string(), Value::u128(transfer_amount)),
            ]),
        )]),
    );

    let charlie_before = free_balance(&api, charlie_account).await;
    dispatch_threshold_1(&api, &alice, &[bob.public_key().0], inner)
        .await
        .expect("as_multi_threshold_1");
    mine_block(&fork).await.expect("mine dispatch block");
    let charlie_after = free_balance(&api, charlie_account).await;

    assert_eq!(
        charlie_after - charlie_before,
        transfer_amount,
        "transfer from derived multisig account did not execute — \
         multi_account_id derivation diverged from the runtime",
    );
}

async fn free_balance(
    api: &subxt::OnlineClient<subxt::config::PolkadotConfig>,
    account: [u8; 32],
) -> u128 {
    let at = api.at_current_block().await.expect("at_current_block");
    let address: subxt::storage::DynamicAddress<Vec<Value>, Value> =
        subxt::dynamic::storage("System", "Account");
    let value = at
        .storage()
        .try_fetch(address, vec![Value::from_bytes(account.as_slice())])
        .await
        .expect("fetch System.Account")
        .expect("account exists");
    let decoded: Value = value.decode_as().expect("decode AccountInfo");
    // AccountInfo { data: AccountData { free, .. }, .. } — walk the
    // composite to `data.free` and read it as u128.
    account_info_free(&decoded)
}

fn account_info_free(info: &Value) -> u128 {
    use subxt::ext::scale_value::{Primitive, ValueDef};
    let ValueDef::Composite(Composite::Named(fields)) = &info.value else {
        panic!("AccountInfo not a named composite: {info:?}");
    };
    let (_, data) = fields
        .iter()
        .find(|(name, _)| name == "data")
        .expect("AccountInfo.data");
    let ValueDef::Composite(Composite::Named(data_fields)) = &data.value else {
        panic!("AccountData not a named composite: {data:?}");
    };
    let (_, free) = data_fields
        .iter()
        .find(|(name, _)| name == "free")
        .expect("AccountData.free");
    match &free.value {
        ValueDef::Primitive(Primitive::U128(v)) => *v,
        other => panic!("free balance not u128: {other:?}"),
    }
}
```

(The `scale_value` introspection enums (`ValueDef`, `Primitive`, `Composite`) are re-exported under `subxt::ext::scale_value`; exact paths may need a one-line fix per the compiler.)

- [ ] **Step 5: Run it**

```bash
pkill -f "chopsticks.*--config" 2>/dev/null
cargo test --features dev-rpc --test 01_multisig_sanity -- --nocapture
```

Expected: PASS. If the assert fires, the derivation prefix/encoding is wrong — dump the runtime's actual multisig events (`Multisig.NewMultisig` carries the multisig account) from the dispatch block and diff against `multi_account_id`'s output before touching the formula.

- [ ] **Step 6: Full suite + commit**

```bash
pkill -f "chopsticks.*--config" 2>/dev/null
cargo test --features dev-rpc -- --test-threads=1
git add -A
git commit -m "feat(on-chain-client): multisig harness — derivation + threshold-1 dispatch, empirically pinned"
```

---

## Task 6 — Test harness: pure-proxy module

`create_pure` / proxied dispatch / proxy rotation. The pure proxy's AccountId32 is **captured from the `Proxy.PureCreated` event**, not derived — the derivation entropy includes block height + extrinsic index, so deriving it offline is both fragile and unnecessary.

**Files:**
- Create: `tests/common/proxy.rs`
- Modify: `tests/common/mod.rs`

- [ ] **Step 1: Create `tests/common/proxy.rs`**

```rust
//! pallet-proxy helpers for the pure-proxy ("P") org-admin pattern:
//!
//! - [`create_pure_via_multisig`] — the multisig M dispatches
//!   `Proxy.create_pure(Any, 0, 0)`; P's AccountId32 is read back from
//!   the `Proxy.PureCreated` event in the mined block (entropy includes
//!   height + ext index, so deriving offline is pointless).
//! - [`proxied`] — wrap a RuntimeCall in `Proxy.proxy(P, None, call)`
//!   so it executes with P as origin.
//! - [`rotate`] — swap the controlling multisig: via the OLD multisig,
//!   P adds the NEW multisig as an Any-proxy delegate, then removes the
//!   old one. P's address (and hence the OrgId `h160_of(P)`) is
//!   untouched.
//!
//! All helpers submit but do NOT mine — the caller drives `dev_newBlock`.

use subxt::OnlineClient;
use subxt::config::PolkadotConfig;
use subxt::dynamic::Value;
use subxt::ext::scale_value::{Composite, Primitive, ValueDef};
use subxt::utils::H256;
use subxt_signer::sr25519::Keypair;

use super::chopsticks_fork::ChopsticksHandle;
use super::chopsticks_reorg::mine_block;
use super::multisig::dispatch_threshold_1;
use super::submit::SubmitError;

/// `RuntimeCall::Proxy(Call::create_pure { proxy_type: Any, delay: 0,
/// index: 0 })` as a dynamic value.
fn create_pure_call() -> Value {
    Value::variant(
        "Proxy",
        Composite::unnamed(vec![Value::variant(
            "create_pure",
            Composite::named(vec![
                (
                    "proxy_type".to_string(),
                    Value::variant("Any", Composite::unnamed(vec![])),
                ),
                ("delay".to_string(), Value::u128(0)),
                ("index".to_string(), Value::u128(0)),
            ]),
        )]),
    )
}

/// Wrap `call` so it executes with `pure_proxy` as origin:
/// `RuntimeCall::Proxy(Call::proxy { real: Id(P), force_proxy_type:
/// None, call })`.
pub fn proxied(pure_proxy: [u8; 32], call: Value) -> Value {
    Value::variant(
        "Proxy",
        Composite::unnamed(vec![Value::variant(
            "proxy",
            Composite::named(vec![
                (
                    "real".to_string(),
                    Value::variant(
                        "Id",
                        Composite::unnamed(vec![Value::from_bytes(pure_proxy.as_slice())]),
                    ),
                ),
                (
                    "force_proxy_type".to_string(),
                    Value::variant("None", Composite::unnamed(vec![])),
                ),
                ("call".to_string(), call),
            ]),
        )]),
    )
}

fn add_proxy_call(delegate: [u8; 32]) -> Value {
    Value::variant(
        "Proxy",
        Composite::unnamed(vec![Value::variant(
            "add_proxy",
            Composite::named(vec![
                (
                    "delegate".to_string(),
                    Value::variant(
                        "Id",
                        Composite::unnamed(vec![Value::from_bytes(delegate.as_slice())]),
                    ),
                ),
                (
                    "proxy_type".to_string(),
                    Value::variant("Any", Composite::unnamed(vec![])),
                ),
                ("delay".to_string(), Value::u128(0)),
            ]),
        )]),
    )
}

fn remove_proxy_call(delegate: [u8; 32]) -> Value {
    Value::variant(
        "Proxy",
        Composite::unnamed(vec![Value::variant(
            "remove_proxy",
            Composite::named(vec![
                (
                    "delegate".to_string(),
                    Value::variant(
                        "Id",
                        Composite::unnamed(vec![Value::from_bytes(delegate.as_slice())]),
                    ),
                ),
                (
                    "proxy_type".to_string(),
                    Value::variant("Any", Composite::unnamed(vec![])),
                ),
                ("delay".to_string(), Value::u128(0)),
            ]),
        )]),
    )
}

/// Create a pure proxy controlled by the 1-of-N multisig (`signer` +
/// `others`). Submits via as_multi_threshold_1, mines one block, and
/// extracts P from the `Proxy.PureCreated` event in that block.
pub async fn create_pure_via_multisig(
    fork: &ChopsticksHandle,
    api: &OnlineClient<PolkadotConfig>,
    signer: &Keypair,
    others: &[[u8; 32]],
) -> Result<[u8; 32], SubmitError> {
    dispatch_threshold_1(api, signer, others, create_pure_call()).await?;
    let block_hash_hex = mine_block(fork)
        .await
        .map_err(|e| SubmitError::Subxt(format!("mine: {e}")))?;
    let block_hash = parse_block_hash(&block_hash_hex)?;

    let at = api
        .at_block(H256(block_hash))
        .await
        .map_err(|e| SubmitError::Subxt(format!("at_block: {e}")))?;
    let events = at
        .events()
        .fetch()
        .await
        .map_err(|e| SubmitError::Subxt(format!("events.fetch: {e}")))?;
    for ev in events.iter() {
        let ev = ev.map_err(|e| SubmitError::Subxt(format!("event iter: {e}")))?;
        if ev.pallet_name() == "Proxy" && ev.event_name() == "PureCreated" {
            let fields = ev
                .field_values()
                .map_err(|e| SubmitError::Subxt(format!("field_values: {e}")))?;
            return account32_from_named_field(&fields, "pure");
        }
    }
    Err(SubmitError::Subxt(
        "no Proxy.PureCreated event in mined block".to_string(),
    ))
}

/// Rotate P's controlling multisig from OLD (signer_old + others_old) to
/// NEW (the 32-byte multisig account `new_multi`). Two proxied calls,
/// each in its own block: add_proxy(new) then remove_proxy(old_multi).
pub async fn rotate(
    fork: &ChopsticksHandle,
    api: &OnlineClient<PolkadotConfig>,
    pure_proxy: [u8; 32],
    signer_old: &Keypair,
    others_old: &[[u8; 32]],
    old_multi: [u8; 32],
    new_multi: [u8; 32],
) -> Result<(), SubmitError> {
    dispatch_threshold_1(
        api,
        signer_old,
        others_old,
        proxied(pure_proxy, add_proxy_call(new_multi)),
    )
    .await?;
    mine_block(fork)
        .await
        .map_err(|e| SubmitError::Subxt(format!("mine add_proxy: {e}")))?;

    dispatch_threshold_1(
        api,
        signer_old,
        others_old,
        proxied(pure_proxy, remove_proxy_call(old_multi)),
    )
    .await?;
    mine_block(fork)
        .await
        .map_err(|e| SubmitError::Subxt(format!("mine remove_proxy: {e}")))?;
    Ok(())
}

fn parse_block_hash(hex_str: &str) -> Result<[u8; 32], SubmitError> {
    let bytes = hex::decode(hex_str.trim_start_matches("0x"))
        .map_err(|e| SubmitError::Subxt(format!("block hash hex: {e}")))?;
    let mut out = [0u8; 32];
    if bytes.len() != 32 {
        return Err(SubmitError::Subxt(format!(
            "block hash was {} bytes",
            bytes.len()
        )));
    }
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Pull a 32-byte AccountId out of a named event field. The dynamic
/// Value for an AccountId32 is a composite wrapping 32 u8 primitives
/// (possibly nested one level — newtype). Handles both shapes.
fn account32_from_named_field(
    fields: &Composite<u32>,
    name: &str,
) -> Result<[u8; 32], SubmitError> {
    let Composite::Named(named) = fields else {
        return Err(SubmitError::Subxt("event fields not named".to_string()));
    };
    let (_, value) = named
        .iter()
        .find(|(n, _)| n == name)
        .ok_or_else(|| SubmitError::Subxt(format!("no field {name:?} in event")))?;
    collect_account32(value)
        .ok_or_else(|| SubmitError::Subxt(format!("field {name:?} is not a 32-byte account")))
}

fn collect_account32(value: &Value<u32>) -> Option<[u8; 32]> {
    match &value.value {
        ValueDef::Composite(c) => {
            let inner: Vec<&Value<u32>> = match c {
                Composite::Named(n) => n.iter().map(|(_, v)| v).collect(),
                Composite::Unnamed(u) => u.iter().collect(),
            };
            if inner.len() == 1 {
                return collect_account32(inner[0]);
            }
            if inner.len() == 32 {
                let mut out = [0u8; 32];
                for (i, v) in inner.iter().enumerate() {
                    match &v.value {
                        ValueDef::Primitive(Primitive::U128(b)) if *b <= 255 => {
                            out[i] = *b as u8;
                        }
                        _ => return None,
                    }
                }
                return Some(out);
            }
            None
        }
        _ => None,
    }
}
```

(Generic parameter on `Value`/`Composite` from `ev.field_values()` is the type-id context `u32`; if subxt 0.50 returns `Composite<u32>` with a different context parameter, adjust the signatures — the shape-walking logic is what matters.)

- [ ] **Step 2: Register in `tests/common/mod.rs`**

Add `pub mod proxy;`.

- [ ] **Step 3: Compile-check the harness**

```bash
cargo test --features dev-rpc --no-run
```

Expected: compiles. (Runtime exercise comes with the scenarios — the helpers are deliberately not given their own fork-spinning test to keep suite wall-clock down; Scenario B failing inside `create_pure_via_multisig` is equally diagnostic.)

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat(on-chain-client): pure-proxy harness — create_pure via PureCreated, proxied dispatch, rotate"
```

---

## Task 7 — Scenario A per spec: `two_orgs_one_watcher.rs`

Two orgs (pure proxies under distinct multisigs), one unfiltered watcher + one filtered watcher, genesis from both + a second update from org A.

**Files:**
- Create: `tests/two_orgs_one_watcher.rs`

- [ ] **Step 1: Write the test**

```rust
//! Scenario A (spec §5.2): two orgs, one watcher. Two pure proxies
//! P_a / P_b controlled by distinct 1-of-2 multisigs each submit a
//! genesis update; an unfiltered watcher sees both, a filtered watcher
//! sees only A's. A second update from A arrives as Event::Update with
//! epoch 2 and prev_root_hash = A's genesis root.

#![cfg(feature = "dev-rpc")]

mod common;

use std::process::Command;
use std::time::Duration;

use common::chopsticks_fork::{ChopsticksHandle, spawn_fork};
use common::chopsticks_reorg::mine_block;
use common::conn::legacy_client;
use common::multisig::{FUND_AMOUNT, dispatch_threshold_1, fund, multi_account_id};
use common::proxy::{create_pure_via_multisig, proxied};
use common::submit::revive_update_runtime_call;
use futures_util::StreamExt;
use on_chain_client::{
    Epoch, Event, OnChainRootHash, OrgAdmin, OrgPubKey, OrgRegistryClient, SubscribedEvent,
    h160_of,
};
use subxt::OnlineClient;
use subxt::config::PolkadotConfig;
use subxt_signer::sr25519::{Keypair, dev};

const ROOT_A1: [u8; 32] = [0xa1; 32];
const KEY_A: [u8; 32] = [0xaa; 32];
const ROOT_A2: [u8; 32] = [0xa2; 32];
const ROOT_B1: [u8; 32] = [0xb1; 32];
const KEY_B: [u8; 32] = [0xbb; 32];

struct Org {
    signer: Keypair,
    other: [u8; 32],
    pure_proxy: [u8; 32],
    admin: OrgAdmin,
}

#[tokio::test]
async fn two_orgs_one_watcher() {
    let fork = spawn_fork().await.expect("spawn fork");
    let contract = deploy_org_registry();
    let api = legacy_client(&fork.ws_url).await.expect("legacy client");
    let client = OrgRegistryClient::from_client(api.clone(), contract)
        .await
        .expect("client construct");

    // Org A: multisig {alice, bob} → P_a. Org B: multisig {charlie, dave} → P_b.
    let org_a = setup_org(&fork, &api, dev::alice(), dev::bob().public_key().0).await;
    let org_b = setup_org(&fork, &api, dev::charlie(), dev::dave().public_key().0).await;
    assert_ne!(org_a.admin, org_b.admin, "distinct orgs must map to distinct OrgIds");

    let mut watcher_all = client.subscribe(None).await.expect("subscribe all");
    let mut watcher_a = client.subscribe(Some(org_a.admin)).await.expect("subscribe A");

    // Genesis A, then genesis B, in separate blocks (deterministic order).
    genesis(&fork, &api, &org_a, contract, ROOT_A1, KEY_A).await;
    genesis(&fork, &api, &org_b, contract, ROOT_B1, KEY_B).await;

    let ev1 = next_event(&mut watcher_all).await;
    let ev2 = next_event(&mut watcher_all).await;
    assert_eq!(
        ev1,
        Event::Genesis {
            admin: org_a.admin,
            root_hash: OnChainRootHash(ROOT_A1),
            org_pub_key: OrgPubKey(KEY_A),
        },
        "first event should be A's genesis (mined first)",
    );
    assert_eq!(
        ev2,
        Event::Genesis {
            admin: org_b.admin,
            root_hash: OnChainRootHash(ROOT_B1),
            org_pub_key: OrgPubKey(KEY_B),
        },
        "second event should be B's genesis",
    );

    // Second update from A: expected_epoch = 1 → epoch becomes 2.
    let update_call =
        revive_update_runtime_call(contract, ROOT_A2, KEY_A, 1);
    dispatch_threshold_1(
        &api,
        &org_a.signer,
        &[org_a.other],
        proxied(org_a.pure_proxy, update_call),
    )
    .await
    .expect("submit A update 2");
    mine_block(&fork).await.expect("mine A update 2");

    let ev3 = next_event(&mut watcher_all).await;
    assert_eq!(
        ev3,
        Event::Update {
            admin: org_a.admin,
            epoch: Epoch(2),
            root_hash: OnChainRootHash(ROOT_A2),
            org_pub_key: OrgPubKey(KEY_A),
            prev_root_hash: OnChainRootHash(ROOT_A1),
        },
    );

    // Filtered watcher: sees A's genesis and A's update — never B's.
    let a1 = next_event(&mut watcher_a).await;
    let a2 = next_event(&mut watcher_a).await;
    assert!(matches!(a1, Event::Genesis { admin, .. } if admin == org_a.admin));
    assert!(
        matches!(a2, Event::Update { admin, epoch, .. } if admin == org_a.admin && epoch == Epoch(2)),
        "filtered watcher's second event should be A's epoch-2 update, got {a2:?}",
    );
}

async fn setup_org(
    fork: &ChopsticksHandle,
    api: &OnlineClient<PolkadotConfig>,
    signer: Keypair,
    other: [u8; 32],
) -> Org {
    let funder = dev::eve();
    let multi = multi_account_id(&[signer.public_key().0, other], 1);
    fund(api, &funder, multi, FUND_AMOUNT).await.expect("fund multisig");
    mine_block(fork).await.expect("mine fund");
    let pure_proxy = create_pure_via_multisig(fork, api, &signer, &[other])
        .await
        .expect("create pure proxy");
    fund(api, &funder, pure_proxy, FUND_AMOUNT).await.expect("fund pure proxy");
    mine_block(fork).await.expect("mine fund proxy");
    Org {
        admin: OrgAdmin(h160_of(pure_proxy)),
        signer,
        other,
        pure_proxy,
    }
}

async fn genesis(
    fork: &ChopsticksHandle,
    api: &OnlineClient<PolkadotConfig>,
    org: &Org,
    contract: [u8; 20],
    root: [u8; 32],
    key: [u8; 32],
) {
    let call = revive_update_runtime_call(contract, root, key, 0);
    dispatch_threshold_1(api, &org.signer, &[org.other], proxied(org.pure_proxy, call))
        .await
        .expect("submit genesis");
    mine_block(fork).await.expect("mine genesis");
}

async fn next_event(
    stream: &mut on_chain_client::SubscribedEventStream,
) -> Event {
    loop {
        let item = tokio::time::timeout(Duration::from_secs(30), stream.next())
            .await
            .expect("timed out waiting for subscribed event")
            .expect("stream ended")
            .expect("stream item error");
        match item {
            SubscribedEvent::BestBlockEvent { event, .. } => return event,
            // Finalised/Reorged notifications (landing in Task 8) are
            // skipped here — this scenario asserts best-block semantics.
            _ => continue,
        }
    }
}

fn deploy_org_registry() -> [u8; 20] {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let on_chain_dir = std::path::PathBuf::from(&manifest_dir).join("../on-chain");

    let output = Command::new("node")
        .arg("scripts/sanity-deploy.mjs")
        .current_dir(&on_chain_dir)
        .env("RPC_URL", "ws://localhost:8000")
        .env("BLOB_PATH", "tmp/revive/OrgRegistry.sol:OrgRegistry.pvm")
        .output()
        .expect("spawn sanity-deploy.mjs");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("--- sanity-deploy stdout ---\n{stdout}--- end stdout ---");
    if !stderr.is_empty() {
        eprintln!("--- sanity-deploy stderr ---\n{stderr}--- end stderr ---");
    }
    assert!(output.status.success(), "sanity-deploy.mjs exited non-zero");

    let marker_line = stdout
        .lines()
        .find(|l| l.starts_with("DEPLOYED_H160="))
        .expect("DEPLOYED_H160= marker not found in deploy output");
    let hex_str = marker_line
        .trim_start_matches("DEPLOYED_H160=")
        .trim_start_matches("0x");
    let bytes = hex::decode(hex_str).expect("decode H160 hex");
    let mut h160 = [0u8; 20];
    assert_eq!(bytes.len(), 20, "deployed H160 was not 20 bytes");
    h160.copy_from_slice(&bytes);
    h160
}
```

Implementation notes:
- If the revive call dispatched through `Proxy.proxy` fails (no `ContractEmitted` event appears), check the block's `System.ExtrinsicFailed` / `Proxy.ProxyExecuted` events first — `ProxyExecuted { result: Err(..) }` carries the inner dispatch error. The most likely cause is pallet-revive refusing an unmapped AccountId32 origin; if so, dispatch `Revive.map_account` AS the pure proxy (`proxied(P, map_account_call)`) once after funding P, then retry. Record whichever way it falls in the test's doc-comment — this pins real chain behaviour the spec cares about (Risk #5).
- `dev::eve()` funds everything to keep alice/bob/charlie/dave nonces predictable for their multisig dispatches.

- [ ] **Step 2: Run it**

```bash
pkill -f "chopsticks.*--config" 2>/dev/null
cargo test --features dev-rpc --test two_orgs_one_watcher -- --nocapture
```

Expected: PASS (after working through any dynamic-API field-name corrections, which fail loudly).

- [ ] **Step 3: Full suite + commit**

```bash
pkill -f "chopsticks.*--config" 2>/dev/null
cargo test --features dev-rpc -- --test-threads=1
git add -A
git commit -m "test(on-chain-client): Scenario A — two orgs, one watcher (multisig + pure proxy)"
```

---

## Task 8 — Scenario B: `off_chain_genesis_ceremony.rs`

Admin set rotates BEFORE genesis; the contract never sees the difference.

**Files:**
- Create: `tests/off_chain_genesis_ceremony.rs`

- [ ] **Step 1: Write the test**

Reuse `deploy_org_registry()` verbatim (copy the fn — tests are separate crates) and the Task 7 helpers:

```rust
//! Scenario B (spec §5.2): off-chain genesis ceremony. A pure proxy P
//! exists but no update() has been called. The admin multisig rotates
//! (M1 {alice,bob} → M2 {charlie,dave}) — P is untouched. The NEW
//! multisig then submits genesis. Asserts: the genesis event's admin is
//! h160_of(P) (the rotation is invisible to the contract), and the old
//! multisig can no longer act through P.

#![cfg(feature = "dev-rpc")]

mod common;

use std::process::Command;
use std::time::Duration;

use common::chopsticks_fork::spawn_fork;
use common::chopsticks_reorg::mine_block;
use common::conn::legacy_client;
use common::multisig::{FUND_AMOUNT, dispatch_threshold_1, fund, multi_account_id};
use common::proxy::{create_pure_via_multisig, proxied, rotate};
use common::submit::revive_update_runtime_call;
use futures_util::StreamExt;
use on_chain_client::{
    Epoch, Event, OnChainRootHash, OrgAdmin, OrgPubKey, OrgRegistryClient, OrgState,
    SubscribedEvent, h160_of,
};
use subxt_signer::sr25519::dev;

const ROOT: [u8; 32] = [0x77; 32];
const KEY: [u8; 32] = [0x88; 32];

#[tokio::test]
async fn rotation_before_genesis_is_invisible_to_contract() {
    let fork = spawn_fork().await.expect("spawn fork");
    let contract = deploy_org_registry();
    let api = legacy_client(&fork.ws_url).await.expect("legacy client");
    let client = OrgRegistryClient::from_client(api.clone(), contract)
        .await
        .expect("client construct");

    let alice = dev::alice();
    let bob: [u8; 32] = dev::bob().public_key().0;
    let charlie = dev::charlie();
    let dave: [u8; 32] = dev::dave().public_key().0;
    let funder = dev::eve();

    // M1 {alice, bob} creates P.
    let m1 = multi_account_id(&[alice.public_key().0, bob], 1);
    fund(&api, &funder, m1, FUND_AMOUNT).await.expect("fund M1");
    mine_block(&fork).await.expect("mine");
    let p = create_pure_via_multisig(&fork, &api, &alice, &[bob])
        .await
        .expect("create P");
    fund(&api, &funder, p, FUND_AMOUNT).await.expect("fund P");
    mine_block(&fork).await.expect("mine");
    let admin = OrgAdmin(h160_of(p));

    // Rotate to M2 {charlie, dave}. P unchanged.
    let m2 = multi_account_id(&[charlie.public_key().0, dave], 1);
    fund(&api, &funder, m2, FUND_AMOUNT).await.expect("fund M2");
    mine_block(&fork).await.expect("mine");
    rotate(&fork, &api, p, &alice, &[bob], m1, m2)
        .await
        .expect("rotate M1 -> M2");

    // Genesis from the NEW multisig.
    let mut stream = client.subscribe(None).await.expect("subscribe");
    let call = revive_update_runtime_call(contract, ROOT, KEY, 0);
    dispatch_threshold_1(&api, &charlie, &[dave], proxied(p, call))
        .await
        .expect("genesis via M2");
    mine_block(&fork).await.expect("mine genesis");

    let evt = tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await
        .expect("timeout")
        .expect("stream ended")
        .expect("stream error");
    let SubscribedEvent::BestBlockEvent { event, .. } = evt else {
        panic!("expected BestBlockEvent, got {evt:?}");
    };
    assert_eq!(
        event,
        Event::Genesis {
            admin,
            root_hash: OnChainRootHash(ROOT),
            org_pub_key: OrgPubKey(KEY),
        },
        "genesis admin must be h160_of(P) — rotation invisible to contract",
    );

    let state = client
        .get_org_state(admin, None)
        .await
        .expect("get_org_state")
        .expect("state exists");
    assert_eq!(
        state,
        OrgState {
            root_hash: OnChainRootHash(ROOT),
            org_pub_key: OrgPubKey(KEY),
            epoch: Epoch(1),
        },
    );

    // The OLD multisig can no longer act through P: its proxied update
    // must NOT produce a contract event (Proxy.NotProxy dispatch error).
    let call2 = revive_update_runtime_call(contract, [0x99; 32], KEY, 1);
    dispatch_threshold_1(&api, &alice, &[bob], proxied(p, call2))
        .await
        .expect("submit (expected to fail at dispatch level)");
    mine_block(&fork).await.expect("mine");
    let stale = tokio::time::timeout(Duration::from_secs(10), stream.next()).await;
    assert!(
        stale.is_err(),
        "old multisig produced a contract event after rotation: {stale:?}",
    );
}
```

Append the same `deploy_org_registry()` helper fn as in Task 7.

- [ ] **Step 2: Run it**

```bash
pkill -f "chopsticks.*--config" 2>/dev/null
cargo test --features dev-rpc --test off_chain_genesis_ceremony -- --nocapture
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "test(on-chain-client): Scenario B — off-chain genesis ceremony, rotation invisible on-chain"
```

---

## Task 9 — `subscribe`: Reorged + FinalisedEvent

Scenario C needs `Reorged` notifications. Implementation: track the previous best `BlockRef` in the stream's scan-state — when a new best block's `parent_hash` is not the previous best's hash, the previous best was reorged out; emit `Reorged { discarded: prev }` before the new block's events. FinalisedEvent comes from a second stream (`stream_blocks()` — subxt's finalized stream) merged in.

**Files:**
- Modify: `src/client.rs` (`subscribe`)

- [ ] **Step 1: Restructure `subscribe`**

Replace the body of `subscribe` with a version that (a) factors the per-block event decoding into a helper, (b) layers reorg detection on the best-block stream, (c) merges a finalized-block stream:

```rust
    /// Subscribe to OrgRegistry events. Yields, per matching contract
    /// event: `BestBlockEvent` (best-fork import), `FinalisedEvent`
    /// (finalized import), and `Reorged { discarded }` when a
    /// previously-best block is no longer an ancestor of the new best
    /// tip (detected via parent-hash mismatch — sufficient for depth-1
    /// reorgs, which is what chopsticks's dev_setHead produces; deeper
    /// reorg walks are a documented follow-up).
    pub async fn subscribe(
        &self,
        admin_filter: Option<OrgAdmin>,
    ) -> Result<SubscribedEventStream, ClientError> {
        let decoder = self.decoder;

        let best = self
            .api
            .stream_best_blocks()
            .await
            .map_err(|e| ClientError::Subxt(format!("stream_best_blocks: {e}")))?;
        let finalized = self
            .api
            .stream_blocks()
            .await
            .map_err(|e| ClientError::Subxt(format!("stream_blocks: {e}")))?;

        // Best-block lane: reorg detection + per-block decode.
        let best_lane = best
            .scan(None::<BlockRef>, move |prev, block_res| {
                let out = match block_res {
                    Ok(block) => {
                        let this_ref = BlockRef {
                            hash: BlockHash(block.hash().0),
                            number: block.number(),
                        };
                        let parent = BlockHash(block.header().parent_hash.0);
                        let reorged = match *prev {
                            Some(p) if p.hash != parent => {
                                Some(SubscribedEvent::Reorged { discarded: p })
                            }
                            _ => None,
                        };
                        *prev = Some(this_ref);
                        Ok((block, reorged))
                    }
                    Err(e) => Err(ClientError::Subxt(format!("best block: {e}"))),
                };
                core::future::ready(Some(out))
            })
            .then(move |res| async move {
                match res {
                    Ok((block, reorged)) => {
                        let mut items: Vec<Result<SubscribedEvent, ClientError>> = Vec::new();
                        if let Some(r) = reorged {
                            items.push(Ok(r));
                        }
                        match decode_block_events(decoder, &block, admin_filter).await {
                            Ok(events) => {
                                let at = BlockRef {
                                    hash: BlockHash(block.hash().0),
                                    number: block.number(),
                                };
                                items.extend(events.into_iter().map(|event| {
                                    Ok(SubscribedEvent::BestBlockEvent { event, at })
                                }));
                            }
                            Err(e) => items.push(Err(e)),
                        }
                        items
                    }
                    Err(e) => alloc::vec![Err(e)],
                }
            })
            .flat_map(futures_util::stream::iter);

        // Finalized lane: per-block decode only.
        let final_lane = finalized
            .then(move |block_res| async move {
                match block_res {
                    Ok(block) => {
                        let at = BlockRef {
                            hash: BlockHash(block.hash().0),
                            number: block.number(),
                        };
                        match decode_block_events(decoder, &block, admin_filter).await {
                            Ok(events) => events
                                .into_iter()
                                .map(|event| Ok(SubscribedEvent::FinalisedEvent { event, at }))
                                .collect(),
                            Err(e) => alloc::vec![Err(e)],
                        }
                    }
                    Err(e) => alloc::vec![Err(ClientError::Subxt(format!("finalized block: {e}")))],
                }
            })
            .flat_map(futures_util::stream::iter);

        let merged = futures_util::stream::select(best_lane, final_lane);
        let boxed: Pin<Box<dyn Stream<Item = Result<SubscribedEvent, ClientError>> + Send>> =
            Box::pin(merged);
        Ok(boxed)
    }
```

And add the factored-out decoding helper as a free async fn in client.rs (replacing the inline loop the old subscribe carried — also delete the now-unused `event_matches_contract` no-op and its call, folding its doc-note into this helper's comment):

```rust
/// Fetch and decode the OrgRegistry events in one block: every
/// `Revive::ContractEmitted` whose payload our decoder recognises,
/// optionally filtered by admin. (Contract-address filtering beyond
/// pallet+variant+ABI-shape is a structural hook for when a future
/// deployment runs many contracts; today the ABI match is the filter.)
async fn decode_block_events<C: subxt::config::Config>(
    decoder: &'static dyn Decoder,
    block: &subxt::client::Block<C, OnlineClient<C>>,
    admin_filter: Option<OrgAdmin>,
) -> Result<Vec<Event>, ClientError> {
    let at_block = block
        .at()
        .await
        .map_err(|e| ClientError::Subxt(format!("block.at: {e}")))?;
    let evs = at_block
        .events()
        .fetch()
        .await
        .map_err(|e| ClientError::Subxt(format!("events.fetch: {e}")))?;

    let mut out = Vec::new();
    for ev in evs.iter() {
        let ev = ev.map_err(|e| ClientError::Subxt(format!("event iter: {e}")))?;
        if ev.pallet_name() != "Revive" || ev.event_name() != "ContractEmitted" {
            continue;
        }
        let parsed = match decoder.parse_revive_event(ev.field_bytes()) {
            Ok(Some(e)) => e,
            Ok(None) => continue,
            Err(e) => return Err(ClientError::Decode(e)),
        };
        if let Some(filter) = admin_filter {
            if !event_matches_admin(&parsed, &filter) {
                continue;
            }
        }
        out.push(parsed);
    }
    Ok(out)
}
```

(The exact path/type of subxt 0.50's block type in a generic helper — `subxt::client::Block` vs a re-export under `subxt::blocks` — and whether it's generic over `Client` will need a compiler-guided touch-up; if generics fight you, make the helper non-generic over `PolkadotConfig` and take `block: &Block<PolkadotConfig, OnlineClient<PolkadotConfig>>`.)

- [ ] **Step 2: Suite must stay green (A-full, A, B all still pass)**

The merged finalized lane changes what existing tests see: chopsticks may report mined blocks as finalized, in which case every scenario event now ALSO arrives as a `FinalisedEvent`. Task 7's `next_event` helper already skips non-best events; scenario_a_full and B match specifically on `BestBlockEvent` but use `stream.next()` once — if a `FinalisedEvent` arrives first they'd panic. Fix A-full and B to use the same skip-loop shape as Task 7's `next_event` (loop until a `BestBlockEvent` arrives) BEFORE running:

```bash
pkill -f "chopsticks.*--config" 2>/dev/null
cargo test --features dev-rpc -- --test-threads=1
```

Expected: green. While here, note (eprintln in one run, then remove) whether chopsticks delivers finalized-head notifications at all — Task 10's Scenario C contingency depends on it.

- [ ] **Step 3: Clippy + commit**

```bash
cargo clippy --all-features --lib -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic
git add -A
git commit -m "feat(on-chain-client): subscribe — Reorged via parent-hash tracking + FinalisedEvent lane"
```

---

## Task 10 — Scenario C: `reorg_cancels_proposed.rs`

**Files:**
- Create: `tests/reorg_cancels_proposed.rs`

- [ ] **Step 1: Write the test**

```rust
//! Scenario C (spec §5.2): a reorg cancels a proposed (best-block-only)
//! update. Genesis lands and is stable; a second update is observed at
//! the best tip; a depth-1 reorg discards that block. Asserts: the
//! watcher receives Reorged { discarded } for it, and finalised state
//! still shows the genesis epoch.
//!
//! Chopsticks finality caveat: chopsticks's dev mode may report each
//! mined block as finalized immediately. If so, the discarded block may
//! have produced a FinalisedEvent BEFORE the reorg — a semantics
//! divergence from live GRANDPA finality, where a finalized block can
//! never be reorged. The test therefore asserts the Reorged
//! notification + the state outcome, and only asserts "no
//! FinalisedEvent for the discarded block" if chopsticks did NOT
//! pre-finalise it. The smoke test (live Paseo) is the authority on
//! real finality semantics; this divergence is recorded in the spec's
//! Open Items (Task 12).

#![cfg(feature = "dev-rpc")]

mod common;

use std::process::Command;
use std::time::Duration;

use common::chopsticks_fork::spawn_fork;
use common::chopsticks_reorg::{induce_reorg, mine_block};
use common::conn::legacy_client;
use common::h160_mapper::h160_of;
use common::submit::submit_update;
use futures_util::StreamExt;
use on_chain_client::{
    Epoch, Event, OnChainRootHash, OrgAdmin, OrgPubKey, OrgRegistryClient, OrgState,
    SubscribedEvent,
};
use subxt_signer::sr25519::dev;

const ROOT_1: [u8; 32] = [0x01; 32];
const ROOT_2: [u8; 32] = [0x02; 32];
const KEY: [u8; 32] = [0x0c; 32];

#[tokio::test]
async fn reorg_discards_proposed_update() {
    let fork = spawn_fork().await.expect("spawn fork");
    let contract = deploy_org_registry();
    let api = legacy_client(&fork.ws_url).await.expect("legacy client");
    let client = OrgRegistryClient::from_client(api.clone(), contract)
        .await
        .expect("client construct");

    let alice = dev::alice();
    let admin = OrgAdmin(h160_of(alice.public_key().0));

    // Genesis (stable base).
    submit_update(&api, &alice, contract, ROOT_1, KEY, 0)
        .await
        .expect("submit genesis");
    let genesis_block = mine_block(&fork).await.expect("mine genesis");

    let mut stream = client.subscribe(None).await.expect("subscribe");

    // Proposed update at the tip.
    submit_update(&api, &alice, contract, ROOT_2, KEY, 1)
        .await
        .expect("submit update 2");
    let update_block = mine_block(&fork).await.expect("mine update");

    // Watcher sees the proposed update as a best-block event.
    let (best_event, best_at) = loop {
        let item = tokio::time::timeout(Duration::from_secs(30), stream.next())
            .await
            .expect("timeout")
            .expect("stream ended")
            .expect("stream error");
        if let SubscribedEvent::BestBlockEvent { event, at } = item {
            break (event, at);
        }
    };
    assert!(
        matches!(best_event, Event::Update { epoch, .. } if epoch == Epoch(2)),
        "expected epoch-2 update at best tip, got {best_event:?}",
    );
    assert_eq!(format!("0x{}", hex::encode(best_at.hash.0)), update_block);

    // Reorg: discard the update block, mine an empty sibling.
    let reorg = induce_reorg(&fork, &update_block, &genesis_block)
        .await
        .expect("induce reorg");
    eprintln!("reorged: discarded {} new best {}", reorg.discarded, reorg.new_best);

    // Watcher receives Reorged for the discarded block.
    let discarded = loop {
        let item = tokio::time::timeout(Duration::from_secs(30), stream.next())
            .await
            .expect("timeout waiting for Reorged")
            .expect("stream ended")
            .expect("stream error");
        if let SubscribedEvent::Reorged { discarded } = item {
            break discarded;
        }
    };
    assert_eq!(
        format!("0x{}", hex::encode(discarded.hash.0)),
        update_block,
        "Reorged should reference the discarded update block",
    );

    // Finalised-state read reflects the genesis, not the discarded update.
    let state = client
        .get_org_state(admin, None)
        .await
        .expect("get_org_state")
        .expect("state exists");
    assert_eq!(
        state,
        OrgState {
            root_hash: OnChainRootHash(ROOT_1),
            org_pub_key: OrgPubKey(KEY),
            epoch: Epoch(1),
        },
        "post-reorg state must be the genesis state",
    );
}
```

Step 1 notes:
- Append the same `deploy_org_registry()` helper as in Task 7.
- If `mine_block`'s mined-hash equality assertions fail because chopsticks returns a different hash format, normalise via lowercase before comparing.

- [ ] **Step 2: Run it**

```bash
pkill -f "chopsticks.*--config" 2>/dev/null
cargo test --features dev-rpc --test reorg_cancels_proposed -- --nocapture
```

Expected: PASS. Two known failure modes to debug systematically (not by tweaking asserts): (a) the legacy backend's best-head subscription doesn't fire for the post-`dev_setHead` block — check chopsticks logs for `chain_subscribeNewHeads` emissions; (b) `get_org_state(admin, None)` reads "current" rather than "latest finalised" under the legacy backend and still sees the discarded state — if so, pass `at = Some(reorg.new_best)` parsed to a `BlockHash` and record the at-semantics nuance for Task 12's doc update.

- [ ] **Step 3: Full suite + commit**

```bash
pkill -f "chopsticks.*--config" 2>/dev/null
cargo test --features dev-rpc -- --test-threads=1
git add -A
git commit -m "test(on-chain-client): Scenario C — reorg discards proposed update, Reorged observed"
```

---

## Task 11 — OrgId invariant: `p_address_is_orgid.rs`

The invariant: the on-chain OrgId (the event's indexed admin / the storage key) IS `h160_of(P)` — pinned against ground truth produced by the runtime itself, surviving a multisig rotation.

**Files:**
- Create: `tests/p_address_is_orgid.rs`

- [ ] **Step 1: Write the test**

```rust
//! OrgId invariant (spec Risk #5): h160_of(P) — our offline pallet-revive
//! AccountId32→H160 mapping — must equal the admin the runtime itself
//! puts in the contract event, and must be stable across a multisig
//! rotation. The runtime event is the ground-truth fixture: if
//! pallet-revive's mapping drifts in a future runtime, this test is the
//! tripwire.

#![cfg(feature = "dev-rpc")]

mod common;

use std::process::Command;
use std::time::Duration;

use common::chopsticks_fork::spawn_fork;
use common::chopsticks_reorg::mine_block;
use common::conn::legacy_client;
use common::multisig::{FUND_AMOUNT, dispatch_threshold_1, fund, multi_account_id};
use common::proxy::{create_pure_via_multisig, proxied, rotate};
use common::submit::revive_update_runtime_call;
use futures_util::StreamExt;
use on_chain_client::{Event, OrgAdmin, OrgRegistryClient, SubscribedEvent, h160_of};
use subxt_signer::sr25519::dev;

#[tokio::test]
async fn pure_proxy_h160_is_org_id_and_survives_rotation() {
    let fork = spawn_fork().await.expect("spawn fork");
    let contract = deploy_org_registry();
    let api = legacy_client(&fork.ws_url).await.expect("legacy client");
    let client = OrgRegistryClient::from_client(api.clone(), contract)
        .await
        .expect("client construct");

    let alice = dev::alice();
    let bob: [u8; 32] = dev::bob().public_key().0;
    let charlie = dev::charlie();
    let dave: [u8; 32] = dev::dave().public_key().0;
    let funder = dev::eve();

    // M1 → P. Predict the OrgId offline BEFORE the chain confirms it.
    let m1 = multi_account_id(&[alice.public_key().0, bob], 1);
    fund(&api, &funder, m1, FUND_AMOUNT).await.expect("fund M1");
    mine_block(&fork).await.expect("mine");
    let p = create_pure_via_multisig(&fork, &api, &alice, &[bob])
        .await
        .expect("create P");
    fund(&api, &funder, p, FUND_AMOUNT).await.expect("fund P");
    mine_block(&fork).await.expect("mine");
    let predicted_org_id = h160_of(p);

    // Genesis via M1; capture the runtime's admin from the event.
    let mut stream = client.subscribe(None).await.expect("subscribe");
    dispatch_threshold_1(
        &api,
        &alice,
        &[bob],
        proxied(p, revive_update_runtime_call(contract, [0x11; 32], [0x22; 32], 0)),
    )
    .await
    .expect("genesis");
    mine_block(&fork).await.expect("mine");
    let admin_genesis = next_admin(&mut stream).await;
    assert_eq!(
        admin_genesis,
        OrgAdmin(predicted_org_id),
        "runtime's OrgId (event admin) != our offline h160_of(P) — mapping drift",
    );

    // Rotate M1 → M2, then update via M2: OrgId must be unchanged.
    let m2 = multi_account_id(&[charlie.public_key().0, dave], 1);
    fund(&api, &funder, m2, FUND_AMOUNT).await.expect("fund M2");
    mine_block(&fork).await.expect("mine");
    rotate(&fork, &api, p, &alice, &[bob], m1, m2).await.expect("rotate");

    dispatch_threshold_1(
        &api,
        &charlie,
        &[dave],
        proxied(p, revive_update_runtime_call(contract, [0x33; 32], [0x22; 32], 1)),
    )
    .await
    .expect("update via M2");
    mine_block(&fork).await.expect("mine");
    let admin_update = next_admin(&mut stream).await;
    assert_eq!(
        admin_update,
        OrgAdmin(predicted_org_id),
        "OrgId changed across multisig rotation — invariant broken",
    );
}

async fn next_admin(stream: &mut on_chain_client::SubscribedEventStream) -> OrgAdmin {
    loop {
        let item = tokio::time::timeout(Duration::from_secs(30), stream.next())
            .await
            .expect("timeout")
            .expect("stream ended")
            .expect("stream error");
        if let SubscribedEvent::BestBlockEvent { event, .. } = item {
            return match event {
                Event::Genesis { admin, .. } | Event::Update { admin, .. } => admin,
            };
        }
    }
}
```

Append the same `deploy_org_registry()` helper as in Task 7.

- [ ] **Step 2: Run + full suite + commit**

```bash
pkill -f "chopsticks.*--config" 2>/dev/null
cargo test --features dev-rpc --test p_address_is_orgid -- --nocapture
cargo test --features dev-rpc -- --test-threads=1
git add -A
git commit -m "test(on-chain-client): OrgId invariant — h160_of(P) pinned against runtime ground truth"
```

---

## Task 12 — subxt light-client smoke test

**Files:**
- Create: `chainspecs/paseo.raw.json`, `chainspecs/asset-hub-paseo.raw.json`
- Create: `tests/smoldot_smoke.rs`

- [ ] **Step 1: Fetch + commit the chainspecs**

The Paseo community maintains chainspecs in the `paseo-network` GitHub org. Primary candidates:

```bash
mkdir -p chainspecs
curl -fsSL -o chainspecs/paseo.raw.json \
  https://raw.githubusercontent.com/paseo-network/paseo-action-submission/main/pas/chain-specs/paseo.raw.json
curl -fsSL -o chainspecs/asset-hub-paseo.raw.json \
  https://raw.githubusercontent.com/paseo-network/paseo-action-submission/main/pas/chain-specs/asset-hub-paseo.raw.json
jq -r '.name' chainspecs/paseo.raw.json            # expect: Paseo / Paseo Testnet
jq -r '.name' chainspecs/asset-hub-paseo.raw.json  # expect: Paseo Asset Hub
```

If either URL 404s, search the `paseo-network` org (`gh search repos --owner paseo-network chain-spec`) — the files exist under that org; only the repo/path may have moved. The `jq .name` checks are the acceptance criterion, not the URL.

- [ ] **Step 2: Write `tests/smoldot_smoke.rs`**

```rust
//! Live-Paseo smoke test for the subxt light-client path (the Phase 1.c
//! PWA transport). `#[ignore]` because it needs the public internet and
//! live-Paseo peers can be slow to sync from; run explicitly:
//!
//! ```bash
//! cargo test --no-default-features --features smoldot --test smoldot_smoke -- --ignored --nocapture
//! ```
//!
//! Gate (per amendment §4.3): runtime_version matches the pinned decoder
//! AND one finalized-block notification arrives.

#![cfg(feature = "smoldot")]

use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use subxt::OnlineClient;
use subxt::backend::ChainHeadBackend;
use subxt::config::PolkadotConfig;
use subxt::lightclient::LightClient;

const PASEO_RELAY_SPEC: &str = include_str!("../chainspecs/paseo.raw.json");
const PASEO_AH_SPEC: &str = include_str!("../chainspecs/asset-hub-paseo.raw.json");

#[tokio::test]
#[ignore = "needs live Paseo connectivity; run with -- --ignored"]
async fn light_client_reads_live_paseo_ah() {
    let (relay, _relay_rpc) =
        LightClient::relay_chain(PASEO_RELAY_SPEC).expect("relay chain init");
    let ah_rpc = relay.parachain(PASEO_AH_SPEC).expect("parachain init");

    let rpc_client = subxt::rpcs::RpcClient::new(ah_rpc);
    let backend: ChainHeadBackend<PolkadotConfig> =
        ChainHeadBackend::builder().build_with_background_driver(rpc_client);
    let api = OnlineClient::<PolkadotConfig>::from_backend(Arc::new(backend))
        .await
        .expect("client from light-client backend");

    let at = api.at_current_block().await.expect("at_current_block");
    let spec_version = at.spec_version();
    eprintln!("live Paseo AH spec_version = {spec_version}");
    assert!(
        on_chain_client::decode::dispatch::for_runtime(spec_version).is_ok(),
        "no decoder for live runtime {spec_version} — runtime upgraded; \
         add a decoder version (see decode/dispatch.rs)",
    );

    // One finalized block within 5 minutes (light client must sync first).
    let mut finalized = api.stream_blocks().await.expect("stream_blocks");
    let block = tokio::time::timeout(Duration::from_secs(300), finalized.next())
        .await
        .expect("no finalized block within 300s")
        .expect("stream ended")
        .expect("block error");
    eprintln!("finalized #{} {:?}", block.number(), block.hash());
}
```

Implementation notes:
- `subxt::lightclient` is the re-export of `subxt-lightclient` behind the `light-client` feature; `LightClientRpc` implements the RPC-client trait that `subxt::rpcs::RpcClient::new` accepts (via subxt-rpcs's `light-client` feature, pulled in transitively). If the `RpcClient::new(ah_rpc)` conversion needs an explicit wrapper type, follow subxt 0.50's `light_client` example in the subxt repo (`examples/light_client_basic.rs` in the 0.50.1 source under `~/.cargo/registry/src/*/subxt-0.50.1/`).
- The decoder assertion intentionally FAILS when Paseo upgrades past `2_002_002` — that's the tripwire working as designed; the fix is a new decoder version, not a looser assert.

- [ ] **Step 3: Build matrix gates**

```bash
cargo build --no-default-features --features smoldot
cargo build --target wasm32-unknown-unknown --no-default-features --features smoldot
cargo clippy --all-features --lib -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic
```

Expected: native build green. The wasm32 lane exercises subxt's `web` feature set; if it fails inside subxt's dependency tree (not our code), capture the error verbatim in the commit message and flag it to the user — per the amendment §2 this is a "re-assess" trigger, NOT something to patch around.

- [ ] **Step 4: Run the smoke test once**

```bash
cargo test --no-default-features --features smoldot --test smoldot_smoke -- --ignored --nocapture
```

Expected: PASS within ~1-5 min. If live Paseo peers are unreachable, re-run up to 3 times before declaring it flaky; document the outcome either way (Task 13 tags depend on it).

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(on-chain-client): subxt light-client smoke test + pinned Paseo chainspecs"
```

---

## Task 13 — Documentation + tags

**Files:**
- Modify: `docs/superpowers/specs/2026-05-13-ods-phase-1b-design.md` (Open Items)
- Modify: `on-chain-client/README.md`
- Modify: `docs/superpowers/plans/2026-06-04-ods-phase-1b-stage2-handoff.md` (mark superseded)

- [ ] **Step 1: Spec Open Items → Resolved**

In the Phase 1.b design doc's Open Items section, resolve/record:
- Runtime pin: `spec_name = "asset-hub-paseo"`, `spec_version = 2_002_002`.
- Transport: subxt 0.50.1; backends — `LegacyBackend` (chopsticks tests), `ChainHeadBackend` over the smoldot light client (production). The hand-rolled `Rpc`/`WsRpc`/`SmoldotRpc` design is superseded by the 2026-06-04 amendment.
- State read: `ReviveApi::get_storage` runtime API (no storage-map read exists for pallet-revive contract slots).
- Threshold>1 `as_multi` ceremony: still open, deliberately deferred (threshold-1 covers the scenarios' admin-set-rotation semantics).
- Chopsticks finality-semantics divergence in Scenario C (whatever Task 10 empirically recorded).
- Any `at`-semantics nuance for `get_org_state(admin, None)` under the legacy backend (from Task 10).

- [ ] **Step 2: README refresh**

Update `on-chain-client/README.md`: status table (all tasks done), feature matrix (`client`/`dev-rpc`/`smoldot`), quickstart commands (the standing-rules test command + the smoke command), and a CI-matrix section listing exactly:

```
cargo build --no-default-features
cargo build --no-default-features --features smoldot
cargo clippy --all-features --lib -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic
cargo test --features dev-rpc -- --test-threads=1
cargo test --no-default-features --features smoldot --test smoldot_smoke -- --ignored   # smoke job, allowed-flaky
```

- [ ] **Step 3: Mark the handoff doc superseded**

Add at the top of `2026-06-04-ods-phase-1b-stage2-handoff.md`:

```markdown
> **Superseded 2026-06-XX** by the completion of
> [`2026-06-04-ods-phase-1b-stage2-subxt-completion.md`](2026-06-04-ods-phase-1b-stage2-subxt-completion.md).
> Kept for the "Critical technical notes" section, which remains accurate.
```

(Fill in the actual date.)

- [ ] **Step 4: Final gate — everything, from clean**

```bash
pkill -f "chopsticks.*--config" 2>/dev/null
cargo build
cargo build --no-default-features
cargo build --no-default-features --features smoldot
cargo build --target wasm32-unknown-unknown --no-default-features   # types+decode+verify lane
cargo clippy --all-features --lib -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic
cargo test --features dev-rpc -- --test-threads=1
```

Expected: all green. Then commit and tag:

```bash
git add -A
git commit -m "docs(phase-1b stage 2): pin runtime/transport/CI matrix; resolve spec open items"
git tag v0.2.0-on-chain-client-stage2
# Only if Task 12 Step 4's smoke run passed:
git tag v0.2.0-stage2-smoldot-ok
```

- [ ] **Step 5: Hand back to the user**

Stage 2's gate is now green in the worktree. Per AGENTS.md, the squash-merge onto master is the user's signed commit — surface the `superpowers:finishing-a-development-branch` skill and stop.

---

## Risks carried into execution

| Risk | First seen in | Response |
|---|---|---|
| `(Value, Value)` not accepted as `IntoEncodableValues` args for the dynamic runtime-API payload | Task 3 | Fall back to whole-return `Value` decoding + variant matching; note in commit |
| pallet-revive rejects unmapped pure-proxy origin (`map_account` required) | Task 7 | Dispatch `Revive.map_account` as P via `proxied(...)`; document in test |
| Chopsticks insta-finalises mined blocks (Scenario C finality divergence) | Task 9/10 | Assert Reorged + state outcome; record divergence in spec Open Items |
| Legacy backend `at = None` reads best rather than finalised | Task 10 | Pin explicit block hash in the assert; record at-semantics in spec |
| subxt `web` + `light-client` fails on wasm32 inside subxt's dep tree | Task 12 | Capture error, STOP, flag to user — amendment §2 re-assess trigger |
| Live-Paseo smoke flaky | Task 12 | `#[ignore]` + ≤3 retries + documented re-run window; tag `smoldot-ok` only on green |
