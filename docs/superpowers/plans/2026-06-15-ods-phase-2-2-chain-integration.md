# ODS Phase 2.2 — `org-node` chain integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Wire `org-node` to the real chain — implement its `ChainReader` over `on-chain-client`'s `OrgRegistryClient` (reads), and build the on-chain **write path** (`update()` submission through a threshold-1 pure-proxy multisig, plus the genesis ceremony) using `subxt`. Prove it end-to-end against a chopsticks fork.

**Architecture:** All chain code is gated behind a new `chain` cargo feature, so the Phase 2.1 core (envelope/verify/sequence) stays `subxt`-free and fast to build. Reads adapt `on-chain-client`'s typed `OrgState` to `org-node`'s `OrgState`. Writes productionise the logic currently living in `on-chain-client/tests/common/` (calldata, multisig, proxy, submit) into `org-node`'s library, **decoupled from chopsticks**: submit functions return the extrinsic hash without mining, and block production is driven by the caller (the integration test mines via `dev_newBlock`; a live chain produces blocks itself).

**Tech Stack:** Rust 2021, `subxt` 0.50 + `subxt-signer` 0.50 (dynamic API — no metadata codegen), `on-chain-client` (path dep, `dev-rpc` feature for the test), `tokio`, `org-members`, `org-node` Phase 2.1 core.

**Spec:** [`docs/superpowers/specs/2026-06-15-ods-phase-2-poc-design.md`](../specs/2026-06-15-ods-phase-2-poc-design.md) §3.2 (crate reuse), §4 (data model / org_id = h160_of(P)), §6 (stories 1 & 3 — genesis + admit write).

**Reference (read these before starting):**
- `on-chain-client/src/{types,state,client,h160}.rs` — the read API and typed values.
- `on-chain-client/tests/common/{submit,multisig,proxy,chopsticks_fork,chopsticks_reorg,conn}.rs` — the write helpers being productionised. **These are the source of truth to lift from.**
- `on-chain-client/tests/off_chain_genesis_ceremony.rs` — the gold-reference end-to-end genesis flow to mirror in Task 6.
- `on-chain/src/OrgRegistry.sol` — `update(bytes32,bytes32,uint256)`, selector `0xf1bc537b`.

---

## Key facts pinned by the exploration (use these exact values)

- **`update` selector:** `[0xf1, 0xbc, 0x53, 0x7b]`. Calldata = `selector ‖ root(32) ‖ orgPubKey(32) ‖ expectedEpoch(uint256 BE, 32)` = 100 bytes.
- **`org_id = h160_of(P)`** where `P` is the pure-proxy `AccountId32`. `on_chain_client::h160_of([u8;32]) -> [u8;20]`.
- **on-chain-client read types:** `OrgAdmin(pub [u8;20])`, `OnChainRootHash(pub [u8;32])`, `OrgPubKey(pub [u8;32])`, `Epoch(pub u64)`; `OrgState { root_hash: OnChainRootHash, org_pub_key: OrgPubKey, epoch: Epoch }`.
- **Client:** `OrgRegistryClient::from_client(api: OnlineClient<PolkadotConfig>, contract: [u8;20]) -> Result<Self, ClientError>`; `get_org_state(admin: OrgAdmin, at: Option<BlockHash>) -> Result<Option<OrgState>, ClientError>`.
- **Multisig pseudo-account:** `blake2_256(SCALE((b"modlpy/utilisuba", sorted_signers, threshold)))` — lift `multi_account_id` from `tests/common/multisig.rs:28` verbatim.
- **Pallet-revive requires `map_account` once** from a fresh pure proxy before its first `Revive.call` (else error 43).
- **Genesis = `update(root, orgPubKey, expectedEpoch=0)`** → epoch becomes 1, emits `GenesisInitialized`.
- **chopsticks does NOT auto-seal** — blocks are produced by `dev_newBlock`. Submit-then-mine-then-read is the required ordering. Use `LegacyBackend` for the subxt client against chopsticks (`tests/common/conn.rs:14`).

---

## File structure

```
org-node/
  Cargo.toml                       # + [feature] chain; + subxt, subxt-signer, on-chain-client, tokio (feature-gated)
  src/
    lib.rs                         # + #[cfg(feature="chain")] pub mod chain_read / chain_write / ceremony
    chain.rs                       # (unchanged) ChainReader trait, OrgState, MockChain
    chain_read.rs                  # NEW: OnChainReader: ChainReader over OrgRegistryClient + type mapping
    chain_write/
      mod.rs                       # NEW: re-exports; WriteError
      calldata.rs                  # NEW: build_update_calldata (pure) + revive_update_runtime_call
      multisig.rs                  # NEW: multi_account_id (pure) + dispatch_threshold_1 + fund
      proxy.rs                     # NEW: proxied, map_account_call, create_pure_via_multisig, rotate
      submit.rs                    # NEW: submit_update (submit-only, returns hash)
    ceremony.rs                    # NEW: genesis_ceremony orchestration (compose proxy+map+update)
  tests/
    chain_genesis_e2e.rs           # NEW (gated): chopsticks end-to-end genesis + admit + read-back + verify
```

`chain_read.rs`, `chain_write/`, and `ceremony.rs` are all `#[cfg(feature = "chain")]`. The pure helpers (`build_update_calldata`, `multi_account_id`) are unit-testable without a chain; the async submit/proxy/ceremony code is exercised by the gated integration test.

---

## Task 0: Add the `chain` feature and dependencies

**Files:**
- Modify: `org-node/Cargo.toml`

- [ ] **Step 1: Add the feature and feature-gated deps**

Edit `org-node/Cargo.toml`. Add a `[features]` section and the chain deps. Keep existing `[dependencies]`/`[dev-dependencies]`.

```toml
[features]
default = []
# On-chain reads (via on-chain-client) + writes (via subxt). Pulls a large
# async stack; the Phase 2.1 core builds and tests without it.
chain = ["dep:subxt", "dep:subxt-signer", "dep:tokio", "dep:on-chain-client", "dep:blake2", "dep:parity-scale-codec", "dep:async-trait", "dep:hex"]

[dependencies]
# ... existing entries unchanged ...
# Features mirror on-chain-client's pins so the subxt types unify across crates.
subxt = { version = "0.50", default-features = false, features = ["native", "jsonrpsee"], optional = true }
subxt-signer = { version = "0.50", default-features = false, features = ["sr25519", "subxt"], optional = true }
tokio = { version = "1", features = ["rt-multi-thread", "macros"], optional = true }
on-chain-client = { path = "../on-chain-client", default-features = false, features = ["dev-rpc"], optional = true }
blake2 = { version = "0.10", optional = true }
parity-scale-codec = { version = "3", default-features = false, features = ["derive"], optional = true }
async-trait = { version = "0.1", optional = true }
hex = { version = "0.4", optional = true }

[dev-dependencies]
# ... existing entries unchanged ...
# The e2e test needs tokio's macros even when running `--features chain`.
tokio = { version = "1", features = ["rt-multi-thread", "macros", "time"] }
```

> `subxt` 0.50 MUST match the version `on-chain-client` pins, so `OnlineClient<PolkadotConfig>` is the same type across both crates. Confirm with `grep '^subxt' ../on-chain-client/Cargo.toml`.
> `on-chain-client`'s `dev-rpc` feature gives the jsonrpsee transport used against chopsticks. (A later phase can switch to `smoldot` for live Paseo.)

- [ ] **Step 2: Verify the core still builds without the feature, and the chain feature resolves**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo build -p org-node`
Expected: builds (no subxt pulled).
Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo build -p org-node --features chain`
Expected: builds (subxt + on-chain-client compile). This will take a while the first time.

- [ ] **Step 3: Commit**

```bash
git add org-node/Cargo.toml
git commit -m "feat(org-node): add feature-gated chain deps (subxt, on-chain-client)"
```

---

## Task 1: `build_update_calldata` (pure, fully testable)

**Files:**
- Create: `org-node/src/chain_write/calldata.rs`
- Create: `org-node/src/chain_write/mod.rs`
- Modify: `org-node/src/lib.rs`

- [ ] **Step 1: Create the write-module root with the error type**

`org-node/src/chain_write/mod.rs`:

```rust
//! On-chain write path: build update() calldata, drive a threshold-1 pure-proxy
//! multisig, and submit extrinsics via subxt. Productionised from
//! on-chain-client/tests/common; decoupled from chopsticks (submit returns the
//! extrinsic hash; block production is the caller's concern).
#![cfg(feature = "chain")]

pub mod calldata;
pub mod multisig;
pub mod proxy;
pub mod submit;

use thiserror::Error;

/// Errors from the on-chain write path.
#[derive(Debug, Error)]
pub enum WriteError {
    #[error("subxt error: {0}")]
    Subxt(String),
    #[error("expected on-chain event not found: {0}")]
    EventNotFound(&'static str),
    #[error("malformed event field: {0}")]
    MalformedEvent(&'static str),
}
```

- [ ] **Step 2: Write the failing test for `build_update_calldata`**

`org-node/src/chain_write/calldata.rs`:

```rust
//! Pure EVM calldata + dynamic runtime-call construction for OrgRegistry.update.
use crate::chain_write::WriteError;

/// keccak256("update(bytes32,bytes32,uint256)")[..4]
pub const UPDATE_SELECTOR: [u8; 4] = [0xf1, 0xbc, 0x53, 0x7b];

/// Build the 100-byte EVM calldata for `update(newRootHash, newOrgPubKey, expectedEpoch)`.
/// Layout: selector(4) ‖ root(32) ‖ orgPubKey(32) ‖ expectedEpoch as uint256 big-endian(32).
pub fn build_update_calldata(
    new_root_hash: [u8; 32],
    new_org_pub_key: [u8; 32],
    expected_epoch: u128,
) -> Vec<u8> {
    let mut data = Vec::with_capacity(100);
    data.extend_from_slice(&UPDATE_SELECTOR);
    data.extend_from_slice(&new_root_hash);
    data.extend_from_slice(&new_org_pub_key);
    let mut epoch_be = [0u8; 32];
    epoch_be[16..32].copy_from_slice(&expected_epoch.to_be_bytes());
    data.extend_from_slice(&epoch_be);
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calldata_layout_is_exact() {
        let root = [0x11u8; 32];
        let key = [0x22u8; 32];
        let data = build_update_calldata(root, key, 7);
        assert_eq!(data.len(), 100);
        assert_eq!(&data[0..4], &UPDATE_SELECTOR);
        assert_eq!(&data[4..36], &root);
        assert_eq!(&data[36..68], &key);
        // epoch 7 as uint256 big-endian: 31 zero bytes then 0x07.
        assert_eq!(data[99], 7);
        assert!(data[68..99].iter().all(|b| *b == 0));
    }
}
```

- [ ] **Step 3: Wire the module and run the test**

In `lib.rs`, add (after the existing modules):

```rust
#[cfg(feature = "chain")]
pub mod chain_write;
```

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-node --features chain --lib chain_write::calldata::`
Expected: `calldata_layout_is_exact` PASS.

- [ ] **Step 4: Add `revive_update_runtime_call`**

Append to `calldata.rs`. This mirrors `on-chain-client/tests/common/submit.rs:91` (`revive_update_runtime_call`) — **copy that function's body exactly**, changing only the import path for `subxt::dynamic::Value`. It builds a `RuntimeCall::Revive(Call::call { dest, value: 0, weight_limit{ref_time,proof_size}, storage_deposit_limit, data })` as a dynamic `Value`. Read `submit.rs:91-130` and reproduce it verbatim here, with this signature:

```rust
use subxt::dynamic::Value;

/// Build the dynamic `Revive.call` runtime call that invokes the contract's
/// update(). Mirror of on-chain-client/tests/common/submit.rs:91 — keep the
/// field names (dest, value, weight_limit{ref_time,proof_size},
/// storage_deposit_limit, data) and the weight/deposit constants identical, as
/// they are matched against runtime metadata.
pub fn revive_update_runtime_call(
    contract_h160: [u8; 20],
    new_root_hash: [u8; 32],
    new_org_pub_key: [u8; 32],
    expected_epoch: u128,
) -> Value {
    // ... exact body from submit.rs:91-130, using build_update_calldata(...) for `data` ...
}
```

> Do not invent constants. The `ref_time = 1_000_000_000_000`, `proof_size = 4_000_000`, `storage_deposit_limit = 10_000_000_000_000` values come straight from the reference; copy them. If the dynamic `Value` construction differs from the reference in any way, prefer the reference.

- [ ] **Step 5: Build with the feature to confirm it compiles**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo build -p org-node --features chain`
Expected: compiles.

- [ ] **Step 6: Commit**

```bash
git add org-node/src/chain_write/mod.rs org-node/src/chain_write/calldata.rs org-node/src/lib.rs
git commit -m "feat(org-node): update() calldata + dynamic Revive.call builder"
```

---

## Task 2: Multisig primitives (`multi_account_id` pure-tested; `dispatch_threshold_1`, `fund`)

**Files:**
- Create: `org-node/src/chain_write/multisig.rs`

- [ ] **Step 1: Lift `multi_account_id` with its pinned-vector test**

`multi_account_id` is pure. Copy it verbatim from `on-chain-client/tests/common/multisig.rs:28` (the `blake2_256((b"modlpy/utilisuba", sorted_signers, threshold))` derivation). Add a test that pins a known vector — **derive the expected value by reading what `01_multisig_sanity.rs` asserts**, or compute it once and hard-pin it:

```rust
//! Threshold-1 multisig: pseudo-account derivation + dispatch + funding.
//! `multi_account_id` mirrors pallet_multisig::Pallet::multi_account_id.
use crate::chain_write::WriteError;

/// Derive the multisig pseudo-account for `signers` at `threshold`.
/// blake2_256(SCALE((b"modlpy/utilisuba", sorted_signers, threshold))).
pub fn multi_account_id(signers: &[[u8; 32]], threshold: u16) -> [u8; 32] {
    // ... exact body from on-chain-client/tests/common/multisig.rs:28 ...
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_account_id_is_order_independent() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        // Sorting inside the derivation must make signer order irrelevant.
        assert_eq!(multi_account_id(&[a, b], 1), multi_account_id(&[b, a], 1));
    }

    #[test]
    fn multi_account_id_depends_on_threshold() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_ne!(multi_account_id(&[a, b], 1), multi_account_id(&[a, b], 2));
    }
}
```

> `multi_account_id` needs `blake2` and `parity-scale-codec`. Add them under the `chain` feature in Cargo.toml (`blake2 = { version = "0.10", optional = true }`, `parity-scale-codec = { version = "3", optional = true }`, and add both to the `chain = [...]` feature list). Match the versions on-chain-client uses.

- [ ] **Step 2: Run the pure tests**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-node --features chain --lib chain_write::multisig::`
Expected: 2 tests PASS.

- [ ] **Step 3: Add `dispatch_threshold_1` and `fund` (async, subxt)**

Append to `multisig.rs`. Copy from `on-chain-client/tests/common/multisig.rs` (`dispatch_threshold_1` at :51, `fund` at :88, `FUND_AMOUNT` at :116), changing the error type to `WriteError` and keeping the subxt dynamic-tx construction identical. Signatures:

```rust
use subxt::dynamic::Value;
use subxt::{OnlineClient, PolkadotConfig};
use subxt_signer::sr25519::Keypair;

pub const FUND_AMOUNT: u128 = 1_000_000_000_000;

/// Submit `Multisig.as_multi_threshold_1(other_signatories, call)`. Sorts
/// signatories ascending (runtime requirement). Does NOT mine/wait.
pub async fn dispatch_threshold_1(
    api: &OnlineClient<PolkadotConfig>,
    signer: &Keypair,
    other_signatories: &[[u8; 32]],
    call: Value,
) -> Result<(), WriteError> {
    // ... exact body from multisig.rs:51, mapping errors to WriteError::Subxt(e.to_string()) ...
}

/// `Balances.transfer_keep_alive(dest, amount)`. Does NOT mine/wait.
pub async fn fund(
    api: &OnlineClient<PolkadotConfig>,
    from: &Keypair,
    dest: [u8; 32],
    amount: u128,
) -> Result<(), WriteError> {
    // ... exact body from multisig.rs:88, mapping errors to WriteError::Subxt ...
}
```

- [ ] **Step 4: Build with feature**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo build -p org-node --features chain`
Expected: compiles.

- [ ] **Step 5: Commit**

```bash
git add org-node/src/chain_write/multisig.rs org-node/Cargo.toml
git commit -m "feat(org-node): multisig pseudo-account, threshold-1 dispatch, fund"
```

---

## Task 3: Proxy primitives (`proxied`, `map_account_call`, `create_pure_via_multisig`, `rotate`) — chopsticks-decoupled

**Files:**
- Create: `org-node/src/chain_write/proxy.rs`

The reference helpers take a `&ChopsticksHandle` and mine internally. **Decouple this:** the productionised versions submit and then read state, but block production is injected by the caller via a `BlockSink` trait so the same code works against chopsticks (mine) and a live chain (wait).

- [ ] **Step 1: Define the `BlockSink` abstraction + lift `proxied`/`map_account_call`**

`org-node/src/chain_write/proxy.rs`:

```rust
//! Pure-proxy creation and call-wrapping. Decoupled from chopsticks via BlockSink.
use subxt::dynamic::Value;
use subxt::{OnlineClient, PolkadotConfig};
use subxt_signer::sr25519::Keypair;

use crate::chain_write::WriteError;

/// Abstraction over "make the chain advance so a just-submitted extrinsic is
/// observable". Chopsticks tests implement this by calling dev_newBlock; a live
/// chain implementation waits for finalisation. Keeps the write path agnostic.
#[async_trait::async_trait]
pub trait BlockSink {
    async fn settle(&self) -> Result<(), WriteError>;
}

/// Wrap `call` so it executes with pure proxy `P` as origin:
/// RuntimeCall::Proxy(proxy { real: Id(P), force_proxy_type: None, call }).
pub fn proxied(pure_proxy: [u8; 32], call: Value) -> Value {
    // ... exact body from on-chain-client/tests/common/proxy.rs:59 ...
}

/// Revive.map_account {} — must be dispatched once by a fresh pure proxy before
/// its first Revive.call.
pub fn map_account_call() -> Value {
    // ... exact body from proxy.rs:99 ...
}
```

> Add `async-trait = { version = "0.1", optional = true }` to deps and to the `chain` feature list.

- [ ] **Step 2: Lift `create_pure_via_multisig` and `rotate`, replacing internal `mine_block` calls with `sink.settle().await?`**

Append to `proxy.rs`. Copy `create_pure_via_multisig` (`proxy.rs:158`) and `rotate` (`proxy.rs:196`), but:
- Replace the `&ChopsticksHandle` parameter with `sink: &dyn BlockSink`.
- Replace each `mine_block(fork).await` with `sink.settle().await?`.
- Keep the `Proxy.PureCreated` event-reading logic (`account32_from_named_field`/`collect_account32` helpers at `proxy.rs:246-287` — copy them too) identical.
- Map errors to `WriteError`.

```rust
/// Submit Proxy.create_pure via threshold-1 multisig, settle, read PureCreated,
/// return P's AccountId32.
pub async fn create_pure_via_multisig(
    sink: &dyn BlockSink,
    api: &OnlineClient<PolkadotConfig>,
    signer: &Keypair,
    others: &[[u8; 32]],
) -> Result<[u8; 32], WriteError> {
    // ... lifted body; mine_block -> sink.settle() ...
}

/// Rotate the multisig controlling P (add new, remove old). P (and org_id) unchanged.
pub async fn rotate(
    sink: &dyn BlockSink,
    api: &OnlineClient<PolkadotConfig>,
    pure_proxy: [u8; 32],
    signer_old: &Keypair,
    others_old: &[[u8; 32]],
    old_multi: [u8; 32],
    new_multi: [u8; 32],
) -> Result<(), WriteError> {
    // ... lifted body; mine_block -> sink.settle() ...
}
```

- [ ] **Step 3: Build with feature**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo build -p org-node --features chain`
Expected: compiles.

- [ ] **Step 4: Commit**

```bash
git add org-node/src/chain_write/proxy.rs org-node/Cargo.toml
git commit -m "feat(org-node): proxy primitives + BlockSink (chopsticks-decoupled)"
```

---

## Task 4: `submit_update` (submit-only)

**Files:**
- Create: `org-node/src/chain_write/submit.rs`

- [ ] **Step 1: Lift the submit function**

`org-node/src/chain_write/submit.rs`:

```rust
//! Submit a contract update() extrinsic. Submit-only: returns the extrinsic
//! hash; the caller settles a block (BlockSink) before reading the result.
use subxt::{OnlineClient, PolkadotConfig};
use subxt_signer::sr25519::Keypair;

use crate::chain_write::calldata::revive_update_runtime_call;
use crate::chain_write::WriteError;

/// Submit `Revive.call` invoking the contract's update(). Signs with `signer`,
/// returns the 0x-prefixed extrinsic hash. Does NOT wait for inclusion.
pub async fn submit_update(
    api: &OnlineClient<PolkadotConfig>,
    signer: &Keypair,
    contract_h160: [u8; 20],
    new_root_hash: [u8; 32],
    new_org_pub_key: [u8; 32],
    expected_epoch: u128,
) -> Result<String, WriteError> {
    // ... exact body from on-chain-client/tests/common/submit.rs:146 (submit_update),
    //     mapping SubmitError -> WriteError::Subxt. Builds the Revive.call dynamic
    //     tx, signs, submits (no wait), returns hex hash. ...
}
```

> Note: for admin writes that go through the proxy+multisig (genesis, updates from a multisig-controlled proxy), the call is wrapped via `proxied(P, revive_update_runtime_call(...))` and dispatched with `dispatch_threshold_1`. `submit_update` here is the **direct** single-signer path (useful when the admin account itself is the contract caller). The ceremony (Task 5) uses the proxied+multisig path. Keep both available.

- [ ] **Step 2: Build + commit**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo build -p org-node --features chain`
Expected: compiles.

```bash
git add org-node/src/chain_write/submit.rs
git commit -m "feat(org-node): submit_update (submit-only, returns extrinsic hash)"
```

---

## Task 5: `OnChainReader` (read path) + type mapping

**Files:**
- Create: `org-node/src/chain_read.rs`
- Modify: `org-node/src/lib.rs`

`org-node`'s `ChainReader` trait (Phase 2.1) returns `org-node`'s `OrgState`. Implement it over `on-chain-client`'s `OrgRegistryClient`, mapping the typed values.

> **Async-trait note:** the Phase 2.1 `ChainReader::get_org_state` is **synchronous** (returns `Result<Option<OrgState>, String>`), but `OrgRegistryClient::get_org_state` is **async**. Do NOT change the core trait (verify.rs depends on its sync shape and is tested synchronously). Instead, `OnChainReader` fetches state asynchronously up-front (the caller does the await before calling verify) and the `ChainReader` impl returns the cached snapshot. Concretely: `OnChainReader` holds a `std::sync::Mutex<Option<OrgState>>` refreshed by an async `refresh(&self, admin)` method; the sync `get_org_state` returns the cached value. This keeps verify-against-chain synchronous while reads happen async.

- [ ] **Step 1: Write `chain_read.rs`**

```rust
//! Adapts on-chain-client's OrgRegistryClient to org-node's synchronous
//! ChainReader. Async fetch refreshes a cached snapshot; the sync trait method
//! returns that snapshot so verify-against-chain stays synchronous.
#![cfg(feature = "chain")]
use std::sync::Mutex;

use on_chain_client::{OrgAdmin, OrgRegistryClient};
use org_members::RootHash;

use crate::chain::{ChainReader, OrgState};
use crate::ids::OrgId;

/// Maps on-chain-client's typed OrgState to org-node's OrgState.
fn map_state(s: on_chain_client::OrgState) -> OrgState {
    OrgState {
        root_hash: RootHash::from_bytes(s.root_hash.0),
        org_pub_key: s.org_pub_key.0,
        epoch: s.epoch.0,
    }
}

/// A ChainReader backed by a live OrgRegistryClient, with a cached snapshot.
pub struct OnChainReader {
    client: OrgRegistryClient,
    org_id: OrgId,
    cached: Mutex<Option<OrgState>>,
}

impl OnChainReader {
    pub fn new(client: OrgRegistryClient, org_id: OrgId) -> Self {
        Self { client, org_id, cached: Mutex::new(None) }
    }

    /// Fetch the latest finalised state for `org_id` and cache it. Call before
    /// invoking verify-against-chain.
    pub async fn refresh(&self) -> Result<(), String> {
        let admin = OrgAdmin(*self.org_id.as_bytes());
        let state = self
            .client
            .get_org_state(admin, None)
            .await
            .map_err(|e| format!("{e:?}"))?
            .map(map_state);
        // Lock poisoning is unreachable here (no panics while held); map it to a string.
        *self.cached.lock().map_err(|_| "cache lock poisoned".to_string())? = state;
        Ok(())
    }
}

impl ChainReader for OnChainReader {
    fn get_org_state(&self, requested: &OrgId) -> Result<Option<OrgState>, String> {
        if requested != &self.org_id {
            return Ok(None); // this reader is pinned to one org
        }
        Ok(*self.cached.lock().map_err(|_| "cache lock poisoned".to_string())?)
    }
}
```

> `OrgState` derives `Copy` (Phase 2.1), so `*self.cached.lock()...?` copies out cleanly. Confirm `OrgState: Copy` — it is.
> Add `#[cfg(feature = "chain")] pub mod chain_read;` and `#[cfg(feature = "chain")] pub use chain_read::OnChainReader;` to `lib.rs`.

- [ ] **Step 2: Build with feature**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo build -p org-node --features chain`
Expected: compiles.

- [ ] **Step 3: Commit**

```bash
git add org-node/src/chain_read.rs org-node/src/lib.rs
git commit -m "feat(org-node): OnChainReader implementing ChainReader over on-chain-client"
```

---

## Task 6: Genesis ceremony orchestration

**Files:**
- Create: `org-node/src/ceremony.rs`
- Modify: `org-node/src/lib.rs`

Compose the primitives into the genesis flow: create proxy P → fund → map_account → submit genesis `update(root, orgPubKey, 0)` through the multisig — mirroring `off_chain_genesis_ceremony.rs` but as reusable library code.

- [ ] **Step 1: Write `ceremony.rs`**

```rust
//! Genesis ceremony: stand up an org's on-chain slot. Composes the chain_write
//! primitives. Block production is injected via BlockSink so this works against
//! chopsticks (mine) and live chains (wait).
#![cfg(feature = "chain")]
use subxt::{OnlineClient, PolkadotConfig};
use subxt_signer::sr25519::Keypair;

use crate::chain_write::multisig::{dispatch_threshold_1, fund, FUND_AMOUNT};
use crate::chain_write::proxy::{create_pure_via_multisig, map_account_call, proxied, BlockSink};
use crate::chain_write::calldata::revive_update_runtime_call;
use crate::chain_write::WriteError;
use crate::ids::OrgId;

/// The on-chain identity produced by genesis.
pub struct GenesisOutcome {
    /// Pure-proxy AccountId32.
    pub p: [u8; 32],
    /// org_id = h160_of(P) — the contract slot key.
    pub org_id: OrgId,
}

/// Run the full genesis ceremony for a single-admin (threshold-1) org.
///
/// Steps (each followed by sink.settle()):
/// 1. create pure proxy P via the admin's threshold-1 multisig
/// 2. fund P
/// 3. map_account from P (pallet-revive prerequisite)
/// 4. submit genesis update(root, orgPubKey, expectedEpoch=0) via proxied multisig
///
/// `funder` pays for P's existential deposit / fees. `admin` is the sole signer;
/// `others` are the multisig co-signatories (empty slice for a 1-of-1).
pub async fn genesis_ceremony(
    sink: &dyn BlockSink,
    api: &OnlineClient<PolkadotConfig>,
    contract_h160: [u8; 20],
    funder: &Keypair,
    admin: &Keypair,
    others: &[[u8; 32]],
    genesis_root: [u8; 32],
    org_pub_key: [u8; 32],
) -> Result<GenesisOutcome, WriteError> {
    // 1. Pure proxy.
    let p = create_pure_via_multisig(sink, api, admin, others).await?;
    // 2. Fund P.
    fund(api, funder, p, FUND_AMOUNT).await?;
    sink.settle().await?;
    // 3. map_account from P.
    dispatch_threshold_1(api, admin, others, proxied(p, map_account_call())).await?;
    sink.settle().await?;
    // 4. Genesis update (expectedEpoch = 0).
    let call = revive_update_runtime_call(contract_h160, genesis_root, org_pub_key, 0);
    dispatch_threshold_1(api, admin, others, proxied(p, call)).await?;
    sink.settle().await?;

    let org_id = OrgId::new(on_chain_client::h160_of(p));
    Ok(GenesisOutcome { p, org_id })
}
```

> Add `#[cfg(feature = "chain")] pub mod ceremony;` to `lib.rs`. `on_chain_client::h160_of` is the pinned mapping.

- [ ] **Step 2: Build with feature + commit**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo build -p org-node --features chain`
Expected: compiles.

```bash
git add org-node/src/ceremony.rs org-node/src/lib.rs
git commit -m "feat(org-node): genesis ceremony orchestration"
```

---

## Task 7: End-to-end chopsticks integration test

**Files:**
- Create: `org-node/tests/chain_genesis_e2e.rs`

This is the proof: against a chopsticks fork, run the org-node genesis ceremony, then an admit update, read state back via `OnChainReader`, and run `verify_envelope_against_chain` against the REAL chain root. It mirrors `on-chain-client/tests/off_chain_genesis_ceremony.rs` for the harness mechanics.

- [ ] **Step 1: Study the reference harness**

Read `on-chain-client/tests/off_chain_genesis_ceremony.rs` and `tests/common/{chopsticks_fork,conn,chopsticks_reorg}.rs` fully. The test must:
- `spawn_fork()` → chopsticks on port 8000 (reuse the same approach; you may copy the needed `common/` helpers into `org-node/tests/common/` OR shell out the same way — copying the minimal `chopsticks_fork.rs`, `conn.rs`, and a `mine_block` is acceptable for a test).
- Deploy the OrgRegistry contract (same Node.js script path the reference uses) and capture the H160.
- Build a `LegacyBackend` subxt client via `legacy_client(ws_url)`.

> Because these test helpers live in `on-chain-client/tests/common/` (not its public API), copy the minimal set needed into `org-node/tests/common/` (chopsticks spawn, legacy_client, mine_block). Keep them test-only. Note in a comment that they are duplicated from on-chain-client's test harness.

- [ ] **Step 2: Implement a chopsticks `BlockSink`**

In the test, implement `BlockSink` by calling `mine_block`:

```rust
struct ChopsticksSink<'a> { handle: &'a ChopsticksHandle }

#[async_trait::async_trait]
impl<'a> org_node::chain_write::proxy::BlockSink for ChopsticksSink<'a> {
    async fn settle(&self) -> Result<(), org_node::chain_write::WriteError> {
        mine_block(self.handle)
            .await
            .map(|_| ())
            .map_err(|e| org_node::chain_write::WriteError::Subxt(format!("{e:?}")))
    }
}
```

- [ ] **Step 3: Write the end-to-end test**

```rust
#![cfg(feature = "chain")]
// Drives the org-node genesis ceremony + an admit update against a chopsticks
// fork, then verifies the received delta against the on-chain root.

// ... harness setup (spawn fork, deploy contract, legacy_client) ...

#[tokio::test]
async fn genesis_then_admit_verifies_against_chain() {
    // 1. Fork + contract + client.
    // 2. dev accounts (subxt_signer::sr25519::dev): funder=eve, admin=alice.
    //    Fund the admin's 1-of-1 multisig account (multi_account_id(&[alice_pub], 1)).
    // 3. Build the genesis trie with org-members: one admin member leaf
    //    (use org-node SigningKeypair for member+device keys, MemberId [1u8;32]).
    //    genesis_root = trie.root_hash().
    // 4. Run genesis_ceremony(sink, api, contract, eve, alice, &[], genesis_root, org_pub_key).
    //    -> GenesisOutcome { p, org_id }.
    // 5. OnChainReader::new(OrgRegistryClient::from_client(api, contract), org_id);
    //    reader.refresh().await; assert get_org_state(org_id) == Some(epoch 1, genesis_root).
    // 6. ADMIT: add member B to the trie -> (new_trie, delta); new_root = new_trie.root_hash().
    //    Build SignedDeltaEnvelope::build(org_id, parent_seq=1, &delta, &admin_member_keypair).
    //    Submit update(new_root, org_pub_key, expected_epoch=1) via proxied multisig; settle.
    //    reader.refresh().await (now epoch 2, new_root).
    // 7. verify_envelope_against_chain(&genesis_trie_mirror, &env, &ctx, &reader)
    //    with ctx.expected_org_id=org_id, author_member_key=&admin_member.verifying_key(),
    //    seq_guard=from_last_seen(1)... wait: genesis is seq? Use parent_seq=2 for the admit
    //    so it is > last_seen(1); ctx.last_committed_epoch=1.
    //    Assert Ok, committed trie root == new_root.
}
```

> Fill in the harness fully (no placeholders in the committed test). The exact org_pub_key can be any fixed 32 bytes for the PoC (the org keypair's public key). Mirror the reference's contract-deploy mechanics exactly. The crux assertion is step 7: the delta verifies because the recomputed root matches the **independently read** on-chain root.

- [ ] **Step 4: Run the e2e test (sequential — shares port 8000)**

Run: `pkill -f "chopsticks.*--config" 2>/dev/null; CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-node --features chain --test chain_genesis_e2e -- --test-threads=1 --nocapture`
Expected: PASS (it spawns chopsticks, runs genesis + admit, verifies). This is slow (fork boot + several blocks).

> If chopsticks is not installed or the contract-deploy script path differs, STOP and report — do not fake the test. The harness must run the real flow.

- [ ] **Step 5: Commit**

```bash
git add org-node/tests/chain_genesis_e2e.rs org-node/tests/common/
git commit -m "test(org-node): chopsticks e2e — genesis + admit verified against chain root"
```

---

## Task 8: Green + clippy + README update

**Files:**
- Modify: `org-node/README.md`

- [ ] **Step 1: Core (no feature) still green**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-node`
Expected: 21 lib tests pass (unchanged by this phase).

- [ ] **Step 2: Chain feature builds + unit tests pass**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-node --features chain --lib`
Expected: pure write-path tests (calldata, multisig) pass alongside the core.

- [ ] **Step 3: Clippy gate (lib, both feature sets)**

Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo clippy -p org-node --lib -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic`
Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo clippy -p org-node --lib --features chain -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic`
Expected: both clean.

- [ ] **Step 4: Update `org-node/README.md`**

Add a "Chain integration (Phase 2.2)" section documenting: the `chain` feature, `OnChainReader` (async refresh → sync ChainReader snapshot), the write path (`chain_write::{calldata,multisig,proxy,submit}`), `ceremony::genesis_ceremony`, the `BlockSink` decoupling, and that the e2e test runs against chopsticks. Note the single-admin / threshold-1 simplification (S1) and that live-Paseo uses on-chain-client's `smoldot` feature (future).

- [ ] **Step 5: Commit**

```bash
git add org-node/README.md
git commit -m "docs(org-node): README — Phase 2.2 chain integration"
```

---

## Self-review notes (author check — applied)

- **Spec coverage:** §3.2 reuse `on-chain-client` reads → Task 5; subxt writes → Tasks 1–4; §6 story 1 genesis → Task 6; story 3 admit-update + verify-against-real-chain → Task 7. The `org_id = h160_of(P)` invariant (§4.1) is produced in Task 6 via `on_chain_client::h160_of`.
- **No core regression:** all chain code is `#[cfg(feature="chain")]`; the Phase 2.1 sync `ChainReader` trait is unchanged (the async/sync gap is bridged by `OnChainReader`'s cached snapshot — explained in Task 5).
- **No invented APIs:** every subxt-touching helper is lifted from a named `on-chain-client/tests/common/*.rs:line`; the plan instructs copying bodies verbatim and only re-typing errors/parameters. Pure helpers (`build_update_calldata`, `multi_account_id`) have full code + tests inline.
- **Chopsticks decoupling:** `BlockSink` replaces the reference's `&ChopsticksHandle`+`mine_block` coupling so the write path is reusable on a live chain.
- **Build constraint:** every cargo command uses `CARGO_HOME=/tmp/cargo_home_fuzz`.
- **Known simplifications carried:** S1 (single admin / threshold-1), S11 (chopsticks ephemeral) per the spec register.

## Follow-up phases (separate plans)
- **2.3 transport** — iroh node (`NodeId = P2pDeviceKey`), authenticated channel, deliver envelope + `org_secret_key`; two-node test driving stories 1→5.
- **2.4 shell** — persona/org persistence (encrypted at rest), Tauri commands/events, SvelteKit screens, two-instance demo.
