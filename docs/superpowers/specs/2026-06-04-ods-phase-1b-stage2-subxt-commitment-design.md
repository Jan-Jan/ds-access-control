# ODS Phase 1.b Stage 2 amendment — commit to subxt fully

**Status:** approved 2026-06-04.
**Amends:** [`2026-05-13-ods-phase-1b-design.md`](2026-05-13-ods-phase-1b-design.md) §"Transport abstraction" and the Stage 2 plan [`../plans/2026-05-28-ods-phase-1b-stage2-rust-client.md`](../plans/2026-05-28-ods-phase-1b-stage2-rust-client.md) Tasks 3, 5, 8, 9.
**Context:** [`../plans/2026-06-04-ods-phase-1b-stage2-handoff.md`](../plans/2026-06-04-ods-phase-1b-stage2-handoff.md) — Deferrals A and B.

---

## 1. Problem

Stage 2 as built carries two parallel transport stacks:

- The planned architecture: `OrgRegistryClient<R: Rpc>` over our own `Rpc` trait
  (`chain_head_storage`, `chain_head_follow`), with `WsRpc` (jsonrpsee) for tests and a
  hand-rolled `SmoldotRpc` for production WASM (plan Tasks 3 + 8).
- The as-built Task 5: `OrgRegistryClient` on **subxt** (`OnlineClient`) for submission,
  storage and event decoding — with `WsRpc` alive alongside it but used only by
  `tests/rpc_ws.rs`.

Both handoff deferrals are symptoms of the split:

- **Deferral A** — `get_org_state` targeted a `Revive::ContractStorage` runtime storage
  map that does not exist; pallet-revive keeps contract slots in a per-contract child
  trie.
- **Deferral B** — `subscribe()` via subxt's `stream_best_blocks` closes early against
  chopsticks.

## 2. Decision

**`OrgRegistryClient` is subxt-native, full stop.** The hand-rolled transport layer is
deleted from the lib: `src/rpc/` (the `Rpc` trait, `WsRpc`) and the planned `SmoldotRpc`.
`tests/rpc_ws.rs` (Task 3's gate) is deleted with it; Task 3's commit stays in history.

What remains ours:

| Module | Why it stays |
|---|---|
| `types.rs`, `state.rs` | Public typed surface; `no_std + alloc` |
| `decode/` | Runtime-version-gated Solidity-ABI decoders. subxt yields raw revive event/storage bytes; these give them meaning |
| `h160.rs` | `h160_of` mapping (production impl still pending) |
| `verify.rs` | `verify_root_against_chain` ↔ `org_members::CandidateTrie` |

**Re-assess trigger:** if any step proves impossible in subxt, stop and revisit this
decision — do not patch around it with a second stack.

## 3. Verified feasibility facts (probed 2026-06-04, chopsticks fork of Paseo AH `spec_version 2_002_002`)

1. **`ReviveApi::get_storage` exists on the live runtime.** Metadata v15 (via
   `state_call Metadata_metadata_at_version 0x0f000000` — note: plain `state_getMetadata`
   returns v14, which omits runtime APIs) lists
   `ReviveApi::get_storage(address: H160, key: [u8; 32]) -> Result<Option<Vec<u8>>, _>`
   ("Query a given storage key in a given contract"), plus `get_storage_var_key`.
2. **subxt 0.50's default backend is `CombinedBackend`** (`from_rpc_client_with_config`,
   `online_client.rs`) — chainHead_v1 + legacy mixed. Chopsticks' partial v2 RPC support
   (no `transactionWatch_v1_submitAndWatch`) breaks it silently. This is the root cause
   of Deferral B.
3. **`OnlineClient::from_backend(Arc<B>)` is public**, and `LegacyBackend::builder()` /
   `ChainHeadBackend::builder()` are constructible — backend selection is ours.
4. **subxt ships a smoldot-backed light client** (`light-client` feature →
   `subxt-lightclient`) and a browser lane (`web` feature). Hand-rolling `SmoldotRpc` is
   unnecessary.
5. **`subxt::dynamic::runtime_api_call(trait, method, args)`** exists for metadata-driven
   runtime-API calls — no codegen needed.

## 4. Design

### 4.1 Transport/backend policy (fixes Deferral B)

`OrgRegistryClient::new(api: OnlineClient<C>)` — the client takes a ready-made subxt
client and stops caring about transports. Construction policy lives at the edges:

- **Tests (chopsticks):** `LegacyBackend::builder().build(rpc_client)` →
  `OnlineClient::from_backend(...)`. Chopsticks fully supports the legacy RPC group (it
  targets polkadot.js). Never use `from_url`/`from_rpc_client` against chopsticks.
- **Production/live:** `ChainHeadBackend`, and the subxt light client for the
  browser/PWA path.

`subscribe()`'s existing `stream_best_blocks` implementation is kept as-is; Scenario
A-full verifies it over the legacy backend.

### 4.2 `get_org_state` via runtime API (fixes Deferral A)

- `subxt::dynamic::runtime_api_call("ReviveApi", "get_storage", [address, key])`
  executed at a `ClientAtBlock`, so historical `at` reads work.
- Three calls for slots `S`, `S+1`, `S+2` (derived by the already-unit-tested
  `solidity_mapping_slot` / `increment_slot`), concatenated into the 96-byte blob the
  existing `decode_org_state` consumes.
- The dead `Revive::ContractStorage` dynamic-storage path is deleted.
- `tests/scenario_a_lite.rs` is promoted to `scenario_a_full`: the event assertion stays,
  plus `get_org_state` must return `OrgState { root_hash, org_pub_key, epoch: Epoch(1) }`.

### 4.3 Tasks 8 + 9 rewritten

- The `smoldot` cargo feature becomes a thin alias over `subxt/light-client`.
- Smoke test: build an `OnlineClient` from subxt's `LightClient` with the pinned Paseo AH
  chainspec; assert `runtime_version` + one finalized-block notification; disconnect.
- Browser path for Phase 1.c: `subxt/web + light-client`.
- Build matrix: the old `--no-default-features --features smoldot` wasm32 lanes are
  replaced by a `wasm32 + subxt/web` lane. The plain `--no-default-features`
  (types + decode + verify, `no_std`) lane stays.

### 4.4 Remaining work, re-sequenced

1. **Amendment groundwork** — delete `src/rpc/` + `tests/rpc_ws.rs`, rewire client
   construction to `from_backend(LegacyBackend)`, all existing tests green again.
2. **`get_org_state`** via `ReviveApi::get_storage`; promote Scenario A-lite → A-full
   (also closes `subscribe` verification).
3. **Task 6 finish** — `common::multisig` + `common::swap_proxy`, fixture-pinned from
   chopsticks (do not trust prefixes from old substrate docs).
4. **Task 7** — Scenarios B, C, OrgId invariant.
5. **Tasks 8 + 9** — subxt light-client smoke vs live Paseo.
6. **Task 10** — pin versions; fold this amendment into the spec's Open Items.

Stage 2 gate is unchanged in substance: full scenario matrix + smoke + clippy
(`unwrap_used`/`expect_used`/`panic` denied in lib code) + tag
`v0.2.0-on-chain-client-stage2`.

## 5. Risks

| Risk | Exposure | Mitigation |
|---|---|---|
| `LegacyBackend` also misbehaves on chopsticks | Low — legacy RPC is chopsticks' primary target | First "re-assess" trigger of §2 |
| subxt light client flaky vs live Paseo | Known (plan Task 9) | `#[ignore]` + documented re-run window |
| Reorg semantics differ legacy vs chainHead backend | Scenario C pins chopsticks/legacy behaviour only | Smoke test (chainHead path) is the live-behaviour check; note in Task 10 doc updates |
| subxt 0.50 → 0.5x churn on `runtime_api_call` / backend builders | Medium | Version pinned in `Cargo.toml`; upgrade is a deliberate task, never incidental |
