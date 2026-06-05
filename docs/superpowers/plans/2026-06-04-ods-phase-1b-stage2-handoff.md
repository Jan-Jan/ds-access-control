# ODS Phase 1.b Stage 2 — handoff status (2026-06-04)

> **Superseded 2026-06-05** by the completion of
> [`2026-06-04-ods-phase-1b-stage2-subxt-completion.md`](2026-06-04-ods-phase-1b-stage2-subxt-completion.md).
> Kept for the "Critical technical notes" section, which remains accurate
> except: WsRpc/the Rpc trait were deleted (subxt-only now), and
> `get_org_state` reads via the `ReviveApi::get_storage` runtime API.

> **Companion doc** to [`2026-05-28-ods-phase-1b-stage2-rust-client.md`](2026-05-28-ods-phase-1b-stage2-rust-client.md) (the plan). This file captures the state of the work as of 2026-06-04 so a future session can pick up cold.

**Worktree:** `/Users/jan-jan/Coding/2-tier-access-control/.claude/worktrees/phase-1b-stage1-solidity/`
**Branch:** `worktree-phase-1b-stage1-solidity`
**Latest commit:** `0a3f489` — `feat(on-chain-client): Tasks 5 + 6.b — OrgRegistryClient + Scenario A-lite`

---

## TL;DR

Stage 2 is **5/10 tasks done end-to-end** (1–5 + half of 6). Scenario A-lite end-to-end passes: deploy → submit → mine → decode event via the real `parse_revive_event` decoder, all in ~24 s against a chopsticks-Paseo fork.

Two known deferrals carry forward and shape what to do next:
1. `OrgRegistryClient::get_org_state` reads via a runtime storage map, but **pallet-revive stores contract slots in a per-contract child trie** (no `ContractStorage` map on the runtime). The code is in place but unverified at runtime; reading requires `childstate_getStorage` or a `ReviveApi` runtime call.
2. `OrgRegistryClient::subscribe` is implemented via subxt's `stream_best_blocks`, but that **closes early against chopsticks** because chopsticks doesn't fully emulate the v2 RPC group subxt expects. The decoder path is verified (Scenario A-lite reads events at a known mined block hash via subxt and runs them through our `parse_revive_event`); only the live-stream plumbing is unverified against chopsticks.

Neither blocker is a crate bug — they're both about how we read from the chain.

---

## Status table

| # | Task | State | Where |
|---|---|---|---|
| 1 | Crate skeleton + feature matrix + types | ✅ | `e573953` |
| 2 | Public types (absorbed into Task 1) | ✅ | `e573953` |
| 3 | `Rpc` trait + `WsRpc` (jsonrpsee, `chainHead_v1_*`) | ✅ | `cdd12f7`; round-trip pinned by `tests/rpc_ws.rs` |
| 4 | Runtime-version-gated storage + event decoders | ✅ | `1de9b7e`; `SPEC_VERSION = 2_002_002` (real Paseo AH value) |
| 5 | `OrgRegistryClient::{get_org_state, subscribe}` | 🟡 event path ✅; `get_org_state` unverified | `0a3f489` |
| 6 | `tests/common/` harness | 🟡 Task-5-enabling subset done (`chopsticks_fork`, `h160_mapper`, `chopsticks_reorg`, `submit`); multisig + swap_proxy deferred to Task 7 | `aef9bcd`, `0a3f489` |
| 7 | Scenarios A/B/C + OrgId invariant | 🟡 A-lite done (event verification); B/C + invariant pending | `0a3f489` |
| 8 | `SmoldotRpc` | ⏳ pending |  |
| 9 | smoldot smoke test | ⏳ pending |  |
| 10 | Pin runtime version + endpoint + method names in design doc | ⏳ pending |  |

---

## What works (committed + tested end-to-end)

- **Lib build matrix:** `cargo build` (default `dev-rpc`), `--no-default-features`, `--no-default-features --features smoldot`, plus both no-default + smoldot on `wasm32-unknown-unknown`. `dev-rpc` does NOT build on wasm32 by design (jsonrpsee/rustls/getrandom). Lib `clippy --all-features` clean.
- **Unit tests (20):** types layout, decoder dispatch, decoder round-trips (storage + both event variants), error paths, signature re-derivation against keccak, `solidity_mapping_slot` + `increment_slot` numeric correctness.
- **Integration tests:**
  - `tests/00_chopsticks_sanity.rs` — spawns fork, round-trips `runtime_version` via `WsRpc`, drops.
  - `tests/rpc_ws.rs` — `runtime_version` + `chain_head_storage` round-trips against chopsticks.
  - `tests/scenario_a_lite.rs` — full end-to-end: spawn fork → deploy `OrgRegistry` via `../on-chain/scripts/sanity-deploy.mjs` (now emits a `DEPLOYED_H160=` marker line) → connect `OrgRegistryClient` → submit Alice's `update(...)` via `submit_update` (subxt) → `dev_newBlock` → fetch events at the mined block via subxt → decode via our `parse_revive_event` → assert `Event::Genesis { admin: h160_of(alice), root, key }`.
- **Test runner command:**
  ```bash
  cd on-chain-client
  pkill -f "chopsticks.*--config" 2>/dev/null
  cargo test --features dev-rpc -- --test-threads=1
  ```
  The harness uses fixed port 8000; tests share it serially. `setsid` + `killpg` in Drop guarantees no orphans across runs.

---

## Deferrals — what's blocked and why

### A. `get_org_state` is unverified at runtime (Task 5 follow-up)

`src/client.rs::get_org_state` builds a dynamic-storage call against `Revive::ContractStorage`. That storage item **does not exist on the live runtime.** From a chopsticks fork of Paseo AH (`spec_version 2002002`), `pallet_by_name("Revive").storage().entries()` reports:

```
PristineCode, CodeInfoOf, AccountInfoOf, ImmutableDataOf,
DeletionQueue, DeletionQueueCounter, OriginalAccount,
EthereumBlock, BlockHash, ReceiptInfoData,
EthBlockBuilderIR, EthBlockBuilderFirstValues, DebugSettingsOf
```

No `ContractStorage`. pallet-revive stores contract slot values in a **per-contract child trie** keyed by the contract's `TrieId` (read from `AccountInfoOf[contract]`). To read a Solidity slot:

1. Read `Revive::AccountInfoOf[contract_h160]` from the main trie → get the contract's `TrieId`.
2. Read the slot from the child trie identified by `TrieId`, using key = the 32-byte Solidity slot id we already derive in `solidity_mapping_slot`.

Two implementation options:
- **(a)** Use the JSON-RPC `childstate_getStorage(trie_id, key, at_block)` method. Whether subxt supports child-trie reads directly is unclear; may need a direct jsonrpsee call against `WsRpc`.
- **(b)** Use a pallet-revive runtime API. If `ReviveApi::get_storage(contract, key)` exists (look it up from runtime metadata's `apis` field — see the runtime version probe in Section "Commands" below), subxt's `runtime_apis()` can call it.

`solidity_mapping_slot` + `increment_slot` are unit-tested and correct; the missing piece is the child-trie or runtime-API plumbing.

### B. `OrgRegistryClient::subscribe` flaky against chopsticks (Task 5 follow-up)

`subscribe()` uses subxt's `stream_best_blocks().await`. Empirically against chopsticks the stream closes immediately (yields zero items) after `dev_newBlock`. Chopsticks's logs show:

```
ERROR (ws): Method not found: transactionWatch_v1_submitAndWatch
```

That's a v2 JSON-RPC method subxt expects. Chopsticks supports `chainHead_v1_follow` (our own `WsRpc` uses it successfully in `tests/rpc_ws.rs`) but not the full v2 group. Likely cause: subxt 0.50's backend selection picks v2-with-`transactionWatch` for chopsticks; partial support disables `stream_best_blocks` silently.

Scenario A-lite sidesteps by reading events at the **specific block hash** returned by `mine_block` (which IS supported — `chainHead_v1_storage` / `block.events()` work fine). That exercises the same decoder path `subscribe()` uses per-block; only the live-stream plumbing is unverified.

Two options to fix:
- **(a)** Use our own `WsRpc::chain_head_follow` (already proven against chopsticks) to drive subscribe, falling back to subxt only for the per-block event read. Requires bridging the two clients inside `OrgRegistryClient`.
- **(b)** Configure subxt's backend selection explicitly — force the legacy v1 backend or the chainHead-only backend (no `transactionWatch`). Unclear if subxt 0.50 exposes that knob; check `subxt::backend::*` modules.

This is also less urgent if (a) Task 9's smoldot smoke uses live Paseo, not chopsticks — the stream may just work there.

### C. Multisig + swap_proxy (Task 6 → Task 7)

Not started. Needed by:
- Scenario B (off-chain genesis ceremony — admin rotation under stable proxy).
- The OrgId invariant test (`tests/p_address_is_orgid.rs` — pure-proxy H160 doesn't change when controlling multisig rotates).

Both require:
- `common::multisig::pseudo_account(signers, threshold) -> AccountId32`: `blake2_256("modlpy/utilisuba" || signers_sorted || threshold)[..32]` or whatever the current pallet-multisig formula is.
- `common::multisig::pure_proxy_address(delegator, index, height) -> AccountId32`: `blake2_256("modlpy/proxy____" || delegator || index || height)[..32]`.
- `common::swap_proxy::rotate(handle, old_signers, new_signers, threshold)`: submits `proxy.add_proxy(new_pure_proxy_owner)` then `proxy.remove_proxy(old)` via the multisig.

These need fixture pinning — both prefixes have changed in past substrate versions. Capture the actual values from live metadata at implementation time.

---

## What to do next (priority order)

1. **Finish Task 5 — `get_org_state` reads via child trie OR runtime API.** Pick option (b) (runtime API) first; it's higher-level and less fragile. Probe live metadata to confirm `ReviveApi` exposes a slot-read method:
   ```bash
   # With chopsticks running on :8000 from on-chain/scripts/chopsticks-sanity.sh:
   curl -s -X POST http://localhost:8000 \
     -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"state_getMetadata","params":[]}' \
     | jq -r '.result' | xxd -r -p | strings | grep -i -E 'revive|storage' | head -40
   ```
   Or use a subxt diagnostic (see `tests/scenario_a_lite.rs` for the pattern that dumped storage items + call variants — extend it to dump `runtime_apis`).

   Alongside: write `tests/scenario_a_full.rs` (rename from A-lite) that DOES verify state via `get_org_state` once the read path works. Replace the event-only assertion with `OrgState { root_hash, org_pub_key, epoch: Epoch(1) }`.

2. **Fix `OrgRegistryClient::subscribe` against chopsticks.** Try option (a) first — use `WsRpc::chain_head_follow` for the stream of best blocks and subxt's `at_block(...).events().fetch()` for per-block decoding. This sidesteps subxt's backend issues while preserving the metadata-aware event decode. If that's too much surface, gate the in-crate subscribe behind a `chainhead-stream` feature and ship subxt's version unchanged for now.

3. **Task 6 finish — multisig + swap_proxy.** Implement `common::multisig` and `common::swap_proxy`. Pin both blake2 derivation prefixes against fixtures captured from chopsticks. Don't trust hardcoded prefixes from old substrate docs — re-derive against a known live multisig.

4. **Task 7 — Scenarios B + C + p_address_is_orgid invariant.** Scenario B needs swap_proxy (admin rotation). Scenario C needs `chopsticks_reorg::induce_reorg` (already implemented). The invariant test pins `h160_of` against a chopsticks-captured (multisig → pure-proxy → H160) chain.

5. **Tasks 8 + 9 — smoldot.** Defer until 1–4 are tight. Confirm subxt 0.50's smoldot backend works on `wasm32-unknown-unknown` with the Paseo AH chain spec.

6. **Task 10 — pin everything in the design doc.** Spec_name = `"asset-hub-paseo"`, spec_version = `2_002_002`, WSS endpoint = pinned at Stage-1 implementation time, chainHead method names = `chainHead_v1_*`. Add a CI matrix entry for `cargo test --features dev-rpc`.

---

## Critical technical notes (the landmines)

**Don't lose these. They cost real time to discover.**

### Build & workspace

- The repo root (`/Users/jan-jan/Coding/2-tier-access-control/Cargo.toml`) has a `[workspace]` declaration (added by Phase 1.d landing on master) that includes `org-members`, `spike-common`, `spike-keyhive`, `spike-p2panda`. Our `on-chain-client/` is **outside** that workspace. The crate's `Cargo.toml` has an empty `[workspace]` declaration at the top to mark it self-contained — **do not remove it.**

- Lib `clippy --all-features` denies `unwrap_used`, `expect_used`, `panic`. These do NOT apply to `tests/` code (which uses `expect`/`assert!` freely). The gate is lib code only.

- `cargo test` invocations must use `--test-threads=1` because the chopsticks harness uses fixed port 8000.

### chopsticks

- Chopsticks forks an internal node worker process. A plain SIGKILL on the parent leaves the worker orphaned to pid 1. Fix in `tests/common/chopsticks_fork.rs`: `setsid` in `pre_exec` so chopsticks is its own session leader, then `killpg(pgid, SIGKILL)` in Drop kills the whole tree. `child.wait()` reaps the zombie. Verify with `ps -ef | grep chopsticks` after a test run — should be empty.

- Chopsticks's HTTP path must be hit before the WS metadata path responds reliably. The harness's prewarm uses `jsonrpsee::http_client` to POST `system_chain` and waits for `"Paseo Asset Hub"`.

- Chopsticks's missing v2 RPC methods: at minimum `transactionWatch_v1_submitAndWatch`. May also be missing other v2 methods. Implications for subxt — see Deferral B.

- Block production is **manual** in chopsticks. After submitting an extrinsic, call `dev_newBlock` (via `chopsticks_reorg::mine_block(&handle)`) to include it. The submit helper does NOT auto-mine.

### subxt 0.50 API quirks

- `api.tx()` is **async** (returns a Future, not the TransactionsClient). Pattern: `let mut tx_client = api.tx().await?;` — note the `mut` (required by `sign_and_submit_then_watch_default`).
- `OnlineClient` does NOT expose `storage()`, `events()`, `metadata()`, or `runtime_version()` directly. All of these come from `ClientAtBlock`: `let at = api.at_current_block().await?; at.storage(); at.metadata(); at.spec_version();`.
- Block subscription: `api.stream_best_blocks().await?` returns `Blocks<T>` which impls `Stream<Item = Result<Block, _>>`. Per block, call `block.at().await?` to get a `ClientAtBlock`, then `events().fetch().await?`.
- Event field name: `event.event_name()` — **not** `variant_name()` (which doesn't exist).
- Dynamic storage: `subxt::dynamic::storage(pallet, item)` returns a `DynamicAddress<KeyParts, Value>` with both params defaulted to `scale_value::Value`. Type-annotate the value side if you need typed decoding: `let address: DynamicAddress<Vec<Value>, Vec<u8>> = ...`. Then `at.storage().try_fetch(address, key_parts).await?` returns `Option<StorageValue<Vec<u8>>>`.
- `StorageValue` exposes `.bytes()` / `.into_bytes()` / `.decode_as::<T>()` — NOT `.encoded()`.
- Dynamic call: `dynamic::tx(pallet, call, vec![Value, ...])`. Compose `Value::unnamed_composite(...)`, `Value::named_composite(...)`, `Value::from_bytes(...)`, `Value::u128(n)`. H160 wrapper structs accept `Value::unnamed_composite(20 × Value::u128)` for the inner [u8; 20].

### pallet-revive on Paseo AH (`spec_version 2_002_002`)

- **Contract storage is NOT a runtime storage map.** It's in a per-contract child trie. See Deferral A.
- The Revive pallet's call variants (`api.metadata().pallet_by_name("Revive").call_variants()`):
  ```
  eth_transact, call, instantiate, instantiate_with_code,
  eth_instantiate_with_code, eth_call, eth_substrate_call,
  upload_code, remove_code, set_code, map_account,
  unmap_account, dispatch_as_fallback_account
  ```
- `Revive.call` args: `(dest: H160, value: u128, gas_limit: Weight, storage_deposit_limit: u128, data: Vec<u8>)`. `Weight = { ref_time: u64, proof_size: u64 }`. Same shape used by `submit::submit_update`.
- The `instantiateWithCode` arg order is (value, weightLimit, storageDepositLimit, code, data, salt) — different from substrate docs you might find online. Confirmed empirically and pinned in `../on-chain/scripts/sanity-deploy.mjs`.

### Solidity event signatures (Task 4 consts)

```
keccak256("GenesisInitialized(address,bytes32,bytes32)")
  = 0x8e65bf095440397e54613932b754917e4522ddb08a8e638bcb8dee69fe685b6d
keccak256("RootUpdated(address,uint256,bytes32,bytes32,bytes32)")
  = 0x247988cb0665746bde9be0b7068f5d0496e8e75d1a4b2692b198f67789ee5b6e
keccak256("update(bytes32,bytes32,uint256)")[..4]
  = 0xf1bc537b
```

The decoder unit test `event_signatures_match_solidity_abi` re-derives these from canonical strings via `tiny-keccak` — never silently drifts.

### `OrgRegistry` storage layout

`mapping(address => OrgState) private orgs;` at slot 0. For an admin `A`:
- Base slot S = `keccak256(abi.encode(uint256(A_padded_to_32), uint256(0)))`. See `client::solidity_mapping_slot`.
- `rootHash`   at slot S
- `orgPubKey`  at slot S+1
- `epoch`      at slot S+2 (uint256, low 8 bytes used)

`get_org_state` reads all three slots and concatenates them into the 96-byte blob `Decoder::decode_org_state` consumes. (Once the child-trie path is wired up.)

### GPG signing

Commits are GPG-signed by default. If pinentry times out, the commit fails with "Timeout" or "Operation cancelled". Per session rules, **never bypass with `--no-gpg-sign` unless the user explicitly authorizes it.** Just retry the commit after the user confirms they're ready at the prompt.

---

## Commands cheat sheet

```bash
# Working directory:
cd /Users/jan-jan/Coding/2-tier-access-control/.claude/worktrees/phase-1b-stage1-solidity/on-chain-client

# Build matrix:
cargo build                                                       # default = dev-rpc
cargo build --no-default-features                                 # no_std + alloc
cargo build --no-default-features --features smoldot              # +smoldot
cargo build --target wasm32-unknown-unknown --no-default-features
cargo build --target wasm32-unknown-unknown --no-default-features --features smoldot

# Lib clippy gate:
cargo clippy --all-features --lib -- -D warnings \
  -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic

# All tests:
pkill -f "chopsticks.*--config" 2>/dev/null
cargo test --features dev-rpc -- --test-threads=1

# Just the end-to-end scenario:
pkill -f "chopsticks.*--config" 2>/dev/null
cargo test --features dev-rpc --test scenario_a_lite -- --nocapture

# Probe live Paseo AH metadata (with chopsticks running):
curl -s -X POST http://localhost:8000 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"state_getRuntimeVersion","params":[]}'

# Manual deploy + capture H160:
cd ../on-chain
scripts/node_modules/.bin/chopsticks --config scripts/chopsticks-config.yml --port 8000 &
# ... wait for prewarm ...
RPC_URL=ws://localhost:8000 \
  BLOB_PATH=tmp/revive/OrgRegistry.sol:OrgRegistry.pvm \
  node scripts/sanity-deploy.mjs | grep DEPLOYED_H160
```

---

## File map

```
on-chain-client/
├── Cargo.toml                 ← Empty [workspace] at top is intentional (see "Critical notes")
├── README.md                  ← Status table + quickstart
├── src/
│   ├── lib.rs                 ← Re-exports; `client` gated on `dev-rpc`
│   ├── types.rs               ← OrgAdmin / OnChainRootHash / OrgPubKey / Epoch
│   ├── state.rs               ← OrgState, Event, BlockRef, SubscribedEvent
│   ├── rpc/
│   │   ├── mod.rs             ← Module exports (cfg-gated)
│   │   ├── trait_def.rs       ← `Rpc` trait, HeadEvent, Error
│   │   └── ws.rs              ← WsRpc — jsonrpsee + chainHead_v1_*
│   ├── decode/
│   │   ├── mod.rs             ← `Decoder` trait + DecodeError
│   │   ├── dispatch.rs        ← `for_runtime(spec_version)`
│   │   └── v_paseo_ah.rs      ← Decoder impl; SPEC_VERSION = 2_002_002
│   ├── client.rs              ← OrgRegistryClient (subxt-based)
│   ├── h160.rs                ← Stub (the *production* h160_of will land alongside child-trie reader)
│   └── verify.rs              ← Stub (CandidateTrie verifier closes loop in Task 5+)
└── tests/
    ├── common/
    │   ├── mod.rs
    │   ├── chopsticks_fork.rs    ← spawn_fork; setsid + killpg
    │   ├── h160_mapper.rs        ← test-only h160_of (EVM-fallback OR keccak)
    │   ├── chopsticks_reorg.rs   ← mine_block, induce_reorg
    │   └── submit.rs             ← subxt-based update() submitter
    ├── 00_chopsticks_sanity.rs   ← Task 6 gate
    ├── rpc_ws.rs                 ← Task 3 gate (now harness-driven)
    └── scenario_a_lite.rs        ← Single-org end-to-end via events

../on-chain/scripts/sanity-deploy.mjs
                              ← Now emits `DEPLOYED_H160=0x...` marker

docs/superpowers/plans/
├── 2026-05-28-ods-phase-1b-stage2-rust-client.md   ← Original plan
└── 2026-06-04-ods-phase-1b-stage2-handoff.md       ← THIS FILE
```

---

## Recent commits (most-recent first)

```
0a3f489  feat(on-chain-client): Tasks 5 + 6.b — OrgRegistryClient + Scenario A-lite
aef9bcd  feat(on-chain-client): chopsticks fork harness + h160_mapper + reorg helper
1de9b7e  feat(on-chain-client): runtime-version-gated storage + event decoders
cdd12f7  feat(on-chain-client): Rpc trait + WsRpc jsonrpsee chainHead_v1_* impl
3218c04  docs(on-chain-client): system overview + deploy pointer in README
e573953  feat(phase-1b stage 2): on-chain-client crate skeleton + public types
1028ff4  plan(phase-1b stage 2): on-chain-client Rust crate plan
```

---

## To resume in a new session

1. Read this file plus the original plan (`2026-05-28-ods-phase-1b-stage2-rust-client.md`).
2. `cd` to the worktree, run the test command in "Commands cheat sheet" — should be green if the env is clean. If not, `pkill -f chopsticks` and retry.
3. Decide which deferral to attack first. The natural next is **#1 (`get_org_state` via runtime API)** because it unblocks honest state verification in Scenario A and is a prerequisite for Scenario C (read-finalised-state-after-reorg).
4. Reach into "Critical technical notes" liberally — those are the parts that cost the most time to figure out.
