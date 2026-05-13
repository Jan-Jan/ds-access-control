# ODS Phase 1.b — On-chain component

**Author:** Jan-Jan van der Vyver (<jan-jan@parity.io>)
**Status:** In review
**Created:** 2026-05-13
**Parent design:** [`Organisational Data Sovereignty p1.md`](../../../Organisational%20Data%20Sovereignty%20p1.md), Implementation Plan item 1.ii

## Overview

Phase 1.b is the on-chain half of the two-tier access-control design. It anchors the off-chain organisation-members trie (Phase 1.a, the `org-members` crate) to a verifiable shared state on Asset Hub, so peers can verify that a received membership delta corresponds to what an admin multisig actually published.

This phase delivers three artifacts:

1. A single audited Solidity contract (`OrgRegistry`) deployed on Asset Hub via `pallet-revive`, holding `(rootHash, orgPubKey, epoch)` per organisation, keyed on the org admin's address.
2. A Rust crate (`on-chain-client`) that lets off-chain peers read on-chain state and subscribe to update events via a light-client transport (smoldot), so the same code runs in a browser PWA.
3. A test suite that exercises the full off-chain genesis ceremony (pure proxy + multisig pseudo-account) end-to-end against a forked Paseo Asset Hub via chopsticks.

What this phase deliberately does **not** deliver: submission-side helpers, Solidity view functions for cross-contract reads, admin-rotation tooling, off-chain delta gossip, browser-WASM PoC integration, or any change to `org-members`.

## Architecture

```
2-tier-access-control/
├── org-members/                    [existing — Phase 1.a]
├── on-chain/                       [NEW] Foundry project
│   ├── src/OrgRegistry.sol
│   ├── test/OrgRegistry.t.sol
│   └── foundry.toml
└── on-chain-client/                [NEW] Rust crate
    ├── src/
    │   ├── lib.rs
    │   ├── types.rs                OrgAdmin, OnChainRootHash, OrgPubKey, Epoch, OrgState, Event
    │   ├── client.rs               OrgRegistryClient
    │   ├── rpc.rs                  Rpc trait + WsRpc + SmoldotRpc
    │   ├── decode/                 storage and event SCALE/ABI decoding (runtime-vN gated)
    │   └── verify.rs               verify_root_against_chain
    └── tests/
        ├── 00_chopsticks_sanity.rs
        ├── two_orgs_one_watcher.rs
        ├── off_chain_genesis_ceremony.rs
        ├── p_address_is_orgid.rs
        ├── smoldot_smoke.rs
        └── common/                 test-only multisig + proxy + chopsticks helpers
```

### Data flow

```
   ┌──────────────┐   trie mutation   ┌────────────────┐
   │ org-members  │ ────────────────▶ │ Delta + new    │
   │   (Phase 1a) │                   │ RootHash       │
   └──────────────┘                   └────────┬───────┘
                                               │
                        ┌──────────────────────┴──────────────────┐
                        │ admins co-sign via pallet-multisig over │
                        │ a multisig pseudo-account that is the   │
                        │ sole proxy of the org's pure proxy P    │
                        │     → pallet-proxy::proxy               │
                        │     → pallet-revive::call(OrgRegistry)  │
                        └──────────────────────┬──────────────────┘
                                               ▼
                                    ┌──────────────────┐
                                    │ OrgRegistry      │  Phase 1.b
                                    │ writes state,    │
                                    │ emits event      │
                                    └────────┬─────────┘
                                             │ ContractEmitted
                            ┌────────────────┴───────────────────────┐
                            │ on-chain-client (smoldot)              │
                            │  - sees BestBlockEvent (in best block) │
                            │      → peers start p2p delta exchange  │
                            │  - sees FinalisedEvent (after GRANDPA) │
                            │      → peers commit local state        │
                            │  - sees Reorged                        │
                            │      → peers cancel optimistic flow    │
                            │ verifies received delta against root   │
                            └────────────────────────────────────────┘
```

### Identity stack

The Substrate-side identity stack from bottom to top, with the corresponding contract-side view:

| Layer | Substrate | Stable? |
|---|---|---|
| Org identity on-chain | `h160_of(P)` where `P` is the pure proxy | **Yes — this is the OrgId** |
| Current authoriser of P | A multisig pseudo-account `M(signers, threshold)` (sole proxy of P) | No — rotated as admins/threshold change |
| Admin set | The `signers` in the current `M(...)` | No — rotated freely |

Inside `OrgRegistry`, `msg.sender == h160_of(P)` for the entire lifetime of the organisation. Rotating admins or the threshold replaces `M(...)` but leaves `P` (and therefore the contract's storage key) untouched. This is the load-bearing property of the design.

## Solidity contract — `OrgRegistry`

Deployed once on Asset Hub via `pallet-revive`. Multi-tenant via `mapping(address => OrgState)`. One audit boundary.

### Storage

```solidity
struct OrgState {
    bytes32 rootHash;       // 32-byte sparse-merkle root from org-members
    bytes32 orgPubKey;      // Ed25519 public key, 32 bytes raw
    uint256 epoch;          // monotonic, +1 per update, 0 = uninitialised
}

mapping(address => OrgState) private orgs;
```

The `address` key is the proxied multisig's mapped H160 (i.e. `h160_of(P)`). One admin proxy ↔ one organisation.

### Single entry point

```solidity
function update(
    bytes32 newRootHash,
    bytes32 newOrgPubKey,
    uint256 expectedEpoch
) external;
```

Logic, in order:

1. Revert `ZeroValue` if `newRootHash == 0` or `newOrgPubKey == 0`.
2. `OrgState storage s = orgs[msg.sender];`
3. Revert `EpochMismatch(expectedEpoch, s.epoch)` if `expectedEpoch != s.epoch`.
4. Revert `NoOpUpdate` if `s.epoch != 0 && newRootHash == s.rootHash && newOrgPubKey == s.orgPubKey`. (Genesis bypasses this check because `s.epoch == 0`.)
5. Branch on genesis:
   - **Genesis** (`s.epoch == 0`): set `(rootHash, orgPubKey)`, set `epoch = 1`, emit `GenesisInitialized`.
   - **Update** (`s.epoch ≥ 1`): keep `prev = s.rootHash`, set `(rootHash, orgPubKey)`, set `epoch = s.epoch + 1`, emit `RootUpdated`.

After genesis, `epoch == 1`. Callers always pass `expectedEpoch =` "the epoch I last saw on-chain", so the very first call passes `0` and subsequent calls pass `1, 2, …`.

### Events

```solidity
event GenesisInitialized(
    address indexed admin,
    bytes32 rootHash,
    bytes32 orgPubKey
);

event RootUpdated(
    address indexed admin,
    uint256 indexed epoch,
    bytes32 rootHash,
    bytes32 orgPubKey,
    bytes32 prevRootHash
);
```

`admin` is indexed on both so the smoldot client can filter per-org subscriptions on the topic. `epoch` is indexed on `RootUpdated` to allow targeted "show me the event at epoch N" queries.

### Errors

```solidity
error ZeroValue();
error EpochMismatch(uint256 expected, uint256 actual);
error NoOpUpdate();
```

Logic step 3 above is therefore `revert EpochMismatch(expectedEpoch, s.epoch)`.

### Out of scope

- No admin-rotation function — pallet-proxy handles it externally and `h160_of(P)` stays stable.
- No pause / kill switch — not requested; can be added in a future audit if needed.
- No on-chain Ed25519 verification — keys are opaque `bytes32`.
- No `view` helpers for other contracts in this phase. `orgs` is `private`.
- No `genesis(...)` function — unified into `update(...)`.

### Known structural properties to document

- **Permissionless org creation.** Any address that calls `update(root, pk, 0)` becomes an admin of its own slot in the mapping. There is no on-chain allowlist of admins. Anyone is free to create an org under their own H160 because the only state they affect is `orgs[msg.sender]`.
- **No on-chain audit trail of admin-set changes.** Pallet-proxy emits its own events, but `OrgRegistry` sees only `msg.sender == h160_of(P)`. This is consistent with the parent spec's noted disadvantage of "admins managed separately from the trie".

## Rust crate — `on-chain-client`

### Constraints (mirroring `org-members`)

- `clippy::unwrap_used`, `clippy::expect_used`, `clippy::panic` denied in lib code.
- Named types over naked primitives (`OrgAdmin([u8; 20])`, `Epoch(u64)`, etc.).
- `no_std`-aspirational: types + verification helper are `no_std + alloc`. The smoldot/WS transport is gated behind a default `client` feature that enables `std`. Browser-WASM uses `std` via `wasm-bindgen`, so this isn't a regression for the PoC.
- WASM target supported (`wasm32-unknown-unknown`).

### Public types

```rust
pub struct OrgAdmin([u8; 20]);
pub struct OnChainRootHash([u8; 32]);
pub struct OrgPubKey([u8; 32]);
pub struct Epoch(u64);

pub struct OrgState {
    pub root_hash:    OnChainRootHash,
    pub org_pub_key:  OrgPubKey,
    pub epoch:        Epoch,
}

pub enum Event {
    Genesis { admin: OrgAdmin, root_hash: OnChainRootHash, org_pub_key: OrgPubKey },
    Update  {
        admin:         OrgAdmin,
        epoch:         Epoch,
        root_hash:     OnChainRootHash,
        org_pub_key:   OrgPubKey,
        prev_root_hash: OnChainRootHash,
    },
}

pub struct BlockRef {
    pub hash:   BlockHash,
    pub number: u64,
}

/// A stream item from `subscribe`. Best-block and finalised notifications are
/// distinct so consumers can act optimistically on best-block events and only
/// commit local state once finalisation arrives. Reorgs notify consumers that
/// a previously-best block has been discarded.
pub enum SubscribedEvent {
    /// Event observed in a best (non-finalised) block. The PWA should start
    /// the off-chain p2p delta exchange but NOT commit local state yet.
    BestBlockEvent  { event: Event, at: BlockRef },

    /// A previously-best block has been reorged out. Any in-flight optimistic
    /// flow keyed on `at.hash` should be cancelled or rolled back.
    Reorged         { discarded: BlockRef },

    /// Event observed in a finalised block. The PWA should commit local state
    /// (apply the verified delta to the local org-members trie).
    FinalisedEvent  { event: Event, at: BlockRef },
}

impl From<OnChainRootHash> for org_members::RootHash { /* byte-for-byte */ }
```

### Transport abstraction

```rust
pub trait Rpc {
    async fn chain_head_storage(&self, block: BlockHash, key: &[u8])
        -> Result<Option<Vec<u8>>, Error>;
    async fn chain_head_follow(&self) -> impl Stream<Item = HeadEvent>;
    async fn runtime_version(&self) -> Result<RuntimeVersion, Error>;
}

pub struct SmoldotRpc { /* smoldot::JsonRpcClient + chain spec */ }   // production
pub struct WsRpc      { /* jsonrpsee WebSocket */ }                   // tests, dev
```

Smoldot is the primary path because it is the natural fit for the Phase 2 PWA (no separate full-node dependency, runs in browser-WASM, no `unstable-*` feature flags). WS is provided behind a `dev-rpc` feature for integration tests against chopsticks/local nodes.

### Client surface

```rust
pub struct OrgRegistryClient<R: Rpc> { /* rpc + contract address + runtime decoder */ }

impl<R: Rpc> OrgRegistryClient<R> {
    pub async fn new(rpc: R, contract: OrgAdmin) -> Result<Self, Error>;

    /// `at = None` reads the latest finalised block. Passing a specific
    /// `BlockRef` lets the PWA read state at the proposed block it just
    /// learned about, so it can validate the new root against a candidate
    /// trie before finalisation. None when the slot has never been written.
    pub async fn get_org_state(&self, admin: &OrgAdmin, at: Option<BlockRef>)
        -> Result<Option<OrgState>, Error>;

    /// Stream of best-block, reorg, and finalised notifications for events
    /// matching `admin` (optional indexed-topic filter). See `SubscribedEvent`.
    pub fn subscribe(&self, admin: Option<OrgAdmin>)
        -> impl Stream<Item = Result<SubscribedEvent, Error>>;
}
```

### Verification helper

```rust
/// Compare a candidate trie's root against on-chain state. Thin wrapper
/// that closes the loop with `org-members::CandidateTrie::verify_against`.
pub fn verify_root_against_chain(
    candidate_root: &org_members::RootHash,
    on_chain:       &OrgState,
) -> Result<(), VerifyError>;
```

Off-chain peer flow, finalisation-aware:

1. `subscribe(...)` yields `BestBlockEvent { event, at }` when an admin's root update is observed in a best block. The peer kicks off the p2p delta exchange optimistically.
2. Peer receives `Delta` from an admin/peer (existing `org-members` wire type).
3. Apply via `OrgTrie::apply_delta` → get `CandidateTrie`.
4. Fetch `OrgState` via `get_org_state(admin, Some(at))` — *at the same block hash* — and call `CandidateTrie::verify_against(&on_chain.root_hash.into())`. If verification passes, hold the verified candidate in memory; **do not** mutate the local trie yet.
5. One of two things happens next:
   - `FinalisedEvent { event, at: at_final }` arrives for the same `(admin, root_hash)`. Commit the verified candidate as the new local trie.
   - `Reorged { discarded }` arrives for the earlier `at.hash`. Discard the in-memory candidate; resume listening for a fresh `BestBlockEvent`.

This pattern lets the PWA pre-fetch and verify deltas in parallel with finalisation, so the user-visible commit happens within milliseconds of GRANDPA finality rather than incurring the full p2p round-trip after finalisation.

### Decoding pallet-revive storage and events

Direct storage read (not via a runtime API call): derive the storage key for the contract's storage slot 0 (the `orgs` mapping), read the SCALE-encoded value, decode the 96 bytes for `OrgState`. Avoids needing a Solidity view function in the contract and is a single chain RPC call.

Risks and mitigations:

- **Runtime-version coupling.** Pin a known-good runtime version and gate the decoders behind a `runtime-vN` cargo feature so future upgrades are an additive PR, not a silent break. Each decoder gets a fixture test pinning it to a known-good byte sequence.
- **`pallet-revive` is still pre-stable.** Same mitigation; chopsticks fork tells us what version Paseo actually runs.
- **Smoldot JSON-RPC v2 chainHead group is also unstable.** The `Rpc` trait isolates this; WS is the fallback transport for the PoC if needed.

## Substrate-side submission flow

This section documents the off-chain submission path admins follow. No code in this phase implements submission; helpers exist only in test code.

### Always-multisig-pseudo-account invariant

Every proxy slot of `P` is always a multisig pseudo-account `M(signers, threshold)`, never a raw `AccountId32`. Admin-set changes are uniform: compute new `M(...)` → add as proxy → remove old. The pure proxy `P` is the only stable Substrate identity; everything else is computed.

### Pure proxy lifecycle

1. **Initial admin A1** creates an `AccountId32` wallet, funds itself.
2. A1 calls `pallet_proxy::create_pure(ProxyType::Any, delay=0, index=0)` → pure proxy `P` is created with A1 as its initial proxy. This is the only moment in `P`'s lifetime where a raw account is its proxy.
3. A1 immediately replaces itself with the multisig pseudo-account `M([A1], 1)` via an atomic `batch_all` of `add_proxy(M([A1], 1))` and `remove_proxy(A1)`, dispatched through `proxy.proxy(real=P, ...)`. Atomic batch ensures `P` is never in a no-proxies state.

### Admin-set rotation

Adding/removing admins or changing the threshold is always: compute new `M(new_signers, new_threshold)` → atomically `add_proxy(new_M) + remove_proxy(old_M)`, dispatched through the current `M`. The current `M`'s threshold determines how many admin signatures are needed for the rotation itself.

### Update submission

A Phase 1.b root update is a multisig of `proxy.proxy(real=P, call=revive.call(OrgRegistry, abi(update, ...)))`:

```
multisig::as_multi(threshold, other_signatories, call=
    proxy.proxy(real=P, call=revive.call(
        dest=OrgRegistry_h160,
        value=0,
        gas_limit, storage_deposit_limit,
        data=abi_encode("update(bytes32,bytes32,uint256)", root, pk, expected_epoch)
    )))
```

Inside the contract, `msg.sender == h160_of(P)` because pallet-revive uses the direct caller of `revive::call`, which is `P` (not the multisig pseudo-account, not any individual signer).

## Testing strategy

### 5.1 Foundry unit tests — `on-chain/test/OrgRegistry.t.sol`

Pure contract logic; admins are vanilla EOA-style addresses provided by Foundry. Coverage:

- Genesis happy path: `update(r, k, 0)` from fresh address → `GenesisInitialized`, state = `(r, k, 1)`.
- Update happy path: `update(r', k', 1)` → `RootUpdated(admin, 2, r', k', r)`, state = `(r', k', 2)`.
- `ZeroValue` revert for `update(0, k, 0)` and `update(r, 0, 0)`.
- `EpochMismatch` revert for stale or future `expectedEpoch`.
- `NoOpUpdate` revert when both `r` and `k` are unchanged after genesis.
- Two distinct admins writing don't perturb each other's state.
- Event topics: `admin` and `epoch` correctly indexed and decodable.
- Permissionless org creation: any address can call genesis; no allowlist effects.

### 5.2 Rust integration tests — chopsticks-forked Paseo Asset Hub

Chosen for fast iteration (~2-5s startup), high determinism (programmable `dev_newBlock`), reorg control via chopsticks' fork-building APIs, and trivial state reset.

**Fork target — Paseo Asset Hub only for Phase 1.b.** Paseo's runtime tracks Polkadot's closely, has `pallet-revive`, and has a small enough state to fork quickly. The exact WSS endpoint URL is confirmed at the start of implementation (see Open Items). Adding Polkadot Asset Hub as a fallback target later is a one-function change in `tests/common/chopsticks_fork.rs` — deferred until Paseo proves insufficient.

#### `00_chopsticks_sanity.rs`

Runs first. Deploys a no-op contract via `pallet-revive` and reads its code hash back. Discovers any chopsticks-vs-pallet-revive incompatibility before we build the harness on top. Logs the runtime version actually executing under chopsticks.

#### Scenario A — `two_orgs_one_watcher.rs`

Validates per-admin event filtering, per-org storage isolation in the shared contract, and the best-block-then-finalised emission ordering.

```
Setup:    two pure proxies P_A, P_B, each with M([signer], 1) as sole proxy.
          Deploy OrgRegistry once.

Actions:  Interleaved best-block submissions (in order):
            P_A: update(root_a0, pk_a0, 0)   → GenesisInitialized
            P_B: update(root_b0, pk_b0, 0)   → GenesisInitialized
            P_A: update(root_a1, pk_a1, 1)   → RootUpdated(epoch=2)
            P_B: update(root_b1, pk_b1, 1)   → RootUpdated(epoch=2)
          Then advance chopsticks until all blocks above are finalised.

Watcher:  client.subscribe(Some(h160_of(P_A)))

Asserts:  - Watcher receives exactly 2 BestBlockEvent items (Genesis + Update
            for A), in submission order.
          - Watcher then receives exactly 2 FinalisedEvent items (same Genesis +
            Update for A), in the same order.
          - Every received event carries admin == h160_of(P_A).
          - No Reorged items.
          - Stream times out cleanly with no further events (no leakage of B's
            events under either status).
          - get_org_state(h160_of(P_A), Some(last_best_block)).epoch == 2
          - get_org_state(h160_of(P_A), None).epoch == 2  (latest finalised)
          - get_org_state(h160_of(P_B), None).epoch == 2, root == root_b1
```

#### Scenario B — `off_chain_genesis_ceremony.rs`

The full off-chain genesis ceremony, expressed as real extrinsics on the forked node. Notation: `M(signers, t)` is the multisig pseudo-account derived from `(sorted(signers), threshold=t)`.

```
Step 1: A1 creates wallet, funds itself.

Step 2: A1 → pallet_proxy::create_pure(ProxyType::Any, delay=0, index=0)
        Result: pure proxy P exists; A1 is its initial sole proxy.

Step 3: A1 → proxy.proxy(real=P, call=batch_all([
            proxy.add_proxy(M([A1], 1), Any, 0),
            proxy.remove_proxy(A1, Any, 0),
        ]))
        Assert: P's proxies == {M([A1], 1)}.

Step 4: A2, A3 create wallets, fund themselves.

Step 5: Switch M([A1], 1) → M([A1,A2,A3], 1).
        Via current M([A1], 1) dispatched by A1:
          proxy.proxy(real=P, call=batch_all([
              proxy.add_proxy(M([A1,A2,A3], 1), Any, 0),
              proxy.remove_proxy(M([A1], 1), Any, 0),
          ]))
        Assert: P's proxies == {M([A1,A2,A3], 1)}.

Step 6: Switch M([A1,A2,A3], 1) → M([A1,A2,A3], 2).
        Via current M([A1,A2,A3], 1) dispatched by any one of A1/A2/A3:
          proxy.proxy(real=P, call=batch_all([
              proxy.add_proxy(M([A1,A2,A3], 2), Any, 0),
              proxy.remove_proxy(M([A1,A2,A3], 1), Any, 0),
          ]))
        Assert: P's proxies == {M([A1,A2,A3], 2)}.
        Assert: a follow-up dispatch via M([A1,A2,A3], 1) reverts NotProxy.

Step 7: Phase 1.b on-chain genesis.
        A1 initiates: multisig::as_multi(2, [A2,A3], call=
            proxy.proxy(real=P, call=revive.call(
                OrgRegistry, abi("update", root_0, pk_0, 0))))
        A2 approves: multisig::approve_as_multi(2, [A1,A3], ...) → dispatched.
        Assert: GenesisInitialized(h160_of(P), root_0, pk_0).
        Assert: client.get_org_state(h160_of(P)) == (root_0, pk_0, 1).

Step 8: Evict A3. A1 and A2 cooperate via M([A1,A2,A3], 2):
          dispatched call = proxy.proxy(real=P, call=batch_all([
              proxy.add_proxy(M([A1,A2], 2), Any, 0),
              proxy.remove_proxy(M([A1,A2,A3], 2), Any, 0),
          ]))
        Assert: P's proxies == {M([A1,A2], 2)}.
        Assert: A3 attempting multisig::as_multi with [A1,A2] as others reverts.

Step 9: Sanity update via M([A1,A2], 2).
        A1 + A2 cosign update(root_1, pk_1, 1).
        Assert: RootUpdated(h160_of(P), 2, root_1, pk_1, root_0).
        Assert: h160_of(P) unchanged across the entire test.
```

What this proves: (a) the atomic `batch_all(add + remove)` idiom safely swaps proxies without leaving `P` undelegated; (b) every authorization layer is a multisig pseudo-account; (c) the contract storage key (`h160_of(P)`) is stable across admin-set rotations.

#### Scenario C — `reorg_cancels_proposed.rs`

Validates that consumers can distinguish optimistic best-block events from finalised ones, and that a reorg discarding the original best block is surfaced before finalisation.

```
Setup:    one pure proxy P_A with M([signer], 1) as sole proxy.
          Deploy OrgRegistry once.

Actions:
  1. Submit P_A: update(root_a0, pk_a0, 0) on the current best chain.
     Wait for BestBlockEvent.
  2. Use chopsticks' fork-building API to rewind one block and build an
     alternative best chain that does NOT include the update extrinsic
     (e.g. dev_setHead to a pre-update block, then dev_newBlock without
     including the update tx in the mempool).
  3. On the new best chain, submit P_A: update(root_a0', pk_a0', 0)
     with different inputs.
  4. Advance until the new chain finalises.

Watcher:  client.subscribe(Some(h160_of(P_A)))

Asserts:  - First yields BestBlockEvent for the original (root_a0, pk_a0).
          - Then yields a Reorged item carrying the discarded block hash.
          - Then yields a BestBlockEvent for (root_a0', pk_a0') at the new
            best block.
          - Finally yields a FinalisedEvent for (root_a0', pk_a0').
          - No FinalisedEvent for (root_a0, pk_a0) ever arrives.
          - get_org_state(h160_of(P_A), None) reflects (root_a0', pk_a0').
```

This is the regression guard for the PWA's optimistic-flow correctness: if `Reorged` ever stops firing, the PWA would commit local state for an update that's no longer on the canonical chain.

#### `p_address_is_orgid.rs` — the OrgId invariant in isolation

Runs the full Scenario B ceremony and asserts at every state transition that `h160_of(P) == h160_of(P)_initial`. Lives in its own file so reviewers can read it in isolation and convince themselves the OrgId is stable, and so it produces a clean failure signal if (for example) a future change to `pallet-revive`'s account mapping breaks the invariant in a way Scenario B's other assertions wouldn't catch.

### 5.3 Smoldot smoke test — `smoldot_smoke.rs`

One test against a real local Asset Hub dev node (chopsticks' faked GRANDPA finality can confuse smoldot). Deploys the contract, does one genesis call via WS, then reads state and one event back via `SmoldotRpc`. Catches transport-layer regressions without making every test pay smoldot's setup cost.

### Test harness pieces

In `on-chain-client/tests/common/` (not exposed as public API):

- `multisig_account_id(signers: &[AccountId32], threshold: u16) -> AccountId32` — deterministic derivation matching `pallet-multisig`'s on-chain computation; pinned by fixture test.
- `h160_of(account: &AccountId32) -> OrgAdmin` — pallet-revive's account mapping; pinned by fixture test.
- `swap_proxy(via_multisig, dispatched_by, real, old, new)` — the canonical batched-add-remove helper used by Steps 3/5/6/8.
- `multisig_dispatch(initiator, approvers, call)` — wraps `as_multi`/`approve_as_multi`.
- `chopsticks_fork::fork_for_tests()` — RAII guard that forks Paseo (or Polkadot AH on fallback), pre-funds dev accounts, returns RPC client. Tears down on `Drop`.

## Sequencing

Phase 1.b is delivered in **two sequential stages** with a hard gate between them. The contract's ABI is the dependency the client crate decodes against; freezing it first avoids client rework if the contract logic later needs revision.

### Stage 1 — Solidity contract (gates Stage 2)

1. `on-chain/OrgRegistry.sol` and full Foundry test coverage (5.1).
2. Chopsticks sanity test (`tests/00_chopsticks_sanity.rs`) — proves Paseo Asset Hub fork + `pallet-revive` work under chopsticks before the harness depends on them. Can run in parallel with task 1; it touches no contract code.

**Gate criteria** — all of the following before Stage 2 starts:
- All Foundry tests passing on a tagged commit.
- Contract deployed to a chopsticks-forked Paseo Asset Hub and the sanity test reads its code hash back correctly.
- ABI exported (Foundry artifact) and pinned in `on-chain/abi/OrgRegistry.json`.

### Stage 2 — On-chain client

3. `on-chain-client` crate skeleton: types, `Rpc` trait, `OrgRegistryClient` struct, `WsRpc` (jsonrpsee).
4. Storage and event decoders, `runtime-vN` gated, fixture-tested.
5. `get_org_state` (with optional `at: BlockRef`) and `subscribe` (yielding `SubscribedEvent`) over WS → Scenario A passes (best-block + finalised emission), Scenario C passes (reorg handling).
6. Test harness `common/` module (multisig derivation, h160 mapper, swap_proxy, chopsticks_fork, chopsticks-reorg helpers).
7. Scenario B and `p_address_is_orgid.rs`.
8. `SmoldotRpc` implementation (`Rpc` trait swap).
9. Smoldot smoke test (5.3).
10. Pin concrete runtime version, chain endpoint, gas/storage-deposit limits in the design doc.

Tasks 3-7 are sequential. Tasks 8 and 9 can be done in parallel after task 5.

If Stage 1's Foundry tests surface a needed contract change after Stage 2 has started, treat it as a stop-the-world for the client crate: revise the contract, re-pin the ABI, then continue Stage 2 from where it was (the decoders in task 4 are usually the only code that needs to track ABI changes).

## Risks

| # | Risk | Mitigation |
|---|---|---|
| 1 | `pallet-revive` is pre-stable; storage layout, account mapping, or event format could change. | Pin runtime version; gate decoders behind `runtime-vN` features; one fixture test per decoder; chopsticks fork reports the live version. |
| 2 | Chopsticks may not execute `pallet-revive` faithfully under lazy execution. | Discovered early via task 2 sanity test. Fallback: local `polkadot-asset-hub --dev`. |
| 3 | Smoldot's JSON-RPC v2 chainHead group is also unstable. | `Rpc` trait isolates the transport; WS fallback remains available. |
| 4 | Paseo's `pallet-revive` may lag Polkadot's or behave differently. | Treated as a blocker if it occurs; we ship Polkadot-AH fallback then. Phase 1.b targets Paseo only. |
| 5 | Our `h160_of` could drift from `pallet-revive`'s mapping. | Fixture test pinning to a known-good pallet output; reverified per chopsticks fork. |
| 6 | Permissionless `update(...)` (any H160 can create its own org slot). | Intentional, documented; Foundry test demonstrates two unrelated addresses each getting their own slot. |
| 7 | No on-chain audit trail of admin-set changes — pallet-proxy emits events, contract doesn't. | Spec already acknowledges this gap; carried forward unchanged. Documented in "known gaps". |
| 8 | Reorg handling in `subscribe`: chopsticks-emulated reorgs must match what real Asset Hub produces over smoldot's `chainHead_v1_follow`. | Scenario C exercises the chopsticks path. The smoldot smoke test (5.3) exercises the real-node best/finalised path. Cross-checking the two confirms no chopsticks-only divergence in reorg semantics. |

## Open items (to be resolved during implementation)

- Exact runtime version to pin. Set at the start of implementation based on what Paseo Asset Hub is running.
- Exact Paseo Asset Hub WSS endpoint URL (looked up at implementation time).
- Gas limits and storage-deposit limits for the `revive.call` payload — determined empirically from chopsticks dry-runs.
- CI matrix: default `cargo test --features dev-rpc` (WS); `--features smoldot` for the smoke job.
- Threshold-1 multisig handling: pallet-multisig dispatches threshold-1 via `as_multi_threshold_1` (a different extrinsic from `as_multi`). The test harness's `multisig_dispatch` helper picks the right call automatically; the pseudo-account derivation is unchanged. Verified during task 6 (harness implementation).

## What this phase explicitly does not deliver

- Submission helpers (admins use polkadot.js / `subxt` directly until Phase 2).
- Solidity view functions for cross-contract reads of org state.
- Admin-rotation tooling — pallet-proxy + pallet-multisig usage is documented here, not wrapped.
- Off-chain delta gossip (Phase 3+).
- Browser-WASM integration of `on-chain-client` (Phase 2).
- Any change to `org-members`.
