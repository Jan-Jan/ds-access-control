# org-node

ODS Phase 2 node logic — the trust brain that sits above `org-members`.

This crate owns what `org-members` deliberately leaves to the caller: ed25519
signing, the `SignedDeltaEnvelope` wire form, monotonic replay protection, and
the **verify-against-chain** flow.

## The one property

`verify_envelope_against_chain` commits a received membership change only if,
after checking org binding + signature + sequence, applying the delta to the
local trie reproduces a root that **independently** matches the on-chain root
(read via `ChainReader`) at a newer epoch. The delta and the trusted root must
travel different trust paths.

## Status (Phase 2.1)

Pure core, no network/chain. The chain is abstracted behind `ChainReader`;
`MockChain` drives tests. Later phases wire `on-chain-client`/subxt (reads +
writes), iroh transport, persona/org persistence, and the Tauri/Svelte shell.

## Layout

- `keys.rs` — `SigningKeypair`; maps to `P2pMemberKey`/`P2pDeviceKey`.
- `ids.rs` — `OrgId` (= `h160_of(P)`).
- `chain.rs` — `ChainReader`, `OrgState`, `MockChain`.
- `envelope.rs` — `SignedDeltaEnvelope` (transcript = org_id ‖ parent_seq ‖ delta).
- `sequence.rs` — `SeqGuard`.
- `verify.rs` — `verify_envelope_against_chain` + `VerifyContext`/`VerifiedUpdate`.

## Chain integration (Phase 2.2)

All on-chain code is gated behind the `chain` cargo feature. The Phase 2.1 core
(envelope / verify / sequence) compiles and tests without it.

### Feature flag

```toml
# Cargo.toml
[features]
chain = ["dep:subxt", "dep:subxt-signer", "dep:tokio", "dep:on-chain-client", ...]
```

Enabling `chain` pulls in `subxt` 0.50, `subxt-signer` 0.50, `on-chain-client`
(path dep, `dev-rpc` feature for chopsticks), and `tokio`.

### Reads — `OnChainReader`

`chain_read::OnChainReader` implements `ChainReader` over
`on-chain-client`'s `OrgRegistryClient`:

- **Async half:** `OnChainReader::refresh(&self) -> Result<(), String>` fetches
  the latest (current best) `OrgState` for the org and caches it in a `Mutex`.
- **Sync half:** `ChainReader::get_org_state` reads the cached snapshot
  synchronously, so `verify_envelope_against_chain` (which is sync) can call it
  without blocking.

Call `refresh` before `verify_envelope_against_chain` to ensure the snapshot is
current. `OrgState` derives `Copy`, so the snapshot is extracted cheaply.

For live Paseo, switch `on-chain-client` to its `smoldot` feature (future work).
The chopsticks integration test uses the `dev-rpc` / jsonrpsee transport with a
`LegacyBackend` client.

### Writes — `chain_write::{calldata, multisig, proxy, submit}`

The write path is productionised from `on-chain-client/tests/common/` and
compiled only with `--features chain`. All submit helpers return without mining
— block production is injected by the caller.

#### `calldata`

`build_update_calldata(root, org_pub_key, expected_epoch) -> [u8; 100]`

Builds the ABI-encoded calldata for `OrgRegistry.update(bytes32,bytes32,uint256)`
(selector `0xf1bc537b`): `selector ‖ root(32) ‖ orgPubKey(32) ‖ expectedEpoch(uint256 BE, 32)`.
Pure function — no chain required.

`revive_update_runtime_call(contract_h160, root, org_pub_key, epoch) -> Value`

Wraps the calldata in a `RuntimeCall::Revive(Call::call { … })` dynamic value
for dispatch through the multisig/proxy stack.

#### `multisig`

`multi_account_id(signatories, threshold) -> [u8; 32]`

Computes the multisig pseudo-account: `blake2_256(SCALE(("modlpy/utilisuba",
sorted_signers, threshold)))`. Pure function.

`dispatch_threshold_1(api, signer, other_signatories, call)` — submits
`Multisig.as_multi_threshold_1`. Does NOT mine or wait.

`fund(api, from, dest, amount)` — `Balances.transfer_keep_alive`. Does NOT mine.

#### `proxy`

`proxied(pure_proxy, call) -> Value` — wraps `call` with `pure_proxy` as origin
via `Proxy.proxy`. Pure function.

`map_account_call() -> Value` — `Revive.map_account {}`. Must be dispatched once
by a fresh pure proxy before its first `Revive.call` (pallet-revive prerequisite,
else error 43). Pure function.

`create_pure_via_multisig(sink, api, signer, others)` — submits
`Proxy.create_pure` through the threshold-1 multisig, calls `sink.settle()`,
reads the `PureCreated` event, and returns the pure-proxy `AccountId32`.

#### `submit`

`submit_update(api, signer, contract_h160, new_root, new_org_pub_key, expected_epoch) -> Result<String, WriteError>`

Direct single-signer `Revive.call` path. Returns the 0x-prefixed extrinsic hash
without waiting for inclusion. For the multisig/proxy admin path, use
`dispatch_threshold_1` with `proxied(P, revive_update_runtime_call(...))`.

#### `BlockSink` decoupling

```rust
#[async_trait]
pub trait BlockSink: Send + Sync {
    async fn settle(&self) -> Result<[u8; 32], WriteError>;
}
```

`settle` advances the chain so a just-submitted extrinsic is observable, and
returns the hash of the block it landed in. Chopsticks tests implement this by
calling `dev_newBlock`; a live-chain implementation would wait for finalisation.
The write path itself is agnostic — the same `genesis_ceremony` code compiles
and runs against both.

`settle` returns the produced block hash so events can be read at the exact block
(`get_org_state(admin, Some(block_hash))`), without relying on "latest".

### `ceremony::genesis_ceremony`

```rust
pub async fn genesis_ceremony(
    sink: &dyn BlockSink,
    api: &OnlineClient<PolkadotConfig>,
    contract_h160: [u8; 20],
    funder: &Keypair,
    admin: &Keypair,
    others: &[[u8; 32]],
    genesis_root: [u8; 32],
    org_pub_key: [u8; 32],
) -> Result<GenesisOutcome, WriteError>
```

Composes the write primitives into the full genesis flow:

1. `create_pure_via_multisig` — creates pure proxy P; `sink.settle()`
2. `fund` P's existential deposit; `sink.settle()`
3. `map_account` from P (pallet-revive prerequisite); `sink.settle()`
4. `update(genesis_root, org_pub_key, expectedEpoch=0)` via proxied multisig;
   `sink.settle()` — epoch becomes 1, contract emits `GenesisInitialized`

Returns `GenesisOutcome { p: [u8; 32], org_id: OrgId }` where
`org_id = h160_of(P)` is the contract slot key.

**Single-admin / threshold-1 simplification (S1):** the ceremony uses a 1-of-N
pure-proxy multisig. A threshold-1 multisig requires at least 2 signatories
(a 1-of-N where N ≥ 2). Pass an empty `others` slice only if the runtime allows
a 1-of-1; for Paseo Asset Hub, supply at least one co-signatory. A future phase
will generalise to M-of-N.

### End-to-end test

```
CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-node \
  --features chain --test chain_genesis_e2e \
  -- --test-threads=1 --nocapture
```

Runs a genesis ceremony followed by an admit-member update against a chopsticks
fork of Paseo Asset Hub, reads state back via `OnChainReader`, and asserts that
`verify_envelope_against_chain` succeeds with the independently-read on-chain
root. Requires internet access (chopsticks downloads the Paseo runtime) and takes
approximately 60 s. Not run in CI by default — trigger manually or in a slow lane.

## Transport (Phase 2.3)

### Feature flag

```toml
# Cargo.toml
[features]
transport = ["dep:iroh", "dep:tokio", ...]
```

All iroh-based transport code is gated behind the `transport` cargo feature.
The crate's Phase 2.1/2.2 core compiles and tests without it.

**Version note:** iroh is pinned to **0.98.2**, not 1.0. The workspace also
contains `spike-p2panda` / `p2panda-net`, which depend on an
`ed25519-dalek` pre-release that conflicts with iroh ≥ 1.0. Pinning to 0.98
keeps all crates in the workspace compatible.

### `OrgEndpoint`

`OrgEndpoint` wraps an iroh `Endpoint` to provide typed send/receive over the
ODS protocol:

- **Identity:** `EndpointId == P2pDeviceKey` — the iroh node key is the device
  ed25519 key. Dialing a peer cryptographically proves device-secret custody;
  the TLS handshake is the authentication step.
- **Relay disabled:** built with `presets::Minimal` + `RelayMode::Disabled` for direct/loopback
  connections. Discovery and relay are left to future phases (see S3 note below).
- **ALPN:** `/ods/org-node/1` — both sides must present this protocol string;
  connections using a different ALPN are rejected.

### Wire protocol

Messages are typed as `WireMessage { envelope: SignedDeltaEnvelope, org_secret: Option<[u8; 32]> }`
(the org secret is present only on admission).

Framing is **length-prefixed**: a 4-byte little-endian `u32` body length precedes
each `postcard`-serialised `WireMessage`. The maximum body size is 1 MiB
(`MAX_FRAME = 1 << 20`); oversized frames are rejected with an error before any
bytes are decoded.

### API

| Function | Description |
|---|---|
| `OrgEndpoint::bind(keypair) -> Result<OrgEndpoint>` | Bind an iroh endpoint on an OS-assigned port, using the given device signing keypair as the iroh node key. |
| `send(endpoint, addr, msg) -> Result<()>` | Open a QUIC stream to `addr`, frame and send `msg`, then flush. |
| `recv_one(endpoint) -> Result<(WireMessage, P2pDeviceKey)>` | Accept one inbound connection, decode the framed message, and return both the message and the **authenticated remote device key**. |

**Security note:** `recv_one` returns the remote device key that was
authenticated by the iroh/QUIC handshake (the key the peer proved ownership of
via TLS). The caller **must still cross-check this key against the members trie**
before trusting the sender — authentication proves key custody, but not
membership.

### Two-node handshake test

```
CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-node \
  --features transport --test transport_handshake
```

Spins up two `OrgEndpoint`s in-process, sends a `WireMessage` from node A to
node B over loopback, and asserts that:

1. The decoded message round-trips correctly.
2. The remote device key returned by `recv_one` matches the sender's key.

The test runs fully offline with no external services required.

### S3 note

iroh is used as a transport stand-in for the Phase 2 PoC. The PoC uses
relay-disabled direct connections (loopback / LAN). Real peer discovery,
relay fallback, and NAT traversal are out of scope for Phase 2 and will be
addressed in a future phase.
