# Phase 1.d sub-crate inventory

Populated by the per-library spike crates during their Task 1
(inventory step) before any gate work begins. Each entry:
`crate name @ pinned rev` — role — relevant API surface — re-exporter.

## Keyhive

Pinned revision: commit `a2876f3c79d89c9dd0c5e9f84802611c716fe27e` on branch
`main`, dated 2026-05-22. Workspace version `0.0.0-alpha.3`. This is
pre-1.0 and explicitly unaudited; the README carries no stability
warning yet, but the alpha tag signals active API development. Four
crates are relevant to the spike: `keyhive_crypto`, `beekem`,
`keyhive_core`, and `keyhive_wasm`. There is no published transport
crate at this revision (Beelay is not yet published from this repo).
Pin the exact SHA; do not use a floating `main` reference.

### `keyhive_crypto @ a2876f3`

**Role.** Low-level cryptographic building blocks: typed digests,
signatures, key exchange, symmetric encryption, domain separation, and
read capabilities. Provides foundational crypto abstractions used by
both `beekem` and `keyhive_core`.

**Relevant API surface.** `AsyncSigner<F>` trait
(`src/signer/async_signer.rs`) — `try_sign_bytes_async(bytes) -> impl
Future<…, Ed25519Signature>` — the primary async signing interface
abstracted to support both multi-threaded and WASM-single-threaded
runtimes. `Verifiable` trait (`src/verifiable.rs`) — trait bound for
all signers. Modules: `digest` (`src/digest.rs`), `signed`
(`src/signed.rs`), `share_key` (`src/share_key.rs`), `symmetric_key`
(`src/symmetric_key.rs`), `read_capability` (`src/read_capability.rs`)
— the typed wrappers for the cryptographic primitives. No explicit
domain-separator seam exposed at the top level.

**Re-exporter.** `beekem` and `keyhive_core` both depend on
`keyhive_crypto` internally. Top-level re-export via `keyhive_core` is
implicit (not via public `pub use`); direct import from
`keyhive_crypto` is required for signer traits.

**Feature flags / `no_std`.** Features: `default = ["std"]`, `std`,
`arbitrary`. Supports `no_std + alloc` when default features are
disabled. Core cryptographic dependencies (`blake3`,
`chacha20poly1305`, `ed25519-dalek`, `x25519-dalek`) all declare
`default-features = false` with `alloc` paths. Gate 0 risk: LOW if the
crypto deps themselves are WASM-compatible; verification required.

### `beekem @ a2876f3`

**Role.** TreeKEM-based Continuous Group Key Agreement (CGKA) at
O(log n) per member change. Implements the group encryption state
machine and operation DAG. This is the scalable CGKA backbone
underlying Keyhive.

**Relevant API surface.** `Cgka` struct (`src/cgka.rs`) — wraps the
underlying BeeKEM tree; type parameters: domain IDs (`IndividualId`,
`DocumentId`), operation log, key material stores. Key methods:
`new()`, `add(member_id, public_key, signer)`,
`remove(member_id)`, `update()` (rotation entry point),
`new_app_secret_for(recipient)`, `decryption_key_for(recipient)`.
Takes a `ShareKey` for rotation. `CgkaOperation` enum
(`src/operation.rs`) — protocol messages. `PcsKey`
(`src/pcs_key.rs`) — per-update key. `Id` module (`src/id.rs`) —
member and document identifiers (concrete types, not generics).
`SecretStore<S, T>` trait — abstract backing storage. No direct
access to individual leaves; tree mutations go through the struct
methods.

**Re-exporter.** `keyhive_core` wraps `beekem::cgka::Cgka` in its own
`Cgka` struct (`keyhive_core/src/cgka.rs`) with domain-ID mapping.
Public re-export: `beekem` types are not directly re-exported by
`keyhive_core` at the top level.

**Feature flags / `no_std`.** Features: `default = ["std"]`, `std`,
`test_utils`, `arbitrary`. Supports `no_std + alloc`. Dependencies
(`blake3`, `chacha20poly1305`, `ed25519-dalek`, `rand`,
`keyhive_crypto`) all with `default-features = false`. Gate 0 risk:
LOW if transitive deps comply.

### `keyhive_core @ a2876f3`

**Role.** High-level integration layer composing cryptographic
primitives with CGKA, delegation/revocation CRDT, and event listeners.
Implements the `Keyhive<F, S, T, P, C, L, R>` main type and principal
hierarchy (`Agent` enum with `Individual`, `Group`, `Document`,
`Active` variants). This is the primary API target for gates 1, 2, 3,
and 4.

**Relevant API surface.** `Agent<F, S, T, L>` enum
(`src/principal/agent.rs`) — four variants: `Active(IndividualId, …)`,
`Individual(IndividualId, …)`, `Group(GroupId, …)`,
`Document(DocumentId, …)` — each wrapped in `Arc<Mutex<…>>`. Note:
`Agent` is generic over signer/listener but **not over an ID type**;
`IndividualId` and `GroupId` are concrete newtype wrappers over
`ed25519_dalek::VerifyingKey`. `Keyhive<F, S, T, P, C, L, R>` struct
(`src/keyhive.rs`) — main type, generic over `FutureForm`,
`AsyncSigner<F>`, `ContentRef` (default `[u8; 32]`), `Plaintext`,
`CiphertextStore`, `MembershipListener<F, S, T>`, `CryptoRng`.
Methods: `generate()`, `generate_group()`, `add_member()`,
`revoke_member()`, `receive_static_event()`, `into_archive()`,
`try_from_archive()`. `Access` enum (`src/access.rs`) — four ordered
levels: `Relay`, `Read`, `Edit`, `Admin`. `Cgka` wrapper
(`src/cgka.rs`) — domain-ID to beekem-ID mapping.
`MembershipListener<F, S, T>` trait (`src/listener/membership.rs`) —
two methods: `on_delegation(delegation: Signed<Delegation>)`,
`on_revocation(revocation: Signed<Revocation>)`. Also composed from
`PrekeyListener` and `CgkaListener` (other listener subtraits).
`CiphertextStore<F, Cr, T>` trait (`src/store/ciphertext.rs`) —
`get_ciphertext(cr) -> Future<…, Option<Arc<EncryptedContent<T, Cr>>>>`,
`get_ciphertext_by_pcs_update(digest) -> Future<…, Vec<…>>`,
`mark_decrypted(cr)`. `DelegationStore` struct
(`src/store/delegation.rs`) — content-addressed map with `insert()`,
`get()`, `remove_by_hash()`, `values()`, `keys()`, `iter()`.
`Identifier` newtype (`src/principal/identifier.rs`) — wraps
`ed25519_dalek::VerifyingKey`; used as the root for `IndividualId`
and `GroupId`.

**Re-exporter.** Not re-exported by any top-level crate. Must be
imported directly.

**Feature flags / `no_std`.** Features: `default = []` (no default
features), `debug_events`, `mermaid_docs`, `test_utils`. **Does not
support `no_std`**: depends on `tokio` (sync), `futures` (full std
stack), `thiserror`, `bincode`. These are unconditional dependencies
(not feature-gated). Gate 0 risk: DEFINITE FAIL on this crate at
`--target wasm32-unknown-unknown` without significant refactoring.
The spike should scope gate 0 to whether `keyhive_crypto` and
`beekem` alone can compile to WASM; gate 0 for `keyhive_core` is a
Hard blocker.

### `keyhive_wasm @ a2876f3`

**Role.** JavaScript bindings via `wasm-bindgen`. Exports the Keyhive
API to browsers and Node.js WASM environments. Provides `JsKeyhive`
and serialization helpers.

**Relevant API surface.** `JsKeyhive` struct (`src/js/keyhive.rs`) —
primary JavaScript export wrapping `Keyhive<…>`. Methods:
`setPanicHook()` (initialization), serialization via `serialize()`
and `fromBytes()` (new as of commit `f162854`). Module exports:
`pub mod js; pub use js::keyhive::JsKeyhive;` and conditional
`js::encrypted` (accessed via `#[wasm_bindgen]` bindings).

**Re-exporter.** This is a consumer of `keyhive_core`, `beekem`, and
`keyhive_crypto`; not re-exported elsewhere.

**Feature flags / `no_std`.** Features: `default =
["console_error_panic_hook", "web-sys", "json"]`, `json` (enables
serde_json), `browser_test`. Dependencies: `keyhive_core`,
`wasm-bindgen`, `wasm-bindgen-futures`, `web-sys` (crypto/storage),
`js-sys`, `getrandom` (js feature), `base64-simd`. **Does not support
`no_std`**: inherits `keyhive_core`'s `tokio` / `futures`
dependencies, plus `wasm-bindgen` requires full std. Gate 0 risk:
DEFINITE FAIL (depends on `keyhive_core`). Out of scope for WASM
compile gate if `keyhive_core` is already ruled out.

### Pinned Cargo.toml entries for spike-keyhive

```toml
[dependencies]
keyhive_crypto = { git = "https://github.com/inkandswitch/keyhive", rev = "a2876f3c79d89c9dd0c5e9f84802611c716fe27e", default-features = false }
beekem         = { git = "https://github.com/inkandswitch/keyhive", rev = "a2876f3c79d89c9dd0c5e9f84802611c716fe27e", default-features = false }
keyhive_core   = { git = "https://github.com/inkandswitch/keyhive", rev = "a2876f3c79d89c9dd0c5e9f84802611c716fe27e" }
```

### Feature-branch and stability caveats

The workspace is `0.0.0-alpha.3` with no explicit stability warning
in the README, but the alpha tag indicates active development. Recent
commits show incremental feature additions (transitive delegation in
`1116eaf`, serialization methods in `f162854`, `Send`-ability fixes
in `7914692`, derived traits in `c48c35f`) and a "Bump keyhive wasm"
commit (`6bb2882`) suggesting version iteration is in flux. No
breaking renames as dramatic as p2panda's `bb62866` are evident in
the last 10 commits, but the lack of an explicit pre-1.0 warning is a
signal to re-verify the API at L1. Freeze on `a2876f3`; do not update
the pin mid-spike without re-running the full L1 battery.

### Gate-by-gate first-impressions hypotheses

These are HYPOTHESES from API inspection, not verified findings; each
will be confirmed or revised at L1.

**Gate 0 — WASM / `no_std` compile.** Split result expected.
`keyhive_crypto` and `beekem` have strong `no_std + alloc` pathways
through their crypto dependencies and can likely clear `--target
wasm32-unknown-unknown`. `keyhive_core` will DEFINITE FAIL due to
unconditional `tokio` + `futures` dependencies. Spike gate 0 is
scoped to whether `keyhive_crypto` + `beekem` alone compile; if both
pass, gate 0 is `Soft` with `fix_effort = Medium` (refactoring
`keyhive_core`'s store and listener traits to be
async-runtime-agnostic); if either fails, gate 0 becomes `Hard` with
`fix_path = Replace` or `Fork`. **Expected severity: Soft. Expected
fix_effort: Medium. Expected failing_subcrate: keyhive_core (not
counted in gate 0 scope).**

**Gate 1 — Stable-ID ACL with trie-lookup resolver.** Moderate risk.
`Agent`, `IndividualId`, and `GroupId` are concrete newtypes over
`ed25519_dalek::VerifyingKey` — **NOT generics over a custom ID
type**. Unlike p2panda's `GroupMember<ID>` which is generic,
Keyhive's principal types are hardwired. The `Keyhive<…, S, …>`
generic over `AsyncSigner<F>` gives a hook for custom
signing/verification, but not for re-mapping IDs. No explicit
`IdentityRegistry` trait exists; key material flows through
`CiphertextStore` and delegation stores. **Expect `Hard`** at the
principal-ID layer. Salvage path: call-site adapter — resolve
`MemberId` via the trie to a `VerifyingKey` immediately before each
`add_member`/`revoke_member` call, then pass the resolved
`Individual` (or synthetic `Agent`) into the library. The wrapper
caches the mapping so the same `MemberId` produces a consistent
`VerifyingKey` across calls. `fix_effort = Medium` depending on how
tightly principal IDs are baked into serialization and archive
formats. **Expected severity: Hard. Expected fix_path: TraitImpl.
Expected fix_effort: Medium. Expected failing_subcrate:
keyhive_core.**

**Gate 2 — Library-native membership-mutation ops
disabled/intercepted.** Likely `Soft` via custom-store impl.
`Keyhive::add_member()` and `revoke_member()` are concrete methods
with no feature flag to remove them, **but** their mutations are
persisted through the `CiphertextStore` / `DelegationStore`
abstractions, both of which are trait-bound in the `Keyhive`
generics. Custom impls can refuse writes routed outside the
trie-driven path. `MembershipListener::on_delegation()` /
`on_revocation()` are post-fact event callbacks, so they cannot
block — they are an audit/logging seam, not an intercept seam.
Better intercept: custom store + a wrapper around `Keyhive` whose
mutating methods are only callable from the trie-resolver code path.
Expect `Soft`, `fix_path = TraitImpl`, `fix_effort = Small` to
`Medium`. **Expected severity: Soft. Expected fix_path: TraitImpl.
Expected fix_effort: Small-Medium.**

**Gate 3 — CGKA / member-as-a-group key rotation driven by trie
change.** Likely `Soft`, `fix_effort = Medium`. `beekem::Cgka` takes
the leaf key as a direct argument
(`add(member_id, public_key, signer)`), giving us the clean
key-injection seam gate 3 needs. Rotation is via `Cgka::update()`
returning a new `PcsKey` and signed operation, with `force_pcs_update`
on the `Keyhive` layer as the entry-point equivalent. No
authoritative key cache outside the provided `SecretStore<S, T>` —
keys are injected per-update. The trie-resolver computes
`p2p_member_key(MemberId)`, packs it as a `ShareKey`, and feeds it
to `Cgka::add` or to the update op. BeeKEM's O(log n) cost is a
strong asymptotic advantage over p2panda DCGKA's O(n) per update.
Risk: the `Cgka` is wrapped by `keyhive_core`'s `Cgka` which performs
the domain-ID mapping; the rotation entry must be threaded through
the wrapper or bypass it. **Expected severity: Soft. Expected
fix_path: TraitImpl + custom listener for trigger. Expected
fix_effort: Medium.**

**Gate 4 — Organisation-as-pseudo-group principal.** Mixed.
`Agent::Group(GroupId, …)` is a first-class variant — Keyhive
explicitly models groups as agents and `transitive_members()`
resolves nested groups. This is a positive surprise relative to
p2panda where `Group::add(member: ActorId)` only accepts an
individual at the spaces layer. However, `Keyhive::add_member()`'s
signature is concrete: the member parameter is wrapped in `Agent`
but `IndividualId` and `GroupId` are both newtypes over
`VerifyingKey`, so the type system does not statically distinguish
them at the call site. Adding an org-group as a member of a
document works via `Agent::Group(group_id, …)`, but rotation
semantics (Flow C — when an individual is removed from the org, the
document's CGKA must rotate) need a custom listener that observes
the org-group's `MembershipListener` events and triggers
`force_pcs_update` on every document that has the org as a member.
**Expect `Soft`** at the agent-model layer (the enum exists and
nested groups resolve), **`Soft`** at the rotation-driver layer
(custom listener bridges the two). Salvage: add a reverse-lookup
(org → documents-where-org-is-member) to drive cascade rotation.
`fix_path = TraitImpl`, `fix_effort = Medium`. **Expected severity:
Soft. Expected fix_path: TraitImpl. Expected fix_effort: Medium.**

**Gate 5 — Peer-to-peer connection policy.** `Soft` via
`MembershipListener` + custom transport. There is no published
transport crate at this revision; Keyhive itself is
transport-agnostic. The `MembershipListener::on_delegation()` and
`on_revocation()` callbacks are the natural hooks for observing
membership changes. Custom listener impl can fire a trie-lookup,
check the peer policy, and emit a signal to close connections or
refuse new ones. No built-in connection-authorization callback at
the protocol level. The spike must implement its own transport stub
and integrate it with the listener. Expect `Soft`, `fix_path =
TraitImpl`, `fix_effort = Small` to `Medium`. **Expected severity:
Soft. Expected fix_path: TraitImpl. Expected fix_effort:
Small-Medium.**

## p2panda

Pinned revision: commit `41559b0dfc2d7d0e9e4fba251ceb7f8094ff8be1` on branch
`main`, dated 2026-05-20. All six relevant crates are at published version
`0.5.2`. The design spec's §Addendum noted that `p2panda-spaces` was on a
feature branch; as of this commit it is merged to `main` and published,
but the README still carries an explicit pre-1.0 stability warning ("APIs
not yet considered stable for production use; Core data types and
user-facing APIs may undergo breaking changes before v1.0.0"). Pin the
exact SHA; do not use a floating `main` reference.

### `p2panda-core @ 41559b0`

**Role.** Lowest-level protocol primitives: `Operation`, `Header`, `Body`,
`RawOperation`, `Hash`, `SigningKey`, `VerifyingKey`, `LogId`, `SeqNum`,
`Topic`.

**Relevant API surface.** `VerifyingKey` (`src/identity.rs`) — newtype
over `ed25519_dalek::VerifyingKey`; implements `Clone + PartialEq + Eq +
Ord + Hash + Serialize + Deserialize` plus the crate's own `Author`
marker trait. This is the raw public-key type that `ActorId` in
`p2panda-spaces` wraps. `IdentityHandle` trait
(`p2panda-auth/src/traits/mod.rs`) — `Copy + Debug + PartialEq + Eq + Ord
+ StdHash` — the generic bound that flows through `p2panda-auth` and
`p2panda-encryption` for all member-ID generics.

**Re-exporter.** `p2panda` (top-level node crate) re-exports
`p2panda-core`. `p2panda-spaces` depends on it via workspace path.

**Feature flags / `no_std`.** Features: `default = ["prune"]`,
`test_utils`. No `#![no_std]`. Depends on `ed25519-dalek`, `blake3`,
`ciborium`. Gate 0 risk: HIGH without patches to transitive dependencies.

### `p2panda-auth @ 41559b0`

**Role.** DAG-based CRDT group membership with fine-grained per-member
permissions. Implements strong-removal conflict resolution. This is the
ACL-authority crate targeted by gates 1, 2, and 4.

**Relevant API surface.** `GroupMember<ID>` enum
(`src/group/member.rs`) — `Individual(ID)` or `Group(ID)`, generic over
any `ID: IdentityHandle`. The `Group` variant models nested groups
(multi-device profiles, org-as-pseudo-group). `Access<C>` struct +
`AccessLevel` (`src/access.rs`) — four tiers: `Pull`, `Read`, `Write`,
`Manage`; generic over conditions type `C`. `Groups` trait
(`src/traits/dgm.rs`) — library-native mutation entry points:
`add(group_id, adder: ID, added: ID, Access<C>) -> Result<M, E>`,
`remove`, `promote`, `demote`; these are the ops gate 2 must intercept.
`GroupMembership` trait — read-only queries: `access()`, `member_ids()`,
`is_member()`. `Resolver` trait (`src/traits/resolver.rs`) — CRDT
state-rebuild and operation-processing interface (NOT a key resolver).

**Re-exporter.** `p2panda-spaces` composes `p2panda-auth` internally and
exposes `Group::add` / `Group::remove` at the spaces level. The top-level
`p2panda` crate does NOT re-export `p2panda-auth`.

**Feature flags / `no_std`.** Features: `default = ["processor"]` (pulls
in `tokio`, `p2panda-store`, `p2panda-stream`), `serde`, `test_utils`,
`test`. No `#![no_std]`. Gate 0: HIGH risk on default features;
`--no-default-features` may reduce the surface — to verify.

### `p2panda-encryption @ 41559b0`

**Role.** Two encryption schemes: `data_scheme` (DCGKA symmetric group
key agreement, O(n) per update, with post-compromise security) and
`message_scheme` (Double-Ratchet forward-secure messaging). `Dcgka` is
the CGKA primitive targeted by gate 3. An audit with Radically Open
Security is scheduled (per parent design §Addendum).

**Relevant API surface.** `Dcgka<ID, OP, PKI, DGM, KMG>`
(`src/data_scheme/dcgka.rs`) — generic over: `ID: IdentityHandle`,
`OP: OperationId + Ord`, `PKI: IdentityRegistry<ID> + PreKeyRegistry<ID,
LongTermKeyBundle>`, `DGM: AckedGroupMembership<ID, OP>`,
`KMG: IdentityManager + PreKeyManager`. Operations: `create`, `update`,
`add`, `remove`, `process`. The `PKI` generic is the key-injection seam
for gate 3. `EncryptionGroup` (`src/data_scheme/group.rs`) —
`add(member: ID, access: Access<C>)`, `remove(member: ID)` —
library-native mutation ops for gate 2. `IdentityRegistry<ID, Y>` trait
(`src/traits/key_registry.rs`) — `identity_key(y: &Y, id: &ID) ->
Result<Option<PublicKey>, E>` — the externally-injectable key-lookup
point for gate 3. `PreKeyRegistry<ID, KB>` trait —
`key_bundle(y: State, id: &ID) -> Result<(State, Option<KB>), E>`.
`KeyRegistry` struct (`src/key_registry.rs`) — concrete in-memory impl
with public `add_longterm_bundle(id, bundle)` and
`add_onetime_bundle(id, bundle)` — the injection points for
externally-resolved key material. Key lookup during DCGKA operations is
exclusively through the injected `PKI` state; there is no
independently-authoritative key cache.

**Re-exporter.** `p2panda-spaces` wraps `p2panda-encryption` internally;
encryption types are `pub(crate)` in spaces. Gate 3 L1 tests must address
this crate directly.

**Feature flags / `no_std`.** Features: `default = ["data_scheme"]`,
`data_scheme`, `message_scheme`, `test_utils`. Crypto deps
(`chacha20poly1305`, `curve25519-dalek`, `x25519-dalek`, `hpke-rs`) all
declare `default-features = false` with `alloc` paths — partial `no_std +
alloc` compatibility is plausible but unconfirmed. Gate 0: MEDIUM risk;
to verify with `cargo check --no-default-features --target
wasm32-unknown-unknown`.

### `p2panda-spaces @ 41559b0`

**Role.** Integration layer composing `p2panda-auth` (group ACL) with
`p2panda-encryption` (DCGKA) into a `Space` abstraction.
`Space<ID,…>` is the ACL-bearing encrypted data context. `Manager` is
the primary application entry point. Primary target for gates 1, 2, 3,
and 4.

**Relevant API surface.** `ActorId` (`src/types.rs`) — `struct
ActorId(pub(crate) VerifyingKey)` — a newtype over a raw ed25519 public
key; this is the hardwired principal type throughout spaces. Central
gate 1 friction point. `Space::add(member: ActorId, access: Access<C>)`
and `Space::remove(member: ActorId)` (`src/space.rs`).
`Group::add(member: ActorId, access: Access<C>)` and
`Group::remove(member: ActorId)` (`src/group.rs`); both delegate to
`process_local_control` which calls `AuthGroup::process` and then
`apply_group_change_to_spaces`. `Manager<ID, S, K, F, M, C, RS>`
(`src/manager.rs`) — seven generics: `ID` = space ID, `S` = store
bundle (implements `SpacesStore + AuthStore + MessageStore`),
`K` = key store, `F` = `Forge` impl, `M` = message type, `C` = access
conditions, `RS` = auth resolver. `Member` (`src/member.rs`) — `id:
ActorId` + `key_bundle: LongTermKeyBundle`. Store traits
(`src/traits/store.rs`): `SpacesStore`, `AuthStore`, `KeyRegistryStore`,
`KeySecretStore`, `MessageStore` — all externally implementable; primary
intercept surface for gate 2. `Forge` trait (`src/traits/forge.rs`) —
`verifying_key() -> VerifyingKey`, `forge(SpacesArgs<…>) -> M` — hook
for intercepting outgoing messages. `SpaceId` trait — `Copy + Debug + Eq
+ Serialize + DeserializeOwned`.

**Re-exporter.** Not re-exported by the top-level `p2panda` crate;
standalone dependency.

**Feature flags / `no_std`.** Feature: `test_utils`. Depends on `tokio`
(sync), `petgraph`, `p2panda-auth`, `p2panda-encryption`. No
`#![no_std]`. Gate 0: DEFINITE FAIL on default features. Gate 0 is
therefore `Hard` for the `p2panda-spaces` crate specifically; gate 0 for
the spike is scoped to whether `p2panda-core` + `p2panda-encryption`
alone pass WASM.

### `p2panda-net @ 41559b0`

**Role.** Data-type-agnostic p2p networking: iroh QUIC/TLS endpoint,
mDNS discovery, confidential PSI-based topic discovery, gossip, and
sync session management. Primary target for gate 5.

**Relevant API surface.**
`Endpoint::builder(address_book).spawn().await` — no connection
authorization callback; no per-peer allowlist in the builder (tracked:
upstream GitHub issue #925, unimplemented in 0.5.2). `NodeId` — type
alias for `VerifyingKey`. `LogSync` — sync manager wrapping
`p2panda-sync`'s `Manager<T>` trait. `WatcherSet<K, T>` / `Watcher<T>`
(`src/watchers.rs`) — generic observer via tokio channels; candidate
hook point for a reactive connection policy. `SessionConfig<T>` (from
`p2panda-sync`) — carries `remote_peer: VerifyingKey` at session-open
time — the trie-lookup hook for gates E1/E2.

**Re-exporter.** `p2panda` (top-level) re-exports `p2panda-net`.

**Feature flags / `no_std`.** Features: `default = [address_book,
iroh_endpoint, iroh_mdns, discovery, gossip, sync]`. Depends on `tokio`,
`ractor`, `iroh 0.98.2`. Gate 0: DEFINITE FAIL; `p2panda-net` is out of
scope for the WASM compile gate.

### `p2panda-sync @ 41559b0`

**Role.** Low-level sync traits and concrete append-only log sync
manager. Defines `Protocol` and `Manager<T>` traits. Provides
`SessionConfig<T>` carrying the remote peer's `VerifyingKey` — the
session-establish hook for gate 5.

**Relevant API surface.** `Protocol` trait (`src/traits.rs`) —
`run(sink, stream) -> impl Future<Output = Result<Output, Error>>`.
`Manager<T>` trait — `session(config) -> impl Future<Protocol>`,
`session_handle(id) -> PinnedSendHandle`, `subscribe() -> impl
Stream<FromSync<Event>>`. `SessionConfig<T>` — `topic`,
`remote_peer: VerifyingKey`, `live_mode: bool`. The `remote_peer` field
is available at session-establish time and is the primary gate 5
intercept point. `FromSync<E>` — event stream with session ID + remote
identity.

**Re-exporter.** `p2panda-net` (via `sync` feature) wraps `p2panda-sync`.
Top-level `p2panda` re-exports `p2panda-sync`.

**Feature flags / `no_std`.** No default features; `test_utils`
optional. Still depends on `tokio`. Gate 0: sync traits alone may be
`no_std`-compilable — to verify at L1.

### Pinned Cargo.toml entries for spike-p2panda

```toml
[dependencies]
p2panda-core       = { git = "https://github.com/p2panda/p2panda", rev = "41559b0dfc2d7d0e9e4fba251ceb7f8094ff8be1", default-features = false }
p2panda-auth       = { git = "https://github.com/p2panda/p2panda", rev = "41559b0dfc2d7d0e9e4fba251ceb7f8094ff8be1", default-features = false, features = ["serde"] }
p2panda-encryption = { git = "https://github.com/p2panda/p2panda", rev = "41559b0dfc2d7d0e9e4fba251ceb7f8094ff8be1", default-features = false, features = ["data_scheme"] }
p2panda-spaces     = { git = "https://github.com/p2panda/p2panda", rev = "41559b0dfc2d7d0e9e4fba251ceb7f8094ff8be1" }
p2panda-net        = { git = "https://github.com/p2panda/p2panda", rev = "41559b0dfc2d7d0e9e4fba251ceb7f8094ff8be1" }
p2panda-sync       = { git = "https://github.com/p2panda/p2panda", rev = "41559b0dfc2d7d0e9e4fba251ceb7f8094ff8be1" }
```

### Feature-branch and stability caveats

As of 2026-05-20, `p2panda-spaces` is on `main` at `0.5.2` (the
feature-branch status noted in the parent design's §Addendum is no
longer current). However, the README warns explicitly that the library
is pre-1.0 and APIs are unstable. The recent `bb62866` commit ("Rename
core data types and methods", 2026-05-15) and `a4dd6c8` ("Add method to
groups CRDT for getting heads filtered by group ids", 2026-05-15)
demonstrate that the public API is still being renamed. Freeze on
`41559b0`; do not update the pin mid-spike without re-running the full
L1 battery.

### Gate-by-gate first-impressions hypotheses

These are HYPOTHESES from a quick API scan, not verified findings; each
will be confirmed or revised at L1.

**Gate 0 — WASM / `no_std` compile.** Split result expected.
`p2panda-encryption` (especially `data_scheme`) has plausible `no_std +
alloc` paths through its crypto deps; `p2panda-core` and the
tokio-dependent crates (`p2panda-auth` on default features,
`p2panda-spaces`, `p2panda-net`) will fail. Gate 0 for the spike is
scoped to whether the crypto primitives alone clear the WASM target. If
they do, gate 0 is `Soft` with `phase3_effort = Medium`; if even
`p2panda-encryption` alone fails, it becomes `Hard` with `fix_path =
TraitImpl` or `Replace`.

**Gate 1 — Stable-ID ACL with trie-lookup resolver.** Highest-risk gate.
`ActorId` is a newtype over `VerifyingKey` hardwired throughout
`p2panda-spaces`: `Group::add(member: ActorId, …)` and `Space::add`
accept only `ActorId`, not a generic. The `GroupMember<ID>` generic in
`p2panda-auth` is promising, but `p2panda-spaces` appears to concrete it
over `ActorId` at compile time. **Expect `Hard` at `p2panda-spaces`
layer**; salvage path is likely `TraitImpl` of `IdentityRegistry`
(letting the `KeyRegistry` hold `MemberId`-indexed bundles populated
by the `MemberKeyResolver`), `fix_effort = Small` to `Medium`. To verify
at L1: attempt `Group<MemberId, …>` instantiation; confirm whether
`ActorId` is hardwired beyond reach.

**Gate 2 — Library-native membership-mutation ops disabled/intercepted.**
Most likely `Soft` via store-trait intercept; possibly `None` via
feature-flag. `Space::add` / `Group::add` in `p2panda-spaces` are
concrete methods with no feature flag to remove them. Best intercept:
custom `SpacesStore + AuthStore` impls that refuse mutations routed
outside the trie-driven path. The `Forge` trait offers a secondary
intercept point (refuse to forge auth-mutation messages). Expect `Soft`,
`fix_path = TraitImpl`, `fix_effort = Small`.

**Gate 3 — DCGKA / member-as-a-group key rotation driven by trie change.**
Likely `Soft`, `fix_effort = Medium`. `Dcgka<ID, OP, PKI, DGM, KMG>` is
fully generic over `PKI: IdentityRegistry + PreKeyRegistry`.
`KeyRegistry::add_longterm_bundle(id, bundle)` is a public injection
point — the spike calls `resolver.p2p_member_key(id)`, builds a bundle,
injects, then triggers `Dcgka::update()`. The library has no
authoritative key cache outside the `PKI` state, which matches our
"no direct key cache" invariant nicely. Risk: rotation in `Dcgka`
generates new group secrets and requires distribution; the local node
must be at least `Manage` level. Observer-only nodes will need a
different path. CGKA scaling is O(n) per update (parent design
§Addendum).

**Gate 4 — Organisation-as-pseudo-group principal.** Mixed. `Soft` at
`p2panda-auth` layer (the `GroupMember::Group(ID)` variant explicitly
models nested groups), but likely `Hard` at `p2panda-spaces` layer
because `Group::add` accepts only `ActorId` (individual), not a nested
group reference. Salvage: implement org-as-pseudo-group at the
`p2panda-auth` layer and bypass spaces' restricted entry points via a
custom `Manager` wrapper. Expect `failing_subcrate = p2panda-spaces`,
`fix_path = TraitImpl`, `fix_effort = Medium`.

**Gate 5 — Peer-to-peer connection policy.** `Soft` via
`p2panda-sync::Manager` wrapping; `Hard` if strict pre-open rejection at
the iroh QUIC layer is required. The `p2panda-net::Endpoint::builder`
has no connection authorization callback; upstream issue #925 is
unimplemented. `SessionConfig<T>::remote_peer: VerifyingKey` is
available at session-open time — a custom `Manager<T>` impl can check
the policy before delegating. Termination (Flows F1/F2) via
`session_handle(id).close()` after a trie-change observer fires. This
produces a small post-open window of unauthorised connection; recorded
as a `Soft` note on latency. Expect `Soft`, `fix_path = TraitImpl`,
`fix_effort = Small`.
