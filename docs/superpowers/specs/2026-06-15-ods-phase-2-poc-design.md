# ODS Phase 2 — Proof-of-concept app: members trie + on-chain functionality

**Author(s):** Jan-Jan van der Vyver (design captured via brainstorming session)
**Status:** In review
**Created:** 2026-06-15
**Spec for:** Phase 2 of [`Organisational Data Sovereignty p1.md`](../../../Organisational%20Data%20Sovereignty%20p1.md) — "Create a proof-of-concept app to demonstrate functionality [of the] members trie and on-chain functionality."

---

## 1. Overview

A demonstrator app that exercises the **members trie** (`org-members`) and the
**on-chain anchor** (`OrgRegistry` via `on-chain-client` + subxt) end-to-end
across five user stories: create an organisation, prepare to join, admit a
member, verify-and-commit membership, and revoke a member.

The app reuses the completed Phase 1 crates as-is and adds one new library
crate, `org-node`, that owns everything those crates deliberately leave to the
caller (signing, envelopes, sequencing, verify-against-chain, key/persona
storage, and peer transport). A thin Tauri shell exposes `org-node` to a
SvelteKit webview.

**The single demonstrated security property:** a receiving member commits a
membership change only after the change's signed delta, applied to its local
trie mirror, reproduces a root that **independently** matches the on-chain root
at the expected epoch. The delta and the trusted root travel different paths.

## 2. Scope

### In scope
- The five user stories (§6), driven by two real app instances (User A, User B)
  on one machine.
- Members trie genesis, member add, member remove (via `org-members`).
- On-chain genesis + `update()` writes (subxt, threshold-1 proxy) and reads /
  subscriptions (`on-chain-client`).
- Signed-delta envelopes, replay protection, and verify-against-chain.
- Real device-to-device transport via **iroh**, authenticated by mapping
  `P2pDeviceKey → iroh NodeId`.
- Local persona/key storage supporting multiple personas per user (one per org).

### Out of scope (later phases — see §7 register)
- CGKA / data-object in-transit encryption (Phase 4).
- Local-first library (Keyhive) ACL substitutions (Phase 3).
- τ-window transitive-trust taint reversal (Phase 5 / future).
- Per-member privacy / ZK membership proofs (future).
- N-of-M threshold admin ceremony (deferred; see S1).

### Deliberate deviation from the written Phase 2 goal
The spec names the deliverable a "progressive web app." This PoC is instead a
**Tauri desktop app** (SvelteKit as the webview). Rationale: going native lets
the app run the *actual* Rust `on-chain-client` (only its wasm32 *browser* lane
is blocked upstream in subxt 0.50.1 — native smoldot works) and use **iroh** as
a real transport whose `NodeId` is an ed25519 key, matching `P2pDeviceKey`.
This trades literal PWA-ness (S8) for full reuse of the tested Rust stack and a
credible Phase-3 transport stand-in. Tauri preserves the spirit: installable,
local-first, cross-platform, offline-capable.

## 3. Architecture

### 3.1 Process topology

```
┌─────────────────────────────────────────────┐
│  SvelteKit webview (UI only — no secrets)     │
└───────────────┬───────────────────────────────┘
                │ Tauri commands / events (IPC)
┌───────────────▼───────────────────────────────┐
│  src-tauri (thin adapter)                      │
├───────────────────────────────────────────────┤
│  org-node  (NEW library — the brain)           │
│   • persona + key store (per-org identities)   │
│   • sign / verify / envelope / sequence        │
│   • verify-against-chain orchestration         │
│   • iroh node (NodeId = P2pDeviceKey)          │
│   • write path: build & submit update() (subxt)│
│  ┌──────────────┐ ┌───────────────┐ ┌────────┐ │
│  │ org-members  │ │ on-chain-client│ │ subxt  │ │
│  │  (trie/SMT)  │ │   (reads)      │ │(writes)│ │
│  └──────────────┘ └───────────────┘ └────────┘ │
└───────────────────────────────────────────────┘
        │ smoldot/RPC                  │ iroh QUIC
        ▼                              ▼
   chopsticks / Paseo            peer device(s)
```

- **UI** holds no secrets and makes no trust decisions; it renders state and
  collects input.
- **`org-node`** is a standalone, headless-testable library crate — the PoC's
  brain, and the artifact Phase 3 builds on. All sensitive logic lives here, not
  in the desktop shell.
- **`src-tauri`** is a thin adapter: Tauri commands (UI→Rust) and events
  (Rust→UI pushes).

### 3.2 Crate reuse
- `org-members` — trie/SMT; add/remove member + device sub-trie, delta
  compute/apply, `verify_against`. Used natively (no WASM).
- `on-chain-client` — reads (`get_org_state`) and subscriptions
  (`subscribe` → best/finalised/reorg). Native smoldot or jsonrpsee transport.
- `subxt` — the write half: builds and submits `update()` extrinsics through the
  threshold-1 proxy. (The write half was always deferred to Phase 2 by
  `on-chain-client`.)

### 3.3 Chain environment
chopsticks fork of Paseo Asset Hub by default (the `on-chain` repo already
scripts this; `ws://localhost:8000`); a configurable endpoint allows pointing
the same app at live Paseo (opt-in). Dev accounts pre-funded on the fork.

### 3.4 Demo topology
Two real instances on one machine, `User A` and `User B`, each with its own
Tauri app-data directory (separate persona stores, separate iroh nodes). They
are genuine iroh peers and both watch the same `OrgRegistry` slot on the same
chain.

## 4. Data model & terminology

### 4.1 Key identifiers
- **`P`** — the pure-proxy **`AccountId32`**: the admin identity that signs
  `update()` (it is `msg.sender`'s source).
- **`org_id`** — **`h160_of(P)`**: pallet-revive's `AccountId32 → H160` mapping.
  This H160 is the contract's `mapping(address => OrgState)` key — "the on-chain
  key where the org information is stored." Stable across multisig rotation
  (invariant `pure_proxy_h160_is_org_id_and_survives_rotation`). This is what A
  shares with B so B knows which slot to read and verify against.
- **`orgPubKey`** — the org's signing/pseudo-group public key stored *inside*
  the slot. Generated at genesis; its secret (`org_secret_key`) is kept local
  and distributed to admitted members (stored, not exercised — see S4/S12).
- **`member_id`** — the stable trie-leaf id, minted by the admin when a member is
  added; null while a persona is still "proposed."
- **`P2pMemberKey` / `P2pDeviceKey`** — ed25519 keys in the trie. The device
  secret also serves as the **iroh node secret**, so `NodeId = P2pDeviceKey`.

### 4.2 Persona (local identity; one per org per user)
`persona_id` (local UUID), `org_id`, profile (`handle`, `name`, `surname`),
member keypair, device keypair(s), `member_id` (null until admitted), `status`
∈ {`proposed`, `active`, `revoked`}.

### 4.3 Org record (a member's local view of an org)
`org_id`; last verified `OrgState` `{root_hash, org_pub_key, epoch}`; the
member's full local **trie mirror** (this simple design shares the whole trie
among members); `org_secret_key` (once admitted); the admin's member + device
pubkeys (to authenticate/connect to A).

### 4.4 On-chain (`OrgRegistry`, unchanged)
`mapping(address org_id => OrgState{rootHash, orgPubKey, epoch})`. `epoch` is a
monotonic compare-and-swap counter. `update(newRoot, newOrgPubKey,
expectedEpoch)` initialises at epoch 0 (→1, `GenesisInitialized`) and otherwise
CAS-increments (`RootUpdated`), rejecting stale or no-op updates.

### 4.5 Storage
Per-instance Tauri app-data directory. Personas/org records persisted to a
passphrase-encrypted-at-rest store. (PoC simplification S9 — production would
use the OS keychain / secure enclave for secret keys.)

## 5. The trust & security spine

### 5.1 Signed-delta envelope
Every trie change A makes is wrapped exactly as the `org-members` README
prescribes:

```
SignedDeltaEnvelope {
  org_id,        // binds to this org's slot
  parent_seq,    // monotonic; replay protection
  delta_bytes,   // postcard(Delta)
  signature,     // A's member key over (org_id ‖ parent_seq ‖ delta_bytes)
}
```

The receiver verifies `org_id` and the signature against the sender's known
member pubkey **before** deserialising `delta_bytes`.

### 5.2 Verify-against-chain (the crux)
A receiving member never trusts a delta on its own. Strict order:
1. Receive envelope over iroh.
2. Check `org_id`, signature (against the sender's known member pubkey), and
   `parent_seq` (reject ≤ last observed).
3. Cross-check the connected iroh NodeId is a device that appears (for the
   expected member) in the trie / exchanged keys.
4. `apply_delta` to the local trie mirror → `CandidateTrie`.
5. `verify_against(on_chain_root)` where `on_chain_root` comes **independently**
   from `on-chain-client` reading the slot at the expected epoch.
6. Match ⇒ commit locally. Mismatch ⇒ reject; nothing committed.

The delta and the trusted root must arrive via different trust paths; receiving
both from the same source tautologically passes and is the primary way to break
the model (`org-members` README §10).

### 5.3 iroh channel authentication
Because `NodeId = P2pDeviceKey`, dialing a peer's NodeId is itself proof the
peer holds that device's secret key. `org-node` additionally checks the
connected NodeId is a device recorded (for the expected member) in the trie /
exchanged keys, so connection identity and trie identity are cross-checked.

### 5.4 Epoch as the change signal
Each instance subscribes (via `on-chain-client`) to its org's slot. An epoch
bump is the trigger to fetch + verify the corresponding delta over iroh. Commit
on **finalised** (not best-block) events; a reorg that retracts the bump
retracts the trigger. Stale/equal epochs are rejected.

## 6. User-story flows

### Story 1 — A creates the organisation (genesis)
1. A fills in a persona; `org-node` generates A's member + device keypairs
   (device secret = iroh node secret).
2. Pure proxy `P` created via threshold-1 multisig; `org_id = h160_of(P)`
   computed; org keypair generated (`orgPubKey` on-chain, `org_secret_key`
   local).
3. `org-node` builds the genesis trie via `org-members`: one member leaf (A) with
   A's device sub-trie; mint A's `member_id`; compute `root_hash`.
4. **Write:** `update(root_hash, orgPubKey, expectedEpoch=0)` through the proxy
   (subxt) → `GenesisInitialized`, epoch → 1.
5. `on-chain-client` confirms the slot reads back `{root_hash, orgPubKey,
   epoch:1}`. A's persona → `active`.

### Story 2 — B prepares to join (out-of-band exchange)
1. A exports an **invite blob** (copy/QR): `org_id`, A's member pubkey + device
   NodeId, `orgPubKey`. B imports it.
2. B creates a *proposed* persona; `org-node` generates B's member + device
   keypairs; `member_id` null (`status: proposed`).
3. B exports a **join-request blob**: handle/name/surname, B's member pubkey, B's
   device NodeId. B sends it to A out-of-band.
4. Both now hold each other's keys + NodeIds → enough to dial. No chain/trie
   change yet.

### Story 3 — A admits B, updates chain, pushes the delta
1. A imports B's join-request, reviews it, mints B's `member_id`, `add_member`s B
   (with device sub-trie) → new trie, `root_hash'`.
2. A wraps the change in a `SignedDeltaEnvelope` (`expectedEpoch`/`parent_seq`
   tracking the genesis state).
3. **Write:** `update(root_hash', orgPubKey, expectedEpoch=1)` → epoch → 2,
   `RootUpdated`.
4. A's iroh node dials B's NodeId and sends the envelope **and** the
   `org_secret_key` over the authenticated channel.

### Story 4 — B verifies and commits
1. B's `on-chain-client` subscription sees epoch 1→2 on `org_id`'s slot → trigger.
2. B receives A's envelope over iroh; `org-node` checks `org_id` + signature
   (against A's known member pubkey) + `parent_seq`; cross-checks the connected
   NodeId is A's device.
3. `apply_delta` → `verify_against(on_chain_root@epoch2)`. Match ⇒ commit:
   persona → `active`, store trie mirror + `org_secret_key`. Mismatch ⇒ reject.

### Story 5 — A revokes B
1. A `remove_member`s B → `root_hash''`; wraps a revocation envelope.
2. **Write:** `update(root_hash'', orgPubKey, expectedEpoch=2)` → epoch → 3.
3. A notifies over iroh: pushes the revocation envelope to remaining members and
   to B (best-effort).
4. B's client detects epoch → 3 (subscription) and/or receives the notice;
   verifies against the chain that B's leaf is gone at the verified root ⇒
   `org-node` **self-deletes** the org record + `org_secret_key` + trie mirror
   locally (persona → `revoked`). The self-delete triggers on the
   **chain-verified** removal, not on trusting A's say-so. If B is offline, the
   deletion happens whenever B next reaches the chain (honest-client assumption,
   per the spec's transitive-trust model). No CRDT taint-reversal (S6).

## 7. Simplifications & future-fix register

| # | Simplification (PoC) | Future fix / phase |
|---|---|---|
| S1 | Single admin, threshold-1 proxy — no N-of-M co-signing | Real threshold ceremony (on-chain-client deferred threshold>1) |
| S2 | Proxy multisig at all (spec-acknowledged): admin pubkeys identifiable; admins managed separately from the trie | FROST + ZK; single source of truth |
| S3 | iroh as transport stand-in | Phase 3 real transport (Beelay/Keyhive bridge) |
| S4 | No CGKA / data-object in-transit encryption — `org_secret_key` stored, never exercised | Phase 4 |
| S5 | No local-first ACL substitutions (stable-id ACL, org pseudo-group, library-level write-authority lockout, p2p policy); verify-against-chain hand-wired at app level | Phase 3 |
| S6 | No τ-window / transitive-trust taint reversal — revocation = local self-delete, no CRDT reversal | Phase 5 / future |
| S7 | Whole trie shared among members — no per-member privacy / ZK membership proofs | Future ZK design |
| S8 | Tauri desktop, not a browser PWA | (deliberate, this PoC) |
| S9 | Keys in passphrase-encrypted app-data file, not OS keychain/secure enclave | Hardening |
| S10 | Out-of-band channel = manual copy/paste; peer NodeId exchanged in that blob (no discovery — a spec non-goal) | n/a (non-goal) |
| S11 | chopsticks ephemeral fork as default; dev-account pre-funding | Paseo / mainnet ops |
| S12 | Org secret distributed over iroh on admission; no rotation / key-exclusion mechanics (follows from S4) | Phase 4 |
| S13 | Competing-delta conflict resolution sidestepped by single-admin (one writer) | Follows from S1 |
| S14 | Device-level (sub-trie) revocation not exercised — trie supports it; PoC demos *member* revocation. One device per persona assumed | Later device flows |

## 8. Error handling

Each surfaced distinctly in the UI; never silently swallowed.
- **Chain:** epoch mismatch / CAS race; write rejected (zero-value, no-op);
  RPC/light-client disconnect; reorg (commit only on finalised).
- **Verify:** signature failure; `org_id` mismatch; stale `parent_seq`; **root
  mismatch** (delta doesn't reproduce the on-chain root → hard reject).
- **iroh:** dial failure; connected NodeId not in trie / expected keys; peer
  offline (revocation self-delete still fires from the chain signal).

## 9. Testing

Matches repo conventions — tested + fuzzed library crates.
- **`org-node` unit tests:** envelope sign/verify; sequencing/replay; the
  verify-against-chain happy path and every rejection path in §5.2.
- **Fuzz (hard rule):** the envelope decoder and the verify-against-chain entry
  point — malformed envelope, wrong root, replayed/forked `parent_seq` — using
  bolero, per the repo's fuzzing pattern.
- **Integration:** reuse the `on-chain-client` chopsticks harness; a two-node
  `org-node` test driving stories 1→5 end-to-end (genesis → admit → verify →
  revoke → self-delete) against the fork, with two in-process iroh nodes.
- **Shell:** the Tauri/Svelte shell stays thin enough to verify manually via the
  two-instance demo; no heavy webview E2E for the PoC.

## 10. Build notes
Tauri, iroh, and subxt are new dependencies. `~/.cargo` is read-only in this
environment; fetch via `CARGO_HOME=/tmp/cargo_home_fuzz`. Feature work happens in
a git worktree per repo convention.

## 11. References
- [`Organisational Data Sovereignty p1.md`](../../../Organisational%20Data%20Sovereignty%20p1.md) — overall design; Phase 2 goal; core design pieces; scenarios.
- [`org-members/README.md`](../../../org-members/README.md) — trie crate; caller responsibilities (envelope, verify-against-chain, replay, authority).
- [`on-chain-client/README.md`](../../../on-chain-client/README.md) — reader half; transport feature matrix; wasm32-browser block.
- [`on-chain/src/OrgRegistry.sol`](../../../on-chain/src/OrgRegistry.sol) — contract; `update()` CAS semantics.
- [`docs/phase-1d/decision.md`](../../phase-1d/decision.md) — Keyhive pick (conditional); no published transport (R12).
