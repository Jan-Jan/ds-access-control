# ODS Phase 2.4 — Tauri + SvelteKit shell Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Wire the headless `org-node` (trust core + chain + transport) into a runnable two-instance demo: an `OrgService` that composes the five user stories, persisted personas/orgs (encrypted at rest), a thin Tauri command/event layer, and a utilitarian SvelteKit UI.

**Architecture:** "Fat Rust core, thin shell" (spec §3.1). The integration logic lives in a new **`OrgService`** in `org-node` (feature `app`), composing the store + chain (`OnChainReader`/ceremony/`submit`) + transport (`OrgEndpoint`) into story operations. It is **headless-testable** against `MockChain` + a temp-dir store + loopback iroh endpoints. `src-tauri` is a thin layer: it holds an `AppState` (the `OrgService` + a tokio runtime) and maps `#[tauri::command]`s + events onto it. The SvelteKit webview renders state and collects input only.

**Verification reality:** Rust logic (store, blobs, `OrgService` against MockChain) is unit/integration-tested headlessly. The SvelteKit build (`npm run build`) and the Tauri app compile (`cargo build`) are CI-checkable. The actual GUI launch, the real-chain (chopsticks) demo, and the two-instance p2p flow are **manual** (the user runs them) — subagents cannot drive a desktop GUI. Tasks state which gate applies.

**Tech Stack:** Rust (`org-node` with new `app` feature: chain + transport + persistence), Tauri 2.x, SvelteKit + `@sveltejs/adapter-static` (SPA), `@tauri-apps/api` 2.x, an AEAD for at-rest encryption (`chacha20poly1305` + `argon2` KDF), `tokio`.

**Spec:** [`docs/superpowers/specs/2026-06-15-ods-phase-2-poc-design.md`](../specs/2026-06-15-ods-phase-2-poc-design.md) §3.1 (topology), §4.2–4.5 (persona/org model, storage), §5 (trust spine), §6 (the five stories), §8 (error handling). Builds on plans 2.1/2.2/2.3.

**Simplifications carried (spec §7):** S1 single-admin 1-of-2 threshold; S9 passphrase-encrypted file store (not OS keychain); S10 manual copy/paste blobs for the out-of-band exchange; S11 chopsticks default.

---

## File structure

```
org-node/
  Cargo.toml                 # + [feature] app = chain+transport+store deps
  src/
    lib.rs                   # + #[cfg(feature="app")] pub mod store / blobs / service
    store.rs                 # NEW: encrypted persona/org persistence (PersonaStore)
    blobs.rs                 # NEW: Invite / JoinRequest out-of-band blob types
    service.rs               # NEW: OrgService — composes store+chain+transport into stories
  tests/
    service_stories.rs       # NEW (gated app): stories against MockChain + temp store + loopback iroh

app/                         # NEW — the Tauri + SvelteKit project
  package.json               # SvelteKit + adapter-static + @tauri-apps/api + @tauri-apps/cli
  svelte.config.js           # adapter-static fallback index.html
  vite.config.ts
  src/
    routes/
      +layout.ts             # export const ssr = false; prerender = true
      +layout.svelte
      +page.svelte           # persona/org dashboard (the 5-story UI)
    lib/
      api.ts                 # typed wrappers around invoke()/listen()
      components/            # PersonaList, CreateOrg, Invite, Admit, Membership, Revoke, StatusBar
  src-tauri/
    Cargo.toml               # depends on org-node (features=["app"])
    tauri.conf.json          # frontendDist ../build, devUrl :5173
    build.rs
    src/
      main.rs                # thin: builds AppState, registers commands, runs
      state.rs               # AppState { service: tokio::Mutex<OrgService>, rt handle }
      commands.rs            # #[tauri::command] wrappers → OrgService; events
  README.md                  # how to run the two-instance demo

docs/superpowers/demo/two-instance-demo.md  # NEW: step-by-step demo runbook
```

`store.rs`/`blobs.rs`/`service.rs` are `#[cfg(feature="app")]` and headless-testable. `app/` is the desktop shell.

---

## Task 0: `app` feature + encrypted `PersonaStore`

**Files:** Modify `org-node/Cargo.toml`, `org-node/src/lib.rs`; Create `org-node/src/store.rs`.

- [ ] **Step 1: Add the `app` feature + persistence deps**

```toml
[features]
# Full node-app integration: chain + transport + encrypted persistence.
app = ["chain", "transport", "dep:chacha20poly1305", "dep:argon2", "dep:rand_core"]

[dependencies]
chacha20poly1305 = { version = "0.10", optional = true }
argon2 = { version = "0.5", optional = true }
# rand_core already present (Phase 2.1); ensure it's available under `app`.
```

> `app` turns on both `chain` and `transport`, so the shell gets everything. `serde`/`postcard` are already deps.

- [ ] **Step 2: Write the failing store test + implementation**

`org-node/src/store.rs` — a `PersonaStore` serialised (postcard) and encrypted at rest with XChaCha20-Poly1305 under an Argon2-derived key from a passphrase. Persona/Org records mirror spec §4.2–4.3.

```rust
//! Encrypted-at-rest persistence for personas and org records (spec §4.2–4.5).
//! PoC simplification S9: passphrase-derived key, not OS keychain.
#![cfg(feature = "app")]
use std::path::PathBuf;

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};

use crate::ids::OrgId;
use crate::OrgNodeError;

/// A locally-held identity, one per org (spec §4.2). Keys stored as 32-byte seeds.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersonaRecord {
    pub persona_id: String,           // local uuid-like id (caller-supplied)
    pub org_id: Option<OrgId>,        // None while a brand-new persona is unattached
    pub handle: String,
    pub name: String,
    pub surname: String,
    pub member_seed: [u8; 32],        // ed25519 member keypair seed
    pub device_seed: [u8; 32],        // ed25519 device keypair seed (= iroh identity)
    pub member_id: Option<[u8; 32]>,  // minted by admin on add; None while proposed
    pub status: PersonaStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PersonaStatus { Proposed, Active, Revoked }

/// A member's local view of an org (spec §4.3).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrgRecord {
    pub org_id: OrgId,
    pub root_hash: [u8; 32],
    pub org_pub_key: [u8; 32],
    pub epoch: u64,
    pub org_secret: Option<[u8; 32]>, // received over iroh on admission (S4: stored, unused)
    pub last_seq: u64,                // SeqGuard high-water mark
    pub admin_member_key: [u8; 32],   // admin's member pubkey (to authenticate deltas)
    pub trie_members: Vec<MemberSnapshot>, // enough to rebuild the local trie mirror
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberSnapshot {
    pub id: [u8; 32],
    pub handle: String,
    pub name: String,
    pub surname: String,
    pub member_key: [u8; 32],
    pub device_keys: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StoreData {
    pub personas: Vec<PersonaRecord>,
    pub orgs: Vec<OrgRecord>,
}

/// Encrypted file store. The file is `nonce(24) ‖ ciphertext`.
pub struct PersonaStore {
    path: PathBuf,
    key: XChaCha20Poly1305,
    data: StoreData,
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], OrgNodeError> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|_| OrgNodeError::Chain("kdf failed".into()))?;
    Ok(key)
}

impl PersonaStore {
    /// Open or create a store at `path` using `passphrase`. The salt is a fixed
    /// per-store value persisted alongside (PoC: derive salt from the path bytes,
    /// or store a sidecar `.salt`). For the PoC use a fixed app salt constant.
    pub fn open(path: PathBuf, passphrase: &str) -> Result<Self, OrgNodeError> {
        const APP_SALT: &[u8] = b"ods-phase2-personastore-v1______"; // 32 bytes
        let key_bytes = derive_key(passphrase, APP_SALT)?;
        let key = XChaCha20Poly1305::new_from_slice(&key_bytes)
            .map_err(|_| OrgNodeError::Chain("bad key".into()))?;
        let data = if path.exists() {
            let blob = std::fs::read(&path).map_err(|e| OrgNodeError::Chain(e.to_string()))?;
            if blob.len() < 24 { return Err(OrgNodeError::Chain("store too short".into())); }
            let (nonce, ct) = blob.split_at(24);
            let pt = key.decrypt(XNonce::from_slice(nonce), ct)
                .map_err(|_| OrgNodeError::Chain("decrypt failed (wrong passphrase?)".into()))?;
            postcard::from_bytes(&pt).map_err(|_| OrgNodeError::Chain("store decode".into()))?
        } else {
            StoreData::default()
        };
        Ok(Self { path, key, data })
    }

    pub fn data(&self) -> &StoreData { &self.data }
    pub fn data_mut(&mut self) -> &mut StoreData { &mut self.data }

    /// Encrypt + write the store. Nonce derived from a counter+random; for the
    /// PoC generate 24 random bytes per save.
    pub fn save<R: rand_core::RngCore + rand_core::CryptoRng>(&self, rng: &mut R) -> Result<(), OrgNodeError> {
        let mut nonce = [0u8; 24];
        rng.fill_bytes(&mut nonce);
        let pt = postcard::to_allocvec(&self.data).map_err(|_| OrgNodeError::Chain("store encode".into()))?;
        let ct = self.key.encrypt(XNonce::from_slice(&nonce), pt.as_slice())
            .map_err(|_| OrgNodeError::Chain("encrypt failed".into()))?;
        let mut out = Vec::with_capacity(24 + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        std::fs::write(&self.path, out).map_err(|e| OrgNodeError::Chain(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn round_trips_encrypted_through_disk() {
        let dir = std::env::temp_dir().join(format!("ods-store-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("store.bin");
        let _ = std::fs::remove_file(&path);

        let mut s = PersonaStore::open(path.clone(), "hunter2").unwrap();
        s.data_mut().personas.push(PersonaRecord {
            persona_id: "p1".into(), org_id: None, handle: "alice".into(),
            name: "A".into(), surname: "U".into(), member_seed: [1u8;32], device_seed: [2u8;32],
            member_id: None, status: PersonaStatus::Proposed,
        });
        s.save(&mut OsRng).unwrap();

        // Reopen with the right passphrase.
        let s2 = PersonaStore::open(path.clone(), "hunter2").unwrap();
        assert_eq!(s2.data().personas.len(), 1);
        assert_eq!(s2.data().personas[0].handle, "alice");

        // Wrong passphrase fails to decrypt.
        assert!(PersonaStore::open(path.clone(), "wrong").is_err());

        let _ = std::fs::remove_file(&path);
    }
}
```

> Confirm exact `argon2` / `chacha20poly1305` 0.10 API names (`hash_password_into`, `XChaCha20Poly1305::new_from_slice`, `encrypt`/`decrypt` with `XNonce`) against docs.rs; adjust if the version differs. The `OrgNodeError::Chain(String)` variant is reused for store errors — acceptable for the PoC, or add a `Store(String)` variant.

- [ ] **Step 3: Wire + test**

`lib.rs`: `#[cfg(feature = "app")] pub mod store;`
Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-node --features app --lib store::`
Expected: `round_trips_encrypted_through_disk` PASS.

- [ ] **Step 4: Commit** — `feat(org-node): encrypted PersonaStore (app feature)`

---

## Task 1: Out-of-band blob types (`Invite`, `JoinRequest`)

**Files:** Create `org-node/src/blobs.rs`; modify `lib.rs`.

The copy/paste payloads from stories 1–2. Base64-of-postcard for easy copy/paste.

- [ ] **Step 1: Implement + test**

```rust
//! Out-of-band exchange blobs (spec story 2). Base64(postcard(..)) for copy/paste.
#![cfg(feature = "app")]
use serde::{Deserialize, Serialize};
use crate::ids::OrgId;
use crate::OrgNodeError;

/// A → B: enough for B to read the org slot and to dial/authenticate A.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invite {
    pub org_id: OrgId,
    pub org_pub_key: [u8; 32],
    pub admin_member_key: [u8; 32],
    pub admin_device_key: [u8; 32],   // A's iroh NodeId
    pub admin_node_addr: Vec<u8>,     // postcard(iroh EndpointAddr) for dialing A (or A dials B)
}

/// B → A: B's proposed persona, so A can mint a member_id and add B.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinRequest {
    pub handle: String,
    pub name: String,
    pub surname: String,
    pub member_key: [u8; 32],
    pub device_key: [u8; 32],         // B's iroh NodeId
    pub node_addr: Vec<u8>,           // postcard(iroh EndpointAddr) for dialing B
}

pub fn encode<T: Serialize>(v: &T) -> Result<String, OrgNodeError> {
    let bytes = postcard::to_allocvec(v).map_err(|_| OrgNodeError::Chain("blob encode".into()))?;
    Ok(base64_encode(&bytes))
}
pub fn decode<T: for<'de> Deserialize<'de>>(s: &str) -> Result<T, OrgNodeError> {
    let bytes = base64_decode(s).ok_or_else(|| OrgNodeError::Chain("blob base64".into()))?;
    postcard::from_bytes(&bytes).map_err(|_| OrgNodeError::Chain("blob decode".into()))
}

// Use a base64 crate (add `base64 = "0.22"` to the app feature deps), or a tiny
// inline encoder. Prefer the crate. Replace base64_encode/decode with
// base64::engine::general_purpose::STANDARD.encode/.decode.
```

> Add `base64 = { version = "0.22", optional = true }` to deps and to the `app` feature. Replace the placeholder `base64_encode/decode` with the real `base64` engine calls. Write a `invite_round_trips`/`join_request_round_trips` test (encode→decode equality).

- [ ] **Step 2: Wire + test + Commit**

`lib.rs`: `#[cfg(feature="app")] pub mod blobs;`
Run: `CARGO_HOME=/tmp/cargo_home_fuzz cargo test -p org-node --features app --lib blobs::` → round-trip tests pass.
Commit: `feat(org-node): out-of-band Invite/JoinRequest blobs`

---

## Task 2: `OrgService` — compose the five stories

**Files:** Create `org-node/src/service.rs`; modify `lib.rs`.

`OrgService` owns the store, a chain handle (subxt client + contract H160 + a `BlockSink`), and the device `OrgEndpoint`. It exposes async story operations. This is the integration crux and the main headless-tested surface.

- [ ] **Step 1: Define `OrgService` skeleton + `create_persona` (no chain/net)**

```rust
//! OrgService: composes store + chain + transport into the five user stories.
#![cfg(feature = "app")]
// imports: store, blobs, keys, ids, chain, chain_write, ceremony, transport, verify, org-members trie
// ... (the implementer assembles from the existing modules) ...

pub struct OrgService {
    store: crate::store::PersonaStore,
    // chain: subxt OnlineClient + contract H160 + BlockSink (boxed) — set when online
    // endpoint: Option<OrgEndpoint> — bound on demand for the active device
    // ...
}

impl OrgService {
    pub fn new(store: crate::store::PersonaStore) -> Self { /* ... */ }

    /// Story precursor: create a local persona (keys generated, status Proposed).
    pub fn create_persona<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self, rng: &mut R, handle: &str, name: &str, surname: &str,
    ) -> Result<String, OrgNodeError> {
        // generate member+device SigningKeypair, store PersonaRecord, save.
    }
}
```

- [ ] **Step 2: Test `create_persona` against a temp store** (headless). Assert it persists and reloads.

- [ ] **Step 3: Implement the chain-backed stories** — `create_organisation` (genesis_ceremony → OrgRecord), `admit_member` (trie add → submit update → push envelope over iroh), `receive_and_verify` (recv_one → verify_envelope_against_chain → commit/update store), `revoke_member` (trie remove → update → notify → self-delete on the B side). Each method composes existing 2.1–2.3 functions. Use a `ChainHandle` abstraction so tests inject a `MockChain` + a no-op/instant `BlockSink`, and production injects the subxt client + chopsticks/Paseo `BlockSink`.

> Because `genesis_ceremony`/`submit_update` need a real subxt client, structure `OrgService` so the **trie + envelope + verify** logic is exercised with `MockChain` in tests, while the **on-chain submission** is behind the injected handle (a trait) that tests stub. The integration test (Task below) drives create→admit→receive→verify with MockChain + two loopback endpoints — proving the composition without a live chain. The real-chain path is already proven by 2.2's e2e.

- [ ] **Step 4: Integration test** `org-node/tests/service_stories.rs` (gated `app`): two `OrgService`s (A with a temp store, B with another), loopback iroh, MockChain shared view. Run stories 1→4 (A creates org [stubbed chain submit that updates the MockChain], B joins via blobs, A admits + pushes over iroh, B receives + verifies + persists Active), then story 5 (A revokes, B self-deletes). Assert B's store transitions Proposed→Active→removed and the verified roots match.

- [ ] **Step 5: clippy `--lib --features app` clean; Commit** per sub-step.

---

## Task 3: Scaffold the Tauri 2 + SvelteKit app

**Files:** Create the `app/` tree (package.json, svelte.config.js, vite.config.ts, src/routes/+layout.ts/+layout.svelte/+page.svelte, src-tauri/{Cargo.toml,tauri.conf.json,build.rs,src/main.rs}).

- [ ] **Step 1: SvelteKit + adapter-static project** in `app/`:
  - `package.json` with `@sveltejs/kit`, `@sveltejs/adapter-static`, `vite`, `svelte`, `@tauri-apps/api@^2`, `@tauri-apps/cli@^2`, scripts `dev` (vite, port 5173), `build` (vite build).
  - `svelte.config.js`: `adapter({ fallback: 'index.html' })`.
  - `src/routes/+layout.ts`: `export const ssr = false; export const prerender = true;`
  - A trivial `+page.svelte` ("ODS PoC") so the build produces output.

- [ ] **Step 2: `src-tauri`** depending on `org-node` with `features=["app"]`:
  - `tauri.conf.json`: `build.beforeDevCommand="npm run dev"`, `build.devUrl="http://localhost:5173"`, `build.beforeBuildCommand="npm run build"`, `build.frontendDist="../build"`; app identifier `io.parity.ods.poc`; a single window.
  - `src/main.rs`: minimal `tauri::Builder::default().run(...)` (commands added in Task 4).

- [ ] **Step 3: Verify** (CI-checkable gates):
  - `cd app && npm install && npm run build` → produces `app/build/` static output.
  - `CARGO_HOME=/tmp/cargo_home_fuzz cargo build` in `app/src-tauri` (compiles the Tauri app + org-node[app]).
  > Do NOT attempt to launch the GUI headlessly. If `cargo tauri build`/bundling needs system webview libs absent here, building the lib (`cargo build`) is sufficient for this gate; note GUI launch is manual.

- [ ] **Step 4: Commit** — `feat(app): scaffold Tauri 2 + SvelteKit static shell`

---

## Task 4: `AppState` + Tauri commands + events

**Files:** Create `app/src-tauri/src/{state.rs,commands.rs}`; modify `main.rs`.

- [ ] **Step 1: `AppState`** — `struct AppState { service: tokio::sync::Mutex<OrgService> }`, plus the app-data dir + endpoint. `manage()` it. Open the `PersonaStore` from the Tauri app-data dir (`app_handle.path().app_data_dir()`), passphrase from an env var or a fixed dev passphrase for the PoC (note S9).

- [ ] **Step 2: Commands** (async, `Result<T, String>`), one per story + queries, each locking the service and calling the matching `OrgService` method:
  `create_persona`, `create_organisation`, `export_invite`, `import_invite`, `export_join_request`, `import_join_request`, `admit_member`, `start_receiver` (spawns a task that loops `recv_one`+verify and `emit`s events), `revoke_member`, `list_personas`, `list_orgs`, `connection_status`. Register via `generate_handler!`.

- [ ] **Step 3: Events** — backend → UI: `emit("epoch-changed", ...)`, `emit("incoming-verified", ...)`, `emit("membership-updated", ...)`, `emit("revoked", ...)`. The receiver task and chain subscription drive these.

- [ ] **Step 4: Headless command tests where feasible** — the command handlers that don't need the chain/GUI (`create_persona`, `export/import_*`, `list_*`) can be tested by constructing an `OrgService` directly (Task 2 covers most of this at the service layer; add a thin `#[cfg(test)]` check that a command wrapper maps errors to `String`). Verify `cargo build` of the Tauri app.

- [ ] **Step 5: Commit** — `feat(app): AppState + Tauri commands/events over OrgService`

---

## Task 5: SvelteKit UI — the five-story screens

**Files:** Create `app/src/lib/api.ts` + `app/src/lib/components/*` + flesh out `+page.svelte`.

Utilitarian (spec §5): renders state, collects input, surfaces the verify-against-chain result explicitly.

- [ ] **Step 1: `api.ts`** — typed wrappers: `invoke` calls for every command (Task 4) + `listen` subscriptions for every event, with TS types mirroring the Rust return shapes.

- [ ] **Step 2: Components** (one responsibility each):
  - `PersonaList.svelte` — personas grouped by org, status badges.
  - `CreateOrg.svelte` — persona form → genesis progress (story 1).
  - `Invite.svelte` — show/copy invite blob (A); import invite + fill proposed persona + copy join-request (B) (story 2).
  - `Admit.svelte` — import join-request, review, "Admit" → trie update + chain write + iroh push (story 3).
  - `Membership.svelte` — live chain status (epoch, verified-root ✓/✗), the commit moment (story 4).
  - `Revoke.svelte` — member list → "Revoke"; B sees "removed & self-deleted" (story 5).
  - `StatusBar.svelte` — chain endpoint (chopsticks/Paseo), epoch, iroh node/connection state.
- [ ] **Step 3: Wire into `+page.svelte`**; the verify-against-chain result must be visible (it's the PoC's point).

- [ ] **Step 4: Verify** — `cd app && npm run build` succeeds (static output). `npm run check` (svelte-check) clean if configured. GUI behaviour is **manual** (user).

- [ ] **Step 5: Commit** — `feat(app): SvelteKit five-story UI`

---

## Task 6: Two-instance demo runbook + README

**Files:** Create `docs/superpowers/demo/two-instance-demo.md`; `app/README.md`.

- [ ] **Step 1: Demo runbook** — exact steps to run the demo on one machine:
  - Start a chopsticks fork (reuse `on-chain/scripts`), deploy OrgRegistry, note the H160 + endpoint.
  - Launch two app instances with **separate app-data dirs** (e.g. `ODS_DATA_DIR=/tmp/ods-A` and `/tmp/ods-B`, or two OS users) so they have distinct persona stores + iroh nodes.
  - Walk stories 1→5: A creates org; A→B invite (copy/paste); B creates persona, B→A join-request; A admits (chain update + iroh push); B verifies (epoch bump, root match) → Active; A revokes → B self-deletes.
  - Point at live Paseo via the endpoint config (opt-in).
- [ ] **Step 2: `app/README.md`** — dev (`npm run tauri dev`) and the demo pointer; the S-list simplifications; how the env var selects the data dir + chain endpoint.
- [ ] **Step 3: Commit** — `docs(app): two-instance demo runbook + README`

---

## Task 7: Green sweep + clippy

- [ ] Core (no feature) 21 tests; `--features app --lib` (store/blobs/service unit tests) green; `service_stories` integration test green (headless, MockChain + loopback iroh).
- [ ] `cargo clippy -p org-node --lib --features app -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic` clean.
- [ ] `cd app && npm run build` green; `cargo build` (app/src-tauri) compiles.
- [ ] Commit any fixes.

---

## Self-review notes (author check — applied)

- **Spec coverage:** §4.2–4.5 persona/org model + encrypted store → Tasks 0–1; §6 stories 1–5 → Task 2 (`OrgService`) + Task 5 (UI); §3.1 thin-shell topology → Tasks 3–4; §8 error handling → command `Result<_, String>` + typed `OrgNodeError`.
- **Headless-testable bulk:** store, blobs, and the full story composition (`OrgService`) are tested without a GUI or live chain (MockChain + temp store + loopback iroh). The real-chain path is already proven (2.2 e2e); the GUI + chopsticks demo is the user's manual verification — stated per task.
- **No core regression:** all new code is `#[cfg(feature="app")]` (which implies chain+transport); the 2.1 core stays light.
- **Version-sensitive bits flagged:** argon2/chacha20poly1305 0.10 API, base64 0.22, Tauri 2.x command/state/event API, SvelteKit adapter-static — confirm exact signatures against docs while implementing.
- **Build constraint:** `CARGO_HOME=/tmp/cargo_home_fuzz` for all cargo; `app/` uses npm (node available via volta).
- **Simplifications:** S1 (1-of-2 multisig), S9 (passphrase store), S10 (manual blobs), S11 (chopsticks) — all carried and noted.

## After this plan
Phase 2 is feature-complete: `org-node` (core + chain + transport + app) plus a runnable Tauri/SvelteKit two-instance demo. Next is integration/hardening and the `finishing-a-development-branch` decision (merge/PR) — to be done with the user once they've run the demo.
