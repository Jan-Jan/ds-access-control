# ODS Phase 2 — two-laptop + live Paseo demo runbook

Run the five user stories across **two different laptops** on a real network,
anchored to **live Paseo Asset Hub** (not chopsticks). This exercises the full
production-shaped path: cross-NAT iroh transport (relay + discovery), real
finalised on-chain writes/reads, and the verify-against-chain gate.

> **Status.** The two enabling changes this requires are now implemented:
> - **Networked transport** — `OrgEndpoint` binds with `presets::N0` (n0 relay +
>   DNS/Pkarr discovery) in `TransportMode::Networked`; peers are dialled by
>   `EndpointId` (= device key) so connectivity works across NATs. Selected by the
>   app via `ODS_TRANSPORT` (default `Networked`; set `loopback` for same-machine).
> - **Finality polling** — `FinalitySink::settle` waits for a newer *finalised*
>   block (≤90 s) after each submit, so reads see the committed state on a live
>   chain.
>
> These paths are **compile-verified only** in CI (they need the internet); this
> runbook is their first real exercise. The offline tests
> (`service_stories`, `transport_handshake`) cover the logic on loopback.

---

## 0. Prerequisites (per laptop)

- Rust toolchain + Node/npm.
- Clone the repo; build the app once:
  ```bash
  cd app && npm install
  ( cd src-tauri && cargo build )     # compiles org-node[app] + Tauri (slow first time)
  ```
- Both laptops need outbound internet (for the n0 relay/discovery and the Paseo RPC). No port-forwarding is required — the relay brokers connectivity through NAT.

## 1. One-time chain setup (do once, from either laptop)

1. **Fund the admin account.** Laptop A's admin account pays for the genesis
   ceremony + updates. Get PAS for **Paseo Asset Hub** from the faucet
   (https://faucet.polkadot.io → Paseo → Asset Hub), sending to A's admin address.
   You'll provide that account's **32-byte seed** as `ODS_ADMIN_SEED` (64 hex).
2. **Deploy `OrgRegistry` to live Paseo AH.** Use the `pallet-revive`
   `instantiateWithCode` flow in `on-chain/` (see `on-chain/README.md`) against a
   live Paseo AH RPC (e.g. `wss://asset-hub-paseo-rpc.dwellir.com`), paying from a
   funded account. Record the deployed contract **H160** → `$CONTRACT`.
   - (B does not deploy and does not pay — B only reads the chain.)

## 2. Configure + launch each laptop

Environment variables (see `app/README.md` for the full table). Seeds/pubkeys are
64-hex (32 bytes). `ODS_TRANSPORT` defaults to `Networked`, so you don't need to
set it for the cross-laptop run.

**Laptop A (admin):**
```bash
cd app
ODS_DATA_DIR=~/.ods \
ODS_PASSPHRASE=<choose-A> \
ODS_CHAIN_WS=wss://asset-hub-paseo-rpc.dwellir.com \
ODS_CONTRACT_H160=$CONTRACT \
ODS_ADMIN_SEED=<A funded account: 64-hex seed> \
ODS_COSIGNER_PUB=<co-signer pubkey: 64-hex> \
npm run tauri dev
```

**Laptop B (joiner):**
```bash
cd app
ODS_DATA_DIR=~/.ods \
ODS_PASSPHRASE=<choose-B> \
ODS_CHAIN_WS=wss://asset-hub-paseo-rpc.dwellir.com \
ODS_CONTRACT_H160=$CONTRACT \
ODS_ADMIN_SEED=<any 64-hex; B never submits> \
npm run tauri dev
```

> `StatusBar` should show the chain endpoint + epoch once each app connects.
> Both apps reach the n0 relay automatically (Networked mode) — no extra config.

## 3. Walk the five stories

The out-of-band blobs (invite, join-request) are copied between the two laptops
over **any channel you like** — Signal, email, a shared note. That manual channel
*is* the "other app" from the spec. The iroh channel (carrying the signed delta +
org secret) is established automatically by NodeId once keys are exchanged.

1. **Laptop A — Create Org** (story 1): fill the persona form → *Create
   Organisation*. A runs the genesis ceremony on Paseo (pure proxy, `map_account`,
   `update` epoch 0) and **waits for finalisation** (tens of seconds). `StatusBar`
   shows epoch 1 and the `org_id`.
2. **A → B invite** (story 2): A *Export Invite* → send the blob to B. B *Import
   Invite*, fills B's persona, *Export Join-Request* → sends that blob back to A.
3. **Laptop A — Admit** (story 3): A pastes B's join-request, reviews the parsed
   fields, *Admit* → A adds B to the trie, submits `update` (epoch 2) on Paseo
   (waits for finality), then dials B **by NodeId over the relay** and pushes the
   signed delta + org secret.
4. **Laptop B — Membership** (story 4): B's receiver (Start Receiver) authenticates
   A's device key (must match the invite), reads Paseo at epoch 2, and shows the
   **verified-root ✓** → B becomes Active, org secret stored.
5. **Laptop A — Revoke** (story 5): provide B's `member_id` (hex) + B's peer-address
   blob (from the Admit step), *Revoke* → A removes B (epoch 3) and notifies B over
   the relay; B verifies against Paseo that it's gone and **self-deletes** its org
   record (persona → Revoked).

## 4. Troubleshooting / expectations

- **On-chain steps take tens of seconds** — each waits for Paseo GRANDPA finality.
  The UI will appear to pause; that's the finality poll (≤90 s).
- **First iroh dial may take a few seconds** while both endpoints register with the
  n0 relay and discovery propagates. Retry if a dial fails — n0's public relays are
  best-effort (a self-hosted relay is the production answer).
- **"chain not configured"** from a command means one of `ODS_CHAIN_WS` /
  `ODS_CONTRACT_H160` / `ODS_ADMIN_SEED` was missing or the connect failed; the
  `StatusBar` `chain_ready` flag reflects the *actual* connection, not just env-var
  presence.
- **Same-LAN-only quick test:** you can also run both on one LAN; keep
  `ODS_TRANSPORT` at its default (Networked) — loopback mode won't reach the other
  machine.

## 5. Known limitations (PoC; spec §7 register)

- **S1** single-admin 1-of-2 threshold multisig (set `ODS_COSIGNER_PUB`).
- **S9** passphrase-encrypted file store (not OS keychain).
- **S14** one device per member (revoke notifies the member's first device key).
- Revoke UI requires pasting `member_id_hex` + the peer address blob (no post-admit
  member-list-with-addresses surface).
- n0 public relay/discovery dependency (Networked mode); self-host for production.
- The on-chain proxy `P` is persisted in the org record, so genesis + later updates
  survive a restart, but doing the full flow in one session is the tested path.

## See also
- Same-machine (chopsticks) demo: [`two-instance-demo.md`](two-instance-demo.md).
- Spec: [`../specs/2026-06-15-ods-phase-2-poc-design.md`](../specs/2026-06-15-ods-phase-2-poc-design.md) (§7 simplifications register).
- `app/README.md` (env-var table), `org-node/README.md` (the headless library).
