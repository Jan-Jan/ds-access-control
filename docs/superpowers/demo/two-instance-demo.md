# ODS Phase 2 — Two-instance demo runbook

Drive the five user stories end-to-end across two running app instances on one
machine, against a local chopsticks fork of Paseo Asset Hub. This exercises the
real stack: `org-node` (members trie + signed-delta envelope + verify-against-chain),
the on-chain `OrgRegistry` (subxt writes, reads), and the iroh device-to-device
channel.

> **Status / honesty note.** The headless logic is fully tested
> (`org-node` unit + `service_stories` e2e + `transport_handshake`). The *running
> app* + *live chain* path below is **not** covered by automated tests — it is the
> manual demo. Known runtime-sensitive points are listed under
> [Known limitations](#known-limitations). The on-chain primitives themselves are
> proven by `on-chain-client`'s chopsticks e2e and `org-node`'s `service_stories`.

---

## 0. Prerequisites

- Node + npm (the repo uses volta) and the chopsticks deps under `on-chain/scripts`.
- Rust toolchain. In this environment, prefix cargo with `CARGO_HOME=/tmp/cargo_home_fuzz` (read-only `~/.cargo`).
- Build the app once:
  ```bash
  cd app && npm install
  cd app/src-tauri && CARGO_HOME=/tmp/cargo_home_fuzz cargo build
  ```
- The Tauri CLI is available via `app`'s devDependency (`@tauri-apps/cli`): run the app with `npm run tauri dev` from `app/`.

---

## 1. Start the chain (chopsticks, Instant block mode)

The app's `FinalitySink` submits an extrinsic and then reads the resulting state;
it does **not** mine blocks. So chopsticks must **auto-produce a block per
transaction**. Launch the fork in **Instant** build-block mode:

```bash
cd on-chain/scripts
# Fork Paseo AH using the repo's config (funds Alice, mock-signature-host: true),
# building a block as soon as a transaction arrives:
npx @acala-network/chopsticks@latest --config chopsticks-config.yml --build-block-mode Instant
# Listens on ws://localhost:8000
```

> `chopsticks-config.yml` pins the Paseo AH endpoint, funds **Alice**
> (`5GrwvaEF…`) with 1e18 planck, and sets `mock-signature-host: true` (the host
> accepts mocked signatures, so the admin signer just needs to *be* the funded
> Alice account). If `--build-block-mode Instant` isn't honoured by your
> chopsticks version, run a sidecar that calls `dev_newBlock` on a short interval
> instead.

Deploy `OrgRegistry` and capture its H160 (reuse the Stage-1 deploy mechanics):

```bash
# From on-chain/scripts — deploys OrgRegistry to the running fork and prints the
# deployed contract address (the DEPLOYED_H160 marker in sanity-deploy.mjs):
node sanity-deploy.mjs    # or: ./chopsticks-sanity.sh (spawns its own fork — see note)
```

Note the printed H160 (e.g. `0xabc…20bytes`). Call it `$CONTRACT_H160`.

---

## 2. Launch two instances (A = admin, B = joiner)

Each instance needs its **own data directory** (separate persona store + iroh
node) and the chain env vars. The well-known dev keys (32-byte seeds / pubkeys,
hex, no `0x` needed):

- **Alice** seed (admin, funded): `e5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a`
- **Bob** public key (co-signer for the 1-of-2 multisig): `8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48`

**Instance A (admin):**
```bash
cd app
ODS_DATA_DIR=/tmp/ods-A \
ODS_PASSPHRASE=demo-A \
ODS_CHAIN_WS=ws://localhost:8000 \
ODS_CONTRACT_H160=$CONTRACT_H160 \
ODS_ADMIN_SEED=e5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a \
ODS_COSIGNER_PUB=8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48 \
npm run tauri dev
```

**Instance B (joiner)** — in a second terminal. B only *reads* on-chain state
(`build_chain_ops` still requires `ODS_ADMIN_SEED` to be set, so provide Bob's
seed; it is unused for B's read-only path):
```bash
cd app
ODS_DATA_DIR=/tmp/ods-B \
ODS_PASSPHRASE=demo-B \
ODS_CHAIN_WS=ws://localhost:8000 \
ODS_CONTRACT_H160=$CONTRACT_H160 \
ODS_ADMIN_SEED=3a9d5b35b9fb4979b5ba87a5b89c3b1b6e3c2c5d9e8f0a1b2c3d4e5f60718293 \
npm run tauri dev
```
> (B's `ODS_ADMIN_SEED` is any 64-hex value — B never submits. The
> `StatusBar` will show the chain endpoint + epoch once connected.)

Each window opens its own ODS PoC dashboard.

---

## 3. Walk the five stories

**Story 1 — A creates the organisation** (window A, *Create Org*):
1. Fill the persona form (handle / name / surname) → this runs `create_persona`.
2. Click **Create Organisation** → runs the genesis ceremony (pure proxy `P`,
   `map_account`, genesis `update(epoch 0)`). On success the dashboard shows the
   new `org_id` (= `h160_of(P)`) and `StatusBar` shows epoch 1. A's persona → Active.

**Story 2 — B prepares to join** (out-of-band copy/paste):
1. Window A, *Invite*: **Export Invite** → copy the blob (org_id + A's member &
   device keys + A's dialable address).
2. Window B, *Invite*: paste the blob → **Import Invite**; fill B's persona form →
   **Export Join-Request** → copy that blob (B's keys + B's dialable address).
3. Paste B's join-request back into window A.

**Story 3 — A admits B** (window A, *Admit*):
1. Paste B's join-request → it previews the parsed handle/name/keys
   (`import_join_request`).
2. **Admit** → A adds B to the trie, submits `update(epoch 1→2)` on-chain, and
   pushes the signed delta + org secret to B over iroh (dialing B's address).

**Story 4 — B verifies & commits** (window B, *Membership*):
1. **Start Receiver** (if not already) → B's iroh endpoint accepts A's push.
2. B authenticates A's device key (must match the Invite), then verifies the
   delta against the **on-chain root at epoch 2** — the view shows the
   **verified-root match ✓** and B's persona flips to **Active**, with the org
   secret stored. (A ✗ would mean the delta didn't reproduce the on-chain root.)

**Story 5 — A revokes B** (window A, *Revoke*):
1. Provide B's `member_id` (hex) and B's peer address blob (from the Admit step),
   then **Revoke** → A removes B from the trie, submits `update(epoch 2→3)`, and
   notifies B over iroh.
2. Window B detects the change, verifies against the chain that B is gone, and
   **self-deletes** its org record + secret (persona → Revoked).

---

## Known limitations (PoC; see spec §7 register)

- **Chain must auto-produce blocks** — `FinalitySink` returns the current best
  block immediately after submit; it does not poll-until-included. Use Instant
  block mode (above). `TODO(demo-wiring)` in `service.rs` describes a
  poll-until-newer-block hardening for slower chains.
- **Revoke UI is manual** — you paste `member_id_hex` + the peer address blob; the
  backend doesn't expose a post-admit member list with addresses.
- **Single active persona/device per instance** — `ensure_endpoint` binds one iroh
  endpoint per running instance.
- **S9** passphrase-encrypted file store (not OS keychain); **S1** single-admin
  1-of-2 threshold multisig; **S11** chopsticks ephemeral fork.
- **Restart caveat** — the pure-proxy `P` is persisted in the org record, but doing
  genesis + admit + revoke within one session is the tested demo path.

## Pointing at live Paseo (optional)
Set `ODS_CHAIN_WS` to a live Paseo Asset Hub RPC and deploy `OrgRegistry` there
(`on-chain/README.md`). The admin account (`ODS_ADMIN_SEED`) must be funded on
that network. Live blocks are produced by the network, so no Instant mode is
needed — but the `FinalitySink` immediate-return assumption should be hardened
first (see above).

## See also
- Spec: [`../specs/2026-06-15-ods-phase-2-poc-design.md`](../specs/2026-06-15-ods-phase-2-poc-design.md)
- `org-node/README.md` (the headless library), `app/README.md` (the shell).
- `on-chain/README.md` (contract + chopsticks deploy).
