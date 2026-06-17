# ODS PoC — desktop app (Tauri 2 + SvelteKit)

A thin desktop shell over the headless [`org-node`](../org-node/) library. The UI
renders state and collects input; **all keys, trust decisions, chain I/O, and
p2p transport live in `org-node`** (feature `app` = core + chain + transport +
encrypted store + `OrgService`), reached over Tauri commands/events.

This is the Phase 2 proof-of-concept demonstrator for the five membership user
stories (create org, join, admit, verify, revoke). It is a **Tauri desktop app**,
a deliberate deviation from the spec's "PWA" wording (see spec §2 / S8) chosen so
the real Rust `on-chain-client` and `iroh` run natively.

## Layout

```
app/
  src/                # SvelteKit (adapter-static SPA, Svelte 5)
    lib/api.ts        # typed invoke()/listen() wrappers for the Tauri surface
    lib/components/   # PersonaList, CreateOrg, Invite, Admit, Membership, Revoke, StatusBar
    routes/+page.svelte
  src-tauri/          # Tauri 2 app (self-contained cargo workspace)
    src/state.rs      # AppState: OrgService + env-var config
    src/commands.rs   # 12 #[tauri::command]s + events over OrgService
```

## Develop

```bash
cd app
npm install
npm run tauri dev      # launches the desktop app (SvelteKit dev server on :5173)
# build checks:
npm run build          # static frontend → app/build/
npm run check          # svelte-check
( cd src-tauri && CARGO_HOME=/tmp/cargo_home_fuzz cargo build )   # compile the Tauri app
```

## Configuration (environment variables)

| Var | Meaning | Default |
|-----|---------|---------|
| `ODS_DATA_DIR` | Persona/org store directory (use distinct dirs per instance) | Tauri `app_data_dir` |
| `ODS_PASSPHRASE` | Passphrase for the encrypted store (S9) | `ods-dev-default` |
| `ODS_CHAIN_WS` | Chain WS endpoint (e.g. `ws://localhost:8000`) | unset → chain not configured |
| `ODS_CONTRACT_H160` | Deployed `OrgRegistry` address (40 hex chars) | — |
| `ODS_ADMIN_SEED` | Admin signer seed (64 hex / 32 bytes; must be a funded account for writes) | — |
| `ODS_COSIGNER_PUB` | Co-signer public key for the 1-of-2 multisig (64 hex) | none (1-of-1, which the runtime rejects — set it) |

If the chain vars are unset, the app runs but on-chain commands return
"chain not configured".

## Run the demo

See [`../docs/superpowers/demo/two-instance-demo.md`](../docs/superpowers/demo/two-instance-demo.md)
for the full two-instance, five-story runbook (including the chopsticks
Instant-block-mode requirement).
