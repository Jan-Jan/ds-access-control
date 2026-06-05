# `on-chain/` — ODS Phase 1.b Stage 1

Solidity contract anchoring the off-chain organisation-members trie on Asset
Hub via `pallet-revive`. Multi-tenant: one contract instance serves every
organisation, keyed on the H160 of each org's proxied pure-proxy admin.

See `docs/superpowers/specs/2026-05-13-ods-phase-1b-design.md` for the design.

## Layout

- `src/OrgRegistry.sol` — the contract.
- `test/OrgRegistry.t.sol` — Foundry unit tests (covers §5.1 of the spec).
- `abi/OrgRegistry.json` — pinned ABI artifact for Stage 2 consumers.
- `scripts/chopsticks-sanity.sh` — deploys to a chopsticks-forked Paseo
  Asset Hub and verifies the code hash. Gate criterion for Stage 2.
- `scripts/chopsticks-config.yml` — chopsticks config pinning Paseo's
  endpoint.
- `scripts/sanity-deploy.mjs` — Node.js deploy + verify script using
  `@polkadot/api`.
- `scripts/wait-for-rpc.mjs` — WS readiness probe used by the sanity harness.
- `scripts/package.json` / `scripts/package-lock.json` — pinned npm
  dependencies for the sanity script (chopsticks, polkadot-api).

## Quickstart

```bash
# Unit tests (no chain required):
cd on-chain && forge test -vv

# Re-pin ABI after a contract change:
forge clean && forge build
jq '{abi: .abi, contractName: "OrgRegistry"}' \
   out/OrgRegistry.sol/OrgRegistry.json > abi/OrgRegistry.json

# Sanity-script deps (run once to materialise scripts/package-lock.json,
# then commit the lockfile so the gate is reproducible):
(cd scripts && npm install)

# Chopsticks sanity (requires resolc + solc + node + npm + jq for the
# ABI re-pin step):
./scripts/chopsticks-sanity.sh
```

## Stage 1 gate (must all pass before Stage 2 starts)

- `forge test` passes (15 tests; 14 unit + 1 fuzz).
- `on-chain/abi/OrgRegistry.json` exists and matches the latest build.
- `scripts/package-lock.json` is checked in and chopsticks resolves to the
  locked version (no `@latest` at runtime).
- `scripts/chopsticks-sanity.sh` exits 0.
- Commit tagged `v0.1.0-on-chain-stage1`.

## What Stage 2 adds (not in this directory)

A sibling `on-chain-client/` Rust crate that reads contract state and
subscribes to events via smoldot. Tracked in its own plan.
