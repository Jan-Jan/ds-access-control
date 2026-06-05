# Pinned Paseo chainspecs (smoldot light-client)

Source: paseo-network/paseo-chain-specs (CDN: https://paseo-r2.zondax.ch/chain-specs/).
- `paseo.raw.json`         <- paseo.raw.smol.json  (relay; lightSyncState + stateRootHash, 14 bootNodes)
- `asset-hub-paseo.raw.json` <- paseo-asset-hub.smol.json (para_id 1000; genesis.stateRootHash, 17 bootNodes)

Retrieved 2026-06-05. These are the light-client-friendly (`.smol`) variants: smoldot warp-syncs
from `lightSyncState`/`stateRootHash` rather than a full `genesis.raw` (the full raw AH spec is ~287 MB,
too large to vendor). For a parachain, `genesis.stateRootHash` is the smoldot-accepted raw form — not the
non-raw `genesis.runtime` patch smoldot rejects.
