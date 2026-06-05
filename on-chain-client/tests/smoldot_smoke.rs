//! Live-Paseo smoke test for the subxt light-client path (the Phase 1.c
//! PWA transport). `#[ignore]` because it needs the public internet and
//! live-Paseo peers can be slow to sync from; run explicitly:
//!
//! ```bash
//! cargo test --no-default-features --features smoldot --test smoldot_smoke -- --ignored --nocapture
//! ```
//!
//! Gate (per amendment §4.3): runtime_version matches the pinned decoder
//! AND one finalized-block notification arrives.

#![cfg(feature = "smoldot")]

use std::time::Duration;

use subxt::OnlineClient;
use subxt::config::PolkadotConfig;
use subxt::lightclient::LightClient;

// The committed light-client-friendly (`.smol`) Paseo specs. The relay
// carries a `lightSyncState` warp-sync checkpoint; the Asset Hub spec is a
// parachain spec (`relay_chain: paseo`, `para_id: 1000`) whose genesis is a
// `stateRootHash` checkpoint — the smoldot-accepted raw form for a
// parachain. See `chainspecs/README.md` for provenance.
const PASEO_RELAY_SPEC: &str = include_str!("../chainspecs/paseo.raw.json");
const PASEO_AH_SPEC: &str = include_str!("../chainspecs/asset-hub-paseo.raw.json");

#[tokio::test]
#[ignore = "needs live Paseo connectivity; run with -- --ignored"]
async fn light_client_reads_live_paseo_ah() {
    // Instantiate the embedded smoldot light client with the Paseo relay
    // chain, then connect it to Asset Hub. `relay_chain` returns the relay
    // RPC (unused here — we only read AH); `parachain` gives us the AH RPC.
    let (relay, _relay_rpc) =
        LightClient::relay_chain(PASEO_RELAY_SPEC).expect("relay chain init");
    let ah_rpc = relay.parachain(PASEO_AH_SPEC).expect("parachain init");

    // The smoldot RPC client converts into a `subxt_rpcs::RpcClient`, so we
    // use the idiomatic 0.50 `from_rpc_client` ctor (matches subxt's shipped
    // `examples/light_client.rs`). It builds a CombinedBackend that probes
    // the node's RPC methods; smoldot exposes the chainHead_v1_* group, so
    // the chainHead backend wins the probe and the legacy half is never
    // invoked. (Don't copy this ctor for chopsticks — its PARTIAL v2
    // support breaks the combined probe; tests use an explicit
    // LegacyBackend instead.)
    let api = OnlineClient::<PolkadotConfig>::from_rpc_client(ah_rpc)
        .await
        .expect("client from light-client backend");

    let at = api.at_current_block().await.expect("at_current_block");
    let spec_version = at.spec_version();
    eprintln!("live Paseo AH spec_version = {spec_version}");
    assert!(
        on_chain_client::decode::dispatch::for_runtime(spec_version).is_ok(),
        "no decoder for live runtime {spec_version} — runtime upgraded; \
         add a decoder version (see decode/dispatch.rs)",
    );

    // One finalized block within 5 minutes (light client must sync first).
    let mut finalized = api.stream_blocks().await.expect("stream_blocks");
    let block = tokio::time::timeout(Duration::from_secs(300), finalized.next())
        .await
        .expect("no finalized block within 300s")
        .expect("stream ended")
        .expect("block error");
    eprintln!("finalized #{} {:?}", block.number(), block.hash());
}
