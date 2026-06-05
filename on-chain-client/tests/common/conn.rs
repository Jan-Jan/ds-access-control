//! Build subxt `OnlineClient`s for tests. Always over an explicit
//! `LegacyBackend`: chopsticks fully implements the legacy RPC group
//! (it targets polkadot.js) but only part of the v2 groups — e.g.
//! `transactionWatch_v1_submitAndWatch` is missing — which silently
//! breaks subxt's default `CombinedBackend` (stream_best_blocks yields
//! zero items). Never use `OnlineClient::from_url` against chopsticks.

use std::sync::Arc;

use subxt::OnlineClient;
use subxt::backend::LegacyBackend;
use subxt::config::PolkadotConfig;

pub async fn legacy_client(
    ws_url: &str,
) -> Result<OnlineClient<PolkadotConfig>, Box<dyn std::error::Error>> {
    let rpc_client = subxt::rpcs::RpcClient::from_insecure_url(ws_url).await?;
    let backend: LegacyBackend<PolkadotConfig> = LegacyBackend::builder().build(rpc_client);
    let api = OnlineClient::from_backend(Arc::new(backend)).await?;
    Ok(api)
}
