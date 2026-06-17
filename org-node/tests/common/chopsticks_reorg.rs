// Duplicated from on-chain-client/tests/common/chopsticks_reorg.rs for the org-node e2e harness.
//! Drive chopsticks's dev_* JSON-RPC extensions to manipulate the local
//! chain — provides `mine_block` for advancing the chain during tests.

use jsonrpsee::core::client::ClientT;
use jsonrpsee::rpc_params;
use jsonrpsee::ws_client::{WsClient, WsClientBuilder};
use serde_json::Value;

use super::chopsticks_fork::ChopsticksHandle;

#[derive(Debug)]
pub enum ReorgError {
    Transport(String),
    UnexpectedResponse(String),
}

impl std::fmt::Display for ReorgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(m) => write!(f, "reorg transport error: {m}"),
            Self::UnexpectedResponse(m) => write!(f, "reorg unexpected response: {m}"),
        }
    }
}

impl std::error::Error for ReorgError {}

/// Mine a new best block via `dev_newBlock`. Returns its 0x-prefixed hex hash.
pub async fn mine_block(handle: &ChopsticksHandle) -> Result<String, ReorgError> {
    let client = ws_client(handle).await?;
    let resp: Value = client
        .request("dev_newBlock", rpc_params![])
        .await
        .map_err(|e| ReorgError::Transport(e.to_string()))?;
    // Chopsticks returns either a bare hash string or
    // `{ blockHash: ..., ... }` depending on version. Accept both.
    if let Some(s) = resp.as_str() {
        return Ok(s.to_string());
    }
    if let Some(s) = resp.get("blockHash").and_then(Value::as_str) {
        return Ok(s.to_string());
    }
    Err(ReorgError::UnexpectedResponse(format!(
        "dev_newBlock: {resp}"
    )))
}

async fn ws_client(handle: &ChopsticksHandle) -> Result<WsClient, ReorgError> {
    WsClientBuilder::default()
        .build(&handle.ws_url)
        .await
        .map_err(|e| ReorgError::Transport(e.to_string()))
}
