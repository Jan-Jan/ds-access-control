//! Drive chopsticks's dev_* JSON-RPC extensions to manipulate the local
//! chain — needed by Scenario C (reorg cancels proposed update).
//!
//! Chopsticks exposes:
//!
//! - `dev_newBlock(params?)` — mine one new block (optionally including
//!   pending extrinsics). Returns the new block hash.
//! - `dev_setHead(block_hash)` — rewind the best-chain tip to a previous
//!   block. Subsequent `dev_newBlock` calls fork from there.
//!
//! `induce_reorg` chains these: rewind to a chosen ancestor, mine a new
//! block (different state from the original tip), and the watcher sees
//! the original tip become a pruned block.

use jsonrpsee::core::client::ClientT;
use jsonrpsee::rpc_params;
use jsonrpsee::ws_client::{WsClient, WsClientBuilder};
use serde_json::Value;

use super::chopsticks_fork::ChopsticksHandle;

/// Result of [`induce_reorg`]: the discarded best-block hash (the one the
/// watcher should see as `pruned`) and the new best-block hash after the
/// fork. Both are 0x-prefixed hex strings as returned by chopsticks.
#[derive(Debug, Clone)]
pub struct ReorgResult {
    pub discarded: String,
    pub new_best: String,
}

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

/// Mine a new best block via `dev_newBlock`. Returns its hash. Useful as
/// the "include the proposed update" step before inducing a reorg of
/// that block.
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

/// Reorg the chain: take `target` as the new tip's parent, mine a new
/// block on top of it. `target` is typically the parent of the block
/// you want to discard.
pub async fn induce_reorg(
    handle: &ChopsticksHandle,
    discard_block: &str,
    parent_of_discarded: &str,
) -> Result<ReorgResult, ReorgError> {
    let client = ws_client(handle).await?;
    let _: Value = client
        .request("dev_setHead", rpc_params![parent_of_discarded])
        .await
        .map_err(|e| ReorgError::Transport(e.to_string()))?;
    let new_best = mine_block(handle).await?;
    Ok(ReorgResult {
        discarded: discard_block.to_string(),
        new_best,
    })
}

async fn ws_client(handle: &ChopsticksHandle) -> Result<WsClient, ReorgError> {
    WsClientBuilder::default()
        .build(&handle.ws_url)
        .await
        .map_err(|e| ReorgError::Transport(e.to_string()))
}
