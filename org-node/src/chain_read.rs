//! Adapts on-chain-client's OrgRegistryClient to org-node's synchronous
//! ChainReader. Async fetch refreshes a cached snapshot; the sync trait method
//! returns that snapshot so verify-against-chain stays synchronous.
#![cfg(feature = "chain")]
use std::sync::Mutex;

use on_chain_client::{OrgAdmin, OrgRegistryClient};
use org_members::RootHash;

use crate::chain::{ChainReader, OrgState};
use crate::ids::OrgId;

/// Maps on-chain-client's typed OrgState to org-node's OrgState.
fn map_state(s: on_chain_client::OrgState) -> OrgState {
    OrgState {
        root_hash: RootHash::from_bytes(s.root_hash.0),
        org_pub_key: s.org_pub_key.0,
        epoch: s.epoch.0,
    }
}

/// A ChainReader backed by a live OrgRegistryClient, with a cached snapshot.
pub struct OnChainReader {
    client: OrgRegistryClient,
    org_id: OrgId,
    cached: Mutex<Option<OrgState>>,
}

impl OnChainReader {
    pub fn new(client: OrgRegistryClient, org_id: OrgId) -> Self {
        Self { client, org_id, cached: Mutex::new(None) }
    }

    /// Fetch the latest (current best) state for `org_id` and cache it. Call
    /// before invoking verify-against-chain.
    pub async fn refresh(&self) -> Result<(), String> {
        let admin = OrgAdmin(*self.org_id.as_bytes());
        let state = self
            .client
            .get_org_state(admin, None)
            .await
            .map_err(|e| format!("{e:?}"))?
            .map(map_state);
        // Lock poisoning is unreachable here (no panics while held); map it to a string.
        *self.cached.lock().map_err(|_| "cache lock poisoned".to_string())? = state;
        Ok(())
    }
}

impl ChainReader for OnChainReader {
    /// Returns `Ok(None)` both when the org slot is genuinely empty on-chain
    /// AND when `refresh()` has not yet been called (initial state). This fails
    /// closed — callers MUST call `refresh().await` before relying on this.
    fn get_org_state(&self, requested: &OrgId) -> Result<Option<OrgState>, String> {
        if requested != &self.org_id {
            return Ok(None); // this reader is pinned to one org
        }
        Ok(*self.cached.lock().map_err(|_| "cache lock poisoned".to_string())?)
    }
}
