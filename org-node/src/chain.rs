//! The chain seen as a read-only oracle. Phase 2.1 uses MockChain; a later
//! phase implements ChainReader over on-chain-client. OrgState mirrors the
//! OrgRegistry slot: (rootHash, orgPubKey, epoch). See spec §4.4.
use std::collections::HashMap;

use org_members::RootHash;

use crate::ids::OrgId;

/// The on-chain state of one org, as stored in the OrgRegistry slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrgState {
    pub root_hash: RootHash,
    pub org_pub_key: [u8; 32],
    pub epoch: u64,
}

/// Read-only access to on-chain org state. The trusted-root oracle: the root
/// returned here MUST come from a path the delta sender does not control.
pub trait ChainReader {
    /// Returns the current OrgState for `org_id`, or None if the slot is empty.
    fn get_org_state(&self, org_id: &OrgId) -> Result<Option<OrgState>, String>;
}

/// In-memory ChainReader for tests. `set` simulates an admin's update().
#[derive(Default, Clone)]
pub struct MockChain {
    slots: HashMap<OrgId, OrgState>,
}

impl MockChain {
    pub fn new() -> Self {
        Self::default()
    }

    /// Simulate an on-chain update() landing for `org_id`.
    pub fn set(&mut self, org_id: OrgId, state: OrgState) {
        self.slots.insert(org_id, state);
    }
}

impl ChainReader for MockChain {
    fn get_org_state(&self, org_id: &OrgId) -> Result<Option<OrgState>, String> {
        Ok(self.slots.get(org_id).copied())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_chain_returns_set_state() {
        let mut chain = MockChain::new();
        let org = OrgId::new([1u8; 20]);
        assert_eq!(chain.get_org_state(&org).unwrap(), None);

        let state = OrgState { root_hash: RootHash::from_bytes([9u8; 32]), org_pub_key: [3u8; 32], epoch: 1 };
        chain.set(org, state);
        assert_eq!(chain.get_org_state(&org).unwrap(), Some(state));
    }
}
