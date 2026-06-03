//! In-memory `MemberKeyResolver` implementation used by tests and
//! scenario drivers in both spikes. NOT a real Sparse Merkle Tree —
//! the actual trie lives in `org-members`; this is a fixture-only stub.

use alloc::vec::Vec;
use hashbrown::HashMap;

use crate::identity::{Epoch, MemberId, OrgKey, P2pDeviceKey, P2pMemberKey};
use crate::resolver::{MemberKeyResolver, ResolverError};

#[derive(Clone, Debug, Default)]
pub struct StubTrie {
    members: HashMap<MemberId, MemberEntry>,
    org: Option<OrgKey>,
    epoch: Epoch,
}

#[derive(Clone, Debug)]
struct MemberEntry {
    p2p_key: P2pMemberKey,
    devices: Vec<P2pDeviceKey>,
}

impl StubTrie {
    pub fn new() -> Self {
        Self::default()
    }

    fn bump(mut self) -> Self {
        self.epoch.0 += 1;
        self
    }

    pub fn add_member(
        mut self,
        id: MemberId,
        p2p_key: P2pMemberKey,
        devices: Vec<P2pDeviceKey>,
    ) -> Self {
        self.members.insert(id, MemberEntry { p2p_key, devices });
        self.bump()
    }

    pub fn with_org_key(mut self, key: OrgKey) -> Self {
        self.org = Some(key);
        self.bump()
    }

    // Scenario-driver mutators. These exist solely so test/scenario code
    // can simulate trie changes; production callers would use the real
    // org-members API.

    pub fn stub_revoke(mut self, id: &MemberId) -> Self {
        self.members.remove(id);
        self.bump()
    }

    pub fn stub_rotate_org_key(mut self, key: OrgKey) -> Self {
        self.org = Some(key);
        self.bump()
    }

    pub fn stub_rotate_member_key(mut self, id: &MemberId, key: P2pMemberKey) -> Self {
        if let Some(entry) = self.members.get_mut(id) {
            entry.p2p_key = key;
        }
        self.bump()
    }

    pub fn stub_remove_device(mut self, id: &MemberId, device: &P2pDeviceKey) -> Self {
        if let Some(entry) = self.members.get_mut(id) {
            entry.devices.retain(|d| d != device);
        }
        self.bump()
    }

    pub fn stub_add_device(mut self, id: &MemberId, device: P2pDeviceKey) -> Self {
        if let Some(entry) = self.members.get_mut(id) {
            entry.devices.push(device);
        }
        self.bump()
    }
}

impl MemberKeyResolver for StubTrie {
    fn p2p_member_key(&self, id: &MemberId) -> Result<P2pMemberKey, ResolverError> {
        self.members
            .get(id)
            .map(|e| e.p2p_key)
            .ok_or(ResolverError::UnknownMember(*id))
    }

    fn org_key(&self) -> Result<OrgKey, ResolverError> {
        self.org.ok_or(ResolverError::OrgKeyUnset)
    }

    fn current_devices(&self, id: &MemberId) -> Result<Vec<P2pDeviceKey>, ResolverError> {
        self.members
            .get(id)
            .map(|e| e.devices.clone())
            .ok_or(ResolverError::UnknownMember(*id))
    }

    fn org_member_ids(&self) -> Vec<MemberId> {
        self.members.keys().copied().collect()
    }

    fn is_member(&self, id: &MemberId) -> bool {
        self.members.contains_key(id)
    }

    fn epoch(&self) -> Epoch {
        self.epoch
    }
}
