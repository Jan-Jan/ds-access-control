//! The `MemberKeyResolver` trait — the spike's contract with the trie.
//!
//! Both spikes resolve every `Principal` through this trait. The library's
//! internal `Principal -> Key` cache (if any) must be a derived view of
//! this trait, never authoritative. See the design's Flow B.

use alloc::vec::Vec;

use crate::identity::{Epoch, MemberId, OrgKey, P2pDeviceKey, P2pMemberKey};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ResolverError {
    #[error("member not in trie: {0:?}")]
    UnknownMember(MemberId),

    #[error("org key not set")]
    OrgKeyUnset,
}

pub trait MemberKeyResolver {
    /// Current member-as-a-group key for `id`, or an error if the member
    /// is not in the trie / is isolated.
    fn p2p_member_key(&self, id: &MemberId) -> Result<P2pMemberKey, ResolverError>;

    /// Current organisation-as-a-pseudo-group key.
    fn org_key(&self) -> Result<OrgKey, ResolverError>;

    /// Currently-authorised devices for `id`. Returns `Ok(vec![])` if the
    /// member exists but is isolated (zero devices is not an error).
    /// Returns `Err(ResolverError::UnknownMember)` if `id` is not in the trie.
    fn current_devices(&self, id: &MemberId) -> Result<Vec<P2pDeviceKey>, ResolverError>;

    /// IDs of all current members of the organisation. Used by Flow E2/F2
    /// (org-as-pseudo-group p2p auth) to fan out across the org.
    fn org_member_ids(&self) -> Vec<MemberId>;

    fn is_member(&self, id: &MemberId) -> bool;

    fn epoch(&self) -> Epoch;
}
