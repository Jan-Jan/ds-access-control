use std::sync::Arc;

use crate::error::OrgMembersError;
use crate::hasher::TrieHasher;
use crate::node::Node;
use crate::smt::DefaultHashes;
use crate::trie::OrgTrie;
use crate::types::{Handle, MemberLeaf, RootHash};

/// A set of changes anchored to a specific base trie root.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Delta {
    pub(crate) base_root: RootHash,
    pub(crate) removed: Vec<Handle>,
    pub(crate) upserted: Vec<MemberLeaf>,
}

impl Delta {
    pub fn base_root(&self) -> &RootHash {
        &self.base_root
    }

    pub fn removed(&self) -> &[Handle] {
        &self.removed
    }

    pub fn upserted(&self) -> &[MemberLeaf] {
        &self.upserted
    }

    pub fn is_empty(&self) -> bool {
        self.removed.is_empty() && self.upserted.is_empty()
    }
}

/// Result of `apply_delta()`. Cannot query members -- can only verify or drop.
///
/// This compile-time guarantee prevents using unverified trie state.
pub struct CandidateTrie<H: TrieHasher> {
    pub(crate) root: Arc<Node>,
    pub(crate) defaults: Arc<DefaultHashes>,
    pub(crate) member_count: usize,
    pub(crate) root_hash: RootHash,
    pub(crate) last_calculated_root: Option<Arc<Node>>,
    pub(crate) _hasher: core::marker::PhantomData<H>,
}

impl<H: TrieHasher> CandidateTrie<H> {
    /// The root hash of the candidate trie (for logging/comparison before verifying).
    pub fn root_hash(&self) -> RootHash {
        self.root_hash
    }

    /// Verifies root hash matches expected value (e.g., from on-chain).
    /// On success, consumes self and returns verified OrgTrie.
    /// On failure, consumes self and returns error.
    pub fn verify_against(self, expected_root: &RootHash) -> Result<OrgTrie<H>, OrgMembersError> {
        if self.root_hash != *expected_root {
            return Err(OrgMembersError::VerificationFailed);
        }

        Ok(OrgTrie::from_candidate(
            self.root,
            self.defaults,
            self.member_count,
            self.root_hash,
            self.last_calculated_root,
        ))
    }
}

impl<H: TrieHasher> std::fmt::Debug for CandidateTrie<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CandidateTrie")
            .field("root_hash", &self.root_hash)
            .field("member_count", &self.member_count)
            .finish()
    }
}
