use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use hashbrown::HashMap;

use crate::error::OrgMembersError;
use crate::hasher::TrieHasher;
use crate::node::Node;
use crate::smt::DefaultHashes;
use crate::trie::OrgTrie;
use crate::types::{MemberId, MemberLeaf, RootHash};

/// A set of changes anchored to a specific base trie root.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Delta {
    pub(crate) base_root: RootHash,
    pub(crate) removed: Vec<MemberId>,
    pub(crate) upserted: Vec<MemberLeaf>,
}

impl Delta {
    pub fn base_root(&self) -> &RootHash {
        &self.base_root
    }

    /// Member ids that were removed.
    pub fn removed(&self) -> &[MemberId] {
        &self.removed
    }

    pub fn upserted(&self) -> &[MemberLeaf] {
        &self.upserted
    }

    pub fn is_empty(&self) -> bool {
        self.removed.is_empty() && self.upserted.is_empty()
    }

    /// Test-only mutator for the `removed` list. Used to construct adversarial
    /// deltas (e.g., stale or duplicate removals) for security testing.
    #[doc(hidden)]
    pub fn removed_mut_for_test(&mut self) -> &mut Vec<MemberId> {
        &mut self.removed
    }

    /// Test-only mutator for the `upserted` list.
    #[doc(hidden)]
    pub fn upserted_mut_for_test(&mut self) -> &mut Vec<MemberLeaf> {
        &mut self.upserted
    }
}

/// Result of `apply_delta()`. Cannot query members -- can only verify or drop.
pub struct CandidateTrie<H: TrieHasher> {
    pub(crate) root: Arc<Node>,
    pub(crate) defaults: Arc<DefaultHashes>,
    pub(crate) member_count: usize,
    pub(crate) root_hash: RootHash,
    pub(crate) skeleton_index: HashMap<String, String>,
    pub(crate) handle_index: HashMap<String, MemberId>,
    pub(crate) _hasher: core::marker::PhantomData<H>,
}

impl<H: TrieHasher> CandidateTrie<H> {
    pub fn root_hash(&self) -> RootHash {
        self.root_hash
    }

    pub fn verify_against(self, expected_root: &RootHash) -> Result<OrgTrie<H>, OrgMembersError> {
        if self.root_hash != *expected_root {
            return Err(OrgMembersError::VerificationFailed);
        }

        Ok(OrgTrie::from_candidate(
            self.root,
            self.defaults,
            self.member_count,
            self.root_hash,
            self.skeleton_index,
            self.handle_index,
        ))
    }
}

impl<H: TrieHasher> fmt::Debug for CandidateTrie<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CandidateTrie")
            .field("root_hash", &self.root_hash)
            .field("member_count", &self.member_count)
            .finish()
    }
}
