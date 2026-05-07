use std::sync::Arc;

use crate::delta::{CandidateTrie, Delta};
use crate::error::OrgMembersError;
use crate::hasher::TrieHasher;
use crate::node::Node;
use crate::smt::{
    self, DefaultHashes,
};
use crate::types::{Handle, MemberLeaf, RootHash};

/// An immutable binary Sparse Merkle Tree for organisation membership.
///
/// Generic over the hash function `H`. Mutations (`upsert`, `delete`) return
/// a new trie via path-copying with lazy hash computation (`OnceLock`).
/// Call `recalculate()` to fill all pending hashes.
pub struct OrgTrie<H: TrieHasher> {
    root: Arc<Node>,
    defaults: Arc<DefaultHashes>,
    /// Cached member count (tracked across mutations).
    member_count: usize,
    /// Root hash from the last recalculate, if any.
    cached_root_hash: Option<RootHash>,
    /// Snapshot of the root at the time of last recalculate (for delta computation).
    last_calculated_root: Option<Arc<Node>>,
    _hasher: core::marker::PhantomData<H>,
}

impl<H: TrieHasher> OrgTrie<H> {
    /// Creates a genesis trie from initial members.
    /// Inserts each member then calls recalculate internally.
    pub fn genesis(members: Vec<MemberLeaf>) -> Result<Self, OrgMembersError> {
        let defaults = Arc::new(DefaultHashes::compute::<H>());
        let mut root = smt::empty_root(&defaults);
        let mut count = 0;

        for member in members {
            // Check for duplicate handles
            if smt::get_member(&root, member.handle()).is_some() {
                return Err(OrgMembersError::DuplicateHandle);
            }
            root = smt::insert::<H>(&root, member, &defaults);
            count += 1;
        }

        // Recalculate all hashes
        let root_hash = smt::recalculate_hashes::<H>(&root);

        Ok(Self {
            root: root.clone(),
            defaults,
            member_count: count,
            cached_root_hash: Some(RootHash(root_hash)),
            last_calculated_root: Some(root),
            _hasher: core::marker::PhantomData,
        })
    }

    /// Returns the root hash. Panics if `recalculate()` has not been called
    /// since the last mutation.
    pub fn root_hash(&self) -> RootHash {
        self.cached_root_hash
            .expect("root_hash() called before recalculate()")
    }

    /// Returns true if all hashes are populated.
    pub fn is_calculated(&self) -> bool {
        self.cached_root_hash.is_some()
    }

    pub fn member_count(&self) -> usize {
        self.member_count
    }

    pub fn contains(&self, handle: &Handle) -> bool {
        smt::get_member(&self.root, handle).is_some()
    }

    pub fn get(&self, handle: &Handle) -> Option<MemberLeaf> {
        smt::get_member(&self.root, handle)
    }

    pub fn members(&self) -> Vec<MemberLeaf> {
        smt::collect_members(&self.root)
    }

    /// Inserts a new member or replaces an existing one at the same handle.
    /// Returns a new trie with empty OnceLock hashes along the affected path.
    pub fn upsert(&self, leaf: MemberLeaf) -> Result<Self, OrgMembersError> {
        let was_present = smt::get_member(&self.root, leaf.handle()).is_some();
        let new_root = smt::insert::<H>(&self.root, leaf, &self.defaults);
        let new_count = if was_present {
            self.member_count
        } else {
            self.member_count + 1
        };

        Ok(Self {
            root: new_root,
            defaults: self.defaults.clone(),
            member_count: new_count,
            cached_root_hash: None, // invalidated
            last_calculated_root: self.last_calculated_root.clone(),
            _hasher: core::marker::PhantomData,
        })
    }

    /// Removes a member by handle. Returns a new trie with the leaf replaced
    /// by an empty sentinel and empty OnceLock hashes along the affected path.
    pub fn delete(&self, handle: &Handle) -> Result<Self, OrgMembersError> {
        if smt::get_member(&self.root, handle).is_none() {
            return Err(OrgMembersError::HandleNotFound);
        }
        let new_root = smt::remove(&self.root, handle, &self.defaults);

        Ok(Self {
            root: new_root,
            defaults: self.defaults.clone(),
            member_count: self.member_count - 1,
            cached_root_hash: None,
            last_calculated_root: self.last_calculated_root.clone(),
            _hasher: core::marker::PhantomData,
        })
    }

    /// Walks the trie bottom-up, filling every empty OnceLock hash.
    /// Returns the trie (now fully hashed) and a delta capturing all changes
    /// since the last recalculate.
    pub fn recalculate(&self) -> Result<(Self, Delta), OrgMembersError> {
        let root_hash = smt::recalculate_hashes::<H>(&self.root);

        // Compute delta from last calculated state
        let delta = if let Some(ref old_root) = self.last_calculated_root {
            let (removed, upserted) = smt::diff_tries(old_root, &self.root);
            Delta {
                base_root: RootHash(*old_root.hash().unwrap_or(&[0u8; 32])),
                removed,
                upserted,
            }
        } else {
            // First recalculate after genesis -- delta from empty
            let members = smt::collect_members(&self.root);
            Delta {
                base_root: RootHash(*self.defaults.at_level(crate::smt::SMT_DEPTH)),
                removed: Vec::new(),
                upserted: members,
            }
        };

        Ok((
            Self {
                root: self.root.clone(),
                defaults: self.defaults.clone(),
                member_count: self.member_count,
                cached_root_hash: Some(RootHash(root_hash)),
                last_calculated_root: Some(self.root.clone()),
                _hasher: core::marker::PhantomData,
            },
            delta,
        ))
    }

    /// Applies a received delta. Returns CandidateTrie (must verify before use).
    /// Fails immediately if delta.base_root != self.root_hash().
    pub fn apply_delta(&self, delta: &Delta) -> Result<CandidateTrie<H>, OrgMembersError> {
        let current_root = self
            .cached_root_hash
            .ok_or(OrgMembersError::HashesNotCalculated)?;

        if delta.base_root != current_root {
            return Err(OrgMembersError::DeltaBaseMismatch);
        }

        // Apply mutations
        let mut root = self.root.clone();
        let mut count = self.member_count;

        for handle in &delta.removed {
            root = smt::remove(&root, handle, &self.defaults);
            count -= 1;
        }
        for member in &delta.upserted {
            let was_present = smt::get_member(&root, member.handle()).is_some();
            root = smt::insert::<H>(&root, member.clone(), &self.defaults);
            if !was_present {
                count += 1;
            }
        }

        // Recalculate hashes
        let root_hash = smt::recalculate_hashes::<H>(&root);

        Ok(CandidateTrie {
            root,
            defaults: self.defaults.clone(),
            member_count: count,
            root_hash: RootHash(root_hash),
            last_calculated_root: self.last_calculated_root.clone(),
            _hasher: core::marker::PhantomData,
        })
    }

    /// Computes the delta that transforms `old` into `self`.
    /// Both tries must have populated hashes.
    pub fn diff_from(&self, old: &OrgTrie<H>) -> Result<Delta, OrgMembersError> {
        if !self.is_calculated() || !old.is_calculated() {
            return Err(OrgMembersError::HashesNotCalculated);
        }

        let (removed, upserted) = smt::diff_tries(&old.root, &self.root);

        Ok(Delta {
            base_root: old.root_hash(),
            removed,
            upserted,
        })
    }

    /// Access to internals for CandidateTrie promotion.
    pub(crate) fn from_candidate(
        root: Arc<Node>,
        defaults: Arc<DefaultHashes>,
        member_count: usize,
        root_hash: RootHash,
        _last_calculated_root: Option<Arc<Node>>,
    ) -> Self {
        Self {
            root: root.clone(),
            defaults,
            member_count,
            cached_root_hash: Some(root_hash),
            last_calculated_root: Some(root),
            _hasher: core::marker::PhantomData,
        }
    }
}

impl<H: TrieHasher> Clone for OrgTrie<H> {
    fn clone(&self) -> Self {
        Self {
            root: self.root.clone(),
            defaults: self.defaults.clone(),
            member_count: self.member_count,
            cached_root_hash: self.cached_root_hash,
            last_calculated_root: self.last_calculated_root.clone(),
            _hasher: core::marker::PhantomData,
        }
    }
}

impl<H: TrieHasher> std::fmt::Debug for OrgTrie<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrgTrie")
            .field("member_count", &self.member_count)
            .field("root_hash", &self.cached_root_hash)
            .field("is_calculated", &self.is_calculated())
            .finish()
    }
}
