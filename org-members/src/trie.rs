use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use hashbrown::HashMap;

use crate::delta::{CandidateTrie, Delta};
use crate::error::OrgMembersError;
use crate::hasher::TrieHasher;
use crate::node::Node;
use crate::smt::{self, DefaultHashes};
use crate::normalize::to_nfc;
use crate::types::{handle_skeleton, MemberId, MemberLeaf, RootHash};

/// An immutable binary Sparse Merkle Tree for organisation membership.
///
/// Mutations (`insert`, `update`, `delete`) return a new trie via path-copying
/// with lazy hash computation. Call `recalculate()` to fill all pending hashes.
///
/// Maintains a skeleton index for UTS#39 confusable/homoglyph detection.
///
/// # Performance note
///
/// `skeleton_index` and `handle_index` are full `HashMap`s cloned on every
/// mutation -- O(N) memory per mutation regardless of how few members changed.
/// At 1000 members that's ~150KB allocation churn per `insert`/`update`/`delete`.
/// Fine at the design's target scale (1000 members, 1% monthly turnover) but
/// undoes the path-copying optimization for larger orgs.
///
/// Future optimization: wrap indexes in `Arc<Indexes>` shared across path-copies,
/// only rebuilt at `recalculate()`. For uncommitted mutations, find pending
/// leaves by walking the trie under unhashed nodes (subtrees whose root has an
/// unset `Once` cell). See discussion in the org-members worktree history.
pub struct OrgTrie<H: TrieHasher> {
    root: Arc<Node>,
    defaults: Arc<DefaultHashes>,
    member_count: usize,
    cached_root_hash: Option<RootHash>,
    last_calculated_root: Option<Arc<Node>>,
    /// Maps skeleton → handle string for confusable detection.
    skeleton_index: HashMap<String, String>,
    /// Maps handle → MemberId for handle-based lookups.
    /// Necessary because handle and id are independent (handle can change rarely
    /// while id stays the same).
    handle_index: HashMap<String, MemberId>,
    _hasher: core::marker::PhantomData<H>,
}

impl<H: TrieHasher> OrgTrie<H> {
    /// Creates a genesis trie from initial members.
    /// Checks both id and handle uniqueness (including confusables).
    pub fn genesis(members: Vec<MemberLeaf>) -> Result<Self, OrgMembersError> {
        let defaults = Arc::new(DefaultHashes::compute::<H>());
        let mut root = smt::empty_root(&defaults);
        let mut count = 0;
        let mut skeleton_index = HashMap::new();
        let mut handle_index = HashMap::new();

        for member in members {
            // Check for duplicate key
            if smt::get_member(&root, member.id()).is_some() {
                return Err(OrgMembersError::DuplicateId);
            }

            // Check for duplicate/confusable handle
            let skeleton = handle_skeleton(member.handle());
            if let Some(existing) = skeleton_index.get(&skeleton) {
                if existing != member.handle() {
                    return Err(OrgMembersError::ConfusableHandle);
                } else {
                    return Err(OrgMembersError::DuplicateHandle);
                }
            }

            skeleton_index.insert(skeleton, member.handle().to_owned());
            handle_index.insert(member.handle().to_owned(), *member.id());
            root = smt::insert::<H>(&root, member, &defaults);
            count += 1;
        }

        let root_hash = smt::recalculate_hashes::<H>(&root)?;

        Ok(Self {
            root: root.clone(),
            defaults,
            member_count: count,
            cached_root_hash: Some(RootHash(root_hash)),
            last_calculated_root: Some(root),
            skeleton_index,
            handle_index,
            _hasher: core::marker::PhantomData,
        })
    }

    /// Returns the root hash. Returns `Err(HashesNotCalculated)` if there are
    /// pending mutations -- call `recalculate()` first.
    pub fn root_hash(&self) -> Result<RootHash, OrgMembersError> {
        self.cached_root_hash.ok_or(OrgMembersError::HashesNotCalculated)
    }

    pub fn is_calculated(&self) -> bool {
        self.cached_root_hash.is_some()
    }

    pub fn member_count(&self) -> usize {
        self.member_count
    }

    pub fn contains(&self, id: &MemberId) -> bool {
        smt::get_member(&self.root, id).is_some()
    }

    pub fn contains_handle(&self, handle: &str) -> bool {
        // NFC-normalize input so callers passing decomposed Unicode still match.
        let normalized = to_nfc(handle);
        self.handle_index.contains_key(normalized.as_str())
    }

    pub fn get(&self, id: &MemberId) -> Option<MemberLeaf> {
        smt::get_member(&self.root, id)
    }

    pub fn get_by_handle(&self, handle: &str) -> Option<MemberLeaf> {
        let normalized = to_nfc(handle);
        let id = self.handle_index.get(normalized.as_str())?;
        smt::get_member(&self.root, id)
    }

    pub fn members(&self) -> Vec<MemberLeaf> {
        smt::collect_members(&self.root)
    }

    /// Inserts a new member. Fails if the id already exists or if the handle
    /// (or a confusable variant) is already taken.
    pub fn insert(&self, leaf: MemberLeaf) -> Result<Self, OrgMembersError> {
        // Check key uniqueness
        if smt::get_member(&self.root, leaf.id()).is_some() {
            return Err(OrgMembersError::DuplicateId);
        }

        // Check handle uniqueness (via skeleton)
        let mut new_skeleton_index = self.skeleton_index.clone();
        let mut new_handle_index = self.handle_index.clone();
        let skeleton = handle_skeleton(leaf.handle());
        if let Some(existing) = new_skeleton_index.get(&skeleton) {
            if existing != leaf.handle() {
                return Err(OrgMembersError::ConfusableHandle);
            } else {
                return Err(OrgMembersError::DuplicateHandle);
            }
        }
        new_skeleton_index.insert(skeleton, leaf.handle().to_owned());
        new_handle_index.insert(leaf.handle().to_owned(), *leaf.id());

        let new_root = smt::insert::<H>(&self.root, leaf, &self.defaults);

        Ok(Self {
            root: new_root,
            defaults: self.defaults.clone(),
            member_count: self.member_count + 1,
            cached_root_hash: None,
            last_calculated_root: self.last_calculated_root.clone(),
            skeleton_index: new_skeleton_index,
            handle_index: new_handle_index,
            _hasher: core::marker::PhantomData,
        })
    }

    /// Updates an existing member (looked up by key). Fails if the key doesn't exist
    /// or if the new handle conflicts with a different member's handle.
    pub fn update(&self, leaf: MemberLeaf) -> Result<Self, OrgMembersError> {
        let existing = smt::get_member(&self.root, leaf.id())
            .ok_or(OrgMembersError::IdNotFound)?;

        let mut new_skeleton_index = self.skeleton_index.clone();
        let mut new_handle_index = self.handle_index.clone();

        // If the handle changed, check the new handle is unique and update the index
        if existing.handle() != leaf.handle() {
            // Remove old handle's skeleton and handle index entry
            let old_skeleton = handle_skeleton(existing.handle());
            new_skeleton_index.remove(&old_skeleton);
            new_handle_index.remove(existing.handle());

            // Check new handle doesn't collide
            let new_skeleton = handle_skeleton(leaf.handle());
            if let Some(existing_handle) = new_skeleton_index.get(&new_skeleton) {
                if existing_handle != leaf.handle() {
                    return Err(OrgMembersError::ConfusableHandle);
                } else {
                    return Err(OrgMembersError::DuplicateHandle);
                }
            }
            new_skeleton_index.insert(new_skeleton, leaf.handle().to_owned());
            new_handle_index.insert(leaf.handle().to_owned(), *leaf.id());
        }

        let new_root = smt::insert::<H>(&self.root, leaf, &self.defaults);

        Ok(Self {
            root: new_root,
            defaults: self.defaults.clone(),
            member_count: self.member_count,
            cached_root_hash: None,
            last_calculated_root: self.last_calculated_root.clone(),
            skeleton_index: new_skeleton_index,
            handle_index: new_handle_index,
            _hasher: core::marker::PhantomData,
        })
    }

    /// Removes a member by id.
    pub fn delete(&self, id: &MemberId) -> Result<Self, OrgMembersError> {
        let existing = smt::get_member(&self.root, id)
            .ok_or(OrgMembersError::IdNotFound)?;

        let new_root = smt::remove(&self.root, id, &self.defaults);

        let mut new_skeleton_index = self.skeleton_index.clone();
        let mut new_handle_index = self.handle_index.clone();
        let skeleton = handle_skeleton(existing.handle());
        new_skeleton_index.remove(&skeleton);
        new_handle_index.remove(existing.handle());

        Ok(Self {
            root: new_root,
            defaults: self.defaults.clone(),
            member_count: self.member_count - 1,
            cached_root_hash: None,
            last_calculated_root: self.last_calculated_root.clone(),
            skeleton_index: new_skeleton_index,
            handle_index: new_handle_index,
            _hasher: core::marker::PhantomData,
        })
    }

    /// Returns the delta of changes accumulated since the last `recalculate()`.
    ///
    /// Does NOT compute hashes or change trie state -- safe to call multiple times
    /// for review. Admins can use this to inspect pending changes before agreeing
    /// to commit a new root hash via `recalculate()`.
    ///
    /// Returns an empty delta if no changes are pending.
    /// Returns `Err(InvariantViolated)` if the internal `last_calculated_root`
    /// invariant is broken (its hash should always be populated when present).
    pub fn pending_changes(&self) -> Result<Delta, OrgMembersError> {
        if let Some(ref old_root) = self.last_calculated_root {
            let (removed, upserted) = smt::diff_tries(old_root, &self.root);
            // Invariant: last_calculated_root is only ever set immediately
            // after recalculate_hashes has populated its Once cell.
            let base_root_bytes = old_root.hash().ok_or(OrgMembersError::InvariantViolated)?;
            Ok(Delta {
                base_root: RootHash(*base_root_bytes),
                removed,
                upserted,
            })
        } else {
            let members = smt::collect_members(&self.root);
            Ok(Delta {
                base_root: RootHash(*self.defaults.at_level(crate::smt::SMT_DEPTH)),
                removed: Vec::new(),
                upserted: members,
            })
        }
    }

    /// Returns true if there are uncommitted mutations since the last `recalculate()`.
    pub fn has_pending_changes(&self) -> bool {
        self.cached_root_hash.is_none()
    }

    /// Walks the trie bottom-up, filling every empty OnceLock hash.
    /// Returns the trie (now fully hashed) and a delta of all pending changes.
    pub fn recalculate(&self) -> Result<(Self, Delta), OrgMembersError> {
        let delta = self.pending_changes()?;
        let root_hash = smt::recalculate_hashes::<H>(&self.root)?;

        Ok((
            Self {
                root: self.root.clone(),
                defaults: self.defaults.clone(),
                member_count: self.member_count,
                cached_root_hash: Some(RootHash(root_hash)),
                last_calculated_root: Some(self.root.clone()),
                skeleton_index: self.skeleton_index.clone(),
                handle_index: self.handle_index.clone(),
                _hasher: core::marker::PhantomData,
            },
            delta,
        ))
    }

    /// Applies a received delta. Returns CandidateTrie (must verify before use).
    pub fn apply_delta(&self, delta: &Delta) -> Result<CandidateTrie<H>, OrgMembersError> {
        let current_root = self
            .cached_root_hash
            .ok_or(OrgMembersError::HashesNotCalculated)?;

        if delta.base_root != current_root {
            return Err(OrgMembersError::DeltaBaseMismatch);
        }

        let mut root = self.root.clone();
        let mut count = self.member_count;
        let mut new_skeleton_index = self.skeleton_index.clone();
        let mut new_handle_index = self.handle_index.clone();

        // Remove: only decrement count if the member was actually present.
        for id in &delta.removed {
            if let Some(existing) = smt::get_member(&root, id) {
                new_skeleton_index.remove(&handle_skeleton(existing.handle()));
                new_handle_index.remove(existing.handle());
                root = smt::remove(&root, id, &self.defaults);
                count -= 1;
            }
        }

        // Upsert: check confusable handles for BOTH new inserts and existing-id updates.
        // For an existing-id update with a different handle, we must remove the old
        // skeleton entry before checking the new one.
        for member in &delta.upserted {
            let existing = smt::get_member(&root, member.id());

            if let Some(ref old) = existing {
                if old.handle() != member.handle() {
                    // Handle changed -- remove old skeleton/handle index entries first
                    new_skeleton_index.remove(&handle_skeleton(old.handle()));
                    new_handle_index.remove(old.handle());
                }
            }

            // Check the upserted handle is unique (unless unchanged for existing member)
            let needs_check = match &existing {
                Some(old) => old.handle() != member.handle(),
                None => true,
            };

            if needs_check {
                let skeleton = handle_skeleton(member.handle());
                if let Some(existing_handle) = new_skeleton_index.get(&skeleton) {
                    if existing_handle != member.handle() {
                        return Err(OrgMembersError::ConfusableHandle);
                    } else {
                        return Err(OrgMembersError::DuplicateHandle);
                    }
                }
                new_skeleton_index.insert(skeleton, member.handle().to_owned());
                new_handle_index.insert(member.handle().to_owned(), *member.id());
            }

            root = smt::insert::<H>(&root, member.clone(), &self.defaults);
            if existing.is_none() {
                count += 1;
            }
        }

        let root_hash = smt::recalculate_hashes::<H>(&root)?;

        Ok(CandidateTrie {
            root,
            defaults: self.defaults.clone(),
            member_count: count,
            root_hash: RootHash(root_hash),
            skeleton_index: new_skeleton_index,
            handle_index: new_handle_index,
            _hasher: core::marker::PhantomData,
        })
    }

    /// Computes the delta that transforms `old` into `self`.
    pub fn diff_from(&self, old: &OrgTrie<H>) -> Result<Delta, OrgMembersError> {
        if !self.is_calculated() || !old.is_calculated() {
            return Err(OrgMembersError::HashesNotCalculated);
        }

        let (removed, upserted) = smt::diff_tries(&old.root, &self.root);

        Ok(Delta {
            base_root: old.root_hash()?,
            removed,
            upserted,
        })
    }

    pub(crate) fn from_candidate(
        root: Arc<Node>,
        defaults: Arc<DefaultHashes>,
        member_count: usize,
        root_hash: RootHash,
        skeleton_index: HashMap<String, String>,
        handle_index: HashMap<String, MemberId>,
    ) -> Self {
        Self {
            root: root.clone(),
            defaults,
            member_count,
            cached_root_hash: Some(root_hash),
            last_calculated_root: Some(root),
            skeleton_index,
            handle_index,
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
            skeleton_index: self.skeleton_index.clone(),
            handle_index: self.handle_index.clone(),
            _hasher: core::marker::PhantomData,
        }
    }
}

impl<H: TrieHasher> fmt::Debug for OrgTrie<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OrgTrie")
            .field("member_count", &self.member_count)
            .field("root_hash", &self.cached_root_hash)
            .field("is_calculated", &self.is_calculated())
            .finish()
    }
}
