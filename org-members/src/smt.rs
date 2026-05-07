use std::sync::Arc;

use crate::device_trie::compute_device_root;
use crate::hasher::TrieHasher;
use crate::node::{Node, NodeKind};
use crate::types::{Handle, MemberLeaf};

/// Depth of the Sparse Merkle Tree (256 bits = 256 levels).
pub const SMT_DEPTH: u16 = 256;

const MEMBER_EMPTY_SENTINEL: &[u8] = b"EMPTY_SENTINEL_ORG_MEMBERS_V1";

/// Precomputed default hashes for each level of the SMT.
/// `default_hashes[0]` = empty leaf hash, `default_hashes[i]` = hash of two default children.
pub struct DefaultHashes {
    hashes: Vec<[u8; 32]>,
}

impl DefaultHashes {
    pub fn compute<H: TrieHasher>() -> Self {
        let mut hashes = Vec::with_capacity(SMT_DEPTH as usize + 1);
        // Level 0: empty leaf
        let leaf_hash = H::hash_member_leaf(MEMBER_EMPTY_SENTINEL);
        hashes.push(leaf_hash);
        // Levels 1..256: hash of two default children
        for i in 1..=SMT_DEPTH as usize {
            let prev = &hashes[i - 1];
            let h = H::hash_member_node(prev, prev);
            hashes.push(h);
        }
        Self { hashes }
    }

    /// Returns the default hash at the given level (0 = leaf, 256 = root of empty tree).
    pub fn at_level(&self, level: u16) -> &[u8; 32] {
        &self.hashes[level as usize]
    }

    /// Returns the default empty leaf hash.
    pub fn empty_leaf(&self) -> &[u8; 32] {
        &self.hashes[0]
    }
}

/// Creates an empty SMT root node for the given depth using default hashes.
pub fn empty_root(defaults: &DefaultHashes) -> Arc<Node> {
    Arc::new(Node::empty(*defaults.at_level(SMT_DEPTH)))
}

/// Inserts a member leaf at the position determined by its handle bits.
/// Returns a new root with path-copied nodes. New nodes have empty OnceLock hashes.
/// Unchanged subtrees are shared via Arc.
pub fn insert<H: TrieHasher>(
    root: &Arc<Node>,
    member: MemberLeaf,
    defaults: &DefaultHashes,
) -> Arc<Node> {
    let handle = member.handle().clone();
    let device_root = compute_device_root::<H>(member.device_slots());
    let new_leaf = Arc::new(Node::leaf(member, device_root));
    insert_at(root, &handle, new_leaf, 0, defaults)
}

/// Removes a member at the position determined by the handle bits.
/// Returns a new root with the leaf replaced by an empty sentinel.
pub fn remove(
    root: &Arc<Node>,
    handle: &Handle,
    defaults: &DefaultHashes,
) -> Arc<Node> {
    let empty_leaf = Arc::new(Node::empty(*defaults.empty_leaf()));
    insert_at(root, handle, empty_leaf, 0, defaults)
}

/// Recursively path-copies from root to the target leaf position.
fn insert_at(
    node: &Arc<Node>,
    handle: &Handle,
    new_leaf: Arc<Node>,
    depth: u16,
    defaults: &DefaultHashes,
) -> Arc<Node> {
    if depth == SMT_DEPTH {
        // We're at the leaf level -- replace with the new leaf
        return new_leaf;
    }

    let go_right = handle.bit(depth as u8);

    let (left, right) = match &node.kind {
        NodeKind::Internal { left, right } => (left.clone(), right.clone()),
        NodeKind::Empty | NodeKind::Leaf { .. } => {
            // Expand: if this is an empty node or a leaf that needs to be pushed down,
            // create default children at the next level.
            // For Empty: both children are default at depth+1
            // For Leaf: this shouldn't happen at non-leaf depth in a well-formed SMT
            let default_child = Arc::new(Node::empty(*defaults.at_level(SMT_DEPTH - depth - 1)));
            (default_child.clone(), default_child)
        }
    };

    let (new_left, new_right) = if go_right {
        (left, insert_at(&right, handle, new_leaf, depth + 1, defaults))
    } else {
        (insert_at(&left, handle, new_leaf, depth + 1, defaults), right)
    };

    Arc::new(Node::internal(new_left, new_right))
}

/// Recursively computes hashes for all nodes with empty OnceLock.
/// Nodes with already-set hashes are skipped (structural sharing benefit).
/// Returns the hash of the given node.
pub fn recalculate_hashes<H: TrieHasher>(
    node: &Arc<Node>,
) -> [u8; 32] {
    // If hash is already set, return it immediately (shared subtree)
    if let Some(h) = node.hash() {
        return *h;
    }

    let computed = match &node.kind {
        NodeKind::Internal { left, right } => {
            let left_hash = recalculate_hashes::<H>(left);
            let right_hash = recalculate_hashes::<H>(right);
            H::hash_member_node(&left_hash, &right_hash)
        }
        NodeKind::Leaf { member, device_root } => {
            let canonical = member.canonical_bytes(device_root);
            H::hash_member_leaf(&canonical)
        }
        NodeKind::Empty => {
            // Empty nodes should always have their hash pre-set.
            // This is a logic error if reached.
            panic!("Empty node without precomputed hash");
        }
    };

    // Set the hash (ignore error if already set by concurrent code)
    let _ = node.set_hash(computed);
    computed
}

/// Looks up a member by handle, traversing the SMT by handle bits.
pub fn get_member(root: &Arc<Node>, handle: &Handle) -> Option<MemberLeaf> {
    let mut current = root.clone();
    for depth in 0..SMT_DEPTH {
        match &current.kind {
            NodeKind::Internal { left, right } => {
                current = if handle.bit(depth as u8) {
                    right.clone()
                } else {
                    left.clone()
                };
            }
            NodeKind::Empty => return None,
            NodeKind::Leaf { .. } => {
                // Shouldn't find a leaf at non-final depth in a well-formed SMT
                return None;
            }
        }
    }
    match &current.kind {
        NodeKind::Leaf { member, .. } => Some(member.clone()),
        _ => None,
    }
}

/// Collects all member leaves in the trie.
pub fn collect_members(root: &Arc<Node>) -> Vec<MemberLeaf> {
    let mut members = Vec::new();
    collect_members_recursive(root, &mut members);
    members
}

fn collect_members_recursive(node: &Arc<Node>, members: &mut Vec<MemberLeaf>) {
    match &node.kind {
        NodeKind::Internal { left, right } => {
            collect_members_recursive(left, members);
            collect_members_recursive(right, members);
        }
        NodeKind::Leaf { member, .. } => {
            members.push(member.clone());
        }
        NodeKind::Empty => {}
    }
}

/// Checks if all nodes in the trie have their hashes computed.
pub fn all_calculated(node: &Arc<Node>) -> bool {
    if !node.is_calculated() {
        return false;
    }
    match &node.kind {
        NodeKind::Internal { left, right } => {
            all_calculated(left) && all_calculated(right)
        }
        _ => true,
    }
}

/// Computes the diff between two tries. Both must have calculated hashes.
/// Returns (removed_handles, upserted_leaves).
pub fn diff_tries(
    old: &Arc<Node>,
    new: &Arc<Node>,
) -> (Vec<Handle>, Vec<MemberLeaf>) {
    let mut removed = Vec::new();
    let mut upserted = Vec::new();
    diff_recursive(old, new, &mut removed, &mut upserted);
    (removed, upserted)
}

fn diff_recursive(
    old: &Arc<Node>,
    new: &Arc<Node>,
    removed: &mut Vec<Handle>,
    upserted: &mut Vec<MemberLeaf>,
) {
    // Short-circuit: if hashes match, subtrees are identical
    if let (Some(old_h), Some(new_h)) = (old.hash(), new.hash()) {
        if old_h == new_h {
            return;
        }
    }

    match (&old.kind, &new.kind) {
        (NodeKind::Internal { left: ol, right: or }, NodeKind::Internal { left: nl, right: nr }) => {
            diff_recursive(ol, nl, removed, upserted);
            diff_recursive(or, nr, removed, upserted);
        }
        (NodeKind::Leaf { member: old_m, .. }, NodeKind::Leaf { member: new_m, .. }) => {
            if old_m != new_m {
                // Updated member (handle should be the same for same position)
                upserted.push(new_m.clone());
            }
        }
        (NodeKind::Leaf { member, .. }, NodeKind::Empty) => {
            removed.push(member.handle().clone());
        }
        (NodeKind::Empty, NodeKind::Leaf { member, .. }) => {
            upserted.push(member.clone());
        }
        (NodeKind::Empty, NodeKind::Empty) => {}
        // Mixed internal/leaf/empty at same depth: recurse into the internal side
        (NodeKind::Internal { left, right }, _) => {
            diff_recursive(left, new, removed, upserted);
            diff_recursive(right, new, removed, upserted);
        }
        (_, NodeKind::Internal { left, right }) => {
            diff_recursive(old, left, removed, upserted);
            diff_recursive(old, right, removed, upserted);
        }
    }
}
