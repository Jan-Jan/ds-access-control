use std::sync::Arc;

use crate::device_trie::compute_device_root;
use crate::hasher::TrieHasher;
use crate::node::{Node, NodeKind};
use crate::types::{bit_at, MemberLeaf};

/// Depth of the Sparse Merkle Tree (256 bits = 256 levels).
pub const SMT_DEPTH: u16 = 256;

const MEMBER_EMPTY_SENTINEL: &[u8] = b"EMPTY_SENTINEL_ORG_MEMBERS_V1";

/// Precomputed default hashes for each level of the SMT.
pub struct DefaultHashes {
    hashes: Vec<[u8; 32]>,
}

impl DefaultHashes {
    pub fn compute<H: TrieHasher>() -> Self {
        let mut hashes = Vec::with_capacity(SMT_DEPTH as usize + 1);
        let leaf_hash = H::hash_member_leaf(MEMBER_EMPTY_SENTINEL);
        hashes.push(leaf_hash);
        for i in 1..=SMT_DEPTH as usize {
            let prev = &hashes[i - 1];
            let h = H::hash_member_node(prev, prev);
            hashes.push(h);
        }
        Self { hashes }
    }

    pub fn at_level(&self, level: u16) -> &[u8; 32] {
        &self.hashes[level as usize]
    }

    pub fn empty_leaf(&self) -> &[u8; 32] {
        &self.hashes[0]
    }
}

pub fn empty_root(defaults: &DefaultHashes) -> Arc<Node> {
    Arc::new(Node::empty(*defaults.at_level(SMT_DEPTH)))
}

/// Inserts a member leaf at the position determined by its id bits.
pub fn insert<H: TrieHasher>(
    root: &Arc<Node>,
    member: MemberLeaf,
    defaults: &DefaultHashes,
) -> Arc<Node> {
    let id = *member.id();
    let device_root = compute_device_root::<H>(member.device_slots());
    let new_leaf = Arc::new(Node::leaf(member, device_root));
    insert_at(root, &id, new_leaf, 0, defaults)
}

/// Removes a member at the position determined by the id bits.
pub fn remove(
    root: &Arc<Node>,
    id: &[u8; 32],
    defaults: &DefaultHashes,
) -> Arc<Node> {
    let empty_leaf = Arc::new(Node::empty(*defaults.empty_leaf()));
    insert_at(root, id, empty_leaf, 0, defaults)
}

fn insert_at(
    node: &Arc<Node>,
    id: &[u8; 32],
    new_leaf: Arc<Node>,
    depth: u16,
    defaults: &DefaultHashes,
) -> Arc<Node> {
    if depth == SMT_DEPTH {
        return new_leaf;
    }

    let go_right = bit_at(id, depth);

    let (left, right) = match &node.kind {
        NodeKind::Internal { left, right } => (left.clone(), right.clone()),
        NodeKind::Empty | NodeKind::Leaf { .. } => {
            let default_child = Arc::new(Node::empty(*defaults.at_level(SMT_DEPTH - depth - 1)));
            (default_child.clone(), default_child)
        }
    };

    let (new_left, new_right) = if go_right {
        (left, insert_at(&right, id, new_leaf, depth + 1, defaults))
    } else {
        (insert_at(&left, id, new_leaf, depth + 1, defaults), right)
    };

    Arc::new(Node::internal(new_left, new_right))
}

/// Recursively computes hashes for all nodes with empty OnceLock.
pub fn recalculate_hashes<H: TrieHasher>(node: &Arc<Node>) -> [u8; 32] {
    if let Some(h) = node.hash() {
        return *h;
    }

    let computed = match &node.kind {
        NodeKind::Internal { left, right } => {
            let left_hash = recalculate_hashes::<H>(left);
            let right_hash = recalculate_hashes::<H>(right);
            H::hash_member_node(&left_hash, &right_hash)
        }
        NodeKind::Leaf {
            member,
            device_root,
        } => {
            let canonical = member.canonical_bytes(device_root);
            H::hash_member_leaf(&canonical)
        }
        NodeKind::Empty => {
            panic!("Empty node without precomputed hash");
        }
    };

    let _ = node.set_hash(computed);
    computed
}

/// Looks up a member by id, traversing the SMT by id bits.
pub fn get_member(root: &Arc<Node>, id: &[u8; 32]) -> Option<MemberLeaf> {
    let mut current = root.clone();
    for depth in 0..SMT_DEPTH {
        match &current.kind {
            NodeKind::Internal { left, right } => {
                current = if bit_at(id, depth) {
                    right.clone()
                } else {
                    left.clone()
                };
            }
            NodeKind::Empty => return None,
            NodeKind::Leaf { .. } => return None,
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

/// Computes the diff between two tries. Both must have calculated hashes.
/// Returns (removed_ids, upserted_leaves).
pub fn diff_tries(
    old: &Arc<Node>,
    new: &Arc<Node>,
) -> (Vec<[u8; 32]>, Vec<MemberLeaf>) {
    let mut removed = Vec::new();
    let mut upserted = Vec::new();
    diff_recursive(old, new, &mut removed, &mut upserted);
    (removed, upserted)
}

fn diff_recursive(
    old: &Arc<Node>,
    new: &Arc<Node>,
    removed: &mut Vec<[u8; 32]>,
    upserted: &mut Vec<MemberLeaf>,
) {
    if let (Some(old_h), Some(new_h)) = (old.hash(), new.hash()) {
        if old_h == new_h {
            return;
        }
    }

    match (&old.kind, &new.kind) {
        (
            NodeKind::Internal {
                left: ol,
                right: or,
            },
            NodeKind::Internal {
                left: nl,
                right: nr,
            },
        ) => {
            diff_recursive(ol, nl, removed, upserted);
            diff_recursive(or, nr, removed, upserted);
        }
        (NodeKind::Leaf { member: old_m, .. }, NodeKind::Leaf { member: new_m, .. }) => {
            if old_m != new_m {
                upserted.push(new_m.clone());
            }
        }
        (NodeKind::Leaf { member, .. }, NodeKind::Empty) => {
            removed.push(*member.id());
        }
        (NodeKind::Empty, NodeKind::Leaf { member, .. }) => {
            upserted.push(member.clone());
        }
        (NodeKind::Empty, NodeKind::Empty) => {}
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
