use std::sync::{Arc, OnceLock};

use crate::types::MemberLeaf;

/// A node in the binary Sparse Merkle Tree.
///
/// Hash is lazily computed via `OnceLock` -- set once during `recalculate()`,
/// then immutable. `Arc` enables structural sharing between trie versions.
pub struct Node {
    hash: OnceLock<[u8; 32]>,
    pub(crate) kind: NodeKind,
}

pub(crate) enum NodeKind {
    Internal {
        left: Arc<Node>,
        right: Arc<Node>,
    },
    Leaf {
        member: MemberLeaf,
        /// Precomputed device sub-trie root (set at leaf creation).
        device_root: [u8; 32],
    },
    /// Empty sentinel node. Hash is precomputed at construction for the given level.
    Empty,
}

impl Node {
    /// Creates a new internal node with empty hash (to be filled by recalculate).
    pub(crate) fn internal(left: Arc<Node>, right: Arc<Node>) -> Self {
        Self {
            hash: OnceLock::new(),
            kind: NodeKind::Internal { left, right },
        }
    }

    /// Creates a new leaf node with empty hash (to be filled by recalculate).
    pub(crate) fn leaf(member: MemberLeaf, device_root: [u8; 32]) -> Self {
        Self {
            hash: OnceLock::new(),
            kind: NodeKind::Leaf {
                member,
                device_root,
            },
        }
    }

    /// Creates an empty sentinel node with a precomputed hash.
    pub(crate) fn empty(hash: [u8; 32]) -> Self {
        let lock = OnceLock::new();
        let _ = lock.set(hash);
        Self {
            hash: lock,
            kind: NodeKind::Empty,
        }
    }

    /// Returns the hash if already computed, or None.
    pub(crate) fn hash(&self) -> Option<&[u8; 32]> {
        self.hash.get()
    }

    /// Sets the hash. Returns Err if already set.
    pub(crate) fn set_hash(&self, hash: [u8; 32]) -> Result<(), [u8; 32]> {
        self.hash.set(hash)
    }

    /// Returns true if the hash has been computed.
    pub(crate) fn is_calculated(&self) -> bool {
        self.hash.get().is_some()
    }
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            NodeKind::Internal { .. } => {
                write!(f, "Node::Internal(hash={:?})", self.hash.get().map(|h| &h[..4]))
            }
            NodeKind::Leaf { member, .. } => {
                write!(f, "Node::Leaf({:?})", member)
            }
            NodeKind::Empty => {
                write!(f, "Node::Empty")
            }
        }
    }
}
