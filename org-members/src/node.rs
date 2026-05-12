use alloc::boxed::Box;
use alloc::sync::Arc;
use core::fmt;

use spin::Once;

use crate::types::{MemberLeaf, NodeHash};

/// A node in the binary Sparse Merkle Tree.
///
/// Hash is lazily computed via `spin::Once` -- set once during `recalculate()`,
/// then immutable. `Arc` enables structural sharing between trie versions.
/// `spin::Once` is `no_std`-compatible and thread-safe.
pub struct Node {
    hash: Once<NodeHash>,
    pub(crate) kind: NodeKind,
}

/// Leaf payload boxed to keep the `NodeKind` enum compact -- internal nodes
/// (the vast majority in a sparse trie) would otherwise carry the full
/// `MemberLeaf` sized variant in their discriminant.
pub(crate) struct LeafPayload {
    pub(crate) member: MemberLeaf,
    /// Precomputed device sub-trie root (set at leaf creation).
    pub(crate) device_root: NodeHash,
}

pub(crate) enum NodeKind {
    Internal {
        left: Arc<Node>,
        right: Arc<Node>,
    },
    Leaf(Box<LeafPayload>),
    /// Empty sentinel node. Hash is precomputed at construction for the given level.
    Empty,
}

impl Node {
    /// Creates a new internal node with empty hash (to be filled by recalculate).
    pub(crate) fn internal(left: Arc<Node>, right: Arc<Node>) -> Self {
        Self {
            hash: Once::new(),
            kind: NodeKind::Internal { left, right },
        }
    }

    /// Creates a new leaf node with empty hash (to be filled by recalculate).
    pub(crate) fn leaf(member: MemberLeaf, device_root: NodeHash) -> Self {
        Self {
            hash: Once::new(),
            kind: NodeKind::Leaf(Box::new(LeafPayload {
                member,
                device_root,
            })),
        }
    }

    /// Creates an empty sentinel node with a precomputed hash.
    pub(crate) fn empty(hash: NodeHash) -> Self {
        let lock = Once::new();
        lock.call_once(|| hash);
        Self {
            hash: lock,
            kind: NodeKind::Empty,
        }
    }

    /// Returns the hash if already computed, or None.
    pub(crate) fn hash(&self) -> Option<&NodeHash> {
        self.hash.get()
    }

    /// Sets the hash. Subsequent calls have no effect (set-once semantics).
    pub(crate) fn set_hash(&self, hash: NodeHash) {
        self.hash.call_once(|| hash);
    }

    /// Returns true if the hash has been computed.
    #[allow(dead_code)]
    pub(crate) fn is_calculated(&self) -> bool {
        self.hash.get().is_some()
    }
}

impl fmt::Debug for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            NodeKind::Internal { .. } => {
                write!(
                    f,
                    "Node::Internal(hash={:?})",
                    self.hash.get().map(|h| &h.as_bytes()[..4])
                )
            }
            NodeKind::Leaf(payload) => {
                write!(f, "Node::Leaf({:?})", payload.member)
            }
            NodeKind::Empty => {
                write!(f, "Node::Empty")
            }
        }
    }
}
