/// Pluggable hash function for the Merkle trie.
///
/// Four domain-separated static methods prevent accidental cross-domain hashing
/// at compile time. Each method maps 1:1 to a future Halo2 circuit gadget.
///
/// Not object-safe (static methods). Use with generics: `OrgTrie<H: TrieHasher>`.
pub trait TrieHasher: Clone + Send + Sync {
    /// Hash a serialized member leaf (domain: MEMBER_LEAF).
    fn hash_member_leaf(data: &[u8]) -> [u8; 32];

    /// Hash two child node hashes into a parent (domain: MEMBER_NODE).
    fn hash_member_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32];

    /// Hash a device public key (domain: DEVICE_LEAF).
    fn hash_device_leaf(data: &[u8]) -> [u8; 32];

    /// Hash two device child hashes into a parent (domain: DEVICE_NODE).
    fn hash_device_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32];
}

/// Blake3-based hasher for testing and non-ZKP use.
/// Uses domain separation via context strings.
#[derive(Clone, Debug)]
pub struct Blake3Hasher;

impl TrieHasher for Blake3Hasher {
    fn hash_member_leaf(data: &[u8]) -> [u8; 32] {
        blake3::keyed_hash(b"org-members::member-leaf________", data).into()
    }

    fn hash_member_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(b"org-members::member-node________");
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }

    fn hash_device_leaf(data: &[u8]) -> [u8; 32] {
        blake3::keyed_hash(b"org-members::device-leaf________", data).into()
    }

    fn hash_device_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(b"org-members::device-node________");
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }
}
