use crate::hasher::TrieHasher;
use crate::types::P2pDeviceSlots;

const DEVICE_EMPTY_SENTINEL: &[u8] = b"EMPTY_SENTINEL_ORG_MEMBERS_DEVICE_V1";

/// Computes the root hash of a depth-2 device sub-trie.
///
/// The sub-trie has 4 leaf slots (matching P2pDeviceSlots).
/// Empty slots use the device empty sentinel hash.
pub fn compute_device_root<H: TrieHasher>(devices: &P2pDeviceSlots) -> [u8; 32] {
    let slots = devices.to_fixed_slots();
    let empty_leaf = device_empty_leaf_hash::<H>();

    // Level 0: 4 leaf hashes
    let leaves: [_; 4] = core::array::from_fn(|i| match slots[i] {
        Some(device) => H::hash_device_leaf(device.as_bytes()),
        None => empty_leaf,
    });

    // Level 1: 2 internal nodes
    let level1_left = H::hash_device_node(&leaves[0], &leaves[1]);
    let level1_right = H::hash_device_node(&leaves[2], &leaves[3]);

    // Level 2: root
    H::hash_device_node(&level1_left, &level1_right)
}

/// Returns the device empty leaf sentinel hash.
pub fn device_empty_leaf_hash<H: TrieHasher>() -> [u8; 32] {
    H::hash_device_leaf(DEVICE_EMPTY_SENTINEL)
}
