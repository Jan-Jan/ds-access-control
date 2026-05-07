use org_members::hasher::Blake3Hasher;
use org_members::trie::OrgTrie;
use org_members::types::{Handle, MemberLeaf, RootHash};
use org_members::OrgMembersError;

type TestTrie = OrgTrie<Blake3Hasher>;

fn make_handle(id: u8) -> Handle {
    let mut bytes = [0u8; 32];
    bytes[0] = id;
    Handle::new(bytes).unwrap()
}

fn make_member(id: u8) -> MemberLeaf {
    let handle = make_handle(id);
    let device = [id; 32];
    MemberLeaf::new(handle, "Alice", "Smith", [id; 32], vec![device]).unwrap()
}

// --- Genesis tests ---

#[test]
fn genesis_single_member() {
    let trie = TestTrie::genesis(vec![make_member(1)]).unwrap();
    assert_eq!(trie.member_count(), 1);
    assert!(trie.is_calculated());
    assert!(trie.contains(&make_handle(1)));
    assert!(!trie.contains(&make_handle(2)));
}

#[test]
fn genesis_multiple_members() {
    let members: Vec<_> = (1..=10).map(make_member).collect();
    let trie = TestTrie::genesis(members).unwrap();
    assert_eq!(trie.member_count(), 10);
    for i in 1..=10 {
        assert!(trie.contains(&make_handle(i)));
    }
}

#[test]
fn genesis_duplicate_handle_fails() {
    let err = TestTrie::genesis(vec![make_member(1), make_member(1)]);
    assert_eq!(err.unwrap_err(), OrgMembersError::DuplicateHandle);
}

#[test]
fn genesis_empty_is_ok() {
    let trie = TestTrie::genesis(vec![]).unwrap();
    assert_eq!(trie.member_count(), 0);
    assert!(trie.is_calculated());
}

// --- Upsert tests ---

#[test]
fn upsert_adds_member() {
    let trie = TestTrie::genesis(vec![make_member(1)]).unwrap();
    let trie = trie.upsert(make_member(2)).unwrap();
    // Not yet recalculated
    assert!(!trie.is_calculated());
    assert_eq!(trie.member_count(), 2);
    assert!(trie.contains(&make_handle(2)));

    let (trie, delta) = trie.recalculate().unwrap();
    assert!(trie.is_calculated());
    assert_eq!(delta.upserted().len(), 1);
    assert!(delta.removed().is_empty());
}

#[test]
fn upsert_replaces_existing() {
    let trie = TestTrie::genesis(vec![make_member(1)]).unwrap();
    let root_before = trie.root_hash();

    // Upsert with same handle but different data
    let updated = MemberLeaf::new(
        make_handle(1),
        "Bob",
        "Jones",
        [42; 32],
        vec![[99; 32]],
    )
    .unwrap();
    let trie = trie.upsert(updated).unwrap();
    let (trie, _) = trie.recalculate().unwrap();

    assert_eq!(trie.member_count(), 1);
    let member = trie.get(&make_handle(1)).unwrap();
    assert_eq!(member.name(), "Bob");
    assert_ne!(trie.root_hash(), root_before);
}

// --- Delete tests ---

#[test]
fn delete_removes_member() {
    let trie = TestTrie::genesis(vec![make_member(1), make_member(2)]).unwrap();
    let trie = trie.delete(&make_handle(1)).unwrap();
    let (trie, delta) = trie.recalculate().unwrap();

    assert_eq!(trie.member_count(), 1);
    assert!(!trie.contains(&make_handle(1)));
    assert!(trie.contains(&make_handle(2)));
    assert_eq!(delta.removed().len(), 1);
}

#[test]
fn delete_nonexistent_fails() {
    let trie = TestTrie::genesis(vec![make_member(1)]).unwrap();
    let err = trie.delete(&make_handle(99));
    assert_eq!(err.unwrap_err(), OrgMembersError::HandleNotFound);
}

// --- Immutability tests ---

#[test]
fn upsert_does_not_mutate_original() {
    let original = TestTrie::genesis(vec![make_member(1)]).unwrap();
    let original_root = original.root_hash();
    let _modified = original.upsert(make_member(2)).unwrap();

    // Original is untouched
    assert_eq!(original.member_count(), 1);
    assert_eq!(original.root_hash(), original_root);
    assert!(!original.contains(&make_handle(2)));
}

#[test]
fn delete_does_not_mutate_original() {
    let original = TestTrie::genesis(vec![make_member(1), make_member(2)]).unwrap();
    let original_root = original.root_hash();
    let _modified = original.delete(&make_handle(1)).unwrap();

    assert_eq!(original.member_count(), 2);
    assert_eq!(original.root_hash(), original_root);
    assert!(original.contains(&make_handle(1)));
}

// --- Delta and CandidateTrie tests ---

#[test]
fn delta_apply_and_verify() {
    let trie_a = TestTrie::genesis(vec![make_member(1), make_member(2)]).unwrap();

    // Create mutations and get delta
    let trie_b = trie_a.upsert(make_member(3)).unwrap();
    let trie_b = trie_b.delete(&make_handle(1)).unwrap();
    let (trie_b, delta) = trie_b.recalculate().unwrap();

    // Apply delta to trie_a
    let candidate = trie_a.apply_delta(&delta).unwrap();
    let expected_root = trie_b.root_hash();
    let verified = candidate.verify_against(&expected_root).unwrap();

    assert_eq!(verified.root_hash(), trie_b.root_hash());
    assert_eq!(verified.member_count(), 2);
    assert!(!verified.contains(&make_handle(1)));
    assert!(verified.contains(&make_handle(2)));
    assert!(verified.contains(&make_handle(3)));
}

#[test]
fn delta_base_mismatch_fails() {
    let trie_a = TestTrie::genesis(vec![make_member(1)]).unwrap();
    let trie_b = TestTrie::genesis(vec![make_member(2)]).unwrap();

    let trie_mod = trie_a.upsert(make_member(3)).unwrap();
    let (_, delta) = trie_mod.recalculate().unwrap();

    // Try to apply trie_a's delta to trie_b (different base root)
    let err = trie_b.apply_delta(&delta);
    assert_eq!(err.unwrap_err(), OrgMembersError::DeltaBaseMismatch);
}

#[test]
fn candidate_verify_wrong_root_fails() {
    let trie = TestTrie::genesis(vec![make_member(1)]).unwrap();
    let trie_mod = trie.upsert(make_member(2)).unwrap();
    let (_, delta) = trie_mod.recalculate().unwrap();

    let candidate = trie.apply_delta(&delta).unwrap();
    let wrong_root = RootHash::from_bytes([0xFF; 32]);
    let err = candidate.verify_against(&wrong_root);
    assert_eq!(err.unwrap_err(), OrgMembersError::VerificationFailed);
}

// --- Diff tests (long-offline catch-up) ---

#[test]
fn diff_produces_valid_delta() {
    let old_trie = TestTrie::genesis(vec![make_member(1), make_member(2)]).unwrap();

    // Build new trie with changes
    let new_trie = old_trie.upsert(make_member(3)).unwrap();
    let new_trie = new_trie.delete(&make_handle(1)).unwrap();
    let (new_trie, _) = new_trie.recalculate().unwrap();

    // Compute diff
    let diff_delta = new_trie.diff_from(&old_trie).unwrap();

    // Apply the diff delta to old_trie
    let candidate = old_trie.apply_delta(&diff_delta).unwrap();
    let verified = candidate.verify_against(&new_trie.root_hash()).unwrap();

    assert_eq!(verified.root_hash(), new_trie.root_hash());
}

// --- Members iteration ---

#[test]
fn members_returns_all() {
    let members: Vec<_> = (1..=5).map(make_member).collect();
    let trie = TestTrie::genesis(members).unwrap();
    let all = trie.members();
    assert_eq!(all.len(), 5);
}

// --- Handle tests ---

#[test]
fn reserved_handle_rejected() {
    let err = Handle::new([0u8; 32]);
    assert_eq!(err.unwrap_err(), OrgMembersError::ReservedHandle);
}

#[test]
fn handle_bit_extraction() {
    let mut bytes = [0u8; 32];
    bytes[0] = 0b10110001;
    let handle = Handle::new(bytes).unwrap();
    assert!(handle.bit(0));   // MSB
    assert!(!handle.bit(1));
    assert!(handle.bit(2));
    assert!(handle.bit(3));
    assert!(!handle.bit(4));
    assert!(!handle.bit(5));
    assert!(!handle.bit(6));
    assert!(handle.bit(7));   // LSB of byte 0
}

// --- MemberLeaf tests ---

#[test]
fn member_leaf_nfc_normalization() {
    let handle = make_handle(1);
    // e + combining acute accent (NFD) vs precomposed e-acute (NFC)
    let nfd = "e\u{0301}";
    let nfc = "\u{00E9}";
    let m1 = MemberLeaf::new(handle.clone(), nfd, "X", [1; 32], vec![[1; 32]]).unwrap();
    let m2 = MemberLeaf::new(handle, nfc, "X", [1; 32], vec![[1; 32]]).unwrap();
    assert_eq!(m1.name(), m2.name());
}

#[test]
fn member_leaf_devices_sorted() {
    let handle = make_handle(1);
    let d1 = [2u8; 32];
    let d2 = [1u8; 32];
    let leaf = MemberLeaf::new(handle, "A", "B", [0; 32], vec![d1, d2]).unwrap();
    assert_eq!(leaf.devices()[0], d2); // [1;32] < [2;32]
    assert_eq!(leaf.devices()[1], d1);
}

#[test]
fn member_leaf_too_many_devices() {
    let handle = make_handle(1);
    let devices: Vec<_> = (0..5).map(|i| [i; 32]).collect();
    let err = MemberLeaf::new(handle, "A", "B", [0; 32], devices);
    assert_eq!(err.unwrap_err(), OrgMembersError::DeviceSlotsFull);
}

#[test]
fn member_leaf_empty_devices() {
    let handle = make_handle(1);
    let err = MemberLeaf::new(handle, "A", "B", [0; 32], vec![]);
    assert_eq!(err.unwrap_err(), OrgMembersError::EmptyDeviceList);
}

#[test]
fn member_leaf_debug_redacts_pii() {
    let leaf = make_member(1);
    let debug = format!("{:?}", leaf);
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("Alice"));
    assert!(!debug.contains("Smith"));
}

// --- Deterministic root hash ---

#[test]
fn same_members_same_root_hash() {
    let members1: Vec<_> = (1..=5).map(make_member).collect();
    let members2: Vec<_> = (1..=5).map(make_member).collect();
    let trie1 = TestTrie::genesis(members1).unwrap();
    let trie2 = TestTrie::genesis(members2).unwrap();
    assert_eq!(trie1.root_hash(), trie2.root_hash());
}

#[test]
fn different_insertion_order_same_root() {
    let trie_ab = TestTrie::genesis(vec![make_member(1), make_member(2)]).unwrap();

    // Build same trie but insert in reverse order
    let trie_ba = TestTrie::genesis(vec![make_member(2), make_member(1)]).unwrap();

    assert_eq!(trie_ab.root_hash(), trie_ba.root_hash());
}

// --- Multiple mutations before recalculate ---

#[test]
fn batch_mutations_then_recalculate() {
    let trie = TestTrie::genesis(vec![make_member(1)]).unwrap();

    let trie = trie.upsert(make_member(2)).unwrap();
    let trie = trie.upsert(make_member(3)).unwrap();
    let trie = trie.upsert(make_member(4)).unwrap();
    let trie = trie.delete(&make_handle(1)).unwrap();

    let (trie, delta) = trie.recalculate().unwrap();

    assert_eq!(trie.member_count(), 3);
    assert!(!trie.contains(&make_handle(1)));
    assert!(trie.contains(&make_handle(2)));
    assert!(trie.contains(&make_handle(3)));
    assert!(trie.contains(&make_handle(4)));

    // Delta should capture all changes
    assert_eq!(delta.removed().len(), 1);
    assert_eq!(delta.upserted().len(), 3);
}
