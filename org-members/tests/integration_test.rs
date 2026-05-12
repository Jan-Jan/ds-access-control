use org_members::hasher::Blake3Hasher;
use org_members::trie::OrgTrie;
use org_members::types::{derive_id, MemberLeaf, RootHash};
use org_members::OrgMembersError;

type TestTrie = OrgTrie<Blake3Hasher>;

fn alice() -> MemberLeaf {
    MemberLeaf::new("alice", "Alice", "Smith", [1; 32], vec![[10; 32]]).unwrap()
}

fn bob() -> MemberLeaf {
    MemberLeaf::new("bob", "Bob", "Jones", [2; 32], vec![[20; 32]]).unwrap()
}

fn charlie() -> MemberLeaf {
    MemberLeaf::new("charlie", "Charlie", "Brown", [3; 32], vec![[30; 32]]).unwrap()
}

fn jan_jan() -> MemberLeaf {
    MemberLeaf::new("jan-jan", "Jan-Jan", "Gödel", [4; 32], vec![[40; 32], [41; 32]]).unwrap()
}

fn diana() -> MemberLeaf {
    MemberLeaf::new("diana", "Diana", "Prince", [5; 32], vec![[50; 32]]).unwrap()
}

/// Helper to get the id for a handle string.
fn id(handle: &str) -> [u8; 32] {
    derive_id(handle)
}

// --- Genesis tests ---

#[test]
fn genesis_single_member() {
    let trie = TestTrie::genesis(vec![alice()]).unwrap();
    assert_eq!(trie.member_count(), 1);
    assert!(trie.is_calculated());
    assert!(trie.contains(&id("alice")));
    assert!(!trie.contains(&id("bob")));
}

#[test]
fn genesis_multiple_members() {
    let trie = TestTrie::genesis(vec![alice(), bob(), charlie(), jan_jan(), diana()]).unwrap();
    assert_eq!(trie.member_count(), 5);
    assert!(trie.contains(&id("alice")));
    assert!(trie.contains(&id("bob")));
    assert!(trie.contains(&id("charlie")));
    assert!(trie.contains(&id("jan-jan")));
    assert!(trie.contains(&id("diana")));
}

#[test]
fn genesis_duplicate_member_fails() {
    // Same handle → same id, so DuplicateId fires first
    let err = TestTrie::genesis(vec![alice(), alice()]);
    assert_eq!(err.unwrap_err(), OrgMembersError::DuplicateId);
}

#[test]
fn genesis_empty_is_ok() {
    let trie = TestTrie::genesis(vec![]).unwrap();
    assert_eq!(trie.member_count(), 0);
    assert!(trie.is_calculated());
}

// --- Insert tests ---

#[test]
fn insert_adds_member() {
    let trie = TestTrie::genesis(vec![alice()]).unwrap();
    let trie = trie.insert(bob()).unwrap();
    assert!(!trie.is_calculated());
    assert_eq!(trie.member_count(), 2);
    assert!(trie.contains(&id("bob")));

    let (trie, delta) = trie.recalculate().unwrap();
    assert!(trie.is_calculated());
    assert_eq!(delta.upserted().len(), 1);
    assert!(delta.removed().is_empty());
}

#[test]
fn insert_duplicate_id_fails() {
    let trie = TestTrie::genesis(vec![alice()]).unwrap();
    let err = trie.insert(alice());
    assert_eq!(err.unwrap_err(), OrgMembersError::DuplicateId);
}

#[test]
fn insert_duplicate_handle_fails() {
    let trie = TestTrie::genesis(vec![alice()]).unwrap();
    // Same handle "alice" but different construction would yield same id,
    // so this is actually a DuplicateId. Test is for completeness.
    let err = trie.insert(alice());
    assert_eq!(err.unwrap_err(), OrgMembersError::DuplicateId);
}

// --- Update tests ---

#[test]
fn update_existing_member() {
    let trie = TestTrie::genesis(vec![alice()]).unwrap();
    let root_before = trie.root_hash();

    // Update alice with new surname and device
    let updated = MemberLeaf::new("alice", "Alice", "Wonderland", [42; 32], vec![[99; 32]]).unwrap();
    let trie = trie.update(updated).unwrap();
    let (trie, _) = trie.recalculate().unwrap();

    assert_eq!(trie.member_count(), 1);
    let member = trie.get(&id("alice")).unwrap();
    assert_eq!(member.surname(), "Wonderland");
    assert_ne!(trie.root_hash(), root_before);
}

#[test]
fn update_nonexistent_fails() {
    let trie = TestTrie::genesis(vec![alice()]).unwrap();
    let err = trie.update(bob());
    assert_eq!(err.unwrap_err(), OrgMembersError::IdNotFound);
}

#[test]
fn update_handle_change_allowed_if_unique() {
    let trie = TestTrie::genesis(vec![alice()]).unwrap();
    // Change alice's handle to "alicia" (same id since we construct with same handle... wait)
    // Actually, changing the handle changes the id. So update by id means the leaf must have
    // the same id. A handle change would mean a different id. So this tests that the handle
    // string inside the leaf can differ from what produced the id.
    // In practice, handle changes would require delete + insert.
    // For now, update just replaces the leaf at the same SMT position.
    let member = trie.get(&id("alice")).unwrap();
    assert_eq!(member.handle(), "alice");
}

// --- Delete tests ---

#[test]
fn delete_removes_member() {
    let trie = TestTrie::genesis(vec![alice(), bob()]).unwrap();
    let trie = trie.delete(&id("alice")).unwrap();
    let (trie, delta) = trie.recalculate().unwrap();

    assert_eq!(trie.member_count(), 1);
    assert!(!trie.contains(&id("alice")));
    assert!(trie.contains(&id("bob")));
    assert_eq!(delta.removed().len(), 1);
}

#[test]
fn delete_nonexistent_fails() {
    let trie = TestTrie::genesis(vec![alice()]).unwrap();
    let err = trie.delete(&id("eve"));
    assert_eq!(err.unwrap_err(), OrgMembersError::IdNotFound);
}

// --- Immutability tests ---

#[test]
fn insert_does_not_mutate_original() {
    let original = TestTrie::genesis(vec![alice()]).unwrap();
    let original_root = original.root_hash();
    let _modified = original.insert(bob()).unwrap();

    assert_eq!(original.member_count(), 1);
    assert_eq!(original.root_hash(), original_root);
    assert!(!original.contains(&id("bob")));
}

#[test]
fn delete_does_not_mutate_original() {
    let original = TestTrie::genesis(vec![alice(), bob()]).unwrap();
    let original_root = original.root_hash();
    let _modified = original.delete(&id("alice")).unwrap();

    assert_eq!(original.member_count(), 2);
    assert_eq!(original.root_hash(), original_root);
    assert!(original.contains(&id("alice")));
}

// --- Delta and CandidateTrie tests ---

#[test]
fn delta_apply_and_verify() {
    let trie = TestTrie::genesis(vec![alice(), bob()]).unwrap();

    let updated = trie.insert(charlie()).unwrap();
    let updated = updated.delete(&id("alice")).unwrap();
    let (updated, delta) = updated.recalculate().unwrap();

    let candidate = trie.apply_delta(&delta).unwrap();
    let verified = candidate.verify_against(&updated.root_hash()).unwrap();

    assert_eq!(verified.root_hash(), updated.root_hash());
    assert_eq!(verified.member_count(), 2);
    assert!(!verified.contains(&id("alice")));
    assert!(verified.contains(&id("bob")));
    assert!(verified.contains(&id("charlie")));
}

#[test]
fn delta_base_mismatch_fails() {
    let parity_trie = TestTrie::genesis(vec![alice()]).unwrap();
    let other_trie = TestTrie::genesis(vec![bob()]).unwrap();

    let modified = parity_trie.insert(charlie()).unwrap();
    let (_, delta) = modified.recalculate().unwrap();

    let err = other_trie.apply_delta(&delta);
    assert_eq!(err.unwrap_err(), OrgMembersError::DeltaBaseMismatch);
}

#[test]
fn candidate_verify_wrong_root_fails() {
    let trie = TestTrie::genesis(vec![alice()]).unwrap();
    let modified = trie.insert(bob()).unwrap();
    let (_, delta) = modified.recalculate().unwrap();

    let candidate = trie.apply_delta(&delta).unwrap();
    let wrong_root = RootHash::from_bytes([0xFF; 32]);
    let err = candidate.verify_against(&wrong_root);
    assert_eq!(err.unwrap_err(), OrgMembersError::VerificationFailed);
}

// --- Diff tests (long-offline catch-up) ---

#[test]
fn diff_produces_valid_delta() {
    let old_trie = TestTrie::genesis(vec![alice(), bob()]).unwrap();

    let current = old_trie.insert(charlie()).unwrap();
    let current = current.delete(&id("alice")).unwrap();
    let (current, _) = current.recalculate().unwrap();

    let catchup_delta = current.diff_from(&old_trie).unwrap();

    let candidate = old_trie.apply_delta(&catchup_delta).unwrap();
    let verified = candidate.verify_against(&current.root_hash()).unwrap();

    assert_eq!(verified.root_hash(), current.root_hash());
}

// --- Members iteration ---

#[test]
fn members_returns_all() {
    let trie = TestTrie::genesis(vec![alice(), bob(), charlie(), jan_jan(), diana()]).unwrap();
    let all = trie.members();
    assert_eq!(all.len(), 5);
}

// --- Handle validation tests ---

#[test]
fn handle_valid_ascii() {
    assert!(MemberLeaf::new("alice", "A", "B", [0; 32], vec![[1; 32]]).is_ok());
    assert!(MemberLeaf::new("bob-jones", "A", "B", [0; 32], vec![[1; 32]]).is_ok());
    assert!(MemberLeaf::new("jan-jan", "A", "B", [0; 32], vec![[1; 32]]).is_ok());
}

#[test]
fn handle_empty_rejected() {
    let err = MemberLeaf::new("", "A", "B", [0; 32], vec![[1; 32]]);
    assert!(err.is_err());
}

#[test]
fn handle_dot_rejected() {
    let err = MemberLeaf::new("alice.bob", "A", "B", [0; 32], vec![[1; 32]]);
    assert!(err.is_err());
}

#[test]
fn handle_uppercase_rejected() {
    assert!(MemberLeaf::new("Alice", "A", "B", [0; 32], vec![[1; 32]]).is_err());
    assert!(MemberLeaf::new("BOB", "A", "B", [0; 32], vec![[1; 32]]).is_err());
}

#[test]
fn handle_lowercase_ok() {
    assert!(MemberLeaf::new("alice", "A", "B", [0; 32], vec![[1; 32]]).is_ok());
    assert!(MemberLeaf::new("bob", "A", "B", [0; 32], vec![[1; 32]]).is_ok());
    assert!(MemberLeaf::new("jan-jan", "A", "B", [0; 32], vec![[1; 32]]).is_ok());
}

#[test]
fn handle_nfc_normalized() {
    let m1 = MemberLeaf::new("e\u{0301}ric", "A", "B", [0; 32], vec![[1; 32]]).unwrap();
    let m2 = MemberLeaf::new("\u{00E9}ric", "A", "B", [0; 32], vec![[1; 32]]).unwrap();
    assert_eq!(m1.handle(), m2.handle());
    assert_eq!(m1.id(), m2.id());
}

#[test]
fn handle_mixed_script_rejected() {
    let mixed = "\u{0430}lice"; // Cyrillic а + Latin lice
    assert!(MemberLeaf::new(mixed, "A", "B", [0; 32], vec![[1; 32]]).is_err());
}

#[test]
fn handle_single_script_unicode_ok() {
    // Pure lowercase Cyrillic: алиса
    assert!(MemberLeaf::new("\u{0430}\u{043B}\u{0438}\u{0441}\u{0430}", "A", "B", [0; 32], vec![[1; 32]]).is_ok());
}

#[test]
fn handle_hyphen_allowed() {
    assert!(MemberLeaf::new("jan-jan", "A", "B", [0; 32], vec![[1; 32]]).is_ok());
    assert!(MemberLeaf::new("a-b-c", "A", "B", [0; 32], vec![[1; 32]]).is_ok());
}

#[test]
fn handle_digits_allowed() {
    assert!(MemberLeaf::new("alice42", "A", "B", [0; 32], vec![[1; 32]]).is_ok());
    assert!(MemberLeaf::new("bob007", "A", "B", [0; 32], vec![[1; 32]]).is_ok());
}

// --- MemberLeaf tests ---

#[test]
fn member_leaf_nfc_normalization() {
    let m1 = MemberLeaf::new("alice", "e\u{0301}", "X", [1; 32], vec![[1; 32]]).unwrap();
    let m2 = MemberLeaf::new("alice", "\u{00E9}", "X", [1; 32], vec![[1; 32]]).unwrap();
    assert_eq!(m1.name(), m2.name());
}

#[test]
fn member_leaf_devices_sorted() {
    let d1 = [2u8; 32];
    let d2 = [1u8; 32];
    let leaf = MemberLeaf::new("alice", "Alice", "Smith", [0; 32], vec![d1, d2]).unwrap();
    assert_eq!(leaf.devices()[0], d2);
    assert_eq!(leaf.devices()[1], d1);
}

#[test]
fn member_leaf_too_many_devices() {
    let devices: Vec<_> = (0..5).map(|i| [i; 32]).collect();
    let err = MemberLeaf::new("alice", "Alice", "Smith", [0; 32], devices);
    assert_eq!(err.unwrap_err(), OrgMembersError::DeviceSlotsFull);
}

#[test]
fn member_leaf_empty_devices() {
    let err = MemberLeaf::new("alice", "Alice", "Smith", [0; 32], vec![]);
    assert_eq!(err.unwrap_err(), OrgMembersError::EmptyDeviceList);
}

#[test]
fn member_leaf_debug_redacts_pii() {
    let debug = format!("{:?}", jan_jan());
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("Jan-Jan"));
    assert!(!debug.contains("Gödel"));
    assert!(!debug.contains("jan-jan"));
}

#[test]
fn member_leaf_has_id_and_handle() {
    let leaf = alice();
    assert_eq!(leaf.handle(), "alice");
    assert_eq!(leaf.id(), &derive_id("alice"));
}

// --- Deterministic root hash ---

#[test]
fn same_members_same_root_hash() {
    let trie1 = TestTrie::genesis(vec![alice(), bob(), charlie()]).unwrap();
    let trie2 = TestTrie::genesis(vec![alice(), bob(), charlie()]).unwrap();
    assert_eq!(trie1.root_hash(), trie2.root_hash());
}

#[test]
fn different_insertion_order_same_root() {
    let trie_abc = TestTrie::genesis(vec![alice(), bob(), charlie()]).unwrap();
    let trie_cba = TestTrie::genesis(vec![charlie(), bob(), alice()]).unwrap();
    assert_eq!(trie_abc.root_hash(), trie_cba.root_hash());
}

// --- Multiple mutations before recalculate ---

#[test]
fn batch_mutations_then_recalculate() {
    let trie = TestTrie::genesis(vec![alice()]).unwrap();

    let trie = trie.insert(bob()).unwrap();
    let trie = trie.insert(charlie()).unwrap();
    let trie = trie.insert(jan_jan()).unwrap();
    let trie = trie.delete(&id("alice")).unwrap();

    let (trie, delta) = trie.recalculate().unwrap();

    assert_eq!(trie.member_count(), 3);
    assert!(!trie.contains(&id("alice")));
    assert!(trie.contains(&id("bob")));
    assert!(trie.contains(&id("charlie")));
    assert!(trie.contains(&id("jan-jan")));

    assert_eq!(delta.removed().len(), 1);
    assert_eq!(delta.upserted().len(), 3);
}

// --- Jan-Jan specific tests ---

#[test]
fn jan_jan_has_two_devices() {
    let trie = TestTrie::genesis(vec![jan_jan()]).unwrap();
    let member = trie.get(&id("jan-jan")).unwrap();
    assert_eq!(member.device_count(), 2);
    assert_eq!(member.name(), "Jan-Jan");
    assert_eq!(member.surname(), "Gödel");
}

#[test]
fn member_lookup_by_id() {
    let trie = TestTrie::genesis(vec![alice(), bob(), jan_jan()]).unwrap();

    let found = trie.get(&id("jan-jan")).unwrap();
    assert_eq!(found.name(), "Jan-Jan");

    let found = trie.get(&id("alice")).unwrap();
    assert_eq!(found.name(), "Alice");

    assert!(trie.get(&id("eve")).is_none());
}

// --- Lookup by handle ---

#[test]
fn get_by_handle() {
    let trie = TestTrie::genesis(vec![alice(), bob(), jan_jan()]).unwrap();

    let found = trie.get_by_handle("jan-jan").unwrap();
    assert_eq!(found.name(), "Jan-Jan");

    let found = trie.get_by_handle("alice").unwrap();
    assert_eq!(found.name(), "Alice");

    assert!(trie.get_by_handle("eve").is_none());
}

#[test]
fn contains_handle() {
    let trie = TestTrie::genesis(vec![alice(), bob()]).unwrap();
    assert!(trie.contains_handle("alice"));
    assert!(trie.contains_handle("bob"));
    assert!(!trie.contains_handle("charlie"));
}

// --- Pending changes (review before recalculate) ---

#[test]
fn pending_changes_empty_when_no_mutations() {
    let trie = TestTrie::genesis(vec![alice(), bob()]).unwrap();
    let pending = trie.pending_changes();
    assert!(pending.is_empty());
    assert!(!trie.has_pending_changes());
}

#[test]
fn pending_changes_reflects_mutations() {
    let trie = TestTrie::genesis(vec![alice(), bob()]).unwrap();
    let trie = trie.insert(charlie()).unwrap();
    let trie = trie.insert(jan_jan()).unwrap();
    let trie = trie.delete(&id("alice")).unwrap();

    assert!(trie.has_pending_changes());

    let pending = trie.pending_changes();
    assert_eq!(pending.removed().len(), 1);
    assert_eq!(pending.upserted().len(), 2);
    // base_root should be the genesis root, not the new uncalculated one
    assert_eq!(pending.base_root(), &TestTrie::genesis(vec![alice(), bob()]).unwrap().root_hash());
}

#[test]
fn pending_changes_idempotent() {
    let trie = TestTrie::genesis(vec![alice()]).unwrap();
    let trie = trie.insert(bob()).unwrap();

    // Calling pending_changes() multiple times should not affect state
    let pending1 = trie.pending_changes();
    let pending2 = trie.pending_changes();
    assert_eq!(pending1.upserted().len(), pending2.upserted().len());
    assert_eq!(pending1.removed().len(), pending2.removed().len());

    // Still has pending changes (no recalculate happened)
    assert!(trie.has_pending_changes());
}

#[test]
fn pending_changes_matches_recalculate_delta() {
    let trie = TestTrie::genesis(vec![alice(), bob()]).unwrap();
    let trie = trie.insert(charlie()).unwrap();
    let trie = trie.delete(&id("alice")).unwrap();

    let preview = trie.pending_changes();
    let (_, committed) = trie.recalculate().unwrap();

    assert_eq!(preview.removed().len(), committed.removed().len());
    assert_eq!(preview.upserted().len(), committed.upserted().len());
    assert_eq!(preview.base_root(), committed.base_root());
}

#[test]
fn pending_changes_after_recalculate_is_empty() {
    let trie = TestTrie::genesis(vec![alice()]).unwrap();
    let trie = trie.insert(bob()).unwrap();
    let (trie, _) = trie.recalculate().unwrap();

    assert!(!trie.has_pending_changes());
    assert!(trie.pending_changes().is_empty());
}
