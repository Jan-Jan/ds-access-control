use org_members::hasher::Blake3Hasher;
use org_members::trie::OrgTrie;
use org_members::types::{Handle, MemberLeaf, RootHash};
use org_members::OrgMembersError;

type TestTrie = OrgTrie<Blake3Hasher>;

/// Creates a handle from a human-readable name by hashing it into 32 bytes.
fn handle(name: &str) -> Handle {
    let hash: [u8; 32] = blake3::hash(name.as_bytes()).into();
    Handle::new(hash).unwrap()
}

fn alice() -> MemberLeaf {
    MemberLeaf::new(handle("alice"), "Alice", "Smith", [1; 32], vec![[10; 32]]).unwrap()
}

fn bob() -> MemberLeaf {
    MemberLeaf::new(handle("bob"), "Bob", "Jones", [2; 32], vec![[20; 32]]).unwrap()
}

fn charlie() -> MemberLeaf {
    MemberLeaf::new(handle("charlie"), "Charlie", "Brown", [3; 32], vec![[30; 32]]).unwrap()
}

fn jan_jan() -> MemberLeaf {
    MemberLeaf::new(
        handle("jan-jan"),
        "Jan-Jan",
        "Gödel",
        [4; 32],
        vec![[40; 32], [41; 32]],
    )
    .unwrap()
}

fn diana() -> MemberLeaf {
    MemberLeaf::new(handle("diana"), "Diana", "Prince", [5; 32], vec![[50; 32]]).unwrap()
}

// --- Genesis tests ---

#[test]
fn genesis_single_member() {
    let trie = TestTrie::genesis(vec![alice()]).unwrap();
    assert_eq!(trie.member_count(), 1);
    assert!(trie.is_calculated());
    assert!(trie.contains(&handle("alice")));
    assert!(!trie.contains(&handle("bob")));
}

#[test]
fn genesis_multiple_members() {
    let trie =
        TestTrie::genesis(vec![alice(), bob(), charlie(), jan_jan(), diana()]).unwrap();
    assert_eq!(trie.member_count(), 5);
    assert!(trie.contains(&handle("alice")));
    assert!(trie.contains(&handle("bob")));
    assert!(trie.contains(&handle("charlie")));
    assert!(trie.contains(&handle("jan-jan")));
    assert!(trie.contains(&handle("diana")));
}

#[test]
fn genesis_duplicate_handle_fails() {
    let err = TestTrie::genesis(vec![alice(), alice()]);
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
    let trie = TestTrie::genesis(vec![alice()]).unwrap();
    let trie = trie.upsert(bob()).unwrap();
    assert!(!trie.is_calculated());
    assert_eq!(trie.member_count(), 2);
    assert!(trie.contains(&handle("bob")));

    let (trie, delta) = trie.recalculate().unwrap();
    assert!(trie.is_calculated());
    assert_eq!(delta.upserted().len(), 1);
    assert!(delta.removed().is_empty());
}

#[test]
fn upsert_replaces_existing() {
    let trie = TestTrie::genesis(vec![alice()]).unwrap();
    let root_before = trie.root_hash();

    // Upsert alice with different data (new surname, new device)
    let updated_alice = MemberLeaf::new(
        handle("alice"),
        "Alice",
        "Wonderland",
        [42; 32],
        vec![[99; 32]],
    )
    .unwrap();
    let trie = trie.upsert(updated_alice).unwrap();
    let (trie, _) = trie.recalculate().unwrap();

    assert_eq!(trie.member_count(), 1);
    let member = trie.get(&handle("alice")).unwrap();
    assert_eq!(member.surname(), "Wonderland");
    assert_ne!(trie.root_hash(), root_before);
}

// --- Delete tests ---

#[test]
fn delete_removes_member() {
    let trie = TestTrie::genesis(vec![alice(), bob()]).unwrap();
    let trie = trie.delete(&handle("alice")).unwrap();
    let (trie, delta) = trie.recalculate().unwrap();

    assert_eq!(trie.member_count(), 1);
    assert!(!trie.contains(&handle("alice")));
    assert!(trie.contains(&handle("bob")));
    assert_eq!(delta.removed().len(), 1);
}

#[test]
fn delete_nonexistent_fails() {
    let trie = TestTrie::genesis(vec![alice()]).unwrap();
    let err = trie.delete(&handle("eve"));
    assert_eq!(err.unwrap_err(), OrgMembersError::HandleNotFound);
}

// --- Immutability tests ---

#[test]
fn upsert_does_not_mutate_original() {
    let original = TestTrie::genesis(vec![alice()]).unwrap();
    let original_root = original.root_hash();
    let _modified = original.upsert(bob()).unwrap();

    assert_eq!(original.member_count(), 1);
    assert_eq!(original.root_hash(), original_root);
    assert!(!original.contains(&handle("bob")));
}

#[test]
fn delete_does_not_mutate_original() {
    let original = TestTrie::genesis(vec![alice(), bob()]).unwrap();
    let original_root = original.root_hash();
    let _modified = original.delete(&handle("alice")).unwrap();

    assert_eq!(original.member_count(), 2);
    assert_eq!(original.root_hash(), original_root);
    assert!(original.contains(&handle("alice")));
}

// --- Delta and CandidateTrie tests ---

#[test]
fn delta_apply_and_verify() {
    let trie = TestTrie::genesis(vec![alice(), bob()]).unwrap();

    // Admin adds charlie, removes alice
    let updated = trie.upsert(charlie()).unwrap();
    let updated = updated.delete(&handle("alice")).unwrap();
    let (updated, delta) = updated.recalculate().unwrap();

    // Another member applies the delta
    let candidate = trie.apply_delta(&delta).unwrap();
    let verified = candidate.verify_against(&updated.root_hash()).unwrap();

    assert_eq!(verified.root_hash(), updated.root_hash());
    assert_eq!(verified.member_count(), 2);
    assert!(!verified.contains(&handle("alice")));
    assert!(verified.contains(&handle("bob")));
    assert!(verified.contains(&handle("charlie")));
}

#[test]
fn delta_base_mismatch_fails() {
    let parity_trie = TestTrie::genesis(vec![alice()]).unwrap();
    let other_trie = TestTrie::genesis(vec![bob()]).unwrap();

    let modified = parity_trie.upsert(charlie()).unwrap();
    let (_, delta) = modified.recalculate().unwrap();

    // Try to apply parity's delta to a completely different org
    let err = other_trie.apply_delta(&delta);
    assert_eq!(err.unwrap_err(), OrgMembersError::DeltaBaseMismatch);
}

#[test]
fn candidate_verify_wrong_root_fails() {
    let trie = TestTrie::genesis(vec![alice()]).unwrap();
    let modified = trie.upsert(bob()).unwrap();
    let (_, delta) = modified.recalculate().unwrap();

    let candidate = trie.apply_delta(&delta).unwrap();
    let wrong_root = RootHash::from_bytes([0xFF; 32]);
    let err = candidate.verify_against(&wrong_root);
    assert_eq!(err.unwrap_err(), OrgMembersError::VerificationFailed);
}

// --- Diff tests (long-offline catch-up) ---

#[test]
fn diff_produces_valid_delta() {
    // jan-jan's device has been offline for weeks with an old trie
    let old_trie = TestTrie::genesis(vec![alice(), bob()]).unwrap();

    // Meanwhile the org changed: charlie joined, alice left
    let current = old_trie.upsert(charlie()).unwrap();
    let current = current.delete(&handle("alice")).unwrap();
    let (current, _) = current.recalculate().unwrap();

    // jan-jan receives the complete new trie and diffs it against their stale copy
    let catchup_delta = current.diff_from(&old_trie).unwrap();

    // Applying the diff delta to the old trie reproduces the current trie
    let candidate = old_trie.apply_delta(&catchup_delta).unwrap();
    let verified = candidate.verify_against(&current.root_hash()).unwrap();

    assert_eq!(verified.root_hash(), current.root_hash());
}

// --- Members iteration ---

#[test]
fn members_returns_all() {
    let trie =
        TestTrie::genesis(vec![alice(), bob(), charlie(), jan_jan(), diana()]).unwrap();
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
    // e + combining acute accent (NFD) vs precomposed e-acute (NFC)
    let nfd = "e\u{0301}";
    let nfc = "\u{00E9}";
    let m1 = MemberLeaf::new(handle("alice"), nfd, "X", [1; 32], vec![[1; 32]]).unwrap();
    let m2 = MemberLeaf::new(handle("alice"), nfc, "X", [1; 32], vec![[1; 32]]).unwrap();
    assert_eq!(m1.name(), m2.name());
}

#[test]
fn member_leaf_devices_sorted() {
    let d1 = [2u8; 32];
    let d2 = [1u8; 32];
    let leaf = MemberLeaf::new(handle("alice"), "Alice", "Smith", [0; 32], vec![d1, d2]).unwrap();
    assert_eq!(leaf.devices()[0], d2); // [1;32] < [2;32]
    assert_eq!(leaf.devices()[1], d1);
}

#[test]
fn member_leaf_too_many_devices() {
    let devices: Vec<_> = (0..5).map(|i| [i; 32]).collect();
    let err = MemberLeaf::new(handle("alice"), "Alice", "Smith", [0; 32], devices);
    assert_eq!(err.unwrap_err(), OrgMembersError::DeviceSlotsFull);
}

#[test]
fn member_leaf_empty_devices() {
    let err = MemberLeaf::new(handle("alice"), "Alice", "Smith", [0; 32], vec![]);
    assert_eq!(err.unwrap_err(), OrgMembersError::EmptyDeviceList);
}

#[test]
fn member_leaf_debug_redacts_pii() {
    let debug = format!("{:?}", jan_jan());
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("Jan-Jan"));
    assert!(!debug.contains("Gödel"));
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

    let trie = trie.upsert(bob()).unwrap();
    let trie = trie.upsert(charlie()).unwrap();
    let trie = trie.upsert(jan_jan()).unwrap();
    let trie = trie.delete(&handle("alice")).unwrap();

    let (trie, delta) = trie.recalculate().unwrap();

    assert_eq!(trie.member_count(), 3);
    assert!(!trie.contains(&handle("alice")));
    assert!(trie.contains(&handle("bob")));
    assert!(trie.contains(&handle("charlie")));
    assert!(trie.contains(&handle("jan-jan")));

    assert_eq!(delta.removed().len(), 1);
    assert_eq!(delta.upserted().len(), 3);
}

// --- Jan-Jan specific tests ---

#[test]
fn jan_jan_has_two_devices() {
    let trie = TestTrie::genesis(vec![jan_jan()]).unwrap();
    let member = trie.get(&handle("jan-jan")).unwrap();
    assert_eq!(member.device_count(), 2);
    assert_eq!(member.name(), "Jan-Jan");
    assert_eq!(member.surname(), "Gödel");
}

#[test]
fn member_lookup_by_handle() {
    let trie = TestTrie::genesis(vec![alice(), bob(), jan_jan()]).unwrap();

    let found = trie.get(&handle("jan-jan")).unwrap();
    assert_eq!(found.name(), "Jan-Jan");

    let found = trie.get(&handle("alice")).unwrap();
    assert_eq!(found.name(), "Alice");

    assert!(trie.get(&handle("eve")).is_none());
}
