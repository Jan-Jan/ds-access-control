use ed25519_dalek::SigningKey;
use org_members::hasher::Blake3Hasher;
use org_members::trie::OrgTrie;
use org_members::types::{DeviceKey, MemberId, MemberKey, MemberLeaf, RootHash};
use org_members::OrgMembersError;

type TestTrie = OrgTrie<Blake3Hasher>;

/// Deterministically derives a MemberId from a seed string for test reproducibility.
fn member_id(seed: &str) -> MemberId {
    let hash: [u8; 32] = blake3::hash(seed.as_bytes()).into();
    MemberId::new(hash)
}

fn member_key(seed: &str) -> MemberKey {
    let mut bytes = [0u8; 32];
    let hash: [u8; 32] = blake3::hash(seed.as_bytes()).into();
    bytes.copy_from_slice(&hash);
    MemberKey::new(SigningKey::from_bytes(&bytes).verifying_key())
}

fn device_key(seed: &str) -> DeviceKey {
    let mut bytes = [0u8; 32];
    let hash: [u8; 32] = blake3::hash(seed.as_bytes()).into();
    bytes.copy_from_slice(&hash);
    DeviceKey::new(SigningKey::from_bytes(&bytes).verifying_key())
}

fn alice() -> MemberLeaf {
    MemberLeaf::new(
        member_id("alice-id"),
        "alice",
        member_key("alice-mk"),
        "Alice",
        "Smith",
        [1; 32],
        vec![device_key("alice-d1")],
    )
    .unwrap()
}

fn bob() -> MemberLeaf {
    MemberLeaf::new(
        member_id("bob-id"),
        "bob",
        member_key("bob-mk"),
        "Bob",
        "Jones",
        [2; 32],
        vec![device_key("bob-d1")],
    )
    .unwrap()
}

fn charlie() -> MemberLeaf {
    MemberLeaf::new(
        member_id("charlie-id"),
        "charlie",
        member_key("charlie-mk"),
        "Charlie",
        "Brown",
        [3; 32],
        vec![device_key("charlie-d1")],
    )
    .unwrap()
}

fn jan_jan() -> MemberLeaf {
    MemberLeaf::new(
        member_id("jan-jan-id"),
        "jan-jan",
        member_key("jan-jan-mk"),
        "Jan-Jan",
        "Gödel",
        [4; 32],
        vec![device_key("jan-jan-d1"), device_key("jan-jan-d2")],
    )
    .unwrap()
}

fn diana() -> MemberLeaf {
    MemberLeaf::new(
        member_id("diana-id"),
        "diana",
        member_key("diana-mk"),
        "Diana",
        "Prince",
        [5; 32],
        vec![device_key("diana-d1")],
    )
    .unwrap()
}

// --- Genesis tests ---

#[test]
fn genesis_single_member() {
    let trie = TestTrie::genesis(vec![alice()]).unwrap();
    assert_eq!(trie.member_count(), 1);
    assert!(trie.is_calculated());
    assert!(trie.contains(&member_id("alice-id")));
    assert!(!trie.contains(&member_id("bob-id")));
}

#[test]
fn genesis_multiple_members() {
    let trie = TestTrie::genesis(vec![alice(), bob(), charlie(), jan_jan(), diana()]).unwrap();
    assert_eq!(trie.member_count(), 5);
    assert!(trie.contains_handle("alice"));
    assert!(trie.contains_handle("bob"));
    assert!(trie.contains_handle("charlie"));
    assert!(trie.contains_handle("jan-jan"));
    assert!(trie.contains_handle("diana"));
}

#[test]
fn genesis_duplicate_id_fails() {
    let err = TestTrie::genesis(vec![alice(), alice()]);
    assert_eq!(err.unwrap_err(), OrgMembersError::DuplicateId);
}

#[test]
fn genesis_duplicate_handle_different_id_fails() {
    let m1 = alice();
    let m2 = MemberLeaf::new(
        member_id("different-id"),
        "alice", // same handle as m1
        member_key("different-mk"),
        "Alice2",
        "Different",
        [99; 32],
        vec![device_key("d")],
    )
    .unwrap();
    let err = TestTrie::genesis(vec![m1, m2]);
    assert_eq!(err.unwrap_err(), OrgMembersError::DuplicateHandle);
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
    assert!(trie.contains_handle("bob"));

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
fn insert_duplicate_handle_different_id_fails() {
    let trie = TestTrie::genesis(vec![alice()]).unwrap();
    let imposter = MemberLeaf::new(
        member_id("imposter-id"),
        "alice",
        member_key("imposter-mk"),
        "I'm",
        "Alice",
        [99; 32],
        vec![device_key("imposter-d")],
    )
    .unwrap();
    let err = trie.insert(imposter);
    assert_eq!(err.unwrap_err(), OrgMembersError::DuplicateHandle);
}

// --- Update tests ---

#[test]
fn update_existing_member() {
    let trie = TestTrie::genesis(vec![alice()]).unwrap();
    let root_before = trie.root_hash().unwrap();

    // Update alice with new key, surname, device (same id, same handle)
    let updated = MemberLeaf::new(
        member_id("alice-id"),
        "alice",
        member_key("alice-rotated-mk"),
        "Alice",
        "Wonderland",
        [42; 32],
        vec![device_key("alice-new-d")],
    )
    .unwrap();
    let trie = trie.update(updated).unwrap();
    let (trie, _) = trie.recalculate().unwrap();

    assert_eq!(trie.member_count(), 1);
    let member = trie.get(&member_id("alice-id")).unwrap();
    assert_eq!(member.surname(), "Wonderland");
    assert_eq!(member.key(), &member_key("alice-rotated-mk"));
    assert_ne!(trie.root_hash().unwrap(), root_before);
}

#[test]
fn update_nonexistent_fails() {
    let trie = TestTrie::genesis(vec![alice()]).unwrap();
    let err = trie.update(bob());
    assert_eq!(err.unwrap_err(), OrgMembersError::IdNotFound);
}

#[test]
fn update_handle_change() {
    let trie = TestTrie::genesis(vec![alice()]).unwrap();
    let renamed = MemberLeaf::new(
        member_id("alice-id"),
        "alicia",
        member_key("alice-mk"),
        "Alice",
        "Smith",
        [1; 32],
        vec![device_key("alice-d1")],
    )
    .unwrap();
    let trie = trie.update(renamed).unwrap();
    let (trie, _) = trie.recalculate().unwrap();

    assert!(!trie.contains_handle("alice"));
    assert!(trie.contains_handle("alicia"));
    assert!(trie.contains(&member_id("alice-id")));
}

// --- Delete tests ---

#[test]
fn delete_removes_member() {
    let trie = TestTrie::genesis(vec![alice(), bob()]).unwrap();
    let trie = trie.delete(&member_id("alice-id")).unwrap();
    let (trie, delta) = trie.recalculate().unwrap();

    assert_eq!(trie.member_count(), 1);
    assert!(!trie.contains_handle("alice"));
    assert!(trie.contains_handle("bob"));
    assert_eq!(delta.removed().len(), 1);
}

#[test]
fn delete_nonexistent_fails() {
    let trie = TestTrie::genesis(vec![alice()]).unwrap();
    let err = trie.delete(&member_id("eve-id"));
    assert_eq!(err.unwrap_err(), OrgMembersError::IdNotFound);
}

// --- Immutability tests ---

#[test]
fn insert_does_not_mutate_original() {
    let original = TestTrie::genesis(vec![alice()]).unwrap();
    let original_root = original.root_hash().unwrap();
    let _modified = original.insert(bob()).unwrap();

    assert_eq!(original.member_count(), 1);
    assert_eq!(original.root_hash().unwrap(), original_root);
    assert!(!original.contains_handle("bob"));
}

#[test]
fn delete_does_not_mutate_original() {
    let original = TestTrie::genesis(vec![alice(), bob()]).unwrap();
    let original_root = original.root_hash().unwrap();
    let _modified = original.delete(&member_id("alice-id")).unwrap();

    assert_eq!(original.member_count(), 2);
    assert_eq!(original.root_hash().unwrap(), original_root);
    assert!(original.contains_handle("alice"));
}

// --- Delta and CandidateTrie tests ---

#[test]
fn delta_apply_and_verify() {
    let trie = TestTrie::genesis(vec![alice(), bob()]).unwrap();

    let updated = trie.insert(charlie()).unwrap();
    let updated = updated.delete(&member_id("alice-id")).unwrap();
    let (updated, delta) = updated.recalculate().unwrap();

    let candidate = trie.apply_delta(&delta).unwrap();
    let verified = candidate.verify_against(&updated.root_hash().unwrap()).unwrap();

    assert_eq!(verified.root_hash().unwrap(), updated.root_hash().unwrap());
    assert_eq!(verified.member_count(), 2);
    assert!(!verified.contains_handle("alice"));
    assert!(verified.contains_handle("bob"));
    assert!(verified.contains_handle("charlie"));
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
    let current = current.delete(&member_id("alice-id")).unwrap();
    let (current, _) = current.recalculate().unwrap();

    let catchup_delta = current.diff_from(&old_trie).unwrap();

    let candidate = old_trie.apply_delta(&catchup_delta).unwrap();
    let verified = candidate.verify_against(&current.root_hash().unwrap()).unwrap();

    assert_eq!(verified.root_hash().unwrap(), current.root_hash().unwrap());
}

// --- Members iteration ---

#[test]
fn members_returns_all() {
    let trie = TestTrie::genesis(vec![alice(), bob(), charlie(), jan_jan(), diana()]).unwrap();
    let all = trie.members();
    assert_eq!(all.len(), 5);
}

// --- Handle validation tests ---

fn leaf_with_handle(handle: &str) -> Result<MemberLeaf, OrgMembersError> {
    MemberLeaf::new(
        member_id("k"),
        handle,
        member_key("k"),
        "A",
        "B",
        [0; 32],
        vec![device_key("d")],
    )
}

#[test]
fn handle_valid_ascii() {
    assert!(leaf_with_handle("alice").is_ok());
    assert!(leaf_with_handle("bob-jones").is_ok());
}

#[test]
fn handle_empty_rejected() {
    assert!(leaf_with_handle("").is_err());
}

#[test]
fn handle_dot_rejected() {
    assert!(leaf_with_handle("alice.bob").is_err());
}

#[test]
fn handle_uppercase_rejected() {
    assert!(leaf_with_handle("Alice").is_err());
    assert!(leaf_with_handle("BOB").is_err());
}

#[test]
fn handle_nfc_normalized() {
    let m1 = leaf_with_handle("e\u{0301}ric").unwrap();
    let m2 = leaf_with_handle("\u{00E9}ric").unwrap();
    assert_eq!(m1.handle(), m2.handle());
}

#[test]
fn handle_mixed_script_rejected() {
    let mixed = "\u{0430}lice"; // Cyrillic а + Latin lice
    assert!(leaf_with_handle(mixed).is_err());
}

#[test]
fn handle_single_script_unicode_ok() {
    assert!(leaf_with_handle("\u{0430}\u{043B}\u{0438}\u{0441}\u{0430}").is_ok());
}

#[test]
fn handle_hyphen_allowed() {
    assert!(leaf_with_handle("jan-jan").is_ok());
}

#[test]
fn handle_digits_allowed() {
    assert!(leaf_with_handle("alice42").is_ok());
}

// --- Confusable detection tests ---

#[test]
fn genesis_rejects_confusables() {
    // Find two handles whose UTS#39 skeletons match by probing candidates at runtime.
    // We can't hard-code a confusable pair safely because the skeleton table is
    // a library-controlled mapping that could shift. The test would silently pass
    // if our pair stopped being confusable. Probe instead, then assert rejection.
    let (h1, h2) = find_confusable_pair()
        .expect("test setup: no confusable pair found among candidates");

    let m1 = MemberLeaf::new(
        member_id("k1"),
        &h1,
        member_key("k1"),
        "A",
        "B",
        [0; 32],
        vec![device_key("d1")],
    )
    .unwrap();
    let m2 = MemberLeaf::new(
        member_id("k2"),
        &h2,
        member_key("k2"),
        "A",
        "B",
        [0; 32],
        vec![device_key("d2")],
    )
    .unwrap();
    let err = TestTrie::genesis(vec![m1, m2]).unwrap_err();
    assert_eq!(err, OrgMembersError::ConfusableHandle);
}

#[test]
fn insert_rejects_confusable_handle() {
    let (h1, h2) =
        find_confusable_pair().expect("test setup: no confusable pair found among candidates");
    let m1 = MemberLeaf::new(
        member_id("k1"),
        &h1,
        member_key("k1"),
        "A",
        "B",
        [0; 32],
        vec![device_key("d1")],
    )
    .unwrap();
    let m2 = MemberLeaf::new(
        member_id("k2"),
        &h2,
        member_key("k2"),
        "A",
        "B",
        [0; 32],
        vec![device_key("d2")],
    )
    .unwrap();

    let trie = TestTrie::genesis(vec![m1]).unwrap();
    let err = trie.insert(m2).unwrap_err();
    assert_eq!(err, OrgMembersError::ConfusableHandle);
}

#[test]
fn update_rejects_confusable_handle() {
    let (h1, h2) =
        find_confusable_pair().expect("test setup: no confusable pair found among candidates");
    // Two members, neither confusable initially.
    let m1 = MemberLeaf::new(
        member_id("k1"),
        &h1,
        member_key("k1"),
        "A",
        "B",
        [0; 32],
        vec![device_key("d1")],
    )
    .unwrap();
    let m2 = alice();

    let trie = TestTrie::genesis(vec![m1, m2]).unwrap();

    // Now try to update alice's handle to a confusable of h1.
    let renamed = MemberLeaf::new(
        member_id("alice-id"),
        &h2,
        member_key("alice-mk"),
        "Alice",
        "Smith",
        [1; 32],
        vec![device_key("alice-d1")],
    )
    .unwrap();
    let err = trie.update(renamed).unwrap_err();
    assert_eq!(err, OrgMembersError::ConfusableHandle);
}

/// Searches a small pool of candidate handles for a pair with matching UTS#39
/// skeletons, suitable for confusable-detection tests. Returns None if no
/// pair was found (in which case the test will skip / signal a setup issue).
fn find_confusable_pair() -> Option<(String, String)> {
    use org_members::types::handle_skeleton;
    // Candidates passing handle validation (lowercase, no '.', valid identifier chars).
    let candidates = [
        "paypal", "paypa1", "h0use", "house", "g00gle", "google", "ab1", "abl", "amaz0n", "amazon",
        "g0t", "got", "0lice", "olice", "01ice", "alice",
    ];
    for (i, &a) in candidates.iter().enumerate() {
        let sk_a = handle_skeleton(a);
        for &b in &candidates[i + 1..] {
            if a != b && sk_a == handle_skeleton(b) {
                return Some((a.to_string(), b.to_string()));
            }
        }
    }
    None
}

// --- MemberLeaf tests ---

#[test]
fn member_leaf_nfc_normalization() {
    let m1 = MemberLeaf::new(
        member_id("k"),
        "alice",
        member_key("k"),
        "e\u{0301}",
        "X",
        [1; 32],
        vec![device_key("d")],
    )
    .unwrap();
    let m2 = MemberLeaf::new(
        member_id("k"),
        "alice",
        member_key("k"),
        "\u{00E9}",
        "X",
        [1; 32],
        vec![device_key("d")],
    )
    .unwrap();
    assert_eq!(m1.name(), m2.name());
}

#[test]
fn member_leaf_too_many_devices() {
    let devices: Vec<_> = (0..5).map(|i| device_key(&format!("d{}", i))).collect();
    let err = MemberLeaf::new(
        member_id("k"),
        "alice",
        member_key("k"),
        "Alice",
        "Smith",
        [0; 32],
        devices,
    );
    assert_eq!(err.unwrap_err(), OrgMembersError::DeviceSlotsFull);
}

#[test]
fn member_leaf_empty_devices() {
    let err = MemberLeaf::new(
        member_id("k"),
        "alice",
        member_key("k"),
        "Alice",
        "Smith",
        [0; 32],
        vec![],
    );
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
fn member_leaf_has_id_handle_and_key() {
    let leaf = alice();
    assert_eq!(leaf.id(), &member_id("alice-id"));
    assert_eq!(leaf.handle(), "alice");
    assert_eq!(leaf.key(), &member_key("alice-mk"));
}

// --- Deterministic root hash ---

#[test]
fn same_members_same_root_hash() {
    let trie1 = TestTrie::genesis(vec![alice(), bob(), charlie()]).unwrap();
    let trie2 = TestTrie::genesis(vec![alice(), bob(), charlie()]).unwrap();
    assert_eq!(trie1.root_hash().unwrap(), trie2.root_hash().unwrap());
}

#[test]
fn different_insertion_order_same_root() {
    let trie_abc = TestTrie::genesis(vec![alice(), bob(), charlie()]).unwrap();
    let trie_cba = TestTrie::genesis(vec![charlie(), bob(), alice()]).unwrap();
    assert_eq!(trie_abc.root_hash().unwrap(), trie_cba.root_hash().unwrap());
}

// --- Multiple mutations before recalculate ---

#[test]
fn batch_mutations_then_recalculate() {
    let trie = TestTrie::genesis(vec![alice()]).unwrap();

    let trie = trie.insert(bob()).unwrap();
    let trie = trie.insert(charlie()).unwrap();
    let trie = trie.insert(jan_jan()).unwrap();
    let trie = trie.delete(&member_id("alice-id")).unwrap();

    let (trie, delta) = trie.recalculate().unwrap();

    assert_eq!(trie.member_count(), 3);
    assert!(!trie.contains_handle("alice"));
    assert!(trie.contains_handle("bob"));
    assert!(trie.contains_handle("charlie"));
    assert!(trie.contains_handle("jan-jan"));

    assert_eq!(delta.removed().len(), 1);
    assert_eq!(delta.upserted().len(), 3);
}

// --- Jan-Jan specific tests ---

#[test]
fn jan_jan_has_two_devices() {
    let trie = TestTrie::genesis(vec![jan_jan()]).unwrap();
    let member = trie.get_by_handle("jan-jan").unwrap();
    assert_eq!(member.device_count(), 2);
    assert_eq!(member.name(), "Jan-Jan");
    assert_eq!(member.surname(), "Gödel");
}

#[test]
fn member_lookup_by_id() {
    let trie = TestTrie::genesis(vec![alice(), bob(), jan_jan()]).unwrap();

    let found = trie.get(&member_id("jan-jan-id")).unwrap();
    assert_eq!(found.name(), "Jan-Jan");

    let found = trie.get(&member_id("alice-id")).unwrap();
    assert_eq!(found.name(), "Alice");

    assert!(trie.get(&member_id("eve-id")).is_none());
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
    let pending = trie.pending_changes().unwrap();
    assert!(pending.is_empty());
    assert!(!trie.has_pending_changes());
}

#[test]
fn pending_changes_reflects_mutations() {
    let trie = TestTrie::genesis(vec![alice(), bob()]).unwrap();
    let trie = trie.insert(charlie()).unwrap();
    let trie = trie.insert(jan_jan()).unwrap();
    let trie = trie.delete(&member_id("alice-id")).unwrap();

    assert!(trie.has_pending_changes());

    let pending = trie.pending_changes().unwrap();
    assert_eq!(pending.removed().len(), 1);
    assert_eq!(pending.upserted().len(), 2);
    assert_eq!(
        pending.base_root(),
        &TestTrie::genesis(vec![alice(), bob()]).unwrap().root_hash().unwrap()
    );
}

#[test]
fn pending_changes_idempotent() {
    let trie = TestTrie::genesis(vec![alice()]).unwrap();
    let trie = trie.insert(bob()).unwrap();

    let pending1 = trie.pending_changes().unwrap();
    let pending2 = trie.pending_changes().unwrap();
    assert_eq!(pending1.upserted().len(), pending2.upserted().len());
    assert_eq!(pending1.removed().len(), pending2.removed().len());

    assert!(trie.has_pending_changes());
}

#[test]
fn pending_changes_matches_recalculate_delta() {
    let trie = TestTrie::genesis(vec![alice(), bob()]).unwrap();
    let trie = trie.insert(charlie()).unwrap();
    let trie = trie.delete(&member_id("alice-id")).unwrap();

    let preview = trie.pending_changes().unwrap();
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
    assert!(trie.pending_changes().unwrap().is_empty());
}

// --- Key rotation through delta (I-1) ---

#[test]
fn member_key_rotation_through_delta() {
    // Peer A and Peer B start with the same trie.
    let starting_members = vec![alice(), bob()];
    let trie_a = TestTrie::genesis(starting_members.clone()).unwrap();
    let trie_b = TestTrie::genesis(starting_members).unwrap();
    assert_eq!(trie_a.root_hash().unwrap(), trie_b.root_hash().unwrap());

    // Peer A rotates alice's MemberKey (handle and id unchanged).
    let rotated_alice = MemberLeaf::new(
        member_id("alice-id"),
        "alice",
        member_key("alice-rotated"),
        "Alice",
        "Smith",
        [1; 32],
        vec![device_key("alice-d1")],
    )
    .unwrap();
    let trie_a = trie_a.update(rotated_alice.clone()).unwrap();
    let (trie_a, delta) = trie_a.recalculate().unwrap();

    // Peer B applies the delta and verifies.
    let candidate = trie_b.apply_delta(&delta).unwrap();
    let trie_b = candidate.verify_against(&trie_a.root_hash().unwrap()).unwrap();

    // Both peers see the new key.
    let on_a = trie_a.get(&member_id("alice-id")).unwrap();
    let on_b = trie_b.get(&member_id("alice-id")).unwrap();
    assert_eq!(on_a.key(), &member_key("alice-rotated"));
    assert_eq!(on_b.key(), &member_key("alice-rotated"));
    assert_eq!(trie_a.root_hash().unwrap(), trie_b.root_hash().unwrap());
}

// --- Adversarial apply_delta (I-2) ---

#[test]
fn apply_delta_ignores_stale_removal() {
    let trie = TestTrie::genesis(vec![alice(), bob()]).unwrap();

    // Construct a delta that removes a member who doesn't exist.
    let ghost_id = member_id("ghost-id");
    let crafted = trie.delete(&member_id("alice-id")).unwrap();
    let (target, mut delta) = crafted.recalculate().unwrap();

    // Inject a stale removal of ghost-id into the delta.
    delta.removed_mut_for_test().push(ghost_id);

    // apply_delta must not underflow member_count, and the resulting candidate
    // must verify against the target trie (which doesn't include ghost-id).
    let candidate = trie.apply_delta(&delta).unwrap();
    let result = candidate.verify_against(&target.root_hash().unwrap()).unwrap();
    assert_eq!(result.member_count(), target.member_count());
}

#[test]
fn apply_delta_rejects_confusable_in_upsert() {
    let (h1, h2) =
        find_confusable_pair().expect("test setup: no confusable pair found among candidates");

    // Receiver trie holds a member with handle h1.
    let m1 = MemberLeaf::new(
        member_id("k1"),
        &h1,
        member_key("k1"),
        "A",
        "B",
        [0; 32],
        vec![device_key("d1")],
    )
    .unwrap();
    let trie = TestTrie::genesis(vec![m1]).unwrap();

    // Craft an adversarial delta whose base matches `trie` but adds a confusable.
    // Start from a real delta to get the right base_root, then swap the upserts.
    let (_, mut delta) = trie.insert(bob()).unwrap().recalculate().unwrap();
    delta.removed_mut_for_test().clear();
    delta.upserted_mut_for_test().clear();
    delta.upserted_mut_for_test().push(
        MemberLeaf::new(
            member_id("k2"),
            &h2,
            member_key("k2"),
            "A",
            "B",
            [0; 32],
            vec![device_key("d2")],
        )
        .unwrap(),
    );

    let err = trie.apply_delta(&delta).unwrap_err();
    assert_eq!(err, OrgMembersError::ConfusableHandle);
}

// --- Send + Sync (recommendation 4) ---

#[test]
fn orgtrie_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<OrgTrie<Blake3Hasher>>();
    assert_send_sync::<MemberLeaf>();
    assert_send_sync::<MemberId>();
    assert_send_sync::<MemberKey>();
    assert_send_sync::<DeviceKey>();
}

// --- Serde validation (C-1) ---

#[cfg(feature = "serde")]
#[test]
fn deserialize_rejects_invalid_handle() {
    use postcard::{from_bytes, to_allocvec};
    let valid = alice();
    let bytes = to_allocvec(&valid).unwrap();

    // Round-trip the valid case to confirm baseline.
    let _: MemberLeaf = from_bytes(&bytes).unwrap();

    // Build a wire payload with an uppercase handle directly via the same
    // serde shape, bypassing MemberLeaf::new.
    #[derive(serde::Serialize)]
    struct EvilLeaf<'a> {
        id: MemberId,
        handle: &'a str,
        key: MemberKey,
        name: &'a str,
        surname: &'a str,
        group_pk: [u8; 32],
        devices: org_members::types::DeviceSlots,
    }

    let devices = {
        let leaf = alice();
        // Borrow the inner DeviceSlots via serde roundtrip.
        let dev_bytes = to_allocvec(&leaf).unwrap();
        let leaf2: MemberLeaf = from_bytes(&dev_bytes).unwrap();
        // Reconstruct DeviceSlots from leaf2.devices() by going through the
        // public new() — this is just a way to grab a valid DeviceSlots instance.
        org_members::types::DeviceSlots::new(leaf2.devices().to_vec()).unwrap()
    };

    let evil = EvilLeaf {
        id: *valid.id(),
        handle: "Alice",  // Uppercase -- should be rejected on deserialize.
        key: *valid.key(),
        name: "A",
        surname: "B",
        group_pk: *valid.group_pk(),
        devices,
    };
    let evil_bytes = to_allocvec(&evil).unwrap();
    let result: Result<MemberLeaf, _> = from_bytes(&evil_bytes);
    assert!(
        result.is_err(),
        "deserialize must reject MemberLeaf with uppercase handle"
    );
}

#[cfg(feature = "serde")]
#[test]
fn deserialize_rejects_empty_device_list() {
    use postcard::{from_bytes, to_allocvec};
    let empty_devices: Vec<DeviceKey> = vec![];
    let bytes = to_allocvec(&empty_devices).unwrap();
    let result: Result<org_members::types::DeviceSlots, _> = from_bytes(&bytes);
    assert!(result.is_err(), "deserialize must reject empty device list");
}
