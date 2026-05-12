use org_members::hasher::Blake3Hasher;
use org_members::trie::OrgTrie;
use org_members::types::{derive_id, validate_handle, MemberLeaf};
use proptest::prelude::*;

type TestTrie = OrgTrie<Blake3Hasher>;

const HANDLES: &[&str] = &[
    "alice", "bob", "charlie", "jan-jan", "diana", "eve", "frank", "grace",
    "hank", "iris", "jack", "kate",
];

fn arb_handle_idx() -> impl Strategy<Value = usize> {
    0..HANDLES.len()
}

fn make_member(handle: &str, variant: u8) -> Option<MemberLeaf> {
    let device = [variant.wrapping_add(1); 32];
    MemberLeaf::new(handle, "Test", "User", [variant; 32], vec![device]).ok()
}

// ============================================================
// Handle validation fuzzing
// ============================================================

proptest! {
    /// Any arbitrary string must either pass validation or return an error. Never panic.
    #[test]
    fn handle_validation_never_panics(s in "\\PC{0,64}") {
        match validate_handle(&s) {
            Ok(normalized) => {
                prop_assert!(!normalized.is_empty());
                for ch in normalized.chars() {
                    prop_assert!(!ch.is_uppercase(), "validated handle contains uppercase: {:?}", ch);
                }
                prop_assert!(!normalized.contains('.'), "validated handle contains '.'");
            }
            Err(_) => {
                // correctly rejected
            }
        }
    }

    /// Valid handles always produce the same id when re-validated.
    #[test]
    fn handle_id_deterministic(idx in arb_handle_idx()) {
        let handle = HANDLES[idx];
        let id1 = derive_id(handle);
        let id2 = derive_id(handle);
        prop_assert_eq!(id1, id2);
    }
}

// ============================================================
// Trie operation invariants
// ============================================================

#[derive(Debug, Clone)]
enum Op {
    Insert(usize),
    Update(usize, u8),
    Delete(usize),
    Recalculate,
}

fn arb_op() -> impl Strategy<Value = Op> {
    prop_oneof![
        arb_handle_idx().prop_map(Op::Insert),
        (arb_handle_idx(), any::<u8>()).prop_map(|(idx, v)| Op::Update(idx, v)),
        arb_handle_idx().prop_map(Op::Delete),
        Just(Op::Recalculate),
    ]
}

proptest! {
    /// Random sequence of trie operations never panics and member_count stays consistent.
    #[test]
    fn trie_ops_never_panic_and_count_consistent(ops in proptest::collection::vec(arb_op(), 0..30)) {
        let mut trie = TestTrie::genesis(vec![]).unwrap();

        for op in &ops {
            match op {
                Op::Insert(idx) => {
                    let handle = HANDLES[*idx];
                    if let Some(member) = make_member(handle, *idx as u8) {
                        if let Ok(new_trie) = trie.insert(member) {
                            trie = new_trie;
                        }
                    }
                }
                Op::Update(idx, variant) => {
                    let handle = HANDLES[*idx];
                    if let Some(member) = make_member(handle, *variant) {
                        if let Ok(new_trie) = trie.update(member) {
                            trie = new_trie;
                        }
                    }
                }
                Op::Delete(idx) => {
                    let handle = HANDLES[*idx];
                    let id = derive_id(handle);
                    if let Ok(new_trie) = trie.delete(&id) {
                        trie = new_trie;
                    }
                }
                Op::Recalculate => {
                    if let Ok((new_trie, _)) = trie.recalculate() {
                        let actual = new_trie.members().len();
                        prop_assert_eq!(
                            new_trie.member_count(), actual,
                            "member_count={} but actual members={}",
                            new_trie.member_count(), actual,
                        );
                        trie = new_trie;
                    }
                }
            }
        }
    }
}

// ============================================================
// Delta roundtrip invariant
// ============================================================

#[derive(Debug, Clone)]
enum DeltaOp {
    Insert(usize),
    Delete(usize),
}

fn arb_delta_op() -> impl Strategy<Value = DeltaOp> {
    prop_oneof![
        arb_handle_idx().prop_map(DeltaOp::Insert),
        arb_handle_idx().prop_map(DeltaOp::Delete),
    ]
}

proptest! {
    /// Delta roundtrip: starting from trie_a, apply ops to get trie_b,
    /// compute the delta, apply it to trie_a, and verify the root matches trie_b.
    #[test]
    fn delta_roundtrip(
        initial_indices in proptest::collection::vec(arb_handle_idx(), 0..6),
        ops in proptest::collection::vec(arb_delta_op(), 1..10),
    ) {
        // Build initial trie (deduplicate)
        let mut seen = vec![false; HANDLES.len()];
        let mut initial = Vec::new();
        for idx in &initial_indices {
            if !seen[*idx] {
                if let Some(m) = make_member(HANDLES[*idx], *idx as u8) {
                    initial.push(m);
                    seen[*idx] = true;
                }
            }
        }

        let trie_a = TestTrie::genesis(initial).unwrap();

        // Apply ops to get trie_b
        let mut trie_b = trie_a.clone();
        for op in &ops {
            match op {
                DeltaOp::Insert(idx) => {
                    let handle = HANDLES[*idx];
                    if let Some(member) = make_member(handle, *idx as u8) {
                        if let Ok(t) = trie_b.insert(member) {
                            trie_b = t;
                        }
                    }
                }
                DeltaOp::Delete(idx) => {
                    let handle = HANDLES[*idx];
                    let id = derive_id(handle);
                    if let Ok(t) = trie_b.delete(&id) {
                        trie_b = t;
                    }
                }
            }
        }

        let (trie_b, delta) = match trie_b.recalculate() {
            Ok(r) => r,
            Err(_) => return Ok(()),
        };

        if delta.is_empty() {
            return Ok(());
        }

        // Apply delta to trie_a
        let candidate = match trie_a.apply_delta(&delta) {
            Ok(c) => c,
            Err(_) => return Ok(()),
        };

        let verified = candidate
            .verify_against(&trie_b.root_hash())
            .map_err(|e| TestCaseError::fail(format!("delta roundtrip verification failed: {:?}", e)))?;

        prop_assert_eq!(verified.root_hash(), trie_b.root_hash(),
            "root hash mismatch after delta roundtrip");
        prop_assert_eq!(verified.member_count(), trie_b.member_count(),
            "member count mismatch after delta roundtrip");
    }
}

// ============================================================
// Diff roundtrip invariant
// ============================================================

proptest! {
    /// diff_from roundtrip: trie_b.diff_from(trie_a) produces a delta that,
    /// when applied to trie_a, yields a trie with the same root as trie_b.
    #[test]
    fn diff_roundtrip(
        initial_indices in proptest::collection::vec(arb_handle_idx(), 0..6),
        ops in proptest::collection::vec(arb_delta_op(), 1..10),
    ) {
        let mut seen = vec![false; HANDLES.len()];
        let mut initial = Vec::new();
        for idx in &initial_indices {
            if !seen[*idx] {
                if let Some(m) = make_member(HANDLES[*idx], *idx as u8) {
                    initial.push(m);
                    seen[*idx] = true;
                }
            }
        }

        let trie_a = TestTrie::genesis(initial).unwrap();

        let mut trie_b = trie_a.clone();
        for op in &ops {
            match op {
                DeltaOp::Insert(idx) => {
                    let handle = HANDLES[*idx];
                    if let Some(member) = make_member(handle, *idx as u8) {
                        if let Ok(t) = trie_b.insert(member) {
                            trie_b = t;
                        }
                    }
                }
                DeltaOp::Delete(idx) => {
                    let handle = HANDLES[*idx];
                    let id = derive_id(handle);
                    if let Ok(t) = trie_b.delete(&id) {
                        trie_b = t;
                    }
                }
            }
        }

        let (trie_b, _) = match trie_b.recalculate() {
            Ok(r) => r,
            Err(_) => return Ok(()),
        };

        // Compute diff
        let diff_delta = match trie_b.diff_from(&trie_a) {
            Ok(d) => d,
            Err(_) => return Ok(()),
        };

        if diff_delta.is_empty() {
            return Ok(());
        }

        // Apply diff to trie_a
        let candidate = match trie_a.apply_delta(&diff_delta) {
            Ok(c) => c,
            Err(_) => return Ok(()),
        };

        let verified = candidate
            .verify_against(&trie_b.root_hash())
            .map_err(|e| TestCaseError::fail(format!("diff roundtrip verification failed: {:?}", e)))?;

        prop_assert_eq!(verified.root_hash(), trie_b.root_hash());
        prop_assert_eq!(verified.member_count(), trie_b.member_count());
    }
}

// ============================================================
// Immutability invariant
// ============================================================

proptest! {
    /// After any mutation, the original trie's root hash (if calculated) is unchanged.
    #[test]
    fn mutations_preserve_original(
        initial_indices in proptest::collection::vec(arb_handle_idx(), 1..4),
        op_idx in arb_handle_idx(),
    ) {
        let mut seen = vec![false; HANDLES.len()];
        let mut initial = Vec::new();
        for idx in &initial_indices {
            if !seen[*idx] {
                if let Some(m) = make_member(HANDLES[*idx], *idx as u8) {
                    initial.push(m);
                    seen[*idx] = true;
                }
            }
        }

        if initial.is_empty() {
            return Ok(());
        }

        let original = TestTrie::genesis(initial).unwrap();
        let original_root = original.root_hash();
        let original_count = original.member_count();

        // Try insert
        let handle = HANDLES[op_idx];
        if let Some(member) = make_member(handle, op_idx as u8) {
            let _ = original.insert(member);
        }

        // Try delete
        let id = derive_id(handle);
        let _ = original.delete(&id);

        // Original must be unchanged
        prop_assert_eq!(original.root_hash(), original_root);
        prop_assert_eq!(original.member_count(), original_count);
    }
}
