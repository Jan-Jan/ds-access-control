# org-members Hyperbridge Security Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Apply the H-1 / H-2 / H-3 / M-1 / M-2 / M-3 / Info-4 findings from the [Hyperbridge review spec](../specs/2026-05-28-org-members-hyperbridge-review.md) to the `org-members` crate, establishing the canonical-form invariant at the `apply_delta` trust boundary.

**Architecture:** All fixes are additive guards at trust boundaries. Honest deltas produced by `recalculate()`, `calculate_delta()`, and `pending_changes()` already satisfy the new invariants (see `diff_recursive` in `src/smt.rs`), so no existing functionality regresses — the strict checks only reject adversarial inputs. Each task is TDD: failing test → minimal implementation → green → commit.

**Tech Stack:** Rust 1.81, `no_std`+`alloc`, `thiserror` 2.x (no `#[from]`/`#[source]`), `proptest`, `postcard`.

**Working directory:** `org-members/` crate root. Build/test commands assume `cd org-members` (or run with `-p org-members` from workspace root).

---

## File Structure

Files modified by this plan:

- `org-members/src/error.rs` — add two error variants (`MalformedDelta`, `FieldTooLong`)
- `org-members/src/types.rs` — add `MAX_NAME_LEN`/`MAX_SURNAME_LEN`, length checks in `MemberLeaf::new` + deserialize, strict `P2pDeviceSlots` deserialize
- `org-members/src/trie.rs` — strict canonical checks in `apply_delta`; checked arithmetic for `member_count`
- `org-members/src/delta.rs` — doc-block on `Delta` declaring the canonical-form invariant and upstream responsibilities
- `org-members/tests/integration_test.rs` — flip `apply_delta_ignores_stale_removal`; add sibling rejection tests; add H-2 / H-3 boundary tests
- `org-members/tests/fuzz_tests.rs` — add `delta_canonicality_fuzz`

No new files. No `Cargo.toml` changes.

---

### Task 1: Add `MalformedDelta` and `FieldTooLong` error variants

**Files:**
- Modify: `org-members/src/error.rs`

- [ ] **Step 1: Write the failing tests**

Append to `org-members/tests/integration_test.rs`:

```rust
// --- Error variant smoke tests (Task 1 of Hyperbridge fixes) ---

#[test]
fn malformed_delta_error_displays_reason() {
    let err = OrgMembersError::MalformedDelta("test reason");
    assert_eq!(format!("{}", err), "malformed delta: test reason");
}

#[test]
fn field_too_long_error_displays_field_and_max() {
    let err = OrgMembersError::FieldTooLong { field: "name", max: 128 };
    assert_eq!(format!("{}", err), "field too long: name exceeds 128 bytes after NFC normalization");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd org-members && cargo test --test integration_test malformed_delta_error -- --exact 2>&1 | tail -20`

Expected: compile error — `MalformedDelta` and `FieldTooLong` variants don't exist.

- [ ] **Step 3: Add the variants**

Edit `org-members/src/error.rs`, replacing the existing `OrgMembersError` enum with:

```rust
use alloc::string::String;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OrgMembersError {
    #[error("duplicate handle")]
    DuplicateHandle,

    #[error("duplicate member id")]
    DuplicateId,

    #[error("member id not found")]
    IdNotFound,

    #[error("invalid handle: {0}")]
    InvalidHandle(String),

    #[error("confusable handle")]
    ConfusableHandle,

    #[error("duplicate device")]
    DuplicateDevice,

    #[error("device not found")]
    DeviceNotFound,

    #[error("device slots full (max 4)")]
    DeviceSlotsFull,

    #[error("member must have at least one device")]
    EmptyDeviceList,

    #[error("delta base root mismatch")]
    DeltaBaseMismatch,

    #[error("verification failed")]
    VerificationFailed,

    #[error("serialization error")]
    SerializationError,

    #[error("hashes not calculated")]
    HashesNotCalculated,

    #[error("internal invariant violated")]
    InvariantViolated,

    #[error("malformed delta: {0}")]
    MalformedDelta(&'static str),

    #[error("field too long: {field} exceeds {max} bytes after NFC normalization")]
    FieldTooLong { field: &'static str, max: usize },
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd org-members && cargo test --test integration_test malformed_delta_error field_too_long -- --exact`

Expected: both tests pass.

- [ ] **Step 5: Run the full suite to confirm no regression**

Run: `cd org-members && cargo test`

Expected: all existing tests still pass (count unchanged from baseline).

- [ ] **Step 6: Commit**

```bash
cd org-members
git add src/error.rs tests/integration_test.rs
git -c commit.gpgsign=false commit -m "org-members: add MalformedDelta and FieldTooLong error variants

Prerequisites for Hyperbridge-review H-1 (canonical delta) and H-3
(name/surname length cap). No behavioral changes yet."
```

---

### Task 2: H-3 — Length cap on `name` and `surname`

**Files:**
- Modify: `org-members/src/types.rs`
- Modify: `org-members/tests/integration_test.rs`

- [ ] **Step 1: Write the failing tests**

Append to `org-members/tests/integration_test.rs`:

```rust
// --- H-3: name/surname length caps ---

#[test]
fn member_leaf_new_rejects_oversized_name() {
    let long_name = "a".repeat(129);
    let err = MemberLeaf::new(
        member_id("k"),
        "alice",
        member_key("k"),
        &long_name,
        "B",
        vec![device_key("d")],
    );
    assert_eq!(
        err.unwrap_err(),
        OrgMembersError::FieldTooLong { field: "name", max: 128 }
    );
}

#[test]
fn member_leaf_new_rejects_oversized_surname() {
    let long_surname = "b".repeat(129);
    let err = MemberLeaf::new(
        member_id("k"),
        "alice",
        member_key("k"),
        "A",
        &long_surname,
        vec![device_key("d")],
    );
    assert_eq!(
        err.unwrap_err(),
        OrgMembersError::FieldTooLong { field: "surname", max: 128 }
    );
}

#[test]
fn member_leaf_new_accepts_max_length_name_and_surname() {
    let name_128 = "a".repeat(128);
    let surname_128 = "b".repeat(128);
    let ok = MemberLeaf::new(
        member_id("k"),
        "alice",
        member_key("k"),
        &name_128,
        &surname_128,
        vec![device_key("d")],
    );
    assert!(ok.is_ok());
}

#[cfg(feature = "serde")]
#[test]
fn deserialize_rejects_oversized_name() {
    use postcard::{from_bytes, to_allocvec};
    use org_members::types::P2pDeviceSlots;

    #[derive(serde::Serialize)]
    struct WireLeaf<'a> {
        id: MemberId,
        handle: &'a str,
        p2p_key: P2pMemberKey,
        name: &'a str,
        surname: &'a str,
        p2p_devices: P2pDeviceSlots,
    }
    let long_name = "a".repeat(200);
    let wire = WireLeaf {
        id: member_id("k"),
        handle: "alice",
        p2p_key: member_key("k"),
        name: &long_name,
        surname: "B",
        p2p_devices: P2pDeviceSlots::new(vec![device_key("d")]).unwrap(),
    };
    let bytes = to_allocvec(&wire).unwrap();
    let result: Result<MemberLeaf, _> = from_bytes(&bytes);
    assert!(result.is_err());
}

#[cfg(feature = "serde")]
#[test]
fn deserialize_rejects_oversized_surname() {
    use postcard::{from_bytes, to_allocvec};
    use org_members::types::P2pDeviceSlots;

    #[derive(serde::Serialize)]
    struct WireLeaf<'a> {
        id: MemberId,
        handle: &'a str,
        p2p_key: P2pMemberKey,
        name: &'a str,
        surname: &'a str,
        p2p_devices: P2pDeviceSlots,
    }
    let long_surname = "b".repeat(200);
    let wire = WireLeaf {
        id: member_id("k"),
        handle: "alice",
        p2p_key: member_key("k"),
        name: "A",
        surname: &long_surname,
        p2p_devices: P2pDeviceSlots::new(vec![device_key("d")]).unwrap(),
    };
    let bytes = to_allocvec(&wire).unwrap();
    let result: Result<MemberLeaf, _> = from_bytes(&bytes);
    assert!(result.is_err());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd org-members && cargo test --test integration_test 'name' 'surname' 2>&1 | tail -30`

Expected: the four "rejects" tests fail (no length check yet); the "accepts max length" test passes.

- [ ] **Step 3: Add the constants and checks**

Edit `org-members/src/types.rs`. Just below the existing `MAX_HANDLE_LEN` constant (around line 21), add:

```rust
/// Maximum byte length of `name` after NFC normalization. Matches
/// `MAX_HANDLE_LEN` and is generous for typical names (KYC standards
/// cap at 50–100 chars; 128 bytes accommodates non-ASCII expansion).
pub const MAX_NAME_LEN: usize = 128;

/// Maximum byte length of `surname` after NFC normalization. See `MAX_NAME_LEN`.
pub const MAX_SURNAME_LEN: usize = 128;
```

Then replace the body of `MemberLeaf::new` (`src/types.rs:485-506`) with:

```rust
    pub fn new(
        id: MemberId,
        handle: &str,
        p2p_key: P2pMemberKey,
        name: &str,
        surname: &str,
        p2p_devices: Vec<P2pDeviceKey>,
    ) -> Result<Self, OrgMembersError> {
        if p2p_devices.is_empty() {
            return Err(OrgMembersError::EmptyDeviceList);
        }
        let validated_handle = validate_handle(handle)?;
        let nfc_name = to_nfc(name);
        if nfc_name.len() > MAX_NAME_LEN {
            return Err(OrgMembersError::FieldTooLong { field: "name", max: MAX_NAME_LEN });
        }
        let nfc_surname = to_nfc(surname);
        if nfc_surname.len() > MAX_SURNAME_LEN {
            return Err(OrgMembersError::FieldTooLong { field: "surname", max: MAX_SURNAME_LEN });
        }
        let device_slots = P2pDeviceSlots::new(p2p_devices)?;
        Ok(Self {
            id,
            handle: validated_handle,
            p2p_key,
            name: nfc_name,
            surname: nfc_surname,
            p2p_devices: device_slots,
        })
    }
```

Then replace the body of the `MemberLeaf` `Deserialize` impl (`src/types.rs:456-476`) with:

```rust
#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for MemberLeaf {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = MemberLeafSerde::deserialize(d)?;
        // Re-validate the handle so an attacker-supplied wire format cannot
        // bypass NFC normalization, lowercase, single-script, no-`.`, or UTS#39
        // restrictions. `validate_handle` also returns the NFC-normalized form,
        // so the stored handle is canonical even if the wire payload wasn't.
        let validated_handle = validate_handle(&raw.handle).map_err(serde::de::Error::custom)?;
        let name = to_nfc(&raw.name);
        if name.len() > MAX_NAME_LEN {
            return Err(serde::de::Error::custom("name exceeds MAX_NAME_LEN after NFC"));
        }
        let surname = to_nfc(&raw.surname);
        if surname.len() > MAX_SURNAME_LEN {
            return Err(serde::de::Error::custom("surname exceeds MAX_SURNAME_LEN after NFC"));
        }
        Ok(Self {
            id: raw.id,
            handle: validated_handle,
            p2p_key: raw.p2p_key,
            name,
            surname,
            p2p_devices: raw.p2p_devices,
        })
    }
}
```

- [ ] **Step 4: Run new tests to verify they pass**

Run: `cd org-members && cargo test --test integration_test 'name' 'surname'`

Expected: all five new tests pass.

- [ ] **Step 5: Run the full suite to confirm no regression**

Run: `cd org-members && cargo test`

Expected: full suite passes. Particularly verify `member_leaf_nfc_normalization` and `update_name_surname_*` still pass (they use short fixtures).

- [ ] **Step 6: Run no_std + WASM checks**

Run: `cd org-members && cargo check --no-default-features --features serde --target wasm32-unknown-unknown 2>&1 | tail -5`

Expected: clean compile (no_std + alloc still satisfied).

- [ ] **Step 7: Commit**

```bash
cd org-members
git add src/types.rs tests/integration_test.rs
git -c commit.gpgsign=false commit -m "org-members: cap name and surname at 128 bytes (H-3)

Adversarial wire-format upsert could carry multi-GiB name/surname strings,
exhausting memory and overflowing the u32 length prefix in canonical_bytes.
Enforce MAX_NAME_LEN / MAX_SURNAME_LEN in MemberLeaf::new and re-enforce in
the wire deserialize path."
```

---

### Task 3: H-2 — Reject non-canonical `P2pDeviceSlots` on deserialize

**Files:**
- Modify: `org-members/src/types.rs`
- Modify: `org-members/tests/integration_test.rs`

- [ ] **Step 1: Write the failing tests**

Append to `org-members/tests/integration_test.rs`:

```rust
// --- H-2: P2pDeviceSlots deserialize rejects non-canonical wire form ---

#[cfg(feature = "serde")]
#[test]
fn deserialize_rejects_unsorted_devices() {
    use postcard::{from_bytes, to_allocvec};
    let d1 = device_key("d1");
    let d2 = device_key("d2");
    let (lo, hi) = if d1.as_bytes() < d2.as_bytes() { (d1, d2) } else { (d2, d1) };
    let unsorted_wire: Vec<P2pDeviceKey> = vec![hi, lo];
    let bytes = to_allocvec(&unsorted_wire).unwrap();
    let result: Result<org_members::types::P2pDeviceSlots, _> = from_bytes(&bytes);
    assert!(result.is_err(), "deserialize must reject unsorted device list");
}

#[cfg(feature = "serde")]
#[test]
fn deserialize_rejects_duplicate_devices() {
    use postcard::{from_bytes, to_allocvec};
    let d = device_key("d1");
    let dup_wire: Vec<P2pDeviceKey> = vec![d, d];
    let bytes = to_allocvec(&dup_wire).unwrap();
    let result: Result<org_members::types::P2pDeviceSlots, _> = from_bytes(&bytes);
    assert!(result.is_err(), "deserialize must reject duplicate devices");
}

#[cfg(feature = "serde")]
#[test]
fn deserialize_rejects_too_many_devices() {
    use postcard::{from_bytes, to_allocvec};
    let many: Vec<P2pDeviceKey> = (0..5).map(|i| device_key(&format!("d{}", i))).collect();
    // Sort so we hit the count check, not the order check.
    let mut sorted = many.clone();
    sorted.sort();
    let bytes = to_allocvec(&sorted).unwrap();
    let result: Result<org_members::types::P2pDeviceSlots, _> = from_bytes(&bytes);
    assert!(result.is_err(), "deserialize must reject more than MAX_DEVICES");
}

#[cfg(feature = "serde")]
#[test]
fn deserialize_accepts_sorted_unique_devices() {
    use postcard::{from_bytes, to_allocvec};
    let d1 = device_key("d1");
    let d2 = device_key("d2");
    let (lo, hi) = if d1.as_bytes() < d2.as_bytes() { (d1, d2) } else { (d2, d1) };
    let canonical: Vec<P2pDeviceKey> = vec![lo, hi];
    let bytes = to_allocvec(&canonical).unwrap();
    let result: org_members::types::P2pDeviceSlots = from_bytes(&bytes).unwrap();
    assert_eq!(result.device_count(), 2);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd org-members && cargo test --test integration_test deserialize_rejects deserialize_accepts_sorted 2>&1 | tail -20`

Expected: `deserialize_rejects_unsorted_devices` and `deserialize_rejects_duplicate_devices` fail (current code silently normalizes). The others pass.

- [ ] **Step 3: Replace the deserialize impl**

Replace `<P2pDeviceSlots as Deserialize>` (`src/types.rs:323-331`) with:

```rust
#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for P2pDeviceSlots {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let slots = Vec::<P2pDeviceKey>::deserialize(d)?;
        // Reject (do not normalize) non-canonical wire forms so postcard bytes
        // have a unique encoding per logical device set. See Hyperbridge S1-16
        // (proof canonicality) and review finding H-2.
        if slots.len() > MAX_DEVICES {
            return Err(serde::de::Error::custom("device slots exceed MAX_DEVICES"));
        }
        for pair in slots.windows(2) {
            if pair[0] >= pair[1] {
                return Err(serde::de::Error::custom(
                    "device slots must be strictly increasing (sorted, no duplicates)",
                ));
            }
        }
        // Empty is still allowed (isolated state).
        Ok(Self { slots })
    }
}
```

- [ ] **Step 4: Run new tests to verify they pass**

Run: `cd org-members && cargo test --test integration_test deserialize_rejects deserialize_accepts_sorted`

Expected: all four new tests pass.

- [ ] **Step 5: Run the full suite — particular focus on existing wire tests**

Run: `cd org-members && cargo test`

Expected: full suite passes. Verify `deserialize_accepts_empty_device_list` (empty len 0 ≤ MAX_DEVICES, no windows to check) and the existing `deserialize_rejects_invalid_handle` round-trip still work. The `P2pDeviceSlots` constructed inside that test goes through `P2pDeviceSlots::new` which sorts, so the serialized form is canonical.

- [ ] **Step 6: WASM check**

Run: `cd org-members && cargo check --no-default-features --features serde --target wasm32-unknown-unknown 2>&1 | tail -5`

Expected: clean.

- [ ] **Step 7: Commit**

```bash
cd org-members
git add src/types.rs tests/integration_test.rs
git -c commit.gpgsign=false commit -m "org-members: reject non-canonical P2pDeviceSlots wire form (H-2)

Previously, P2pDeviceSlots::deserialize silently sorted and deduped wire
input. Multiple wire byte strings collapsed to the same logical slot set,
breaking the canonical-form invariant the higher-level signing layer relies
on. Now reject (do not normalize) unsorted or duplicate-containing input.
Caller-side construction via P2pDeviceSlots::new keeps its normalize-on-
construct behavior; only the trust boundary tightens."
```

---

### Task 4: H-1 — Strict canonical `Delta` in `apply_delta` + M-3 test flip

**Files:**
- Modify: `org-members/src/trie.rs`
- Modify: `org-members/tests/integration_test.rs`

This is the largest task and the heart of the post-mortem response. Strict canonicality at `apply_delta` entry.

- [ ] **Step 1: Write the failing tests**

Append to `org-members/tests/integration_test.rs`:

```rust
// --- H-1: apply_delta rejects non-canonical Delta ---

#[test]
fn apply_delta_rejects_stale_removal() {
    // After H-1: a removal of an id not present in the trie is MalformedDelta.
    // (Previously this was silently tolerated -- see commit history for the
    // prior test apply_delta_ignores_stale_removal which is now removed.)
    let trie = TestTrie::genesis(vec![alice(), bob()]).unwrap();
    let ghost_id = member_id("ghost-id");
    let crafted = trie.delete_member(&member_id("alice-id")).unwrap();
    let (_target, mut delta) = crafted.recalculate().unwrap();
    let mut new_removed = delta.removed().to_vec();
    new_removed.push(ghost_id);
    new_removed.sort();
    org_members::delta::test_support::delta_set_removed(&mut delta, new_removed);

    let err = trie.apply_delta(&delta).unwrap_err();
    assert!(matches!(err, OrgMembersError::MalformedDelta(_)));
}

#[test]
fn apply_delta_rejects_unsorted_removed() {
    let trie = TestTrie::genesis(vec![alice(), bob(), charlie()]).unwrap();
    let modified = trie
        .delete_member(&member_id("alice-id")).unwrap()
        .delete_member(&member_id("bob-id")).unwrap();
    let (_target, mut delta) = modified.recalculate().unwrap();
    // Force reverse order so it's no longer strictly increasing.
    let mut rev = delta.removed().to_vec();
    rev.reverse();
    if rev.len() < 2 || rev[0] < rev[1] {
        // Already happens to be increasing after reverse (only one removal),
        // so manually duplicate to break strictness. But we have 2 removals,
        // so reverse guarantees decreasing.
        panic!("test setup expected ≥2 removals in decreasing order");
    }
    org_members::delta::test_support::delta_set_removed(&mut delta, rev);

    let err = trie.apply_delta(&delta).unwrap_err();
    assert!(matches!(err, OrgMembersError::MalformedDelta(_)));
}

#[test]
fn apply_delta_rejects_duplicate_in_removed() {
    let trie = TestTrie::genesis(vec![alice(), bob()]).unwrap();
    let modified = trie.delete_member(&member_id("alice-id")).unwrap();
    let (_target, mut delta) = modified.recalculate().unwrap();
    let one = delta.removed()[0];
    org_members::delta::test_support::delta_set_removed(&mut delta, vec![one, one]);

    let err = trie.apply_delta(&delta).unwrap_err();
    assert!(matches!(err, OrgMembersError::MalformedDelta(_)));
}

#[test]
fn apply_delta_rejects_duplicate_in_upserted() {
    let trie = TestTrie::genesis(vec![alice()]).unwrap();
    let modified = trie.add_member(bob()).unwrap();
    let (_target, mut delta) = modified.recalculate().unwrap();
    let one = delta.upserted()[0].clone();
    org_members::delta::test_support::delta_set_upserted(&mut delta, vec![one.clone(), one]);

    let err = trie.apply_delta(&delta).unwrap_err();
    assert!(matches!(err, OrgMembersError::MalformedDelta(_)));
}

#[test]
fn apply_delta_rejects_unsorted_upserted() {
    let trie = TestTrie::genesis(vec![alice()]).unwrap();
    let modified = trie.add_member(bob()).unwrap().add_member(charlie()).unwrap();
    let (_target, mut delta) = modified.recalculate().unwrap();
    if delta.upserted().len() < 2 {
        panic!("test setup expected ≥2 upserts");
    }
    let mut rev = delta.upserted().to_vec();
    rev.reverse();
    org_members::delta::test_support::delta_set_upserted(&mut delta, rev);

    let err = trie.apply_delta(&delta).unwrap_err();
    assert!(matches!(err, OrgMembersError::MalformedDelta(_)));
}

#[test]
fn apply_delta_rejects_id_in_both_removed_and_upserted() {
    let trie = TestTrie::genesis(vec![alice()]).unwrap();
    // Build a delta that updates alice (upserts) AND removes her -- inject
    // the removal artificially via test_support.
    let modified = trie
        .rotate_p2p_key(&member_id("alice-id"), member_key("alice-rotated"))
        .unwrap();
    let (_target, mut delta) = modified.recalculate().unwrap();
    org_members::delta::test_support::delta_set_removed(&mut delta, vec![member_id("alice-id")]);
    // upserted still contains the rotated alice from the original recalc.

    let err = trie.apply_delta(&delta).unwrap_err();
    assert!(matches!(err, OrgMembersError::MalformedDelta(_)));
}

#[test]
fn apply_delta_rejects_noop_upsert() {
    let trie = TestTrie::genesis(vec![alice(), bob()]).unwrap();
    // Build a real delta (e.g., add charlie), then append alice unchanged.
    let modified = trie.add_member(charlie()).unwrap();
    let (_target, mut delta) = modified.recalculate().unwrap();
    let mut up = delta.upserted().to_vec();
    up.push(alice());
    up.sort_by(|a, b| a.id().cmp(b.id()));
    org_members::delta::test_support::delta_set_upserted(&mut delta, up);

    let err = trie.apply_delta(&delta).unwrap_err();
    assert!(matches!(err, OrgMembersError::MalformedDelta(_)));
}

#[test]
fn apply_delta_canonical_delta_still_works() {
    // Sanity: the strict checks must not break honest round-trips.
    let trie = TestTrie::genesis(vec![alice(), bob()]).unwrap();
    let updated = trie.add_member(charlie()).unwrap();
    let updated = updated.delete_member(&member_id("alice-id")).unwrap();
    let (updated, delta) = updated.recalculate().unwrap();

    let candidate = trie.apply_delta(&delta).unwrap();
    let verified = candidate.verify_against(&updated.root_hash().unwrap()).unwrap();
    assert_eq!(verified.root_hash().unwrap(), updated.root_hash().unwrap());
}
```

Also: **remove** the existing `apply_delta_ignores_stale_removal` test at `tests/integration_test.rs:1098-1117`. Its behavior is now replaced by `apply_delta_rejects_stale_removal`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd org-members && cargo test --test integration_test apply_delta_rejects apply_delta_canonical 2>&1 | tail -40`

Expected: all `apply_delta_rejects_*` tests fail (no strict checks yet); `apply_delta_canonical_delta_still_works` passes (honest path).

- [ ] **Step 3: Add the strict canonicality checks in `apply_delta`**

Replace the body of `apply_delta` (`src/trie.rs:400-474`) with:

```rust
    /// Applies a received delta. Returns CandidateTrie (must verify before use).
    ///
    /// Rejects deltas that are not in canonical form (H-1):
    /// - `removed` MUST be strictly increasing by id; every id MUST exist in the trie.
    /// - `upserted` MUST be strictly increasing by id; every leaf MUST produce an
    ///   observable change vs. the current trie state at that id.
    /// - `removed` and `upserted` MUST be disjoint.
    ///
    /// Together these guarantee that the postcard byte string of an accepted
    /// `Delta` is the unique encoding for the transition from `base_root` to
    /// the resulting root. See `docs/superpowers/specs/2026-05-28-org-members-
    /// hyperbridge-review.md` for the threat model.
    pub fn apply_delta(&self, delta: &Delta) -> Result<CandidateTrie<H>, OrgMembersError> {
        let current_root = self
            .cached_root_hash
            .ok_or(OrgMembersError::HashesNotCalculated)?;

        if delta.base_root != current_root {
            return Err(OrgMembersError::DeltaBaseMismatch);
        }

        // --- Canonical-form checks (H-1) ---
        // removed: strictly increasing, every id present.
        for pair in delta.removed.windows(2) {
            if pair[0] >= pair[1] {
                return Err(OrgMembersError::MalformedDelta(
                    "removed not strictly increasing",
                ));
            }
        }
        for id in &delta.removed {
            if smt::get_member(&self.root, id).is_none() {
                return Err(OrgMembersError::MalformedDelta(
                    "removed id not present in trie",
                ));
            }
        }
        // upserted: strictly increasing, each leaf produces an observable change.
        for pair in delta.upserted.windows(2) {
            if pair[0].id() >= pair[1].id() {
                return Err(OrgMembersError::MalformedDelta(
                    "upserted not strictly increasing by id",
                ));
            }
        }
        for leaf in &delta.upserted {
            if let Some(existing) = smt::get_member(&self.root, leaf.id()) {
                if &existing == leaf {
                    return Err(OrgMembersError::MalformedDelta(
                        "upserted leaf identical to existing trie state",
                    ));
                }
            }
        }
        // removed and upserted disjoint (two-pointer merge over sorted ids).
        let mut ri = 0;
        let mut ui = 0;
        while ri < delta.removed.len() && ui < delta.upserted.len() {
            match delta.removed[ri].cmp(delta.upserted[ui].id()) {
                core::cmp::Ordering::Less => ri += 1,
                core::cmp::Ordering::Greater => ui += 1,
                core::cmp::Ordering::Equal => {
                    return Err(OrgMembersError::MalformedDelta(
                        "id appears in both removed and upserted",
                    ));
                }
            }
        }

        // --- Apply (every operation is now guaranteed meaningful) ---
        let mut root = self.root.clone();
        let mut count = self.member_count;
        let mut new_skeleton_index = self.skeleton_index.clone();
        let mut new_handle_index = self.handle_index.clone();

        for id in &delta.removed {
            // Existence verified above; the lookup here is to extract the
            // handle/skeleton for index maintenance.
            let existing = smt::get_member(&root, id).ok_or(OrgMembersError::InvariantViolated)?;
            new_skeleton_index.remove(&handle_skeleton(existing.handle()));
            new_handle_index.remove(existing.handle());
            root = smt::remove(&root, id, &self.defaults);
            count = count.checked_sub(1).ok_or(OrgMembersError::InvariantViolated)?;
        }

        for member in &delta.upserted {
            let existing = smt::get_member(&root, member.id());

            if let Some(ref old) = existing {
                if old.handle() != member.handle() {
                    new_skeleton_index.remove(&handle_skeleton(old.handle()));
                    new_handle_index.remove(old.handle());
                }
            }

            let needs_check = match &existing {
                Some(old) => old.handle() != member.handle(),
                None => true,
            };

            if needs_check {
                let skeleton = handle_skeleton(member.handle());
                if let Some(existing_handle) = new_skeleton_index.get(&skeleton) {
                    if existing_handle != member.handle() {
                        return Err(OrgMembersError::ConfusableHandle);
                    } else {
                        return Err(OrgMembersError::DuplicateHandle);
                    }
                }
                new_skeleton_index.insert(skeleton, member.handle().to_owned());
                new_handle_index.insert(member.handle().to_owned(), *member.id());
            }

            root = smt::insert::<H>(&root, member.clone(), &self.defaults);
            if existing.is_none() {
                count = count.checked_add(1).ok_or(OrgMembersError::InvariantViolated)?;
            }
        }

        let root_hash = smt::recalculate_hashes::<H>(&root)?;

        Ok(CandidateTrie {
            root,
            defaults: self.defaults.clone(),
            member_count: count,
            root_hash: root_hash.into(),
            skeleton_index: new_skeleton_index,
            handle_index: new_handle_index,
            _hasher: core::marker::PhantomData,
        })
    }
```

Note: this also folds in M-2's `checked_sub` / `checked_add` for the apply-side `count` arithmetic. The remaining M-2 sites (`insert_leaf`, `delete_by_id`) are addressed in Task 5.

- [ ] **Step 4: Run new tests to verify they pass**

Run: `cd org-members && cargo test --test integration_test apply_delta_rejects apply_delta_canonical`

Expected: all eight new tests pass.

- [ ] **Step 5: Run the full suite to confirm no regression**

Run: `cd org-members && cargo test`

Expected:
- All existing `apply_delta_*`, `calculate_delta_*`, `pending_changes_*`, `delta_roundtrip` (fuzz), `calculate_delta_roundtrip` (fuzz), `member_key_rotation_through_delta`, and `apply_delta_rejects_confusable_in_upsert` tests still pass — they use honest deltas from `recalculate()` / `calculate_delta()` / `pending_changes()`, all of which produce canonical output via `diff_recursive`.
- The old `apply_delta_ignores_stale_removal` is gone (removed in Step 1).

- [ ] **Step 6: WASM check**

Run: `cd org-members && cargo check --no-default-features --features serde --target wasm32-unknown-unknown 2>&1 | tail -5`

Expected: clean.

- [ ] **Step 7: Commit**

```bash
cd org-members
git add src/trie.rs tests/integration_test.rs
git -c commit.gpgsign=false commit -m "org-members: reject non-canonical Delta in apply_delta (H-1, M-3)

Enforce the canonical-form invariant at the apply_delta trust boundary:
- removed strictly increasing, every id present in trie
- upserted strictly increasing by id, every leaf produces an observable change
- removed and upserted disjoint

Honest deltas from recalculate(), calculate_delta(), and pending_changes() all
satisfy these by construction via diff_recursive's left-then-right traversal,
so no regression in the round-trip path.

Adversarial poisoning (stale removals, duplicates, no-op upserts, unsorted
inputs) now returns MalformedDelta. Replaces the test that asserted the prior
lenient behavior. See docs/superpowers/specs/2026-05-28-org-members-
hyperbridge-review.md (H-1, M-3) and the matching post-mortem class:
https://blog.hyperbridge.network/april-13-post-mortem/"
```

---

### Task 5: M-2 — Checked arithmetic in `insert_leaf` and `delete_by_id`

**Files:**
- Modify: `org-members/src/trie.rs`

The apply-side count was already converted in Task 4. This task addresses the remaining two sites.

- [ ] **Step 1: Replace the unchecked arithmetic**

In `src/trie.rs`, find the `insert_leaf` function and replace the `member_count` line in its `Self {}` initializer (around line 278):

From:
```rust
            member_count: self.member_count + 1,
```

To:
```rust
            member_count: self.member_count
                .checked_add(1)
                .ok_or(OrgMembersError::InvariantViolated)?,
```

Find the `delete_by_id` function and replace its `member_count` line (around line 339):

From:
```rust
            member_count: self.member_count - 1,
```

To:
```rust
            member_count: self.member_count
                .checked_sub(1)
                .ok_or(OrgMembersError::InvariantViolated)?,
```

- [ ] **Step 2: Run the full suite to confirm no regression**

Run: `cd org-members && cargo test`

Expected: all tests pass. The checked arithmetic produces identical observable behavior on the correct paths exercised by the suite; the new error path is only reachable if a future bug breaks the invariant `member_count == actual members in trie`.

- [ ] **Step 3: WASM check**

Run: `cd org-members && cargo check --no-default-features --features serde --target wasm32-unknown-unknown 2>&1 | tail -5`

Expected: clean.

- [ ] **Step 4: Commit**

```bash
cd org-members
git add src/trie.rs
git -c commit.gpgsign=false commit -m "org-members: use checked arithmetic for member_count (M-2)

Defensive: insert_leaf and delete_by_id now use checked_add/checked_sub and
return InvariantViolated on overflow/underflow rather than wrapping silently
in release. The invariant 'member_count == actual members' holds today (fuzz-
asserted) so no observable behavior change in correct paths."
```

---

### Task 6: Info-4 — Canonicality fuzz harness

**Files:**
- Modify: `org-members/tests/fuzz_tests.rs`

- [ ] **Step 1: Write the proptest**

Append to `org-members/tests/fuzz_tests.rs`:

```rust
// ============================================================
// H-1 / H-2 canonicality fuzz: every non-canonical mutation of
// an honest delta must be rejected by apply_delta with
// OrgMembersError::MalformedDelta.
// ============================================================

use org_members::OrgMembersError;

#[derive(Debug, Clone)]
enum Mutator {
    /// Append a stale (unused) removal.
    AppendStaleRemoval,
    /// Duplicate the last entry in `removed`.
    DuplicateLastRemoved,
    /// Duplicate the last entry in `upserted`.
    DuplicateLastUpserted,
    /// Reverse `removed` (force unsorted, only meaningful when len >= 2).
    ReverseRemoved,
    /// Reverse `upserted` (force unsorted, only meaningful when len >= 2).
    ReverseUpserted,
    /// Append a no-op upsert (clone of a current trie leaf that is NOT already
    /// in the upsert list; chooses the first handle from HANDLES that fits).
    AppendNoopUpsert,
    /// Move the first removed id into upserted as a leaf-clone (id in both sides).
    MoveRemovedIntoUpserted,
}

fn arb_mutator() -> impl Strategy<Value = Mutator> {
    prop_oneof![
        Just(Mutator::AppendStaleRemoval),
        Just(Mutator::DuplicateLastRemoved),
        Just(Mutator::DuplicateLastUpserted),
        Just(Mutator::ReverseRemoved),
        Just(Mutator::ReverseUpserted),
        Just(Mutator::AppendNoopUpsert),
        Just(Mutator::MoveRemovedIntoUpserted),
    ]
}

proptest! {
    #[test]
    fn delta_canonicality_fuzz(
        seed_ops in proptest::collection::vec(arb_delta_op(), 1..8),
        mutator in arb_mutator(),
    ) {
        // 1. Build a honest base trie and honest delta.
        let mut seen = vec![false; HANDLES.len()];
        let mut initial = Vec::new();
        for h in HANDLES.iter().take(4) {
            if let Some(m) = make_member(h, 0) {
                initial.push(m);
                seen[HANDLES.iter().position(|x| x == h).unwrap()] = true;
            }
        }
        let base = TestTrie::genesis(initial).unwrap();

        let mut work = base.clone();
        for op in &seed_ops {
            match op {
                DeltaOp::Insert(idx) => {
                    if let Some(m) = make_member(HANDLES[*idx], 0) {
                        if let Ok(t) = work.add_member(m) { work = t; }
                    }
                }
                DeltaOp::Delete(idx) => {
                    let id = member_id(&format!("{}-id-0", HANDLES[*idx]));
                    if let Ok(t) = work.delete_member(&id) { work = t; }
                }
            }
        }
        let (_target, mut delta) = match work.recalculate() {
            Ok(r) => r,
            Err(_) => return Ok(()),
        };
        if delta.is_empty() {
            return Ok(());
        }

        // 2. Apply the mutator. If the mutation can't be applied to this delta
        //    shape, skip — fuzz still covers the cases that fire.
        let applied = match mutator {
            Mutator::AppendStaleRemoval => {
                let ghost = member_id("zzz-fuzz-ghost-id-xyzzy");
                let mut r = delta.removed().to_vec();
                if r.iter().any(|x| *x == ghost) || base.contains(&ghost) {
                    return Ok(());
                }
                r.push(ghost);
                r.sort();
                org_members::delta::test_support::delta_set_removed(&mut delta, r);
                true
            }
            Mutator::DuplicateLastRemoved => {
                let r = delta.removed();
                if r.is_empty() { return Ok(()); }
                let mut new = r.to_vec();
                new.push(*r.last().unwrap());
                org_members::delta::test_support::delta_set_removed(&mut delta, new);
                true
            }
            Mutator::DuplicateLastUpserted => {
                let u = delta.upserted();
                if u.is_empty() { return Ok(()); }
                let mut new: Vec<MemberLeaf> = u.to_vec();
                new.push(u.last().unwrap().clone());
                org_members::delta::test_support::delta_set_upserted(&mut delta, new);
                true
            }
            Mutator::ReverseRemoved => {
                let r = delta.removed();
                if r.len() < 2 { return Ok(()); }
                let mut new = r.to_vec();
                new.reverse();
                org_members::delta::test_support::delta_set_removed(&mut delta, new);
                true
            }
            Mutator::ReverseUpserted => {
                let u = delta.upserted();
                if u.len() < 2 { return Ok(()); }
                let mut new: Vec<MemberLeaf> = u.to_vec();
                new.reverse();
                org_members::delta::test_support::delta_set_upserted(&mut delta, new);
                true
            }
            Mutator::AppendNoopUpsert => {
                // Find a base-trie member whose id is NOT in delta.removed and
                // NOT already in delta.upserted; clone-append.
                let removed: Vec<_> = delta.removed().to_vec();
                let upserted_ids: Vec<_> = delta.upserted().iter().map(|m| *m.id()).collect();
                let mut chosen: Option<MemberLeaf> = None;
                for m in base.members() {
                    if !removed.contains(m.id()) && !upserted_ids.contains(m.id()) {
                        chosen = Some(m);
                        break;
                    }
                }
                let leaf = match chosen { Some(l) => l, None => return Ok(()) };
                let mut new: Vec<MemberLeaf> = delta.upserted().to_vec();
                new.push(leaf);
                new.sort_by(|a, b| a.id().cmp(b.id()));
                org_members::delta::test_support::delta_set_upserted(&mut delta, new);
                true
            }
            Mutator::MoveRemovedIntoUpserted => {
                let r = delta.removed();
                if r.is_empty() { return Ok(()); }
                let collide_id = r[0];
                let leaf = match base.get(&collide_id) {
                    Some(l) => l,
                    None => return Ok(()),
                };
                let mut new: Vec<MemberLeaf> = delta.upserted().to_vec();
                new.push(leaf);
                new.sort_by(|a, b| a.id().cmp(b.id()));
                org_members::delta::test_support::delta_set_upserted(&mut delta, new);
                true
            }
        };

        if !applied {
            return Ok(());
        }

        // 3. apply_delta must now reject with MalformedDelta.
        let err = match base.apply_delta(&delta) {
            Ok(_) => return Err(TestCaseError::fail(
                "apply_delta accepted a non-canonical delta (mutator ran but check missed)"
            )),
            Err(e) => e,
        };
        prop_assert!(
            matches!(err, OrgMembersError::MalformedDelta(_)),
            "expected MalformedDelta, got {:?}", err,
        );
    }
}
```

- [ ] **Step 2: Run the fuzz**

Run: `cd org-members && cargo test --test fuzz_tests delta_canonicality_fuzz 2>&1 | tail -20`

Expected: passes (the H-1 + H-2 checks land all cases). proptest may run hundreds of iterations.

- [ ] **Step 3: Run the full test suite**

Run: `cd org-members && cargo test`

Expected: full suite green.

- [ ] **Step 4: WASM check**

Run: `cd org-members && cargo check --no-default-features --features serde --target wasm32-unknown-unknown 2>&1 | tail -5`

Expected: clean.

- [ ] **Step 5: Commit**

```bash
cd org-members
git add tests/fuzz_tests.rs
git -c commit.gpgsign=false commit -m "org-members: add delta canonicality fuzz harness (Info-4)

Each mutator corresponds to one regression seed for H-1/H-2: stale removal,
duplicate id in removed, duplicate id in upserted, unsorted removed/upserted,
no-op upsert, and id in both removed and upserted. Mirrors the Hyperbridge
post-mortem recommendation 'Continuous structural fuzzing for verifier
libraries'."
```

---

### Task 7: M-1 — Documentation on `Delta`

**Files:**
- Modify: `org-members/src/delta.rs`

- [ ] **Step 1: Replace the `Delta` doc comment**

In `src/delta.rs`, replace the existing doc above the `Delta` struct (line 15) with:

```rust
/// A set of changes anchored to a specific base trie root.
///
/// # Canonical-form invariant
///
/// Every `Delta` accepted by `OrgTrie::apply_delta` is in canonical form:
///
/// - `removed` is strictly increasing by `MemberId` and every id is present in
///   the trie at `base_root`.
/// - `upserted` is strictly increasing by `MemberId` and every leaf produces
///   an observable change vs. the current state at that id.
/// - `removed` and `upserted` are disjoint.
///
/// Combined with the fact that `recalculate()`, `calculate_delta()`, and
/// `pending_changes()` all produce canonical deltas by construction (via
/// `diff_recursive`'s left-then-right SMT traversal), this gives the higher-
/// level layer a strong guarantee: for any `(base_root, target_root)` pair,
/// there is exactly one postcard byte string of a `Delta` that `apply_delta`
/// will accept.
///
/// # What this crate does NOT do
///
/// `Delta` is scoped only by `base_root`. The following are the caller's
/// responsibility and MUST be enforced upstream of `apply_delta`:
///
/// - **Authentication** — verify a signature over `postcard(Delta)` bytes
///   against an admin/quorum key before applying.
/// - **Organisation binding** — wrap deltas in `(org_id, postcard(Delta),
///   signature)` envelopes; the lib has no notion of which organisation a
///   delta belongs to.
/// - **Replay protection across time** — `base_root` rejects deltas once the
///   trie has moved past their parent, but a trie that revisits a prior root
///   would accept a stale delta. Use a monotonic sequence number in the
///   envelope.
/// - **Authority** — `apply_delta` accepts any well-formed change; whether the
///   signer is allowed to make this change (quorum, role-based veto, rate
///   limits) is policy that lives above this crate.
/// - **Independent trusted root** — `CandidateTrie::verify_against`'s
///   `expected_root` argument must come from a path the attacker cannot
///   control (on-chain commit, signed admin attestation, etc.), not from the
///   same payload as the delta.
///
/// See `org-members/README.md` for the full enumeration of upstream security
/// responsibilities, and `docs/superpowers/specs/2026-05-28-org-members-
/// hyperbridge-review.md` for the threat model.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Delta {
```

(Leave the field definitions below it unchanged.)

- [ ] **Step 2: Verify rustdoc builds**

Run: `cd org-members && cargo doc --no-deps 2>&1 | tail -10`

Expected: clean build, no broken intra-doc links. The doc comment uses code-spans and plain text; no `[]` link syntax that could break.

- [ ] **Step 3: Run the full suite**

Run: `cd org-members && cargo test`

Expected: all tests pass (doc-only change).

- [ ] **Step 4: Commit**

```bash
cd org-members
git add src/delta.rs
git -c commit.gpgsign=false commit -m "org-members: document Delta canonical-form invariant and upstream contract (M-1)

State the canonical-form invariant that holds after H-1/H-2 land, and
enumerate the security checks the higher-level lib must still perform.
Points at org-members/README.md for the full upstream-responsibilities list
and at the Hyperbridge review spec for the threat model. Doc-only."
```

---

### Task 8: Final cross-configuration verification

**Files:** none modified.

- [ ] **Step 1: Run the full matrix**

Run each in `org-members/`:

```bash
cd org-members
cargo test                                                                         # default (std + serde)
cargo check --no-default-features                                                  # bare no_std
cargo check --no-default-features --features serde                                 # no_std + serde
cargo check --no-default-features --features serde --target wasm32-unknown-unknown # WASM
cargo clippy -- -D warnings                                                        # clippy clean
```

Expected for each: zero warnings, zero failures. If clippy flags anything in code touched by this plan, fix it inline (don't add `#[allow]`).

- [ ] **Step 2: Diff summary**

Run: `git diff --stat main -- org-members` (or however your branch compares to baseline).

Sanity-check that the changes are confined to: `src/error.rs`, `src/types.rs`, `src/trie.rs`, `src/delta.rs`, `tests/integration_test.rs`, `tests/fuzz_tests.rs`. Nothing else should have changed.

- [ ] **Step 3: Update the README status note**

The README's "Current status" line (added during the spec phase) currently says the canonical-form invariant does NOT yet hold. After this plan lands it DOES hold. Edit `org-members/README.md`:

Find:
```
**Current status:** the invariant does NOT yet hold — `apply_delta` accepts non-canonical wire forms (stale removals, duplicate ids, unsorted device lists). Tracked by findings H-1 and H-2 in the [Hyperbridge review spec](../docs/superpowers/specs/2026-05-28-org-members-hyperbridge-review.md); until those land, callers must defensively re-canonicalise before signing or replay-deduping delta bytes.
```

Replace with:
```
**Status:** the invariant holds as of the [Hyperbridge fix series](../docs/superpowers/plans/2026-05-28-org-members-hyperbridge-fixes.md) (commits land H-1, H-2, H-3, M-1, M-2, M-3, Info-4 from the [review spec](../docs/superpowers/specs/2026-05-28-org-members-hyperbridge-review.md)).
```

- [ ] **Step 4: Commit the status update**

```bash
cd org-members
git add README.md
git -c commit.gpgsign=false commit -m "org-members: flip README status — canonical-form invariant now holds"
```

---

## Verification checklist (at the end of this plan)

After Task 8 completes:

- [ ] `cargo test` green on the default config
- [ ] `cargo check --no-default-features` green
- [ ] `cargo check --no-default-features --features serde` green
- [ ] `cargo check --no-default-features --features serde --target wasm32-unknown-unknown` green
- [ ] `cargo clippy -- -D warnings` green
- [ ] `cargo doc --no-deps` green
- [ ] Diff confined to the six files listed in "File Structure"
- [ ] Each commit is atomic and self-contained (one task = one commit, except Task 1 which is preparatory)
- [ ] No `Co-Authored-By:` lines in any commit (per project AGENTS.md)
- [ ] No GPG signing in worktree commits (per project AGENTS.md — already covered by `-c commit.gpgsign=false` in every commit command)

## What this plan does NOT touch (deferred to future work)

From the review spec:

- **L-1** (recursion depth in `recalculate_hashes`) — note in spec; revisit when Poseidon lands.
- **L-2** (`From<NodeHash> for RootHash`) — type-safety hygiene; can be a separate small PR.
- HashMap-index churn optimisation — already a known follow-up in `OrgTrie`'s doc-comment.
- Poseidon hasher — placeholder; security review needs to be redone when implemented.
- WASM runtime tests — compile-only today; `wasm-bindgen-test` is its own follow-up.

These intentionally stay out of scope to keep this plan focused on the Hyperbridge response.
