# AGENTS.md

Guidance for future agent sessions working on this codebase. Terse on purpose.

## Project context

Two-tier blockchain-mediated access control for local-first collaboration.
Phase 1.a is the `org-members` Rust library: an immutable binary Sparse Merkle
Tree (SMT) for organisation membership. Phase 1.a is `no_std`/WASM-compilable
and depends only on `alloc`. The local-first collaboration layer consumes
this lib's types (using the `p2p_key` as the member-as-a-group key when
granting access) but is out of scope here.

Design doc (canonical): `docs/plans/2026-05-07-org-members-design.md` (in
main worktree, not always in feature worktrees).

## User preferences (sticky)

- **No `Co-Authored-By:` lines in commit messages.** Hard rule.
- **`/superpowers:brainstorming` before any non-trivial design work.** Don't
  start coding alternatives until brainstorming has run and the user has
  confirmed direction.
- **Always work in a git worktree for feature work.** Use the worktree skill.
- **Prefer Result over panics.** Crate root denies `clippy::unwrap_used`,
  `clippy::expect_used`, `clippy::panic`. No exceptions in lib code; `unwrap()`
  is fine in tests.
- **Named types over naked primitives.** `MemberId([u8; 32])` not `[u8; 32]`.
  `MemberKey(VerifyingKey)` not raw bytes. Wrap PII with redacting `Debug`.
- **`no_std` is a hard requirement.** Verify with
  `cargo check --no-default-features --features serde --target wasm32-unknown-unknown`
  after any dependency change.
- **Don't ask "should I commit?" repeatedly.** Just commit at natural points.

## Domain vocabulary (use these terms)

- **Organisation** -- the entity owning the membership trie. Singular instance
  per trie.
- **Member** -- a person belonging to an Organisation.
- **Handle** -- the human-readable member identifier. Validated (UTS#39, NFC,
  lowercase, no `.`, single-script, `-` allowed). Mutable but changes rarely.
  PII; redacted in Debug.
- **MemberId** -- 32-byte immutable identifier; SMT key. Caller-generated,
  effectively random.
- **P2pMemberKey** -- ed25519 VerifyingKey for peer-to-peer use. Used by the
  local-first software as the "member-as-a-group" key: when an Organisation
  grants access to a member, the grant is encoded against this key, and
  member's devices derive their access from it. Rotatable. Future versions
  will add a separate on-chain key (`ChainKey` or similar -- name TBD).
- **P2pDeviceKey** -- ed25519 VerifyingKey for a member's device. Stored sorted.
- **P2pDeviceSlots** -- fixed depth-2 sub-trie holding 0..4 P2pDeviceKeys per
  member. Zero devices represents the *isolated* state (see below).
- **Isolated member** -- a member with zero p2p devices. Reached via
  `emergency_isolate_member` or by `delete_p2p_device` of the last device.
  The member stays in the trie; un-isolate by adding a device back.

## Public API style

The MAIN API uses domain-specific operations, NOT generic CRUD:

| Operation | Use case |
|---|---|
| `add_member(leaf)` | Onboard a new member (requires ≥1 device) |
| `delete_member(id)` | Off-board a member entirely |
| `update_name_surname(id, name, surname)` | PII edit |
| `update_handle(id, new_handle)` | Rename a member |
| `rotate_p2p_key(id, new_key)` | Routine rotation of the member-as-a-group key |
| `add_p2p_device(id, device)` | New device for an existing member |
| `delete_p2p_device(id, device, new_key)` | Device retired or compromised. Requires `new_key` because the deleted device had access to the old key. |
| `emergency_isolate_member(id, new_key)` | Multiple devices compromised; cut off all access at once |

The generic `insert`/`update`/`delete` are crate-private helpers
(`insert_leaf`/`update_leaf`/`delete_by_id`). Don't expose them.

Domain operations:
- All take `&MemberId` for lookup (not handles -- handles are mutable).
- All return `Result<Self, OrgMembersError>` -- propagate errors.
- All produce a new immutable trie via path-copying.
- Only handle-changing operations (`add_member`, `update_handle`) touch the
  skeleton/handle indexes. The rest skip that work.

When adding a new operation: prefer a single-purpose domain method over
extending an existing one. Test each domain operation independently in
`tests/integration_test.rs`.
- **Recalculate** -- the operation that walks the trie and fills lazy hash
  cells. Produces a `Delta` of accumulated changes.
- **Delta** -- a set of changes (`removed: Vec<MemberId>`, `upserted: Vec<MemberLeaf>`)
  anchored to a `base_root`. The wire format between admins.
- **CandidateTrie** -- result of applying a delta. Cannot be queried; must be
  verified against an expected root hash before becoming a usable `OrgTrie`.
- **NodeHash** -- 32-byte hash output from `TrieHasher` (any internal node,
  leaf, or root of a subtree).
- **RootHash** -- type-distinct wrapper for the externally-meaningful root
  of the whole trie. `From<NodeHash> for RootHash` converts at the boundary.
- **Skeleton** -- UTS#39 canonical form for confusable detection. Two handles
  with the same skeleton are rejected as homoglyphs.

Do NOT introduce: "user", "account", "node id" (ambiguous), or naked "group"
(use "member-as-a-group" if you mean the principal that a `p2p_key` represents).

## Critical invariants (verified by tests)

1. SMT key is the `MemberId` -- handle and `p2p_key` are independent of it
   and of each other.
2. After any mutation (`add_member`, `delete_member`, `update_*`,
   `rotate_p2p_key`, `add_p2p_device`, `delete_p2p_device`, `emergency_isolate_member`),
   hashes are NOT computed. `recalculate()` fills them. `root_hash()` returns
   `Err(HashesNotCalculated)` until then.
3. Path-copying preserves immutability: old trie's `root_hash()` is unchanged
   after mutating a new copy.
4. `apply_delta`:
   - Rejects if `delta.base_root != self.root_hash()`.
   - Ignores stale removals (doesn't underflow `member_count`).
   - Re-checks confusable handles for both new and renamed members.
5. Wire-format leaves (deserialize) re-run handle validation and DeviceSlots
   construction. Don't bypass via `derive(Deserialize)`.
6. `Node`, `MemberLeaf`, `OrgTrie<H>` are `Send + Sync` for downstream parallel
   use. `spin::Once` (not std `OnceLock`) for the hash cell.

## Build / test commands

```bash
# Default (std + serde):
cargo build && cargo test && cargo clippy

# All build configurations:
cargo check --no-default-features                                          # bare no_std
cargo check --no-default-features --features serde                         # no_std + serde
cargo check --no-default-features --features serde --target wasm32-unknown-unknown
```

Tests live in:
- `org-members/tests/integration_test.rs` -- example/unit-style scenarios
- `org-members/tests/fuzz_tests.rs` -- proptest invariants (no panics, count
  consistency, delta roundtrip, immutability)

Test count varies by commit; `cargo test` is the source of truth.

## Lessons learned (don't repeat these)

- **Don't use `sed` on Rust test files.** It wiped a 600-line file once.
  Use the `Edit` tool instead.
- **`once_cell::sync::OnceCell` requires `critical-section` or `std`.** Use
  `spin::Once` for `no_std` instead. Its API is `call_once(|| value)`, not
  `set(value)`.
- **`thiserror` 2.x works in `no_std`** if you don't use `#[from]`/`#[source]`
  features that require `std::error::Error`.
- **`hashbrown` 0.15 with `default-hasher` feature uses `foldhash`** (not
  `ahash`). `foldhash` is `no_std`-compatible.
- **Derived `Deserialize` is a trust boundary footgun.** If a type has
  invariants enforced in its constructor, deserialize must re-run them.
  Standard pattern: deserialize into a private struct, then call the
  validating constructor.
- **WASM `cargo check` only confirms it compiles**, not that it runs. For
  runtime verification add `wasm-bindgen-test` later.
- **`spin::Once::call_once` panics if it recurses on itself** -- don't call
  recalculate inside a hasher impl.

## Where to look first

- `org-members/src/lib.rs` -- crate root, re-exports
- `org-members/src/types.rs` -- MemberId, MemberKey, DeviceKey, MemberLeaf, RootHash, handle validation
- `org-members/src/trie.rs` -- `OrgTrie` public API
- `org-members/src/smt.rs` -- low-level SMT operations (path copying, recalculate)
- `org-members/src/delta.rs` -- Delta, CandidateTrie
- `org-members/src/node.rs` -- internal Node type with `spin::Once` hash
- `org-members/src/hasher.rs` -- TrieHasher trait + Blake3Hasher default

## Known follow-ups (in code review)

Tracked in source comments and doc-strings:
- HashMap indexes (`skeleton_index`, `handle_index`) clone in full per mutation
  -- O(N) memory churn. Future fix: Arc-share frozen index + walk pending
  leaves under unhashed nodes. See doc on `OrgTrie`.
- Poseidon hasher not yet implemented; Blake3 is the placeholder.
- WASM runtime test not yet added (only compile-checked).
- No Merkle path / membership proof extraction API yet.
