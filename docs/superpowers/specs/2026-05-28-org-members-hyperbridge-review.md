# org-members security review — Hyperbridge April 13 post-mortem & web3 hack lessons

**Date:** 2026-05-28
**Reviewer:** jan-jan + claude-opus-4-7
**Subject:** `org-members` crate (Phase 1.a SMT library)
**Reference incident:** [Hyperbridge MMR Verifier Exploit, 2026-04-13](https://blog.hyperbridge.network/april-13-post-mortem/) and the SRLabs audit findings published alongside it.

## 1. Scope and method

This document records a focused security review of the `org-members` crate against the lessons from the Hyperbridge April 13 post-mortem and adjacent web3 hack classes. The review compares each structural lesson from the post-mortem to the corresponding trust boundary in `org-members` and produces concrete code-level findings with mitigations.

The review covers:

- `src/lib.rs`, `src/types.rs`, `src/trie.rs`, `src/smt.rs`, `src/delta.rs`, `src/hasher.rs`, `src/node.rs`, `src/device_trie.rs`, `src/error.rs`, `src/normalize.rs`
- `tests/integration_test.rs`, `tests/fuzz_tests.rs`

Out of scope: the local-first collaboration layer above this crate, the on-chain settlement layer below it, and the future Poseidon hasher (Blake3 is the placeholder).

## 2. Threat model used for the review

The trust-boundary mapping from MMR-style proofs to `org-members`:

| Hyperbridge surface     | `org-members` analogue                                |
| ----------------------- | ----------------------------------------------------- |
| "the proof"             | `Delta { base_root, removed, upserted }` (wire form)  |
| "the verifier"          | `OrgTrie::apply_delta` → `CandidateTrie::verify_against` |
| "trusted root"          | `expected_root: RootHash` passed by caller            |
| "downstream consumers"  | code that iterates `delta.removed()` / `delta.upserted()` for side effects (notifications, replication, audit logs) |
| "validator signatures"  | out-of-scope here; lives in the higher-level lib that signs postcard(Delta) blobs |

The realistic adversary is a **member with broadcast capability who can craft Delta blobs** (e.g. a peer in the local-first mesh). They cannot forge admin signatures. They can submit wire-form variants that still verify against the legitimate target root.

## 3. Hyperbridge lessons translated to this crate

Three structural lessons from the post-mortem:

1. **All input must be consumed.** ("if (leafIter.length != 0) revert OutOfBoundsLeaves();")
2. **Proof canonicality.** One canonical byte string per logical statement — duplicates, unsorted indices, trailing data all rejected.
3. **Input validation at every trust boundary.** Don't trust wire-format invariants; re-validate.

In `org-members` terms, all three reduce to a single invariant we should be able to hand upstream:

> If `apply_delta(d).verify_against(R)` succeeds, then `d` is the **unique** byte string such that applying it to a trie with root `base_root(d)` yields a trie with root `R`.

Today that invariant does not hold.

## 4. Findings

Severity uses the SRLabs scale used in the Hyperbridge report (Critical / High / Medium / Low / Informational).

### H-1 — `Delta` is non-canonical at `apply_delta` (High)

**Where:** `src/trie.rs:400-474` (`apply_delta`); test that encodes the anti-pattern at `tests/integration_test.rs:1098-1117`.

**Hyperbridge analog:** Out-of-bounds leaves (the original April 13 root cause) and S4-4 (duplicate leaf indices in `MerkleMultiProof`). Same structural shape: the verifier silently tolerates wire-form noise that downstream consumers treat as meaningful.

**Behaviour today.** `apply_delta` accepts deltas containing:

- Stale removals (id not in trie — silently skipped, asserted by the test cited above)
- Duplicate ids in `removed`
- Duplicate ids in `upserted` (later entry wins silently)
- The same id in both `removed` and `upserted` (effective re-creation)
- No-op upserts (a leaf identical to the existing one)
- Arbitrary ordering of `removed` and `upserted`

All of these produce the same `candidate.root_hash`, so `verify_against(expected_root)` accepts every variant.

**Why it matters.** A member who can broadcast deltas can construct many distinct postcard blobs that all verify against the legitimate target root. The trie state is correct in every variant — but:

- Downstream consumers that iterate `delta.removed()` for side effects (notify removed members, update local caches, replicate to a search index, write audit logs) act on attacker-injected ghost entries. This is the exact Hyperbridge pattern: *"any caller iterating over the input leaf array would treat both entries as verified."*
- Replay-cache dedup keyed on the hash of the delta blob is bypassed — N distinct blobs all do the same thing.
- A relay/gossip node that deserialises then re-serialises silently produces a different blob from the original signed one.

**Mitigation.** Strict rejection at `apply_delta` entry. Specifically:

1. `delta.removed` MUST be strictly increasing by id and every id MUST exist in the current trie.
2. `delta.upserted` MUST be strictly increasing by id and every entry MUST produce an observable change vs. the current trie state at that id.
3. `delta.removed` and `delta.upserted` MUST be disjoint by id.

Introduce `OrgMembersError::MalformedDelta(reason: &'static str)` for these rejections (distinct from `DeltaBaseMismatch` and `VerificationFailed` so callers can distinguish "stale" from "poisoned").

**Cost.** Two sorted-merge passes over `removed` and `upserted`. Same asymptotic cost as today's loops.

### H-2 — `P2pDeviceSlots` deserialise silently normalises (High)

**Where:** `src/types.rs:323-331`. The doc comment makes the behaviour explicit: *"Unsorted wire input is silently normalized into canonical sorted form."*

**Hyperbridge analog:** S1-16 (single-leaf MMR fast path accepts trailing data — "breaks proof canonicality and creates latent risk for callers that rely on proof bytes for replay protection").

**Behaviour today.** `<P2pDeviceSlots as Deserialize>::deserialize` calls `P2pDeviceSlots::new(slots)`, which sorts in place and dedups. Unsorted or duplicate-containing wire bytes are accepted and re-emitted as the sorted-deduped form. Same `MemberLeaf` → same trie hash via a non-canonical wire form.

**Why it matters.** Same class as H-1 at finer grain. Every place that holds a `P2pDeviceSlots` indirectly inherits the malleability — including the `p2p_devices` field of every `MemberLeaf` in `delta.upserted`.

**Mitigation.** On deserialise, reject (not normalise) inputs that are unsorted or contain duplicates. Caller-construction via `P2pDeviceSlots::new` keeps its current normalise-on-construct behaviour (caller convenience, not a trust boundary).

Concretely, replace the deserialize body with:

- Read `Vec<P2pDeviceKey>` from the wire.
- Reject if `> MAX_DEVICES`.
- Reject if any consecutive pair is unsorted or equal.
- Construct directly (no sort, no dedup).

### H-3 — No length cap on `name` / `surname` on the wire (High)

**Where:** `MemberLeaf::deserialize` (`src/types.rs:456-476`); `MemberLeaf::new` (`src/types.rs:485-506`); `canonical_bytes` width cast at `src/types.rs:589-593`.

**Hyperbridge analog:** General "input validation at every trust boundary" principle from the post-mortem's *What This Changes Going Forward* section.

**Behaviour today.** `handle` is capped at `MAX_HANDLE_LEN = 128` (re-checked on deserialise via `validate_handle`). `name` and `surname` pass through `to_nfc` with no length check. An adversarial wire-format upsert can carry a multi-gigabyte `name` field. `apply_delta` then NFC-normalises it, hashes it, and stores it.

**Why it matters.** Memory-exhaustion DoS during `apply_delta`. Past 4 GiB the `len() as u32` cast in `canonical_bytes` silently truncates, producing a divergent hash from the same payload depending on length-prefix overflow — soundness break at the hashing boundary.

**Mitigation.** Introduce `MAX_NAME_LEN` and `MAX_SURNAME_LEN` (suggest `64` each — RFC 5321 local-part precedent, matches `MAX_HANDLE_LEN`'s reasoning). Enforce in `MemberLeaf::new` (return a new `OrgMembersError::FieldTooLong { field: &'static str, max: usize }` variant) and re-enforce in `MemberLeaf::deserialize` before the `to_nfc` call (so we never NFC-expand attacker-controlled gigabytes).

### M-1 — `Delta` carries no organisation binding or sequence number (Medium → Doc-only)

**Where:** `src/delta.rs:14-22` (`Delta` definition).

**Hyperbridge analog:** General cross-chain-message-spoofing class (broader than any single SRLabs finding).

**Behaviour today.** `Delta` is anchored only by `base_root: RootHash`. Two distinct tries that transiently share a root would accept each other's deltas. A delta could in principle be re-applied if the trie cycles back to a prior root (add-then-remove the same member).

**Why it matters at this layer — actually, it doesn't, much.** With H-1 + H-2 in place, the canonical-form invariant means there is exactly one valid byte string per `(base_root, target_root)` pair. The natural replay surface (different wire encodings of the same change) is closed. Cross-org and cross-time replay protection genuinely belongs in the higher-level lib that signs `postcard(Delta)` blobs — that layer wraps deltas in `(org_id, sequence, signature)` envelopes.

**Mitigation.** Document-only. Add a doc block to `Delta` that states the contract handed upstream:

> `Delta` is scoped only by `base_root`. Cross-org binding, monotonic sequencing, signer authorisation, and replay protection across time are the caller's responsibility. The recommended pattern is to wrap `postcard(Delta)` in a signed envelope `(org_id, seq, sig)` before transmission.

Also add a `Delta` doc-comment that names the canonical-form invariant from §3 explicitly, so upstream can rely on it.

### M-2 — `member_count` arithmetic is unchecked (Medium)

**Where:** `src/trie.rs:278` (`+ 1` in `insert_leaf`), `src/trie.rs:316` (carry in `update_leaf`), `src/trie.rs:339` (`- 1` in `delete_by_id`), `src/trie.rs:421` (`-= 1` in `apply_delta` remove loop), `src/trie.rs:459` (`+= 1` in `apply_delta` upsert loop).

**Hyperbridge analog:** General integer-safety hygiene (not a specific SRLabs item, but the post-mortem's general principle of "properties enforced on-chain rather than assumed" maps directly).

**Behaviour today.** All five sites use unchecked `usize` arithmetic. The invariant *"`member_count` equals the actual number of members in the trie"* holds today (fuzz-asserted in `tests/fuzz_tests.rs:127-132`), but a future bug that breaks it would wrap to `usize::MAX` silently in release.

**Mitigation.** Replace each site with `checked_add(1)` / `checked_sub(1)` returning `OrgMembersError::InvariantViolated` on overflow/underflow. Cheap, defensive, future-proof.

### M-3 — Adversarial-delta test encodes the buggy behaviour (Medium, follow-on to H-1)

**Where:** `tests/integration_test.rs:1098-1117` (`apply_delta_ignores_stale_removal`).

**Behaviour today.** The test injects a stale removal into a delta and asserts that `apply_delta` accepts it. Under H-1's fix, the correct behaviour is rejection.

**Mitigation.** Flip the assertion: stale removal must produce `OrgMembersError::MalformedDelta(_)`. Add sibling tests for the other H-1 cases (duplicate ids in `removed`, duplicate ids in `upserted`, id in both, no-op upsert, unsorted input).

### L-1 — Unbounded recursion in `recalculate_hashes` and `insert_at` (Low)

**Where:** `src/smt.rs:101-125` (`recalculate_hashes`), `src/smt.rs:68-96` (`insert_at`).

**Behaviour today.** Both recurse to `SMT_DEPTH = 256`. With current stack frames (Blake3 hashing, Arc clones) the worst case fits comfortably in the default 8 MiB Rust thread stack. WASM stacks are typically smaller (~1 MiB default); the future Poseidon hasher will have heavier per-frame footprint.

**Mitigation.** Note for follow-up when Poseidon lands: convert `recalculate_hashes` to an explicit stack (`Vec<&Arc<Node>>`). No action required today.

### L-2 — `From<NodeHash> for RootHash` is infallible (Low)

**Where:** `src/types.rs:292-296`.

**Behaviour today.** Any `NodeHash` (intermediate node hash) can be widened to a `RootHash`. Not exploitable today because `expected_root: RootHash` comes from trusted callers, but the type distinction's defensive value is partly undermined.

**Mitigation.** Optional. Drop the `From` impl in favour of an explicit `RootHash::from_root_node(&Node)` or `RootHash::from_trusted_bytes([u8; 32])` constructor only called at trie-root sites. Worth one PR's effort; not urgent.

### Info-1 — Hash domain separation looks correct (Informational)

**Where:** `src/hasher.rs:9-50`.

Four distinct keyed_hash contexts for `member-leaf`, `member-node`, `device-leaf`, `device-node`. Empty sentinels (`src/smt.rs:13`, `src/device_trie.rs:4`) are non-zero, domain-tagged strings. No cross-domain collision path visible. Pre-flight check needed again when Poseidon replaces Blake3.

### Info-2 — Deserialise re-validation is largely correct (Informational)

`MemberLeaf::deserialize` re-runs `validate_handle` and `to_nfc` on name/surname (`src/types.rs:456-476`). `P2pMemberKey` / `P2pDeviceKey` re-run `VerifyingKey::from_bytes`. The lib's stated lesson — *"Derived `Deserialize` is a trust boundary footgun"* (`org-members/AGENTS.md`) — is reflected in the code. The gaps are H-2 (silent normalise) and H-3 (no length cap).

### Info-3 — `add_p2p_device` does not rotate the p2p_key (Informational)

Intentional and correct (`src/trie.rs:202-211`). AGENTS.md explicitly documents: *"A new device is trusted with the current key."* The rotation requirement is only on `delete_p2p_device` / `emergency_isolate_member`, where the deleted device had access to the old key.

### Info-4 — Missing structural fuzz harness for canonicality (Informational)

**Hyperbridge analog:** *"Continuous structural fuzzing for verifier libraries"* (from the post-mortem's *What This Changes Going Forward* section).

Existing fuzz tests (`tests/fuzz_tests.rs`) cover no-panic, count consistency, delta roundtrip, immutability. None of them probe *"any wire form other than the canonical one is rejected by apply_delta"*. After H-1 + H-2 land, add a `delta_canonicality_fuzz` that takes a valid delta, applies an arbitrary mutator (inject stale removal, inject duplicate, swap two entries, append no-op upsert, replace `p2p_devices` with an unsorted equivalent), and asserts `apply_delta` returns `MalformedDelta`. Each H-1 / H-2 case becomes a regression seed.

## 5. Recommended fix order

1. **H-1** — add `OrgMembersError::MalformedDelta`, enforce sorted-unique-disjoint in `apply_delta`.
2. **H-2** — flip `P2pDeviceSlots::deserialize` from normalise to reject.
3. **H-3** — add `MAX_NAME_LEN` / `MAX_SURNAME_LEN`, enforce in `new` and `deserialize`, add `FieldTooLong` error.
4. **M-2** — switch `member_count` arithmetic to checked.
5. **M-3** — flip `apply_delta_ignores_stale_removal`; add sibling tests for the other canonicality cases.
6. **Info-4** — add the `delta_canonicality_fuzz` harness with regression seeds for each H-1 / H-2 case.
7. **M-1** — doc-only update to `Delta` stating the canonical-form invariant and upstream's responsibilities.
8. **L-2** — drop `From<NodeHash> for RootHash`, add explicit constructor.
9. **L-1** — note for follow-up when Poseidon lands.

Steps 1-6 are the substance of the response to the Hyperbridge post-mortem; steps 7-9 are general hardening.

## 6. The invariant we want to hand upstream after these fixes

> **Canonical-form invariant.** If `OrgTrie::apply_delta(&d)?.verify_against(&R)?` succeeds, then `d` is the unique byte string `b` (under postcard) such that some honest sequence of `OrgTrie` mutations starting from a trie with `root_hash() == d.base_root()` would produce a trie with `root_hash() == R` and `Delta::serialize` would emit `b`.

Once this holds, the higher-level lib can:

- Hash `postcard(Delta)` and use it as a replay-cache key.
- Sign `postcard(Delta)` knowing no semantically-equivalent alternative blob exists.
- Bind `(org_id, seq, sig, postcard(Delta))` in a wrapper envelope for cross-org / replay protection.

…without having to defensively re-canonicalise on every receive.

## 7. Out of scope

- The local-first collaboration layer (handles signing, authority, org-binding, sequencing).
- The on-chain settlement layer (checks the root hash on-chain).
- Poseidon hasher (placeholder today; redo Info-1 review when it lands).
- WASM runtime tests (compile-checked only today; AGENTS.md tracks this).
- HashMap index churn optimisation (tracked in `OrgTrie` doc-comment).
