# org-members

Immutable binary Sparse Merkle Tree (SMT) for organisation membership.

API reference: rustdoc on `OrgTrie`, `MemberLeaf`, `Delta`, `CandidateTrie`.
Crate-internal guidance: `AGENTS.md`.

## What this crate guarantees

The target contract is one invariant, precisely:

> **Canonical-form invariant.** If `OrgTrie::apply_delta(&d)?.verify_against(&R)?` succeeds, then `d` is the unique postcard byte string such that some honest sequence of `OrgTrie` mutations starting from a trie with `root_hash() == d.base_root()` produces a trie with `root_hash() == R`.

**Status:** the invariant holds. Established by the [Hyperbridge fix series](../docs/superpowers/plans/2026-05-28-org-members-hyperbridge-fixes.md), which lands H-1, H-2, H-3, M-1, M-2, M-3, and Info-4 from the [review spec](../docs/superpowers/specs/2026-05-28-org-members-hyperbridge-review.md). Callers can rely on `apply_delta` rejecting any non-canonical wire form; defensive re-canonicalisation upstream is no longer required.

Everything else is the caller's responsibility. This README enumerates what "everything else" means in security terms.

## Trust boundary

```
   ┌──────────────────────────────────────────────────────────┐
   │  Higher-level library                                    │
   │   - signs deltas, verifies signatures                    │
   │   - binds deltas to (org_id, sequence)                   │
   │   - decides authority / quorum / policy                  │
   │   - reconciles against the trusted root (e.g. on-chain)  │
   │   - dedupes / replay-protects                            │
   └────────────────────┬─────────────────────────────────────┘
                        │ postcard bytes
   ┌────────────────────▼─────────────────────────────────────┐
   │  org-members                                             │
   │   - parses Delta from postcard bytes                     │
   │   - rejects malformed/non-canonical wire form            │
   │   - applies delta → CandidateTrie                        │
   │   - verifies CandidateTrie.root_hash == expected         │
   │   - returns the new immutable OrgTrie                    │
   └──────────────────────────────────────────────────────────┘
```

The crate does **not** sign, does **not** authenticate, does **not** authorise, does **not** sequence, does **not** dedupe, does **not** know what organisation it belongs to. All of those live above.

## Security checks the caller MUST perform

### 1. Verify the proposed new root against a trusted source before accepting

This is the contract `CandidateTrie::verify_against` exists for. The `expected_root: RootHash` argument must come from **a source the attacker does not control** — typically:

- A root committed on-chain by an admin-controlled multi-sig
- A root signed by ≥ N of M admin keys, verified at the caller
- A root from a notary / settlement layer

```rust
// WRONG: trusting the root from the same payload as the delta
let expected = received_blob.claimed_root;     // attacker chose this too
let trie = candidate.verify_against(&expected)?;

// RIGHT: trusting an independent oracle
let expected = onchain.read_org_root(org_id)?; // attacker can't forge this
let trie = candidate.verify_against(&expected)?;
```

The crate cannot enforce this. `RootHash::from_bytes` accepts any 32 bytes; what matters is *where those bytes came from*.

### 2. Authenticate the delta blob before applying

The crate has no notion of "who sent this." Callers must:

- Verify a signature over the postcard bytes of the `Delta` against a known admin / quorum public key.
- Do this **before** calling `apply_delta` (so attacker-controlled bytes never reach the trie).
- Use the canonical-form invariant: once you've verified one byte string for a given `(base_root, target_root)`, no other byte string with the same effect exists, so signatures, hashes, and replay caches all key cleanly off the blob bytes.

### 3. Bind the delta to its organisation

`Delta` carries `base_root` and nothing else. Two distinct organisations whose tries happen to share a root would accept each other's deltas. Wrap every transmitted delta in an envelope:

```rust
struct SignedDeltaEnvelope {
    org_id: [u8; 32],
    parent_seq: u64,
    delta_bytes: Vec<u8>,   // postcard(Delta)
    signature: Signature,   // over (org_id || parent_seq || delta_bytes)
}
```

Verify `org_id` matches your local org's identity before deserialising `delta_bytes`. The crate has no opinion on the envelope format — just don't let raw `Delta` blobs cross the network unwrapped.

### 4. Replay protection across time

`base_root` alone provides natural protection while the trie keeps moving forward — a delta for v1→v2 is rejected by `apply_delta` once the trie has advanced past v2. But if the trie's history ever revisits a prior root (e.g. add-then-remove the same member), a stale delta becomes applicable again. Defend at the envelope level with a monotonic `parent_seq` and reject envelopes whose `parent_seq` you have already observed.

### 5. Authorise the signer for the proposed change

A canonical, correctly-signed delta is not the same as an authorised delta. The crate accepts any well-formed change; whether the signer is *allowed* to remove a particular member, isolate a particular member, or rotate a particular key is a policy decision the higher layer owns. Examples of policy the caller should encode:

- Quorum requirements (N-of-M admin signatures for any delta that changes membership count).
- Role-based veto (no single admin can `emergency_isolate_member` themselves).
- Rate limits / suspicious-change detection (a delta that removes >10% of members in one batch warrants out-of-band confirmation).

### 6. Treat `delta.removed()` / `delta.upserted()` as descriptive, not normative

The crate produces deltas in canonical form, but they describe **the wire change**, not the policy decision behind it. Side-effects driven by iterating these arrays — notifying removed members, replicating to search indexes, writing audit logs, kicking sessions — should:

- Use the **resulting `OrgTrie`** as the source of truth for current state, not the delta arrays.
- Use the delta arrays only to *enumerate* what changed, not to *decide* what changed (always cross-check against the trie).
- Be idempotent: the same delta may be retransmitted by the gossip layer; effects must not double-fire.

### 7. Resolve conflicts between competing valid deltas

Two admins working off the same `base_root` can produce two distinct canonical deltas that both verify. Both are well-formed; the crate has no preference. The caller chooses the conflict resolution policy — first-finalised-wins on-chain, last-writer-wins by timestamp, deterministic tie-break on signer id, manual escalation, etc. The lib's job ends at "this candidate is well-formed and matches expected_root."

### 8. Handle PII outside the crate

`MemberLeaf::Debug` redacts handle / name / surname (`[REDACTED]`) so debug logs don't leak PII through this crate. But:

- The crate's `MemberLeaf` accessors (`.handle()`, `.name()`, `.surname()`) return the raw values — anything the caller does with those is the caller's PII responsibility.
- `postcard(Delta)` contains plaintext PII. Encrypt at the transport layer; encrypt at rest.
- Audit logs that record `delta.upserted()` are PII. Apply your retention and access-control policy.

### 9. Validate inputs you originate

Before calling `add_member` / `update_handle` / etc., callers must do their own input validation appropriate to context:

- Confirm the human submitting a handle change actually owns the member id (auth check above this lib).
- Apply application-level rate limits (the crate does no rate limiting).
- Enforce any business rules the crate doesn't know about (e.g. "cannot remove the last admin").

The crate validates *what it needs to maintain its own invariants* (handle shape, device count, id presence/absence). It does not validate *what makes business sense*.

### 10. Keep `expected_root` and `delta` independent

The most common way to break the security model is to receive `(delta, expected_root)` as a single payload from the same untrusted source, then call `apply_delta(delta).verify_against(expected_root)`. That tautologically passes — the attacker chose both sides. The expected root must come from a separate trust path.

## What the crate does on its own

For completeness, what the caller does **not** need to re-do:

- Handle validation (UTS#39, NFC, lowercase, single-script, no `.`, length-capped) is re-run on every wire-format `MemberLeaf` deserialise.
- Confusable/homoglyph collision is re-checked in `apply_delta` for both newly-upserted and renamed members.
- ed25519 keys (`P2pMemberKey`, `P2pDeviceKey`) are re-validated on deserialise via `VerifyingKey::from_bytes`.
- Device-slot constraints (≤ `MAX_DEVICES`, no duplicates, sorted) are enforced on deserialise (after the H-2 fix) — non-canonical wire forms are rejected, not normalised.
- `Delta` canonical form (sorted-unique-disjoint, no stale removals, no no-op upserts) is enforced in `apply_delta` (after the H-1 fix).
- `base_root` of the delta must match the current trie root; mismatched deltas are rejected with `DeltaBaseMismatch`.
- `CandidateTrie::verify_against` checks the post-application root against the caller-supplied expected root.

The combination of those guarantees gives the caller the canonical-form invariant at the top of this README. Build everything else on that foundation.
