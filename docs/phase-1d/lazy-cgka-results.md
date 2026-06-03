# Phase 1.d — Lazy-CGKA design results

**Date:** 2026-06-03
**Pinned Keyhive commit:** `a2876f3c79d89c9dd0c5e9f84802611c716fe27e`
**Status:** Design decided; semantics validated by L3 test on first run.

## Problem statement

Both Keyhive's `Keyhive::add_member(Agent::Individual, ...)` and
p2panda's `manager.add_member(member_id, key_bundle)` *eagerly* place a
new member in the CGKA encryption tree. The eager-add convenience path
therefore requires the new member's prekey material at add-time. For
ODS this is unworkable because publishing prekeys to the on-chain trie
would mean a write per prekey rotation; off-chain prekey publication
adds infrastructure (a public-read contact-card doc) and creates a
bootstrap chicken-and-egg for the first member.

## Decision

ODS commits to a **two-tier** decomposition that operates *below* the
eager-add convenience APIs:

| Tier | Source of truth | Cadence | Carries |
|------|-----------------|---------|---------|
| ACL  | Trie (on-chain) | Rare — onboarding + rotation/revocation | `(MemberId, VerifyingKey)` |
| CGKA tree | Per-document BeeKEM state | Per-write, per-rotation | x25519 leaf keys (online members only) |

### Flow

1. **Grant.** Alice grants bob ACL access on doc D. The trie records
   the delegation against bob's `MemberId`/`VerifyingKey`. No prekey
   publication. No CGKA mutation. Bob may be offline.
2. **Come-online self-add.** When bob next syncs, his client sees the
   delegation, fetches doc D's current CGKA state, generates a fresh
   x25519 leaf, and commits a self-add to BeeKEM (signed by bob,
   verifiable as authorised by alice's delegation).
3. **History transfer.** Bob asks an already-authorised peer for the
   document's history. ODS's existing encryption-at-rest /
   encryption-in-transit split makes this safe: the peer has plaintext
   at-rest and retransmits under the current CGKA epoch (which bob is
   now in). No new privilege leak — the peer already had read access.
4. **Revocation.** Trie revokes bob. Existing members commit a CGKA
   remove/update; bob's leaf rotates out. Forward security holds via
   fresh `PcsKey` on the new epoch.

## Library-API consequence

Both libraries ship the architectural decomposition the lazy model
needs; both ship the eager-add convenience APIs at the top:

| Layer | Keyhive | p2panda |
|---|---|---|
| Eager-add convenience (requires prekey at add-time) | `keyhive_core::Keyhive::add_member` | `p2panda_spaces::Manager::add_member` |
| Direct delegation construction (no prekey needed) | `keyhive_core` delegation log | `p2panda-auth` `GroupCrdt` |
| Direct CGKA placement (caller supplies leaf key) | `beekem::Cgka::add(id, pk, signer)` | `p2panda-encryption` `Dcgka::*` |

Phase 3 composes the lower two rows directly. The convenience APIs are
out of the production path.

## Burden impact

Gate 1 `phase3_effort` for Keyhive reverts to **Small** (the original
API-only prediction; the mid-spike `Medium` revision based on the
high-level-API observation is superseded). p2panda's gate 1 was
already Small/Small. Burden:

| Library | Before | After | Δ |
|---|---|---|---|
| Keyhive | 24 | **22** | −2 |
| p2panda | 32 | 32 | — |
| Delta (Keyhive vs p2panda) | −25 % | **−31 %** | — |

Other gates unchanged.

## Running-code validation

`spike-keyhive/tests/l3_lazy_onboarding.rs` exercises the design
end-to-end. **Four invariants, all hold on first run, no integration
finding surfaced:**

1. **Forward security in the new-member direction.** Pre-onboarding
   ciphertexts (epoch N, alice-only) are **not** decryptable by bob
   after he is added in epoch N+1. BeeKEM's epoch separation works
   symmetrically — old epochs were never encrypted to bob, no
   "welcome message" carries old secrets across the boundary.
2. **Post-onboarding decryption.** Post-onboarding ciphertexts
   (epoch N+1+) **are** decryptable by bob directly.
3. **History transfer via re-transmission.** Alice re-encrypts the
   pre-onboarding plaintext (which she has at-rest) under the current
   CGKA epoch. Bob decrypts the retransmission and recovers the
   original bytes.
4. **Consistency.** Alice's view remains intact across the lazy
   onboarding event — she decrypts all three ciphertexts (original
   pre-content, post-content, retransmitted pre-content).

The test exercises Keyhive's high-level `add_member` entry point for
the ACL grant + CGKA placement step. The mechanism being validated —
**BeeKEM epoch separation + plaintext re-transmission under the new
epoch** — is identical under the lower-level composition.

## What this means for Phase 3

The design semantics are proven. Phase 3's remaining task is
*wiring*, not *design*:

1. Construct delegations directly against `Identifier(VerifyingKey)`
   without materialising an `Individual` (or, equivalently, use
   Keyhive's lower-level signed-op constructors that don't require
   prekey state).
2. Drive `beekem::Cgka::add` from the new member's own client when
   the trie delegation reaches them.
3. Wire the history-transfer mechanism into the application's sync
   protocol — an existing authorised peer detects "new member needs
   history" and emits retransmissions.
4. Add `MemberKeyResolver::find_member_by_device(&VerifyingKey) ->
   Option<MemberId>` to `spike-common` as the foundation-trait
   extension supporting reverse-lookup in gates 4C+5. (Foundation
   change deferred per the spike-common-freeze policy.)

## Resolved findings

The 2026-06-02 evening "ContactCard publication" architectural
implication is **withdrawn**. The trie does not need to publish or
sign ContactCards. The `MemberKeyResolver::contact_card` extension
proposed in that interim revision is **not required**.

## Cross-references

- Full design narrative: [`spike-keyhive-decision.md` §3.1](spike-keyhive-decision.md)
- Gate-1 evidence (incl. design pivot section): [`spike-keyhive/src/evidence/s1.md`](../../spike-keyhive/src/evidence/s1.md)
- Test source: [`spike-keyhive/tests/l3_lazy_onboarding.rs`](../../spike-keyhive/tests/l3_lazy_onboarding.rs)
- Head-to-head comparison §5.1: [`spike-comparison.html`](spike-comparison.html)
- Burden matrix (Keyhive gate 1 row): [`gap-matrix.md`](gap-matrix.md)
