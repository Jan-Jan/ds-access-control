# ODS Phase 1.d — p2panda spike decision

**Status:** Draft (single-library decision; head-to-head with Keyhive pending)
**Date:** 2026-05-28
**Pinned commit:** `41559b0dfc2d7d0e9e4fba251ceb7f8094ff8be1`
**Detailed findings:** [`spike-p2panda-report.html`](spike-p2panda-report.html)

This document records the per-library decision for p2panda based on the
ODS Phase 1.d spike. The final head-to-head decision between p2panda
and Keyhive comes after the Keyhive spike completes (see
[`spike-comparison.html`](spike-comparison.html) — to be produced).

---

## 1. Pick

**p2panda is qualified as a viable Phase 3 substrate, with bounded fork
burden.**

The spike successfully demonstrated every substitution the ODS design
requires (six gates across L1, L2, and L3 test levels) without modifying
p2panda's source. The friction encountered is localised to two crates
(`p2panda-spaces` and, conditionally, `p2panda-sync`) and is salvageable
through a small fork plus the adapter code already written in the spike.

The strength of this recommendation depends on whether WASM is a hard
requirement for Phase 3:

- **Without WASM** — burden 20. One small fork (one `pub use` line) plus
  the in-spike `TraitImpl` code. Highly recommended.
- **With WASM** — burden 32. Adds one Large fork of `p2panda-sync` to
  swap `tokio` for `tokio_with_wasm`. Recommended with explicit
  acknowledgement of the network-layer work.

This is a per-library qualification, not the final head-to-head pick.
The final decision compares total burden against Keyhive's spike when
that completes.

## 2. Disqualifying gaps

**None.** No gate produced a finding that disqualifies p2panda. Every
Hard severity has a documented salvage path under the project's
fork-locally policy, and the salvage paths are bounded:

| Gate | Salvage | Effort |
|---|---|---|
| 0 (WASM) | Fork `p2panda-sync` → `tokio_with_wasm` | Large (only with WASM requirement) |
| 1 (stable-ID ACL) | TraitImpl already implemented in `spike-p2panda/src/s1_stable_id_acl.rs` | Small |
| 2 (op interception) | Fork `p2panda-spaces` with `pub use types::AuthGroupState;` | Small |
| 4A (org-pseudo-group delegation) | Same fork as gate 2 (transitive) | Small (shared) |
| 4C (org-pseudo-group rotation) | Same fork as gate 2 (transitive) | Small (shared) |

The fact that three Hard rows (2, 4A, 4C) share a single root cause and a
single one-line fork patch is the strongest signal that p2panda's
upstream API surface is close to being a clean fit.

## 3. Per-library narrative

### What worked

- **`p2panda-auth` is a clean target for stable-ID ACL.** The `GroupCrdt`
  CRDT is fully generic over its identity type bound. `MemberId` plugs in
  directly. Nested groups (`GroupMember::Group(ID)`) work cleanly and the
  CRDT's `members()` method auto-resolves them — no manual walker needed
  for the org-as-pseudo-group principal.

- **`p2panda-encryption`'s DCGKA is genuinely substrate-agnostic.** The
  `IdentityRegistry` and `PreKeyRegistry` traits expose every key
  injection point we need. The spike's `ResolverPki<R>` wraps the
  `MemberKeyResolver` and the spike's `trigger_recompute` drives DCGKA
  updates after trie rotation. Both flows pass with full encryption-layer
  evidence (not simpler probes).

- **`p2panda-sync`'s `SessionConfig::remote` exposes the peer key at
  session-establish time.** This is the natural hook for connection-policy
  enforcement and the spike's `PolicyManager` uses it directly.

### What needed work

- **`p2panda-spaces` is the friction point.** Three of the four Hard rows
  in the no-WASM picture trace back to one issue: the public store and
  group traits reference types from private modules. A single
  `pub use` patch unblocks them all.

- **`ActorId` is hardwired through `Group::add` / `Space::add`.** Stable-ID
  ACL at the spaces layer requires a wrapper. The spike's
  `materialise_actor_id` resolves a `Principal` to a fresh `ActorId` at
  call time (~10 lines). `From<VerifyingKey> for ActorId` is public — a
  positive surprise that makes the wrapper trivial.

- **`Dcgka::update` vs `Dcgka::remove`.** Discovered during L3 revocation:
  the spike's gate-3 `trigger_recompute` wraps `Dcgka::update`, which is
  correct for key rotation but wrong for membership removal
  (`update` sends direct messages to all DGM members including the
  removed one, breaking forward-security). Phase 3 must dispatch to
  `Dcgka::remove` on revocation. Documented in
  `spike-p2panda/src/evidence/s3.md`.

### Escape hatches taken

1. **Orphan rule.** Newtypes (`SpikeMemberId`, `DcgkaMemberId`,
   `AuthMemberId`) wrap `MemberId` to implement foreign traits in
   downstream code. Goes away in Phase 3 (impls in the production
   crate are legal directly on `MemberId`).
2. **`IdentityRegistry::identity_key` is a static method.** The spike
   threads the resolver via the `Y` type parameter
   (`Y = ResolverPki<R>`). Works; alternative is to fork
   `p2panda-encryption` to change the receiver to `&self`.
3. **Ed25519 → X25519 byte reinterpretation** for the PKI lookup role.
   Justified because the identity key at this position is a stable
   anchor for bundle lookup; actual ECDH uses separate pre-key bundles.
   Phase 3 must validate the separation is preserved.
4. **`KeyRegistry<MemberId>` as DCGKA's `PKI` generic** (not `ResolverPki`
   directly). Required because the PKI state must be `Serialize + Deserialize`
   and must hold pre-key bundles. The resolver populates the
   `KeyRegistry` at group setup and at rotation time.
5. **Reverse-lookup closure** in `PolicyManager` — the
   `MemberKeyResolver` trait has no
   `find_member_by_device(VerifyingKey)` method. The closure injection
   works but Phase 3 should formalise this.
6. **`p2panda-encryption::test_utils` feature** in spike dev-deps to
   construct DCGKA state in tests via
   `KeyManager::init_and_generate_prekey`. Production code uses the
   real key-generation path.

### Constraint discovered

- **`GroupMember::Group(ID)` with `Access::manage()` is rejected by
  the CRDT** (`ManagerGroupsNotAllowed`). The org pseudo-group must
  use `Read` or `Write` access; managerial actions stay with
  `Individual` members. This matches the ODS design — admin status
  is on-chain, not in the local-first ACL.

## 4. Risk register for the pick (the Soft rows)

Each `Soft` row in the gap matrix is phase-3 work. None is showstopping.

| # | Risk | Mitigation |
|---|---|---|
| R1 | Gate 3 Flow B (CGKA compute) — DCGKA construction has many generics; the integration code threads them all. | Spike already does this; phase 3 reuses the type aliases in `s3_cgka_rotation.rs`. |
| R2 | Gate 3 Flow C (CGKA recompute) — rotation triggers must distinguish member-as-a-group rotation from individual device removal. | Phase 3 trie-observer dispatches to the correct DCGKA op (`update` vs `remove`). Integration finding documented. |
| R3 | Gate 5 Flow E1/E2 — pre-open session policy works at the `p2panda-sync` layer, not at the iroh QUIC layer. A peer can complete the TCP/TLS handshake before being rejected. | Acceptable for ODS; revocation security depends on the trie, not on connection refusal. |
| R4 | Gate 5 Flow F1/F2 — termination is pull-based via `recheck_open_sessions`. Trie change → close has latency proportional to the recheck cadence. | Phase 3 needs trie-push notification; risk note in `spike-p2panda/src/evidence/s5.md`. |
| R5 | Gate 5 reverse lookup — closure-based workaround; phase 3 should formalise as a `MemberKeyResolver` trait method. | Small change to `spike-common` foundation in phase 3. |

## 5. Salvage paths for any not-picked alternative

The final phase-1.d decision document will record this section after
the Keyhive spike. For now, see `spike-comparison.html` (forthcoming).

## 6. Gap matrix appendix

The canonical machine-readable matrix is at
[`docs/phase-1d/gap-matrix.json`](gap-matrix.json); the rendered Markdown
version is at [`docs/phase-1d/gap-matrix.md`](gap-matrix.md). Full
narrative summaries are in the HTML report
[`spike-p2panda-report.html`](spike-p2panda-report.html) §6.

Headline figures:

- **Without WASM gate:** 4 Hard + 6 Soft = burden 20.
- **With WASM gate:** 5 Hard + 6 Soft = burden 32.

## 7. Replication instructions

To reproduce the spike's findings:

```bash
# Clone and enter the worktree
cd /Users/jan-jan/Coding/2-tier-access-control
git checkout worktree-spike-phase-1d   # branch from this spike

# Confirm the p2panda pin
grep "p2panda-spaces" spike-p2panda/Cargo.toml
# Expected: rev = "41559b0dfc2d7d0e9e4fba251ceb7f8094ff8be1"

# Full test suite (workspace-wide, default features)
cargo test --workspace
# Expected: ~129 tests pass

# Per-gate L1+L2 sweep
cargo test -p spike-p2panda

# Three L3 scenarios
cargo test -p spike-p2panda --test l3_revocation
cargo test -p spike-p2panda --test l3_gating
cargo test -p spike-p2panda --test l3_org_pseudo_group

# Build matrix
cargo clippy --workspace --all-features -- -D warnings
cargo clippy --workspace --tests --all-features -- -D warnings
cargo check -p spike-common --no-default-features --features serde --target wasm32-unknown-unknown
cargo check -p spike-keyhive --no-default-features --target wasm32-unknown-unknown

# Gate 0 per-crate WASM probe (see docs/phase-1d/gate-0-results.md)
# Six sub-crate checks; five pass, p2panda-sync fails.
```

The spike spans 14 commits on the `worktree-spike-phase-1d` branch from
`74c3dce` (inventory) through `09e1a5f` (consolidation).

---

**Next step.** Same shape of spike against Keyhive, then the head-to-head
comparison report and the final phase-1.d decision document.
