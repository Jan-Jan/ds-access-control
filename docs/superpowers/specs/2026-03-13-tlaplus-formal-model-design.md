# Formal Verification of Two-Tier Blockchain-Mediated Access Control

## Goal

Comprehensive formal model of the Two-Tier Access Control system in TLA+ verified with Apalache (SMT-based symbolic model checker), with TLC as fallback. The model verifies safety properties, liveness properties, and protocol correctness across both tiers.

## Language & Tooling

- **Primary:** TLA+ with Apalache
- **Fallback:** TLA+ with TLC (explicit-state model checker)
- **Rationale:** Apalache handles parameterized/unbounded state spaces better via SMT solving, which suits a system parameterized by member count, threshold, etc. TLC is more battle-tested and serves as fallback if Apalache hits limitations.

## Module Structure

### Tier 1 (OE)

```
OEMerkleTree.tla              -- membership data model
RootHashUpdate.tla             -- propose/verify/commit via proxy multisig
OESKMemberDistribution.tla     -- post-commit OESK distribution to members
OE.tla                         -- composition spec wiring Tier 1 together
OEProperties.tla               -- invariants and temporal properties
```

### Tier 2 (CU)

```
OEAssumptions.tla              -- axioms from verified Tier 1 properties
SyncGate.tla                   -- gates ALL inbound CU operations
TrustPromotionGate.tla         -- observation-based window lifecycle
CULifecycle.tla                -- CU state model, mutations flow through gates
CU.tla                         -- composition spec wiring Tier 2 together
CUProperties.tla               -- invariants and temporal properties
```

### Dependency Flow

- Tier 1 modules are self-contained.
- `OE.tla` composes all Tier 1 modules; cross-cutting Tier 1 properties are checked here.
- `OEAssumptions.tla` encodes proven Tier 1 properties as axioms (e.g., `IsValidZKP(handle, rootHash) <=> handle \in MembersOf(rootHash)`).
- Tier 2 modules depend on `OEAssumptions.tla`, never on Tier 1 internals.

## Abstraction Levels

### Tier 1: Partially Abstract

- **Merkle tree:** Function from handle to `{handle, roles, oePubKey, status}`. Not a binary tree — structural properties abstracted away.
- **Root hashes:** Abstract values; each maps to a membership snapshot.
- **Proxy multisig:** Modeled with explicit approval set and threshold count. The proxy allows updating the accounts associated with the multisig (admin changes are a two-step process: Merkle tree update + multisig update).
- **OESK:** Abstract value that changes each epoch. Well-formedness is a boolean predicate.
- **Challenge-response:** `AdminVerifies(admin, handle, rootHash)` succeeds iff admin has tree for `rootHash` and handle is a leaf with matching key.
- **ZKP:** `ZKPVerifies(handle, rootHash)` succeeds iff `handle \in MembersOf(rootHash)`. Used only by non-admin verifiers.
- **Double Ratchet:** Abstracted as secure pairwise channel — messages are delivered faithfully or not at all. No modeling of ratchet state.

### Tier 2: Fully Abstract

- **OE:** Axioms from `OEAssumptions.tla`. `MembersOf(rootHash)` returns a set of handles.
- **ZKP:** Boolean predicate `IsValidZKP(handle, rootHash)`.
- **CU encryption keys:** Abstract values that change on re-key events.

## Verification Auth Model

Two mechanisms, selected by what the verifier has access to:

| Verifier | Mechanism | Has Access To |
|----------|-----------|---------------|
| Admin verifying anyone (off-chain) | Challenge-response | Full Merkle tree |
| Non-admin verifying anyone | ZKP | Root hash only |
| Anyone proving to a smart contract | ZKP | Smart contract has root hash only |

This covers: admin-to-admin (challenge-response), admin-to-member (challenge-response), member-to-admin (ZKP), CU peer-to-peer (ZKP), smart contracts (ZKP). Note: even admins use ZKP for on-chain interactions because smart contracts only have the root hash.

**Deviation from source document:** The source document describes admins verifying members via ZKP during OESK distribution. This spec simplifies admin-facing verification to challenge-response, since the admin already has the full tree and ZKP adds no security benefit in that context. The source document text has not yet been updated to reflect this simplification.

## Module Details

### `OEMerkleTree.tla`

**State:**
- `members`: set of `{handle, roles, oePubKey, status}` where `status \in {"active", "revoked"}`
- `rootHashes`: sequence of root hashes, each mapping to a frozen membership snapshot
- `currentEpoch`: integer index into `rootHashes`

**Operations:**
- `AddMember(handle, metadata)` — adds leaf to pending tree
- `RevokeMember(handle)` — marks as revoked in pending tree
- `BuildNewTree()` — produces new root hash from current state

Pure data module. No protocol logic, no concurrency.

### `RootHashUpdate.tla`

**State:**
- `updatePhase \in {"idle", "proposed", "distributing", "approving", "committed", "failed"}`
- `proposer`: handle of initiating admin
- `pendingRootHash`: proposed new root hash
- `newOESK`: generated secret key (abstract value)
- `deltaMerkleTree`: delta anchored to current/old root hash
- `multisigApprovals`: set of admins who have verified and approved
- `threshold`: minimum approvals required
- `multisigAccounts`: set of accounts authorized for the proxy multisig (mirrors admin set)
- `competingProposals`: set of other in-flight proposals

**Transitions:**
1. `Propose(admin)` — admin applies a batch of changes to the Merkle tree (add/remove/update members). Generates new OESK. Phase → "proposed".
2. `DistributeToAdmin(proposer, admin)` — proposer sends Merkle delta + OESK to each admin via pairwise Double Ratchet. Phase → "distributing".
3. `AdminVerifiesAndApproves(admin)` — admin independently verifies:
   - Merkle delta is well-formed and its root matches the proposed root hash
   - OESK is well-formed
   Then approves via proxy multisig. Added to `multisigApprovals`. Phase → "approving".
4. `Commit()` — once `|multisigApprovals| >= threshold`, the proxy multisig executes, updating the on-chain root hash. Phase → "committed". `currentEpoch` increments. Competing proposals fail.
5. `Fail()` — competing proposal commits first (root hash changed), invalidating this proposal.

**Key constraints:**
- Delta anchored to current (old) tree — prevents puppet admin attack
- Multisig accounts correspond to admins in the current (old) tree — threshold approval comes from current admins
- Competing proposals serialized by blockchain — first to commit wins
- Changing admins is a two-step process: (1) update the Merkle tree (add/remove admin members), (2) update the proxy multisig accounts to match. This follows the standard Polkadot DAO methodology.

**Failure scenarios:**
- `ProposalSuperseded` — another proposal commits first
- `InsufficientApprovals` — not enough admins online or willing to approve
- `AdminRejectsDelta` — admin verifies delta, finds it inconsistent or malicious, refuses to approve
- `CompetingProposers` — multiple admins propose concurrently; at most one succeeds

### `OESKMemberDistribution.tla`

**State:**
- `memberKeyState`: function `handle -> {"awaiting", "received", "verified"}`
- `distributionEpoch`: which epoch is being distributed
- `onlineStatus`: function `handle -> {"online", "offline"}` (orthogonal, changes non-deterministically)
- `adminRootHashHistory`: function `admin -> set of rootHash` (retained old root hashes)

**Transitions:**
1. `DetectNewRootHash(member)` — member sees on-chain update → enters "awaiting"
2. `RequestFromAdmin(member, admin)` — member contacts admin
3. `AdminVerifiesMember(admin, member)` — admin looks up member's handle in tree, performs challenge-response. For multi-epoch offline members, admin uses retained root hash history to verify against the member's last known root hash, then checks member exists in current tree.
4. `MemberVerifiesAdmin(member, admin)` — member verifies admin's ZKP against current on-chain root hash
5. `DistributeToMember(admin, member)` — admin sends OESK + relevant Merkle path → member state becomes "verified"
6. `GoOffline(member)` / `GoOnline(member)` — non-deterministic, anytime

**Key constraints:**
- Revoked members: admin checks current tree, member isn't in it → distribution refused (expected outcome, not failure)
- Multi-epoch catch-up: admin retains root hash history, can verify members who've been offline across multiple updates
- Malicious admin: can pass ZKP verification from member's perspective but send garbage OESK (threat scenario T1)

### `OEAssumptions.tla`

Axioms from Tier 1 taken as given in Tier 2:
- `MembersOf(rootHash)` — set of handles valid under a root hash
- `CurrentRootHash(oeId)` — current on-chain root hash
- `IsValidZKP(handle, rootHash) <=> handle \in MembersOf(rootHash)`
- `RootHashHistory(oeId)` — sequence of all past root hashes
- Root hash updates are totally ordered by the blockchain
- `AdminVerifies(admin, handle, rootHash)` — challenge-response succeeds iff handle is in tree for rootHash

### `SyncGate.tla`

**State:**
- `gateStatus`: function `(cuId, memberHandle) -> {"untrusted", "trusted"}`
- `lastKnownRootHash`: function `(cuId, oeId) -> rootHash` — what this CU node last read from chain
- `memberLastKnownRootHash`: function `memberHandle -> rootHash` — what each member's device last read
- `inboundQueue`: set of `{changeId, authorHandle, authorOeId, content, receivedAtRootHash}`

**Transitions:**
1. `RootHashChanges(oeId)` — new root hash detected on-chain → all members from that OE become "untrusted", syncing halts
2. `MemberProvesZKP(handle, oeId)` — member presents ZKP against `lastKnownRootHash` → becomes "trusted", syncing resumes
3. `ReceiveSync(change, authorHandle)` — if author is "trusted", change accepted and placed in unverified window (handed to TrustPromotionGate). If "untrusted", rejected.
4. `OfflineSync(change, authorHandle, peerHandle)` — two offline peers sync; both must hold the same `lastKnownRootHash` and both must be "trusted" against it. Change enters unverified window.

**Edge cases:**
- Two offline peers hold different `lastKnownRootHash` → sync rejected
- Change accepted against old root hash, new one published but not yet observed → change correctly enters unverified window for later evaluation

### `TrustPromotionGate.tla`

**State:**
- `windows`: set of `{windowId, startObservation, endObservation, startRootHash, endRootHash, changes, authors, status}`
  - `status \in {"open", "promoted", "discarded"}`
  - `startObservation` / `endObservation`: when the device read the chain (not on-chain epoch)
  - `startRootHash` / `endRootHash`: root hash read at each observation
- `authors`: set of `{handle, oeId}` who contributed changes in this window

**Transitions:**
1. `OpenWindow(observation, rootHashRead)` — new window opens when device reads chain
2. `AddChangeToWindow(windowId, change)` — synced change placed in current open window
3. `CloseWindow(observation, rootHashRead)` — device reads chain again, window closes:
   - If `rootHashRead == startRootHash` → **auto-promote**: no membership changes occurred, all changes in window promoted immediately
   - If `rootHashRead != startRootHash` → **evaluate**: check all authors with edit rights against `endRootHash`. If all pass ZKP → promote. If any fail → discard entire window.
4. `PromoteWindow(windowId)` — changes become trusted, permanent
5. `DiscardWindow(windowId)` — changes permanently deleted, never recoverable

**Key properties:**
- Windows defined by device observations, not on-chain epochs
- Windows stay small with frequent chain reads, grow large during offline periods
- `receivedInWindow` assignment is monotonic — determined by receiver, not sender. Sender cannot influence which window their changes land in.
- Once discarded, never recoverable. Once promoted, permanent.

### `CULifecycle.tla`

**State:**
- `cuMembers`: function `cuId -> set of {handle, oeId, deviceKey, role}` where `role \in {"admin", "member"}`
- `cuOEs`: function `cuId -> set of oeId` — associated OEs
- `cuSymKey`: function `cuId -> secretKey` — current CU encryption key
- `rekeyNeeded`: function `cuId -> BOOLEAN`

**Transitions:**
1. `CreateCU(creatorHandle, oeIds, initialMembers)` — creator becomes admin
2. `AddMember(adminHandle, newHandle, oeId)` — member must be in `MembersOf(CurrentRootHash(oeId))`
3. `RemoveMember(adminHandle, targetHandle)` — explicit removal, triggers re-key
4. `OERevocationCascade(handle, oeId)` — revoked from OE → removed from all CUs for that OE → triggers re-key
5. `RekeyIfNeeded(cuId)` — new CU symmetric key, distributed only to verified members
6. `AdminRemoved(cuId)` — single admin revoked → leaderless state

**Critical:** All mutations (1-5) are themselves CU operations that flow through SyncGate and TrustPromotionGate. A revoked admin's CU changes in an unverified window are discarded just like document changes.

**Cross-OE federation:** CU with `cuOEs = {oeX, oeY}` accepts members from either OE. Gates verify ZKPs against the respective OE's root hash per member.

## Properties to Verify

### Tier 1 — Safety

| ID | Property |
|----|----------|
| S1 | Only a current admin can propose a new root hash |
| S2 | Root hash commits only after proxy multisig threshold is reached (t admins verified delta and OESK and approved). Each approval constitutes genuine confirmation — admins independently verify before approving. |
| S3 | At most one root hash update succeeds per current root hash. Competing proposals fail. |
| S4 | A revoked member cannot produce a valid ZKP against any root hash published after their revocation |
| S5 | Admins retain root hash history. A member offline since observation N can be verified against root hash N, provided they remain in the current tree. |
| S5a | Changing admin set requires two steps: (1) Merkle tree update with new admin roles, (2) proxy multisig account update. New admins cannot approve root hash updates until both steps complete. |

### Tier 1 — Liveness

| ID | Property |
|----|----------|
| L1 | If proposer is honest, at least t-1 other admins are honest and online, and no competing proposal commits first, then the root hash update eventually completes |
| L2 | If at least one admin with OESK is online and a valid member comes online, that member eventually receives new OESK and Merkle path |

### Tier 1 — Threat Scenarios

| ID | Scenario |
|----|----------|
| T1 | Malicious admin (valid) sends garbage OESK to member during distribution. Member's ZKP check passes. Without cross-check mechanism, this is undetectable. |
| T2 | Two admins collude to push malicious tree. Succeeds iff they meet threshold — confirming acceptable risk. |
| T3 | Attacker compromises enough admin keys to block threshold. OE freezes — confirming emergency recovery scenario. |
| T4 | A single OE member is compromised, exposing the OESK. All OE-wide shared data is accessible to the attacker until root hash is updated and OESK rotated. Confirms source document Vulnerability 1 — inherent to distributed shared secrets. |

**Accepted risk (not modeled as violation):** Soon-to-be-revoked members can still generate valid ZKPs until the root hash is updated (source document Vulnerability 5). This is accepted under the assumption that root hash updates complete within minutes and that a member aware of impending revocation could act maliciously well before the process starts.

### Tier 2 — Safety

| ID | Property |
|----|----------|
| S6 | A revoked member's changes in an unverified window are never promoted to trusted |
| S7 | If an unverified window contains changes from a revoked member, the entire window is discarded, including valid members' changes in that same window |
| S8 | Trust promotion is anchored to root hash read at observation time, not to any claimed timestamp or causal position on changes. Backdating CRDT operations is impossible — the receiving device assigns the window, not the sender. |
| S9 | A member revoked from an OE is removed from all associated CUs. Their CU lifecycle changes (role changes, member additions) in unverified windows are also discarded. |
| S10 | If a window closes and root hash is unchanged since it opened, all changes auto-promote |
| S11 | All CU state mutations (membership, roles, re-keying) pass through sync gate and trust promotion gate, same as content changes |
| S12 | In a cross-OE CU, a root hash change in OE-X does not affect trust status of OE-Y members |
| S13 | After CU re-key triggered by member removal/revocation, the new CU symmetric key is never distributed to a removed or revoked member |
| S14 | Two offline peers with different `lastKnownRootHash` values cannot sync — sync is rejected |

### Tier 2 — Liveness

| ID | Property |
|----|----------|
| L3 | A valid member who works offline eventually has changes promoted, provided they remain a valid OE member and prove it |
| L4 | The system does not deadlock. Either an offline member comes online and verifies, or a deadline expires and the window is discarded. |
| L5 | A member offline across multiple root hash changes can catch up via admin with retained history and resume participating |

## Explicit Exclusions

The following are mentioned in the source document but intentionally excluded from this formal model:

- **Cyclic CU nesting** — structural invariant, excluded per user decision
- **OE bootstrapping** — genesis smart contract; one-time setup, not ongoing protocol
- **Relay node behavior** — infrastructure concern, not protocol logic
- **Blockchain transaction cost/throughput** — infrastructure reliability, not modelable in TLA+
- **Member self-deletion of local data upon revocation** — local cleanup behavior, not protocol-level
- **Passkeys, search, key recovery** — listed as open questions in source, out of scope for this model

## Model Checking Bounds

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| OE members | 4 | Dimensions: {admin, valid-member} x {online, offline}; any can become revoked |
| Admins | 3 | Default threshold scenario |
| Threshold | 3 (primary), 2 (secondary) | Primary demonstrates 3-admin consensus; secondary covers small OEs |
| OEs | 2 | For cross-OE federation in Tier 2 |
| CUs | 2 | Single-OE CU + cross-OE CU |
| Root hash changes | 3 | Multi-epoch offline catch-up |
| Observations per device | 4 | One more than root hash changes |
| Unverified windows | 3 | One per observation gap |

## Scenarios

### Tier 1

| # | Scenario |
|---|----------|
| 1 | Happy path: propose → distribute to admins → proxy multisig threshold reached → commit |
| 2 | Competing proposals: two admins propose simultaneously, one wins, other fails |
| 3 | Insufficient signatures: not enough admins online → update stalls |
| 4 | Revoked member requests OESK → admin rejects via challenge-response |
| 5 | Malicious admin sends garbage OESK to member → member accepts (demonstrates T1) |
| 6 | Multi-epoch offline member contacts admin, proves identity against old root hash, receives current OESK |
| 7 | Admin doesn't retain old root hash → offline member can't be verified (demonstrates consequence when S5 precondition is not met) |
| 8 | Colluding admins meet threshold → push malicious tree (demonstrates T2) |
| 9 | Malicious admin proposes tree replacing all other admins with puppets → fails because proxy multisig accounts correspond to current admins and delta is anchored to current tree. Note: even if the Merkle tree is accepted, the attacker still can't use the new admins until the proxy multisig accounts are also updated (two-step process). |

### Tier 2

| # | Scenario |
|---|----------|
| 10 | Happy path: sync → window → observation with same root hash → auto-promote |
| 11 | Revoked member's changes in window → observation detects new root hash → window discarded |
| 12 | Valid member synced offline with revoked member → tainted window discarded (S7) |
| 13 | Valid member worked offline alone → comes back, proves membership → changes promoted (L3) |
| 14 | Member offline across 3 root hash changes → catches up via admin with history → resumes (L5) |
| 15 | CU admin revoked from OE → their CU membership changes in unverified window discarded (S9) |
| 16 | Cross-OE CU: OE-X root hash changes, OE-Y members unaffected (S12) |
| 17 | CU lifecycle mutation (add member) by revoked admin → goes through gate → discarded (S11) |
| 18 | CRDT backdating attack: revoked member crafts changes with causal positions before root hash change. Irrelevant — trust promotion doesn't inspect claimed timestamps or causal ordering. Window assignment is by receiver's observation time, not sender's claim. Changes land in a window where the author can't prove membership → discarded. |
| 19 | Single-admin CU: admin gets revoked from OE → CU enters leaderless state. Content collaboration continues (gates still function) but CU membership/role changes are blocked until new admin is assigned. |
| 20 | Mismatched offline sync: two offline peers hold different `lastKnownRootHash` → sync rejected (demonstrates S14) |
| 21 | CU re-key after member removal: removed member requests new CU symmetric key → refused. New key only distributed to verified remaining members (demonstrates S13) |
| 22 | Single member compromised: attacker obtains OESK, accesses all OE-wide shared data until next root hash update and OESK rotation (demonstrates T4) |
