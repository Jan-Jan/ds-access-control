# ODS Phase 1.b Stage 1 — Solidity contract + Foundry tests + chopsticks sanity

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Spec:** [`docs/superpowers/specs/2026-05-13-ods-phase-1b-design.md`](../specs/2026-05-13-ods-phase-1b-design.md) (commit `6245ada`).

**Goal:** Deliver Stage 1 of ODS Phase 1.b: a single audited Solidity contract (`OrgRegistry`) with full Foundry unit-test coverage, plus a chopsticks-forked-Paseo-Asset-Hub sanity test proving the contract deploys and is readable via pallet-revive. This is the gate that must pass before Stage 2 (the `on-chain-client` Rust crate) starts.

**Architecture:** A standalone Foundry project at `on-chain/` containing one Solidity contract, an exhaustive unit-test suite covering each invariant from the spec's §5.1, and a small chopsticks-sanity script. The contract is multi-tenant via `mapping(address => OrgState)` keyed on the proxied multisig's mapped H160, with a unified `update(rootHash, orgPubKey, expectedEpoch)` entry point that handles both genesis and updates with strict +1 epoch progression, zero-value and no-op rejection, and two distinct events.

**Tech Stack:** Solidity 0.8.27 (pinned, matches modern Foundry defaults), `forge-std` (Foundry standard library, installed as a git submodule under `lib/`), Foundry (`forge`, `cast`) for EVM-side compilation and tests, `chopsticks` (acala-network/chopsticks) for the Paseo Asset Hub fork, and `resolc` (the revive Solidity compiler) + a pallet-revive deployment helper for the chopsticks sanity test.

**Out of scope for this plan:**
- The `on-chain-client` Rust crate, smoldot transport, `Rpc` trait, decoders, `subscribe`/`get_org_state`, all integration test scenarios A/B/C, smoldot smoke test, OrgId-invariant test (`p_address_is_orgid.rs`). All covered by Stage 2's separate plan.
- Any changes to `org-members`.
- Submission-side helpers, admin-rotation tooling, off-chain delta gossip.

**Follow-up plan:** ODS Phase 1.b Stage 2 — `on-chain-client` Rust crate. Written after this plan lands and Stage 1's gate criteria are satisfied, so it can incorporate any learnings about pallet-revive's deployment mechanics under chopsticks.

---

## File structure produced by this plan

```
2-tier-access-control/
├── org-members/                            [existing — unchanged]
├── docs/                                   [existing — unchanged]
└── on-chain/                               [NEW]
    ├── foundry.toml                        compiler + test config
    ├── remappings.txt                      forge-std → lib/forge-std/src/
    ├── .gitignore                          cache/, out/, broadcast/, node_modules/
    ├── .gitmodules                         forge-std submodule
    ├── README.md                           build/test/deploy quickstart
    ├── lib/forge-std/                      git submodule
    ├── src/
    │   └── OrgRegistry.sol                 the contract
    ├── test/
    │   └── OrgRegistry.t.sol               Foundry unit tests
    ├── abi/
    │   └── OrgRegistry.json                pinned ABI artifact (gate output)
    └── scripts/
        ├── chopsticks-sanity.sh            entrypoint: fork + deploy + verify
        └── chopsticks-config.yml           chopsticks config pinning Paseo AH
```

After the plan completes the repo also has these git-level outputs:
- A new git submodule entry for `on-chain/lib/forge-std`.
- A tag `v0.1.0-on-chain-stage1` on the gate-passing commit.

---

## Working-directory and toolchain prerequisites

**Worktree:** the executor must already have created an isolated git worktree per the `superpowers:using-git-worktrees` skill. All commands below assume the worktree root is the current directory.

**Tools the executor must have available** (verify before Task 1):

```bash
foundryup --version  # or: forge --version    ;  must print a version
cast --version
git --version
node --version       # for the chopsticks sanity helper (>= 20.x)
npx --version
```

If `forge` is missing, install Foundry: `curl -L https://foundry.paradigm.xyz | bash && foundryup`.

`resolc` and the pallet-revive deployment helper are installed *inside* Task 13 (chopsticks sanity) — they aren't needed for the earlier tasks. This keeps the toolchain footprint small for the contract-development tasks.

---

## Task 1: Initialise the Foundry project

**Files:**
- Create: `on-chain/foundry.toml`
- Create: `on-chain/remappings.txt`
- Create: `on-chain/.gitignore`
- Create: `on-chain/lib/forge-std/` (via submodule)
- Create: `on-chain/.gitmodules`

- [ ] **Step 1: Create the `on-chain/` directory.**

```bash
mkdir -p on-chain/{src,test,abi,scripts}
```

- [ ] **Step 2: Write `on-chain/foundry.toml`.**

```toml
[profile.default]
src             = "src"
test            = "test"
out             = "out"
libs            = ["lib"]
solc_version    = "0.8.27"
optimizer       = true
optimizer_runs  = 200
evm_version     = "cancun"
remappings      = ["forge-std/=lib/forge-std/src/"]
verbosity       = 2
fuzz            = { runs = 256 }

[fmt]
line_length     = 100
tab_width       = 4
bracket_spacing = false
```

- [ ] **Step 3: Write `on-chain/remappings.txt`.**

```
forge-std/=lib/forge-std/src/
```

- [ ] **Step 4: Write `on-chain/.gitignore`.**

```
cache/
out/
broadcast/
node_modules/
.env
.env.local
*.log
```

- [ ] **Step 5: Install `forge-std` as a submodule.**

```bash
cd on-chain
forge install foundry-rs/forge-std --no-commit
cd ..
```

Expected: a `lib/forge-std/` directory appears, and `.gitmodules` is created at `on-chain/.gitmodules`.

- [ ] **Step 6: Verify Foundry builds an empty project.**

```bash
cd on-chain && forge build && cd ..
```

Expected output ends with `Compiler run successful!` (zero source files compiled is fine).

- [ ] **Step 7: Commit.**

```bash
git add on-chain/foundry.toml on-chain/remappings.txt on-chain/.gitignore on-chain/.gitmodules on-chain/lib/forge-std
git commit -m "chore: initialise Foundry project for on-chain/"
```

---

## Task 2: Genesis happy path (TDD — drives initial contract structure)

**Files:**
- Create: `on-chain/test/OrgRegistry.t.sol`
- Create: `on-chain/src/OrgRegistry.sol`

This task is intentionally larger than the rest: it's the first TDD cycle and drives the contract skeleton (storage, struct, events, errors, function signature). Subsequent tasks add one assertion at a time.

- [ ] **Step 1: Write the failing genesis test.**

Create `on-chain/test/OrgRegistry.t.sol` with:

```solidity
// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.27;

import {Test} from "forge-std/Test.sol";
import {OrgRegistry} from "../src/OrgRegistry.sol";

contract OrgRegistryTest is Test {
    OrgRegistry internal reg;

    address internal admin   = address(0xA11CE);
    bytes32 internal root0   = bytes32(uint256(0x1111));
    bytes32 internal pk0     = bytes32(uint256(0x2222));

    event GenesisInitialized(address indexed admin, bytes32 rootHash, bytes32 orgPubKey);

    function setUp() public {
        reg = new OrgRegistry();
    }

    function test_GenesisHappyPath_StoresStateAndEmits() public {
        vm.expectEmit(true, false, false, true, address(reg));
        emit GenesisInitialized(admin, root0, pk0);

        vm.prank(admin);
        reg.update(root0, pk0, 0);

        (bytes32 r, bytes32 k, uint256 e) = reg.orgsView(admin);
        assertEq(r, root0,    "rootHash mismatch");
        assertEq(k, pk0,      "orgPubKey mismatch");
        assertEq(e, 1,        "epoch after genesis must be 1");
    }
}
```

- [ ] **Step 2: Run test to verify it fails.**

```bash
cd on-chain && forge test --match-test test_GenesisHappyPath_StoresStateAndEmits -vv && cd ..
```

Expected: compilation error — `Source not found "../src/OrgRegistry.sol"`.

- [ ] **Step 3: Create the minimum `OrgRegistry.sol` that makes this test pass.**

Create `on-chain/src/OrgRegistry.sol`:

```solidity
// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.27;

/// @title OrgRegistry — on-chain anchor for the off-chain organisation members trie.
/// @notice Multi-tenant: one contract instance serves every organisation. Each org
///         is keyed on the H160 of its proxied (pure-proxy) admin account.
contract OrgRegistry {
    struct OrgState {
        bytes32 rootHash;
        bytes32 orgPubKey;
        uint256 epoch;
    }

    mapping(address => OrgState) private orgs;

    event GenesisInitialized(address indexed admin, bytes32 rootHash, bytes32 orgPubKey);

    function update(bytes32 newRootHash, bytes32 newOrgPubKey, uint256 expectedEpoch) external {
        OrgState storage s = orgs[msg.sender];
        require(expectedEpoch == s.epoch);
        s.rootHash  = newRootHash;
        s.orgPubKey = newOrgPubKey;
        s.epoch     = 1;
        emit GenesisInitialized(msg.sender, newRootHash, newOrgPubKey);
    }

    /// @notice Test-only convenience view. Public read access to the orgs mapping.
    /// @dev    Kept on the contract for test introspection; the spec's "no view
    ///         functions" rule applies to *cross-contract* reads from other
    ///         on-chain code. This is a flat view returning the struct as a tuple.
    function orgsView(address admin) external view returns (bytes32, bytes32, uint256) {
        OrgState storage s = orgs[admin];
        return (s.rootHash, s.orgPubKey, s.epoch);
    }
}
```

- [ ] **Step 4: Run test to verify it passes.**

```bash
cd on-chain && forge test --match-test test_GenesisHappyPath_StoresStateAndEmits -vv && cd ..
```

Expected: `[PASS] test_GenesisHappyPath_StoresStateAndEmits ... 1 passed`.

- [ ] **Step 5: Commit.**

```bash
git add on-chain/src/OrgRegistry.sol on-chain/test/OrgRegistry.t.sol
git commit -m "feat(on-chain): OrgRegistry skeleton + genesis happy-path test"
```

---

## Task 3: Update happy path after genesis (drives epoch increment + RootUpdated event)

**Files:**
- Modify: `on-chain/test/OrgRegistry.t.sol`
- Modify: `on-chain/src/OrgRegistry.sol`

- [ ] **Step 1: Add the failing test.**

Append to `OrgRegistryTest`:

```solidity
    bytes32 internal root1 = bytes32(uint256(0x3333));
    bytes32 internal pk1   = bytes32(uint256(0x4444));

    event RootUpdated(
        address indexed admin,
        uint256 indexed epoch,
        bytes32 rootHash,
        bytes32 orgPubKey,
        bytes32 prevRootHash
    );

    function test_UpdateAfterGenesis_IncrementsEpochAndEmits() public {
        vm.prank(admin);
        reg.update(root0, pk0, 0);  // genesis: epoch becomes 1

        vm.expectEmit(true, true, false, true, address(reg));
        emit RootUpdated(admin, 2, root1, pk1, root0);

        vm.prank(admin);
        reg.update(root1, pk1, 1);  // update: expectedEpoch = 1 (the epoch we replace)

        (bytes32 r, bytes32 k, uint256 e) = reg.orgsView(admin);
        assertEq(r, root1, "rootHash should be updated");
        assertEq(k, pk1,   "orgPubKey should be updated");
        assertEq(e, 2,     "epoch after first update must be 2");
    }
```

- [ ] **Step 2: Run test to verify it fails.**

```bash
cd on-chain && forge test --match-test test_UpdateAfterGenesis -vv && cd ..
```

Expected: FAIL — current contract always sets `epoch = 1` and always emits `GenesisInitialized`.

- [ ] **Step 3: Extend `OrgRegistry.sol` to handle both genesis and update.**

Replace the `update` function:

```solidity
    event RootUpdated(
        address indexed admin,
        uint256 indexed epoch,
        bytes32 rootHash,
        bytes32 orgPubKey,
        bytes32 prevRootHash
    );

    function update(bytes32 newRootHash, bytes32 newOrgPubKey, uint256 expectedEpoch) external {
        OrgState storage s = orgs[msg.sender];
        require(expectedEpoch == s.epoch);

        if (s.epoch == 0) {
            s.rootHash  = newRootHash;
            s.orgPubKey = newOrgPubKey;
            s.epoch     = 1;
            emit GenesisInitialized(msg.sender, newRootHash, newOrgPubKey);
        } else {
            bytes32 prev = s.rootHash;
            s.rootHash   = newRootHash;
            s.orgPubKey  = newOrgPubKey;
            s.epoch      = s.epoch + 1;
            emit RootUpdated(msg.sender, s.epoch, newRootHash, newOrgPubKey, prev);
        }
    }
```

- [ ] **Step 4: Run all tests to verify both pass.**

```bash
cd on-chain && forge test -vv && cd ..
```

Expected: 2 passed, 0 failed.

- [ ] **Step 5: Commit.**

```bash
git add on-chain/src/OrgRegistry.sol on-chain/test/OrgRegistry.t.sol
git commit -m "feat(on-chain): handle genesis vs update branches with strict +1 epoch"
```

---

## Task 4: ZeroValue revert for `rootHash == 0` (drives ZeroValue custom error)

**Files:**
- Modify: `on-chain/test/OrgRegistry.t.sol`
- Modify: `on-chain/src/OrgRegistry.sol`

- [ ] **Step 1: Add the failing test.**

Append to `OrgRegistryTest`:

```solidity
    function test_RevertsZeroValue_WhenRootHashIsZero() public {
        vm.expectRevert(OrgRegistry.ZeroValue.selector);
        vm.prank(admin);
        reg.update(bytes32(0), pk0, 0);
    }
```

- [ ] **Step 2: Run test to verify it fails.**

```bash
cd on-chain && forge test --match-test test_RevertsZeroValue_WhenRootHashIsZero -vv && cd ..
```

Expected: FAIL — either compile error (`ZeroValue` not defined) or behavioural failure (no revert).

- [ ] **Step 3: Add the `ZeroValue` error and the check.**

In `OrgRegistry.sol`, before the events, add:

```solidity
    error ZeroValue();
```

And at the top of `update(...)`, before reading storage:

```solidity
        if (newRootHash == bytes32(0) || newOrgPubKey == bytes32(0)) revert ZeroValue();
```

- [ ] **Step 4: Run all tests to verify they pass.**

```bash
cd on-chain && forge test -vv && cd ..
```

Expected: 3 passed, 0 failed.

- [ ] **Step 5: Commit.**

```bash
git add on-chain/src/OrgRegistry.sol on-chain/test/OrgRegistry.t.sol
git commit -m "feat(on-chain): reject zero rootHash with ZeroValue custom error"
```

---

## Task 5: ZeroValue revert for `orgPubKey == 0` (regression test on existing check)

**Files:**
- Modify: `on-chain/test/OrgRegistry.t.sol`

The check from Task 4 already covers this branch; this task adds the explicit test so the two-input rule is regression-locked.

- [ ] **Step 1: Add the test.**

Append:

```solidity
    function test_RevertsZeroValue_WhenOrgPubKeyIsZero() public {
        vm.expectRevert(OrgRegistry.ZeroValue.selector);
        vm.prank(admin);
        reg.update(root0, bytes32(0), 0);
    }
```

- [ ] **Step 2: Run the test.**

```bash
cd on-chain && forge test --match-test test_RevertsZeroValue_WhenOrgPubKeyIsZero -vv && cd ..
```

Expected: PASS (the existing `||` check covers it).

- [ ] **Step 3: Run the full suite to ensure no regressions.**

```bash
cd on-chain && forge test -vv && cd ..
```

Expected: 4 passed, 0 failed.

- [ ] **Step 4: Commit.**

```bash
git add on-chain/test/OrgRegistry.t.sol
git commit -m "test(on-chain): regression-lock ZeroValue check for orgPubKey"
```

---

## Task 6: EpochMismatch revert with typed parameters (drives EpochMismatch custom error)

**Files:**
- Modify: `on-chain/test/OrgRegistry.t.sol`
- Modify: `on-chain/src/OrgRegistry.sol`

- [ ] **Step 1: Add the failing test for a stale `expectedEpoch`.**

Append:

```solidity
    function test_RevertsEpochMismatch_WhenExpectedEpochIsStale() public {
        vm.prank(admin);
        reg.update(root0, pk0, 0);  // epoch becomes 1

        vm.expectRevert(abi.encodeWithSelector(OrgRegistry.EpochMismatch.selector, uint256(0), uint256(1)));
        vm.prank(admin);
        reg.update(root1, pk1, 0);  // passes stale expected=0 when actual=1
    }
```

- [ ] **Step 2: Run test to verify it fails.**

```bash
cd on-chain && forge test --match-test test_RevertsEpochMismatch_WhenExpectedEpochIsStale -vv && cd ..
```

Expected: FAIL — current contract uses `require(expectedEpoch == s.epoch)` without the typed error.

- [ ] **Step 3: Define the typed error and replace the `require`.**

In `OrgRegistry.sol`, alongside `ZeroValue`:

```solidity
    error EpochMismatch(uint256 expected, uint256 actual);
```

Replace the existing `require(expectedEpoch == s.epoch);` line in `update(...)` with:

```solidity
        if (expectedEpoch != s.epoch) revert EpochMismatch(expectedEpoch, s.epoch);
```

- [ ] **Step 4: Run all tests to verify they pass.**

```bash
cd on-chain && forge test -vv && cd ..
```

Expected: 5 passed, 0 failed.

- [ ] **Step 5: Commit.**

```bash
git add on-chain/src/OrgRegistry.sol on-chain/test/OrgRegistry.t.sol
git commit -m "feat(on-chain): replace require with typed EpochMismatch error"
```

---

## Task 7: EpochMismatch also reverts for a future `expectedEpoch`

**Files:**
- Modify: `on-chain/test/OrgRegistry.t.sol`

The Task 6 implementation already covers this; this task locks it in as a regression test.

- [ ] **Step 1: Add the test.**

Append:

```solidity
    function test_RevertsEpochMismatch_WhenExpectedEpochIsInTheFuture() public {
        // Fresh admin slot: s.epoch == 0. Passing expectedEpoch=42 should revert.
        vm.expectRevert(abi.encodeWithSelector(OrgRegistry.EpochMismatch.selector, uint256(42), uint256(0)));
        vm.prank(admin);
        reg.update(root0, pk0, 42);
    }
```

- [ ] **Step 2: Run the test.**

```bash
cd on-chain && forge test --match-test test_RevertsEpochMismatch_WhenExpectedEpochIsInTheFuture -vv && cd ..
```

Expected: PASS.

- [ ] **Step 3: Run the full suite.**

```bash
cd on-chain && forge test -vv && cd ..
```

Expected: 6 passed, 0 failed.

- [ ] **Step 4: Commit.**

```bash
git add on-chain/test/OrgRegistry.t.sol
git commit -m "test(on-chain): regression-lock EpochMismatch for future expected epoch"
```

---

## Task 8: NoOpUpdate revert when both inputs unchanged (drives NoOpUpdate custom error)

**Files:**
- Modify: `on-chain/test/OrgRegistry.t.sol`
- Modify: `on-chain/src/OrgRegistry.sol`

- [ ] **Step 1: Add the failing test.**

Append:

```solidity
    function test_RevertsNoOpUpdate_AfterGenesis_WhenInputsUnchanged() public {
        vm.prank(admin);
        reg.update(root0, pk0, 0);  // epoch becomes 1

        vm.expectRevert(OrgRegistry.NoOpUpdate.selector);
        vm.prank(admin);
        reg.update(root0, pk0, 1);  // identical inputs
    }

    function test_AllowsUpdate_WhenOnlyOrgPubKeyChanged() public {
        vm.prank(admin);
        reg.update(root0, pk0, 0);

        vm.prank(admin);
        reg.update(root0, pk1, 1);  // root unchanged, pk changed → allowed

        (bytes32 r, bytes32 k, uint256 e) = reg.orgsView(admin);
        assertEq(r, root0);
        assertEq(k, pk1);
        assertEq(e, 2);
    }

    function test_AllowsUpdate_WhenOnlyRootHashChanged() public {
        vm.prank(admin);
        reg.update(root0, pk0, 0);

        vm.prank(admin);
        reg.update(root1, pk0, 1);  // pk unchanged, root changed → allowed

        (bytes32 r, bytes32 k, uint256 e) = reg.orgsView(admin);
        assertEq(r, root1);
        assertEq(k, pk0);
        assertEq(e, 2);
    }
```

- [ ] **Step 2: Run the new tests to verify the no-op test fails (the other two should pass already).**

```bash
cd on-chain && forge test --match-test test_RevertsNoOpUpdate_AfterGenesis_WhenInputsUnchanged -vv && cd ..
cd on-chain && forge test --match-test test_AllowsUpdate -vv && cd ..
```

Expected: the `NoOp` test FAILs; both `AllowsUpdate` tests PASS.

- [ ] **Step 3: Add the `NoOpUpdate` error and the check.**

In `OrgRegistry.sol`, alongside the other errors:

```solidity
    error NoOpUpdate();
```

In `update(...)`, after the epoch check but inside the *update* branch only (genesis must bypass this — for fresh slots there is nothing to compare against, and genesis already passes the `expectedEpoch == 0` gate). The cleanest placement is after the `if (s.epoch == 0)` branch:

```solidity
        if (s.epoch == 0) {
            s.rootHash  = newRootHash;
            s.orgPubKey = newOrgPubKey;
            s.epoch     = 1;
            emit GenesisInitialized(msg.sender, newRootHash, newOrgPubKey);
        } else {
            if (newRootHash == s.rootHash && newOrgPubKey == s.orgPubKey) revert NoOpUpdate();
            bytes32 prev = s.rootHash;
            s.rootHash   = newRootHash;
            s.orgPubKey  = newOrgPubKey;
            s.epoch      = s.epoch + 1;
            emit RootUpdated(msg.sender, s.epoch, newRootHash, newOrgPubKey, prev);
        }
```

- [ ] **Step 4: Run all tests to verify they pass.**

```bash
cd on-chain && forge test -vv && cd ..
```

Expected: 9 passed, 0 failed.

- [ ] **Step 5: Commit.**

```bash
git add on-chain/src/OrgRegistry.sol on-chain/test/OrgRegistry.t.sol
git commit -m "feat(on-chain): reject no-op updates and lock single-field-change semantics"
```

---

## Task 9: Per-admin storage isolation

**Files:**
- Modify: `on-chain/test/OrgRegistry.t.sol`

Verifies the contract's central multi-tenant property: two distinct admins writing to the same contract don't perturb each other's state.

- [ ] **Step 1: Add the test.**

Append:

```solidity
    function test_TwoAdmins_StorageIsIsolated() public {
        address adminB    = address(0xB0B);
        bytes32 rootB     = bytes32(uint256(0x5555));
        bytes32 pkB       = bytes32(uint256(0x6666));

        // Admin A genesis + 1 update.
        vm.prank(admin);
        reg.update(root0, pk0, 0);
        vm.prank(admin);
        reg.update(root1, pk1, 1);

        // Admin B genesis only.
        vm.prank(adminB);
        reg.update(rootB, pkB, 0);

        (bytes32 rA, bytes32 kA, uint256 eA) = reg.orgsView(admin);
        assertEq(rA, root1, "A.root unaffected by B");
        assertEq(kA, pk1,   "A.pk   unaffected by B");
        assertEq(eA, 2,     "A.epoch unaffected by B");

        (bytes32 rB, bytes32 kB, uint256 eB) = reg.orgsView(adminB);
        assertEq(rB, rootB, "B.root unaffected by A");
        assertEq(kB, pkB,   "B.pk   unaffected by A");
        assertEq(eB, 1,     "B.epoch unaffected by A");
    }
```

- [ ] **Step 2: Run the test.**

```bash
cd on-chain && forge test --match-test test_TwoAdmins_StorageIsIsolated -vv && cd ..
```

Expected: PASS.

- [ ] **Step 3: Run the full suite.**

```bash
cd on-chain && forge test -vv && cd ..
```

Expected: 10 passed, 0 failed.

- [ ] **Step 4: Commit.**

```bash
git add on-chain/test/OrgRegistry.t.sol
git commit -m "test(on-chain): regression-lock per-admin storage isolation"
```

---

## Task 10: Indexed event topics decoding

**Files:**
- Modify: `on-chain/test/OrgRegistry.t.sol`

Verifies that `admin` (and `epoch` for `RootUpdated`) are properly indexed so off-chain clients can filter on the topic without parsing the full log.

- [ ] **Step 1: Add the tests.**

Append:

```solidity
    function test_GenesisEvent_AdminTopicIsIndexed() public {
        vm.recordLogs();
        vm.prank(admin);
        reg.update(root0, pk0, 0);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1, "exactly one event");
        // topic0 = event sig; topic1 = indexed admin
        assertEq(logs[0].topics.length, 2, "GenesisInitialized: 1 indexed param + sig");
        assertEq(address(uint160(uint256(logs[0].topics[1]))), admin, "topic1 is admin");
    }

    function test_RootUpdatedEvent_AdminAndEpochTopicsAreIndexed() public {
        vm.prank(admin);
        reg.update(root0, pk0, 0);

        vm.recordLogs();
        vm.prank(admin);
        reg.update(root1, pk1, 1);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1, "exactly one event");
        // topic0 = sig; topic1 = indexed admin; topic2 = indexed epoch
        assertEq(logs[0].topics.length, 3, "RootUpdated: 2 indexed params + sig");
        assertEq(address(uint160(uint256(logs[0].topics[1]))), admin, "topic1 is admin");
        assertEq(uint256(logs[0].topics[2]), 2, "topic2 is epoch=2");
    }
```

You will also need to import the `Vm` type (it lives in `forge-std/Test.sol`'s exported namespace via `Vm.Log`). Foundry's `Test` re-exports it; check the top of the file. If the symbol isn't accessible, add at the top of the file:

```solidity
import {Vm} from "forge-std/Vm.sol";
```

- [ ] **Step 2: Run the tests.**

```bash
cd on-chain && forge test --match-test test_GenesisEvent_AdminTopicIsIndexed -vv && cd ..
cd on-chain && forge test --match-test test_RootUpdatedEvent_AdminAndEpochTopicsAreIndexed -vv && cd ..
```

Expected: both PASS.

- [ ] **Step 3: Run the full suite.**

```bash
cd on-chain && forge test -vv && cd ..
```

Expected: 12 passed, 0 failed.

- [ ] **Step 4: Commit.**

```bash
git add on-chain/test/OrgRegistry.t.sol
git commit -m "test(on-chain): assert indexed topics on Genesis and RootUpdated"
```

---

## Task 11: Permissionless org creation

**Files:**
- Modify: `on-chain/test/OrgRegistry.t.sol`

Locks in the spec's intentional property that any caller can create their own org slot. The test demonstrates two unrelated addresses each creating a slot, then asserts neither has visibility into the other's state (already covered by Task 9, but the explicit "permissionless" framing is the point here).

- [ ] **Step 1: Add the test.**

Append:

```solidity
    function test_PermissionlessOrgCreation_ArbitraryAddressesCanGenesis() public {
        address[] memory admins = new address[](3);
        admins[0] = address(0xCAFE);
        admins[1] = address(0xBEEF);
        admins[2] = address(0xF00D);

        for (uint256 i = 0; i < admins.length; i++) {
            bytes32 r = bytes32(uint256(0xA000 + i));
            bytes32 k = bytes32(uint256(0xB000 + i));

            vm.prank(admins[i]);
            reg.update(r, k, 0);

            (bytes32 gotR, bytes32 gotK, uint256 gotE) = reg.orgsView(admins[i]);
            assertEq(gotR, r, "rootHash mismatch for admin i");
            assertEq(gotK, k, "orgPubKey mismatch for admin i");
            assertEq(gotE, 1, "epoch=1 after genesis for admin i");
        }
    }
```

- [ ] **Step 2: Run the test.**

```bash
cd on-chain && forge test --match-test test_PermissionlessOrgCreation -vv && cd ..
```

Expected: PASS.

- [ ] **Step 3: Run the full suite.**

```bash
cd on-chain && forge test -vv && cd ..
```

Expected: 13 passed, 0 failed.

- [ ] **Step 4: Commit.**

```bash
git add on-chain/test/OrgRegistry.t.sol
git commit -m "test(on-chain): document permissionless org creation as intentional"
```

---

## Task 12: Pin the ABI artifact

**Files:**
- Create: `on-chain/abi/OrgRegistry.json`

The Stage 1 gate criterion requires the contract's ABI to be exported and pinned at a stable path so Stage 2's Rust crate can decode against a frozen interface.

- [ ] **Step 1: Rebuild artifacts cleanly.**

```bash
cd on-chain && forge clean && forge build && cd ..
```

Expected: `Compiler run successful!` and `on-chain/out/OrgRegistry.sol/OrgRegistry.json` exists.

- [ ] **Step 2: Extract just the ABI section into the pinned artifact.**

```bash
mkdir -p on-chain/abi
jq '{abi: .abi, contractName: "OrgRegistry"}' \
   on-chain/out/OrgRegistry.sol/OrgRegistry.json \
   > on-chain/abi/OrgRegistry.json
```

Expected: `on-chain/abi/OrgRegistry.json` exists and contains a top-level `abi` array plus `"contractName": "OrgRegistry"`.

- [ ] **Step 3: Sanity-check the ABI shape.**

```bash
jq '.abi[] | select(.type=="function") | .name' on-chain/abi/OrgRegistry.json
jq '.abi[] | select(.type=="event")    | .name' on-chain/abi/OrgRegistry.json
jq '.abi[] | select(.type=="error")    | .name' on-chain/abi/OrgRegistry.json
```

Expected output (order may vary):
```
"orgsView"
"update"
"GenesisInitialized"
"RootUpdated"
"EpochMismatch"
"NoOpUpdate"
"ZeroValue"
```

- [ ] **Step 4: Commit.**

```bash
git add on-chain/abi/OrgRegistry.json
git commit -m "build(on-chain): pin OrgRegistry ABI artifact at on-chain/abi/"
```

---

## Task 13: Chopsticks-Paseo deployment sanity script

**Files:**
- Create: `on-chain/scripts/chopsticks-config.yml`
- Create: `on-chain/scripts/package.json`
- Create: `on-chain/scripts/sanity-deploy.mjs`
- Create: `on-chain/scripts/chopsticks-sanity.sh`

Proves that `OrgRegistry`, compiled by the *real* pallet-revive toolchain (`resolc`), deploys to a chopsticks-forked Paseo Asset Hub and is readable from chain storage. The script computes the blake2-256 code hash locally and asserts it matches `Revive::PristineCode(code_hash)` on chain after the instantiate extrinsic completes.

- [ ] **Step 1: Install `resolc`.**

```bash
cargo install --git https://github.com/paritytech/revive --locked resolc
resolc --version
```

Expected: `resolc <some version>`. If the install fails because the repo path or crate name has moved, check the current location of revive's Solidity compiler in the [paritytech/revive](https://github.com/paritytech/revive) repository and adjust. The plan must be updated to reflect the working install command before continuing.

- [ ] **Step 2: Pin the Paseo Asset Hub endpoint in the chopsticks config.**

Look up the canonical Paseo Asset Hub WSS endpoint via the [polkadot-js/apps](https://github.com/polkadot-js/apps) repo (`packages/apps-config/src/endpoints/testingRelayPaseo.ts`) or the official Polkadot docs. Then create `on-chain/scripts/chopsticks-config.yml`:

```yaml
# Paseo Asset Hub fork config for the OrgRegistry deployment sanity check.
# Endpoint pinned at Stage-1 implementation time; update if Paseo moves.
endpoint: <paste-canonical-paseo-asset-hub-wss-here>
mock-signature-host: true
db: ./tmp/chopsticks-paseo-ah.db.sqlite
runtime-log-level: 1
# Pre-fund Alice so the sanity script can pay fees without a faucet trip.
import-storage:
  System:
    Account:
      - - - 5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY
        - providers: 1
          data:
            free: '1000000000000000000'
```

Do NOT invent an endpoint URL — paste the one you looked up. If Paseo Asset Hub does not exist or does not expose a public WSS endpoint at implementation time, **stop and consult the user**: this is a gate-criterion blocker, not a code problem to work around.

- [ ] **Step 3: Create `on-chain/scripts/package.json`.**

```json
{
  "name": "on-chain-sanity",
  "private": true,
  "type": "module",
  "dependencies": {
    "@polkadot/api": "^11",
    "@polkadot/util": "^12",
    "@polkadot/util-crypto": "^12"
  }
}
```

Install:

```bash
cd on-chain/scripts && npm install && cd ../..
```

Expected: `node_modules/` appears under `on-chain/scripts/`.

- [ ] **Step 4: Create the deployment script `on-chain/scripts/sanity-deploy.mjs`.**

```javascript
// Deploys OrgRegistry.polkavm to a running chopsticks Paseo AH fork via
// pallet-revive's `instantiateWithCode`, then reads `Revive.PristineCode`
// for the deployed code hash and asserts it matches the locally-computed
// blake2-256 of the blob. Exits 0 on success, non-zero on any mismatch.

import {ApiPromise, Keyring, WsProvider} from '@polkadot/api';
import {blake2AsHex} from '@polkadot/util-crypto';
import {readFileSync} from 'node:fs';
import {hexToU8a} from '@polkadot/util';

const RPC_URL  = process.env.RPC_URL  || 'ws://localhost:8000';
const BLOB_PATH = process.env.BLOB_PATH || 'tmp/revive/OrgRegistry.polkavm';

const blob       = readFileSync(BLOB_PATH);
const localHash  = blake2AsHex(blob, 256);
console.log(`local code blake2-256: ${localHash}`);

const api    = await ApiPromise.create({provider: new WsProvider(RPC_URL)});
const alice  = new Keyring({type: 'sr25519'}).addFromUri('//Alice');

// pallet-revive expects: code, value, gasLimit, storageDepositLimit, data, salt.
// gasLimit and storageDepositLimit are intentionally loose for the sanity
// run — Paseo's weights govern the real values. If these need tuning at
// execution time, update both this script and the plan.
const instantiate = api.tx.revive.instantiateWithCode(
  '0x' + blob.toString('hex'),
  0,                                 // endowment
  {refTime: 5_000_000_000_000n, proofSize: 1_000_000n},   // gas
  null,                              // storageDepositLimit: unlimited
  '0x',                              // data: empty constructor
  '0x' + '00'.repeat(32),            // salt
);

console.log('submitting instantiateWithCode as Alice...');
const result = await new Promise((resolve, reject) => {
  instantiate.signAndSend(alice, ({status, dispatchError, events}) => {
    if (dispatchError) {
      reject(new Error(`dispatchError: ${dispatchError.toString()}`));
      return;
    }
    if (status.isInBlock || status.isFinalized) {
      resolve({status, events});
    }
  }).catch(reject);
});
console.log(`included in block: ${result.status.toString()}`);

// Read PristineCode(hash) — pallet-revive stores the deployed code keyed
// by its blake2-256 hash. If our local hash matches, we have proof the
// same bytes are stored on chain.
const pristine = await api.query.revive.pristineCode(localHash);
if (pristine.isEmpty || pristine.toHex() === '0x') {
  console.error(`FAIL: no PristineCode entry at ${localHash}`);
  process.exit(1);
}
const onChainBytes = hexToU8a(pristine.toHex());
const onChainHash  = blake2AsHex(onChainBytes, 256);
if (onChainHash !== localHash) {
  console.error(`FAIL: on-chain code hash ${onChainHash} != local ${localHash}`);
  process.exit(1);
}

console.log(`OK: on-chain code hash matches local (${localHash})`);
await api.disconnect();
process.exit(0);
```

The `revive.instantiateWithCode` extrinsic's exact field shape can shift between pallet-revive versions. If the JS bindings reject the call shape above (`TypeError: argument count mismatch` or similar), inspect the metadata via `api.tx.revive.instantiateWithCode.meta.toHuman()` and align the arguments to what the chain expects, then update both this script and this task. Don't paper over a shape change — record it.

- [ ] **Step 5: Create the orchestrator `on-chain/scripts/chopsticks-sanity.sh`.**

```bash
#!/usr/bin/env bash
# Stage 1 gate: chopsticks-Paseo sanity check for OrgRegistry.
# Spins up chopsticks, compiles OrgRegistry with resolc, runs the JS
# deployment + verify script. Exits 0 on success.

set -euo pipefail

cd "$(dirname "$0")/.."  # cwd = on-chain/

CONFIG="scripts/chopsticks-config.yml"
SRC="src/OrgRegistry.sol"
ARTIFACT_DIR="tmp/revive"
BLOB="$ARTIFACT_DIR/OrgRegistry.polkavm"
PORT=8000

mkdir -p "$ARTIFACT_DIR" tmp

echo "[1/4] Compiling $SRC with resolc..."
resolc --bin "$SRC" -o "$ARTIFACT_DIR/"
test -s "$BLOB" || { echo "resolc produced no output at $BLOB" >&2; exit 1; }

echo "[2/4] Starting chopsticks (Paseo AH fork) on ws://localhost:$PORT..."
npx --yes @acala-network/chopsticks@latest --config "$CONFIG" --port "$PORT" &
CHOPSTICKS_PID=$!
trap "kill $CHOPSTICKS_PID 2>/dev/null || true" EXIT

echo "[3/4] Waiting for chopsticks RPC to accept connections..."
for i in $(seq 1 60); do
  if curl -s -o /dev/null -w '%{http_code}' \
       -H 'content-type: application/json' \
       -d '{"jsonrpc":"2.0","id":1,"method":"system_health","params":[]}' \
       "http://localhost:$PORT" 2>/dev/null | grep -q '^200$'; then
    break
  fi
  sleep 1
done
curl -s -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"system_health","params":[]}' \
     "http://localhost:$PORT" > /dev/null \
  || { echo "chopsticks did not come up within 60s" >&2; exit 1; }

echo "[4/4] Running deploy-and-verify script..."
RPC_URL="ws://localhost:$PORT" BLOB_PATH="$BLOB" \
  node scripts/sanity-deploy.mjs

echo "OK — Stage 1 chopsticks sanity passed."
```

The exact `resolc` output extension may be `.polkavm`, `.contract`, or similar depending on resolc's release; the script assumes `OrgRegistry.polkavm` and the `BLOB_PATH` env var lets you override if needed. If resolc's output filename is different, update both `BLOB` in this script and the path passed via env to the JS step.

Make it executable:

```bash
chmod +x on-chain/scripts/chopsticks-sanity.sh
```

- [ ] **Step 6: Run the sanity script.**

```bash
on-chain/scripts/chopsticks-sanity.sh
```

Expected: ends with `OK — Stage 1 chopsticks sanity passed.` and exit code 0.

If this fails:
- **Endpoint resolution / chopsticks startup failure** → check the WSS endpoint in `chopsticks-config.yml` is reachable from your network; chopsticks downloads metadata over the same connection.
- **`api.tx.revive.instantiateWithCode` argument mismatch** → inspect `api.tx.revive.instantiateWithCode.meta.toHuman()` (e.g. via `node -e "import('@polkadot/api').then(...)"`) and adjust the JS script to match the live pallet metadata, then update this task before retrying.
- **`PristineCode` not found** → the contract didn't deploy. Inspect the events in the JS script output for an `ExtrinsicFailed` with a dispatch error and resolve before retrying.

Don't bypass any failure with `|| true` — the gate criterion requires this to legitimately pass.

- [ ] **Step 7: Add `tmp/` and `node_modules/` to gitignore so we don't commit transient artefacts.**

Append to `on-chain/.gitignore`:

```
tmp/
scripts/node_modules/
scripts/package-lock.json
```

- [ ] **Step 8: Commit.**

```bash
git add on-chain/scripts/chopsticks-sanity.sh \
        on-chain/scripts/chopsticks-config.yml \
        on-chain/scripts/sanity-deploy.mjs \
        on-chain/scripts/package.json \
        on-chain/.gitignore
git commit -m "test(on-chain): chopsticks-Paseo deployment sanity check"
```

---

## Task 14: Stage 1 closeout — README, full-suite check, tag

**Files:**
- Create: `on-chain/README.md`

- [ ] **Step 1: Write `on-chain/README.md`.**

```markdown
# `on-chain/` — ODS Phase 1.b Stage 1

Solidity contract anchoring the off-chain organisation-members trie on Asset
Hub via `pallet-revive`. Multi-tenant: one contract instance serves every
organisation, keyed on the H160 of each org's proxied pure-proxy admin.

See `docs/superpowers/specs/2026-05-13-ods-phase-1b-design.md` for the design.

## Layout

- `src/OrgRegistry.sol` — the contract.
- `test/OrgRegistry.t.sol` — Foundry unit tests (covers §5.1 of the spec).
- `abi/OrgRegistry.json` — pinned ABI artifact for Stage 2 consumers.
- `scripts/chopsticks-sanity.sh` — deploys to a chopsticks-forked Paseo
  Asset Hub and verifies the code hash. Gate criterion for Stage 2.
- `scripts/chopsticks-config.yml` — chopsticks config pinning Paseo's
  endpoint.

## Quickstart

```bash
# Unit tests (no chain required):
cd on-chain && forge test -vv

# Re-pin ABI after a contract change:
forge clean && forge build
jq '{abi: .abi, contractName: "OrgRegistry"}' \
   out/OrgRegistry.sol/OrgRegistry.json > abi/OrgRegistry.json

# Chopsticks sanity (requires resolc + a pallet-revive deployment helper):
./scripts/chopsticks-sanity.sh
```

## Stage 1 gate (must all pass before Stage 2 starts)

- `forge test` passes (13 tests).
- `on-chain/abi/OrgRegistry.json` exists and matches the latest build.
- `scripts/chopsticks-sanity.sh` exits 0.
- Commit tagged `v0.1.0-on-chain-stage1`.

## What Stage 2 adds (not in this directory)

A sibling `on-chain-client/` Rust crate that reads contract state and
subscribes to events via smoldot. Tracked in its own plan.
```

- [ ] **Step 2: Run the full test suite one more time as a final check.**

```bash
cd on-chain && forge test -vv && cd ..
```

Expected: 13 passed, 0 failed.

- [ ] **Step 3: Verify the gate criteria explicitly.**

```bash
# Gate 1: tests
cd on-chain && forge test && cd ..

# Gate 2: ABI artifact exists and is non-empty
test -s on-chain/abi/OrgRegistry.json && echo "ABI OK"

# Gate 3: chopsticks sanity
on-chain/scripts/chopsticks-sanity.sh
```

All three must succeed.

- [ ] **Step 4: Commit and tag.**

```bash
git add on-chain/README.md
git commit -m "docs(on-chain): README and Stage 1 closeout"
git tag -a v0.1.0-on-chain-stage1 -m "ODS Phase 1.b Stage 1 — Solidity contract gate passed"
```

- [ ] **Step 5: Confirm tag is visible.**

```bash
git tag -l 'v0.1.0-on-chain-stage1' --format='%(refname:short) %(subject)'
```

Expected: a single line `v0.1.0-on-chain-stage1 ODS Phase 1.b Stage 1 — Solidity contract gate passed`.

---

## Stage 1 → Stage 2 hand-off

When all Task-14 gate checks pass:

1. Surface the tagged commit (`v0.1.0-on-chain-stage1`) to the human reviewer for sign-off.
2. Capture any unexpected discoveries during chopsticks deployment (e.g. resolc version chosen, exact deployment helper, Paseo runtime version observed) in a short note inline-appended to `docs/superpowers/specs/2026-05-13-ods-phase-1b-design.md` under "Open items" → "Resolved during Stage 1".
3. Start writing Stage 2's plan with `superpowers:writing-plans`, scoped to the on-chain-client crate. That plan can now reference concrete facts from the Stage 1 outcome (runtime version, deployed contract code hash, deployment helper invocation).

---

## Plan self-review

Spec coverage check (mapping spec §5.1 assertions → tasks):
- Genesis happy path → Task 2.
- Update happy path → Task 3.
- `ZeroValue` for zero `rootHash` → Task 4.
- `ZeroValue` for zero `orgPubKey` → Task 5.
- `EpochMismatch` for stale `expectedEpoch` → Task 6.
- `EpochMismatch` for future `expectedEpoch` → Task 7.
- `NoOpUpdate` when both `r` and `k` unchanged → Task 8 (plus the two single-field-changed positive tests).
- Two distinct admins isolated → Task 9.
- Event topics correctly indexed → Task 10.
- Permissionless org creation → Task 11.

Gate criteria (spec §Sequencing → Stage 1 → "Gate criteria"):
- All Foundry tests passing → Task 14 Step 2.
- Contract deployed to chopsticks-forked Paseo AH + sanity reads code hash → Task 13 + Task 14 Step 3.
- ABI exported and pinned in `on-chain/abi/OrgRegistry.json` → Task 12.

No gaps identified. All custom errors, events, and the `update` function are introduced by the test that requires them, and no later task references an undefined symbol.
