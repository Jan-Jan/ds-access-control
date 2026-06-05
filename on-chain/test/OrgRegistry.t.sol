// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.27;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {OrgRegistry} from "../src/OrgRegistry.sol";

contract OrgRegistryTest is Test {
    OrgRegistry internal reg;

    address internal admin   = address(0xA11CE);
    bytes32 internal root0   = bytes32(uint256(0x1111));
    bytes32 internal pk0     = bytes32(uint256(0x2222));

    function setUp() public {
        reg = new OrgRegistry();
    }

    // Reads OrgState directly from storage via vm.load, bypassing any
    // contract-side helper. Storage layout: `mapping(address => OrgState) orgs`
    // is the only state at slot 0, so the slot for a given admin is
    // keccak256(abi.encode(admin, uint256(0))); the struct's three fields
    // occupy the next three consecutive slots.
    function _loadOrg(address adminAddr)
        internal
        view
        returns (bytes32 r, bytes32 k, uint256 e)
    {
        bytes32 base = keccak256(abi.encode(adminAddr, uint256(0)));
        r = vm.load(address(reg), base);
        k = vm.load(address(reg), bytes32(uint256(base) + 1));
        e = uint256(vm.load(address(reg), bytes32(uint256(base) + 2)));
    }

    function test_GenesisHappyPath_StoresStateAndEmits() public {
        vm.expectEmit(true, false, false, true, address(reg));
        emit OrgRegistry.GenesisInitialized(admin, root0, pk0);

        vm.prank(admin);
        reg.update(root0, pk0, 0);

        (bytes32 r, bytes32 k, uint256 e) = _loadOrg(admin);
        assertEq(r, root0,    "rootHash mismatch");
        assertEq(k, pk0,      "orgPubKey mismatch");
        assertEq(e, 1,        "epoch after genesis must be 1");
    }

    bytes32 internal root1 = bytes32(uint256(0x3333));
    bytes32 internal pk1   = bytes32(uint256(0x4444));

    function test_UpdateAfterGenesis_IncrementsEpochAndEmits() public {
        vm.prank(admin);
        reg.update(root0, pk0, 0);  // genesis: epoch becomes 1

        vm.expectEmit(true, true, false, true, address(reg));
        emit OrgRegistry.RootUpdated(admin, 2, root1, pk1, root0);

        vm.prank(admin);
        reg.update(root1, pk1, 1);  // update: expectedEpoch = 1 (the epoch we replace)

        (bytes32 r, bytes32 k, uint256 e) = _loadOrg(admin);
        assertEq(r, root1, "rootHash should be updated");
        assertEq(k, pk1,   "orgPubKey should be updated");
        assertEq(e, 2,     "epoch after first update must be 2");
    }

    function test_RevertsZeroValue_WhenRootHashIsZero() public {
        vm.expectRevert(OrgRegistry.ZeroValue.selector);
        vm.prank(admin);
        reg.update(bytes32(0), pk0, 0);
    }

    function test_RevertsZeroValue_WhenOrgPubKeyIsZero() public {
        vm.expectRevert(OrgRegistry.ZeroValue.selector);
        vm.prank(admin);
        reg.update(root0, bytes32(0), 0);
    }

    function test_RevertsEpochMismatch_WhenExpectedEpochIsStale() public {
        vm.prank(admin);
        reg.update(root0, pk0, 0);  // epoch becomes 1

        vm.expectRevert(abi.encodeWithSelector(OrgRegistry.EpochMismatch.selector, uint256(0), uint256(1)));
        vm.prank(admin);
        reg.update(root1, pk1, 0);  // passes stale expected=0 when actual=1
    }

    function test_RevertsEpochMismatch_WhenExpectedEpochIsInTheFuture() public {
        // Fresh admin slot: s.epoch == 0. Passing expectedEpoch=42 should revert.
        vm.expectRevert(abi.encodeWithSelector(OrgRegistry.EpochMismatch.selector, uint256(42), uint256(0)));
        vm.prank(admin);
        reg.update(root0, pk0, 42);
    }

    /// Race loser: two updates prepared against the same `expectedEpoch` race
    /// each other on-chain. The first lands and bumps `epoch`; the second is
    /// the "loser" and must revert `EpochMismatch` without mutating state.
    /// A subsequent re-prepared call from the loser (with the now-current
    /// epoch) must succeed normally.
    function test_RaceLoser_RevertsEpochMismatch_LeavesStateUnchanged_ThenSucceedsOnRetry() public {
        // Genesis: epoch becomes 1.
        vm.prank(admin);
        reg.update(root0, pk0, 0);

        // Winner: legitimate update with expectedEpoch=1 → epoch becomes 2.
        vm.prank(admin);
        reg.update(root1, pk1, 1);

        (bytes32 rWinner, bytes32 kWinner, uint256 eWinner) = _loadOrg(admin);
        assertEq(rWinner, root1, "winner: rootHash updated");
        assertEq(kWinner, pk1,   "winner: orgPubKey updated");
        assertEq(eWinner, 2,     "winner: epoch is 2");

        // Loser: prepared against epoch=1 (now stale). Distinct payload so
        // the revert is provably about epoch CAS, not NoOpUpdate.
        bytes32 rLose = bytes32(uint256(0x7777));
        bytes32 kLose = bytes32(uint256(0x8888));
        vm.expectRevert(abi.encodeWithSelector(OrgRegistry.EpochMismatch.selector, uint256(1), uint256(2)));
        vm.prank(admin);
        reg.update(rLose, kLose, 1);

        // State must be byte-for-byte unchanged after the revert.
        (bytes32 rPost, bytes32 kPost, uint256 ePost) = _loadOrg(admin);
        assertEq(rPost, root1, "post-revert: rootHash unchanged");
        assertEq(kPost, pk1,   "post-revert: orgPubKey unchanged");
        assertEq(ePost, 2,     "post-revert: epoch unchanged");

        // Loser re-prepares against the now-current epoch=2 and succeeds.
        vm.prank(admin);
        reg.update(rLose, kLose, 2);

        (bytes32 rFinal, bytes32 kFinal, uint256 eFinal) = _loadOrg(admin);
        assertEq(rFinal, rLose, "retry: rootHash updated");
        assertEq(kFinal, kLose, "retry: orgPubKey updated");
        assertEq(eFinal, 3,     "retry: epoch advanced to 3");
    }

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

        (bytes32 r, bytes32 k, uint256 e) = _loadOrg(admin);
        assertEq(r, root0);
        assertEq(k, pk1);
        assertEq(e, 2);
    }

    function test_AllowsUpdate_WhenOnlyRootHashChanged() public {
        vm.prank(admin);
        reg.update(root0, pk0, 0);

        vm.prank(admin);
        reg.update(root1, pk0, 1);  // pk unchanged, root changed → allowed

        (bytes32 r, bytes32 k, uint256 e) = _loadOrg(admin);
        assertEq(r, root1);
        assertEq(k, pk0);
        assertEq(e, 2);
    }

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

            (bytes32 gotR, bytes32 gotK, uint256 gotE) = _loadOrg(admins[i]);
            assertEq(gotR, r, "rootHash mismatch for admin i");
            assertEq(gotK, k, "orgPubKey mismatch for admin i");
            assertEq(gotE, 1, "epoch=1 after genesis for admin i");
        }
    }

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

        (bytes32 rA, bytes32 kA, uint256 eA) = _loadOrg(admin);
        assertEq(rA, root1, "A.root unaffected by B");
        assertEq(kA, pk1,   "A.pk   unaffected by B");
        assertEq(eA, 2,     "A.epoch unaffected by B");

        (bytes32 rB, bytes32 kB, uint256 eB) = _loadOrg(adminB);
        assertEq(rB, rootB, "B.root unaffected by A");
        assertEq(kB, pkB,   "B.pk   unaffected by A");
        assertEq(eB, 1,     "B.epoch unaffected by A");
    }

    /// Fuzz: any two successful update calls from the same admin must produce
    /// epochs (1, 2) — strictly +1, never skipping or wrapping. Inputs that
    /// would hit ZeroValue / EpochMismatch / NoOpUpdate are filtered via
    /// vm.assume so only happy-path calls exercise the monotonicity assertion.
    function testFuzz_EpochMonotone_IncrementsByOne(
        address fuzzAdmin,
        bytes32 r0,
        bytes32 k0,
        bytes32 r1,
        bytes32 k1
    ) public {
        vm.assume(r0 != bytes32(0) && k0 != bytes32(0));
        vm.assume(r1 != bytes32(0) && k1 != bytes32(0));
        vm.assume(r0 != r1 || k0 != k1);

        vm.prank(fuzzAdmin);
        reg.update(r0, k0, 0);
        (,, uint256 e1) = _loadOrg(fuzzAdmin);
        assertEq(e1, 1, "epoch after genesis must be 1");

        vm.prank(fuzzAdmin);
        reg.update(r1, k1, 1);
        (bytes32 gotR, bytes32 gotK, uint256 e2) = _loadOrg(fuzzAdmin);
        assertEq(e2, 2,  "epoch after first update must be 2");
        assertEq(gotR, r1, "rootHash should be the second input");
        assertEq(gotK, k1, "orgPubKey should be the second input");
    }
}
