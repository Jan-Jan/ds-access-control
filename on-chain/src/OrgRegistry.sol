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

    error ZeroValue();
    error EpochMismatch(uint256 expected, uint256 actual);
    error NoOpUpdate();

    event GenesisInitialized(address indexed admin, bytes32 rootHash, bytes32 orgPubKey);

    event RootUpdated(
        address indexed admin,
        uint256 indexed epoch,
        bytes32 rootHash,
        bytes32 orgPubKey,
        bytes32 prevRootHash
    );

    function update(bytes32 newRootHash, bytes32 newOrgPubKey, uint256 expectedEpoch) external {
        if (newRootHash == bytes32(0) || newOrgPubKey == bytes32(0)) revert ZeroValue();
        OrgState storage s = orgs[msg.sender];
        if (expectedEpoch != s.epoch) revert EpochMismatch(expectedEpoch, s.epoch);

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
    }
}
