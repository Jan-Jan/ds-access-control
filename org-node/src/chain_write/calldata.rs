//! Pure EVM calldata + dynamic runtime-call construction for OrgRegistry.update.
//! `build_update_calldata` is pure and fully testable without a chain.
//! `revive_update_runtime_call` builds the `RuntimeCall::Revive(Call::call{..})`
//! dynamic Value — copied verbatim from on-chain-client/tests/common/submit.rs:91.
#![cfg(feature = "chain")]

use subxt::dynamic::Value;
use subxt::ext::scale_value::Composite;

/// keccak256("update(bytes32,bytes32,uint256)")[..4]
pub const UPDATE_SELECTOR: [u8; 4] = [0xf1, 0xbc, 0x53, 0x7b];

/// Weight limit passed to `Revive.call`. Mirrors on-chain-client/tests/common/submit.rs.
const WEIGHT_REF_TIME: u64 = 1_000_000_000_000;
const WEIGHT_PROOF_SIZE: u64 = 4_000_000;

/// Storage deposit limit for `Revive.call`. Mirrors on-chain-client/tests/common/submit.rs.
const STORAGE_DEPOSIT_LIMIT: u128 = 10_000_000_000_000;

/// Build the 100-byte EVM calldata for `update(newRootHash, newOrgPubKey, expectedEpoch)`.
/// Layout: selector(4) ‖ root(32) ‖ orgPubKey(32) ‖ expectedEpoch as uint256 big-endian(32).
pub fn build_update_calldata(
    new_root_hash: [u8; 32],
    new_org_pub_key: [u8; 32],
    expected_epoch: u128,
) -> Vec<u8> {
    let mut data = Vec::with_capacity(100);
    data.extend_from_slice(&UPDATE_SELECTOR);
    data.extend_from_slice(&new_root_hash);
    data.extend_from_slice(&new_org_pub_key);
    let mut epoch_be = [0u8; 32];
    epoch_be[16..32].copy_from_slice(&expected_epoch.to_be_bytes());
    data.extend_from_slice(&epoch_be);
    data
}

/// Build the dynamic `Revive.call` runtime call that invokes the contract's
/// update(). Mirror of on-chain-client/tests/common/submit.rs:91 — keep the
/// field names (dest, value, weight_limit{ref_time,proof_size},
/// storage_deposit_limit, data) and the weight/deposit constants identical, as
/// they are matched against runtime metadata.
pub fn revive_update_runtime_call(
    contract_h160: [u8; 20],
    new_root_hash: [u8; 32],
    new_org_pub_key: [u8; 32],
    expected_epoch: u128,
) -> Value {
    let calldata = build_update_calldata(new_root_hash, new_org_pub_key, expected_epoch);
    let h160_bytes: Vec<Value> = contract_h160
        .iter()
        .map(|b| Value::u128(u128::from(*b)))
        .collect();
    Value::variant(
        "Revive",
        Composite::unnamed(vec![Value::variant(
            "call",
            Composite::named(vec![
                ("dest".to_string(), Value::unnamed_composite(h160_bytes)),
                ("value".to_string(), Value::u128(0)),
                // The live Paseo-AH pallet-revive names this field
                // `gas_limit` at the *extrinsic* arg level (where
                // `submit_update` passes it positionally), but the
                // RuntimeCall enum variant — which is what we build here
                // for nesting inside Proxy.proxy / Multisig — declares it
                // as `weight_limit`. Matched by name, so it must be exact.
                (
                    "weight_limit".to_string(),
                    Value::named_composite([
                        ("ref_time", Value::u128(u128::from(WEIGHT_REF_TIME))),
                        ("proof_size", Value::u128(u128::from(WEIGHT_PROOF_SIZE))),
                    ]),
                ),
                (
                    "storage_deposit_limit".to_string(),
                    Value::u128(STORAGE_DEPOSIT_LIMIT),
                ),
                ("data".to_string(), Value::from_bytes(calldata)),
            ]),
        )]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calldata_layout_is_exact() {
        let root = [0x11u8; 32];
        let key = [0x22u8; 32];
        let data = build_update_calldata(root, key, 7);
        assert_eq!(data.len(), 100);
        assert_eq!(&data[0..4], &UPDATE_SELECTOR);
        assert_eq!(&data[4..36], &root);
        assert_eq!(&data[36..68], &key);
        // epoch 7 as uint256 big-endian: 31 zero bytes then 0x07.
        assert_eq!(data[99], 7);
        assert!(data[68..99].iter().all(|b| *b == 0));
    }
}
