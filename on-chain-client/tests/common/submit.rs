//! Single-account submitter for `OrgRegistry.update(...)` via subxt.
//! Sufficient for Task 5's Scenario A + C gates (single accounts act as
//! their own admin). Task 7's Scenario B layers a multisig + pure-proxy
//! pseudo-account on top.
//!
//! Two pieces:
//!
//! 1. [`build_update_calldata`] — pure: produces the Solidity ABI-encoded
//!    calldata for `OrgRegistry.update(bytes32, bytes32, uint256)` from
//!    typed args. Tested in-process (no fork needed) so a bad selector
//!    or wrong padding fails before we waste time on a chain round-trip.
//!
//! 2. [`submit_update`] — async: constructs a `Revive.call(dest, value=0,
//!    weight_limit, storage_deposit_limit, data)` extrinsic via subxt's
//!    dynamic API, signs with the given `subxt_signer::sr25519::Keypair`,
//!    submits, and waits for `InBlock`. Returns the extrinsic hash on
//!    success or a structured error.
//!
//! The dynamic API avoids pinning a metadata snapshot — useful because
//! Paseo AH's pallet-revive is pre-stable and call shapes have moved
//! across runtime versions. The trade-off is that the field-name +
//! variant-name strings have to match what the live runtime metadata
//! declares; mismatches surface as `SubmitError::Subxt` rather than
//! silent corruption.

use subxt::OnlineClient;
use subxt::config::PolkadotConfig;
use subxt::dynamic::{self, Value};
use subxt::ext::scale_value::Composite;
use subxt_signer::sr25519::Keypair;
use tiny_keccak::{Hasher, Keccak};

/// 4-byte Solidity selector for `update(bytes32,bytes32,uint256)`.
/// Re-derived in [`tests::selector_matches_solidity_abi`].
const UPDATE_SELECTOR: [u8; 4] = [0xf1, 0xbc, 0x53, 0x7b];

/// Weight limit passed to `Revive.call`. Same `(refTime, proofSize)`
/// budget that `../on-chain/scripts/sanity-deploy.mjs` uses for the
/// deploy extrinsic — comfortably under Paseo AH's per-extrinsic limit
/// and ample for a 3-arg setter on a tiny contract.
const WEIGHT_REF_TIME: u64 = 1_000_000_000_000;
const WEIGHT_PROOF_SIZE: u64 = 4_000_000;

/// Storage deposit limit for `Revive.call`. Update is in-place rewrite
/// of an existing slot (no growth) so this is generous; tracks the
/// deploy script's value for consistency.
const STORAGE_DEPOSIT_LIMIT: u128 = 10_000_000_000_000;

#[derive(Debug)]
pub enum SubmitError {
    Subxt(String),
}

impl std::fmt::Display for SubmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Subxt(m) => write!(f, "subxt error: {m}"),
        }
    }
}

impl std::error::Error for SubmitError {}

/// Encode the EVM calldata for `OrgRegistry.update(new_root_hash,
/// new_org_pub_key, expected_epoch)`. Output layout:
///
/// ```text
/// [0..4]      = UPDATE_SELECTOR
/// [4..36]     = new_root_hash (bytes32)
/// [36..68]    = new_org_pub_key (bytes32)
/// [68..100]   = expected_epoch (uint256 BE; low 16 bytes used)
/// ```
pub fn build_update_calldata(
    new_root_hash: [u8; 32],
    new_org_pub_key: [u8; 32],
    expected_epoch: u128,
) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + 32 * 3);
    data.extend_from_slice(&UPDATE_SELECTOR);
    data.extend_from_slice(&new_root_hash);
    data.extend_from_slice(&new_org_pub_key);
    let mut epoch_be = [0u8; 32];
    epoch_be[16..32].copy_from_slice(&expected_epoch.to_be_bytes());
    data.extend_from_slice(&epoch_be);
    data
}

/// Build the `RuntimeCall::Revive(Call::call { .. })` enum value that
/// invokes `OrgRegistry.update(...)` — usable as the inner call of
/// `Multisig.as_multi_threshold_1` / `Proxy.proxy`.
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

/// Submit a `Revive.call` extrinsic that invokes `OrgRegistry.update(...)`
/// from the given signer's account. Fires the extrinsic into the
/// mempool and returns the extrinsic hash (0x-prefixed hex). **Does not
/// wait for inclusion** — chopsticks builds blocks on demand via
/// `dev_newBlock`, so the caller is responsible for driving block
/// production (via `chopsticks_reorg::mine_block`) and then verifying
/// inclusion either by subscribing to events or by reading state at the
/// new block. This separation keeps the submitter transport-agnostic
/// (the same function works against live Paseo, just with no need to
/// mine manually) and avoids subxt's `wait_for_finalized` hanging
/// indefinitely when chopsticks is in manual block-production mode.
///
/// The caller provides `api` — use `conn::legacy_client` to build one
/// for chopsticks; production callers pass their own `OnlineClient`.
pub async fn submit_update(
    api: &OnlineClient<PolkadotConfig>,
    signer: &Keypair,
    contract_h160: [u8; 20],
    new_root_hash: [u8; 32],
    new_org_pub_key: [u8; 32],
    expected_epoch: u128,
) -> Result<String, SubmitError> {
    let calldata = build_update_calldata(new_root_hash, new_org_pub_key, expected_epoch);

    // pallet-revive `call` args (current Polkadot SDK):
    //   dest: H160, value: u128, gas_limit: Weight,
    //   storage_deposit_limit: u128, data: Vec<u8>.
    // H160 is a tuple struct around [u8; 20]; the dynamic API maps a
    // raw byte composite to it. Weight has named fields `ref_time` and
    // `proof_size`. Names are confirmed against `api.metadata()` the
    // first time this is exercised on a live fork.
    let h160_bytes: Vec<Value> = contract_h160
        .iter()
        .map(|b| Value::u128(u128::from(*b)))
        .collect();
    let call_args = vec![
        Value::unnamed_composite(h160_bytes),
        Value::u128(0),
        Value::named_composite([
            ("ref_time", Value::u128(u128::from(WEIGHT_REF_TIME))),
            ("proof_size", Value::u128(u128::from(WEIGHT_PROOF_SIZE))),
        ]),
        Value::u128(STORAGE_DEPOSIT_LIMIT),
        Value::from_bytes(calldata),
    ];
    let tx = dynamic::tx("Revive", "call", call_args);

    let mut tx_client = api
        .tx()
        .await
        .map_err(|e| SubmitError::Subxt(format!("tx_client: {e}")))?;
    let progress = tx_client
        .sign_and_submit_then_watch_default(&tx, signer)
        .await
        .map_err(|e| SubmitError::Subxt(format!("submit: {e}")))?;
    let ext_hash = progress.extrinsic_hash();
    // Dropping `progress` here closes the status subscription — we
    // don't need to track inclusion in this helper. The caller drives
    // block production and verifies out-of-band.
    Ok(format!("0x{}", hex::encode(ext_hash.0)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_matches_solidity_abi() {
        let mut h = Keccak::v256();
        h.update(b"update(bytes32,bytes32,uint256)");
        let mut out = [0u8; 32];
        h.finalize(&mut out);
        assert_eq!(out[..4], UPDATE_SELECTOR);
    }

    #[test]
    fn calldata_layout_matches_evm_abi() {
        let root = [0xaa; 32];
        let key = [0xbb; 32];
        let epoch = 0x1234u128;

        let data = build_update_calldata(root, key, epoch);
        assert_eq!(data.len(), 4 + 32 * 3);
        assert_eq!(&data[..4], &UPDATE_SELECTOR);
        assert_eq!(&data[4..36], &root);
        assert_eq!(&data[36..68], &key);
        // epoch is uint256 big-endian: high 16 bytes zero, then u128 BE.
        assert!(data[68..84].iter().all(|b| *b == 0));
        let mut expected_epoch_bytes = [0u8; 16];
        expected_epoch_bytes.copy_from_slice(&data[84..100]);
        assert_eq!(u128::from_be_bytes(expected_epoch_bytes), epoch);
    }
}
