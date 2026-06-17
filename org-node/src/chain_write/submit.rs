//! Submit a contract update() extrinsic. Submit-only: returns the extrinsic
//! hash; the caller settles a block (BlockSink) before reading the result.
//! Lifted verbatim from on-chain-client/tests/common/submit.rs:146; errors
//! retyped to WriteError; .unwrap()/.expect() replaced with WriteError.
#![cfg(feature = "chain")]

use subxt::OnlineClient;
use subxt::config::PolkadotConfig;
use subxt::dynamic::{self, Value};
use subxt_signer::sr25519::Keypair;

use crate::chain_write::WriteError;
use crate::chain_write::calldata::build_update_calldata;

/// Weight limit passed to `Revive.call`. Mirrors on-chain-client/tests/common/submit.rs.
const WEIGHT_REF_TIME: u64 = 1_000_000_000_000;
const WEIGHT_PROOF_SIZE: u64 = 4_000_000;

/// Storage deposit limit for `Revive.call`. Mirrors on-chain-client/tests/common/submit.rs.
const STORAGE_DEPOSIT_LIMIT: u128 = 10_000_000_000_000;

/// Submit a `Revive.call` extrinsic that invokes `OrgRegistry.update(...)`
/// from the given signer's account. Signs with `signer`, returns the
/// 0x-prefixed extrinsic hash. Does NOT wait for inclusion.
///
/// For admin writes that go through the proxy+multisig (genesis, updates from
/// a multisig-controlled proxy), the call is wrapped via `proxied(P,
/// revive_update_runtime_call(...))` and dispatched with `dispatch_threshold_1`.
/// This function is the **direct** single-signer path (useful when the admin
/// account itself is the contract caller).
pub async fn submit_update(
    api: &OnlineClient<PolkadotConfig>,
    signer: &Keypair,
    contract_h160: [u8; 20],
    new_root_hash: [u8; 32],
    new_org_pub_key: [u8; 32],
    expected_epoch: u128,
) -> Result<String, WriteError> {
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
        .map_err(|e| WriteError::Subxt(format!("tx_client: {e}")))?;
    let progress = tx_client
        .sign_and_submit_then_watch_default(&tx, signer)
        .await
        .map_err(|e| WriteError::Subxt(format!("submit: {e}")))?;
    let ext_hash = progress.extrinsic_hash();
    // Dropping `progress` here closes the status subscription — we
    // don't need to track inclusion in this helper. The caller drives
    // block production and verifies out-of-band.
    Ok(format!("0x{}", hex::encode(ext_hash.0)))
}
