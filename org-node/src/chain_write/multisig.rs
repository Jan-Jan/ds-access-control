//! Threshold-1 multisig: pseudo-account derivation + dispatch + funding.
//! `multi_account_id` mirrors pallet_multisig::Pallet::multi_account_id.
//! Lifted verbatim from on-chain-client/tests/common/multisig.rs; errors
//! retyped to WriteError; .unwrap()/.expect() replaced with ? / WriteError.
#![cfg(feature = "chain")]

use blake2::Blake2bVar;
use blake2::digest::{Update as _, VariableOutput};
use parity_scale_codec::Encode;
use subxt::OnlineClient;
use subxt::config::PolkadotConfig;
use subxt::dynamic::{self, Value};
use subxt::ext::scale_value::Composite;
use subxt_signer::sr25519::Keypair;

use crate::chain_write::WriteError;

/// 100 PAS (Paseo AH uses 10 decimals). Generous budget for existential
/// deposit + fees + pallet-revive storage deposits in scenario tests.
pub const FUND_AMOUNT: u128 = 1_000_000_000_000;

/// pallet-multisig pseudo-account: `blake2_256(scale_encode((
/// b"modlpy/utilisuba", sorted_signers, threshold)))`. Mirrors
/// `pallet_multisig::Pallet::multi_account_id`.
pub fn multi_account_id(signers: &[[u8; 32]], threshold: u16) -> [u8; 32] {
    let mut sorted: Vec<[u8; 32]> = signers.to_vec();
    sorted.sort();
    let entropy = (b"modlpy/utilisuba", sorted, threshold).encode();
    blake2_256(&entropy)
}

fn blake2_256(data: &[u8]) -> [u8; 32] {
    // 32 is always a valid blake2b output size; the only invalid sizes are
    // 0 and >64. Map construction failure to a compile-time-unreachable path
    // by returning zeroes (but in practice this branch is never taken).
    let mut hasher = match Blake2bVar::new(32) {
        Ok(h) => h,
        Err(_) => return [0u8; 32],
    };
    hasher.update(data);
    let mut out = [0u8; 32];
    // The output buffer is exactly the declared size — finalize_variable only
    // fails if the buffer is longer than the output length we declared (32).
    // This branch is statically unreachable.
    let _ = hasher.finalize_variable(&mut out);
    out
}

/// Submit `call` from the 1-of-N multisig formed by `signer` +
/// `other_signatories` via `Multisig.as_multi_threshold_1`. The dispatch
/// origin inside `call` is `multi_account_id(all_signers, 1)`.
/// `other_signatories` may be passed in any order (sorted internally; the
/// runtime requires strict ascending order).
/// Does NOT mine — caller drives block production (e.g. via BlockSink).
pub async fn dispatch_threshold_1(
    api: &OnlineClient<PolkadotConfig>,
    signer: &Keypair,
    other_signatories: &[[u8; 32]],
    call: Value,
) -> Result<(), WriteError> {
    // pallet-multisig requires other_signatories strictly sorted
    // ascending (SignatoriesOutOfOrder otherwise) — and our submission
    // helper doesn't watch for dispatch errors, so an unsorted list
    // would silently no-op. Sort here; this also matches what
    // multi_account_id does internally.
    let mut sorted_others: Vec<[u8; 32]> = other_signatories.to_vec();
    sorted_others.sort();
    let others: Vec<Value> = sorted_others
        .iter()
        .map(|id| Value::from_bytes(id.as_slice()))
        .collect();
    let tx = dynamic::tx(
        "Multisig",
        "as_multi_threshold_1",
        vec![Value::unnamed_composite(others), call],
    );
    let mut tx_client = api
        .tx()
        .await
        .map_err(|e| WriteError::Subxt(format!("tx_client: {e}")))?;
    tx_client
        .sign_and_submit_then_watch_default(&tx, signer)
        .await
        .map_err(|e| WriteError::Subxt(format!("as_multi_threshold_1 submit: {e}")))?;
    Ok(())
}

/// Transfer `amount` plancks from `from` to the 32-byte account `dest`
/// via `Balances.transfer_keep_alive`. Used to fund multisig pseudo-
/// accounts and pure proxies (existential deposit + fees + revive
/// storage deposits). Does NOT mine.
pub async fn fund(
    api: &OnlineClient<PolkadotConfig>,
    from: &Keypair,
    dest: [u8; 32],
    amount: u128,
) -> Result<(), WriteError> {
    let dest_value = Value::variant(
        "Id",
        Composite::unnamed(vec![Value::from_bytes(dest.as_slice())]),
    );
    let tx = dynamic::tx(
        "Balances",
        "transfer_keep_alive",
        vec![dest_value, Value::u128(amount)],
    );
    let mut tx_client = api
        .tx()
        .await
        .map_err(|e| WriteError::Subxt(format!("tx_client: {e}")))?;
    tx_client
        .sign_and_submit_then_watch_default(&tx, from)
        .await
        .map_err(|e| WriteError::Subxt(format!("transfer submit: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_account_id_is_order_independent() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        // Sorting inside the derivation must make signer order irrelevant.
        assert_eq!(multi_account_id(&[a, b], 1), multi_account_id(&[b, a], 1));
    }

    #[test]
    fn multi_account_id_depends_on_threshold() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_ne!(multi_account_id(&[a, b], 1), multi_account_id(&[a, b], 2));
    }
}
