//! pallet-multisig helpers: pseudo-account derivation + threshold-1
//! dispatch. The derivation is pinned EMPIRICALLY by
//! `multisig_dispatch_executes_from_derived_account` (the 01_multisig_sanity
//! integration test): we fund the derived address and dispatch a transfer
//! *from* it via `as_multi_threshold_1` — a wrong derivation means the
//! funded account and the dispatch origin differ, and the transfer fails
//! with insufficient funds.
//!
//! Threshold-1 only: threshold>1 `as_multi` ceremonies are deliberately
//! deferred — the scenarios need "the admin set changes while the pure
//! proxy stays stable", which threshold-1 multisigs with disjoint signer
//! sets exercise fully.

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use parity_scale_codec::Encode;
use subxt::OnlineClient;
use subxt::config::PolkadotConfig;
use subxt::dynamic::{self, Value};
use subxt::ext::scale_value::Composite;
use subxt_signer::sr25519::Keypair;

use super::submit::SubmitError;

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
    let mut hasher = Blake2bVar::new(32).expect("32 is a valid blake2b output size");
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("output buffer is the declared size");
    out
}

/// Submit `call` from the 1-of-N multisig formed by `signer` +
/// `other_signatories` via `Multisig.as_multi_threshold_1`. The dispatch
/// origin inside `call` is `multi_account_id(all_signers, 1)`.
/// `other_signatories` may be passed in any order (sorted internally; the
/// runtime requires strict ascending order).
/// Does NOT mine — caller drives `dev_newBlock` (chopsticks is manual).
pub async fn dispatch_threshold_1(
    api: &OnlineClient<PolkadotConfig>,
    signer: &Keypair,
    other_signatories: &[[u8; 32]],
    call: Value,
) -> Result<(), SubmitError> {
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
        .map_err(|e| SubmitError::Subxt(format!("tx_client: {e}")))?;
    tx_client
        .sign_and_submit_then_watch_default(&tx, signer)
        .await
        .map_err(|e| SubmitError::Subxt(format!("as_multi_threshold_1 submit: {e}")))?;
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
) -> Result<(), SubmitError> {
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
        .map_err(|e| SubmitError::Subxt(format!("tx_client: {e}")))?;
    tx_client
        .sign_and_submit_then_watch_default(&tx, from)
        .await
        .map_err(|e| SubmitError::Subxt(format!("transfer submit: {e}")))?;
    Ok(())
}

/// 100 PAS (Paseo AH uses 10 decimals). Generous budget for existential
/// deposit + fees + pallet-revive storage deposits in scenario tests.
pub const FUND_AMOUNT: u128 = 1_000_000_000_000;
