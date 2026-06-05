//! Empirical pin of the pallet-multisig pseudo-account derivation. Funds
//! `multi_account_id({alice, bob}, 1)` and then has alice dispatch a
//! transfer FROM that multisig via as_multi_threshold_1. If our
//! derivation diverged from the runtime's, the funded account and the
//! dispatch origin would differ and the inner transfer would fail with
//! insufficient funds — asserted via the post-state balances.

#![cfg(feature = "dev-rpc")]

mod common;

use common::chopsticks_fork::spawn_fork;
use common::chopsticks_reorg::mine_block;
use common::conn::legacy_client;
use common::multisig::{FUND_AMOUNT, dispatch_threshold_1, fund, multi_account_id};
use subxt::dynamic::Value;
use subxt::ext::scale_value::Composite;
use subxt_signer::sr25519::dev;

#[tokio::test]
async fn multisig_dispatch_executes_from_derived_account() {
    let fork = spawn_fork().await.expect("spawn fork");
    let api = legacy_client(&fork.ws_url).await.expect("legacy client");

    let alice = dev::alice();
    let bob = dev::bob();
    let charlie_account: [u8; 32] = dev::charlie().public_key().0;
    let signers = [alice.public_key().0, bob.public_key().0];
    let multi = multi_account_id(&signers, 1);
    eprintln!("multisig account: 0x{}", hex::encode(multi));

    fund(&api, &alice, multi, FUND_AMOUNT).await.expect("fund multisig");
    mine_block(&fork).await.expect("mine fund block");

    // Inner call: transfer 10 PAS from the multisig to charlie.
    let transfer_amount: u128 = 100_000_000_000;
    let inner = Value::variant(
        "Balances",
        Composite::unnamed(vec![Value::variant(
            "transfer_keep_alive",
            Composite::named(vec![
                (
                    "dest".to_string(),
                    Value::variant(
                        "Id",
                        Composite::unnamed(vec![Value::from_bytes(
                            charlie_account.as_slice(),
                        )]),
                    ),
                ),
                ("value".to_string(), Value::u128(transfer_amount)),
            ]),
        )]),
    );

    let charlie_before = free_balance(&api, charlie_account).await;
    dispatch_threshold_1(&api, &alice, &[bob.public_key().0], inner)
        .await
        .expect("as_multi_threshold_1");
    mine_block(&fork).await.expect("mine dispatch block");
    let charlie_after = free_balance(&api, charlie_account).await;

    assert_eq!(
        charlie_after - charlie_before,
        transfer_amount,
        "transfer from derived multisig account did not execute — \
         multi_account_id derivation diverged from the runtime",
    );
}

async fn free_balance(
    api: &subxt::OnlineClient<subxt::config::PolkadotConfig>,
    account: [u8; 32],
) -> u128 {
    let at = api.at_current_block().await.expect("at_current_block");
    let address: subxt::storage::DynamicAddress<Vec<Value>, Value> =
        subxt::dynamic::storage("System", "Account");
    let value = at
        .storage()
        .try_fetch(address, vec![Value::from_bytes(account.as_slice())])
        .await
        .expect("fetch System.Account")
        .expect("account exists");
    let decoded: Value = value.decode_as().expect("decode AccountInfo");
    account_info_free(&decoded)
}

fn account_info_free(info: &Value) -> u128 {
    use subxt::ext::scale_value::{Primitive, ValueDef};
    let ValueDef::Composite(Composite::Named(fields)) = &info.value else {
        panic!("AccountInfo not a named composite: {info:?}");
    };
    let (_, data) = fields
        .iter()
        .find(|(name, _)| name == "data")
        .expect("AccountInfo.data");
    let ValueDef::Composite(Composite::Named(data_fields)) = &data.value else {
        panic!("AccountData not a named composite: {data:?}");
    };
    let (_, free) = data_fields
        .iter()
        .find(|(name, _)| name == "free")
        .expect("AccountData.free");
    match &free.value {
        ValueDef::Primitive(Primitive::U128(v)) => *v,
        other => panic!("free balance not u128: {other:?}"),
    }
}
