//! pallet-proxy helpers for the pure-proxy ("P") org-admin pattern:
//!
//! - [`create_pure_via_multisig`] — the multisig M dispatches
//!   `Proxy.create_pure(Any, 0, 0)`; P's AccountId32 is read back from
//!   the `Proxy.PureCreated` event in the mined block (entropy includes
//!   height + ext index, so deriving offline is pointless).
//! - [`proxied`] — wrap a RuntimeCall in `Proxy.proxy(P, None, call)`
//!   so it executes with P as origin.
//! - [`rotate`] — swap the controlling multisig: via the OLD multisig,
//!   P adds the NEW multisig as an Any-proxy delegate, then removes the
//!   old one. P's address (and hence the OrgId `h160_of(P)`) is
//!   untouched.
//!
//! All helpers submit but do NOT mine — the caller drives `dev_newBlock`
//! — EXCEPT `create_pure_via_multisig` and `rotate`, which mine
//! internally because they must read back events / sequence two calls.
//!
//! API note (subxt 0.50.1): there is no `Event::field_values()`. Event
//! fields are pulled out dynamically via
//! `Event::decode_fields_unchecked_as::<Composite<()>>()` —
//! `scale_value::Composite<()>` implements `DecodeAsFields`. The context
//! generic on the resulting `Value`/`Composite` is therefore `()`, not
//! `u32`; the shape-walking logic is otherwise unchanged.

use subxt::OnlineClient;
use subxt::config::PolkadotConfig;
use subxt::dynamic::Value;
use subxt::ext::scale_value::{Composite, Primitive, ValueDef};
use subxt::utils::H256;
use subxt_signer::sr25519::Keypair;

use super::chopsticks_fork::ChopsticksHandle;
use super::chopsticks_reorg::mine_block;
use super::multisig::dispatch_threshold_1;
use super::submit::SubmitError;

/// `RuntimeCall::Proxy(Call::create_pure { proxy_type: Any, delay: 0,
/// index: 0 })` as a dynamic value.
fn create_pure_call() -> Value {
    Value::variant(
        "Proxy",
        Composite::unnamed(vec![Value::variant(
            "create_pure",
            Composite::named(vec![
                (
                    "proxy_type".to_string(),
                    Value::variant("Any", Composite::unnamed(vec![])),
                ),
                ("delay".to_string(), Value::u128(0)),
                ("index".to_string(), Value::u128(0)),
            ]),
        )]),
    )
}

/// Wrap `call` so it executes with `pure_proxy` as origin:
/// `RuntimeCall::Proxy(Call::proxy { real: Id(P), force_proxy_type:
/// None, call })`.
pub fn proxied(pure_proxy: [u8; 32], call: Value) -> Value {
    Value::variant(
        "Proxy",
        Composite::unnamed(vec![Value::variant(
            "proxy",
            Composite::named(vec![
                (
                    "real".to_string(),
                    Value::variant(
                        "Id",
                        Composite::unnamed(vec![Value::from_bytes(pure_proxy.as_slice())]),
                    ),
                ),
                (
                    "force_proxy_type".to_string(),
                    Value::variant("None", Composite::unnamed(vec![])),
                ),
                ("call".to_string(), call),
            ]),
        )]),
    )
}

/// `RuntimeCall::Revive(Call::map_account {})` as a dynamic value.
///
/// pallet-revive keeps an `AddressMapper` table linking each substrate
/// `AccountId32` to the H160 it acts as inside the EVM. The fallback
/// mapping (`to_fallback_account_id`) only applies to accounts that have
/// never been mapped AND have no on-chain "stateful" mapping — and a
/// fresh **pure proxy** that has never called `map_account` cannot be a
/// `Revive.call` origin: the dispatch reverts with Revive error 43
/// (pallet index 100) *before* the contract runs, so no
/// `ContractEmitted` event is produced. Empirically pinned by the
/// genesis-event diagnostic during Task 7: the pure proxy must dispatch
/// `Revive.map_account` (which takes **no arguments** — verified against
/// live Paseo-AH metadata: `Revive::map_account fields=[]`) once after
/// being funded, AS ITSELF, before it can submit `OrgRegistry.update`.
/// Plain dev accounts (e.g. Alice) worked unmapped in earlier scenarios
/// only because they already had a mapping from prior chain activity in
/// the forked state.
pub fn map_account_call() -> Value {
    Value::variant(
        "Revive",
        Composite::unnamed(vec![Value::variant(
            "map_account",
            Composite::unnamed(vec![]),
        )]),
    )
}

fn add_proxy_call(delegate: [u8; 32]) -> Value {
    Value::variant(
        "Proxy",
        Composite::unnamed(vec![Value::variant(
            "add_proxy",
            Composite::named(vec![
                (
                    "delegate".to_string(),
                    Value::variant(
                        "Id",
                        Composite::unnamed(vec![Value::from_bytes(delegate.as_slice())]),
                    ),
                ),
                (
                    "proxy_type".to_string(),
                    Value::variant("Any", Composite::unnamed(vec![])),
                ),
                ("delay".to_string(), Value::u128(0)),
            ]),
        )]),
    )
}

fn remove_proxy_call(delegate: [u8; 32]) -> Value {
    Value::variant(
        "Proxy",
        Composite::unnamed(vec![Value::variant(
            "remove_proxy",
            Composite::named(vec![
                (
                    "delegate".to_string(),
                    Value::variant(
                        "Id",
                        Composite::unnamed(vec![Value::from_bytes(delegate.as_slice())]),
                    ),
                ),
                (
                    "proxy_type".to_string(),
                    Value::variant("Any", Composite::unnamed(vec![])),
                ),
                ("delay".to_string(), Value::u128(0)),
            ]),
        )]),
    )
}

/// Create a pure proxy controlled by the 1-of-N multisig (`signer` +
/// `others`). Submits via as_multi_threshold_1, mines one block, and
/// extracts P from the `Proxy.PureCreated` event in that block.
pub async fn create_pure_via_multisig(
    fork: &ChopsticksHandle,
    api: &OnlineClient<PolkadotConfig>,
    signer: &Keypair,
    others: &[[u8; 32]],
) -> Result<[u8; 32], SubmitError> {
    dispatch_threshold_1(api, signer, others, create_pure_call()).await?;
    let block_hash_hex = mine_block(fork)
        .await
        .map_err(|e| SubmitError::Subxt(format!("mine: {e}")))?;
    let block_hash = parse_block_hash(&block_hash_hex)?;

    let at = api
        .at_block(H256(block_hash))
        .await
        .map_err(|e| SubmitError::Subxt(format!("at_block: {e}")))?;
    let events = at
        .events()
        .fetch()
        .await
        .map_err(|e| SubmitError::Subxt(format!("events.fetch: {e}")))?;
    for ev in events.iter() {
        let ev = ev.map_err(|e| SubmitError::Subxt(format!("event iter: {e}")))?;
        if ev.pallet_name() == "Proxy" && ev.event_name() == "PureCreated" {
            let fields: Composite<()> = ev
                .decode_fields_unchecked_as()
                .map_err(|e| SubmitError::Subxt(format!("decode fields: {e}")))?;
            return account32_from_named_field(&fields, "pure");
        }
    }
    Err(SubmitError::Subxt(
        "no Proxy.PureCreated event in mined block".to_string(),
    ))
}

/// Rotate P's controlling multisig from OLD (signer_old + others_old) to
/// NEW (the 32-byte multisig account `new_multi`). Two proxied calls,
/// each in its own block: add_proxy(new) then remove_proxy(old_multi).
pub async fn rotate(
    fork: &ChopsticksHandle,
    api: &OnlineClient<PolkadotConfig>,
    pure_proxy: [u8; 32],
    signer_old: &Keypair,
    others_old: &[[u8; 32]],
    old_multi: [u8; 32],
    new_multi: [u8; 32],
) -> Result<(), SubmitError> {
    dispatch_threshold_1(
        api,
        signer_old,
        others_old,
        proxied(pure_proxy, add_proxy_call(new_multi)),
    )
    .await?;
    mine_block(fork)
        .await
        .map_err(|e| SubmitError::Subxt(format!("mine add_proxy: {e}")))?;

    dispatch_threshold_1(
        api,
        signer_old,
        others_old,
        proxied(pure_proxy, remove_proxy_call(old_multi)),
    )
    .await?;
    mine_block(fork)
        .await
        .map_err(|e| SubmitError::Subxt(format!("mine remove_proxy: {e}")))?;
    Ok(())
}

fn parse_block_hash(hex_str: &str) -> Result<[u8; 32], SubmitError> {
    let bytes = hex::decode(hex_str.trim_start_matches("0x"))
        .map_err(|e| SubmitError::Subxt(format!("block hash hex: {e}")))?;
    let mut out = [0u8; 32];
    if bytes.len() != 32 {
        return Err(SubmitError::Subxt(format!(
            "block hash was {} bytes",
            bytes.len()
        )));
    }
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Pull a 32-byte AccountId out of a named event field. The dynamic
/// Value for an AccountId32 is a composite wrapping 32 u8 primitives
/// (possibly nested one level — newtype). Handles both shapes.
fn account32_from_named_field(
    fields: &Composite<()>,
    name: &str,
) -> Result<[u8; 32], SubmitError> {
    let Composite::Named(named) = fields else {
        return Err(SubmitError::Subxt("event fields not named".to_string()));
    };
    let (_, value) = named
        .iter()
        .find(|(n, _)| n == name)
        .ok_or_else(|| SubmitError::Subxt(format!("no field {name:?} in event")))?;
    collect_account32(value)
        .ok_or_else(|| SubmitError::Subxt(format!("field {name:?} is not a 32-byte account")))
}

fn collect_account32(value: &Value<()>) -> Option<[u8; 32]> {
    match &value.value {
        ValueDef::Composite(c) => {
            let inner: Vec<&Value<()>> = match c {
                Composite::Named(n) => n.iter().map(|(_, v)| v).collect(),
                Composite::Unnamed(u) => u.iter().collect(),
            };
            if inner.len() == 1 {
                return collect_account32(inner[0]);
            }
            if inner.len() == 32 {
                let mut out = [0u8; 32];
                for (i, v) in inner.iter().enumerate() {
                    match &v.value {
                        ValueDef::Primitive(Primitive::U128(b)) if *b <= 255 => {
                            out[i] = *b as u8;
                        }
                        _ => return None,
                    }
                }
                return Some(out);
            }
            None
        }
        _ => None,
    }
}
