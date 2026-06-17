//! Genesis ceremony: stand up an org's on-chain slot. Composes the chain_write
//! primitives. Block production is injected via BlockSink so this works against
//! chopsticks (mine) and live chains (wait).
#![cfg(feature = "chain")]
use subxt::{OnlineClient, config::PolkadotConfig};
use subxt_signer::sr25519::Keypair;

use crate::chain_write::calldata::revive_update_runtime_call;
use crate::chain_write::multisig::{dispatch_threshold_1, fund, FUND_AMOUNT};
use crate::chain_write::proxy::{create_pure_via_multisig, map_account_call, proxied, BlockSink};
use crate::chain_write::WriteError;
use crate::ids::OrgId;

/// The on-chain identity produced by genesis.
pub struct GenesisOutcome {
    /// Pure-proxy AccountId32.
    pub p: [u8; 32],
    /// org_id = h160_of(P) — the contract slot key.
    pub org_id: OrgId,
}

/// Run the full genesis ceremony for a single-admin (threshold-1) org.
///
/// Steps (each followed by sink.settle()):
/// 1. create pure proxy P via the admin's threshold-1 multisig
/// 2. fund P
/// 3. map_account from P (pallet-revive prerequisite)
/// 4. submit genesis update(root, orgPubKey, expectedEpoch=0) via proxied multisig
///
/// `funder` pays for P's existential deposit / fees. `admin` is the sole signer;
/// `others` are the multisig co-signatories (empty slice for a 1-of-1).
#[allow(clippy::too_many_arguments)]
pub async fn genesis_ceremony(
    sink: &dyn BlockSink,
    api: &OnlineClient<PolkadotConfig>,
    contract_h160: [u8; 20],
    funder: &Keypair,
    admin: &Keypair,
    others: &[[u8; 32]],
    genesis_root: [u8; 32],
    org_pub_key: [u8; 32],
) -> Result<GenesisOutcome, WriteError> {
    // 1. Pure proxy.
    let p = create_pure_via_multisig(sink, api, admin, others).await?;
    // 2. Fund P.
    fund(api, funder, p, FUND_AMOUNT).await?;
    sink.settle().await?;
    // 3. map_account from P.
    dispatch_threshold_1(api, admin, others, proxied(p, map_account_call())).await?;
    sink.settle().await?;
    // 4. Genesis update (expectedEpoch = 0).
    let call = revive_update_runtime_call(contract_h160, genesis_root, org_pub_key, 0);
    dispatch_threshold_1(api, admin, others, proxied(p, call)).await?;
    sink.settle().await?;

    let org_id = OrgId::new(on_chain_client::h160_of(p));
    Ok(GenesisOutcome { p, org_id })
}
