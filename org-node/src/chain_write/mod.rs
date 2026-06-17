//! On-chain write path: build update() calldata, drive a threshold-1 pure-proxy
//! multisig, and submit extrinsics via subxt. Productionised from
//! on-chain-client/tests/common; decoupled from chopsticks (submit returns the
//! extrinsic hash; block production is the caller's concern).
#![cfg(feature = "chain")]

pub mod calldata;
pub mod multisig;
pub mod proxy;
pub mod submit;

use thiserror::Error;

/// Errors from the on-chain write path.
#[derive(Debug, Error)]
pub enum WriteError {
    #[error("subxt error: {0}")]
    Subxt(String),
    #[error("expected on-chain event not found: {0}")]
    EventNotFound(&'static str),
    #[error("malformed event field: {0}")]
    MalformedEvent(&'static str),
}
