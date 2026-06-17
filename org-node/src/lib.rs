//! ODS Phase 2 node logic. See docs/superpowers/specs/2026-06-15-ods-phase-2-poc-design.md.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod chain;
pub mod envelope;
pub mod error;
pub mod ids;
pub mod keys;
pub mod sequence;
pub mod verify;

#[cfg(feature = "transport")]
pub mod transport;

#[cfg(feature = "chain")]
pub mod chain_read;
#[cfg(feature = "chain")]
pub mod chain_write;
#[cfg(feature = "chain")]
pub mod ceremony;

#[cfg(feature = "chain")]
pub use chain_read::OnChainReader;

#[cfg(feature = "app")]
pub mod blobs;
#[cfg(feature = "app")]
pub mod store;
#[cfg(feature = "app")]
pub mod service;

#[cfg(feature = "app")]
pub use service::{ChainOps, MockChainOps, OrgService, ReceiveOutcome, SelfDeleteOutcome};
#[cfg(feature = "app")]
pub use service::SubxtChainOps;

#[cfg(test)]
mod test_fixtures;

pub use chain::{ChainReader, OrgState};
pub use envelope::SignedDeltaEnvelope;
pub use error::OrgNodeError;
pub use ids::OrgId;
pub use keys::SigningKeypair;
pub use sequence::SeqGuard;
pub use verify::{verify_envelope_against_chain, VerifyContext, VerifiedUpdate};
