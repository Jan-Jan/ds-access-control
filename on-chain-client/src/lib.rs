//! Read-only client for the `OrgRegistry` contract on Asset Hub via
//! `pallet-revive`. See the design at
//! `docs/superpowers/specs/2026-05-13-ods-phase-1b-design.md` (§3 covers
//! this crate's public surface; §5.2 lists the integration test scenarios
//! that gate Stage 2) as amended by
//! `docs/superpowers/specs/2026-06-04-ods-phase-1b-stage2-subxt-commitment-design.md`
//! (single transport stack: subxt).
//!
//! Build modes:
//!
//! - `default = ["dev-rpc"]`: std + subxt over jsonrpsee. Used by
//!   integration tests against a chopsticks fork.
//! - `--no-default-features`: `no_std + alloc`. Types, decoders and
//!   verifier only; no client available.
//! - `--no-default-features --features smoldot`: std + subxt's smoldot
//!   light client. Used by the Phase 1.c PWA and the live-Paseo smoke test.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "client")]
pub mod client;
pub mod decode;
pub mod h160;
pub mod state;
pub mod types;
pub mod verify;

pub use crate::h160::h160_of;
pub use crate::state::{BlockHash, BlockRef, Event, OrgState, SubscribedEvent};
pub use crate::types::{Epoch, OnChainRootHash, OrgAdmin, OrgPubKey};

#[cfg(feature = "client")]
pub use crate::client::{ClientError, OrgRegistryClient, SubscribedEventStream};
