//! Runtime-version-gated storage and event decoders. Each pinned Paseo AH
//! runtime version gets its own submodule (e.g. `v_paseo_ah`),
//! exhaustively fixture-tested against bytes constructed from a known
//! input shape. A `Decoder` trait + `dispatch::for_runtime` picks the
//! right impl at runtime based on the version reported by
//! `Rpc::runtime_version`.
//!
//! Risk #1 in the design doc (pallet-revive is pre-stable, both as a
//! pallet and a storage/event shape) is the reason these are
//! version-gated rather than written against a single assumed layout.
//!
//! Storage and event input shapes:
//!
//! - **Storage:** the caller (`OrgRegistryClient::get_org_state` in
//!   Task 5) issues three `chainHead_v1_storage` reads against the
//!   contract's slots `S`, `S+1`, `S+2` where
//!   `S = keccak256(abi.encode(uint256(admin), uint256(0)))`. The three
//!   32-byte slot values are concatenated and handed to
//!   `Decoder::decode_org_state` as one 96-byte blob.
//! - **Events:** the input is the SCALE-encoded payload of a
//!   `pallet_revive::Event::ContractEmitted { contract, data, topics }`
//!   variant — i.e. the bytes *after* the outer `RuntimeEvent` variant
//!   discriminant has been peeled off. `Decoder::parse_revive_event`
//!   returns `Ok(None)` for events from other contracts (mismatched
//!   topics[0]); this is normal because the follow subscription delivers
//!   every contract's events on one stream.

use alloc::string::String;
use core::fmt;

use crate::state::{Event, OrgState};

pub mod dispatch;
pub mod v_paseo_ah;

/// Trait implemented by each runtime-version-specific decoder. Each impl
/// is a unit struct with no state — chosen so `dispatch::for_runtime` can
/// hand out `&'static dyn Decoder` references without lifetime gymnastics.
pub trait Decoder: Send + Sync {
    /// Decode 96 concatenated bytes (3 × 32-byte EVM slots) into an
    /// `OrgState`. Errors if the input is the wrong length or the epoch
    /// slot has a non-zero high half (which would mean the on-chain
    /// counter exceeds `u64::MAX` — not reachable in practice and a sign
    /// of corruption if observed).
    fn decode_org_state(&self, bytes: &[u8]) -> Result<OrgState, DecodeError>;

    /// Parse the SCALE-encoded payload of `pallet_revive::Event::
    /// ContractEmitted` (`contract: H160, data: Vec<u8>, topics:
    /// Vec<H256>`) into a typed `Event`. Returns `Ok(None)` for events
    /// from other contracts (signature mismatch on `topics[0]`).
    fn parse_revive_event(&self, event_bytes: &[u8]) -> Result<Option<Event>, DecodeError>;
}

/// Errors returned by `Decoder` methods. Variants are deliberately narrow:
/// every decode failure is either a length mismatch, a SCALE-codec error,
/// or a value outside the contract's invariants (e.g. epoch overflow).
#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// `dispatch::for_runtime` was called with a `spec_version` for which
    /// no decoder is compiled in. Caller should refuse to operate until a
    /// matching decoder is added.
    UnsupportedRuntime { spec_version: u32 },
    /// Storage blob was not 96 bytes. Caller should re-read all three
    /// slots — partial reads should never reach here.
    StorageLengthMismatch { expected: usize, actual: usize },
    /// The high 24 bytes of the EVM epoch slot were non-zero, meaning the
    /// counter would not fit in `u64`. Per the contract, monotonic +1
    /// increments make this unreachable; observing it implies corruption
    /// or a contract bug.
    EpochOverflow,
    /// SCALE decoding of the event payload failed.
    Scale(String),
    /// Event payload was well-formed SCALE but didn't have the expected
    /// number of topics for the matched event signature.
    InvalidTopicCount {
        event: &'static str,
        expected: usize,
        actual: usize,
    },
    /// Event payload was well-formed SCALE but `data` length didn't match
    /// the ABI-encoded length for the matched event signature.
    InvalidDataLength {
        event: &'static str,
        expected: usize,
        actual: usize,
    },
    /// An indexed `address` topic had non-zero bytes in its 12-byte
    /// left-padding region (Solidity always zero-pads). Almost certainly
    /// a malformed event from a non-Solidity caller.
    InvalidAddressTopic,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedRuntime { spec_version } => {
                write!(f, "no decoder for runtime spec_version {spec_version}")
            }
            Self::StorageLengthMismatch { expected, actual } => write!(
                f,
                "storage blob length {actual} != expected {expected}"
            ),
            Self::EpochOverflow => write!(f, "epoch slot exceeds u64::MAX"),
            Self::Scale(msg) => write!(f, "scale decode error: {msg}"),
            Self::InvalidTopicCount { event, expected, actual } => write!(
                f,
                "{event} event had {actual} topics, expected {expected}"
            ),
            Self::InvalidDataLength { event, expected, actual } => write!(
                f,
                "{event} event data was {actual} bytes, expected {expected}"
            ),
            Self::InvalidAddressTopic => {
                write!(f, "address topic had non-zero padding bytes")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {}
