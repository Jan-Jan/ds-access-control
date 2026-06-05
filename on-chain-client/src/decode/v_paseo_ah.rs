//! Decoder for a single pinned Paseo AH runtime version. Reachable via
//! `dispatch::for_runtime` when `spec_version == SPEC_VERSION`.
//!
//! Layouts decoded:
//!
//! - **`decode_org_state`** — takes 96 concatenated bytes (3 × 32-byte EVM
//!   storage slots: `rootHash` || `orgPubKey` || `epoch` big-endian).
//!   The first two slots are copied wholesale; the epoch slot is decoded
//!   as a `uint256` whose high 24 bytes must be zero (a +1-per-update
//!   counter never reaches `u64::MAX`, so a non-zero high half is treated
//!   as `DecodeError::EpochOverflow`).
//! - **`parse_revive_event`** — takes the SCALE-encoded payload of
//!   `pallet_revive::Event::ContractEmitted { contract, data, topics }`.
//!   `topics[0]` is the EVM event signature hash; mismatched signatures
//!   yield `Ok(None)` because the follow stream carries every contract's
//!   events. Decoded events return `Event::Genesis` or `Event::Update`
//!   with all indexed and non-indexed fields recovered.

use alloc::format;
use alloc::vec::Vec;

use parity_scale_codec::Decode;

use super::{DecodeError, Decoder};
use crate::state::{Event, OrgState};
use crate::types::{Epoch, OnChainRootHash, OrgAdmin, OrgPubKey};

/// Paseo AH runtime spec_version this decoder targets. Captured from a
/// chopsticks fork in Task 6 (`state_getRuntimeVersion` reported
/// `specName: "asset-hub-paseo"`, `specVersion: 2002002`). Task 10 may
/// widen `dispatch::for_runtime` to accept a known-good range once we've
/// run against several upstream versions.
pub const SPEC_VERSION: u32 = 2_002_002;

/// `keccak256("GenesisInitialized(address,bytes32,bytes32)")`.
/// Re-derived in `tests::event_signatures_match_solidity_abi` to lock the
/// const against ABI drift.
pub(super) const SIG_GENESIS_INITIALIZED: [u8; 32] = [
    0x8e, 0x65, 0xbf, 0x09, 0x54, 0x40, 0x39, 0x7e, 0x54, 0x61, 0x39, 0x32, 0xb7, 0x54, 0x91, 0x7e,
    0x45, 0x22, 0xdd, 0xb0, 0x8a, 0x8e, 0x63, 0x8b, 0xcb, 0x8d, 0xee, 0x69, 0xfe, 0x68, 0x5b, 0x6d,
];

/// `keccak256("RootUpdated(address,uint256,bytes32,bytes32,bytes32)")`.
pub(super) const SIG_ROOT_UPDATED: [u8; 32] = [
    0x24, 0x79, 0x88, 0xcb, 0x06, 0x65, 0x74, 0x6b, 0xde, 0x9b, 0xe0, 0xb7, 0x06, 0x8f, 0x5d, 0x04,
    0x96, 0xe8, 0xe7, 0x5d, 0x1a, 0x4b, 0x26, 0x92, 0xb1, 0x98, 0xf6, 0x77, 0x89, 0xee, 0x5b, 0x6e,
];

pub(super) struct DecoderImpl;

/// Static instance handed out by `dispatch::for_runtime`. Zero-sized so a
/// `&'static dyn Decoder` reference costs nothing.
pub(super) static DECODER: DecoderImpl = DecoderImpl;

impl Decoder for DecoderImpl {
    fn decode_org_state(&self, bytes: &[u8]) -> Result<OrgState, DecodeError> {
        if bytes.len() != 96 {
            return Err(DecodeError::StorageLengthMismatch {
                expected: 96,
                actual: bytes.len(),
            });
        }
        let mut root_hash = [0u8; 32];
        root_hash.copy_from_slice(&bytes[0..32]);
        let mut org_pub_key = [0u8; 32];
        org_pub_key.copy_from_slice(&bytes[32..64]);
        let epoch = decode_uint256_to_u64(&bytes[64..96])?;
        Ok(OrgState {
            root_hash: OnChainRootHash(root_hash),
            org_pub_key: OrgPubKey(org_pub_key),
            epoch: Epoch(epoch),
        })
    }

    fn parse_revive_event(&self, mut bytes: &[u8]) -> Result<Option<Event>, DecodeError> {
        // pallet_revive::Event::ContractEmitted {
        //     contract: H160,     // 20 raw bytes
        //     data: Vec<u8>,      // compact_len(data) || data
        //     topics: Vec<H256>,  // compact_len(topics) || topics[0..N]
        // }
        let _contract: [u8; 20] = Decode::decode(&mut bytes)
            .map_err(|e| DecodeError::Scale(format!("contract: {e}")))?;
        let data: Vec<u8> =
            Decode::decode(&mut bytes).map_err(|e| DecodeError::Scale(format!("data: {e}")))?;
        let topics: Vec<[u8; 32]> = Decode::decode(&mut bytes)
            .map_err(|e| DecodeError::Scale(format!("topics: {e}")))?;
        if !bytes.is_empty() {
            return Err(DecodeError::Scale(format!(
                "trailing {} bytes after ContractEmitted payload",
                bytes.len()
            )));
        }

        let Some(sig) = topics.first() else {
            return Ok(None);
        };
        match *sig {
            SIG_GENESIS_INITIALIZED => parse_genesis(&data, &topics).map(Some),
            SIG_ROOT_UPDATED => parse_root_updated(&data, &topics).map(Some),
            _ => Ok(None),
        }
    }
}

fn decode_uint256_to_u64(bytes: &[u8]) -> Result<u64, DecodeError> {
    // Solidity uint256 is big-endian. The high 24 bytes must be zero for
    // the counter to fit in u64; the contract increments by 1 per update
    // so this is always the case in practice.
    debug_assert_eq!(bytes.len(), 32);
    if bytes[..24].iter().any(|b| *b != 0) {
        return Err(DecodeError::EpochOverflow);
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[24..32]);
    Ok(u64::from_be_bytes(buf))
}

fn parse_genesis(data: &[u8], topics: &[[u8; 32]]) -> Result<Event, DecodeError> {
    if topics.len() != 2 {
        return Err(DecodeError::InvalidTopicCount {
            event: "GenesisInitialized",
            expected: 2,
            actual: topics.len(),
        });
    }
    if data.len() != 64 {
        return Err(DecodeError::InvalidDataLength {
            event: "GenesisInitialized",
            expected: 64,
            actual: data.len(),
        });
    }
    let admin = unpack_address_topic(&topics[1])?;
    let mut root_hash = [0u8; 32];
    root_hash.copy_from_slice(&data[0..32]);
    let mut org_pub_key = [0u8; 32];
    org_pub_key.copy_from_slice(&data[32..64]);
    Ok(Event::Genesis {
        admin: OrgAdmin(admin),
        root_hash: OnChainRootHash(root_hash),
        org_pub_key: OrgPubKey(org_pub_key),
    })
}

fn parse_root_updated(data: &[u8], topics: &[[u8; 32]]) -> Result<Event, DecodeError> {
    if topics.len() != 3 {
        return Err(DecodeError::InvalidTopicCount {
            event: "RootUpdated",
            expected: 3,
            actual: topics.len(),
        });
    }
    if data.len() != 96 {
        return Err(DecodeError::InvalidDataLength {
            event: "RootUpdated",
            expected: 96,
            actual: data.len(),
        });
    }
    let admin = unpack_address_topic(&topics[1])?;
    let epoch = decode_uint256_to_u64(&topics[2])?;
    let mut root_hash = [0u8; 32];
    root_hash.copy_from_slice(&data[0..32]);
    let mut org_pub_key = [0u8; 32];
    org_pub_key.copy_from_slice(&data[32..64]);
    let mut prev_root_hash = [0u8; 32];
    prev_root_hash.copy_from_slice(&data[64..96]);
    Ok(Event::Update {
        admin: OrgAdmin(admin),
        epoch: Epoch(epoch),
        root_hash: OnChainRootHash(root_hash),
        org_pub_key: OrgPubKey(org_pub_key),
        prev_root_hash: OnChainRootHash(prev_root_hash),
    })
}

fn unpack_address_topic(topic: &[u8; 32]) -> Result<[u8; 20], DecodeError> {
    if topic[..12].iter().any(|b| *b != 0) {
        return Err(DecodeError::InvalidAddressTopic);
    }
    let mut admin = [0u8; 20];
    admin.copy_from_slice(&topic[12..32]);
    Ok(admin)
}

#[cfg(test)]
mod tests {
    use super::*;

    use parity_scale_codec::Encode;
    use tiny_keccak::{Hasher, Keccak};

    /// Lock the hardcoded signature consts against ABI drift: rederive
    /// them from the Solidity event canonical signature strings and check
    /// equality. If anyone renames or reorders a parameter in the
    /// contract, this fails before any decoder logic gets a chance to
    /// silently mismatch real events.
    #[test]
    fn event_signatures_match_solidity_abi() {
        fn keccak(s: &str) -> [u8; 32] {
            let mut h = Keccak::v256();
            h.update(s.as_bytes());
            let mut out = [0u8; 32];
            h.finalize(&mut out);
            out
        }
        assert_eq!(
            keccak("GenesisInitialized(address,bytes32,bytes32)"),
            SIG_GENESIS_INITIALIZED,
        );
        assert_eq!(
            keccak("RootUpdated(address,uint256,bytes32,bytes32,bytes32)"),
            SIG_ROOT_UPDATED,
        );
    }

    // ----- storage decoder -----

    #[test]
    fn decode_org_state_round_trip() {
        let mut blob = [0u8; 96];
        blob[..32].fill(0xaa);
        blob[32..64].fill(0xbb);
        // uint256 big-endian: value 7 in the low byte.
        blob[95] = 7;

        let state = DECODER.decode_org_state(&blob).expect("decode");
        assert_eq!(state.root_hash, OnChainRootHash([0xaa; 32]));
        assert_eq!(state.org_pub_key, OrgPubKey([0xbb; 32]));
        assert_eq!(state.epoch, Epoch(7));
    }

    #[test]
    fn decode_org_state_max_u64_epoch_ok() {
        let mut blob = [0u8; 96];
        blob[88..96].copy_from_slice(&u64::MAX.to_be_bytes());
        let state = DECODER.decode_org_state(&blob).expect("decode");
        assert_eq!(state.epoch, Epoch(u64::MAX));
    }

    #[test]
    fn decode_org_state_epoch_overflow_rejected() {
        let mut blob = [0u8; 96];
        // Set a byte in the high 24 of the epoch slot.
        blob[64] = 0x01;
        assert_eq!(
            DECODER.decode_org_state(&blob),
            Err(DecodeError::EpochOverflow),
        );
    }

    #[test]
    fn decode_org_state_wrong_length_rejected() {
        let blob = [0u8; 95];
        assert_eq!(
            DECODER.decode_org_state(&blob),
            Err(DecodeError::StorageLengthMismatch {
                expected: 96,
                actual: 95,
            }),
        );
    }

    // ----- event decoder -----

    /// Build a synthetic `ContractEmitted` SCALE payload mirroring what
    /// pallet-revive emits for a real EVM log. Replaces real on-chain
    /// capture for the Task 4 gate; Task 6's `capture-fixtures` bin will
    /// drop in chopsticks-captured `.bin` files alongside these to verify
    /// no drift.
    fn build_contract_emitted(
        contract: [u8; 20],
        data: Vec<u8>,
        topics: Vec<[u8; 32]>,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        contract.encode_to(&mut buf);
        data.encode_to(&mut buf);
        topics.encode_to(&mut buf);
        buf
    }

    fn padded_address(addr: [u8; 20]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[12..32].copy_from_slice(&addr);
        out
    }

    fn uint256_be(n: u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[24..32].copy_from_slice(&n.to_be_bytes());
        out
    }

    #[test]
    fn parse_genesis_event_round_trip() {
        let admin = [0x11u8; 20];
        let contract = [0x55u8; 20];
        let root_hash = [0xaau8; 32];
        let org_pub_key = [0xbbu8; 32];

        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&root_hash);
        data.extend_from_slice(&org_pub_key);

        let topics = alloc::vec![SIG_GENESIS_INITIALIZED, padded_address(admin)];

        let bytes = build_contract_emitted(contract, data, topics);
        let parsed = DECODER.parse_revive_event(&bytes).expect("decode");
        assert_eq!(
            parsed,
            Some(Event::Genesis {
                admin: OrgAdmin(admin),
                root_hash: OnChainRootHash(root_hash),
                org_pub_key: OrgPubKey(org_pub_key),
            }),
        );
    }

    #[test]
    fn parse_root_updated_event_round_trip() {
        let admin = [0x22u8; 20];
        let contract = [0x55u8; 20];
        let root_hash = [0xccu8; 32];
        let org_pub_key = [0xddu8; 32];
        let prev_root_hash = [0xeeu8; 32];

        let mut data = Vec::with_capacity(96);
        data.extend_from_slice(&root_hash);
        data.extend_from_slice(&org_pub_key);
        data.extend_from_slice(&prev_root_hash);

        let topics = alloc::vec![
            SIG_ROOT_UPDATED,
            padded_address(admin),
            uint256_be(42),
        ];

        let bytes = build_contract_emitted(contract, data, topics);
        let parsed = DECODER.parse_revive_event(&bytes).expect("decode");
        assert_eq!(
            parsed,
            Some(Event::Update {
                admin: OrgAdmin(admin),
                epoch: Epoch(42),
                root_hash: OnChainRootHash(root_hash),
                org_pub_key: OrgPubKey(org_pub_key),
                prev_root_hash: OnChainRootHash(prev_root_hash),
            }),
        );
    }

    #[test]
    fn parse_event_from_other_contract_returns_none() {
        // Same OrgRegistry contract address, but topics[0] doesn't match
        // any signature we know — could be e.g. a different contract
        // deployed at a similar slot, or a future event we haven't taught
        // the decoder. Decoder returns Ok(None), caller skips it.
        let contract = [0x55u8; 20];
        let bogus_sig = [0xffu8; 32];
        let topics = alloc::vec![bogus_sig];
        let bytes = build_contract_emitted(contract, Vec::new(), topics);
        assert_eq!(DECODER.parse_revive_event(&bytes), Ok(None));
    }

    #[test]
    fn parse_event_empty_topics_returns_none() {
        // pallet-revive can emit `ContractEmitted` with empty topics if a
        // contract calls `log0(data)` (no topics, only data). Decoder
        // skips these — no event signature to match against.
        let contract = [0x55u8; 20];
        let bytes = build_contract_emitted(contract, alloc::vec![0xde, 0xad], Vec::new());
        assert_eq!(DECODER.parse_revive_event(&bytes), Ok(None));
    }

    #[test]
    fn parse_genesis_wrong_topic_count_rejected() {
        let contract = [0x55u8; 20];
        // Only topics[0] — missing the indexed admin.
        let topics = alloc::vec![SIG_GENESIS_INITIALIZED];
        let bytes = build_contract_emitted(contract, alloc::vec![0u8; 64], topics);
        assert_eq!(
            DECODER.parse_revive_event(&bytes),
            Err(DecodeError::InvalidTopicCount {
                event: "GenesisInitialized",
                expected: 2,
                actual: 1,
            }),
        );
    }

    #[test]
    fn parse_genesis_wrong_data_length_rejected() {
        let contract = [0x55u8; 20];
        let admin = [0x11u8; 20];
        let topics = alloc::vec![SIG_GENESIS_INITIALIZED, padded_address(admin)];
        // 32 bytes instead of 64.
        let bytes = build_contract_emitted(contract, alloc::vec![0u8; 32], topics);
        assert_eq!(
            DECODER.parse_revive_event(&bytes),
            Err(DecodeError::InvalidDataLength {
                event: "GenesisInitialized",
                expected: 64,
                actual: 32,
            }),
        );
    }

    #[test]
    fn parse_event_with_corrupted_address_topic_rejected() {
        // Topic[1] has a non-zero byte inside the 12-byte padding region.
        let contract = [0x55u8; 20];
        let mut topic1 = [0u8; 32];
        topic1[5] = 0xff;
        topic1[12..32].fill(0x11);
        let topics = alloc::vec![SIG_GENESIS_INITIALIZED, topic1];
        let bytes = build_contract_emitted(contract, alloc::vec![0u8; 64], topics);
        assert_eq!(
            DECODER.parse_revive_event(&bytes),
            Err(DecodeError::InvalidAddressTopic),
        );
    }

    #[test]
    fn parse_event_trailing_bytes_rejected() {
        let contract = [0x55u8; 20];
        let topics = alloc::vec![SIG_GENESIS_INITIALIZED, padded_address([0x11u8; 20])];
        let mut bytes = build_contract_emitted(contract, alloc::vec![0u8; 64], topics);
        bytes.push(0xde); // extra byte after the valid payload
        assert!(matches!(
            DECODER.parse_revive_event(&bytes),
            Err(DecodeError::Scale(_)),
        ));
    }
}
