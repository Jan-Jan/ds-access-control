//! Regenerate the committed fuzz corpus seed files for the two raw-byte
//! targets. `#[ignore]`d so it never runs in the default suite (it writes into
//! the source tree); run it explicitly when the contract ABI changes:
//!
//!     cargo test --test regenerate_corpus -- --ignored
//!
//! Seeds are structurally-valid (and a few deliberately-invalid) decoder
//! inputs, so the fuzzer starts from real shapes and mutates outward. The
//! filenames are descriptive; bolero reads every file in a target's `corpus/`
//! dir regardless of name.

use std::fs;
use std::path::Path;

#[path = "fuzz_support/mod.rs"]
mod support;

use support::{encode_contract_emitted, padded_address, sig_genesis, sig_root_updated, uint256_be};

const CONTRACT: [u8; 20] = [0x55; 20];
const ADMIN: [u8; 20] = [0x11; 20];
const ROOT: [u8; 32] = [0xaa; 32];
const KEY: [u8; 32] = [0xbb; 32];
const PREV_ROOT: [u8; 32] = [0xcc; 32];

fn write_seed(dir: &str, name: &str, bytes: &[u8]) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(dir);
    fs::create_dir_all(&path).expect("create corpus dir");
    fs::write(path.join(name), bytes).expect("write seed file");
}

#[test]
#[ignore = "writes seed files into the source tree; run with --ignored"]
fn regenerate_parse_revive_event_corpus() {
    let dir = "tests/fuzz_parse_revive_event/corpus";

    // Valid GenesisInitialized payload.
    let mut g_data = Vec::new();
    g_data.extend_from_slice(&ROOT);
    g_data.extend_from_slice(&KEY);
    write_seed(
        dir,
        "valid_genesis",
        &encode_contract_emitted(CONTRACT, g_data, vec![sig_genesis(), padded_address(ADMIN)]),
    );

    // Valid RootUpdated payload.
    let mut u_data = Vec::new();
    u_data.extend_from_slice(&ROOT);
    u_data.extend_from_slice(&KEY);
    u_data.extend_from_slice(&PREV_ROOT);
    write_seed(
        dir,
        "valid_root_updated",
        &encode_contract_emitted(
            CONTRACT,
            u_data,
            vec![sig_root_updated(), padded_address(ADMIN), uint256_be(42)],
        ),
    );

    // Empty-topics (log0) payload -> decoder returns Ok(None).
    write_seed(
        dir,
        "empty_topics",
        &encode_contract_emitted(CONTRACT, vec![0xde, 0xad], vec![]),
    );

    // Wrong topic count for the genesis signature (missing indexed admin).
    write_seed(
        dir,
        "wrong_topic_count",
        &encode_contract_emitted(CONTRACT, vec![0u8; 64], vec![sig_genesis()]),
    );

    // Bad address-topic padding (non-zero byte in the 12-byte pad region).
    let mut bad_topic = padded_address(ADMIN);
    bad_topic[5] = 0xff;
    write_seed(
        dir,
        "bad_address_padding",
        &encode_contract_emitted(CONTRACT, vec![0u8; 64], vec![sig_genesis(), bad_topic]),
    );

    // Valid genesis payload with one trailing byte.
    let mut g_data2 = Vec::new();
    g_data2.extend_from_slice(&ROOT);
    g_data2.extend_from_slice(&KEY);
    let mut trailing =
        encode_contract_emitted(CONTRACT, g_data2, vec![sig_genesis(), padded_address(ADMIN)]);
    trailing.push(0xde);
    write_seed(dir, "trailing_byte", &trailing);
}

#[test]
#[ignore = "writes seed files into the source tree; run with --ignored"]
fn regenerate_decode_org_state_corpus() {
    let dir = "tests/fuzz_decode_org_state/corpus";

    // Valid 96-byte blob, epoch = 7.
    let mut valid = [0u8; 96];
    valid[..32].fill(0xaa);
    valid[32..64].fill(0xbb);
    valid[95] = 7;
    write_seed(dir, "valid_epoch_7", &valid);

    // Valid blob with epoch = u64::MAX (boundary).
    let mut max_epoch = [0u8; 96];
    max_epoch[88..96].copy_from_slice(&u64::MAX.to_be_bytes());
    write_seed(dir, "epoch_u64_max", &max_epoch);

    // Epoch-overflow blob (non-zero byte in the high 24 of the epoch slot).
    let mut overflow = [0u8; 96];
    overflow[64] = 0x01;
    write_seed(dir, "epoch_overflow", &overflow);

    // Wrong length (95 bytes) -> StorageLengthMismatch.
    write_seed(dir, "wrong_length_95", &[0u8; 95]);
}
