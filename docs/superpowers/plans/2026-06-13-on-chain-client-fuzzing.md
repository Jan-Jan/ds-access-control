# on-chain-client Decoder Fuzzing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add bolero-based fuzz testing to `on-chain-client`'s untrusted-byte decoders so "never panic on arbitrary chain bytes" and "decoder is the exact inverse of the on-chain encoding" become continuously-checked invariants.

**Architecture:** Three bolero targets, each a `harness = false` test binary in its own directory (`tests/<target>/fuzz_target.rs`) with sibling `corpus/`+`crashes/` dirs. Two targets feed arbitrary `&[u8]` to the public decoder path (`decode::dispatch::for_runtime`) and assert no panic; the third generates structurally-valid events via a derived `bolero::TypeGenerator`, encodes them to a canonical `ContractEmitted` SCALE payload, decodes them back, and asserts equality. A bare `cargo test` runs all three on stable Rust (corpus replay + bounded generated inputs); `cargo bolero` escalates to libFuzzer on nightly.

**Tech Stack:** Rust 2024, `bolero = "0.13"`, `parity-scale-codec` + `tiny-keccak` (dev-side), the existing `on-chain-client` decoder API.

**Spec:** `docs/superpowers/specs/2026-06-13-on-chain-client-fuzzing-design.md`

---

## File Structure

```
on-chain-client/
  Cargo.toml                                   # MODIFY: +3 dev-deps, +3 [[test]] entries
  README.md                                    # MODIFY: +Fuzzing section
  tests/
    fuzz_parse_revive_event/
      fuzz_target.rs                           # CREATE: raw-bytes never-panic target
      corpus/                                  # CREATE: 6 committed seed files
      crashes/.gitkeep                         # CREATE
    fuzz_decode_org_state/
      fuzz_target.rs                           # CREATE: raw-bytes never-panic target
      corpus/                                  # CREATE: 4 committed seed files
      crashes/.gitkeep                         # CREATE
    fuzz_event_round_trip/
      fuzz_target.rs                           # CREATE: structured inverse-property target
      corpus/.gitkeep                          # CREATE
      crashes/.gitkeep                         # CREATE
    fuzz_support/mod.rs                        # CREATE: shared encoder + sig derivation (via #[path])
    regenerate_corpus.rs                       # CREATE: #[ignore]d seed-file generator
```

**Cargo target-discovery rules that shape this layout:**
- Files **directly under `tests/`** are auto-discovered as integration-test
  targets. `regenerate_corpus.rs` is one such file: it gets the default libtest
  harness automatically, so it needs **no** `[[test]]` entry.
- Files in **subdirectories of `tests/`** are *not* auto-discovered. That is why
  the three fuzz targets (in their own dirs) each need an explicit `[[test]]`
  entry, and why the shared helper lives at `tests/fuzz_support/mod.rs` — a
  subdir, so it is never compiled as a phantom zero-test target. It is pulled
  into the round-trip target and the regenerator via
  `#[path = ".../fuzz_support/mod.rs"] mod support;` (the same shared-module
  pattern the repo already uses for `tests/common/`). The two raw-byte targets
  don't use it.

---

## Task 1: Add bolero scaffolding — one trivial target, green under `cargo test`

Establishes the dev-deps, the `[[test]]` wiring, and the `harness = false` + `bolero::check!` mechanics with the simplest possible target before adding real logic.

**Files:**
- Modify: `on-chain-client/Cargo.toml` (`[dev-dependencies]` and new `[[test]]`)
- Create: `on-chain-client/tests/fuzz_decode_org_state/fuzz_target.rs`
- Create: `on-chain-client/tests/fuzz_decode_org_state/crashes/.gitkeep`

- [ ] **Step 1: Add dev-dependencies to `Cargo.toml`**

In `on-chain-client/Cargo.toml`, add to the existing `[dev-dependencies]` section (after the `libc` line):

```toml
# Fuzzing: bolero runs targets on stable via `cargo test` (corpus replay +
# bounded generated inputs) and drives libFuzzer/AFL under `cargo-bolero` on
# nightly. parity-scale-codec / tiny-keccak are already library deps but
# integration-test crates can't see the library's normal deps, so they're
# re-declared dev-side for the round-trip target + corpus regenerator.
bolero = "0.13"
parity-scale-codec = { version = "3", default-features = false, features = ["derive"] }
tiny-keccak = { version = "2", default-features = false, features = ["keccak"] }
```

- [ ] **Step 2: Add the first `[[test]]` entry to `Cargo.toml`**

Append to the end of `on-chain-client/Cargo.toml`:

```toml
[[test]]
name = "fuzz_decode_org_state"
path = "tests/fuzz_decode_org_state/fuzz_target.rs"
harness = false
```

- [ ] **Step 3: Write the target binary**

Create `on-chain-client/tests/fuzz_decode_org_state/fuzz_target.rs`:

```rust
//! Fuzz target: `Decoder::decode_org_state` must never panic on arbitrary
//! bytes. Reaches the decoder through the public `for_runtime` path — the
//! exact surface `OrgRegistryClient::get_org_state` uses.
//!
//! `harness = false` binary: a panic (the bolero failure signal) exits
//! non-zero and fails `cargo test`. Run a single target with
//! `cargo test --test fuzz_decode_org_state`; deep-fuzz with
//! `cargo bolero test fuzz_decode_org_state --engine libfuzzer`.

use bolero::check;
// `Decoder` must be in scope: `decode_org_state` is a trait method, callable
// only when the trait is imported — even through the `&dyn Decoder` returned
// by `for_runtime`.
use on_chain_client::decode::Decoder;
use on_chain_client::decode::dispatch::{PASEO_AH_SPEC_VERSION, for_runtime};

fn main() {
    let decoder = for_runtime(PASEO_AH_SPEC_VERSION)
        .expect("pinned Paseo AH decoder must resolve");
    check!().for_each(|input: &[u8]| {
        // Property: any byte slice yields Ok/Err, never a panic/abort.
        let _ = decoder.decode_org_state(input);
    });
}
```

- [ ] **Step 4: Create the crashes dir placeholder**

```bash
mkdir -p on-chain-client/tests/fuzz_decode_org_state/crashes
touch on-chain-client/tests/fuzz_decode_org_state/crashes/.gitkeep
```

- [ ] **Step 5: Run the target to verify it builds and passes**

Run: `cd on-chain-client && cargo test --test fuzz_decode_org_state`
Expected: builds, runs bolero in test mode, exits 0. Output includes a bolero
summary line (e.g. `running test ... ` then generated-input iterations). No
panic.

- [ ] **Step 6: Verify the existing suite + lib clippy gate still pass**

Run: `cd on-chain-client && cargo build --all-features && cargo clippy --all-features --lib -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic`
Expected: both succeed. (The `.expect()` in the target is in a test binary, not
`--lib`, so the gate does not see it.)

- [ ] **Step 7: Commit**

```bash
cd "$(git rev-parse --show-toplevel)"
git add on-chain-client/Cargo.toml on-chain-client/tests/fuzz_decode_org_state/
git commit -m "test(fuzz): bolero scaffolding + decode_org_state never-panic target"
```

---

## Task 2: Add the `parse_revive_event` never-panic target

The highest-value target — `parse_revive_event` SCALE-decodes two unbounded `Vec`s from arbitrary bytes.

**Files:**
- Modify: `on-chain-client/Cargo.toml` (new `[[test]]`)
- Create: `on-chain-client/tests/fuzz_parse_revive_event/fuzz_target.rs`
- Create: `on-chain-client/tests/fuzz_parse_revive_event/crashes/.gitkeep`

- [ ] **Step 1: Add the `[[test]]` entry to `Cargo.toml`**

Append to `on-chain-client/Cargo.toml`:

```toml
[[test]]
name = "fuzz_parse_revive_event"
path = "tests/fuzz_parse_revive_event/fuzz_target.rs"
harness = false
```

- [ ] **Step 2: Write the target binary**

Create `on-chain-client/tests/fuzz_parse_revive_event/fuzz_target.rs`:

```rust
//! Fuzz target: `Decoder::parse_revive_event` must never panic on arbitrary
//! bytes. The input models the SCALE payload of
//! `pallet_revive::Event::ContractEmitted { contract, data, topics }` — but
//! the point of fuzzing is that we feed *arbitrary* bytes, including
//! truncated / oversized / adversarial length prefixes, and require a clean
//! Ok/Err rather than a panic, abort, or runaway allocation.
//!
//! `harness = false` binary. Run with
//! `cargo test --test fuzz_parse_revive_event`; deep-fuzz with
//! `cargo bolero test fuzz_parse_revive_event --engine libfuzzer`.

use std::panic::AssertUnwindSafe;

use bolero::check;
use on_chain_client::decode::dispatch::{PASEO_AH_SPEC_VERSION, for_runtime};

fn main() {
    let decoder = for_runtime(PASEO_AH_SPEC_VERSION)
        .expect("pinned Paseo AH decoder must resolve");
    // bolero wraps each iteration in `catch_unwind`, which needs the closure's
    // captures to be `RefUnwindSafe`. `&dyn Decoder` is not, but every impl is
    // a stateless unit struct, so an unwind can't leave it inconsistent —
    // assert it. Deref the wrapper inside the closure (not its `.0` field) so
    // the closure captures the `AssertUnwindSafe` wrapper itself.
    // (`parse_revive_event` needs no `use Decoder`: the receiver is the
    // `dyn Decoder` trait object, which already names the trait.)
    let decoder = AssertUnwindSafe(decoder);
    check!().for_each(move |input: &[u8]| {
        let _ = (*decoder).parse_revive_event(input);
    });
}
```

- [ ] **Step 3: Create the crashes dir placeholder**

```bash
mkdir -p on-chain-client/tests/fuzz_parse_revive_event/crashes
touch on-chain-client/tests/fuzz_parse_revive_event/crashes/.gitkeep
```

- [ ] **Step 4: Run the target**

Run: `cd on-chain-client && cargo test --test fuzz_parse_revive_event`
Expected: builds, runs, exits 0, no panic.

- [ ] **Step 5: Commit**

```bash
cd "$(git rev-parse --show-toplevel)"
git add on-chain-client/Cargo.toml on-chain-client/tests/fuzz_parse_revive_event/
git commit -m "test(fuzz): parse_revive_event never-panic target"
```

---

## Task 3: Shared support module — canonical encoder + signature derivation

The round-trip target and the corpus regenerator both need to (a) derive the two event-signature topic hashes and (b) encode a `ContractEmitted` payload exactly as pallet-revive would. Put that in one shared, non-target module file.

**Files:**
- Create: `on-chain-client/tests/fuzz_support/mod.rs`

- [ ] **Step 1: Write the support module**

Create `on-chain-client/tests/fuzz_support/mod.rs`:

```rust
//! Shared helpers for the structured fuzz target (`fuzz_event_round_trip`)
//! and the corpus regenerator. Pulled in with
//! `#[path = ".../fuzz_support/mod.rs"] mod support;`. It lives in a
//! subdirectory so cargo does NOT auto-discover it as a (zero-test) target.
//!
//! Two pieces:
//!   * `sig_genesis()` / `sig_root_updated()` — the EVM event-signature topic
//!     hashes, derived from their canonical Solidity signature strings rather
//!     than copied from the decoder's `pub(super)` constants. Independent
//!     derivation = a drift guard (matches the lib's internal
//!     `event_signatures_match_solidity_abi` test).
//!   * `encode_contract_emitted` — the canonical SCALE encoding of
//!     `pallet_revive::Event::ContractEmitted { contract, data, topics }`,
//!     mirroring the contract ABI. Independent of the decoder, so a round trip
//!     through it is a genuine cross-check, not a tautology.
//!
//! Not every item is used by every includer; `#[allow(dead_code)]` keeps the
//! shared module warning-free when a consumer uses only part of it.
#![allow(dead_code)]

use parity_scale_codec::Encode;
use tiny_keccak::{Hasher, Keccak};

fn keccak(s: &str) -> [u8; 32] {
    let mut h = Keccak::v256();
    h.update(s.as_bytes());
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    out
}

pub fn sig_genesis() -> [u8; 32] {
    keccak("GenesisInitialized(address,bytes32,bytes32)")
}

pub fn sig_root_updated() -> [u8; 32] {
    keccak("RootUpdated(address,uint256,bytes32,bytes32,bytes32)")
}

/// Left-pad a 20-byte EVM address into a 32-byte indexed topic (Solidity
/// zero-pads on the left).
pub fn padded_address(addr: [u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..32].copy_from_slice(&addr);
    out
}

/// Encode a `u64` as a big-endian `uint256` topic.
pub fn uint256_be(n: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&n.to_be_bytes());
    out
}

/// Canonical SCALE encoding of `ContractEmitted { contract, data, topics }`:
/// `contract` is 20 raw bytes, then compact-length-prefixed `data`, then
/// compact-length-prefixed `topics`.
pub fn encode_contract_emitted(
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
```

- [ ] **Step 2: Verify it compiles (it has no `[[test]]` entry, so compile it via a consumer in Task 4)**

No standalone build here — `fuzz_support/mod.rs` is only compiled when included
by a target. It is checked for the first time in Task 4 Step 4. Proceed.

- [ ] **Step 3: Commit**

```bash
cd "$(git rev-parse --show-toplevel)"
git add on-chain-client/tests/fuzz_support/
git commit -m "test(fuzz): shared ContractEmitted encoder + signature derivation"
```

---

## Task 4: Add the structured round-trip (inverse-property) target

Generates structurally-valid events, encodes → decodes, asserts equality. Fails if the decoder ever stops inverting the documented encoding.

**Files:**
- Modify: `on-chain-client/Cargo.toml` (new `[[test]]`)
- Create: `on-chain-client/tests/fuzz_event_round_trip/fuzz_target.rs`
- Create: `on-chain-client/tests/fuzz_event_round_trip/corpus/.gitkeep`
- Create: `on-chain-client/tests/fuzz_event_round_trip/crashes/.gitkeep`

- [ ] **Step 1: Add the `[[test]]` entry to `Cargo.toml`**

Append to `on-chain-client/Cargo.toml`:

```toml
[[test]]
name = "fuzz_event_round_trip"
path = "tests/fuzz_event_round_trip/fuzz_target.rs"
harness = false
```

- [ ] **Step 2: Write the target binary**

Create `on-chain-client/tests/fuzz_event_round_trip/fuzz_target.rs`:

```rust
//! Fuzz target (structured / inverse property): for any structurally-valid
//! event, `parse_revive_event(encode(event)) == Some(event)`. bolero's
//! derived `TypeGenerator` produces only well-formed `EventShape`s, so any
//! deviation is a real decoder regression (wrong field order, dropped
//! padding, mis-decoded epoch), not malformed input.
//!
//! `harness = false` binary. Run with
//! `cargo test --test fuzz_event_round_trip`; deep-fuzz with
//! `cargo bolero test fuzz_event_round_trip --engine libfuzzer`.

use std::panic::AssertUnwindSafe;

use bolero::{TypeGenerator, check};
use on_chain_client::decode::dispatch::{PASEO_AH_SPEC_VERSION, for_runtime};
use on_chain_client::{Epoch, Event, OnChainRootHash, OrgAdmin, OrgPubKey};

#[path = "../fuzz_support/mod.rs"]
mod support;

use support::{encode_contract_emitted, padded_address, sig_genesis, sig_root_updated, uint256_be};

/// A structurally-valid event. bolero fills every field with generated bytes;
/// the variants mirror the two Solidity events the decoder understands.
#[derive(Debug, Clone, TypeGenerator)]
enum EventShape {
    Genesis {
        contract: [u8; 20],
        admin: [u8; 20],
        root: [u8; 32],
        key: [u8; 32],
    },
    Update {
        contract: [u8; 20],
        admin: [u8; 20],
        epoch: u64,
        root: [u8; 32],
        key: [u8; 32],
        prev_root: [u8; 32],
    },
}

/// Encode a shape into a canonical `ContractEmitted` payload AND the `Event`
/// the decoder should reconstruct from it.
fn encode_and_expect(shape: &EventShape) -> (Vec<u8>, Event) {
    match *shape {
        EventShape::Genesis { contract, admin, root, key } => {
            let mut data = Vec::with_capacity(64);
            data.extend_from_slice(&root);
            data.extend_from_slice(&key);
            let topics = vec![sig_genesis(), padded_address(admin)];
            let bytes = encode_contract_emitted(contract, data, topics);
            let expected = Event::Genesis {
                admin: OrgAdmin(admin),
                root_hash: OnChainRootHash(root),
                org_pub_key: OrgPubKey(key),
            };
            (bytes, expected)
        }
        EventShape::Update { contract, admin, epoch, root, key, prev_root } => {
            let mut data = Vec::with_capacity(96);
            data.extend_from_slice(&root);
            data.extend_from_slice(&key);
            data.extend_from_slice(&prev_root);
            let topics = vec![sig_root_updated(), padded_address(admin), uint256_be(epoch)];
            let bytes = encode_contract_emitted(contract, data, topics);
            let expected = Event::Update {
                admin: OrgAdmin(admin),
                epoch: Epoch(epoch),
                root_hash: OnChainRootHash(root),
                org_pub_key: OrgPubKey(key),
                prev_root_hash: OnChainRootHash(prev_root),
            };
            (bytes, expected)
        }
    }
}

fn main() {
    let decoder = for_runtime(PASEO_AH_SPEC_VERSION)
        .expect("pinned Paseo AH decoder must resolve");
    // AssertUnwindSafe for bolero's per-iteration catch_unwind (decoders are
    // stateless unit structs); deref inside the closure so the wrapper itself
    // is captured. The `dyn Decoder` receiver makes `use Decoder` unnecessary.
    let decoder = AssertUnwindSafe(decoder);
    check!()
        .with_type::<EventShape>()
        .cloned()
        .for_each(move |shape: EventShape| {
            let (bytes, expected) = encode_and_expect(&shape);
            let decoded = (*decoder)
                .parse_revive_event(&bytes)
                .expect("valid ContractEmitted payload must decode without error");
            assert_eq!(
                decoded,
                Some(expected),
                "decoder must invert the canonical encoding for {shape:?}",
            );
        });
}
```

- [ ] **Step 3: Create the corpus + crashes dir placeholders**

```bash
mkdir -p on-chain-client/tests/fuzz_event_round_trip/corpus on-chain-client/tests/fuzz_event_round_trip/crashes
touch on-chain-client/tests/fuzz_event_round_trip/corpus/.gitkeep on-chain-client/tests/fuzz_event_round_trip/crashes/.gitkeep
```

- [ ] **Step 4: Run the target (this also first-compiles `fuzz_support/mod.rs`)**

Run: `cd on-chain-client && cargo test --test fuzz_event_round_trip`
Expected: builds (compiles `fuzz_support/mod.rs` via the `#[path]` include),
runs, exits 0. Every generated `EventShape` round-trips, no assertion fires.

- [ ] **Step 5: Prove the harness bites (fault injection, not committed)**

Temporarily edit `encode_and_expect` so the Genesis arm swaps `root` and `key`
in `data` (`data.extend_from_slice(&key); data.extend_from_slice(&root);`).

Run: `cd on-chain-client && cargo test --test fuzz_event_round_trip`
Expected: FAILS with the `decoder must invert the canonical encoding` assertion
(or a crash file written under `crashes/`). This confirms the round-trip
actually detects encoder/decoder divergence.

Then **revert** the edit and re-run; expected: PASS. Delete any file bolero
wrote under `crashes/` during the fault-injection run:
`git clean -fd on-chain-client/tests/fuzz_event_round_trip/crashes/` (then
`touch .../crashes/.gitkeep` if it was removed).

- [ ] **Step 6: Commit**

```bash
cd "$(git rev-parse --show-toplevel)"
git add on-chain-client/Cargo.toml on-chain-client/tests/fuzz_event_round_trip/
git commit -m "test(fuzz): structured round-trip inverse-property target"
```

---

## Task 5: Corpus regenerator + committed seed files

A committed `#[ignore]`d test that writes the raw-byte seed files for the two
never-panic targets. Run once to materialise the seeds, then commit them. The
test stays as executable documentation / a rebuild button.

**Files:**
- Create: `on-chain-client/tests/regenerate_corpus.rs`
- Create (generated): `on-chain-client/tests/fuzz_parse_revive_event/corpus/*` (6 files)
- Create (generated): `on-chain-client/tests/fuzz_decode_org_state/corpus/*` (4 files)

No `Cargo.toml` change: `tests/regenerate_corpus.rs` is a direct child of
`tests/`, so cargo auto-discovers it as an ordinary default-harness integration
test (its `#[test]` fns are `#[ignore]`d).

- [ ] **Step 1: Write the regenerator**

Create `on-chain-client/tests/regenerate_corpus.rs`:

```rust
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
```

- [ ] **Step 2: Run the regenerator to produce the seed files**

Run: `cd on-chain-client && cargo test --test regenerate_corpus -- --ignored`
Expected: two tests run and pass; afterwards the corpus dirs are populated:

Run: `ls on-chain-client/tests/fuzz_parse_revive_event/corpus on-chain-client/tests/fuzz_decode_org_state/corpus`
Expected: 6 files in the first dir (`valid_genesis`, `valid_root_updated`,
`empty_topics`, `wrong_topic_count`, `bad_address_padding`, `trailing_byte`) and
4 in the second (`valid_epoch_7`, `epoch_u64_max`, `epoch_overflow`,
`wrong_length_95`). The pre-existing `.gitkeep` (if any) may coexist.

- [ ] **Step 3: Re-run the two never-panic targets to confirm they ingest the seeds**

Run: `cd on-chain-client && cargo test --test fuzz_parse_revive_event --test fuzz_decode_org_state`
Expected: both build and pass; bolero now replays the committed corpus before
generating inputs (no panic).

- [ ] **Step 4: Commit the regenerator and the generated seeds**

```bash
cd "$(git rev-parse --show-toplevel)"
git add on-chain-client/tests/regenerate_corpus.rs \
        on-chain-client/tests/fuzz_parse_revive_event/corpus \
        on-chain-client/tests/fuzz_decode_org_state/corpus
git commit -m "test(fuzz): corpus regenerator + committed seed inputs"
```

---

## Task 6: README Fuzzing section + full-suite green

**Files:**
- Modify: `on-chain-client/README.md`

- [ ] **Step 1: Add a Fuzzing section to the README**

Append to `on-chain-client/README.md` (after the existing clippy/testing
content — place it as a new top-level `## Fuzzing` section):

```markdown
## Fuzzing

The untrusted-byte decoders are fuzzed with [bolero](https://crates.io/crates/bolero).
Three targets live under `tests/<target>/fuzz_target.rs`:

| Target | Checks |
| --- | --- |
| `fuzz_parse_revive_event` | `parse_revive_event` never panics on arbitrary bytes |
| `fuzz_decode_org_state` | `decode_org_state` never panics on arbitrary bytes |
| `fuzz_event_round_trip` | `parse_revive_event` is the exact inverse of the on-chain encoding (structured inputs) |

**Default lane (stable, CI):** the targets are `harness = false` binaries, so a
plain `cargo test` runs each one — replaying its committed `corpus/` seeds plus
a bounded batch of generated inputs. No nightly toolchain required. Run one
target directly with `cargo test --test fuzz_parse_revive_event`.

**Deep fuzzing (nightly, on demand):**

```bash
cargo install cargo-bolero
cargo bolero test fuzz_parse_revive_event --engine libfuzzer   # coverage-guided
```

Any crash is written to the target's `crashes/` dir; commit it there as a
permanent regression seed.

**Corpus seeds** for the two byte targets are produced by an `#[ignore]`d
regenerator — rebuild them after a contract ABI change with:

```bash
cargo test --test regenerate_corpus -- --ignored
```
```

- [ ] **Step 2: Run the entire test suite to confirm nothing regressed**

Run: `cd on-chain-client && cargo test`
Expected: the existing lib + integration tests pass AND the three fuzz target
binaries run and pass. (The `regenerate_corpus` tests are `#[ignore]`d, so they
are skipped — shown as `ignored` in the summary.)

Note: the chopsticks-backed integration tests need their external harness; if
this environment can't run them, scope the check to what fuzzing touches:
`cargo test --test fuzz_parse_revive_event --test fuzz_decode_org_state --test fuzz_event_round_trip --lib`
and run the full `cargo test` where the chopsticks harness is available.

- [ ] **Step 3: Run the `--lib` clippy deny-gate one more time**

Run: `cd on-chain-client && cargo clippy --all-features --lib -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic`
Expected: clean. (Fuzz code is in test targets, not `--lib`.)

- [ ] **Step 4: Commit**

```bash
cd "$(git rev-parse --show-toplevel)"
git add on-chain-client/README.md
git commit -m "docs(on-chain-client): README Fuzzing section"
```

---

## Self-Review Notes (for the implementer)

- **Spec coverage:** Task 1–2 = the two never-panic targets (spec §Targets 1–2);
  Task 3–4 = the round-trip inverse-property target (spec §Targets 3);
  Task 5 = corpus seeding (spec §Corpus seeding); Task 6 = docs + run story
  (spec §Documentation, §Run story). Fault-injection sanity (spec §Testing) is
  Task 4 Step 5.
- **`for_runtime` import path:** `on_chain_client::decode::dispatch::for_runtime`
  and `PASEO_AH_SPEC_VERSION` are both `pub` (verified in `dispatch.rs`).
  `for_runtime` returns `&'static dyn Decoder`, and **the `Decoder` trait
  (`on_chain_client::decode::Decoder`, also `pub`) must be imported** to call
  `decode_org_state` / `parse_revive_event` on it — trait methods are only
  callable with the trait in scope, even through a trait object. All three
  targets import it.
- **Type names** used in the round-trip target — `Event::{Genesis,Update}`,
  `OrgAdmin`, `OnChainRootHash`, `OrgPubKey`, `Epoch` — are all re-exported from
  the crate root (`lib.rs` `pub use`). `Event` variant fields match
  `state.rs`/`v_paseo_ah.rs`: Genesis = `{admin, root_hash, org_pub_key}`,
  Update = `{admin, epoch, root_hash, org_pub_key, prev_root_hash}`.
- **Lint safety:** every `.expect()`/`assert_eq!` is in a `tests/` target, never
  `--lib`, so the `unwrap/expect/panic` deny-gate (lib-only) is unaffected.
- **bolero API:** `check!().for_each(|input: &[u8]| ...)` for raw bytes;
  `check!().with_type::<T>().cloned().for_each(|t: T| ...)` for a derived
  `TypeGenerator` (matches bolero's documented examples).
```
