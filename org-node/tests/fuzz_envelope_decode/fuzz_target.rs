//! Fuzz target: `SignedDeltaEnvelope` postcard decode must never panic on
//! arbitrary bytes. Also drives `decode_delta` on any successfully-parsed
//! envelope to verify the inner delta decode is equally panic-free.
//!
//! `harness = false` binary: a panic (the bolero failure signal) exits
//! non-zero and fails `cargo test`. Run a single target with
//! `cargo test -p org-node --test fuzz_envelope_decode`; deep-fuzz with
//! `cargo bolero test fuzz_envelope_decode --engine libfuzzer`.

use bolero::check;
use org_node::envelope::SignedDeltaEnvelope;

fn main() {
    check!().for_each(|bytes: &[u8]| {
        // Decoding arbitrary bytes as an envelope, then (if it parses) decoding
        // the inner delta, must only ever return Ok/Err — never panic.
        if let Ok(env) = postcard::from_bytes::<SignedDeltaEnvelope>(bytes) {
            let _ = env.decode_delta();
        }
    });
}
