//! Fuzz target: `Decoder::decode_org_state` must never panic on arbitrary
//! bytes. Reaches the decoder through the public `for_runtime` path — the
//! exact surface `OrgRegistryClient::get_org_state` uses.
//!
//! `harness = false` binary: a panic (the bolero failure signal) exits
//! non-zero and fails `cargo test`. Run a single target with
//! `cargo test --test fuzz_decode_org_state`; deep-fuzz with
//! `cargo bolero test fuzz_decode_org_state --engine libfuzzer`.

use std::panic::AssertUnwindSafe;

use bolero::check;
use on_chain_client::decode::dispatch::{PASEO_AH_SPEC_VERSION, for_runtime};

fn main() {
    let decoder = for_runtime(PASEO_AH_SPEC_VERSION)
        .expect("pinned Paseo AH decoder must resolve");
    // bolero runs each iteration inside `catch_unwind`, which requires the
    // closure's captures to be `RefUnwindSafe`. `&dyn Decoder` is not
    // `RefUnwindSafe` by default, but every `Decoder` impl is a stateless unit
    // struct, so an unwind cannot leave it observably inconsistent — assert it.
    // Deref the wrapper inside the closure (rather than capturing its `.0`
    // field) so the closure captures the `AssertUnwindSafe` wrapper itself.
    // (`decode_org_state` needs no `use Decoder`: the receiver is the
    // `dyn Decoder` trait object, which already names the trait.)
    let decoder = AssertUnwindSafe(decoder);
    check!().for_each(move |input: &[u8]| {
        // Property: any byte slice yields Ok/Err, never a panic/abort.
        let _ = (*decoder).decode_org_state(input);
    });
}
