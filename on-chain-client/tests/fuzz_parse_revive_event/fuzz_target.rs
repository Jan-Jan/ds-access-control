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
