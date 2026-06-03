# spike-common

Shared contract for the ODS Phase 1.d library-qualification spikes.

This crate defines the contract that both `spike-keyhive` and `spike-p2panda`
implement against. See the design at
`docs/superpowers/specs/2026-05-13-ods-phase-1d-library-qualification-design.md`
for the full picture.

## Build configurations

```
cargo build && cargo test                                                  # default
cargo check --no-default-features                                          # bare no_std
cargo check --no-default-features --features serde                         # no_std + serde
cargo check --no-default-features --features serde --target wasm32-unknown-unknown
```

## Binary

`cargo run --bin gap-update --features json` updates `docs/phase-1d/gap-matrix.{md,json}`
from the latest test-result fingerprints.

## Example: adding a gap-matrix row from a test

````rust
use spike_common::report::{
    Effort, FixPath, GapEntry, Library, PrincipalKind, Severity, SubFlow,
};

let entry = GapEntry {
    library: Library::Keyhive,
    gate: 1,
    sub_flow: SubFlow::A,
    principal: PrincipalKind::Member,
    severity: Severity::Soft,
    failing_subcrate: Some("keyhive_core".into()),
    fix_path: FixPath::TraitImpl,
    fix_effort: Some(Effort::Small),
    phase3_effort: Effort::Medium,
    evidence: vec!["my_test_name".into()],
    escape_hatch: None,
    salvage_notes: "Capability trait is public".into(),
    notes: "passes after thin shim".into(),
};

// Then pipe `serde_json::to_string(&entry)?` to `gap-update`'s stdin.
````
