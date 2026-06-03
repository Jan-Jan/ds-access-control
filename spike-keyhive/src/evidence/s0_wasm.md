# Gate 0 evidence — Keyhive WASM / `no_std`

All three relevant Keyhive sub-crates (`keyhive_crypto`, `beekem`,
`keyhive_core`) compile cleanly for `wasm32-unknown-unknown` at the
pinned commit `a2876f3c`. The single peer-dep workaround needed is
`getrandom = { version = "0.2", features = ["js"] }`, which is
standard for any WASM Rust project consuming ed25519-dalek or
x25519-dalek.

The inventory's prediction that `keyhive_core` would DEFINITE FAIL
due to `tokio` + `futures` being unconditional was wrong: although
both crates appear in the dep tree, only their wasm32-compatible
slices (e.g., `tokio::sync` channels/mutexes) are reached by
keyhive_core's code paths, and they compile cleanly to wasm32.

A subtlety with beekem: its no_std mode is currently broken at the
pin (45 compile errors when `default-features = false` is propagated
to its `keyhive_crypto` dep — missing trait imports for `Digest::hash`
and `async_signer::try_sign_async`). This is an upstream bug in
beekem, not a WASM blocker — keeping beekem's `std` feature enabled
(its default) compiles cleanly for wasm32, since `wasm32-unknown-unknown`
is a std-bearing target.

The `spike-keyhive` crate itself does not compile for wasm32 because
it requests tokio's `rt-multi-thread` feature for native test
convenience; that feature is rejected by tokio on wasm32. This is a
spike-tooling concern, not a Keyhive concern.

See `docs/phase-1d/gate-0-results.md` (Keyhive section) for the
per-crate build matrix output. The gate-0 outcome for the
head-to-head comparison: **Keyhive has zero Hard rows for WASM**
(compared to p2panda's one Hard row in `p2panda-sync`).
