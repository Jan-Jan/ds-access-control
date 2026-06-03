# Gate 0 evidence — WASM / no_std verification

Five of the six p2panda sub-crates can be compiled for `wasm32-unknown-unknown`. `p2panda-core`
and `p2panda-auth` pass with a single `getrandom = { version = "0.2", features = ["js"] }` peer
dep in the consuming crate. `p2panda-encryption` and `p2panda-spaces` additionally require
`getrandom = { version = "0.3", features = ["wasm_js"] }` because `p2panda-encryption` pins
`rand_chacha 0.9.0` which uses `getrandom 0.3` — a generation that ships separate WASM support
under a different feature flag. `p2panda-net` passes cleanly with `--no-default-features`
because that strips iroh and the gossip/sync/discovery features, leaving only the actor skeleton
(`ractor`) and `tokio_with_wasm`; re-enabling any default feature would reintroduce iroh 0.98.2
and std tokio, which are Hard blockers.

Only `p2panda-sync` is a hard WASM blocker: it unconditionally depends on std tokio
(`default-features = true`) which transitively pulls in `mio 1.2.0`, a platform-specific I/O
poller with no wasm32-unknown-unknown backend. This cannot be fixed with a consumer-side feature
flag; it requires an upstream PR replacing the tokio dependency with `tokio_with_wasm`, or a
local fork. All other sub-crates are Soft gaps — their WASM path exists and is short (consumer
adds one or two getrandom peer deps).

See `docs/phase-1d/gate-0-results.md` for per-crate invocations, exact error messages, and dep
chain backtraces.
