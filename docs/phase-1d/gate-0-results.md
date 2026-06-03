# Phase 1.d Gate 0 — WASM / no_std verification results

**Date:** 2026-05-21
**Pinned p2panda commit:** 41559b0dfc2d7d0e9e4fba251ceb7f8094ff8be1
**Probe method:** Option A — scratch crate per sub-crate in /tmp/wasm-probe-<name>/

## Rationale for Option A

`cargo check -p <name> --no-default-features --target wasm32-unknown-unknown` issued from the
workspace root emits `error: cannot specify features for packages outside of workspace` for
non-workspace dependencies. Each sub-crate was therefore probed via an isolated scratch crate
in `/tmp` that depends on exactly one p2panda crate with `default-features = false`.

---

## Per-sub-crate results

### p2panda-core

- **Invocation:**
  ```
  cargo check --target wasm32-unknown-unknown
  [dep: p2panda-core, default-features = false]
  [dep: getrandom = { version = "0.2", features = ["js"] }]
  ```
- **Result:** PASS
- **Notes:** Without the `getrandom = { version = "0.2", features = ["js"] }` peer dep the
  probe fails with `error: the wasm*-unknown-unknown targets are not supported by default, you
  may need to enable the "js" feature`. Adding `getrandom/js` as a peer dep in the consuming
  crate unblocks compilation cleanly.
- **Hypothesis revision:** Confirmed — core is WASM-compatible with a trivial consumer-side
  getrandom workaround.

---

### p2panda-auth

- **Invocation:**
  ```
  cargo check --target wasm32-unknown-unknown
  [dep: p2panda-auth, default-features = false]
  [dep: getrandom = { version = "0.2", features = ["js"] }]
  ```
- **Result:** PASS
- **Notes:** Same getrandom 0.2 / js peer dep requirement as core. No other std-only deps in
  the `--no-default-features` surface. petgraph + tracing both compile cleanly for wasm32.
- **Hypothesis revision:** Confirmed — auth is WASM-compatible with the same trivial workaround.

---

### p2panda-encryption

- **Invocation (first attempt):**
  ```
  cargo check --target wasm32-unknown-unknown
  [dep: p2panda-encryption, default-features = false]
  [dep: getrandom = { version = "0.2", features = ["js"] }]
  ```
- **Result (first attempt):** FAIL
- **First error:**
  ```
  error: The wasm32-unknown-unknown targets are not supported by default; you may need to
  enable the "wasm_js" configuration flag.
  --> getrandom-0.3.4/src/backends.rs:194:17
  ```
- **Dep chain:** `p2panda-encryption` depends directly on
  `rand_chacha = { version = "0.9.0", features = ["os_rng"] }` (hardcoded in its
  `Cargo.toml`). `rand_chacha 0.9` pulls `rand_core 0.9.5` which pulls `getrandom 0.3.4`.
  getrandom 0.3 requires the `wasm_js` feature (not just `js`) and a `--cfg getrandom_backend`
  rustflag — neither of which is satisfied by only pinning getrandom 0.2.

- **Invocation (second attempt — workaround):**
  ```
  cargo check --target wasm32-unknown-unknown
  [dep: p2panda-encryption, default-features = false]
  [dep: getrandom = { version = "0.2", features = ["js"] }]
  [dep: getrandom03 = { package = "getrandom", version = "0.3", features = ["wasm_js"] }]
  ```
- **Result (second attempt):** PASS
- **Notes:** Adding `getrandom 0.3` with `features = ["wasm_js"]` as a second peer dep
  satisfies both getrandom generations and the crate compiles cleanly. This is a Soft gap:
  the consuming project (spike-p2panda) must add `getrandom = { version = "0.3",
  features = ["wasm_js"] }` alongside the existing `getrandom 0.2/js` pin.
- **Hypothesis revision:** Confirmed as plausible, but the path requires a dual getrandom pin
  (v0.2/js + v0.3/wasm_js) in the consuming crate. p2panda-encryption itself would need an
  upstream patch to expose a `wasm` feature flag that selects a WASM-safe RNG provider.

---

### p2panda-spaces

- **Invocation (first attempt):**
  ```
  cargo check --target wasm32-unknown-unknown
  [dep: p2panda-spaces, default-features = false]
  [dep: getrandom = { version = "0.2", features = ["js"] }]
  ```
- **Result (first attempt):** FAIL
- **First error:** Same getrandom 0.3.4 error as encryption (spaces depends on
  p2panda-encryption which pulls rand_chacha 0.9).
- **Dep chain:** `p2panda-spaces → p2panda-encryption → rand_chacha 0.9 → getrandom 0.3.4`

- **Invocation (second attempt — workaround):**
  ```
  cargo check --target wasm32-unknown-unknown
  [dep: p2panda-spaces, default-features = false]
  [dep: getrandom = { version = "0.2", features = ["js"] }]
  [dep: getrandom03 = { package = "getrandom", version = "0.3", features = ["wasm_js"] }]
  ```
- **Result (second attempt):** PASS
- **Notes:** Despite `p2panda-spaces/Cargo.toml` listing
  `tokio = { features = ["sync"], default-features = true }`, the `tokio::sync` primitives
  (channels, mutexes) compile for wasm32 — they are not OS-thread-dependent at the type-check
  level. The getrandom dual-pin workaround is sufficient.
- **Hypothesis revision:** Confirmed with the dual-getrandom workaround. The tokio `sync`
  feature is wasm32-compatible; only tokio's I/O reactor (mio) is std-only.

---

### p2panda-net

- **Invocation:**
  ```
  cargo check --target wasm32-unknown-unknown
  [dep: p2panda-net, default-features = false]
  [dep: getrandom = { version = "0.2", features = ["js"] }]
  ```
- **Result:** PASS
- **Notes:** With `--no-default-features` the iroh, iroh-gossip, p2panda-sync, and
  p2panda-discovery optional deps are all stripped. What remains is the actor framework
  (`ractor`), `tokio_with_wasm` (which is explicitly WASM-compatible), and core types.
  The probe passes without any additional getrandom pinning because tokio_with_wasm uses
  getrandom 0.2 internally.

  **Important caveat:** re-enabling any default feature (`iroh_endpoint`, `gossip`, `sync`,
  `discovery`, `address_book`) would pull in iroh 0.98.2 + std tokio and break WASM
  compilation. The no-default-features surface is useful only for the actor skeleton and
  connection-type definitions.
- **Hypothesis revision:** Hypothesis was too pessimistic about net in isolation; the
  `--no-default-features` slice compiles. However the operationally useful features all
  require iroh/std and are Hard blockers.

---

### p2panda-sync

- **Invocation:**
  ```
  cargo check --target wasm32-unknown-unknown
  [dep: p2panda-sync, default-features = false]
  [dep: getrandom = { version = "0.2", features = ["js"] }]
  ```
- **Result:** FAIL (unrecoverable without upstream changes)
- **First error:**
  ```
  error[E0432]: unresolved import `crate::sys::IoSourceState`
  --> mio-1.2.0/src/net/tcp/listener.rs
  ```
- **Dep chain:** `p2panda-sync → tokio = { default-features = true, features = ["macros", "sync"] }
  → mio 1.2.0` — mio has no wasm32-unknown-unknown platform support at all; it is a
  Unix/Windows-only polling library. Since p2panda-sync uses `default-features = true` for
  tokio there is no feature flag to strip mio.
- **Salvage:** Replacing std tokio with `tokio_with_wasm` in p2panda-sync and removing the
  direct tokio-stream dependency would require forking or upstream changes. The sync protocol
  logic itself (byte-stream framing, state machines) is WASM-portable, but the async runtime
  glue is not.
- **Hypothesis revision:** Confirmed as Hard blocker. p2panda-sync cannot compile for
  wasm32-unknown-unknown without forking the crate or an upstream patch.

---

## Summary

Five of the six p2panda sub-crates have a plausible WASM path: `p2panda-core` and
`p2panda-auth` pass with a simple `getrandom = { version = "0.2", features = ["js"] }` peer
dep; `p2panda-encryption` and `p2panda-spaces` pass with an additional
`getrandom = { version = "0.3", features = ["wasm_js"] }` peer dep (to satisfy rand_chacha
0.9's getrandom 0.3 requirement); and `p2panda-net --no-default-features` passes using
`tokio_with_wasm`, though its operationally useful features (iroh, gossip, sync) are all
Hard-blocked by iroh 0.98.2 + std tokio.

Only `p2panda-sync` is a Hard WASM blocker: it unconditionally depends on `tokio` with
`default-features = true` which pulls in `mio`, a std-only I/O poller that has zero support
for wasm32-unknown-unknown. Fixing this requires either forking p2panda-sync or an upstream
PR switching to `tokio_with_wasm`.

The sub-crate inventory hypothesis was substantially confirmed: core and encryption are
WASM-viable. The surprise is that spaces and the stripped net surface are also viable, and
that the encryption path requires dual-pinning getrandom rather than just `getrandom/js`.

---

# Keyhive

**Date:** 2026-06-01
**Pinned Keyhive commit:** a2876f3c79d89c9dd0c5e9f84802611c716fe27e
**Probe method:** Option A — scratch crate per sub-crate in /tmp/wasm-probe-<name>/

## Per-sub-crate results

### keyhive_crypto

- **Invocation:**
  ```
  cargo check --target wasm32-unknown-unknown
  [dep: keyhive_crypto, default-features = false]
  [dep: getrandom = { version = "0.2", features = ["js"] }]
  ```
- **Result:** PASS
- **Notes:** Compiles cleanly under `no_std + alloc` with the standard
  `getrandom 0.2 / js` peer-dep workaround. All crypto primitives
  (`blake3`, `chacha20poly1305`, `ed25519-dalek`, `x25519-dalek`) propagate
  `default-features = false` correctly.
- **Hypothesis revision:** Confirmed — inventory predicted LOW risk; the
  result is PASS.

---

### beekem

- **Invocation (first attempt — no_std):**
  ```
  cargo check --target wasm32-unknown-unknown
  [dep: beekem, default-features = false]
  [dep: getrandom = { version = "0.2", features = ["js"] }]
  ```
- **Result (first attempt):** FAIL — 45 compile errors
- **First errors:**
  ```
  error[E0599]: no function or associated item named `hash` found for struct `Digest<T>` in the current scope
  help: trait `Hash` which provides `hash` is implemented but not in scope; perhaps you want to import it
   = use core::hash::Hash;

  error[E0425]: cannot find function `try_sign_async` in module `async_signer`
  error[E0277]: a value of type `BTreeMap<Digest<T>, Arc<T>>` cannot be built from an iterator over elements of type `((), Arc<T>)`
  ```
- **Dep chain:** beekem's source code at the pin assumes its
  `keyhive_crypto` dependency has its `std` feature enabled. With
  `default-features = false` propagated, `Digest::hash` (a method
  provided behind the std feature) is not visible, `async_signer`
  exports `try_sign_async` only when std is enabled, and several
  serde derive paths fall over.

- **Invocation (second attempt — default features kept):**
  ```
  cargo check --target wasm32-unknown-unknown
  [dep: beekem, default-features = true (i.e. std enabled)]
  [dep: getrandom = { version = "0.2", features = ["js"] }]
  ```
- **Result (second attempt):** PASS
- **Notes:** beekem with `std` enabled compiles cleanly to wasm32. The
  std feature is satisfiable on `wasm32-unknown-unknown` (the target IS
  std-bearing; it's the *no_std* mode that's broken at the pin, not
  WASM itself).
- **Hypothesis revision:** Confirmed as WASM-viable. The inventory's
  "LOW risk" hypothesis for beekem WASM holds, with the caveat that
  beekem's no_std mode is currently broken at the pin (an upstream bug
  that does not block WASM use).

---

### keyhive_core

- **Invocation:**
  ```
  cargo check --target wasm32-unknown-unknown
  [dep: keyhive_core, default-features = false]
  [dep: getrandom = { version = "0.2", features = ["js"] }]
  ```
- **Result:** PASS — **MAJOR positive surprise**.
- **Notes:** Compiles cleanly to wasm32 with default features
  (which for keyhive_core is `default = []` — no default features).
  The inventory's hypothesis was DEFINITE FAIL based on the reading
  that `tokio` and `futures` are unconditional dependencies. That
  reading was wrong: tokio and futures are present in the dep tree
  via transitive paths that don't pull std-only tokio features. The
  build output shows `tokio v1.52.3` checked successfully against
  wasm32. The keyhive_core implementation evidently uses only the
  `tokio::sync` primitives that ARE wasm32-compatible (channels,
  mutexes), not the I/O reactor.
- **Hypothesis revision:** **Inventory hypothesis is REJECTED.**
  keyhive_core is WASM-viable. This is the most important finding
  for the head-to-head comparison: Keyhive has a much cleaner WASM
  story than p2panda, which has one Hard blocker (p2panda-sync) that
  cannot be salvaged without forking.

---

## Summary — Keyhive

All three relevant Keyhive sub-crates have a viable WASM path at the
pinned SHA. `keyhive_crypto` and `keyhive_core` pass cleanly with the
standard `getrandom = { version = "0.2", features = ["js"] }` peer-dep
workaround; `beekem` passes when its `std` feature is enabled (which
is its default at the pin).

The `spike-keyhive` crate itself does NOT compile for wasm32 because
its Cargo.toml requests tokio's `rt-multi-thread` feature for native
test convenience, and tokio rejects `rt-multi-thread` on wasm32. This
is a spike-tooling concern, not a Keyhive concern: a production
consumer of keyhive_core for browsers would not request
`rt-multi-thread`.

The inventory's DEFINITE FAIL prediction for `keyhive_core` was
incorrect. The actual gate-0 result for Keyhive: **all gap-matrix
rows None** (no fork or salvage required for WASM use). Compared to
p2panda's gate-0 result (4 rows None/Soft + 1 row Hard requiring a
fork of `p2panda-sync` for the WASM use case), Keyhive's WASM story
is materially better.

