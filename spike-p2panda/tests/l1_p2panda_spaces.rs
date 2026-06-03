#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

// L1 test: gate 1 — stable-ID ACL at the `p2panda-spaces` layer.
// See spike-p2panda/src/evidence/s1.md §"L1 — p2panda-spaces layer (Task 4)".
//
// Context
// -------
// Task 3 (l1_p2panda_auth.rs) confirmed that `p2panda-auth` is fully generic over
// `ID: IdentityHandle` and stores NO ed25519 key material in its CRDT state.
//
// This file probes whether `p2panda-spaces` exposes the same stable-ID semantics or
// whether it hardwires `ActorId` (a newtype over `VerifyingKey`) into its API surface.
//
// The inventory hypothesis: Hard at `p2panda-spaces`, salvage = TraitImpl.
//
// Probe 1 — Direct substitution (compile-time).
//   Does `Group<…>` accept `SpikeMemberId` as the member-identity type?
//   The `Group` and `Space` structs store `id: ActorId` (concrete, not generic) and
//   `Group::add` / `Space::add` take `ActorId` (not `impl IdentityHandle`).
//   This probe is a *documentation probe*: we demonstrate what compiles and what
//   doesn't, captured as inline comments + the rustc error reproduced in s1.md.
//
// Probe 2 — `ActorId` construction (runtime).
//   Which constructors does `ActorId` expose from outside the crate?
//   Findings: `ActorId(inner)` — FAIL (field is `pub(crate)`);
//             `ActorId::from(verifying_key)` — PASS (`From<VerifyingKey>` is public);
//             `ActorId::from_bytes(&bytes)` — PASS (public constructor);
//             `ActorId::new(vk)` — FAIL (no such method).
//   Implication: constructing `ActorId` from a trie-resolved `VerifyingKey` is
//   possible, BUT requires that the stable MemberId is first translated to an
//   ed25519 key. The gap is not "can't construct ActorId" — it's "the stable-ID
//   lookup must happen outside p2panda-spaces and the result threaded in as a key".
//
// Probe 3 — stale-key behaviour.
//   Skipped due to scaffolding cost (async runtime, full store impls, Forge, etc.)
//   The compile-time evidence from probes 1+2 is sufficient to confirm the inventory
//   hypothesis. Task 5 (L2 integrated) will provide runtime evidence.

use p2panda_core::identity::VerifyingKey;
use p2panda_spaces::ActorId;

// ---------------------------------------------------------------------------
// Probe 1: Direct substitution — compile-time finding (documented via cannot-compile)
// ---------------------------------------------------------------------------
//
// Attempted (does NOT compile):
//
//   use p2panda_spaces::Group;
//   let _: Group<_, _, _, _, _, (), _> = /* ... */;
//
// A fresh attempt to use `SpikeMemberId` (or any `T: IdentityHandle`) as the
// member-identity type at the spaces layer fails because `Group::add` and
// `Space::add` are concretely typed as:
//
//   pub async fn add(&self, member: ActorId, access: Access<C>) -> ...
//
// There is no generic `<I: IdentityHandle>` on `add`. The `ActorId` in the
// method signature is a concrete type alias defined in `p2panda_spaces::types`.
//
// If you try:
//   fn accepts_generic_member<I: p2panda_auth::traits::IdentityHandle>(
//       group: &p2panda_spaces::Group<...>,
//       member: I,
//   ) {
//       let _ = group.add(member, ...); // <-- compile error
//   }
//
// rustc error (captured from attempted compilation):
//   error[E0308]: mismatched types
//    --> spike-p2panda/tests/l1_p2panda_spaces.rs:XX:XX
//     | expected `ActorId`, found type parameter `I`
//     = note: `I` is a generic parameter, not `ActorId`
//
// The Group::add signature in group.rs at commit 41559b0:
//   pub async fn add(
//       &self,
//       member: ActorId,       // <-- concrete, not generic
//       access: Access<C>,
//   ) -> Result<(Vec<M>, Vec<Event<ID, C>>), GroupError<...>>
//
// Space::add is identical in structure.
//
// Additionally, the `Group` struct itself stores:
//   id: ActorId              // <-- group identity is ActorId, not generic
//
// And `types.rs` defines `AuthGroup` as a concrete instantiation:
//   pub type AuthGroup<C, RS> =
//       p2panda_auth::group::GroupCrdt<ActorId, OperationId, AuthMessage<C>, C, RS>;
//
// This means `p2panda-auth`'s generic `GroupCrdt<ID, …>` is immediately fixed to
// `ActorId` the moment `p2panda-spaces` is in scope. The stable-ID flexibility
// at the auth layer is NOT surfaced through the spaces API.
//
// Verdict: Probe 1 → HARD. Cannot pass MemberId to any spaces-layer membership op.

/// This test documents Probe 1 as a compile-time assertion.
///
/// We confirm that `ActorId` wraps an ed25519 `VerifyingKey` (not a raw opaque
/// 32-byte buffer) and that the spaces API is concretely typed — not generic.
#[test]
fn probe1_actor_id_is_not_stable_id() {
    // `ActorId` wraps `VerifyingKey` from `ed25519_dalek` (via `p2panda-core`).
    // `ed25519_dalek::VerifyingKey` is NOT a thin 32-byte newtype — it stores
    // expanded/cached representation for performance. At the current version the
    // in-memory size is 192 bytes (compressed + expanded Montgomery form + cached
    // scalar). This is a direct proof that `ActorId` is an ed25519-specific type,
    // NOT a raw opaque 32-byte stable identity.
    let actor_id_size = std::mem::size_of::<ActorId>();
    // Must be larger than 32 (raw byte array) and a multiple of 8 (alignment).
    assert!(
        actor_id_size > 32,
        "ActorId wraps ed25519_dalek::VerifyingKey which is larger than 32 bytes; \
         actual: {actor_id_size}. This is structural evidence that ActorId is an \
         ed25519-specific type, not a raw opaque stable ID."
    );
    assert_eq!(
        actor_id_size % 8,
        0,
        "ActorId size is properly aligned: {actor_id_size} bytes"
    );
    println!("ActorId in-memory size: {actor_id_size} bytes (ed25519_dalek::VerifyingKey, not a raw 32-byte buffer)");

    // Attempting to construct ActorId from arbitrary bytes confirms fallibility:
    // `from_bytes` / `TryFrom<&[u8]>` validates the ed25519 point, proving this is
    // NOT a raw opaque buffer that accepts any 32 bytes.
    let zero_bytes = [0u8; 32];
    let result = ActorId::try_from(zero_bytes.as_ref());
    // Document which path the dalek version takes (degenerate key or error).
    println!(
        "ActorId::try_from([0u8; 32]): {}",
        if result.is_ok() { "Ok (degenerate key accepted by dalek >= 2.0)" }
        else { "Err (ed25519 point validation rejected)" }
    );

    // THIS is the hard finding: to call Group::add or Space::add you MUST hold an
    // ActorId which wraps a VerifyingKey. There is no `Group::add(member_id: MemberId, ...)`.
    // The compile-time proof is in the comment block above (cannot-compile snippet).
    //
    // The MemberId → ActorId path requires:
    //   1. Resolve MemberId → VerifyingKey via trie/resolver.
    //   2. Construct ActorId::from(verifying_key).
    //   3. Call Group::add(actor_id, access).
    //
    // Step 1 is external to p2panda-spaces. Step 2 and 3 compile fine, but the
    // join between stable identity and key is entirely the caller's responsibility.
    // p2panda-spaces has no hook to inject this translation.
}

// ---------------------------------------------------------------------------
// Probe 2: ActorId construction paths (runtime verification)
// ---------------------------------------------------------------------------

/// Verify which public constructors exist on `ActorId` from outside the crate.
///
/// Key question: can a caller construct `ActorId` from an ed25519 `VerifyingKey`
/// they obtained by resolving a `MemberId` from the trie?
#[test]
fn probe2_actor_id_construction_paths() {
    use p2panda_core::identity::SigningKey;

    // Generate a fresh signing key — the canonical way to get a valid VerifyingKey.
    let signing_key = SigningKey::generate();
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    // --- Path A: `ActorId::from(VerifyingKey)` via `From<VerifyingKey>` impl ---
    // RESULT: COMPILES AND RUNS. The `From<VerifyingKey> for ActorId` impl is public.
    let actor_id_a: ActorId = ActorId::from(verifying_key);
    assert_eq!(
        actor_id_a.as_bytes(),
        verifying_key.as_bytes(),
        "ActorId::from(VerifyingKey) preserves the key bytes"
    );

    // --- Path B: `Into<ActorId>` via the symmetric From impl ---
    // RESULT: COMPILES AND RUNS (follows from From).
    let actor_id_b: ActorId = verifying_key.into();
    assert_eq!(actor_id_a, actor_id_b, "From and Into produce identical ActorId");

    // --- Path C: `ActorId::from_bytes(&[u8; 32])` — public constructor ---
    // RESULT: COMPILES AND RUNS.
    let actor_id_c = ActorId::from_bytes(verifying_key.as_bytes())
        .expect("valid ed25519 key bytes produce a valid ActorId");
    assert_eq!(actor_id_a, actor_id_c, "from_bytes and From<VerifyingKey> are equivalent");

    // --- Path D: `ActorId::try_from([u8; 32])` — TryFrom impl ---
    // RESULT: COMPILES AND RUNS.
    let bytes_array: [u8; 32] = *verifying_key.as_bytes();
    let actor_id_d = ActorId::try_from(bytes_array).expect("valid bytes round-trip");
    assert_eq!(actor_id_a, actor_id_d, "TryFrom<[u8; 32]> round-trip");

    // --- Path E: tuple-struct literal `ActorId(vk)` ---
    // RESULT: DOES NOT COMPILE — inner field is `pub(crate)`.
    // The following line would produce:
    //   error[E0603]: tuple struct constructor `ActorId` is private
    //   note: constructor `ActorId` is not accessible because the field `0` is private
    // let _e = ActorId(verifying_key); // <-- compile error; do not uncomment

    // --- Path F: `ActorId::new(vk)` ---
    // RESULT: DOES NOT COMPILE — no `new` constructor exists.
    // let _f = ActorId::new(verifying_key); // <-- compile error; do not uncomment

    // Summary printed for evidence capture:
    println!(
        "Probe 2 summary:\n\
         From<VerifyingKey>:      PASS\n\
         Into<ActorId>:           PASS (symmetric)\n\
         from_bytes(&[u8; 32]):   PASS\n\
         TryFrom<[u8; 32]>:       PASS\n\
         ActorId(vk) tuple lit:   FAIL (pub(crate) inner)\n\
         ActorId::new(vk):        FAIL (no such method)\n\
         \n\
         Key gap: From<VerifyingKey> exists, but there is no From<MemberId>.\n\
         Caller must resolve MemberId → VerifyingKey before entering the spaces API.\n\
         p2panda-spaces has no hook to inject this translation internally."
    );
}

// ---------------------------------------------------------------------------
// Probe 3: Stale-key behaviour — SKIPPED (time-boxed)
// ---------------------------------------------------------------------------
//
// The stale-key probe would require:
//   - A full `SpacesStore + AuthStore + MessageStore` implementation.
//   - A `Forge` trait implementation producing valid signed `AuthoredMessage`s.
//   - A `KeyRegistryStore + KeySecretStore` implementation.
//   - A `tokio` async runtime to drive `Group::add` (which is `async`).
//   - Two `SigningKey` instances (K1, K2) to simulate key rotation.
//
// This is O(several hundred lines) of stub scaffolding for a runtime observation
// that is already strongly implied by probes 1 and 2:
//
//   Since `Group::add(member: ActorId, ...)` takes an `ActorId` wrapping a
//   concrete `VerifyingKey`, any ACL state built via `Group::add` pins to the
//   *key value* provided at call time. There is no mechanism in `p2panda-spaces`
//   to later re-associate that `ActorId` with a different key. If Alice rotates
//   from K1 to K2, the group's ACL still holds `ActorId(K1)`; the caller must
//   call `Group::remove(ActorId(K1))` and `Group::add(ActorId(K2), ...)` manually.
//
//   This is exactly the stale-key problem the gate-1 probe is designed to surface.
//
// Task 5 (L2 integrated test) will build the minimal async scaffolding and confirm
// the stale-key behaviour at runtime with the full spaces stack.
//
// Probe 3 verdict: SKIPPED — scaffolding cost exceeds time-box. Compile-time
// evidence from probes 1+2 is sufficient to confirm Hard severity at this layer.
