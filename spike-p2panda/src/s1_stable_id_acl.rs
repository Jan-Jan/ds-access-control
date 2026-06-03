//! Gate 1 substitution: stable-ID ACL with trie-lookup resolver.
//!
//! Per `evidence/s1.md`, p2panda-spaces hardwires `ActorId` over
//! `VerifyingKey`. This module implements the `TraitImpl` salvage path via two
//! independent pieces:
//!
//! ## 1. `ResolverPki<R>` — instance-level PKI adapter
//!
//! Wraps a [`MemberKeyResolver`] and exposes both:
//! - Instance methods (`identity_key_with_resolver`) for convenience.
//! - [`IdentityRegistry<MemberId, ResolverPki<R>>`] — the trait impl where `Y = Self`,
//!   meaning the resolver is the state. Because the upstream trait defines
//!   `identity_key` as a *static* associated function (`fn identity_key(y: &Y, …)`),
//!   the caller passes a `&ResolverPki<R>` as the state `y`, making the resolver
//!   accessible. This is the minimal escape hatch for the upstream static-method API
//!   shape. See `evidence/s1.md` §L2 for details.
//!
//! ### Key-type note
//!
//! `IdentityRegistry::identity_key` returns `x25519::PublicKey` (a 32-byte ECDH key).
//! `P2pMemberKey` wraps an ed25519 `VerifyingKey` whose compressed representation is
//! also 32 bytes. This impl reinterprets the compressed ed25519 bytes as an x25519
//! `PublicKey` via `PublicKey::from_bytes`. In the DCGKA the identity key is a stable
//! anchor for bundle verification; actual ECDH uses separate pre-key bundles, so the
//! byte-level reinterpretation is safe for the PKI-lookup role.
//!
//! ## 2. `materialise_actor_id` — spaces-layer call-time converter
//!
//! Accepts a [`Principal`] and a resolver, returns a fresh [`ActorId`] by calling
//! `resolver.p2p_member_key(id)` (or `org_key()`) and constructing
//! `ActorId::from(verifying_key)`. Because the resolver is called on every invocation,
//! the returned `ActorId` tracks key rotation automatically.
//!
//! See `evidence/s1.md` §L2 and the design doc §Data flow Flow A.

use p2panda_core::identity::VerifyingKey as PandaVerifyingKey;
use p2panda_encryption::crypto::x25519::PublicKey as X25519PublicKey;
use p2panda_encryption::traits::IdentityRegistry;
use p2panda_spaces::ActorId;
use spike_common::identity::{MemberId, Principal};
use spike_common::resolver::{MemberKeyResolver, ResolverError};

// ---------------------------------------------------------------------------
// ResolverPki — wraps a MemberKeyResolver; implements IdentityRegistry<MemberId, Self>
// ---------------------------------------------------------------------------

/// Wraps a [`MemberKeyResolver`] and implements
/// [`IdentityRegistry<MemberId, ResolverPki<R>>`].
///
/// The `Y` (state) parameter is `ResolverPki<R>` itself — the caller passes
/// `&self` as the state argument to the static trait method, making the resolver
/// accessible without needing `&self` on the method signature.
///
/// See module-level docs for the key-type note and orphan-rule discussion.
pub struct ResolverPki<R> {
    /// The live resolver — consulted on every key-lookup call.
    pub resolver: R,
}

impl<R: MemberKeyResolver> ResolverPki<R> {
    /// Wraps a resolver in a `ResolverPki`.
    pub fn new(resolver: R) -> Self {
        Self { resolver }
    }

    /// Instance-level identity key lookup. Returns `None` for unknown members
    /// (graceful — not an error) and `Err` only for non-`UnknownMember` resolver
    /// failures.
    pub fn identity_key_with_resolver(
        &self,
        id: &MemberId,
    ) -> Result<Option<X25519PublicKey>, ResolverError> {
        match self.resolver.p2p_member_key(id) {
            Ok(key) => {
                let bytes = *key.0.as_bytes();
                Ok(Some(X25519PublicKey::from_bytes(bytes)))
            }
            Err(ResolverError::UnknownMember(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Organisation identity key (resolves `Principal::Org`).
    pub fn org_identity_key(&self) -> Result<Option<X25519PublicKey>, ResolverError> {
        match self.resolver.org_key() {
            Ok(key) => {
                let bytes = *key.0.as_bytes();
                Ok(Some(X25519PublicKey::from_bytes(bytes)))
            }
            Err(ResolverError::OrgKeyUnset) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// Implement [`IdentityRegistry<MemberId, ResolverPki<R>>`] where `Y = ResolverPki<R>`.
///
/// The caller passes `&pki` as the `y` state argument. This is the escape hatch for
/// the upstream static-method API shape: the resolver is threaded via `Y` rather than
/// via `&self`.
///
/// Orphan-rule note: `ResolverPki` is defined in this crate, so the impl is permitted
/// even though both `IdentityRegistry` and `MemberId` are foreign types.
impl<R: MemberKeyResolver> IdentityRegistry<MemberId, ResolverPki<R>> for ResolverPki<R> {
    type Error = ResolverError;

    fn identity_key(
        y: &ResolverPki<R>,
        id: &MemberId,
    ) -> Result<Option<X25519PublicKey>, Self::Error> {
        y.identity_key_with_resolver(id)
    }
}

// ---------------------------------------------------------------------------
// materialise_actor_id — spaces-layer wrapper
// ---------------------------------------------------------------------------

/// Resolves a [`Principal`] to a freshly-materialised [`ActorId`] at call time.
///
/// This is the integration seam between application code (which carries stable
/// [`Principal`] values) and the `p2panda-spaces` API (which requires [`ActorId`]
/// wrapping a concrete `VerifyingKey`).
///
/// Because the resolver is called on **every invocation**, the returned `ActorId`
/// always reflects the *current* key in the trie. After a key rotation the next call
/// returns `ActorId(K2)`, not the stale `ActorId(K1)`. Callers managing `Group` /
/// `Space` membership must reconcile this: on rotation they call
/// `Group::remove(old)` then `Group::add(new, access)`.
///
/// ## Construction path
///
/// L1 probe 2 (Task 4) confirmed that `From<VerifyingKey> for ActorId` is public even
/// though the inner field is `pub(crate)`. This one-step conversion is the only stable
/// path from an externally-resolved key to an `ActorId`.
///
/// ## Key type bridging
///
/// `spike_common::identity::P2pMemberKey` wraps `ed25519_dalek::VerifyingKey`.
/// `p2panda_spaces::ActorId` requires `p2panda_core::identity::VerifyingKey`
/// (a newtype over `ed25519_dalek::VerifyingKey`).
/// Conversion: `dalek::VerifyingKey → PandaVerifyingKey → ActorId` — two trivial
/// newtype steps; no cryptographic work.
pub fn materialise_actor_id<R: MemberKeyResolver>(
    resolver: &R,
    principal: &Principal,
) -> Result<ActorId, ResolverError> {
    match principal {
        Principal::Member(id) => {
            let key = resolver.p2p_member_key(id)?;
            let panda_vk = PandaVerifyingKey::from(key.0);
            Ok(ActorId::from(panda_vk))
        }
        Principal::Org => {
            let key = resolver.org_key()?;
            let panda_vk = PandaVerifyingKey::from(key.0);
            Ok(ActorId::from(panda_vk))
        }
    }
}
