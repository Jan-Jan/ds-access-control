//! Shared contract for ODS Phase 1.d library-qualification spikes.
//!
//! Defines: identity types, the `MemberKeyResolver` trait, an in-memory
//! `StubTrie` implementation, scenario fixtures, and the gap matrix
//! types used to score Keyhive and p2panda against the six gates.
//!
//! See `docs/superpowers/specs/2026-05-13-ods-phase-1d-library-qualification-design.md`
//! for the full design.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

extern crate alloc;

pub mod identity;
pub mod resolver;
pub mod stub_trie;
pub mod scenarios;
pub mod report;
