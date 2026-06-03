//! Phase 1.d qualification spike for the Keyhive (Ink & Switch) local-first stack.
//!
//! Pinned at commit `a2876f3c` (main, 2026-05-22). See
//! [`docs/phase-1d/subcrate-inventory.md`](../../docs/phase-1d/subcrate-inventory.md)
//! for the sub-crate map and pinned dependency block.
//!
//! Not `no_std`: keyhive_core pulls `tokio` + `futures` through
//! unconditional default features. This is recorded as a gate-0
//! finding rather than worked around.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod adapter;
pub mod s1_stable_id_acl;
pub mod s2_membership_intercept;
pub mod s3_cgka_rotation;
pub mod s4_org_pseudo_group;
pub mod s5_p2p_policy;

#[doc = include_str!("evidence/s0_wasm.md")]
pub mod evidence_s0 {}

#[doc = include_str!("evidence/s1.md")]
pub mod evidence_s1 {}

#[doc = include_str!("evidence/s2.md")]
pub mod evidence_s2 {}

#[doc = include_str!("evidence/s3.md")]
pub mod evidence_s3 {}

#[doc = include_str!("evidence/s4.md")]
pub mod evidence_s4 {}

#[doc = include_str!("evidence/s5.md")]
pub mod evidence_s5 {}
