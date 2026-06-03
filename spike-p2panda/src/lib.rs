//! Phase 1.d qualification spike for the p2panda local-first stack.
//!
//! Pinned at commit `41559b0` (main, 2026-05-20). See
//! [`docs/phase-1d/subcrate-inventory.md`](../../docs/phase-1d/subcrate-inventory.md)
//! for the sub-crate map and pinned dependency block.
//!
//! Not `no_std`: p2panda pulls `tokio` through the default features of
//! every public crate (`p2panda-spaces`, `p2panda-net`). This is recorded
//! as a gate-0 finding rather than worked around.

pub mod s1_stable_id_acl;
pub mod s2_membership_intercept;
pub mod s3_cgka_rotation;
pub mod s4_org_pseudo_group;
pub mod s5_p2p_policy;

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
