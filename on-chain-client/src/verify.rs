//! Verifier that closes the loop with `org_members::CandidateTrie::verify_against`.
//! Compares a candidate trie's root against on-chain state read at a given
//! block; the trie crate owns the actual SMT verification.
//!
//! Lands in Stage 2 Task 5 (after the client surface in `client.rs` is in
//! place). At that point `org-members` is added as a dependency; for Task 1
//! this module is a placeholder so the module tree matches the plan.
