//! Fuzz target: `verify_envelope_against_chain` must never panic on a malformed
//! envelope, and any accepted update must match the on-chain root.
//!
//! The fixed, honestly-built local trie + chain are the honest context; only
//! the envelope bytes are fuzz-controlled.
//!
//! `harness = false` binary: a panic (the bolero failure signal) exits
//! non-zero and fails `cargo test`. Run with
//! `cargo test -p org-node --test fuzz_verify_against_chain`; deep-fuzz with
//! `cargo bolero test fuzz_verify_against_chain --engine libfuzzer`.

use std::panic::AssertUnwindSafe;

use bolero::check;
use org_members::hasher::Blake3Hasher;
use org_members::trie::OrgTrie;
use org_members::{MemberId, MemberLeaf};
use org_node::chain::{ChainReader, MockChain, OrgState};
use org_node::envelope::SignedDeltaEnvelope;
use org_node::ids::OrgId;
use org_node::keys::SigningKeypair;
use org_node::sequence::SeqGuard;
use org_node::verify::{verify_envelope_against_chain, VerifyContext};

fn fixed_trie(admin: &SigningKeypair) -> OrgTrie<Blake3Hasher> {
    let leaf = MemberLeaf::new(
        MemberId::new([1u8; 32]),
        "admin",
        admin.member_key(),
        "T",
        "U",
        vec![admin.device_key()],
    )
    .unwrap();
    let (trie, _) = OrgTrie::<Blake3Hasher>::genesis(vec![leaf]).unwrap().recalculate().unwrap();
    trie
}

fn main() {
    let admin = SigningKeypair::from_seed([1u8; 32]);
    let local = fixed_trie(&admin);
    let org = OrgId::new([5u8; 20]);
    let mut chain = MockChain::new();
    chain.set(org, OrgState { root_hash: local.root_hash().unwrap(), org_pub_key: [0u8; 32], epoch: 9 });
    let vk = admin.verifying_key();

    // bolero wraps each iteration in `catch_unwind`, which requires the
    // closure's captures to be `RefUnwindSafe`. `OrgTrie` contains a
    // `spin::Once` (interior mutability), so wrap the captures.
    // None of local/chain/org/vk can actually be left inconsistent by an unwind
    // because the closure never mutates them — asserting safety is correct.
    let local = AssertUnwindSafe(local);
    let chain = AssertUnwindSafe(chain);

    check!().for_each(move |bytes: &[u8]| {
        if let Ok(env) = postcard::from_bytes::<SignedDeltaEnvelope>(bytes) {
            let ctx = VerifyContext {
                expected_org_id: org,
                author_member_key: &vk,
                seq_guard: SeqGuard::from_last_seen(0),
                last_committed_epoch: 0,
            };
            if let Ok(out) = verify_envelope_against_chain(&*local, &env, &ctx, &*chain) {
                // Any accepted update must equal the chain root it verified against.
                assert_eq!(
                    out.trie.root_hash().unwrap(),
                    chain.get_org_state(&org).unwrap().unwrap().root_hash
                );
            }
        }
    });
}
