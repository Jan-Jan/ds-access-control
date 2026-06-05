//! Logical state types: `OrgState` (the decoded contents of an org slot)
//! plus the events streamed by `OrgRegistryClient::subscribe`. Matches the
//! surface declared in spec §3.

use crate::types::{Epoch, OnChainRootHash, OrgAdmin, OrgPubKey};

/// 32-byte block hash. Asset Hub uses blake2-256 for block hashing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BlockHash(pub [u8; 32]);

/// A reference to a specific block by hash and number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BlockRef {
    pub hash: BlockHash,
    pub number: u64,
}

/// The current state of an org's slot in `OrgRegistry`, as decoded from
/// contract storage at a specific block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrgState {
    pub root_hash: OnChainRootHash,
    pub org_pub_key: OrgPubKey,
    pub epoch: Epoch,
}

/// A decoded `OrgRegistry` event. `Update` carries `prev_root_hash` so
/// clients can reconstruct the chain of roots from events alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Genesis {
        admin: OrgAdmin,
        root_hash: OnChainRootHash,
        org_pub_key: OrgPubKey,
    },
    Update {
        admin: OrgAdmin,
        epoch: Epoch,
        root_hash: OnChainRootHash,
        org_pub_key: OrgPubKey,
        prev_root_hash: OnChainRootHash,
    },
}

/// A notification yielded by `OrgRegistryClient::subscribe`. Best-block and
/// finalised emissions are distinct so consumers can act optimistically on
/// best-block events and only commit local state once finalisation arrives.
/// `Reorged` notifies the consumer that a previously-best block has been
/// discarded; any in-flight optimistic flow keyed on `at.hash` should be
/// cancelled or rolled back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubscribedEvent {
    /// Event observed in a best (non-finalised) block.
    BestBlockEvent { event: Event, at: BlockRef },
    /// A previously-best block has been reorged out.
    Reorged { discarded: BlockRef },
    /// Event observed in a finalised block.
    FinalisedEvent { event: Event, at: BlockRef },
}
