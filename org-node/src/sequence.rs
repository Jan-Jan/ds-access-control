//! Monotonic replay guard for envelope parent_seq. The trie's base_root gives
//! natural protection while history moves forward; SeqGuard defends the edge
//! case where a root recurs (add-then-remove). See org-members README §4.
use crate::error::OrgNodeError;

/// Tracks the highest parent_seq committed for one org.
#[derive(Clone, Copy, Debug, Default)]
pub struct SeqGuard {
    last_seen: u64,
}

impl SeqGuard {
    /// Starts at 0 (no envelope committed yet; the genesis trie is sequence 0).
    /// The first envelope must therefore carry `parent_seq >= 1`.
    pub fn new() -> Self {
        Self { last_seen: 0 }
    }

    pub fn from_last_seen(last_seen: u64) -> Self {
        Self { last_seen }
    }

    pub fn last_seen(&self) -> u64 {
        self.last_seen
    }

    /// Accept `seq` only if strictly greater than the last seen. Does not mutate.
    pub fn check(&self, seq: u64) -> Result<(), OrgNodeError> {
        if seq > self.last_seen {
            Ok(())
        } else {
            Err(OrgNodeError::StaleSeq { got: seq, last_seen: self.last_seen })
        }
    }

    /// Commit `seq` as the new high-water mark. MUST be called only AFTER an
    /// envelope has FULLY verified (signature, org binding, sequence check, AND
    /// the on-chain root match). Calling it earlier — e.g. right after `check`
    /// but before the root match — would advance the replay watermark for an
    /// envelope that may still be rejected, creating a replay-protection bypass.
    /// Forward-only: a `seq` not greater than the current mark is ignored.
    pub fn advance(&mut self, seq: u64) {
        if seq > self.last_seen {
            self.last_seen = seq;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_equal_and_lower_seq() {
        let g = SeqGuard::from_last_seen(5);
        assert!(g.check(6).is_ok());
        assert_eq!(g.check(5), Err(OrgNodeError::StaleSeq { got: 5, last_seen: 5 }));
        assert_eq!(g.check(4), Err(OrgNodeError::StaleSeq { got: 4, last_seen: 5 }));
    }

    #[test]
    fn advance_moves_high_water_mark_forward_only() {
        let mut g = SeqGuard::new();
        g.advance(3);
        assert_eq!(g.last_seen(), 3);
        g.advance(2); // ignored
        assert_eq!(g.last_seen(), 3);
    }
}
