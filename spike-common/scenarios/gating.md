# Gating scenario

**Purpose:** Exercise gate 5 (p2p connection policy) for member-as-a-group.

**Initial state:**
- alice and bob (as in revocation).
- Org key set.
- One doc/space `D` whose ACL grants `Principal::Member(alice)` and
  `Principal::Member(bob)`.
- An open p2p sync session for `D` between alice's device and bob's device.

**Steps:**
1. bob is revoked from the trie.
2. Trie-change observer fires.

**Observable assertions:**
- An open p2p sync session from bob's device is terminated within the
  test's timeout (the timeout itself is recorded as a `notes` field in
  the gap matrix; latency to terminate is part of the evidence).
- A fresh sync attempt from bob's device is rejected by the conn policy
  before the handshake completes.
- alice's session remains open.

**Substitutions exercised:** #5 (p2p connection policy), and #4 (the trie
change is what drives termination).
