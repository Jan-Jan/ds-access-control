# Revocation scenario

**Purpose:** Exercise gates 1, 3, and a touch of 5 — a member is revoked from
the trie; the (D)CGKA must rotate and the revoked member's devices must
lose access to the doc.

**Initial state:**
- alice (`MemberId([0xa1; 32])`) with one device.
- bob (`MemberId([0xb1; 32])`) with one device.
- Org key set.
- One doc/space `D` whose ACL grants `Principal::Member(alice)` and
  `Principal::Member(bob)`. Both have read+write.

**Steps:**
1. bob is revoked from the trie (`stub_revoke(bob)`).
2. The spike's trie-change observer fires, notifying the library adapter
   that the trie has advanced.

**Observable assertions:**
- bob's device cannot decrypt new doc payloads after revocation.
- alice's device can still decrypt the doc.
- (D)CGKA has advanced one epoch.

**Substitutions exercised:** #1 (stable-ID ACL), #3 (membership-op
interception — bob was removed by the *trie*, not by a library-native
`remove_member` call), #4 (rotation-on-trie-change).
