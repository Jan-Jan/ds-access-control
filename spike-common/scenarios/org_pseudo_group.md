# Org-as-pseudo-group scenario

**Purpose:** Exercise gates 1, 3, 4 and the org-keyed paths of 5 — verify
that the organisation-as-pseudo-group principal works as an ACL subject
and that rotating a member's p2p key does not break org-keyed doc access.

**Initial state:**
- alice and bob.
- Org key set.
- One doc/space `D` whose ACL grants the org-as-pseudo-group (single
  `Principal::Org` entry, not per-member entries).
- alice and bob each have read+write via the org membership.

**Steps:**
1. alice's p2p member key is rotated to a new value (`stub_rotate_member_key`).
2. Trie-change observer fires.

**Observable assertions:**
- The doc is readable by alice's new key after rotation.
- The same doc is readable by bob without any explicit ACL change (the
  org-keyed delegation never named alice or bob individually).
- (D)CGKA recompute was triggered for the org-keyed doc.

**Substitutions exercised:** #1 (stable-ID ACL via the `Principal::Org`
subject), #2 (org-as-pseudo-group principal), #4 (rotation-on-trie-change
via the org-keyed path).
