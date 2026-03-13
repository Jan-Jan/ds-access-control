# **Two Tier Blockchain Mediated Local-First Access Control**

## *A best of both worlds proposal enabling blockchain prescribed membership for organizational collaboration*

Author: [Jan-Jan van der Vyver](mailto:jan-jan@parity.io)  
Status: In review  
Last updated: 12 Mar 2026

# **BLUF**

To meet data sovereignty and company privacy requirements, and at the same time simplifying cross-company collaboration, we propose a two tier access control infrastructure: 

1. **Organizational Entities (OEs)**, e.g. companies, clubs, the ICC, etc:  
   * Off-chain Merkle tree with member metadata (e.g. handle, name, OE roles, OE public key) as leaves.  
   * Anchored on-chain only via Merkle root hashes (to preserve privacy).  
   * Serve as the identity, and OE membership revocation (used for trust promotion gating on the CU side), and company-wide distribution backbone.  
2. **Collaboration Units (CUs)**, e.g. project teams, departments, cross-company working groups:  
   * Entirely off-chain — wrapping existing libraries designed for secure, local-first applications collaboration to be mediated by OE membership (see next bullet), i.e. any peer-to-peer library for establishing shared encryption keys should suffice.  
     * This allows different per CU encryption libraries so the technology best suited to the documentation type being collaborated on can be chosen.  
   * **Membership validity is (re)verified against OEs via Zero-Knowledge Proofs (ZKPs) based on member handle**, after each OE Merkle root update on-chain.  
     * Hence, OE public key and CU public key changes are decoupled, which should make the OE Merkle tree more stable.  
   * Dual successive gate mechanisms are proposed, to allow offline collaboration and seamless UX during key updates:  
     * The **sync gate** allows syncing of changes, based on ZKPs against the last known OE root hash. Changes that pass the sync gate enter the unverified window, where they await trust promotion.   
     * The **trust promotion gate** takes the unverified window of changes, since the last time the OE root hash was read till when it was read now, to either promote to trusted or to discard all those changes based on the ZKPs.  
       * This unverified window grows longer the longer a device collaborates without access to the latest OE root hash.

Note: This can be implemented in phases, where the OE implementation already suffices for on-chain activities, e.g. executing a smart contract that requires a Zero-Knowledge Proof (ZKP) wherewith the transaction signee demonstrates they are a member of the OE and has a specific/required role (i.e. authority).

# **Requirements**

## **Unique Selling Propositions**

1. Easy cross company / federated collaboration:  
   1. Basic: e.g. I can share my doc with my OE and another OE.   
   2. Advanced: e.g. I can share my doc with a certain group (i.e. a CU) within my company (i.e. an OE), and with another group in another company.  
2. Data sovereignty:   
   1. All documents/data should be encrypted (even at rest) with keys that are accessible to the corresponding CUs (or even OE) that have read access.  
      1. Note: This is intended for off-chain encryption, because encrypting data on-chain would leave it permanently readable to members who have been removed.  
   2. Even though data might be synced via public servers, due to encryption, data is never readable to 3rd parties / unauthorized parties.  
3. Smart contract integration:  
   1. It should be possible to gate smart contracts based on whether a member has a role within an OE, e.g. only an employee of company X who has the right to make public statements, may sign and publish a document to the public.

## **Requirements**

4. Decentralised and resilient.  
   1. It should be possible for an individual to keep editing documents/data even if offline.  
   2. It should be possible for collaborators to collaborate peer-to-peer even if disconnected from the internet.  
   3. To minimize velocity loss, upon a OE secret key change:  
      1. If the individual is still part of the OE (and the CU), they can continue to edit the document/data uninterrupted,  
      2. Note: In the special case where document/data is shared with OE, it is merely re-encrypted (with the new OESK) and shared right away again.  
   4. CUs must be able to:  
      1. Be robust while having a single admin, e.g. no collaboration downtime even if the admin is offline.  
      2. At least scale from a small (1) to medium (10) number of members, ideally to 100s of members.  
      3. Handle members being offline for long periods of time (e.g. 1 month).  
         1. Advanced: OE policy can enforce shorter offline windows through the app itself rather than the OE and CU mechanisms described in this proposal.  
   5. The system needs to be able to recover from peer-to-peer mediated collaboration over a time period between parties that were all disconnected from / unaware of the OE root hash and secret key change (till later when they reconnected), and one of them lost their membership to the OE. In this case data loss is preferred over allowing potentially malicious data to merge.  
      1. Also retro-dating attacks should be impossible, i.e. it should be impossible for an ex-member to make a claim they made a change in the past (even if this leads to potential data losses). I.e. all changes from ex-members not synced before an OE root hash / secret key change must be rejected.  
5. Quantum proof algorithms should be preferred, unless computationally unrealistic.  
   1. In the unrealistic cases they should be called out, and a migration capability should be built in.  
6. Add/Update/Remove (a.k.a. CRUD):  
   1. It should be possible for anyone to create an OE.  
      1. Creator is immediately administrator   
   2. It should be possible for a member of an OE to create CU associated with the OE.  
      1. Creator is immediately administrator for that CU  
   3. It should be possible for a group member, with the rights to do so, to add/update/remove members from an OE or CU.  
      1. Note: Remove, i.e. member revocation:  
         1. Should be from a specific point in time, whereafter the old member no longer has the right to access to the group’s data (neither read nor write access), nor the ability to execute smart contracts that require group membership, including those that require a specific role within a group.  
         2. Should cascade, i.e. if a member is removed from the OE, they should automatically be removed from all the corresponding CUs.  
      2. Note: Adding members to a CU requires them already be members of the OE.  
   4. Advanced: It should be possible for CUs to have other CUs as children.  
      1. However, cyclic dependencies should be impossible.  
7. Discoverability:  
   1. OE: It should be possible for a group member with naming rights to publicly name an OE (e.g. on dotNS).  
   2. CU: It should be possible for a person/account to know/discover all the groups they are members of.  
   3. OE members:  
      1. It should be easy for a member of an OE to get the public key of another member of the OE using the latter’s handle.  
      2. An OE can determine whether they would allow this capability to other OEs or members of the public  
8. Privacy:   
   1. OEs:  
      1. Who the members are of an OE should be private (to the public).  
         1. Note: Meeting this requirement would also satisfy the GDPR right to be forgotten requirement. At least it does in the weak sense where the person’s PII doesn’t get captured on-chain.  
      2. Within an OE membership could either be opaque or transparent to the other members, i.e.  
         1. internally opaque \= one member doesn’t know who all the members are of the OE are  
            1. Note: This requires a discoverability mechanism, e.g. when user A is creating a new CU, they need to be able to add user B, iff they know their handle within the OE.  
         2. internally transparent \= all members know who all other members of the OE are.  
   2. CUs:  
      1. CUs should be secret from anyone who is not a member (unless it is decided by that CU’s admins to add their CU to a discoverability mechanism/service).  
      2. CU membership is secret from anyone who is not a member of that CU (unless the it is decided by that CU’s admins to add their members to a discoverability mechanism/service).  
   3. Documents  
      1. Documents need to encrypted at rest / on the local machine.  
9. To simplify organising: it should be possible for CUs to not just have members as children but also other CUs.  
   1. Cyclic relationships are NOT permitted.  
   2. The policy of members of which OEs are allowed in children CU needs to be defined in the parent CU, i.e. the child CU must have a policy as strict or stricter.  
10. Easy cross-company collaboration:   
    1. It should be easily possible for members of one OE to collaborate with another. E.g. as an author I want to share my document with others in my OE and others in another OE.   
    2. Advanced use case: It should be possible to create a new CU that include members a CU from one OE, and another CU from another OE.  
       1. E.g. a new CU is created where it’s members are inherited/derived from members of the “project x” group in company Y and the “x project” group in company Z.  
11. Post-Compromise Security (PCS) — the cryptographic guarantee that if an attacker compromises a member's current key, they will not be able to decrypt future application data.  
12. Threat models:  
    1. Insider:  
       1. OE admins are afforded more trust, but a single compromised admin should not be able to upload a new OE root hash e.g. where all other members (e.g. employees) are removed.  
    2. Outside:  
       1. Compromised relay: All information on relay nodes need to be encrypted. I.e. it should be impossible for a 3rd party relay node to access the content of documents/data.  
       2. Adversarial nation states: It should impossible for nation states to force 3rd parties to reveal (e.g. relay nodes) to reveal any documents/data.  
13. Acceptable risk:  
    1. If a threshold of FROST administrators lose their keys simultaneously, the OE cannot update its root hash. I.e. a new OE will need to be created from scratch.  
14. Scalability:  
    1. This should work for up to 1000 person OEs with 1% monthly turnover.  
    2. This should work for CUs with up to 100 members spread across up to 3 OEs.  
    3. This should work for OE members that belong to up to 50 CUs.

# **High level proposal**

A purely peer-to-peer local-first network struggles with global identity discovery and objective revocation (e.g. the "Duelling Admins" problem, where a revoked admin backdates their actions to appear valid, or other malicious reads/writes of company data). This problem/struggle is solved by linking local-first data/document collaboration with organizational membership (including identity) verifiable against an on-chain artifact (ie. true at a point in time).

## **Tier 1: Organizational Entities (OEs) — Off-Chain Company Directory Anchored On-Chain**

OEs represent sovereign entities, such as "Company X" or "Co-op Y" or “Club Z”. These groups act as the ultimate cryptographic source of truth for membership (e.g. employment) and roles (i.e. authority needed for smart contracts).

* **Structure**: The simplest way to present OEs are off-chain Merkle trees.  
* **Leaf Composition:** The leaves of this Merkle tree contain the member’s  
  * unique handle,  
  * name and surname,  
  * smart contract roles if any, and   
  * OE public key.  
* **Privacy:**  
  * The blockchain stores **only** the Merkle root of this tree.  
  * OE administrators have access to the whole Merkle tree.  
  * OE administrators distribute to individual members only the part of the tree they need to be able to generate a non-interactive ZKP (such as a zk-STARK), and no more. I.e. it is impossible for a member to see all other members of an OE.  
* **Update cadence:**  
  * The OE Secret Key (OESK) should be updated whenever a member might be compromised, and at a minimum cadence set by the OE.  
* **(Optional) limiting on-chain metadata leaking**:  
  * Through use of smart contracts authorized by ZKPs it might be possible to associate accounts with an OE. However, through hard derivation, Polkadot allows the creation of temporary or even once-off accounts to eliminate the value of this metadata leaking. The ZKP becomes "I know an OE private key such that (a) its corresponding public key is a valid leaf in the Merkle tree under this root hash, and (b) hard-deriving it with this path produces this child public key." This mechanism prevents CU thrashing, because it doesn’t require updating the OE root hash. 

**ZKP choice:**

* zk-STARKS are preferred, because they rely only on collision-resistant hash functions and are considered quantum-resistant. However, this choice is mediated by blockchain ability, because they carry comparatively large proof sizes (40-200 KB) and high on-chain verification costs.   
* If, and only if, the on-chain compute doesn’t suffice, then zk-Groth16 can be used instead as a cheaper alternative (\~200 B and simple pairing check/verification), but, in addition to not being quantum proof, it also requires a trusted setup — The ceremony must be multi-party, ideally ≥10 participants, so no single party can produce forged proofs. The ceremony and its transcripts must be publicly verifiable.  
* Either way, the ZKP circuit should be implemented behind an abstract verifier interface so that the underlying proof system can be replaced without changes to application logic, i.e. the ZKP circuit should be easy to upgrade.

**Combined root hash on-chain update, and OE Secret Key generation:**  
To make sure a new OE Secret Key (OESK) is readily available upon root hash changes, creating the OESK is O(1) measured against members, and to eliminate a single point of compromise (using Frost), this is a 3 step process:

1. An administrator sends a transaction to the root hash updating smart contract with their ZKP (containing their membership and role, which is verified against the old root hash) and the new root hash, but the contract doesn't update the root hash yet.  
2. That same administrator communicates the delta Merkle tree to the other administrators.  
3. Another administrator generates a new OESK shared with a threshold of other administrators and confirms the root hash on-chain — to keep things simple we propose using Shamir's Secret Sharing (SSS) and asymmetric encryption, without the need for real-time interactive rounds:  
   1. Generation: The initiating administrator (the "Proposer") locally generates the new OE Secret Key (OESK) using a cryptographically secure random number generator.  
   2. Splitting: The Proposer immediately uses Shamir's Secret Sharing to split the new OESK into n shares, requiring a threshold of t shares to reconstruct it.  
   3. Distribution: The Proposer encrypts each individual share using the respective public keys of the other n \- 1 administrators and transmits them via a secure off-chain channel to the other administrators.  
   4. Acknowledgement: The receiving administrators decrypt their shares, verify they are valid, and send a simple, digitally signed acknowledgment back to the Proposer.  
   5. Commitment: Once the Proposer receives t \- 1 valid acknowledgments—proving that at least t admins (including the Proposer) now securely hold the ability to reconstruct the key—the Proposer executes the smart contract transaction to update the root hash on-chain with a ZKP (containing their membership and role, which is verified against the new root hash) and confirming the new root hash.

**Distributing of the OE Secret Key (OESK) & part of new Merkle tree via pairwise Double Ratchet:**

* Upon the on-chain update of the OE root hash, members query administrators for the new OESK. Administrators and members establish secure channels using standard pairwise Double Ratchet (i.e. Signal Protocol).   
  * The post quantum PQXDH should be preferred over X3DH. Disclaimer: a fully post-quantum Double Ratchet would require replacing the X25519-based ratchet keys with a PQ KEM, but no practical implementation exists. Also PQXDH is underspecified and will be addressed in its own design doc.  
* Before sharing or trusting the OESK, the new part of the Merkle tree relevant to the member (for constructing ZKPs), and optionally the handles of all the removed or changed members, both parties produce and verify ZKPs of membership (and in the case of the administrator, also their role):  
  * the administrator verifies both the member’s ZKP against the old root hash, and the member is present under the new root hash, while   
  * the member verifies the administrator’s ZKP against the current/new on-chain root hash.  
* **Scalability note**: For a 1,000-member OE with 1% monthly churn, distribution requires up to 1,000/t pairwise ratchet sessions per update cycle (where t is the number of admins with the new OESK). Under the connectivity assumption this is operationally manageable, but it suggest increasing the number of admin nodes as the organisation grows, or providing a key-wrapping relay should be considered as a performance optimisation.  
* **Alternatives considered — TreeKEM**: Would reduce distribution to O(log N), but the OESK and hence the root hash could be stopped from updating if even 1 member is/remains offline (e.g. on vacation).

**OE smart contracts:**  
All other smart contracts that rely on OE membership and role, are similar to the one used to update the root-hash on-chain, except they rely on the current root hash and can be defined require another number of signatures. 

**OE bootstrapping:**  
OEs can be bootstrapped by an initial set of administrators, with a genesis smart contract (relying a ZKP containing their membership and role, which is verified against the proposed initial root hash, just to demonstrate it is well formed) establishing

* the initial root hash,  
* ZKP protocol to use,  
* member and their roles (i.e. at least the initial set of administrators), and  
* the threshold needed for updates.

**Vulnerabilities/Threats:**

1. If a single OE member is compromised, so is the OESK. This is the true and real drawback of distributed collaboration, especially since access will be obtained to all documents shared OE wide. (Note, a compromised login in a traditional centralised control has the same drawback.)  
   1. Note: Detection of whether the OESK is compromised is out-of-scope for this work.  
   2. A simple update of root hash (with new public and private keys of the compromised member, or temporarily omitting the compromised member) and recalculation of the OESK resolves this problem, (but by then the damage of exposed documents and data on the user’s machine is already done).   
   3. A mitigation measure could be smarter relays that only share data with machines that can present valid ZKPs, but that only helps if only the OESK was compromised and not the whole member device (i.e. access to the documents/data).  
   4. Another mitigation measure could be using the OESK and OEPK in the CUs to construct the per document encryption, but again this only helps if only the OESK was compromised and not also access to all the CUs (which is possible if the whole member device is compromised).  
2. Two administrators can collude, e.g. to remove all members of an organization except for themselves. Choose your administrators carefully, or set up your OE to require more administrator signatures for root hash updates and OESK creation.  
3. Similarly, multiple administrators can submit competing new root hashes, but the first completed update process will win, since blockchain are strictly ordered, and updates depend on the preceding/old root hash, i.e. the first updated accepted will change the root hash, and make the other transaction fail.  
4. It is unlikely, but possible for a malicious actor to compromise just enough admin keys to prevent the threshold from being reached, effectively freezing the OE's ability to ever revoke anyone again.  
   1. In this extreme case mitigation could be to temporarily place all admins on a virtual private network to gain consensus on the new OESK, and with new keys for all the compromised administrators. This would be an emergency last-resort action, and it relies on out-of-band trust.  
5. Soon to be revoked members can still generate valid ZKPs till the root hash has been updated. This is deemed acceptable, under the assumptions that   
   1. the root hash update process can be completed within minutes, and  
   2. if the to be revoked members knew in advance of their upcoming revocation they can do all the malicious things they wanted to well before the root hash change process even started.  
6. There is no maximum time specified in this design for the process to complete root hash update and new secret calculation. This is not considered that important, because no information about changes in membership status has been leaked, nor does it affect the members ability to collaborate. But, this is trivial to add.  
7. Blockchain transaction cost: A blockchain with unreasonable spikes in transaction cost will be ill suited, as it could price out root hash updates. Unacceptable especially of a key has been compromised and the update is to fix the security hole.   
8. Blockchain transaction reliability/throughput: This is even worse, as the cost problem might be fixed by unreasonable amounts of money, if a blockchain is overwhelmed with traffic and not allowing root hash updates required to fix critical security problems, that is completely unacceptable.

## **Tier 2: Collaboration Units (CUs) — The Off-Chain Collaboration Mesh**

With OE membership resolved, specifically the point-in-time when it changes (new OE root hash gets published). This reduces collaborator trust to “that ex-member is no longer trusted from that point-in-time”. So access control with collaborators can be maximally decoupled from OEs (1) to keep the OE data structure simple, and (2) to enable collaborations to otherwise be completely established and maintained peer-to-peer (with the added advantage of secrecy). 

The set of collaborators so established and their rights we call a Collaboration Unit (CU). CUs represent specific teams, projects, or ad hoc groups. There is a document/data associated with the CU, which members of the CU collaborate on. 

The two key elements of CUs are the sync gate and the trust promotion gate. The sync gate allows syncing of changes, based on ZKPs against the last known OE root hash. Changes that pass the sync gate enter the unverified window, where they await trust promotion. The trust promotion gate takes the unverified window of changes, since the last time the OE root hash was read till when it was read now, to either promote to trusted or to discard all those changes.

* **Structure:** CUs are constructed entirely off-chain using (established) peer-to-peer technologies for creating group secret keys, e.g. CRDTs.   
* **The Cryptographic Link:** 	  
  * To become, or continue to be, a CU member, said member must cryptographically (ZKP) prove they belong to an associated OE.  
  * A member’s handle is the link between OEs and CUs, because it is constant and unique in the OE.   
    * OEs are focused on members, and their metadata.  
    * CUs are focused at the member device level:  
      * The member’s keys are derived from their device keys. (Therefore, keys on a CU are likely to rotate more frequently than on an OE.)  
* **Heterogeneity**: Appropriate stack can be chosen on a per CU basis (see [Underlying technology](#underlying-technology)).  
  * There might be limitations in heterogeneity when creating CUs with other CUs as members though.  
* **Sync gate:**  
  * Determines whether or not to accept changes from collaborators.  
  * At creation or upon a change in the OE root hash treats all collaborators as untrusted, i.e. does not accept document syncing.  
  * Promotes collaborators to trusted status upon receiving ZKPs that are verified against the (locally securely stored / lastest read) OE root hash, i.e. accepts document syncing and places changes in the unverified window.  
* **Trust promotion gate**:  
  * The simplified collaboration lifecycle is essentially:  
    * Received: change arrives from a collaborator (via the sync gate).  
    * Unverified/Pending: sits in the untrusted window; not yet promoted.  
    * Promoted to trusted (or discarded): only once the device can read the current OE root hash AND every collaborator with edit rights in that window has provided a valid ZKP against it.  
  * This means OE membership revocation, e.g. an employee being removed from the OE, is enforced naturally: the removed member cannot produce a valid ZKP against the new root hash, so the unverified window they are part of is never promoted, and their changes are discarded. More precisely, publishing a new OE Merkle root hash triggers:  
    * All changes in any unverified window that includes the revoked member are rejected — it is impossible to backdate past this gate, because trust promotion is anchored to the current on-chain root hash, not to the claimed timestamp of a change.  
    * A re-keying of the encryption protecting associated data/documents, effectively revoking the removed member's read access going forward.  
  * Changes are never "trusted then clawed back" — they are held as unverified until membership can be confirmed.  
  * The untrusted window is a queue that grows during offline collaboration, not a history that gets rewritten.  
    * This window grows the longer a device collaborates without access to the latest root hash, e.g. during offline work or offline collaboration.  
* **Potential gates simplification**: If an OE is willing to communicate which members have been removed as part of a root hash update, the gates processes can be significantly simplified, especially the trust promotion gate, because  
  * CU admins can immediately remove all ex-members, and   
  * similarly, CU members can check whether to stop sharing and whether a new secret is required for their CU, based on whether it contains any ex-members.  
* **Document shared at OE level**: If a data/document is (read) shared with the entire OE the document encryption and distribution gets re-encrypted immediately upon receiving the new OESK.  
* **Offline collaboration**: The sync gate allows offline collaboration, verified against the latest OE root hash both parties hold (if they hold different OE root hash values this fails by default). But, those document changes will only be approved/rejected once they go online again and read the latest OE root hash.  
* **Key independence:** Each CU maintains its own symmetric encryption key, independent from its parent CU and the OE Secret Key. This avoids re-key cascades across nested CU hierarchies, at the cost of requiring access to be explicitly granted at each level.  
* **Encrypted at rest**: OE membership revocation only “really” works if all documents/data are encrypted at rest. Otherwise, mechanisms such as backups make it too easy to defeat to gain access to old information.  
* **Limited privacy**: No one who is not a member of a CU will know who the members of a CU are, but all members of a CU are visible to all other members.  
* **OE root hash into CU update journey:**  
  * The user app listens for changes in relevant OE root hash(es).  
  * Upon detecting a change, sync gating kicks in, i.e. it immediately halts syncing, but ZKP exchanges continue so syncing can be re-instated.  
    * I.e. all syncs are stopped, and only re-instated once the collaborator has proven themselves to still be a valid member of their OE.  
  * If it learns (from the administrators) that they are no longer part of the OE:  
    * It immediately deletes all associated documents/data.  
    * Bonus: Communicates to all CUs (using ZKP based on previous root hash) that it is no longer a member of the OE. This is useful in [cross-company federation](#cross-company-federation), or if the administrators don’t communicate all the removed members as part of the OE update.  
  * If it learns (from the administrators) that they are still a member (and all the corresponding data):  
    * Establishes new CU secret keys as needed with others online who can prove they are still members of the relevant OE  (based on ZKP with new root hash).  
      * Prioritized based on unverified or pending changes in the trust promotion gate, and first on documents/data being actively collaborated on.  
      * To minimise the need for unnecessary new key generation (i.e. minimize CU CRDT bloat), only generate a new shared secret key in the CU if the shared secret key, of the set of proven valid members trying to actively collaborate, relies on a member who is offline and has not yet proven themselves vis-à-vis the latest OE root hash.  
      * Note: documents/data shared with the entire OE is re-encrypted using the new OESK.  
    * Re-encrypting documents/data with new keys as needed.  
    * Start relaying/distributing encrypted documents, but only with members with valid ZKPs, and only the documents relevant to them.  
      * Note this presupposes p2p distribution. Basic relay nodes won’t be able to assess this, because CUs are invisible to them.  
* **Offline work isn’t lost**: If a member goes offline for a 3-week field assignment, and the OE root hash updates in week 1, the three weeks offline work is treated as pending, until the trust promotion gate marks the window as trusted, and so their work will be synced/integrated.  
  * **Working offline with an ex-member won’t be accepted**: The counter example is if said member collaborated on a document during those 3 weeks with someone who lost their OE membership in week 1, then the unverified window containing their joint work will be discarded by the trust promotion gate once the new OE root hash is read. The same is true for any updates that are made to CUs themselves.

**Vulnerabilities/Threats**

* Timestamp Spoofing and Clock Drift attacks are nullified, because the trust promotion is anchored to the on-chain root hash, not to claimed timestamps. The spoofed timestamp doesn't move the gate. Malicious actors (ex-members) cannot bypass the trust promotion window by spoofing off-chain timestamps, because the window measures when the changes are received. The system effectively discards any updates from ex-members, as well as any updates from valid members who synced with ex-members while offline.  
* While relay nodes cannot read the encrypted documents, the metadata (who is syncing with whom, size of payloads, frequency of updates) remains visible. This metadata can map out a company's entire organizational structure and identify key projects.  
  * Potential mitigations:  
    * Restrict OE traffic to OE endorsed relay nodes  
    * Use purely p2p distribution, but then take care on how peers are found and how to backup documents that only a single member can access.  
* CU CRDT bloat due to key changes could be a problem, but this isn’t new to this proposal, but inherent to the technology. That said only recalculating new CU keys if needed e.g. on membership change, this can be minimized.  
* If CU has a single admin and that admin gets removed as an OE member, the CU group membership and roles cannot be modified.   
  * Mitigation: Randomly assign new administrator (after CU deadtime expired).

### **Cross-Company Federation** {#cross-company-federation}

Because CUs are largely decoupled from OEs, cross-company collaboration becomes trivial. If Company X and Company Y form a joint project, a new CU is created. The access control policy for this specific document simply states: *"Accept ZKPs that validate against the Merkle Root of Company X OR the Merkle Root of Company Y."*

This enables mathematically verifiable federation. Neither company surrenders control of their identity management to the other, no complex LDAP federation bridges are required, and the underlying users remain entirely self-sovereign.

### **Underlying technology** {#underlying-technology}

#### **Keyhive/BeeKEM or p2panda-auth/-encryption**

The two top underlying technologies for CUs, i.e., technologies that manage access control for local-first collaboration, are Keyhive/BeeKEM and p2panda-auth/-encryption. Either can be chosen as the underlying implementation depending on organizational or even project/collaboration needs, i.e. it is possible to choose the appropriate stack per CU.

Both libraries would need to be adapted (see [Wrapping](#wrapping) below) to work as CUs, and with different trade-offs, the headlines being:

1. That Keyhive/BeeKEM gives you   
   1. O(log N) key updates (needed for at least every OE root hash change), and   
      2. deep CRDT integration (e.g. Automerge)  
   2. at the cost of   
      1. more work needed to handle nested CUs and Federated CUs.  
2. While p2panda-auth gives you  
   1. a cleaner capability token model and   
      2. better native support for nested groups and federation,   
   2. at the cost of   
      1. O(N) key wrapping cost, and  
      1. more custom CRDT collaboration software integration.

See [Addendum: Keyhive/BeeKEM vs p2panda-auth/-encryption](#addendum:-keyhive/beekem-vs-p2panda-auth/-encryption) for more details.

*Caveat emptor: Both libraries are at pre 1.0 release.*

#### **Wrapping** {#wrapping}

Neither underlying technology works as-is for CUs. Both must be wrapped with a common **OEValidityGate** component that:

* binds CU membership to current OE validity,  
* places inbound changes into the unverified window,  
* promotes a window to trusted once all edit-rights holders have verified, and  
* discards a window when a member fails verification or the deadline expires.

`OEValidityGate`  
  `├── constructor(oeIds: Set, members: Set<{handle, oeId}>) → void`  
  `│# oeIds:   the OEs whose members are permitted in this CU`  
  `│# members: initial member set;`  
  `│# 		each member untrusted until proven otherwise`  
  `├── verifyMembershipZKP(proof, handle, oeId) → bool`  
  `│# Validates a member using the current OE root hash`  
  `├── hasValidZKPForCurrentEpoch(handle, oeId) → bool`  
  `│# returns true iff the member already proved current OE membership`  
  `│# reads from secure local storage`  
  `├── subscribeToRootHashUpdates(oeId, callback) → void`  
  `│# callback payload: { newRootHash, revokedHandles?: Set<handle> }`  
  `│# revokedHandles present only if OE communicates removals explicitly`  
  `│# (see "Potential gating simplification" in CU section)`  
  `├── getCurrentOERootHash(oeId) → rootHash`  
  `│# reads from encrypted local store`  
  `│# updated atomically with OESK on each epoch change`  
  `├── receiveSync(changes, authorHandle, oeId) → void`  
  `│# places changes in unverified window`  
  `├── promoteWindow(windowId) → bool`  
  `│# promotes if all edit-rights holders have valid ZKPs`  
  `└── expireWindow(windowId) → void`  
    `# discards window after CU deadline`

**Keyhive/BeeKEM** — the trust promotion gate operates as a pre-admission filter on the sync/transport layer: 

* **On OE root hash change**: All other members are immediately locally untrusted. A BeeKEM group key update is triggered only if the current shared secret has a dependency on a member who cannot yet pass *hasValidZKPForCurrentEpoch*. Members are reinstated as they re-prove membership, or fully dropped when the CU deadline expires. If *revokedHandles* is provided, those members are hard-removed immediately without waiting for the deadline.  
* **On every inbound sync**: Only syncs from authors verified against the last known OE root hash are accepted. The gate inspects authorship of every operation in the incoming DAG and places the payload into the unverified window, tagged by author. Any causal branch, or the entire payload, whose author lacks *hasValidZKPForCurrentEpoch* before the deadline is discarded from the window and never promoted. This prevents both backdating and mule attacks, since promotion is determined by the author's OE membership during the window (from start to finish), not by the operation's claimed causal position or the transmitting peer's own validity.

**p2panda-auth/-encryption** — the trust promotion gate operates at capability issuance and sync verification:

* **On OE root hash change**: A capability epoch rotation is triggered, and all other members are immediately locally untrusted. If *revokedHandles* is provided, the mentioned members' tokens are invalidated immediately and all remaining members are promoted to trusted and hence the rotation is issued to them. Otherwise, all members must present a freshly minted token tied to the new OE root hash before they can participate (i.e. be promoted to trusted and issued the rotation).  
* **On every inbound sync**: Only bamboo log entries from members verified against the last known OE root hash are accepted. Those are held in the unverified window until the OE root hash is checked again, and if they are confirmed to still be valid, only then are those log entries promoted to trusted. Because p2panda uses per-author logs rather than a shared DAG, a member who fails to re-prove membership can have their entries discarded cleanly without affecting the promotion of valid peers' independent work. Each capability token embeds its issuing *oeId*, so the gate can verify and promote changes from members across multiple OEs against their respective root hashes — supporting cross-company CUs natively.

### **Alternatives considered/rejected**

* OEs:  
  * Certificate Transparency-Style Append-Only Logs as a Blockchain Alternative:   
    * With a public blockchain, any two companies can independently verify each other's root hash state without prior agreement on which log to trust.  
    * Won’t work as easily with smart contracts.  
    * Updates (i.e. log append writes) to a CT log need an API to protect it, which means 3rd party trust is needed, whereas blockchain updates are trustless.  
    * A complete CT log, even a well-monitored one, depends on the integrity of the log operator(s) and the vigilance of independent monitors, whereas a blockchain is trustless.  
* CUs:  
  * Any kind of centralized CU access control.  
  * Any kind of CU access control that require all members to be online to update keys, e.g. TreeKEM based.  
* Combined OE and CU  
  * This would require the new data structure to become a DAG (increased complexity), more regular on-chain root hash and OESK updates (i.e. vulnerable to thrashing in large orgs with too many team updates), and cross company / federated collaboration isn’t easy anymore.

# **Open questions / further work**

1. **Collaborating with individuals**: Individuals might simply be identified as they classically would be in local-first software (i.e. as per paradigm used in the CU implementation). So removing them from a CU needs to be manually done, but they are always trusted.  
2. **Passkeys**: This could make security more easy to use for most users.  
3. **Relay nodes**: Relay nodes need to stop relaying old encrypted files immediately upon OE changes. If relay nodes were OE specific that could be as simple as a complete flush of files upon OE root hash change.  
4. **Offline CU cycle prevention**: A mechanism for enforcing DAG acyclicity for purely off-chain CUs (without on-chain ID assignment) needs to be designed if offline CU creation is required.  
5. **Search**: Any document search would need to be implemented on the user devices, and integrated into the app, because documents are encrypted at rest.  
6. **OE member key recovery**: Encrypted blobs containing private key shards for account recovery, can be included in the as part of the member information.  
7. **Minimize the impact of individual key rotation**: If the key pair used in an OE is compromised this triggers a new root hash, which for a 1000 person company is a heavy response to a single key – this is unavoidable, because it is assumed that the OESK will be compromised along with it.   
   1. Furthermore, by restricting OEs to member keys, and using device keys in CUs, if device is stolen or device key compromised, then the key rotations/updates are computationally cheaper, because they are restricted to CUs.

# **Addendum**

## **Addendum: Keyhive/BeeKEM vs p2panda-auth/-encryption** {#addendum:-keyhive/beekem-vs-p2panda-auth/-encryption}

While both Keyhive/BeeKEM and p2panda-auth solve the fundamental problem of decentralized access control, they approach the challenge from distinct architectural philosophies. Consider the following table for the differences, specifically evaluated against the operational requirement for the dual gating mechanism:

| Architectural Dimension | Keyhive/BeeKEM | p2panda-auth/-encryption |
| ----- | ----- | ----- |
| **Core Access Control Model** | Convergent Capabilities (Concaps). Access is delegated across a continuous, stateful Automerge CRDT graph. | Explicit, cumulative roles (Pull, Read, Write, Manage) enforced via a Causal-Length CRDT Directed Acyclic Graph (DAG). |
| **Group Key Agreement Math** | BeeKEM (Decentralized TreeKEM / CGKA). Utilizes a binary tree, Diffie-Hellman operations, and BLAKE3 KDFs. O(log N) per membership change.  | Dual Scheme: Double Ratchet for ephemeral messaging; Symmetric Data Encryption for persistent state. O(N) on membership change.  |
| **Unverified Window / Trust Promotion Handling** | The unverified window is managed at the transport layer as a pre-admission filter. Inbound changes are held, tagged by author, and only promoted once all edit-rights holders pass hasValidZKPForCurrentEpoch. Window discard is handled by dropping the entire causal branch or payload associated with the non-promoting author. Because Automerge preserves full causal history, window discard requires relay interruption and accepts data loss as the cost of clean removal — partially tainted branches cannot be surgically excised without risking CRDT state divergence. | The unverified window maps naturally onto per-author Bamboo logs held pending capability verification. Trust promotion is tied to presenting a valid current-epoch capability token against the new root hash.  Because each author maintains an independent log rather than contributing to a shared causal graph, window discard for a non-promoting author is clean and surgical — their entries are dropped without affecting the promotion of any other author's independent work. Transitive invalidation via the Resolver trait handles causal descendants of discarded entries deterministically. |
| **Concurrency Resolution** | Mathematical resolution of conflict keys. Nodes calculate the highest non-blank descendants and merge diverging tree branches simultaneously. | Pluggable Resolver trait. Triggers deterministic transitive invalidation of causal descendants upon conflict or revocation. |
| **Forward Secrecy (FS)** | Provided by periodic Update Key operations, though practically constrained by the application's need to traverse causal document history. | Absolute FS available via Double Ratchet for streams; optional/manual FS for the symmetric Data Encryption scheme. |
| **Post-Compromise Security (PCS)** | Native and continuous. An attacker cannot decrypt future data after a legitimate leaf node rotates their key via an Update Key operation. | Native and enforced. Immediate symmetric key rotation is forced across the group upon any member removal or demotion. |
| **ZKP Integration Suitability** | High. The identity-agnostic nature of concaps makes injecting ZKP validation at the transport/network layer seamless. | Exceptionally High. Explicit architectural support for "Custom Access Conditions" allows direct ZKP payload injection into operation headers. |
| **Concurrent Membership Changes** | Handles concurrent add/remove via causal DAG; BeeKEM merges deterministically. | Concurrent ops sequenced per-author log; admin conflicts require explicit policy. |
| **CRDT Integration** | First-class — designed for Automerge; access control and ops share the same causal graph. | Document ops separate from auth layer; integration via capability checks at app level. |
| **Offline / Local-First** | Fully local-first; peers carry capability proofs inline with ops | Fully local-first; Bamboo logs are self-certifying and operable entirely offline |
| **Nested CU Support** | Possible via capability delegation; BeeKEM tree composition across groups is non-trivial | Cleaner support via capability token hierarchies; parent CU can issue scoped tokens to child CU admin key |
| **Cross-OE Federation** | Designed for single-org; multi-root ZKP verification requires the OE Validity Gate wrapper | More naturally multi-tenant; capability tokens can encode external issuer OE identity |
| **Maturity** | Research / early production (Ink & Switch / Fission); API may be unstable | More production-oriented; used in real deployments |

