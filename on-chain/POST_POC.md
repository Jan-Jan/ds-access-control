# Post-PoC TODO — `on-chain/`

Forward-compatibility work deliberately deferred from the Stage 1 PoC. The
current `OrgRegistry.sol` ships a minimal, non-upgradeable contract; this
document captures what must change before any mainnet deployment, the
constraints driving each change, and the full architectural rationale for
why UUPS (rather than redeploy + migrate) is the recommended path.

> **TL;DR.** The PoC contract is a research artifact, not a mainnet
> commitment. Before mainnet — and crucially, before any cross-org
> contract launches against this address — migrate to a UUPS-proxied
> design. Retrofitting UUPS onto a contract with live dependents is the
> expensive path; doing it once, before external dependencies exist, is
> cheap.

---

## Why the PoC is intentionally simple

The current `OrgRegistry.sol` (49 lines) is the minimal viable anchor:

- **Non-upgradeable.** No proxy, no admin, no pause switch.
- **`orgPubKey` is opaque `bytes32`.** No explicit key-type discriminator.
- **`orgs` mapping is `private`.** No cross-org reads from other contracts.
- **No `VERSION` constant.** No on-chain self-identification.
- **Single audit boundary.** ~20 lines of logic.

This is correct for the PoC because:

1. **Scope discipline.** Phase 1.b validates that the off-chain trie has a
   working on-chain anchor. Anything beyond that is premature complexity
   that grows the audit surface and slows iteration.
2. **No cross-org composition yet.** Phase 1 orgs are independent; no
   contract reads another org's state. Public getters and explicit
   key-type fields are not load-bearing.
3. **Ed25519 fits in 32 bytes.** While Ed25519 is the only scheme in use,
   opaque `bytes32` storage is sufficient and self-describing schemes add
   cost without benefit.
4. **Migration is cheap when the population is small.** Moving a handful
   of test orgs to a successor contract is trivial; the calculus changes
   when dozens-to-hundreds of production orgs and downstream contracts
   depend on the address.

The PoC contract will not be the mainnet contract. The bytecode that comes
out of Stage 1 is a research result, not a permanent commitment.

---

## Pre-mainnet TODO checklist

### Architectural

- [ ] **Migrate to UUPS proxy pattern.** Single permanent address;
      structured upgrade path. See "UUPS, explained" below.
- [ ] **Verify pallet-revive supports `delegatecall` faithfully.** UUPS
      depends on it. Add a sanity test that deploys a proxy + impl pair
      and exercises a round-trip on chopsticks-forked Paseo AH before
      committing to the design.
- [ ] **Define the upgrade authority.** Recommended: a Polkadot pure
      proxy controlled by a project multisig (e.g. 3-of-5 maintainers)
      plus an on-chain timelock (24–72h) on `_authorizeUpgrade`. This
      mirrors Polkadot's governed-runtime-upgrade model and will feel
      native to users.
- [ ] **Plan two governance-defined sunset events:**
  1. Flip the upgrade authority to a DAO / on-chain governance once the
     project matures.
  2. Optionally freeze upgrades entirely (set authority to `address(0)`)
     once PQ migration is complete and the protocol is stable —
     "training wheels off" pattern.
- [ ] **Integrate `@openzeppelin/upgrades` plugin** into the build to
      validate storage-layout compatibility between versions. Reordering
      a struct field silently corrupts every org's state; the plugin is
      the only practical guard.

### Storage model (driven by cross-org composition + PQ migration)

- [ ] **Drop `private` on `orgs` (or add an explicit `getOrg(address)`
      view).** Required for cross-org composition: any contract or
      off-chain client needs to read another org's state without
      out-of-band knowledge.
- [ ] **Add an explicit `orgKeyType` discriminator.** Cross-org consumers
      cannot be expected to know an org's key scheme out-of-band. A
      `uint8` is enough (256 schemes); reserve values for Ed25519 (the
      current default), sr25519, BLS12-381 G1, and at least Dilithium/
      Falcon for the PQ horizon.
- [ ] **Switch `orgPubKey` from `bytes32` to `bytes` (variable length).**
      Dilithium keys are ~2.5KB; Falcon ~900B. They will not fit in 32
      bytes. Decide whether the on-chain blob holds the raw key, or a
      hash with the blob in a separate mapping (cheaper for cross-org
      reads that don't need the material).

### Documentation / process

- [ ] **Add a `VERSION` constant** to the impl contract. Constants live
      in bytecode, not storage, so they cost nothing. Off-chain clients
      use it as a cheap sanity check against the impl they think they're
      talking to.
- [ ] **Document `orgPubKey` semantics in code.** Whether opaque or
      self-describing, the comment should make the assumption explicit
      so a future reviewer doesn't break it accidentally.
- [ ] **ABI versioning strategy.** Keep `abi/OrgRegistry-vN.json`
      artifacts in-repo; cross-org consumers pin to a version.

### External

- [ ] **External smart-contract audit before mainnet.** The PoC's
      simplicity makes a future audit cheap; the UUPS variant materially
      increases the surface (proxy, initializer, upgrade authorization,
      storage layout discipline). Budget accordingly.

---

## UUPS, explained

### The pattern

A **proxy** is a tiny contract whose only job is to `delegatecall` every
incoming call into an **implementation** contract. `delegatecall` is
special: it runs the implementation's *bytecode* in the proxy's *storage
context*. So:

```
              User
               │
               ▼
        ┌──────────────┐
        │    Proxy     │ ← stable address, holds all storage
        │   (~20 LoC)  │
        └──────┬───────┘
               │ delegatecall
               ▼
        ┌──────────────┐
        │  OrgRegistry │ ← logic only, no persistent state
        │     impl     │
        └──────────────┘
```

Storage lives at the proxy. Code is fetched from the implementation. To
upgrade: deploy a new implementation contract, then atomically change
the proxy's "current implementation" pointer.

**UUPS** (Universal Upgradeable Proxy Standard, EIP-1822) puts the
upgrade machinery in the *implementation*, not the proxy. The
implementation exposes an `upgradeTo(newImpl)` function with access
control; the proxy is dumb. This is the modern OZ recommendation; it
supersedes the older **Transparent Proxy** pattern, which put the upgrade
machinery in the proxy and added per-call gas overhead because the proxy
had to distinguish admin calls from user calls.

### Implementation slot (EIP-1967)

The proxy needs somewhere to store "which implementation am I pointing
at?" To avoid colliding with user storage, that pointer lives at a
deterministic high slot:

```
keccak256("eip1967.proxy.implementation") - 1
= 0x360894...3bc
```

Every EIP-1967 proxy uses this exact slot, so tooling (block explorers,
Tenderly, OZ's `upgrades` plugin) can locate the impl without reading
bytecode.

### What it looks like in code

```solidity
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract OrgRegistry is Initializable, UUPSUpgradeable {
    address public upgradeAuthority;
    mapping(address => OrgState) private orgs;

    // Replaces the constructor; constructors don't run for proxied
    // contracts because the proxy never deploys the impl's code in its
    // own context.
    function initialize(address authority) external initializer {
        __UUPSUpgradeable_init();
        upgradeAuthority = authority;
    }

    // OZ requires you implement this; it gates `upgradeTo`.
    function _authorizeUpgrade(address newImpl) internal override {
        require(msg.sender == upgradeAuthority, "not authorized");
    }

    function update(...) external { /* unchanged */ }
}
```

**Deploying:**
1. Deploy the `OrgRegistry` implementation contract (its constructor
   runs but does nothing useful).
2. Deploy `ERC1967Proxy(implAddr, initCalldata)` where `initCalldata` is
   `abi.encodeCall(OrgRegistry.initialize, (authority))`.
3. From this point on, everyone interacts with the proxy address.

**Upgrading:**
1. Deploy `OrgRegistryV2` implementation.
2. The authority calls `proxy.upgradeToAndCall(v2Addr, migrationCalldata)`.
3. Storage at the proxy is untouched; V2's code now interprets it.

### Storage rules (the part that bites)

For an upgrade to be safe, V2's storage layout must be a strict extension
of V1's:

- **Existing variables stay at the same slot, in the same order, with
  the same type.** Reordering, changing a `uint256` to `int256`, or
  changing a struct's field order → silent state corruption.
- **New variables go at the end.** A new mapping, a new top-level
  field, a new field appended to an existing struct — fine.
- **No deletes.** Removing a variable shifts everything after it.
  Replace its definition with a placeholder of the same size and stop
  using it.
- **No reordering within structs** — especially structs stored in
  mappings (each mapping entry's slots are computed from the struct
  layout).

OZ's `@openzeppelin/upgrades` plugin validates these constraints
automatically and refuses to deploy a V2 whose layout is incompatible.
Do not attempt upgrades without it.

### Pallet-revive caveats

Pallet-revive is EVM-compatible but pre-stable. Verify before committing
to UUPS:

- Does `delegatecall` work? (It is in the EVM spec; pallet-revive aims
  for EVM compat, but the surface is still evolving.)
- Does the EIP-1967 storage slot derivation produce the same layout? (It
  should — keccak-based, no chain-specific tweaks.)
- Does revive's instantiation flow let you deploy with constructor args
  (the proxy needs them)? Stage 1 already proved `instantiateWithCode`
  works for code+data.

The Stage 1 chopsticks sanity exercises `instantiateWithCode`. A sibling
sanity should be added that deploys a proxy + impl pair and round-trips
a `delegatecall` before the design is locked in.

---

## UUPS vs Redeploy-V2 — full trade-off table

| Concern | UUPS | Redeploy V2 |
|---|---|---|
| **Stable address for cross-org consumers** | ✅ Forever. Downstream contracts hardcode the proxy and never re-deploy. | ❌ Address changes per version. Need a "registry of registries" or off-chain config to discover the current version. Downstream contracts must redeploy to point at V2. |
| **Migration coordination** | One transaction by the authority. All orgs move atomically. | Per-org: each pure proxy calls `update(...)` on V2 to republish state. Orgs that never migrate are stranded on V1. |
| **PQ migration cost** | Low. Deploy V2 impl, flip the pointer, done. | High. Hundreds-to-thousands of orgs each coordinate their pure-proxy multisigs. Stragglers stay on Ed25519 indefinitely — exactly the threat you're migrating away from. |
| **Centralisation / trust** | ❌ Someone holds the upgrade key. Mitigations: multisig + on-chain timelock + transparent governance. | ✅ No upgrade authority. Anyone can deploy V2; adoption is per-org. |
| **Audit surface** | Larger. Proxy, initializer, `_authorizeUpgrade`, storage layout discipline. Wormhole-style "uninitialized implementation" attacks are real. | Smaller. Each version is a standalone contract; migration is userland calls. |
| **Storage discipline** | Strict. One mistaken reorder corrupts every org's state. OZ plugin mandatory. | None. Each version starts fresh. |
| **Gas overhead per call** | ~2.5k extra (one `DELEGATECALL`, one `SLOAD` for impl slot). Trivial for ODS's update frequency. | Zero. |
| **Composability with other contracts** | ✅ Other contracts can `IOrgRegistry(PROXY)` once and never update. | ❌ Hardcoded V1 addresses break on V2. Forces a coordinated redeploy of all downstream contracts. |
| **Recovery from a buggy impl** | Roll back to previous impl with a single tx. | Bug in V2 means V2 stays buggy or you ship V3; the population fragments. |
| **Alignment with Polkadot model** | ✅ Polkadot itself runs on governed runtime upgrades. UUPS with a pure-proxy authority mirrors this. | Different model: no upgrades, just successor deployments. |

### Where each one breaks down

**UUPS breaks down if:**
- You can't agree on an upgrade authority that's politically acceptable
  to org operators. (Who watches the watchers?)
- Pallet-revive doesn't support `delegatecall` faithfully — discovered
  during some future runtime upgrade.
- Storage discipline slips and a junior dev reorders fields in V3.

**Redeploy V2 breaks down if:**
- Cross-org consumers can't tolerate a moving target. (They have to
  consult something to learn "current address". That something becomes
  the new permanent contract you wanted to avoid.)
- PQ migration urgency exceeds organisational coordination capacity.
  (Imagine a Dilithium-mandate deadline and 30% of orgs haven't moved.)
- A downstream ecosystem grows: every cross-org collab contract has to
  redeploy alongside.

---

## Recommended path: hybrid

Given the eventual cross-org composition + PQ migration requirements:

**Phase 1 (now, this PoC): keep it simple.** The current
`OrgRegistry.sol` is correct as a research artifact. No proxy. No
`orgKeyType`. No cross-org getters. The simplicity lets you iterate on
the off-chain trie design without simultaneously absorbing UUPS
complexity.

**Phase 2 (before any cross-org contract launches, before mainnet):
UUPS-from-the-start V2.** Treat the move from PoC to V2 as a known,
planned forced redeploy event. There are no production deployments to
migrate yet, so the cost is just "rerun the deploy script with a new
contract." From this point on, the proxy address is permanent and
upgrade-driven.

**The mistake to avoid:** retrofitting UUPS into an already-deployed,
already-depended-on contract. That puts you in the worst position —
needing both the migration ceremony (because the old address has
dependents) *and* the proxy discipline (because the new one is
upgradeable). Doing it once, before any external dependencies exist, is
much cheaper and lower-risk.

---

## Open questions for the V2 design

The following decisions are deliberately deferred but will need
resolution during Phase 2 / V2 design:

- **Upgrade authority membership and threshold.** Who specifically holds
  the multisig keys? What's the threshold? What's the timelock duration?
- **Sunset trigger for the authority.** What event flips upgrade
  authority to governance? What event freezes upgrades entirely?
- **`orgKeyType` value allocation.** Which integer means which scheme?
  Document in a shared registry to avoid drift between the contract,
  org-members, and any cross-org consumer.
- **Storage layout for variable-length `orgPubKey`.** Inline `bytes` in
  the struct vs. side-mapping vs. on-chain hash + off-chain blob — gas
  vs. cross-org-read cost.
- **Cross-org read access control.** Fully public, or gated by some
  permission scheme (e.g. orgs can opt out of being readable by
  non-members)?
- **Backwards-compat reads during PQ migration.** If org A has migrated
  to Dilithium but org B hasn't, cross-org consumers must handle both.
  Define the dispatch contract before V2 ships.
