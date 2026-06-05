// Deploys OrgRegistry to a running chopsticks Paseo AH fork via
// pallet-revive's `instantiateWithCode`, then reads `Revive.PristineCode`
// for the deployed code hash and asserts it matches the locally-computed
// keccak-256 of the blob. Exits 0 on success, non-zero on any mismatch.
//
// Deviations from plan template (discovered at implementation time):
//   - resolc v1.1.0 emits <source>:<ContractName>.pvm, not .polkavm.
//     BLOB_PATH default updated accordingly.
//   - instantiateWithCode live arg order (from meta.toHuman()):
//       (value, weightLimit, storageDepositLimit, code, data, salt)
//     Template had code as first arg which would have been rejected.
//   - storageDepositLimit is a required Compact<u128>, not an Option.
//     Using a generous limit of 10_000_000_000_000n.
//   - pallet-revive uses keccak-256 (not blake2-256) as the PristineCode
//     storage key. Confirmed empirically from chopsticks-forked Paseo AH.
//   - weightLimit refTime capped at 1_000_000_000_000n (below the chain's
//     per-extrinsic limit of 1_599_875_000_000n) to avoid exhaustsResources.

import {ApiPromise, Keyring, WsProvider} from '@polkadot/api';
import {keccakAsHex} from '@polkadot/util-crypto';
import {readFileSync} from 'node:fs';

const RPC_URL   = process.env.RPC_URL   || 'ws://localhost:8000';
const BLOB_PATH = process.env.BLOB_PATH || 'tmp/revive/OrgRegistry.sol:OrgRegistry.pvm';

const blob      = readFileSync(BLOB_PATH);
const localHash = keccakAsHex(blob);
console.log(`local code keccak-256: ${localHash}`);

const api   = await ApiPromise.create({provider: new WsProvider(RPC_URL), noInitWarn: true});
const alice = new Keyring({type: 'sr25519'}).addFromUri('//Alice');

// Live metadata arg order (verified via api.tx.revive.instantiateWithCode.meta.toHuman()):
//   value, weightLimit, storageDepositLimit, code, data, salt
// refTime and proofSize are capped below the Paseo AH per-extrinsic limits:
//   maxExtrinsic refTime = 1,599,875,000,000  proofSize = 8,388,608
const instantiate = api.tx.revive.instantiateWithCode(
  0,                                                    // value
  {refTime: 1_000_000_000_000n, proofSize: 4_000_000n}, // weightLimit (within block limits)
  10_000_000_000_000n,                                  // storageDepositLimit
  '0x' + blob.toString('hex'),                          // code
  '0x',                                                 // data (constructor args)
  null,                                                 // salt (None → CREATE1)
);

console.log('submitting instantiateWithCode as Alice...');
const result = await new Promise((resolve, reject) => {
  instantiate.signAndSend(alice, ({status, dispatchError, events}) => {
    if (dispatchError) {
      if (dispatchError.isModule) {
        const decoded = api.registry.findMetaError(dispatchError.asModule);
        reject(new Error(`dispatchError: ${decoded.section}.${decoded.name}: ${decoded.docs}`));
      } else {
        reject(new Error(`dispatchError: ${dispatchError.toString()}`));
      }
      return;
    }
    if (status.isInBlock || status.isFinalized) {
      resolve({status, events});
    }
  }).catch(reject);
});
console.log(`included in block: ${result.status.toString()}`);

// Gate on extrinsic-level outcome. signAndSend's dispatchError fires inside
// the callback, but if a System.ExtrinsicFailed arrives in the same event
// batch as the inBlock notification the resolve has already run, so we also
// inspect the events ourselves and fail loudly.
let extrinsicSucceeded = false;
for (const {event} of result.events) {
  if (event.section === 'system' && event.method === 'ExtrinsicSuccess') {
    extrinsicSucceeded = true;
  }
  if (event.section === 'system' && event.method === 'ExtrinsicFailed') {
    const [dispatchError] = event.data;
    let detail = dispatchError.toString();
    if (dispatchError.isModule) {
      const decoded = api.registry.findMetaError(dispatchError.asModule);
      detail = `${decoded.section}.${decoded.name}: ${decoded.docs}`;
    }
    console.error(`FAIL: ExtrinsicFailed — ${detail}`);
    process.exit(1);
  }
  if (event.section === 'revive') {
    console.log(`  event: ${event.section}.${event.method}`, event.data.toHuman());
    // Emit a parseable marker for the Stage 2 Rust harness
    // (tests/scenario_a.rs) when this is the Instantiated event. The
    // contract field is the deployed H160; tests grep for this prefix
    // in stdout. Keeping it here rather than printing only the H160
    // alone preserves the human-readable log format.
    if (event.method === 'Instantiated') {
      const data = event.data.toJSON();
      // Polkadot.js's toJSON shapes Instantiated either as
      // [deployer, contract] (when treated as tuple) or
      // { deployer, contract } (when treated as struct) depending on
      // the runtime metadata. Accept both.
      const contract = Array.isArray(data) ? data[1] : (data && data.contract);
      if (contract) {
        console.log(`DEPLOYED_H160=${contract}`);
      }
    }
  }
}
if (!extrinsicSucceeded) {
  console.error('FAIL: no ExtrinsicSuccess event emitted; deploy outcome unknown');
  process.exit(1);
}

const pristine = await api.query.revive.pristineCode(localHash);
// pristine.isEmpty alone is codec-version sensitive; also verify the
// underlying byte length so a missing entry is unambiguously detected
// regardless of whether the storage type is Option<Bytes> or bare Bytes.
const pristineLen = pristine.toU8a(true).length;
if (pristine.isEmpty || pristineLen === 0) {
  console.error(`FAIL: no PristineCode entry at ${localHash} (len=${pristineLen})`);
  process.exit(1);
}
// pristine.toU8a(true) strips the SCALE Bytes wrapper and returns raw code bytes.
// pristine.toHex() includes a compact-length prefix so must NOT be used for hashing.
const onChainBytes = pristine.toU8a(true);
const onChainHash  = keccakAsHex(onChainBytes);
if (onChainHash !== localHash) {
  console.error(`FAIL: on-chain code hash ${onChainHash} != local ${localHash}`);
  process.exit(1);
}

console.log(`OK: on-chain code hash matches local (${localHash})`);
await api.disconnect();
process.exit(0);
