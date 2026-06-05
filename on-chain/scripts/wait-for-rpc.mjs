// Waits for the chopsticks WS RPC at $RPC_URL to be ready by opening a
// WsProvider, awaiting ApiPromise.isReady, and querying system.chain() to
// confirm the chain is actually serving. Exits 0 on success, 1 on timeout
// (default 60s, override with $WAIT_TIMEOUT_SEC).
//
// Probing the WS transport directly — rather than HTTP via curl — matches
// what sanity-deploy.mjs uses and survives chopsticks releases that may
// stop multiplexing HTTP on the WS port.

import {ApiPromise, WsProvider} from '@polkadot/api';

const RPC_URL          = process.env.RPC_URL          || 'ws://localhost:8000';
const TIMEOUT_SEC      = Number(process.env.WAIT_TIMEOUT_SEC || 60);
const RECONNECT_DELAY  = 1000;  // ms between WsProvider reconnect attempts

const provider = new WsProvider(RPC_URL, RECONNECT_DELAY);

const timeoutHandle = setTimeout(() => {
  console.error(`wait-for-rpc: ${RPC_URL} did not become ready within ${TIMEOUT_SEC}s`);
  provider.disconnect().catch(() => {});
  process.exit(1);
}, TIMEOUT_SEC * 1000);

try {
  const api = await ApiPromise.create({provider, noInitWarn: true});
  const chain = await api.rpc.system.chain();
  clearTimeout(timeoutHandle);
  console.log(`wait-for-rpc: ${RPC_URL} ready (chain: ${chain.toString()})`);
  await api.disconnect();
  process.exit(0);
} catch (err) {
  clearTimeout(timeoutHandle);
  console.error(`wait-for-rpc: ${err.message || err}`);
  await provider.disconnect().catch(() => {});
  process.exit(1);
}
