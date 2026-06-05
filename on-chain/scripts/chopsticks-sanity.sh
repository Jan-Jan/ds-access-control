#!/usr/bin/env bash
# Stage 1 gate: chopsticks-Paseo sanity check for OrgRegistry.
#
# Prerequisites:
#   resolc       — Revive Solidity compiler (tested: v1.1.0)
#   solc ≥0.8.27 — Solidity compiler (resolc delegates to it)
#   node ≥18     — JavaScript runtime
#   npm          — Node package manager (installs deps from package.json)
#   curl         — HTTP client (used for the RPC pre-warm probe)
#
# Reproducibility:
#   chopsticks is pinned via scripts/package.json (and scripts/package-lock.json
#   once `npm install` has been run). The script invokes the local install via
#   `npx` without `--yes` or `@latest`, so the gate resolves to the exact
#   version recorded in the lockfile.
#
# Deviations from plan template (discovered at implementation time):
#   - resolc v1.1.0 names the output file "OrgRegistry.sol:OrgRegistry.pvm"
#     (source-file-prefixed, .pvm extension), not "OrgRegistry.polkavm".
#     BLOB path and glob updated accordingly.
#   - resolc requires the solc binary on PATH; this script prepends ~/bin
#     where both resolc and solc 0.8.27 were installed during Task 13.

set -euo pipefail

cd "$(dirname "$0")/.."  # cwd = on-chain/

# Ensure ~/bin (resolc + solc) is on PATH
export PATH="$HOME/bin:$PATH"

CONFIG="scripts/chopsticks-config.yml"
SRC="src/OrgRegistry.sol"
ARTIFACT_DIR="tmp/revive"
# resolc v1.1.0 output: <source-file>:<ContractName>.pvm
BLOB="$ARTIFACT_DIR/OrgRegistry.sol:OrgRegistry.pvm"
PORT=8000

mkdir -p "$ARTIFACT_DIR" tmp

echo "[1/5] Compiling $SRC with resolc..."
resolc --bin "$SRC" --solc "$(which solc)" -o "$ARTIFACT_DIR/" --overwrite
test -s "$BLOB" || { echo "resolc produced no output at $BLOB" >&2; exit 1; }

echo "[2/5] Installing JS dependencies (pinned via package-lock.json)..."
(cd scripts && npm ci --silent --no-audit --no-fund \
  || npm install --silent --no-audit --no-fund)

echo "[3/5] Starting chopsticks (Paseo AH fork) on ws://localhost:$PORT..."
# macOS lacks `setsid` so we can't put chopsticks in its own process group
# for a tree-kill. Instead the trap tears down direct children with
# `pkill -P` (available on both BSD and GNU) and then chopsticks itself.
# `wait` blocks until the node process has actually exited so the sqlite
# WAL/shm cleanup below doesn't race with a still-flushing chopsticks.
scripts/node_modules/.bin/chopsticks \
  --config "$CONFIG" --port "$PORT" &
CHOPSTICKS_PID=$!
trap '
  pkill -P $CHOPSTICKS_PID 2>/dev/null || true
  kill $CHOPSTICKS_PID 2>/dev/null || true
  wait $CHOPSTICKS_PID 2>/dev/null || true
  rm -f tmp/chopsticks-paseo-ah.db.sqlite-shm tmp/chopsticks-paseo-ah.db.sqlite-wal 2>/dev/null || true
' EXIT

echo "[4/5] Waiting for chopsticks WS RPC to accept connections..."
# Two-stage probe:
#  (a) Poll HTTP `system_chain` until chopsticks returns the expected chain
#      name. Observed empirically: chopsticks's WS metadata path doesn't
#      become responsive until the first HTTP request triggers runtime
#      initialisation. Without this pre-warm, the subsequent ApiPromise
#      metadata fetch hangs indefinitely (reproduced with WAIT_TIMEOUT_SEC
#      up to 180s). Typical pre-warm latency: 5–15s on a cold cache.
#  (b) Verify the WS path with the same ApiPromise sanity-deploy.mjs uses,
#      so any WS-specific issue still fails the gate.
echo "  (a) HTTP pre-warm..."
for i in $(seq 1 30); do
  if curl -sS -m 5 -X POST "http://localhost:$PORT" \
       -H 'Content-Type: application/json' \
       -d '{"jsonrpc":"2.0","id":1,"method":"system_chain","params":[]}' \
       2>/dev/null | grep -q 'Paseo Asset Hub'; then
    break
  fi
  sleep 2
  if [ "$i" -eq 30 ]; then
    echo "chopsticks did not respond to HTTP system_chain within 60s" >&2
    exit 1
  fi
done
echo "  (b) WS verify..."
RPC_URL="ws://localhost:$PORT" \
  node scripts/wait-for-rpc.mjs \
  || { echo "chopsticks WS path did not become ready within timeout" >&2; exit 1; }

echo "[5/5] Running deploy-and-verify script..."
RPC_URL="ws://localhost:$PORT" BLOB_PATH="$BLOB" \
  node scripts/sanity-deploy.mjs

echo "OK — Stage 1 chopsticks sanity passed."
