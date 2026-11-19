#!/usr/bin/env bash
# Start the full BastionGuard demo topology in the background.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/bin"
DEMO="$ROOT/demo-state"
LOGDIR="$DEMO/logs"
mkdir -p "$LOGDIR" "$DEMO/targets"

pkill -f 'bin/bg-' 2>/dev/null || true
sleep 0.3

AUTHKEY="$(tr -d '\n' < "$DEMO/agent-authorized-key.txt")"
"$BIN/bg-target" -host db-1      -listen 127.0.0.1:2201 -state "$DEMO/targets" -authkey "$AUTHKEY" >"$LOGDIR/target-db-1.log" 2>&1 &
"$BIN/bg-target" -host db-2      -listen 127.0.0.1:2202 -state "$DEMO/targets" -authkey "$AUTHKEY" >"$LOGDIR/target-db-2.log" 2>&1 &
"$BIN/bg-target" -host cache-1   -listen 127.0.0.1:2203 -state "$DEMO/targets" -authkey "$AUTHKEY" >"$LOGDIR/target-cache-1.log" 2>&1 &
"$BIN/bg-target" -host dmz-web-1 -listen 127.0.0.1:2211 -state "$DEMO/targets" -authkey "$AUTHKEY" >"$LOGDIR/target-dmz-web-1.log" 2>&1 &
"$BIN/bg-target" -host dmz-web-2 -listen 127.0.0.1:2212 -state "$DEMO/targets" -authkey "$AUTHKEY" >"$LOGDIR/target-dmz-web-2.log" 2>&1 &
"$BIN/bg-relay" -state "$DEMO/relay-home" -config "$DEMO/relay-home/relay.json" >"$LOGDIR/relay-home.out" 2>&1 &
"$BIN/bg-relay" -state "$DEMO/relay-dmz"  -config "$DEMO/relay-dmz/relay.json"  >"$LOGDIR/relay-dmz.out" 2>&1 &
sleep 0.6
BG_STATE_DIR="$DEMO/laptop" "$BIN/bg-agent" -state "$DEMO/laptop" >"$LOGDIR/agent.out" 2>&1 &
sleep 0.9
BG_STATE_DIR="$DEMO/laptop" "$BIN/bgctl" -socket "$DEMO/laptop/agent.sock" ping
