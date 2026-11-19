#!/usr/bin/env bash
# Demo helper: simulate the operator clicking "approve" on each pending request.
# Only the "待审批" section is considered; auto-policy requests never reach it.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOCK="$ROOT/demo-state/laptop/agent.sock"
CTL="$ROOT/bin/bgctl"
export BG_STATE_DIR="$ROOT/demo-state/laptop"
while true; do
  out="$("$CTL" -socket "$SOCK" list 2>/dev/null)" || { sleep 0.4; continue; }
  # Stop scanning once the grants section begins.
  id="$(printf '%s\n' "$out" | sed -n '/待审批/,/生效中的授权/p' | awk '/^  [A-Za-z0-9_-]+/{print $1; exit}')"
  if [ -n "${id:-}" ]; then
    echo "[approver] 批准 $id"
    "$CTL" -socket "$SOCK" approve "$id" 900 >/dev/null 2>&1 || true
  fi
  sleep 0.4
done
