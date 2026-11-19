#!/usr/bin/env bash
# BastionGuard 端到端演示：本机模拟完整拓扑，同时演练正常运维与恶意借用。
#
# 拓扑:
#   笔记本 bg-agent ──presence(mTLS)──▶ relay-home (跳板机1) ──mTLS──▶ relay-dmz (跳板机2)
#   worker-jump（运维入口，被假定为可能被 root 攻破）
#   目标: db-1/db-2/cache-1 (ops 区)  dmz-web-1/dmz-web-2 (dmz 区, 二级跳转)
#   隐藏目标 loot-1: 不在任何中继 ACL 里
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/bin"
DEMO="$ROOT/demo-state"
LOGDIR="$DEMO/logs"
PIDS=()

c_info() { printf '\033[36m▸ %s\033[0m\n' "$*"; }
c_ok()   { printf '\033[32m✓ %s\033[0m\n' "$*"; }
c_warn() { printf '\033[33m! %s\033[0m\n' "$*"; }
c_bad()  { printf '\033[31m✗ %s\033[0m\n' "$*"; }
c_hdr()  { printf '\n\033[1;35m========== %s ==========\033[0m\n' "$*"; }

cleanup() {
  c_info "清理演示进程"
  pkill -f 'auto-approver' 2>/dev/null || true
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  pkill -f 'bg-agent' 2>/dev/null || true
  pkill -f 'bg-relay' 2>/dev/null || true
  pkill -f 'bg-target' 2>/dev/null || true
  pkill -f 'bg-worker' 2>/dev/null || true
  pkill -f 'bg-attacker' 2>/dev/null || true
  disown -a 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT

wait_port() {
  local port="$1" tries="${2:-50}"
  for _ in $(seq 1 "$tries"); do
    (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && { exec 3>&- 3<&-; return 0; }
    sleep 0.1
  done
  return 1
}

ctl() { BG_STATE_DIR="$DEMO/laptop" "$BIN/bgctl" -socket "$DEMO/laptop/agent.sock" "$@"; }
first_pending() { ctl list 2>/dev/null | sed -n '/待审批/,/生效中的授权/p' | awk '/^  [A-Za-z0-9_-]+/{print $1; exit}'; }
acount() { grep -c "\"kind\":\"$1\"" "$AUDIT" 2>/dev/null || true; }

# 自动批准器：只处理真正进入队列的 prompt 请求（auto 规则不进队列）。
approver_loop() {
  while true; do
    local id
    id="$(first_pending)"
    if [ -n "${id:-}" ]; then
      c_warn "模拟人工: 批准 $id"
      ctl approve "$id" 900 >/dev/null 2>&1 || true
    fi
    sleep 0.4
  done
}

stop_approver() { [ -n "${APPROVER_PID:-}" ] && kill "$APPROVER_PID" 2>/dev/null || true; APPROVER_PID=""; }
start_approver() { approver_loop "$@" >"$LOGDIR/approver.log" 2>&1 & APPROVER_PID=$!; PIDS+=("$APPROVER_PID"); }

run_bounded() { # seconds cmd...
  local secs="$1"; shift
  ( "$@" & local p=$!; sleep "$secs"; kill "$p" 2>/dev/null; wait "$p" 2>/dev/null )
}

# ---------------------------------------------------------------- 0. 注册
# 先确保上一轮的残留进程全部退出，避免旧 CA 的进程占用端口。
pkill -f 'bg-agent' 2>/dev/null || true
pkill -f 'bg-relay' 2>/dev/null || true
pkill -f 'bg-target' 2>/dev/null || true
pkill -f 'bg-worker' 2>/dev/null || true
pkill -f 'auto-approver' 2>/dev/null || true
sleep 1
rm -rf "$DEMO"
mkdir -p "$LOGDIR"
c_hdr "0. 注册：CA / 两台中继 / worker / 笔记本身份与策略"
"$BIN/bg-enroll" -root "$DEMO"
AUTHKEY="$(tr -d '\n' < "$DEMO/agent-authorized-key.txt")"

# ---------------------------------------------------------------- 1. 目标主机
c_hdr "1. 启动 5 台模拟目标 sshd（只信任笔记本公钥）"
"$BIN/bg-target" -host db-1      -listen 127.0.0.1:2201 -state "$DEMO/targets" -authkey "$AUTHKEY" >"$LOGDIR/target-db-1.log" 2>&1 & PIDS+=($!)
"$BIN/bg-target" -host db-2      -listen 127.0.0.1:2202 -state "$DEMO/targets" -authkey "$AUTHKEY" >"$LOGDIR/target-db-2.log" 2>&1 & PIDS+=($!)
"$BIN/bg-target" -host cache-1   -listen 127.0.0.1:2203 -state "$DEMO/targets" -authkey "$AUTHKEY" >"$LOGDIR/target-cache-1.log" 2>&1 & PIDS+=($!)
"$BIN/bg-target" -host dmz-web-1 -listen 127.0.0.1:2211 -state "$DEMO/targets" -authkey "$AUTHKEY" >"$LOGDIR/target-dmz-web-1.log" 2>&1 & PIDS+=($!)
"$BIN/bg-target" -host dmz-web-2 -listen 127.0.0.1:2212 -state "$DEMO/targets" -authkey "$AUTHKEY" >"$LOGDIR/target-dmz-web-2.log" 2>&1 & PIDS+=($!)
for p in 2201 2202 2203 2211 2212; do wait_port "$p" || { c_bad "目标端口 $p 未就绪"; exit 1; }; done
c_ok "5 台目标就绪"

# ---------------------------------------------------------------- 2. 中继
c_hdr "2. 启动两台跳板中继（mTLS 哑转发，无目标主机信任钥）"
"$BIN/bg-relay" -state "$DEMO/relay-home" -config "$DEMO/relay-home/relay.json" >"$LOGDIR/relay-home.out" 2>&1 & PIDS+=($!)
"$BIN/bg-relay" -state "$DEMO/relay-dmz"  -config "$DEMO/relay-dmz/relay.json"  >"$LOGDIR/relay-dmz.out" 2>&1 & PIDS+=($!)
wait_port 2301 && wait_port 2302 || { c_bad "中继未就绪"; exit 1; }
c_ok "relay-home:2301 / relay-dmz:2302 就绪"

# ---------------------------------------------------------------- 3. agent
c_hdr "3. 启动笔记本 bg-agent（私钥不出本机，presence 长连接）"
BG_STATE_DIR="$DEMO/laptop" "$BIN/bg-agent" -state "$DEMO/laptop" >"$LOGDIR/agent.out" 2>&1 & PIDS+=($!)
sleep 1.5
ctl ping || { c_bad "agent 未上线"; exit 1; }
start_approver

W() { "$BIN/bg-worker" -state "$DEMO/worker-jump" "$@"; }

# ---------------------------------------------------------------- 4. 正常运维
c_hdr "4. 正常 A：auto 只读命令（零弹窗，审计逐条记录）"
W -zone ops ssh db-1:2201 hostname
W -zone ops ssh db-2:2202 uptime
if [ -s "$LOGDIR/approver.log" ]; then c_bad "只读命令不应触发审批"; else c_ok "无弹窗，静默放行"; fi

c_hdr "5. 正常 B：写操作 → 一次确认覆盖整个会话"
W -zone ops ssh cache-1:2203 'systemctl restart cache'
c_ok "一次批准完成写操作"

c_hdr "6. 正常 C：多级跳转（worker→relay-home→relay-dmz→dmz 主机）"
W -chain relay-home,relay-dmz -zone dmz ssh dmz-web-1:2211 hostname
grep -q '"depth":2' "$DEMO/laptop/agent-audit.jsonl" && c_ok "审计记录链深=2"

c_hdr "7. 正常 D：批量脚本（N 台合并为一次确认，绑定脚本哈希）"
printf 'hostname\nuptime\n' > "$DEMO/patch.sh"
W -zone ops batch -script "$DEMO/patch.sh" db-1:2201 db-2:2202 cache-1:2203
[ "$(grep -c '"kind":"auth_sign"' "$DEMO/laptop/agent-audit.jsonl" || true)" -ge 3 ] && c_ok "三个目标各自独立签名"

c_hdr "8. 正常 E：脚本被改 → 哈希不同 → 触发新审批，人工拒绝"
printf 'hostname\ncat /etc/shadow\n' > "$DEMO/patch-evil.sh"
stop_approver; sleep 0.5
( W -zone ops batch -script "$DEMO/patch-evil.sh" db-1:2201 2>"$LOGDIR/tamper.err" & localp=$!
  sleep 3
  id="$(first_pending)"; c_warn "异常脚本请求 ${id:-<空>}，执行拒绝"
  [ -n "${id:-}" ] && ctl deny "$id" >/dev/null
  wait "$localp" 2>/dev/null || true )
grep -q '"decision":"deny"' "$DEMO/laptop/agent-audit.jsonl" && c_ok "篡改脚本被拒绝"
start_approver

c_hdr "9. 正常 F：长会话 revoke 立即掐断数据隧道"
( W -zone ops ssh cache-1:2203 'bghold 120s' 2>"$LOGDIR/hold.err" & localp=$!
  sleep 5
  sid="$(ctl list | grep -o 'session=[A-Za-z0-9_-]*' | head -1 | cut -d= -f2)"
  if [ -n "${sid:-}" ]; then ctl revoke "$sid" >/dev/null && c_ok "已撤销 $sid"; else c_bad "未找到存活授权"; fi
  sleep 2
  kill "$localp" 2>/dev/null || true )
grep -q TEARDOWN "$DEMO/relay-home/relay-relay-home.log" && c_ok "revoke 触发中继 TEARDOWN"

# ---------------------------------------------------------------- 攻击面
c_hdr "10. 攻击①：root 伪造未授权目标 loot-1（中继区域 ACL 拒绝）"
"$BIN/bg-attacker" -state "$DEMO/worker-jump" -mode forge -target loot-1:2299 -zone restricted 2>&1 | sed 's/^/   /'
grep -q 'not in zone' "$DEMO/relay-home/relay-relay-home.log" && c_ok "未授权目标隧道被拒"

c_hdr "11. 攻击②：协议合规地伪造敏感命令到合法网段（人工可见并拒绝）"
stop_approver; sleep 0.3
( "$BIN/bg-attacker" -state "$DEMO/worker-jump" -mode forge -target db-1:2201 -zone ops 2>"$LOGDIR/atk2.err" & localp=$!
  sleep 3
  id="$(first_pending)"; c_warn "队列出现 cat /etc/shadow 异常请求 ${id:-<空>}"
  [ -n "${id:-}" ] && ctl deny "$id" >/dev/null
  wait "$localp" 2>/dev/null )
grep -q 'operator rejected' "$LOGDIR/atk2.err" && c_ok "恶意借用被同事察觉并拒绝"
start_approver

c_hdr "12. 攻击③：笔记本离线 → presence 消失 → 借用快速失败"
pkill -f 'bin/bg-agent'; sleep 1.5
if run_bounded 8 W -zone ops ssh db-1:2201 hostname 2>"$LOGDIR/offline.err"; then :; fi
grep -q 'offline' "$LOGDIR/offline.err" && c_ok "离线窗口借用面为零"
BG_STATE_DIR="$DEMO/laptop" "$BIN/bg-agent" -state "$DEMO/laptop" >"$LOGDIR/agent2.out" 2>&1 & PIDS+=($!)
sleep 1.2; ctl ping

c_hdr "13. 攻击④：抓帧重放（nonce 去重，无签名产出）"
mkdir -p "$DEMO/capture"
BG_CAPTURE_DIR="$DEMO/capture" W -zone ops ssh db-1:2201 hostname >/dev/null
run_bounded 6 "$BIN/bg-attacker" -state "$DEMO/worker-jump" -mode replay -replay "$DEMO/capture/captured-sealed.bin"
grep -q replay_blocked "$DEMO/laptop/agent-audit.jsonl" && c_ok "重放被 nonce 缓存丢弃"

c_hdr "14. 攻击⑤：目标主机钥变化（MITM/换机 → 紧急升级）"
pkill -f 'host db-1 ' 2>/dev/null; sleep 0.5
"$BIN/bg-target" -host db-1 -listen 127.0.0.1:2201 -state "$DEMO/targets" -authkey "$AUTHKEY" >"$LOGDIR/target-db-1b.log" 2>&1 & PIDS+=($!)
sleep 1
stop_approver; sleep 0.3
( W -zone ops ssh db-1:2201 hostname 2>"$LOGDIR/mitm.err" & localp=$!
  sleep 3
  id="$(first_pending)"; c_warn "主机钥变化紧急请求 ${id:-<空>}，拒绝"
  [ -n "${id:-}" ] && ctl deny "$id" >/dev/null
  kill "$localp" 2>/dev/null || true )
grep -q hostkey_mismatch "$DEMO/laptop/agent-audit.jsonl" && c_ok "主机钥变化被识别并紧急告警"

# ---------------------------------------------------------------- 审计汇总
c_hdr "15. 审计汇总（笔记本本地 agent-audit.jsonl）"
AUDIT="$DEMO/laptop/agent-audit.jsonl"
printf '   总事件 %s 条\n' "$(wc -l <"$AUDIT" | tr -d ' ')"
echo "   — 按决策结果 —"
for d in auto_allow allow deny signed expired revoked waiting; do
  n="$(grep -c "\"decision\":\"$d\"" "$AUDIT" 2>/dev/null || true)"
  printf '   %-18s %s\n' "$d" "${n:-0}"
done
echo "   — 按事件类型 —"
for k in prompt auth_sign session_open batch_open replay_blocked hostkey_tofu hostkey_mismatch grant_expired revoke; do
  n="$(grep -c "\"kind\":\"$k\"" "$AUDIT" 2>/dev/null || true)"
  printf '   %-18s %s\n' "$k" "${n:-0}"
done
c_info "中继侧（跳板机只见路由元数据 + 密文控制帧）:"
grep -E 'OPEN|DENY|TEARDOWN|presence' "$DEMO/relay-home/relay-relay-home.log" | tail -6 | sed 's/^/   /'
c_info "目标侧（真正落地的登录与命令）:"
sed 's/^/   /' "$DEMO/targets/sshd-db-1.log" | tail -6

c_hdr "演示完成"
echo "人工入口: BG_STATE_DIR=$DEMO/laptop $BIN/bgctl -socket $DEMO/laptop/agent.sock list"
echo "完整审计: $AUDIT"
