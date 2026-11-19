# BastionGuard

用 Go 重做跳板机 SSH 钥匙转发，消除经典 `ssh -A`（agent forwarding）的核心风险：
**跳板机上的高权限者可以在运维人员在线期间，借用转发的钥匙登录该人员能访问的所有机器。**

BastionGuard 的答案是：**私钥永不离开运维人员自己的电脑，跳板机退化为零密钥的哑中继；
每一次借用都绑定到当次真实目标，异常借用在笔记本上可见、可拒绝。**

---

## 1. 威胁模型与对应防线

| 评审指出的风险 | 本系统的防线 |
| --- | --- |
| 跳板机 root 拿到转发钥匙即可横向登录 | 跳板机上**不存在**任何目标主机信任的私钥；只有节点 mTLS 身份和节点签名钥，目标 `authorized_keys` 里没有它们 |
| 借用不区分目标，一把钥匙通吃 | 每个授权（grant）绑定 `链ID / 跳数 / 来源节点 / 用户 / 目标主机 / 主机钥指纹 / TTL`；SSH 认证签名逐个回笔记本校验，目标不匹配即拒 |
| 人被弹窗轰炸后习惯性点同意 | 窄口径 auto 规则覆盖明确的只读操作（零弹窗）；新目标/写操作**一次确认覆盖整个会话**；批量 N 台合并为一次确认 |
| 人不在线时仍可被借用 | 笔记本主动保持 presence 长连接；断连后中继拒绝一切控制面请求，worker 看门狗快速失败 |
| 中继偷看/篡改借用内容 | 控制消息用 ECDH(P-256)+AES-GCM **端到端封缄**，中继只见密文；每条消息另附 Ed25519 签名，worker 钉扎回复方公钥，中继无法伪造「允许」 |
| 抓帧重放 | 每条消息随机 nonce，笔记本侧 nonce 去重；封缄使用一次性临时 ECDH 密钥 |
| 中间人/主机被重装 | 主机钥 TOFU 账本钉扎，指纹变化触发**紧急**人工升级 |
| 长会话失控 | grant 有 TTL，后台 reaper 到期即经中继 `teardown` 真正掐断数据隧道；`bgctl revoke` 可立即掐断 |
| 静默渗透难发现 | 突发检测（短时间多个新目标）、静默时段自动升级；全部决策与每次签名写本地 JSONL 审计 |

## 2. 架构

```
 笔记本 (bg-agent + bgctl)                跳板机/中继 (bg-relay, 哑转发)            目标主机 (bg-target sshd)
 ┌──────────────────────┐   mTLS 连接    ┌──────────────────────┐   区域ACL   ┌────────────────────┐
 │ Ed25519 签名私钥      │◀──presence────│ presence 表 / 路由表  │──TCP/mTLS──▶│ 只信任笔记本公钥     │
 │ 策略引擎 / 授权存储    │               │ 无目标信任钥          │             │ 登录/命令全部留痕    │
 │ nonce 缓存 / TOFU账本 │──sealed 回复─▶│ 只见密文控制帧        │◀──data帧────│                    │
 │ 审计 JSONL           │               └──────────────────────┘             └────────────────────┘
 └──────────────────────┘                         ▲
        ▲ 本地 unix socket (0600)                 │ mTLS
        │                                  ┌──────┴────────┐
       bgctl                          worker (bg-worker)：SSH 客户端，
   审批/撤销/状态                      remoteSigner 把每次签名请求转回笔记本
```

- **bg-agent**（笔记本）：持有唯一被目标信任的 Ed25519 私钥；维护 presence、评估策略、管理授权、执行签名。
- **bg-relay**（跳板机）：mTLS 认证节点、执行网络层区域 ACL、转发数据帧与密文控制帧，无任何签名能力。
- **bg-worker**（跳板机运维入口）：发起隧道与 SSH 会话；`ssh.Signer` 的实现不持有私钥，每次 `Sign` 都是一次带授权校验的远程调用。
- **bg-target**：Go 原生 sshd 模拟主机，`authorized_keys` 只含笔记本公钥。
- **bg-attacker**：协议合规的攻击模拟器，演示 root 拿权后的各类借用尝试。
- **bgctl / bg-enroll**：本地审批控制 CLI / 拓扑与身份注册工具。

## 3. 快速开始

```bash
go build ./...                      # 编译全部组件到 bin/
go test -race ./...                 # 单元测试（协议/策略/授权/防重放）
bash scripts/demo.sh                # 一键端到端攻防演示（约 1 分钟）
```

演示拓扑全部跑在本机回环地址：5 台目标主机、2 台中继（含二级跳转）、1 个 worker、1 个笔记本 agent，
覆盖 6 类正常运维场景与 5 类攻击场景，结尾输出审计汇总。

手动单步操作时用 `scripts/start-topo.sh` 起拓扑、`scripts/auto-approver.sh` 模拟人工批准，然后：

```bash
# auto 只读：零弹窗
./bin/bg-worker -state demo-state/worker-jump -zone ops ssh db-1:2201 hostname
# 写操作：笔记本上 bgctl list 看到请求后 approve 一次
./bin/bg-worker -state demo-state/worker-jump -zone ops ssh cache-1:2203 'systemctl restart cache'
BG_STATE_DIR=demo-state/laptop ./bin/bgctl -socket demo-state/laptop/agent.sock list
BG_STATE_DIR=demo-state/laptop ./bin/bgctl -socket demo-state/laptop/agent.sock approve <request_id> 1800
# 二级跳转
./bin/bg-worker -state demo-state/worker-jump -chain relay-home,relay-dmz -zone dmz ssh dmz-web-1:2211 hostname
# 批量（一次确认，绑定脚本哈希）
./bin/bg-worker -state demo-state/worker-jump -zone ops batch -script patch.sh db-1:2201 db-2:2202
```

## 4. 确认频率的取舍

详见 [docs/DESIGN.md](docs/DESIGN.md)。核心原则：**用规则的窄度换安静，用会话粒度换效率，用可见性兜底剩余风险。**

## 5. 目录结构

```
cmd/            bg-agent bgctl bg-relay bg-target bg-worker bg-attacker bg-enroll
internal/
  proto/        消息信封、Ed25519 签名、ECDH+AES-GCM 封缄、中继帧
  keys/         CA、节点证书、身份包（enrollment bundle）
  relay/        mTLS 哑中继、presence 表、区域 ACL、teardown
  agent/        策略执行、授权存储、审批队列、nonce 去重、TOFU、审计、reaper
  policy/       auto/prompt/escalate/deny 规则与静默时段、突发阈值
  worker/       隧道会话、remoteSigner、远程主机钥校验、批量
  sshd/         模拟目标主机
scripts/        demo.sh / start-topo.sh / auto-approver.sh
docs/           设计说明与威胁建模
```
