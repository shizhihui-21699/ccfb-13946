// Command bgctl is the operator's local control CLI: list pending borrow
// requests, approve/deny them, inspect live grants, and revoke them.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

type controlRequest struct {
	Op        string `json:"op"`
	RequestID string `json:"request_id,omitempty"`
	Allow     bool   `json:"allow,omitempty"`
	TTL       int    `json:"ttl,omitempty"`
}

func main() {
	socket := flag.String("socket", defaultSocket(), "agent control socket")
	flag.Usage = usage
	flag.Parse()
	if flag.NArg() == 0 {
		usage()
		os.Exit(2)
	}
	op := flag.Arg(0)
	req := controlRequest{Op: op}
	switch op {
	case "list", "ping":
	case "approve":
		req.Op = "decide"
		req.Allow = true
		req.RequestID = flag.Arg(1)
		req.TTL = atoiOr(flag.Arg(2), 3600)
	case "deny":
		req.Op = "decide"
		req.RequestID = flag.Arg(1)
	case "revoke":
		req.RequestID = flag.Arg(1)
	default:
		usage()
		os.Exit(2)
	}
	resp, err := call(*socket, req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bgctl: %v\n", err)
		os.Exit(1)
	}
	render(op, resp)
}

func call(socket string, req controlRequest) (map[string]any, error) {
	c, err := net.Dial("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("connect agent socket %s: %w (is bg-agent running?)", socket, err)
	}
	defer c.Close()
	line, _ := json.Marshal(req)
	if _, err := c.Write(append(line, '\n')); err != nil {
		return nil, err
	}
	buf := make([]byte, 16*1024*1024)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	var resp map[string]any
	if err := json.Unmarshal(buf[:n], &resp); err != nil {
		return nil, err
	}
	if ok, _ := resp["ok"].(bool); !ok {
		return nil, fmt.Errorf("%v", resp["error"])
	}
	return resp, nil
}

func render(op string, resp map[string]any) {
	switch op {
	case "ping":
		fmt.Printf("agent online: %v\n", resp["online"])
	case "list":
		pending, _ := resp["pending"].([]any)
		grants, _ := resp["grants"].([]any)
		if len(pending) == 0 {
			fmt.Println("没有待审批的借用请求")
		} else {
			fmt.Println("待审批请求 (bgctl approve <id> [ttl秒] / bgctl deny <id>):")
			for _, p := range pending {
				pm := p.(map[string]any)
				urgent := ""
				if u, ok := pm["urgent"].(bool); ok && u {
					urgent = " [紧急]"
				}
				fmt.Printf("  %s%s\n     %s\n", pm["request_id"], urgent, describe(pm))
			}
		}
		if len(grants) == 0 {
			fmt.Println("没有生效中的授权")
		} else {
			fmt.Println("生效中的授权 (bgctl revoke <session_id>):")
			for _, g := range grants {
				gm := g.(map[string]any)
				fmt.Printf("  session=%s %s@%s 到期=%v auto=%v\n",
					gm["SessionID"], gm["User"], gm["Host"], gm["ExpiresAt"], gm["Auto"])
			}
		}
	default:
		fmt.Println("ok")
	}
}

func describe(pm map[string]any) string {
	if pm["kind"] == "batch_open" {
		batch := pm["batch"].([]any)
		return fmt.Sprintf("批量脚本 → %d 台, 链深 %v, 来源 %v", len(batch), pm["depth"], pm["origin_node"])
	}
	mode := "交互会话"
	if inter, _ := pm["interactive"].(bool); !inter {
		mode = fmt.Sprintf("命令: %v", pm["command"])
	}
	return fmt.Sprintf("%v@%v [%s] 链深%v 来源%v", pm["user"], pm["host"], mode, pm["depth"], pm["origin_node"])
}

func usage() {
	fmt.Fprint(os.Stderr, `bgctl — BastionGuard 本地审批控制

用法:
  bgctl list                         查看待审批请求和生效授权
  bgctl approve <request_id> [ttl]   批准一次借用 (默认 3600 秒)
  bgctl deny <request_id>            拒绝
  bgctl revoke <session_id>          立即撤销一个生效授权
  bgctl ping                         查看 agent 是否在线
  bgctl -socket <path> ...           指定控制 socket
`)
}

func defaultSocket() string {
	dir := os.Getenv("BG_STATE_DIR")
	if dir == "" {
		dir = os.ExpandEnv("$HOME/.bastionguard")
	}
	return dir + "/agent.sock"
}

func atoiOr(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := time.ParseDuration(s + "s")
	if err != nil {
		return def
	}
	return int(n.Seconds())
}
