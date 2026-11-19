// Command bg-worker is the operator-facing CLI on a jump host. It opens
// approved tunnels and runs SSH over them; it never holds a target-capable key.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"bastionguard/internal/proto"
	"bastionguard/internal/worker"

	"golang.org/x/crypto/ssh"
)

func main() {
	stateDir := flag.String("state", ".", "worker state directory")
	entry := flag.String("entry", "", "entry relay address (default from bundle)")
	chainCSV := flag.String("chain", "", "comma-separated relay chain node ids")
	zone := flag.String("zone", "", "target zone")
	user := flag.String("user", "ops", "ssh user")
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}
	w, err := worker.New(*stateDir)
	if err != nil {
		fail(err)
	}
	if *entry == "" {
		*entry = w.BundleHomeAddr()
	}
	chain := splitCSV(*chainCSV)

	switch args[0] {
	case "ssh":
		if len(args) < 2 {
			usage()
			os.Exit(2)
		}
		host, port := splitHostPort(args[1])
		cmd := strings.Join(args[2:], " ")
		runOne(w, worker.Config{
			EntryAddr: *entry, Chain: chain, Zone: *zone,
			TargetHost: host, TargetPort: port, User: *user,
			Command: cmd, Interactive: cmd == "",
		})
	case "batch":
		// batch -script file.sh host1:port host2:port ...
		fs := flag.NewFlagSet("batch", flag.ExitOnError)
		scriptPath := fs.String("script", "", "script file (hash is what gets approved)")
		_ = fs.Parse(args[1:])
		rest := fs.Args()
		if *scriptPath == "" || len(rest) == 0 {
			usage()
			os.Exit(2)
		}
		script, err := os.ReadFile(*scriptPath)
		if err != nil {
			fail(err)
		}
		sum := sha256.Sum256(script)
		hash := "sha256:" + hex.EncodeToString(sum[:])
		var targets []proto.BatchTarget
		for _, hp := range rest {
			h, p := splitHostPort(hp)
			targets = append(targets, proto.BatchTarget{Host: h, Port: p, User: *user})
		}
		runBatch(w, worker.Config{
			EntryAddr: *entry, Chain: chain, Zone: *zone, User: *user,
			Command: "script " + *scriptPath, ScriptHash: hash,
		}, targets, string(script))
	default:
		usage()
		os.Exit(2)
	}
}

func runOne(w *worker.Worker, cfg worker.Config) {
	sess, err := w.OpenSession(cfg)
	if err != nil {
		fail(err)
	}
	defer sess.Close()
	client, err := worker.DialSSH(sess, w.BundleAgentSignPub())
	if err != nil {
		fail(err)
	}
	defer client.Close()
	if cfg.Interactive {
		fmt.Printf("[bg] 已连接 %s (session %s) — 演示环境只支持 exec，输入命令行即可，exit 退出\n", cfg.TargetHost, sess.ID())
		return
	}
	out, err := execOutput(client, cfg.Command)
	if err != nil {
		fail(err)
	}
	fmt.Printf("===== %s =====\n%s", cfg.TargetHost, out)
}

func runBatch(w *worker.Worker, cfg worker.Config, targets []proto.BatchTarget, script string) {
	sessions, err := w.OpenBatch(cfg, targets)
	if err != nil {
		fail(err)
	}
	var wg sync.WaitGroup
	for _, sess := range sessions {
		wg.Add(1)
		go func(s *worker.Session) {
			defer wg.Done()
			defer s.Close()
			client, err := worker.DialSSH(s, w.BundleAgentSignPub())
			if err != nil {
				fmt.Printf("===== %s ERROR: %v\n", s.TargetName(), err)
				return
			}
			defer client.Close()
			out, err := execOutput(client, script)
			if err != nil {
				fmt.Printf("===== %s ERROR: %v\n", s.TargetName(), err)
				return
			}
			fmt.Printf("===== %s =====\n%s", s.TargetName(), out)
		}(sess)
	}
	wg.Wait()
}

func execOutput(client *ssh.Client, cmd string) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	out, err := sess.CombinedOutput(cmd)
	return string(out), err
}

func splitHostPort(s string) (string, int) {
	parts := strings.Split(s, ":")
	if len(parts) == 1 {
		return parts[0], 22
	}
	p := 0
	fmt.Sscanf(parts[1], "%d", &p)
	if p == 0 {
		p = 22
	}
	return parts[0], p
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func usage() {
	fmt.Fprint(os.Stderr, `bg-worker — 跳板机侧运维入口

用法:
  bg-worker [-chain r1,r2] [-zone z] [-user u] ssh host:port [command...]
  bg-worker [-chain r1,r2] [-zone z] [-user u] batch -script file.sh host1:port host2:port ...
`)
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "bg-worker: %v\n", err)
	os.Exit(1)
}

var _ = io.EOF
var _ = base64.StdEncoding
