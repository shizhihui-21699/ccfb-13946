// Command bg-agent is the laptop guardian process. It owns the signing key,
// keeps presence to the home relay, evaluates policy, and serves the local
// approval socket used by bgctl.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"bastionguard/internal/agent"
)

func main() {
	stateDir := flag.String("state", envOr("BG_STATE_DIR", os.ExpandEnv("$HOME/.bastionguard")), "agent state directory")
	flag.Parse()
	socket := *stateDir + "/agent.sock"
	a, err := agent.New(*stateDir, socket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bg-agent: %v\n", err)
		os.Exit(1)
	}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		a.Stop()
	}()
	fmt.Fprintf(os.Stderr, "bg-agent running; state=%s socket=%s\n", *stateDir, socket)
	if err := a.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "bg-agent: %v\n", err)
		os.Exit(1)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
