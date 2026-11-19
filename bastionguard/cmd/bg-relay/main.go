// Command bg-relay runs one jump-host relay node.
package main

import (
	"flag"
	"fmt"
	"os"

	"bastionguard/internal/relay"
)

func main() {
	stateDir := flag.String("state", ".", "node state directory (ca.pem, node.crt, node.key)")
	cfgPath := flag.String("config", "relay.json", "relay config file")
	flag.Parse()
	cfg, err := relay.LoadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bg-relay: %v\n", err)
		os.Exit(1)
	}
	r, err := relay.New(cfg, *stateDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bg-relay: %v\n", err)
		os.Exit(1)
	}
	if err := r.Serve(); err != nil {
		fmt.Fprintf(os.Stderr, "bg-relay: %v\n", err)
		os.Exit(1)
	}
}
