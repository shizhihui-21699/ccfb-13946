// Command bg-target runs one simulated target host's SSH server. Only the
// laptop agent's public key is accepted.
package main

import (
	"flag"
	"fmt"
	"os"

	"bastionguard/internal/sshd"
)

func main() {
	host := flag.String("host", "host-1", "logical host name")
	listen := flag.String("listen", "127.0.0.1:2201", "listen address")
	stateDir := flag.String("state", "./state", "state directory")
	authKey := flag.String("authkey", "", "base64 ed25519 authorized public key")
	flag.Parse()
	if *authKey == "" {
		fmt.Fprintln(os.Stderr, "bg-target: -authkey is required")
		os.Exit(2)
	}
	srv, _, err := sshd.New(*host, *listen, *stateDir, *authKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bg-target: %v\n", err)
		os.Exit(1)
	}
	if err := srv.Serve(); err != nil {
		fmt.Fprintf(os.Stderr, "bg-target: %v\n", err)
		os.Exit(1)
	}
}
