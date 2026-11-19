// Command bg-enroll mints the complete demo topology: the laptop agent, two
// relay nodes (jump hosts), one worker, and a CA. Targets enroll themselves
// separately with the agent's authorized public key.
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"bastionguard/internal/keys"
)

type topology struct {
	homeAddr  string
	dmzAddr   string
	workerDir string
	agentDir  string
	homeDir   string
	dmzDir    string
}

func main() {
	root := flag.String("root", "./demo-state", "root directory for all node state")
	flag.Parse()
	t := topology{
		homeAddr:  "127.0.0.1:2301",
		dmzAddr:   "127.0.0.1:2302",
		agentDir:  filepath.Join(*root, "laptop"),
		homeDir:   filepath.Join(*root, "relay-home"),
		dmzDir:    filepath.Join(*root, "relay-dmz"),
		workerDir: filepath.Join(*root, "worker-jump"),
	}
	if err := os.MkdirAll(*root, 0o755); err != nil {
		fail(err)
	}

	ca, err := keys.NewCA()
	if err != nil {
		fail(err)
	}
	agentID, err := keys.NewAgentIdentity("laptop-agent")
	if err != nil {
		fail(err)
	}
	// mTLS identity for the laptop itself.
	laptopNode, err := keys.NewNodeKeys(ca, agentID.ID, "agent")
	if err != nil {
		fail(err)
	}
	homeNode, err := keys.NewNodeKeys(ca, "relay-home", "relay")
	if err != nil {
		fail(err)
	}
	dmzNode, err := keys.NewNodeKeys(ca, "relay-dmz", "relay")
	if err != nil {
		fail(err)
	}
	workerNode, err := keys.NewNodeKeys(ca, "worker-jump", "worker")
	if err != nil {
		fail(err)
	}

	// Laptop: identity file + mTLS material + CA + a reference bundle so the
	// agent knows the worker's ECDH public key for sealing replies.
	if err := os.MkdirAll(t.agentDir, 0o700); err != nil {
		fail(err)
	}
	if err := agentID.Store(t.agentDir); err != nil {
		fail(err)
	}
	mustWrite(filepath.Join(t.agentDir, "ca.pem"), ca.CertPEM, 0o644)
	mustWrite(filepath.Join(t.agentDir, "laptop.crt"), laptopNode.TLSPEM, 0o644)
	mustWrite(filepath.Join(t.agentDir, "laptop.key"), laptopNode.TLSKeyEM, 0o600)
	mustWrite(filepath.Join(t.agentDir, "policy.json"), []byte(defaultPolicy()), 0o600)

	// Worker bundle.
	wb, err := workerNode.Bundle(ca.CertPEM, agentID, "relay-home", t.homeAddr)
	if err != nil {
		fail(err)
	}
	wb.Role = "worker"
	if err := keys.WriteNodeMaterial(t.workerDir, wb); err != nil {
		fail(err)
	}

	// Agent needs a bundle-shaped file pointing at the worker (for its ECDH
	// sealing key); reuse the same bundle.
	agentBundle := *wb
	if err := keys.WriteNodeMaterial(t.agentDir, &agentBundle); err != nil {
		fail(err)
	}

	// Relay nodes get bundles too, plus their relay configs.
	hb, err := homeNode.Bundle(ca.CertPEM, agentID, "relay-home", t.homeAddr)
	if err != nil {
		fail(err)
	}
	hb.Role = "relay"
	if err := keys.WriteNodeMaterial(t.homeDir, hb); err != nil {
		fail(err)
	}
	db, err := dmzNode.Bundle(ca.CertPEM, agentID, "relay-home", t.homeAddr)
	if err != nil {
		fail(err)
	}
	db.Role = "relay"
	if err := keys.WriteNodeMaterial(t.dmzDir, db); err != nil {
		fail(err)
	}
	mustWrite(filepath.Join(t.homeDir, "relay.json"), []byte(homeConfig(t)), 0o600)
	mustWrite(filepath.Join(t.dmzDir, "relay.json"), []byte(dmzConfig(t)), 0o600)

	// Convenience: emit the authorized key material targets need.
	authKey := base64.StdEncoding.EncodeToString(agentID.SignPub)
	mustWrite(filepath.Join(*root, "agent-authorized-key.txt"), []byte(authKey+"\n"), 0o644)

	fmt.Printf("enrollment complete under %s\n", *root)
	fmt.Printf("  agent : %s\n", t.agentDir)
	fmt.Printf("  relays: %s, %s\n", t.homeDir, t.dmzDir)
	fmt.Printf("  worker: %s\n", t.workerDir)
	fmt.Printf("  agent authorized key: %s\n", authKey)
}

func defaultPolicy() string {
	return `{
  "quiet_hours": ["03:30", "03:31"],
  "burst_threshold": 4,
  "burst_window": "20s",
  "default_ttl": 1800,
  "max_grant_ttl": 43200,
  "rules": [
    {
      "name": "deny-restricted-zone",
      "zones": ["restricted"],
      "mode": "deny"
    },
    {
      "name": "auto-readonly-ops",
      "users": ["ops"],
      "commands": ["hostname", "uptime", "whoami", "systemctl status"],
      "mode": "auto",
      "ttl_seconds": 600
    }
  ]
}
`
}

func homeConfig(t topology) string {
	return fmt.Sprintf(`{
  "node_id": "relay-home",
  "listen_addr": %q,
  "local_zones": ["ops"],
  "zone_targets": {
    "ops": {
      "db-1:2201": "127.0.0.1:2201",
      "db-2:2202": "127.0.0.1:2202",
      "cache-1:2203": "127.0.0.1:2203"
    },
    "dmz": {
      "dmz-web-1:2211": "127.0.0.1:2211",
      "dmz-web-2:2212": "127.0.0.1:2212"
    }
  },
  "routes": [
    {"zone": "dmz", "next_node": "relay-dmz", "next_addr": %q}
  ]
}
`, t.homeAddr, t.dmzAddr)
}

func dmzConfig(t topology) string {
	return fmt.Sprintf(`{
  "node_id": "relay-dmz",
  "listen_addr": %q,
  "local_zones": ["dmz"],
  "zone_targets": {
    "dmz": {
      "dmz-web-1:2211": "127.0.0.1:2211",
      "dmz-web-2:2212": "127.0.0.1:2212"
    }
  },
  "routes": []
}
`, t.dmzAddr)
}

func mustWrite(path string, data []byte, mode os.FileMode) {
	if err := os.WriteFile(path, data, mode); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "bg-enroll: %v\n", err)
	os.Exit(1)
}
