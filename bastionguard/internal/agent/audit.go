package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditEvent is one JSONL audit record. Every borrow decision and every SSH
// signature lands here, including the chain position and origin node, so a
// malicious request is reconstructable even when it was denied.
type AuditEvent struct {
	TS        time.Time `json:"ts"`
	Kind      string    `json:"kind"`
	RequestID string    `json:"request_id,omitempty"`
	SessionID string    `json:"session_id,omitempty"`
	GrantID   string    `json:"grant_id,omitempty"`
	ChainID   string    `json:"chain_id,omitempty"`
	Depth     int       `json:"depth,omitempty"`
	Origin    string    `json:"origin,omitempty"`
	User      string    `json:"user,omitempty"`
	Host      string    `json:"host,omitempty"`
	Zone      string    `json:"zone,omitempty"`
	FP        string    `json:"fingerprint,omitempty"`
	Decision  string    `json:"decision,omitempty"`
	Mode      string    `json:"mode,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	Rule      string    `json:"rule,omitempty"`
	Auto      bool      `json:"auto,omitempty"`
	TTL       int       `json:"ttl_seconds,omitempty"`
	Urgent    bool      `json:"urgent,omitempty"`
}

type auditLog struct {
	mu sync.Mutex
	f  *os.File
}

func openAuditLog(stateDir string) (*auditLog, error) {
	path := filepath.Join(stateDir, "agent-audit.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &auditLog{f: f}, nil
}

func (a *auditLog) write(e AuditEvent) {
	e.TS = time.Now()
	if e.TS.IsZero() {
		e.TS = time.Now()
	}
	line, _ := json.Marshal(e)
	a.mu.Lock()
	defer a.mu.Unlock()
	fmt.Fprintln(a.f, string(line))
	a.f.Sync()
}

func (a *auditLog) close() { _ = a.f.Close() }
