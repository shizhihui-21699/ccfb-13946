package agent

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"bastionguard/internal/proto"
)

// askHuman enqueues a request, notifies the operator, and waits for bgctl or
// the timeout. Only one prompt per session_open — the resulting grant covers
// every signature inside that approved session.
func (a *Agent) askHuman(pr PendingRequest, urgent bool) (decision, bool) {
	ch := make(chan decision, 1)
	a.mu.Lock()
	a.pendings[pr.RequestID] = &pending{req: pr, replyCh: ch}
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		delete(a.pendings, pr.RequestID)
		a.mu.Unlock()
	}()

	body := describePending(pr)
	a.notifier.Notify("BastionGuard 借用请求", body, urgent)
	a.auditor.write(AuditEvent{
		Kind: "prompt", RequestID: pr.RequestID, SessionID: pr.SessionID,
		ChainID: pr.ChainID, Depth: pr.Depth, Origin: pr.OriginNode,
		User: pr.User, Host: pr.Host, Decision: "waiting", Urgent: urgent,
	})

	// Timeout keeps a compromised jump host from parking requests forever.
	timeout := 2 * time.Minute
	if urgent {
		timeout = 90 * time.Second
	}
	select {
	case d := <-ch:
		return d, true
	case <-time.After(timeout):
		return decision{}, false
	case <-a.stopCh:
		return decision{}, false
	}
}

func describePending(pr PendingRequest) string {
	if pr.Kind == proto.KindBatchOpen {
		return fmt.Sprintf("批量脚本 → %d 台 (链深 %d, 来源 %s)", len(pr.Batch), pr.Depth, pr.OriginNode)
	}
	mode := "交互会话"
	if !pr.Interactive && pr.Command != "" {
		mode = "命令: " + pr.Command
	}
	return fmt.Sprintf("%s@%s [%s] 链深%d 来源%s", pr.User, pr.Host, mode, pr.Depth, pr.OriginNode)
}

// ListPending returns a snapshot for bgctl list.
func (a *Agent) ListPending() []PendingRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]PendingRequest, 0, len(a.pendings))
	for _, p := range a.pendings {
		out = append(out, p.req)
	}
	return out
}

// Decide resolves a pending request from bgctl.
func (a *Agent) Decide(requestID string, allow bool, ttl int) error {
	a.mu.Lock()
	p, ok := a.pendings[requestID]
	a.mu.Unlock()
	if !ok {
		return fmt.Errorf("no pending request %s", requestID)
	}
	p.replyCh <- decision{allow: allow, ttl: ttl}
	return nil
}

// ListGrants exposes live grants for bgctl status.
func (a *Agent) ListGrants() []Grant { return a.grants.snapshot() }

// Revoke kills all target grants of a session and tears down its live relay
// tunnels immediately (operator panics mid-session).
func (a *Agent) Revoke(sessionID string) bool {
	grants := a.grants.snapshot()
	found := false
	for _, g := range grants {
		if g.SessionID == sessionID {
			found = true
			break
		}
	}
	if !found {
		return false
	}
	a.grants.remove(sessionID)
	a.auditor.write(AuditEvent{Kind: "revoke", SessionID: sessionID, Decision: "revoked"})
	a.teardown(sessionID)
	return true
}

// teardown asks the home relay to close every tunnel of a logical session.
func (a *Agent) teardown(sessionID string) {
	a.mu.Lock()
	pc := a.presence
	a.mu.Unlock()
	if pc == nil {
		return
	}
	_ = proto.WriteFrame(pc, proto.Frame{Type: proto.FrameTeardown, Payload: []byte(sessionID)})
}

// serveControlSocket exposes a tiny line-based local API to bgctl. The socket
// file is 0600 in the user's state dir — no network exposure at all.
func (a *Agent) serveControlSocket() {
	defer a.wg.Done()
	_ = os.MkdirAll(filepath.Dir(a.socketPath), 0o700)
	_ = os.Remove(a.socketPath)
	ln, err := net.Listen("unix", a.socketPath)
	if err != nil {
		a.auditor.write(AuditEvent{Kind: "control_socket", Decision: "error", Reason: err.Error()})
		return
	}
	defer ln.Close()
	_ = os.Chmod(a.socketPath, 0o600)
	go func() {
		<-a.stopCh
		ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go a.serveControlConn(c)
	}
}

type controlRequest struct {
	Op        string `json:"op"`
	RequestID string `json:"request_id,omitempty"`
	Allow     bool   `json:"allow,omitempty"`
	TTL       int    `json:"ttl,omitempty"`
}

func (a *Agent) serveControlConn(c net.Conn) {
	defer c.Close()
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		var req controlRequest
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			writeControl(c, map[string]any{"ok": false, "error": "bad json"})
			continue
		}
		switch req.Op {
		case "list":
			writeControl(c, map[string]any{"ok": true, "pending": a.ListPending(), "grants": a.ListGrants()})
		case "decide":
			err := a.Decide(req.RequestID, req.Allow, req.TTL)
			writeControl(c, map[string]any{"ok": err == nil, "error": errStr(err)})
		case "revoke":
			writeControl(c, map[string]any{"ok": a.Revoke(req.RequestID)})
		case "ping":
			writeControl(c, map[string]any{"ok": true, "online": a.IsOnline()})
		default:
			writeControl(c, map[string]any{"ok": false, "error": "unknown op"})
		}
	}
}

func (a *Agent) IsOnline() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.presence != nil
}

func (a *Agent) pinHost(host string, port int, fp string) {
	a.mu.Lock()
	a.hostKeys[fmt.Sprintf("%s:%d", host, port)] = fp
	ledger := map[string]string{}
	for k, v := range a.hostKeys {
		ledger[k] = v
	}
	a.mu.Unlock()
	data, _ := json.MarshalIndent(ledger, "", "  ")
	_ = os.WriteFile(filepath.Join(a.stateDir, "known-hosts.json"), data, 0o600)
}

func writeControl(c net.Conn, v any) {
	data, _ := json.Marshal(v)
	_, _ = c.Write(append(data, '\n'))
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
