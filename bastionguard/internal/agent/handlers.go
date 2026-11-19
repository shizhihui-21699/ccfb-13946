package agent

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net"
	"time"

	"bastionguard/internal/policy"
	"bastionguard/internal/proto"
)

// handleControl dispatches one authenticated control message.
func (a *Agent) handleControl(presence net.Conn, session string, m *proto.Message) {
	now := time.Now()
	switch m.Kind {
	case proto.KindSessionOpen:
		a.handleSessionOpen(presence, session, m, now)
	case proto.KindBatchOpen:
		a.handleBatchOpen(presence, session, m, now)
	case proto.KindHostKeyCheck:
		a.handleHostKeyCheck(presence, session, m)
	case proto.KindAuthSign:
		a.handleAuthSign(presence, session, m)
	case proto.KindSessionClose:
		if m.TargetHost != "" {
			// One batch member finished: release only its grant and keep the
			// sibling targets' grants alive.
			a.grants.removeTarget(m.SessionID, m.TargetHost)
		} else {
			a.grants.remove(m.SessionID)
		}
		a.auditor.write(AuditEvent{Kind: "session_close", SessionID: m.SessionID, ChainID: m.ChainID, Origin: m.OriginNode, Host: m.TargetHost})
		a.reply(presence, session, &proto.Message{Kind: proto.KindSessionClose, SessionID: m.SessionID, RequestID: m.RequestID, Allow: true})
	case proto.KindHeartbeat:
		// Liveness only; no grant extension.
	default:
		a.auditor.write(AuditEvent{Kind: "unknown_message", Decision: "deny", Reason: m.Kind})
	}
}

func (a *Agent) handleSessionOpen(presence net.Conn, session string, m *proto.Message, now time.Time) {
	req := policy.Request{
		User: m.User, Host: m.TargetHost, Zone: "", Command: m.Command,
		Interactive: m.Interactive, OriginNode: m.OriginNode, Depth: m.Depth,
	}
	mode, rule, ttl := a.pol.Decide(req)
	urgent := false
	if a.pol.InQuietHours(now) && mode == policy.ModeAuto {
		mode = policy.ModeEscalate // never silent while the operator is away
		urgent = true
	}
	if a.burst.record(now, m.TargetHost) {
		mode = policy.ModeEscalate
		urgent = true
	}
	ev := AuditEvent{
		Kind: "session_open", RequestID: m.RequestID, SessionID: m.SessionID,
		ChainID: m.ChainID, Depth: m.Depth, Origin: m.OriginNode, User: m.User,
		Host: m.TargetHost, Mode: string(mode), Urgent: urgent,
	}
	if rule != nil {
		ev.Rule = rule.Name
	}

	switch mode {
	case policy.ModeDeny:
		ev.Decision = "deny"
		ev.Reason = "explicit deny rule"
		a.auditor.write(ev)
		a.reply(presence, session, &proto.Message{Kind: proto.KindDecision, RequestID: m.RequestID, SessionID: m.SessionID, Allow: false, Reason: ev.Reason})
		return
	case policy.ModeAuto:
		ev.Decision = "auto_allow"
		ev.Auto = true
		ev.TTL = ttl
		a.auditor.write(ev)
		a.issueGrant(m, ttl, true, ruleName(rule))
		a.reply(presence, session, &proto.Message{Kind: proto.KindDecision, RequestID: m.RequestID, SessionID: m.SessionID, GrantID: m.SessionID, Allow: true, TTLSeconds: ttl})
		return
	default:
		// ModePrompt or ModeEscalate: one human decision covers the whole session.
		pr := PendingRequest{
			RequestID: m.RequestID, Kind: m.Kind, SessionID: m.SessionID,
			ChainID: m.ChainID, Depth: m.Depth, OriginNode: m.OriginNode,
			User: m.User, Host: m.TargetHost, Command: m.Command,
			Interactive: m.Interactive, Urgent: urgent, CreatedAt: now,
		}
		dec, ok := a.askHuman(pr, urgent)
		if !ok {
			ev.Decision = "timeout"
			a.auditor.write(ev)
			a.reply(presence, session, &proto.Message{Kind: proto.KindDecision, RequestID: m.RequestID, SessionID: m.SessionID, Allow: false, Reason: "no approval within timeout"})
			return
		}
		if !dec.allow {
			ev.Decision = "deny"
			ev.Reason = "operator rejected"
			a.auditor.write(ev)
			a.reply(presence, session, &proto.Message{Kind: proto.KindDecision, RequestID: m.RequestID, SessionID: m.SessionID, Allow: false, Reason: ev.Reason})
			return
		}
		if dec.ttl > 0 {
			ttl = dec.ttl
		}
		ev.Decision = "allow"
		ev.TTL = ttl
		a.auditor.write(ev)
		a.issueGrant(m, ttl, false, ruleName(rule))
		a.reply(presence, session, &proto.Message{Kind: proto.KindDecision, RequestID: m.RequestID, SessionID: m.SessionID, GrantID: m.SessionID, Allow: true, TTLSeconds: ttl})
	}
}

// handleBatchOpen collapses a whole script run into ONE approval. The grant
// carries the script hash; every per-host signing request re-checks it.
func (a *Agent) handleBatchOpen(presence net.Conn, session string, m *proto.Message, now time.Time) {
	if len(m.Batch) == 0 || m.ScriptHash == "" {
		a.reply(presence, session, &proto.Message{Kind: proto.KindDecision, RequestID: m.RequestID, Allow: false, Reason: "malformed batch request"})
		return
	}
	urgent := a.pol.InQuietHours(now)
	pr := PendingRequest{
		RequestID: m.RequestID, Kind: m.Kind, SessionID: m.SessionID,
		ChainID: m.ChainID, Depth: m.Depth, OriginNode: m.OriginNode,
		User: m.User, Batch: m.Batch, Command: m.Command, Urgent: urgent, CreatedAt: now,
	}
	ev := AuditEvent{
		Kind: "batch_open", RequestID: m.RequestID, SessionID: m.SessionID,
		ChainID: m.ChainID, Depth: m.Depth, Origin: m.OriginNode, User: m.User,
		Mode: string(policy.ModePrompt), Urgent: urgent,
		Host: fmt.Sprintf("%d hosts", len(m.Batch)),
	}
	dec, ok := a.askHuman(pr, urgent)
	if !ok || !dec.allow {
		ev.Decision = "deny"
		if !ok {
			ev.Decision = "timeout"
		}
		a.auditor.write(ev)
		a.reply(presence, session, &proto.Message{Kind: proto.KindDecision, RequestID: m.RequestID, SessionID: m.SessionID, Allow: false, Reason: "batch rejected"})
		return
	}
	ttl := dec.ttl
	if ttl == 0 {
		ttl = 300 // batch grants default to 5 minutes
	}
	ev.Decision = "allow"
	ev.TTL = ttl
	a.auditor.write(ev)
	// One grant per target, all sharing the batch session and script hash.
	for _, bt := range m.Batch {
		g := &Grant{
			ID: newRequestID(), SessionID: m.SessionID, ChainID: m.ChainID,
			Depth: m.Depth, OriginNode: m.OriginNode, User: firstNonEmpty(bt.User, m.User),
			Host: bt.Host, Port: orPort(bt.Port), ScriptHash: m.ScriptHash,
			ExpiresAt: now.Add(time.Duration(ttl) * time.Second), RuleName: "batch",
		}
		a.grants.put(g)
	}
	a.reply(presence, session, &proto.Message{Kind: proto.KindDecision, RequestID: m.RequestID, SessionID: m.SessionID, Allow: true, TTLSeconds: ttl})
}

// handleHostKeyCheck implements TOFU pinned against the grant's fingerprint.
// A changed host key means either a rebuilt machine or a MITM — either way
// the operator gets an urgent prompt.
func (a *Agent) handleHostKeyCheck(presence net.Conn, session string, m *proto.Message) {
	g, ok := a.grants.get(m.SessionID, m.TargetHost)
	allow := false
	reason := ""
	if !ok {
		reason = "no live grant for session"
	} else {
		fp := FingerprintHost(decodeB64(m.SignData)) // SignData carries the host key wire bytes here
		if known, exists := a.hostKeys[m.TargetHost+":"+itoa(m.TargetPort)]; exists {
			if known != fp {
				reason = "HOST KEY CHANGED (possible MITM or rebuilt host)"
				a.auditor.write(AuditEvent{Kind: "hostkey_mismatch", SessionID: m.SessionID, Host: m.TargetHost, FP: fp, Decision: "escalate", Urgent: true, Reason: reason})
				pr := PendingRequest{RequestID: m.RequestID, Kind: m.Kind, SessionID: m.SessionID, Host: m.TargetHost, User: m.User, Reason: reason, Urgent: true, CreatedAt: time.Now()}
				if dec, ok := a.askHuman(pr, true); ok && dec.allow {
					allow = true
					a.pinHost(m.TargetHost, m.TargetPort, fp)
				}
			} else {
				allow = true
			}
		} else {
			// First sighting: trust on first use, recorded in the ledger.
			allow = true
			a.pinHost(m.TargetHost, m.TargetPort, fp)
			a.auditor.write(AuditEvent{Kind: "hostkey_tofu", SessionID: m.SessionID, Host: m.TargetHost, FP: fp, Decision: "allow"})
		}
		if g.Fingerprint != "" && g.Fingerprint != fp && allow {
			allow = false
			reason = "host key does not match grant fingerprint"
		}
	}
	a.auditor.write(AuditEvent{Kind: "hostkey_check", SessionID: m.SessionID, Host: m.TargetHost, Decision: map[bool]string{true: "allow", false: "deny"}[allow], Reason: reason})
	a.reply(presence, session, &proto.Message{Kind: proto.KindHostKeyReply, RequestID: m.RequestID, SessionID: m.SessionID, Allow: allow, Reason: reason, Fingerprint: m.Fingerprint})
}

// handleAuthSign is the moment the old SSH agent forwarding would have signed
// blindly. Here the signature exists only if a live, target-matched grant
// exists, and is returned without the private key ever moving.
func (a *Agent) handleAuthSign(presence net.Conn, session string, m *proto.Message) {
	g, ok := a.grants.get(m.SessionID, m.TargetHost)
	ev := AuditEvent{Kind: "auth_sign", RequestID: m.RequestID, SessionID: m.SessionID, ChainID: m.ChainID, Depth: m.Depth, Origin: m.OriginNode, Host: m.TargetHost, User: m.User}
	if !ok {
		ev.Decision = "deny"
		ev.Reason = "no live grant (expired, rejected, or never approved)"
		a.auditor.write(ev)
		a.reply(presence, session, &proto.Message{Kind: proto.KindAuthSignReply, RequestID: m.RequestID, SessionID: m.SessionID, Allow: false, Reason: ev.Reason})
		return
	}
	if g.Host != m.TargetHost || g.User != m.User {
		ev.Decision = "deny"
		ev.Reason = fmt.Sprintf("grant is for %s@%s but signature requested for %s@%s", g.User, g.Host, m.User, m.TargetHost)
		a.auditor.write(ev)
		a.reply(presence, session, &proto.Message{Kind: proto.KindAuthSignReply, RequestID: m.RequestID, SessionID: m.SessionID, Allow: false, Reason: ev.Reason})
		return
	}
	if g.ScriptHash != "" && g.ScriptHash != m.ScriptHash {
		ev.Decision = "deny"
		ev.Reason = "batch script hash does not match approved script"
		a.auditor.write(ev)
		a.reply(presence, session, &proto.Message{Kind: proto.KindAuthSignReply, RequestID: m.RequestID, SessionID: m.SessionID, Allow: false, Reason: ev.Reason})
		return
	}
	data, err := base64.StdEncoding.DecodeString(m.SignData)
	if err != nil {
		ev.Decision = "deny"
		ev.Reason = "bad signing payload"
		a.auditor.write(ev)
		a.reply(presence, session, &proto.Message{Kind: proto.KindAuthSignReply, RequestID: m.RequestID, SessionID: m.SessionID, Allow: false, Reason: ev.Reason})
		return
	}
	sig := ed25519.Sign(a.identity.SignPriv, data)
	ev.Decision = "signed"
	ev.GrantID = g.ID
	ev.Auto = g.Auto
	a.auditor.write(ev)
	a.reply(presence, session, &proto.Message{
		Kind: proto.KindAuthSignReply, RequestID: m.RequestID, SessionID: m.SessionID,
		Allow: true, SignData: base64.StdEncoding.EncodeToString(sig), SignAlg: "ssh-ed25519",
	})
}

func (a *Agent) issueGrant(m *proto.Message, ttl int, auto bool, rule string) {
	g := &Grant{
		ID: newRequestID(), SessionID: m.SessionID, ChainID: m.ChainID, Depth: m.Depth,
		OriginNode: m.OriginNode, User: m.User, Host: m.TargetHost, Port: m.TargetPort,
		Fingerprint: m.Fingerprint, Interactive: m.Interactive, ScriptHash: m.ScriptHash,
		ExpiresAt: time.Now().Add(time.Duration(ttl) * time.Second), Auto: auto, RuleName: rule,
	}
	a.grants.put(g)
}

func ruleName(r *policy.Rule) string {
	if r == nil {
		return ""
	}
	return r.Name
}

func decodeB64(s string) []byte {
	b, _ := base64.StdEncoding.DecodeString(s)
	return b
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func orPort(p int) int {
	if p == 0 {
		return 22
	}
	return p
}

func itoa(i int) string {
	return fmt.Sprintf("%d", i)
}
