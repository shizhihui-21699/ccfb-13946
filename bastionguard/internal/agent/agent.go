// Package agent is the laptop-side guardian. It holds the only signing key
// that target hosts trust, keeps a presence connection to the home relay, and
// makes every borrow decision locally. Nothing in this package ever sends the
// private key anywhere.
package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"bastionguard/internal/keys"
	"bastionguard/internal/policy"
	"bastionguard/internal/proto"
)

// PendingRequest is what bgctl shows the operator.
type PendingRequest struct {
	RequestID   string              `json:"request_id"`
	Kind        string              `json:"kind"`
	SessionID   string              `json:"session_id,omitempty"`
	ChainID     string              `json:"chain_id,omitempty"`
	Depth       int                 `json:"depth"`
	OriginNode  string              `json:"origin_node"`
	User        string              `json:"user"`
	Host        string              `json:"host,omitempty"`
	Zone        string              `json:"zone,omitempty"`
	Command     string              `json:"command,omitempty"`
	Interactive bool                `json:"interactive"`
	Batch       []proto.BatchTarget `json:"batch,omitempty"`
	Reason      string              `json:"reason,omitempty"`
	Urgent      bool                `json:"urgent"`
	CreatedAt   time.Time           `json:"created_at"`
}

type pending struct {
	req     PendingRequest
	replyCh chan decision
}

type decision struct {
	allow bool
	ttl   int
}

type Agent struct {
	stateDir   string
	identity   *keys.AgentIdentity
	pol        *policy.Policy
	auditor    *auditLog
	notifier   Notifier
	opener     *proto.Opener
	sealer     *proto.Sealer // seals replies for the worker node
	workerPub  []byte        // worker node ECDH public key (pinned at enrollment)
	workerSign ed25519.PublicKey

	tlsCfg   *tls.Config
	homeAddr string
	homeNode string

	mu       sync.Mutex
	presence net.Conn
	grants   *grantStore
	pendings map[string]*pending
	burst    *burstTracker
	nonces   *nonceCache
	hostKeys map[string]string // host:port -> fingerprint (TOFU ledger)
	stopCh   chan struct{}
	wg       sync.WaitGroup

	socketPath string
}

// New wires the agent from on-disk state.
func New(stateDir, socketPath string) (*Agent, error) {
	id, err := keys.LoadAgent(stateDir)
	if err != nil {
		return nil, err
	}
	pol, err := policy.Load(filepath.Join(stateDir, "policy.json"))
	if err != nil {
		return nil, fmt.Errorf("load policy: %w", err)
	}
	auditor, err := openAuditLog(stateDir)
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(filepath.Join(stateDir, "ca.pem"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	cert, err := tls.LoadX509KeyPair(filepath.Join(stateDir, "laptop.crt"), filepath.Join(stateDir, "laptop.key"))
	if err != nil {
		return nil, err
	}
	bundle, err := keys.LoadBundle(stateDir)
	if err != nil {
		return nil, err
	}
	workerEcdh, err := base64.StdEncoding.DecodeString(bundle.EcdhPub)
	if err != nil {
		return nil, err
	}
	sealer, err := proto.NewSealer(workerEcdh, "worker")
	if err != nil {
		return nil, err
	}
	workerSignRaw, err := base64.StdEncoding.DecodeString(bundle.SignPub)
	if err != nil || len(workerSignRaw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("bad worker signing key in bundle")
	}
	hostLedgerPath := filepath.Join(stateDir, "known-hosts.json")
	hk := map[string]string{}
	if data, err := os.ReadFile(hostLedgerPath); err == nil {
		_ = json.Unmarshal(data, &hk)
	}

	a := &Agent{
		stateDir:   stateDir,
		identity:   id,
		pol:        pol,
		auditor:    auditor,
		notifier:   NewNotifier(),
		opener:     proto.NewOpener(id.EcdhPriv),
		sealer:     sealer,
		workerSign: ed25519.PublicKey(workerSignRaw),
		tlsCfg: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      pool,
			MinVersion:   tls.VersionTLS13,
		},
		homeAddr:   bundle.HomeRelayAddr,
		homeNode:   bundle.AgentHomeRelay,
		grants:     newGrantStore(),
		pendings:   map[string]*pending{},
		burst:      newBurstTracker(pol.BurstWindowDuration(), pol.BurstThreshold),
		nonces:     newNonceCache(10 * time.Minute),
		hostKeys:   hk,
		stopCh:     make(chan struct{}),
		socketPath: socketPath,
	}
	return a, nil
}

// Run maintains the presence connection and serves the local control socket.
func (a *Agent) Run() error {
	a.wg.Add(3)
	go a.maintainPresence()
	go a.serveControlSocket()
	go a.leaseReaper()
	a.wg.Wait()
	return nil
}

// leaseReaper periodically expires grants whose TTL elapsed and tells the
// relay to tear their tunnels down. A hanging session cannot outlive its
// approval window.
func (a *Agent) leaseReaper() {
	defer a.wg.Done()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-a.stopCh:
			return
		case now := <-ticker.C:
			expired := a.grants.takeExpired(now)
			for _, g := range expired {
				a.auditor.write(AuditEvent{
					Kind: "grant_expired", SessionID: g.SessionID, Host: g.Host,
					User: g.User, Decision: "expired",
				})
				a.teardown(g.SessionID)
			}
		}
	}
}

func (a *Agent) Stop() {
	close(a.stopCh)
	a.mu.Lock()
	if a.presence != nil {
		_ = a.presence.Close()
	}
	a.mu.Unlock()
	a.auditor.close()
}

// maintainPresence dials the home relay and reconnects with backoff. While no
// presence connection exists, the relay refuses every control request — this
// is the "only while the operator is online" guarantee.
func (a *Agent) maintainPresence() {
	defer a.wg.Done()
	backoff := time.Second
	for {
		select {
		case <-a.stopCh:
			return
		default:
		}
		err := a.presenceRound()
		if err != nil {
			a.auditor.write(AuditEvent{Kind: "presence", Decision: "down", Reason: err.Error()})
		}
		select {
		case <-a.stopCh:
			return
		case <-time.After(backoff):
		}
		if backoff < 15*time.Second {
			backoff *= 2
		}
	}
}

func (a *Agent) presenceRound() error {
	conn, err := tls.Dial("tcp", a.homeAddr, a.tlsCfg)
	if err != nil {
		return err
	}
	hello := proto.Hello{Role: "presence", Node: a.identity.ID}
	if err := proto.WriteFrame(conn, proto.Frame{Type: proto.FrameHello, Payload: mustJSON(hello)}); err != nil {
		conn.Close()
		return err
	}
	a.mu.Lock()
	a.presence = conn
	a.mu.Unlock()
	a.auditor.write(AuditEvent{Kind: "presence", Decision: "up", Origin: a.homeNode})
	defer func() {
		a.mu.Lock()
		if a.presence == conn {
			a.presence = nil
		}
		a.mu.Unlock()
		conn.Close()
	}()
	for {
		f, err := proto.ReadFrame(conn)
		if err != nil {
			return err
		}
		if f.Type != proto.FrameControl {
			continue
		}
		msg, err := a.opener.Open(f.Payload)
		if err != nil {
			a.auditor.write(AuditEvent{Kind: "seal_error", Decision: "deny", Reason: err.Error()})
			continue
		}
		// The sealed channel proves confidentiality; the embedded signature
		// proves the message came from the enrolled worker and was not altered.
		if err := msg.Verify(); err != nil {
			a.auditor.write(AuditEvent{Kind: "bad_signature", Decision: "deny", Reason: err.Error()})
			continue
		}
		if !keysEqual(msg.NodePub, base64.StdEncoding.EncodeToString(a.workerSign)) {
			a.auditor.write(AuditEvent{Kind: "unexpected_sender", Decision: "deny", Reason: "signed by non-enrolled node"})
			continue
		}
		if a.nonces.seenOrAdd(msg.Nonce, time.Now()) {
			a.auditor.write(AuditEvent{Kind: "replay_blocked", Decision: "deny", RequestID: msg.RequestID, SessionID: msg.SessionID, Reason: "duplicate or missing nonce"})
			continue
		}
		go a.handleControl(conn, f.Session, msg)
	}
}

func keysEqual(a, b string) bool {
	x, err1 := base64.StdEncoding.DecodeString(a)
	y, err2 := base64.StdEncoding.DecodeString(b)
	if err1 != nil || err2 != nil || len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func newRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// reply seals a control message for the worker and hands it to the relay over
// the presence connection; the relay routes it back via the session id.
func (a *Agent) reply(presence net.Conn, session string, m *proto.Message) {
	m.NodePub = ""
	m.TS = time.Now().Unix()
	if m.Nonce == "" {
		var b [12]byte
		_, _ = rand.Read(b[:])
		m.Nonce = base64.RawURLEncoding.EncodeToString(b[:])
	}
	if err := m.Sign(a.identity.SignPriv); err != nil {
		a.auditor.write(AuditEvent{Kind: "reply_error", Decision: "error", Reason: err.Error()})
		return
	}
	sealed, err := a.sealer.Seal(m)
	if err != nil {
		a.auditor.write(AuditEvent{Kind: "reply_error", Decision: "error", Reason: err.Error()})
		return
	}
	a.mu.Lock()
	pc := a.presence
	a.mu.Unlock()
	if pc == nil || pc != presence {
		a.auditor.write(AuditEvent{Kind: "reply_error", Decision: "error", Reason: "presence changed while handling request"})
		return
	}
	if err := proto.WriteFrame(presence, proto.Frame{Type: proto.FrameControl, Session: session, Payload: sealed}); err != nil {
		a.auditor.write(AuditEvent{Kind: "reply_error", Decision: "error", Reason: err.Error()})
	}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
