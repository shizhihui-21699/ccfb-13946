// Package worker runs on the jump host. It holds NO key that target hosts
// trust: its own node key only authenticates it to relays. Every SSH userauth
// signature is requested from the laptop agent over the sealed control
// channel and scoped to one approved session.
package worker

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"bastionguard/internal/keys"
	"bastionguard/internal/proto"
)

// Config describes where to dial and which chain the operator asked for.
type Config struct {
	EntryAddr   string
	Chain       []string // relay node ids, entry first
	Zone        string
	TargetHost  string
	TargetPort  int
	User        string
	Command     string
	Interactive bool
	ScriptHash  string // set in batch mode
}

// Worker is one jump-host process identity.
type Worker struct {
	bundle   *keys.Bundle
	tlsCfg   *tls.Config
	opener   *proto.Opener
	sealer   *proto.Sealer
	signPriv ed25519.PrivateKey
	mu       sync.Mutex
	waiters  map[string]chan *proto.Message
}

func New(stateDir string) (*Worker, error) {
	bundle, err := keys.LoadBundle(stateDir)
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(filepath.Join(stateDir, "ca.pem"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	cert, err := tls.LoadX509KeyPair(filepath.Join(stateDir, "node.crt"), filepath.Join(stateDir, "node.key"))
	if err != nil {
		return nil, err
	}
	ecdhPriv, err := loadEcdh(bundle.EcdhPriv)
	if err != nil {
		return nil, err
	}
	agentEcdh, err := base64.StdEncoding.DecodeString(bundle.AgentEcdhPub)
	if err != nil {
		return nil, err
	}
	sealer, err := proto.NewSealer(agentEcdh, "agent")
	if err != nil {
		return nil, err
	}
	signSeed, err := base64.StdEncoding.DecodeString(bundle.SignPriv)
	if err != nil || len(signSeed) != ed25519.SeedSize {
		return nil, fmt.Errorf("bad worker signing seed in bundle")
	}
	return &Worker{
		bundle:   bundle,
		tlsCfg:   &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, MinVersion: tls.VersionTLS13},
		opener:   proto.NewOpener(ecdhPriv),
		sealer:   sealer,
		signPriv: ed25519.NewKeyFromSeed(signSeed),
		waiters:  map[string]chan *proto.Message{},
	}, nil
}

// Session is one approved tunnel to one target.
type Session struct {
	w         *Worker
	conn      net.Conn
	connID    string // relay mesh routing id (unique per connection)
	sessionID string // logical agent session id (grant key)
	chainID   string
	cfg       Config
	readBuf   []byte
	readOff   int
	closed    bool
	closeErr  error
	closeMu   sync.Mutex
}

// OpenSession performs the hello + sealed session_open dance and returns a
// net.Conn carrying raw SSH bytes.
func (w *Worker) OpenSession(cfg Config) (*Session, error) {
	sessID := randID()
	chainID := randID()
	connID := randID()
	conn, err := tls.Dial("tcp", cfg.EntryAddr, w.tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("dial entry relay: %w", err)
	}
	hello := proto.Hello{
		Role: "client", Node: w.bundle.NodeID, ConnID: connID, Session: sessID,
		Zone: cfg.Zone, Target: net.JoinHostPort(cfg.TargetHost, fmt.Sprintf("%d", cfg.TargetPort)),
		Chain: cfg.Chain,
	}
	if err := proto.WriteFrame(conn, proto.Frame{Type: proto.FrameHello, Payload: mustJSON(hello)}); err != nil {
		conn.Close()
		return nil, err
	}
	s := &Session{w: w, conn: conn, connID: connID, sessionID: sessID, chainID: chainID, cfg: cfg}
	w.registerSession(s)

	open := &proto.Message{
		Kind: proto.KindSessionOpen, RequestID: randID(), SessionID: sessID,
		ChainID: chainID, Depth: len(cfg.Chain), OriginNode: w.bundle.NodeID,
		User: cfg.User, TargetHost: cfg.TargetHost, TargetPort: cfg.TargetPort,
		Command: cfg.Command, Interactive: cfg.Interactive, ScriptHash: cfg.ScriptHash,
	}
	reply, err := w.roundTrip(conn, connID, open)
	if err != nil {
		w.unregisterSession(connID)
		conn.Close()
		return nil, err
	}
	if !reply.Allow {
		w.unregisterSession(connID)
		conn.Close()
		return nil, fmt.Errorf("laptop agent denied session: %s", reply.Reason)
	}
	return s, nil
}

// OpenBatch asks once for approval covering many targets and returns sessions
// only after the single approval succeeds. All target tunnels share one agent
// session id and script hash, but each gets its own relay conn id.
func (w *Worker) OpenBatch(cfg Config, targets []proto.BatchTarget) ([]*Session, error) {
	sessID := randID()
	chainID := randID()
	open := &proto.Message{
		Kind: proto.KindBatchOpen, RequestID: randID(), SessionID: sessID,
		ChainID: chainID, Depth: len(cfg.Chain), OriginNode: w.bundle.NodeID,
		User: cfg.User, Batch: targets, ScriptHash: cfg.ScriptHash, Command: cfg.Command,
	}
	// First target's relay connection carries the batch_open control message.
	first := targets[0]
	probeCfg := cfg
	probeCfg.TargetHost = first.Host
	probeCfg.TargetPort = orDefaultPort(first.Port)
	probeCfg.User = firstNonEmpty(first.User, cfg.User)
	firstConnID := randID()
	conn, err := tls.Dial("tcp", cfg.EntryAddr, w.tlsCfg)
	if err != nil {
		return nil, err
	}
	hello := proto.Hello{
		Role: "client", Node: w.bundle.NodeID, ConnID: firstConnID, Session: sessID,
		Zone: cfg.Zone, Target: net.JoinHostPort(probeCfg.TargetHost, fmt.Sprintf("%d", probeCfg.TargetPort)),
		Chain: cfg.Chain,
	}
	if err := proto.WriteFrame(conn, proto.Frame{Type: proto.FrameHello, Payload: mustJSON(hello)}); err != nil {
		conn.Close()
		return nil, err
	}
	s := &Session{w: w, conn: conn, connID: firstConnID, sessionID: sessID, chainID: chainID, cfg: probeCfg}
	w.registerSession(s)
	reply, err := w.roundTrip(conn, firstConnID, open)
	if err != nil {
		w.unregisterSession(firstConnID)
		conn.Close()
		return nil, err
	}
	if !reply.Allow {
		w.unregisterSession(firstConnID)
		conn.Close()
		return nil, fmt.Errorf("batch rejected by laptop agent: %s", reply.Reason)
	}
	sessions := []*Session{s}
	for _, bt := range targets[1:] {
		cc := cfg
		cc.TargetHost = bt.Host
		cc.TargetPort = orDefaultPort(bt.Port)
		cc.User = firstNonEmpty(bt.User, cfg.User)
		sess, err := w.openApproved(cc, sessID, chainID)
		if err != nil {
			for _, x := range sessions {
				x.Close()
			}
			return nil, err
		}
		sessions = append(sessions, sess)
	}
	return sessions, nil
}

// openApproved opens a relay tunnel under an already approved batch session.
func (w *Worker) openApproved(cfg Config, sessID, chainID string) (*Session, error) {
	connID := randID()
	conn, err := tls.Dial("tcp", cfg.EntryAddr, w.tlsCfg)
	if err != nil {
		return nil, err
	}
	hello := proto.Hello{
		Role: "client", Node: w.bundle.NodeID, ConnID: connID, Session: sessID,
		Zone: cfg.Zone, Target: net.JoinHostPort(cfg.TargetHost, fmt.Sprintf("%d", cfg.TargetPort)),
		Chain: cfg.Chain,
	}
	if err := proto.WriteFrame(conn, proto.Frame{Type: proto.FrameHello, Payload: mustJSON(hello)}); err != nil {
		conn.Close()
		return nil, err
	}
	s := &Session{w: w, conn: conn, connID: connID, sessionID: sessID, chainID: chainID, cfg: cfg}
	w.registerSession(s)
	return s, nil
}

func (w *Worker) registerSession(s *Session) {
	w.mu.Lock()
	w.waiters[s.connID] = make(chan *proto.Message, 16)
	w.mu.Unlock()
	go w.readLoop(s)
}

func (w *Worker) unregisterSession(connID string) {
	w.mu.Lock()
	delete(w.waiters, connID)
	w.mu.Unlock()
}

func (w *Worker) readLoop(s *Session) {
	defer func() {
		// A closed relay connection (e.g. agent went offline) must unblock any
		// pending roundTrip instead of leaving it to the full timeout.
		w.mu.Lock()
		if ch := w.waiters[s.connID]; ch != nil {
			close(ch)
			delete(w.waiters, s.connID)
		}
		w.mu.Unlock()
	}()
	for {
		f, err := proto.ReadFrame(s.conn)
		if err != nil {
			s.closeWith(err)
			return
		}
		switch f.Type {
		case proto.FrameData:
			s.pushData(f.Payload)
		case proto.FrameControl:
			msg, err := w.opener.Open(f.Payload)
			if err != nil {
				continue
			}
			if err := msg.Verify(); err != nil {
				continue
			}
			// Pin replies to the enrolled laptop agent's signing key: a relay
			// root cannot inject a fake "allow" decision even with TLS MITM.
			if msg.NodePub != w.bundle.AgentSignPub {
				continue
			}
			w.mu.Lock()
			ch := w.waiters[s.connID]
			w.mu.Unlock()
			if ch != nil {
				select {
				case ch <- msg:
				default:
				}
			}
		}
	}
}

// roundTrip sends one sealed control message on a relay connection routed by
// connID. The inner Message's SessionID (the agent grant key) is untouched.
func (w *Worker) roundTrip(conn net.Conn, connID string, m *proto.Message) (*proto.Message, error) {
	// Always fresh: SSH may retry an auth round, and a reused nonce would be
	// mistaken for a replay by the agent's dedup cache.
	m.Nonce = randID()
	m.TS = time.Now().Unix()
	if err := m.Sign(w.signPriv); err != nil {
		return nil, err
	}
	sealed, err := w.sealer.Seal(m)
	if err != nil {
		return nil, err
	}
	if err := proto.WriteFrame(conn, proto.Frame{Type: proto.FrameControl, Session: connID, Payload: sealed}); err != nil {
		return nil, err
	}
	// Demo-only evidence capture: when BG_CAPTURE_DIR is set the worker
	// persists one sealed control frame so bg-attacker can attempt a real
	// replay. In production this hook is simply never enabled.
	if dir := os.Getenv("BG_CAPTURE_DIR"); dir != "" {
		_ = os.WriteFile(filepath.Join(dir, "captured-sealed.bin"), sealed, 0o600)
	}
	w.mu.Lock()
	ch := w.waiters[connID]
	w.mu.Unlock()
	if ch == nil {
		return nil, errors.New("session gone")
	}
	select {
	case reply, ok := <-ch:
		if !ok {
			return nil, errors.New("relay closed the control channel (laptop agent offline?)")
		}
		return reply, nil
	case <-time.After(2*time.Minute + 30*time.Second):
		return nil, errors.New("agent approval timed out")
	}
}

// Control sends a non-open control message on an existing connection.
func (s *Session) Control(m *proto.Message) (*proto.Message, error) {
	m.SessionID = s.sessionID
	if m.ChainID == "" {
		m.ChainID = s.chainID
	}
	if m.OriginNode == "" {
		m.OriginNode = s.w.bundle.NodeID
	}
	return s.w.roundTrip(s.conn, s.connID, m)
}

func (s *Session) ID() string    { return s.sessionID }
func (s *Session) Chain() string { return s.chainID }

// Write sends raw SSH bytes to the target.
func (s *Session) Write(p []byte) (int, error) {
	if err := proto.WriteFrame(s.conn, proto.Frame{Type: proto.FrameData, Session: s.connID, Payload: p}); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Read returns raw SSH bytes from the target.
func (s *Session) Read(p []byte) (int, error) {
	for {
		s.closeMu.Lock()
		if s.readOff < len(s.readBuf) {
			n := copy(p, s.readBuf[s.readOff:])
			s.readOff += n
			s.closeMu.Unlock()
			return n, nil
		}
		if s.closed {
			err := s.closeErr
			s.closeMu.Unlock()
			return 0, err
		}
		s.closeMu.Unlock()
		time.Sleep(2 * time.Millisecond)
	}
}

func (s *Session) pushData(p []byte) {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.readOff > 0 {
		s.readBuf = append(s.readBuf[s.readOff:], p...)
		s.readOff = 0
	} else {
		s.readBuf = append(s.readBuf, p...)
	}
}

func (s *Session) closeWith(err error) {
	s.closeMu.Lock()
	s.closed = true
	s.closeErr = err
	s.closeMu.Unlock()
}

func (s *Session) Close() error {
	closeMsg := &proto.Message{
		Kind: proto.KindSessionClose, RequestID: randID(),
		TargetHost: s.cfg.TargetHost, User: s.cfg.User,
	}
	_, _ = s.Control(closeMsg)
	s.w.unregisterSession(s.connID)
	return s.conn.Close()
}

func (s *Session) LocalAddr() net.Addr              { return dummyAddr{} }
func (s *Session) RemoteAddr() net.Addr             { return dummyAddr{} }
func (s *Session) SetDeadline(time.Time) error      { return nil }
func (s *Session) SetReadDeadline(time.Time) error  { return nil }
func (s *Session) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "bastionguard" }
func (dummyAddr) String() string  { return "tunnel" }

func randID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// BundleHomeAddr exposes the home relay address from the enrollment bundle.
func (w *Worker) BundleHomeAddr() string { return w.bundle.HomeRelayAddr }

// BundleAgentSignPub exposes the laptop agent's authorized signing key.
func (w *Worker) BundleAgentSignPub() string { return w.bundle.AgentSignPub }

// TargetName labels a session in batch output.
func (s *Session) TargetName() string {
	return net.JoinHostPort(s.cfg.TargetHost, fmt.Sprintf("%d", s.cfg.TargetPort))
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func orDefaultPort(p int) int {
	if p == 0 {
		return 22
	}
	return p
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
