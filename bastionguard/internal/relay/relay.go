// Package relay is the jump-host process. It is deliberately a *dumb* relay:
// it authenticates nodes with mTLS, enforces network-level zone ACLs, and
// shovels frames. It holds no signing key capable of authenticating to any
// target host, and control frames are end-to-end encrypted for the laptop.
package relay

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"bastionguard/internal/proto"
)

// RouteEntry maps a target zone to the next relay node id and dial address.
type RouteEntry struct {
	Zone     string `json:"zone"`
	NextNode string `json:"next_node"`
	NextAddr string `json:"next_addr"`
}

// Config is one relay node's configuration.
type Config struct {
	NodeID      string                       `json:"node_id"`
	ListenAddr  string                       `json:"listen_addr"`
	LocalZones  []string                     `json:"local_zones"`  // zones this relay may dial directly
	ZoneTargets map[string]map[string]string `json:"zone_targets"` // zone -> logical target -> dial address
	Routes      []RouteEntry                 `json:"routes"`
}

type presenceConn struct {
	conn net.Conn
	seen time.Time
}

type sessRoute struct {
	connID      string   // worker-side routing id for this single connection
	logicalSess string   // agent-side session id (grant key), shared by a batch
	down        net.Conn // worker-side / upstream-relay-side connection
	up          net.Conn // next-hop or target connection
}

type Relay struct {
	cfg      Config
	tlsCfg   *tls.Config
	mu       sync.Mutex
	presence map[string]*presenceConn       // node id -> agent presence connection
	sessions map[string]*sessRoute          // conn id -> route
	logical  map[string]map[string]struct{} // logical session id -> set of conn ids
	logFile  string
	stopCh   chan struct{}
}

func New(cfg Config, stateDir string) (*Relay, error) {
	caPEM, err := os.ReadFile(filepath.Join(stateDir, "ca.pem"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("bad CA PEM")
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(stateDir, "node.crt"), filepath.Join(stateDir, "node.key"))
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}
	return &Relay{
		cfg:      cfg,
		tlsCfg:   tlsCfg,
		presence: map[string]*presenceConn{},
		sessions: map[string]*sessRoute{},
		logical:  map[string]map[string]struct{}{},
		logFile:  filepath.Join(stateDir, "relay-"+cfg.NodeID+".log"),
		stopCh:   make(chan struct{}),
	}, nil
}

func (r *Relay) logf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, err := os.OpenFile(r.logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\n", time.Now().Format(time.RFC3339), fmt.Sprintf(format, args...))
}

func LoadConfig(path string) (Config, error) {
	var c Config
	data, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return c, err
	}
	return c, nil
}

func (r *Relay) Serve() error {
	ln, err := tls.Listen("tcp", r.cfg.ListenAddr, r.tlsCfg)
	if err != nil {
		return err
	}
	r.logf("relay %s listening on %s; local zones %v", r.cfg.NodeID, r.cfg.ListenAddr, r.cfg.LocalZones)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go r.onConn(conn)
	}
}

// certCN extracts the node id from the verified client certificate.
func certCN(conn *tls.Conn) (string, error) {
	st := conn.ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return "", errors.New("no peer certificate")
	}
	return st.PeerCertificates[0].Subject.CommonName, nil
}

func (r *Relay) onConn(conn net.Conn) {
	defer conn.Close()
	tc, ok := conn.(*tls.Conn)
	if !ok {
		r.logf("reject non-TLS connection")
		return
	}
	first, err := proto.ReadFrame(tc)
	if err != nil {
		r.logf("hello read failed: %v", err)
		return
	}
	if first.Type != proto.FrameHello {
		r.logf("first frame was not hello")
		return
	}
	var hello proto.Hello
	if err := json.Unmarshal(first.Payload, &hello); err != nil {
		r.logf("bad hello: %v", err)
		return
	}
	cn, err := certCN(tc)
	if err != nil {
		r.logf("cert error: %v", err)
		return
	}
	if hello.Node != cn {
		r.logf("DENY hello node %q != cert CN %q", hello.Node, cn)
		return
	}
	switch hello.Role {
	case "presence":
		r.servePresence(tc, hello)
	case "client", "relay":
		r.serveSession(tc, hello)
	default:
		r.logf("DENY unknown hello role %q from %s", hello.Role, cn)
	}
}

// servePresence registers the agent's long-lived control connection. Only one
// presence connection per node; a new one replaces the old one.
func (r *Relay) servePresence(conn net.Conn, hello proto.Hello) {
	r.mu.Lock()
	if old := r.presence[hello.Node]; old != nil {
		_ = old.conn.Close()
	}
	r.presence[hello.Node] = &presenceConn{conn: conn, seen: time.Now()}
	r.mu.Unlock()
	r.logf("presence ONLINE node=%s", hello.Node)
	defer func() {
		r.mu.Lock()
		if cur := r.presence[hello.Node]; cur != nil && cur.conn == conn {
			delete(r.presence, hello.Node)
		}
		r.mu.Unlock()
		r.logf("presence OFFLINE node=%s", hello.Node)
	}()
	for {
		f, err := proto.ReadFrame(conn)
		if err != nil {
			return
		}
		switch f.Type {
		case proto.FrameControl:
			// Agent -> worker replies: route back to the session's down conn.
			r.routeControlToWorker(f)
		case proto.FrameTeardown:
			// Agent -> relay: kill every connection of this logical session,
			// closing the underlying target TCP connection immediately.
			r.teardownLogical(string(f.Payload), hello.Node)
		}
	}
}

// teardownLogical closes all relay connections sharing one agent session id.
func (r *Relay) teardownLogical(logicalSess, requester string) {
	r.mu.Lock()
	connIDs := make([]string, 0)
	for cid := range r.logical[logicalSess] {
		connIDs = append(connIDs, cid)
	}
	rtList := make([]*sessRoute, 0, len(connIDs))
	for _, cid := range connIDs {
		if rt := r.sessions[cid]; rt != nil {
			rtList = append(rtList, rt)
		}
	}
	r.mu.Unlock()
	for _, rt := range rtList {
		r.logf("TEARDOWN session=%s conn=%s requested_by=%s", logicalSess, rt.connID, requester)
		_ = rt.down.Close()
		_ = rt.up.Close()
	}
}

func (r *Relay) routeControlToWorker(f proto.Frame) {
	r.mu.Lock()
	rt := r.sessions[f.Session]
	r.mu.Unlock()
	if rt == nil || rt.down == nil {
		r.logf("control reply for unknown session %s dropped", f.Session)
		return
	}
	if err := proto.WriteFrame(rt.down, f); err != nil {
		r.logf("control reply write failed: %v", err)
	}
}

// serveSession handles one worker/relay tunnel connection.
func (r *Relay) serveSession(conn net.Conn, hello proto.Hello) {
	if hello.Session == "" || hello.Target == "" {
		r.logf("DENY session hello missing session/target from %s", hello.Node)
		return
	}
	// ConnID routes frames on the relay mesh; Session stays inside the sealed
	// control messages and keys the agent-side grants.
	connID := hello.ConnID
	if connID == "" {
		connID = hello.Session // tolerate older clients
	}
	zone := hello.Zone
	dialAddr, ok := r.resolveTarget(zone, hello.Target)
	if !ok {
		r.logf("DENY conn=%s node=%s target=%s not in zone %s ACL", connID, hello.Node, hello.Target, zone)
		writeErr(conn, "target not permitted by relay zone ACL")
		return
	}
	up, isLocal, err := r.dialNext(hello, dialAddr)
	if err != nil {
		r.logf("DENY conn=%s dial failed: %v", connID, err)
		writeErr(conn, err.Error())
		return
	}
	r.mu.Lock()
	r.sessions[connID] = &sessRoute{connID: connID, logicalSess: hello.Session, down: conn, up: up}
	if r.logical[hello.Session] == nil {
		r.logical[hello.Session] = map[string]struct{}{}
	}
	r.logical[hello.Session][connID] = struct{}{}
	r.mu.Unlock()
	r.logf("OPEN conn=%s session=%s node=%s zone=%s target=%s local=%t depth=%d",
		connID, hello.Session, hello.Node, hello.Zone, hello.Target, isLocal, len(hello.Chain))
	defer func() {
		r.mu.Lock()
		delete(r.sessions, connID)
		if set := r.logical[hello.Session]; set != nil {
			delete(set, connID)
			if len(set) == 0 {
				delete(r.logical, hello.Session)
			}
		}
		r.mu.Unlock()
		up.Close()
		conn.Close()
		r.logf("CLOSE conn=%s session=%s", connID, hello.Session)
	}()

	// Upstream frames from the worker: data -> next hop/target, control ->
	// presence connection of the laptop agent.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		r.pumpWorkerToUp(conn, up, hello, isLocal)
	}()
	go func() {
		defer wg.Done()
		r.pumpUpToWorker(up, conn, isLocal)
	}()
	wg.Wait()
}

func (r *Relay) pumpWorkerToUp(down, up net.Conn, hello proto.Hello, isLocal bool) {
	cid := hello.ConnID
	if cid == "" {
		cid = hello.Session
	}
	for {
		f, err := proto.ReadFrame(down)
		if err != nil {
			_ = up.Close()
			return
		}
		switch f.Type {
		case proto.FrameData:
			if isLocal {
				if _, err := up.Write(f.Payload); err != nil {
					return
				}
			} else {
				f.Session = cid
				if err := proto.WriteFrame(up, f); err != nil {
					return
				}
			}
		case proto.FrameControl:
			// Forward to the laptop via its presence connection at the home
			// relay. This relay is the home relay in the demo topology.
			r.mu.Lock()
			pc := r.presence[agentNodeID(hello)]
			r.mu.Unlock()
			if pc == nil {
				// The relay cannot seal an error for the agent, so it logs and
				// drops the connection; the worker's watchdog turns that into a
				// clean "agent offline" failure.
				r.logf("DENY control conn=%s: agent offline; closing", cid)
				_ = down.Close()
				return
			}
			pc.seen = time.Now()
			f.Session = cid
			if err := proto.WriteFrame(pc.conn, f); err != nil {
				r.logf("presence write failed: %v", err)
				return
			}
		}
	}
}

func (r *Relay) pumpUpToWorker(up, down net.Conn, isLocal bool) {
	if isLocal {
		// Raw TCP bytes from the target; wrap into data frames.
		buf := make([]byte, proto.MaxDataFrame)
		for {
			n, err := up.Read(buf)
			if n > 0 {
				payload := make([]byte, n)
				copy(payload, buf[:n])
				if werr := proto.WriteFrame(down, proto.Frame{Type: proto.FrameData, Payload: payload}); werr != nil {
					return
				}
			}
			if err != nil {
				_ = down.Close()
				return
			}
		}
	}
	// Inter-relay: framed input, re-frame downstream.
	for {
		f, err := proto.ReadFrame(up)
		if err != nil {
			_ = down.Close()
			return
		}
		if err := proto.WriteFrame(down, f); err != nil {
			return
		}
	}
}

// agentNodeID derives the presence id of the laptop. All demo workers act on
// behalf of the single enrolled agent; the hello carries its chain so the
// relay stays topology-agnostic.
func agentNodeID(hello proto.Hello) string {
	if len(hello.Chain) > 0 {
		return "laptop-agent"
	}
	return "laptop-agent"
}

// resolveTarget maps a logical target name inside a zone to the concrete
// dial address this relay is allowed to use.
func (r *Relay) resolveTarget(zone, target string) (string, bool) {
	m, ok := r.cfg.ZoneTargets[zone]
	if !ok {
		return "", false
	}
	addr, ok := m[target]
	if !ok {
		// Wildcard entry allows any target inside the zone; the map value
		// holds the dial address for the literal name.
		if wildcard, hasWC := m["*"]; hasWC {
			return wildcard, true
		}
		return "", false
	}
	return addr, true
}

// dialNext dials either the local target directly (plain TCP, frames unwrap
// here) or the next relay in the chain (mTLS, frames stay framed).
func (r *Relay) dialNext(hello proto.Hello, localDialAddr string) (net.Conn, bool, error) {
	isLocalZone := false
	for _, z := range r.cfg.LocalZones {
		if z == hello.Zone {
			isLocalZone = true
			break
		}
	}
	if isLocalZone {
		c, err := net.DialTimeout("tcp", localDialAddr, 5*time.Second)
		return c, true, err
	}
	for _, rt := range r.cfg.Routes {
		if rt.Zone == hello.Zone {
			c, err := tls.Dial("tcp", rt.NextAddr, r.tlsCfg)
			if err != nil {
				return nil, false, err
			}
			nextHello := hello
			nextHello.Node = r.cfg.NodeID
			nextHello.Role = "relay"
			if err := proto.WriteFrame(c, proto.Frame{Type: proto.FrameHello, Payload: mustJSON(nextHello)}); err != nil {
				c.Close()
				return nil, false, err
			}
			return c, false, nil
		}
	}
	return nil, false, fmt.Errorf("no route to zone %s", hello.Zone)
}

func writeErr(conn net.Conn, msg string) {
	// Reuse the hello frame type as a generic "connection refused before
	// establishment" envelope; callers treat any first-frame response that is
	// not an open tunnel as a denial.
	_ = proto.WriteFrame(conn, proto.Frame{Type: proto.FrameHello, Payload: mustJSON(proto.Hello{Node: "error: " + msg})})
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
