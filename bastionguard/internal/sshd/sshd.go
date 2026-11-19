// Package sshd is the simulated target host's SSH server. It authenticates
// only against the laptop agent's signing public key and logs every command
// executed, so the demo can prove which logins actually reached the host.
package sshd

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type Server struct {
	Host       string // logical host name, e.g. "db-1"
	ListenAddr string
	hostSigner ssh.Signer
	authKey    string // base64 of authorized ed25519 public key
	mu         sync.Mutex
	logFile    string
}

// New creates a server with a freshly generated host key.
func New(host, listenAddr, stateDir, agentPubB64 string) (*Server, []byte, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, nil, err
	}
	s := &Server{
		Host:       host,
		ListenAddr: listenAddr,
		hostSigner: signer,
		authKey:    agentPubB64,
		logFile:    filepath.Join(stateDir, "sshd-"+host+".log"),
	}
	// Authorized keys file: only the laptop agent's control signing key.
	// The worker never holds this key; every userauth signature is produced
	// on the laptop via the control channel.
	authLine := fmt.Sprintf("ssh-ed25519 %s bastionguard-agent\n", agentPubB64)
	if err := os.WriteFile(filepath.Join(stateDir, "authorized_keys_"+host), []byte(authLine), 0o600); err != nil {
		return nil, nil, err
	}
	// Known-hosts material for the worker/agent TOFU check.
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	knownLine := fmt.Sprintf("%s %s", listenAddr, string(ssh.MarshalAuthorizedKey(sshPub)))
	return s, []byte(knownLine), nil
}

func (s *Server) logf(format string, args ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(s.logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, format+"\n", args...)
}

func (s *Server) config() *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{}
	cfg.AddHostKey(s.hostSigner)
	cfg.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		authorized, err := ssh.ParsePublicKey(wrapEd25519Wire(decodeB64(s.authKey)))
		if err != nil {
			return nil, fmt.Errorf("server key config error")
		}
		if key.Type() != "ssh-ed25519" || !bytesEqual(key.Marshal(), authorized.Marshal()) {
			s.logf("DENIED login user=%s remote=%s keytype=%s", conn.User(), conn.RemoteAddr(), key.Type())
			return nil, fmt.Errorf("unknown public key")
		}
		s.logf("ACCEPTED login user=%s remote=%s", conn.User(), conn.RemoteAddr())
		return &ssh.Permissions{Extensions: map[string]string{"user": conn.User()}}, nil
	}
	return cfg
}

func (s *Server) Serve() error {
	ln, err := net.Listen("tcp", s.ListenAddr)
	if err != nil {
		return err
	}
	s.logf("sshd %s listening on %s", s.Host, s.ListenAddr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(nconn net.Conn) {
	conn, chans, reqs, err := ssh.NewServerConn(nconn, s.config())
	if err != nil {
		s.logf("handshake failed from %s: %v", nconn.RemoteAddr(), err)
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only session channels")
			continue
		}
		ch, reqs, err := newCh.Accept()
		if err != nil {
			continue
		}
		go s.handleSession(conn, ch, reqs)
	}
}

func (s *Server) handleSession(conn *ssh.ServerConn, ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	user := ""
	if conn.Permissions != nil {
		user = conn.Permissions.Extensions["user"]
	}
	for req := range reqs {
		switch req.Type {
		case "exec":
			var payload struct{ Command string }
			if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
				req.Reply(false, nil)
				continue
			}
			s.logf("EXEC user=%s host=%s cmd=%q", user, s.Host, payload.Command)
			req.Reply(true, nil)
			s.runFakeCommand(ch, payload.Command)
			return
		case "shell":
			req.Reply(true, nil)
			fmt.Fprintf(ch, "[%s@%s bastionguard fake-shell] $ ", user, s.Host)
			io.Copy(io.Discard, ch)
			return
		default:
			req.Reply(false, nil)
		}
	}
}

// runFakeCommand produces deterministic output for the demo's scripted calls.
func (s *Server) runFakeCommand(ch ssh.Channel, command string) {
	c := strings.TrimSpace(command)
	switch {
	case strings.HasPrefix(c, "bghold"):
		// Simulate a long-lived session (deployment tail, interactive job).
		dur := 10 * time.Second
		fields := strings.Fields(c)
		if len(fields) > 1 {
			if parsed, err := time.ParseDuration(fields[1]); err == nil {
				dur = parsed
			}
		}
		fmt.Fprintf(ch, "[%s] holding session for %s\n", s.Host, dur)
		timer := time.NewTimer(dur)
		defer timer.Stop()
		<-timer.C
		fmt.Fprintf(ch, "[%s] hold complete\n", s.Host)
	case strings.HasPrefix(c, "hostname"):
		fmt.Fprintf(ch, "%s\n", s.Host)
	case strings.HasPrefix(c, "uptime"):
		fmt.Fprintln(ch, " 10:00 up 42 days, 3:14, 1 user, load 0.10 0.08 0.05")
	case strings.HasPrefix(c, "whoami"):
		fmt.Fprintln(ch, "ops")
	default:
		fmt.Fprintf(ch, "[%s] executed: %s\n", s.Host, c)
	}
	fmt.Fprintf(ch, "exit-status 0\n")
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{0}))
}

func decodeB64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

// wrapEd25519Wire encodes a raw ed25519 public key as the SSH wire format.
func wrapEd25519Wire(raw []byte) []byte {
	typeName := "ssh-ed25519"
	out := make([]byte, 0, 4+len(typeName)+4+len(raw))
	out = appendLenStr(out, []byte(typeName))
	out = appendLenStr(out, raw)
	return out
}

func appendLenStr(buf, s []byte) []byte {
	var l [4]byte
	l[0] = byte(len(s) >> 24)
	l[1] = byte(len(s) >> 16)
	l[2] = byte(len(s) >> 8)
	l[3] = byte(len(s))
	buf = append(buf, l[:]...)
	return append(buf, s...)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
