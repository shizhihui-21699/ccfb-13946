package worker

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"

	"bastionguard/internal/agent"
	"bastionguard/internal/proto"

	"golang.org/x/crypto/ssh"
)

// remoteSigner implements ssh.Signer without ever seeing the private key.
// PublicKey returns the agent's key; Sign asks the laptop over the sealed
// control channel, and the laptop only answers if a live grant matches this
// exact session and target.
type remoteSigner struct {
	pubKey  ssh.PublicKey
	session *Session
	user    string
}

func newRemoteSigner(session *Session, agentSignPubB64 string, user string) (*remoteSigner, error) {
	raw, err := base64.StdEncoding.DecodeString(agentSignPubB64)
	if err != nil {
		return nil, err
	}
	// The bundle stores the raw 32-byte ed25519 key; x/crypto/ssh wants the
	// SSH wire format (type string + length-prefixed key), so wrap it first.
	wire := wrapEd25519Wire(raw)
	pub, err := ssh.ParsePublicKey(wire)
	if err != nil {
		return nil, err
	}
	return &remoteSigner{pubKey: pub, session: session, user: user}, nil
}

// wrapEd25519Wire encodes a raw ed25519 public key as an SSH wire key.
func wrapEd25519Wire(raw []byte) []byte {
	typeName := "ssh-ed25519"
	out := make([]byte, 0, 4+len(typeName)+4+len(raw))
	out = appendString(out, []byte(typeName))
	out = appendString(out, raw)
	return out
}

func appendString(buf, s []byte) []byte {
	var l [4]byte
	l[0] = byte(len(s) >> 24)
	l[1] = byte(len(s) >> 16)
	l[2] = byte(len(s) >> 8)
	l[3] = byte(len(s))
	buf = append(buf, l[:]...)
	return append(buf, s...)
}

func (r *remoteSigner) PublicKey() ssh.PublicKey { return r.pubKey }

// Sign satisfies ssh.Signer. The opts-free interface is what x/crypto/ssh
// calls for an ssh-ed25519 key; SignWithAlgorithm covers algorithm-aware users.
func (r *remoteSigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	return r.signRemotely(data, "")
}

func (r *remoteSigner) SignWithAlgorithm(_ io.Reader, data []byte, _ string) (*ssh.Signature, error) {
	return r.signRemotely(data, "ssh-ed25519")
}

func (r *remoteSigner) signRemotely(data []byte, alg string) (*ssh.Signature, error) {
	msg := &proto.Message{
		Kind:       proto.KindAuthSign,
		RequestID:  randID(),
		User:       r.user,
		TargetHost: r.session.cfg.TargetHost,
		TargetPort: r.session.cfg.TargetPort,
		SignData:   base64.StdEncoding.EncodeToString(data),
		SignAlg:    firstStr(alg, "ssh-ed25519"),
		ScriptHash: r.session.cfg.ScriptHash,
	}
	reply, err := r.session.Control(msg)
	if err != nil {
		return nil, err
	}
	if !reply.Allow {
		return nil, fmt.Errorf("laptop refused signature: %s", reply.Reason)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(reply.SignData)
	if err != nil {
		return nil, err
	}
	return &ssh.Signature{Format: "ssh-ed25519", Blob: sigBytes}, nil
}

func firstStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// hostKeyCallback asks the laptop whether to trust this host key (TOFU +
// grant fingerprint pinning), instead of trusting anything the relay offers.
func hostKeyCallback(session *Session) ssh.HostKeyCallback {
	return func(hostname string, _ net.Addr, key ssh.PublicKey) error {
		msg := &proto.Message{
			Kind:        proto.KindHostKeyCheck,
			RequestID:   randID(),
			TargetHost:  session.cfg.TargetHost,
			TargetPort:  session.cfg.TargetPort,
			User:        session.cfg.User,
			SignData:    base64.StdEncoding.EncodeToString(key.Marshal()),
			Fingerprint: agent.FingerprintHost(key.Marshal()),
		}
		reply, err := session.Control(msg)
		if err != nil {
			return err
		}
		if !reply.Allow {
			return fmt.Errorf("host key rejected by laptop: %s", reply.Reason)
		}
		return nil
	}
}

// DialSSH performs the full SSH handshake over the approved tunnel.
func DialSSH(session *Session, agentSignPubB64 string) (*ssh.Client, error) {
	signer, err := newRemoteSigner(session, agentSignPubB64, session.cfg.User)
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ClientConfig{
		User:            session.cfg.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKeyCallback(session),
	}
	conn, chans, reqs, err := ssh.NewClientConn(session, "bastionguard-tunnel", cfg)
	if err != nil {
		return nil, err
	}
	return ssh.NewClient(conn, chans, reqs), nil
}
