// Package proto defines the control protocol between jump-host workers and the
// laptop agent. The relay (bastion) only carries these messages as opaque,
// end-to-end encrypted frames and can read none of them.
package proto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Message kinds.
const (
	KindSessionOpen   = "session_open"
	KindBatchOpen     = "batch_open"
	KindPending       = "pending"
	KindDecision      = "decision"
	KindHostKeyCheck  = "hostkey_check"
	KindHostKeyReply  = "hostkey_reply"
	KindAuthSign      = "auth_sign"
	KindAuthSignReply = "auth_sign_reply"
	KindHeartbeat     = "heartbeat"
	KindSessionClose  = "session_close"
	KindError         = "error"
)

// Message is the single envelope of the control protocol. Only fields
// relevant to a given kind are populated.
type Message struct {
	Kind       string `json:"kind"`
	RequestID  string `json:"request_id,omitempty"`
	SessionID  string `json:"session_id,omitempty"`
	GrantID    string `json:"grant_id,omitempty"`
	ChainID    string `json:"chain_id,omitempty"`
	Depth      int    `json:"depth,omitempty"`
	OriginNode string `json:"origin_node,omitempty"`
	User       string `json:"user,omitempty"`

	TargetHost  string        `json:"target_host,omitempty"`
	TargetPort  int           `json:"target_port,omitempty"`
	Fingerprint string        `json:"fingerprint,omitempty"`
	Command     string        `json:"command,omitempty"`
	Interactive bool          `json:"interactive,omitempty"`
	ScriptHash  string        `json:"script_hash,omitempty"`
	Batch       []BatchTarget `json:"batch,omitempty"`

	// Signing request (SSH publickey userauth challenge).
	SignData string `json:"sign_data,omitempty"` // base64 raw data-to-sign
	SignAlg  string `json:"sign_alg,omitempty"`

	// Decisions / replies.
	Allow      bool   `json:"allow,omitempty"`
	Reason     string `json:"reason,omitempty"`
	TTLSeconds int    `json:"ttl_seconds,omitempty"`

	Nonce string `json:"nonce,omitempty"`
	TS    int64  `json:"ts,omitempty"`

	// Authentication of the message itself. The signature covers the exact
	// JSON encoding of the message with the Sig field blanked.
	NodePub string `json:"node_pub,omitempty"` // base64 ed25519 public key
	Sig     string `json:"sig,omitempty"`      // base64 ed25519 signature
}

// BatchTarget is one host inside a batch_open request.
type BatchTarget struct {
	Host string `json:"host"`
	Port int    `json:"port,omitempty"`
	User string `json:"user,omitempty"`
}

// signingView returns a value whose JSON encoding is the canonical bytes
// covered by the signature. Struct field order is fixed by the language spec,
// and encoding/json is deterministic for structs, so both sides reproduce the
// same bytes as long as they use this package.
func (m *Message) signingView() Message {
	c := *m
	c.Sig = ""
	return c
}

// Sign attaches an ed25519 signature over the canonical message bytes.
func (m *Message) Sign(priv ed25519.PrivateKey) error {
	m.NodePub = base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	raw, err := json.Marshal(m.signingView())
	if err != nil {
		return err
	}
	m.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, raw))
	return nil
}

// Verify checks the embedded signature against the embedded public key.
func (m *Message) Verify() error {
	if m.NodePub == "" || m.Sig == "" {
		return fmt.Errorf("message %s missing node signature", m.Kind)
	}
	pubBytes, err := base64.StdEncoding.DecodeString(m.NodePub)
	if err != nil {
		return fmt.Errorf("bad node_pub: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(m.Sig)
	if err != nil {
		return fmt.Errorf("bad sig: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("bad node public key length")
	}
	raw, err := json.Marshal(m.signingView())
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), raw, sig) {
		return fmt.Errorf("control message signature invalid (relay tampering or forged request)")
	}
	return nil
}

// Encode is a length-prefixed JSON frame used on every control stream.
func Encode(buf []byte) []byte {
	out := make([]byte, 4+len(buf))
	out[0] = byte(len(buf) >> 24)
	out[1] = byte(len(buf) >> 16)
	out[2] = byte(len(buf) >> 8)
	out[3] = byte(len(buf))
	copy(out[4:], buf)
	return out
}

// DecodeLength returns the frame length held in the 4-byte header.
func DecodeLength(hdr [4]byte) int {
	return int(hdr[0])<<24 | int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
}
