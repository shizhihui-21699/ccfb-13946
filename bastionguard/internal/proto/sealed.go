package proto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
)

// Sealed is an ECIES-style envelope: an ephemeral ECDH P-256 key, a random
// nonce, and an AES-256-GCM ciphertext. The relay forwards only this blob, so
// a root attacker on the bastion sees ciphertext even on the inner control
// channel. The receiver's static ECDH public key is pinned at enrollment.
type Sealed struct {
	EphPub string `json:"eph_pub"` // base64 P-255 raw point / P-256 uncompressed
	Nonce  string `json:"nonce"`   // 12 random bytes, base64
	CT     string `json:"ct"`      // gcm(json(Message)), base64
}

// Sealer seals messages for one remote static ECDH public key.
type Sealer struct {
	remote *ecdh.PublicKey
	peer   string // label of the peer (for logs)
}

// Opener opens messages using a local static ECDH private key.
type Opener struct {
	priv *ecdh.PrivateKey
}

func NewSealer(remotePublic []byte, peer string) (*Sealer, error) {
	pub, err := ecdh.P256().NewPublicKey(remotePublic)
	if err != nil {
		return nil, fmt.Errorf("bad peer ecdh key for %s: %w", peer, err)
	}
	return &Sealer{remote: pub, peer: peer}, nil
}

func NewOpener(priv *ecdh.PrivateKey) *Opener {
	return &Opener{priv: priv}
}

func deriveKey(shared []byte, nonce []byte) []byte {
	// Bind the nonce into the KDF so identical plaintexts never repeat keys.
	mac := hmac.New(sha256.New, shared)
	mac.Write([]byte("bastionguard/v1/seal"))
	mac.Write(nonce)
	return mac.Sum(nil)
}

// Seal encrypts a signed Message for the configured peer.
func (s *Sealer) Seal(m *Message) ([]byte, error) {
	plain, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(s.remote)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	gcm, err := newGCM(deriveKey(shared, nonce))
	if err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plain, nil)
	return json.Marshal(Sealed{
		EphPub: base64.StdEncoding.EncodeToString(eph.PublicKey().Bytes()),
		Nonce:  base64.StdEncoding.EncodeToString(nonce),
		CT:     base64.StdEncoding.EncodeToString(ct),
	})
}

// Open decrypts a sealed frame and returns the embedded Message.
func (o *Opener) Open(frame []byte) (*Message, error) {
	var env Sealed
	if err := json.Unmarshal(frame, &env); err != nil {
		return nil, fmt.Errorf("bad sealed envelope: %w", err)
	}
	ephRaw, err := base64.StdEncoding.DecodeString(env.EphPub)
	if err != nil {
		return nil, err
	}
	ephPub, err := ecdh.P256().NewPublicKey(ephRaw)
	if err != nil {
		return nil, err
	}
	shared, err := o.priv.ECDH(ephPub)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil || len(nonce) != 12 {
		return nil, fmt.Errorf("bad nonce")
	}
	ct, err := base64.StdEncoding.DecodeString(env.CT)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(deriveKey(shared, nonce))
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("sealed frame authentication failed")
	}
	var m Message
	if err := json.Unmarshal(plain, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// SignIDPub renders an ed25519 public key as the base64 string used inside
// identity bundles.
func SignIDPub(priv ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
}
