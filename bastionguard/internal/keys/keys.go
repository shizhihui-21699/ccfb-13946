// Package keys manages all long-lived identity material for bastionguard:
// node mTLS certificates, control-plane signing keys, ECDH sealing keys and
// SSH host/authorized keys. Nothing here ever leaves the machine in plaintext
// except inside an enrollment bundle the operator deliberately copies.
package keys

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// CA holds the demo certificate authority material.
type CA struct {
	Cert    *x509.Certificate
	CertPEM []byte
	Key     *rsa.PrivateKey
}

// NodeKeys is one node's full identity set.
type NodeKeys struct {
	ID       string
	SignPriv ed25519.PrivateKey
	SignPub  ed25519.PublicKey
	EcdhPriv *ecdh.PrivateKey
	TLSPriv  *rsa.PrivateKey
	TLSCert  *x509.Certificate
	TLSPEM   []byte
	TLSKeyEM []byte // PEM-encoded PKCS8
}

// Bundle is what the laptop produces to enroll a relay node or a worker.
type Bundle struct {
	NodeID         string `json:"node_id"`
	Role           string `json:"role"` // relay | worker
	CAPEM          string `json:"ca_pem"`
	NodeCertPEM    string `json:"node_cert_pem"`
	NodeKeyPEM     string `json:"node_key_pem"`
	SignPub        string `json:"sign_pub"`  // ed25519, base64
	SignPriv       string `json:"sign_priv"` // ed25519 seed, base64
	EcdhPub        string `json:"ecdh_pub"`  // P-256, base64
	EcdhPriv       string `json:"ecdh_priv"` // PKCS8 DER, base64
	AgentSignPub   string `json:"agent_sign_pub"`
	AgentEcdhPub   string `json:"agent_ecdh_pub"`
	AgentHomeRelay string `json:"agent_home_relay"`
	HomeRelayAddr  string `json:"home_relay_addr"`
}

// NewCA creates an RSA-2048 demo CA (kept on the laptop; certs are short lived).
func NewCA() (*CA, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "bastionguard-demo-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), Key: key}, nil
}

// NewNodeKeys mints a complete identity for a relay or the worker.
func NewNodeKeys(ca *CA, id, role string) (*NodeKeys, error) {
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ecdhPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	tlsPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   id,
			Organization: []string{"bastionguard-" + role},
		},
		NotBefore:   time.Now().Add(-time.Minute),
		NotAfter:    time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:    []string{"localhost", id},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &tlsPriv.PublicKey, ca.Key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(tlsPriv)
	if err != nil {
		return nil, err
	}
	return &NodeKeys{
		ID:       id,
		SignPriv: signPriv,
		SignPub:  signPub,
		EcdhPriv: ecdhPriv,
		TLSPriv:  tlsPriv,
		TLSCert:  cert,
		TLSPEM:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		TLSKeyEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}, nil
}

// AgentIdentity is the operator-side identity. The signing key is the
// high-value secret: it authorizes every jump and signs every SSH challenge.
type AgentIdentity struct {
	ID       string
	SignPriv ed25519.PrivateKey
	SignPub  ed25519.PublicKey
	EcdhPriv *ecdh.PrivateKey
}

func NewAgentIdentity(id string) (*AgentIdentity, error) {
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ecdhPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &AgentIdentity{ID: id, SignPriv: signPriv, SignPub: signPub, EcdhPriv: ecdhPriv}, nil
}

// StoredAgent is the on-disk agent identity file (0600).
type StoredAgent struct {
	ID        string `json:"id"`
	SignSeed  string `json:"sign_seed"` // 32-byte ed25519 seed, base64
	EcdhKey   string `json:"ecdh_key"`  // PKCS8 DER, base64
	HomeRelay string `json:"home_relay"`
}

func (a *AgentIdentity) Store(dir string) error {
	stored := StoredAgent{
		ID:        a.ID,
		SignSeed:  base64.StdEncoding.EncodeToString(a.SignPriv.Seed()),
		EcdhKey:   base64.StdEncoding.EncodeToString(mustMarshalECDH(a.EcdhPriv)),
		HomeRelay: "",
	}
	return writeJSON(filepath.Join(dir, "agent.json"), stored, 0o600)
}

func LoadAgent(dir string) (*AgentIdentity, error) {
	var s StoredAgent
	if err := readJSON(filepath.Join(dir, "agent.json"), &s); err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(s.SignSeed)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("bad agent sign seed")
	}
	signPriv := ed25519.NewKeyFromSeed(seed)
	ecdhDER, err := base64.StdEncoding.DecodeString(s.EcdhKey)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(ecdhDER)
	if err != nil {
		return nil, err
	}
	ecdhPriv, err := toECDH(key)
	if err != nil {
		return nil, err
	}
	return &AgentIdentity{
		ID:       s.ID,
		SignPriv: signPriv,
		SignPub:  signPriv.Public().(ed25519.PublicKey),
		EcdhPriv: ecdhPriv,
	}, nil
}

func mustMarshalECDH(k *ecdh.PrivateKey) []byte {
	b, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		panic(err)
	}
	return b
}

// NodeBundle builds the enrollment bundle for a relay or the worker.
func (nk *NodeKeys) Bundle(caPEM []byte, agent *AgentIdentity, homeRelay, homeAddr string) (*Bundle, error) {
	ecdhDER, err := x509.MarshalPKCS8PrivateKey(nk.EcdhPriv)
	if err != nil {
		return nil, err
	}
	return &Bundle{
		NodeID:         nk.ID,
		Role:           "", // filled by caller
		CAPEM:          string(caPEM),
		NodeCertPEM:    string(nk.TLSPEM),
		NodeKeyPEM:     string(nk.TLSKeyEM),
		SignPub:        base64.StdEncoding.EncodeToString(nk.SignPub),
		SignPriv:       base64.StdEncoding.EncodeToString(nk.SignPriv.Seed()),
		EcdhPub:        base64.StdEncoding.EncodeToString(nk.EcdhPriv.PublicKey().Bytes()),
		EcdhPriv:       base64.StdEncoding.EncodeToString(ecdhDER),
		AgentSignPub:   base64.StdEncoding.EncodeToString(agent.SignPub),
		AgentEcdhPub:   base64.StdEncoding.EncodeToString(agent.EcdhPriv.PublicKey().Bytes()),
		AgentHomeRelay: homeRelay,
		HomeRelayAddr:  homeAddr,
	}, nil
}

// WriteNodeMaterial writes a bundle's files into a node state directory.
func WriteNodeMaterial(dir string, b *Bundle) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	files := map[string][]byte{
		"ca.pem":      []byte(b.CAPEM),
		"node.crt":    []byte(b.NodeCertPEM),
		"node.key":    []byte(b.NodeKeyPEM),
		"bundle.json": mustJSON(b),
	}
	for name, data := range files {
		mode := os.FileMode(0o644)
		if name == "node.key" || name == "bundle.json" {
			mode = 0o600
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, mode); err != nil {
			return err
		}
	}
	return nil
}

func LoadBundle(dir string) (*Bundle, error) {
	var b Bundle
	if err := readJSON(filepath.Join(dir, "bundle.json"), &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// ECDSA curve helper retained for potential future cert profiles.
var _ = elliptic.P256

// toECDH normalizes the various private-key types ParsePKCS8PrivateKey may
// return (Go 1.27 hands back *ecdsa.PrivateKey for NIST curves) into the
// *ecdh.PrivateKey the sealing layer needs.
func toECDH(key any) (*ecdh.PrivateKey, error) {
	switch k := key.(type) {
	case *ecdh.PrivateKey:
		return k, nil
	case *ecdsa.PrivateKey:
		return k.ECDH()
	default:
		return nil, fmt.Errorf("stored key type %T is not an ECDH-capable key", key)
	}
}

func writeJSON(path string, v any, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, mode)
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func mustJSON(v any) []byte {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	return b
}
