package proto

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestSignVerifyTamper(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := &Message{Kind: KindAuthSign, SessionID: "s1", Nonce: "n1", User: "ops", TargetHost: "db-1"}
	if err := m.Sign(priv); err != nil {
		t.Fatal(err)
	}
	if err := m.Verify(); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	// A relay-level attacker flips the target after signing.
	m.TargetHost = "loot-1"
	if err := m.Verify(); err == nil {
		t.Fatal("tampered message was accepted")
	}
}

func TestSealedRoundTrip(t *testing.T) {
	recvPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := NewSealer(recvPriv.PublicKey().Bytes(), "test")
	if err != nil {
		t.Fatal(err)
	}
	opener := NewOpener(recvPriv)
	original := &Message{Kind: KindSessionOpen, SessionID: "s9", Nonce: "nonce-x", TargetHost: "db-9"}
	frame, err := sealer.Seal(original)
	if err != nil {
		t.Fatal(err)
	}
	got, err := opener.Open(frame)
	if err != nil {
		t.Fatal(err)
	}
	if got.SessionID != "s9" || got.TargetHost != "db-9" || got.Nonce != "nonce-x" {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

func TestSealedRejectsWrongKey(t *testing.T) {
	recvPriv, _ := ecdh.P256().GenerateKey(rand.Reader)
	otherPriv, _ := ecdh.P256().GenerateKey(rand.Reader)
	sealer, _ := NewSealer(recvPriv.PublicKey().Bytes(), "test")
	frame, err := sealer.Seal(&Message{Kind: KindAuthSign, Nonce: "n"})
	if err != nil {
		t.Fatal(err)
	}
	// A holder of a different static key must not be able to open the frame.
	if _, err := NewOpener(otherPriv).Open(frame); err == nil {
		t.Fatal("sealed frame opened with the wrong key")
	}
}
