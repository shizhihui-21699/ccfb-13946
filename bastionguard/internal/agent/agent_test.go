package agent

import (
	"testing"
	"time"
)

func TestGrantStoreBatchIsolation(t *testing.T) {
	s := newGrantStore()
	sess := "batch-1"
	now := time.Now()
	for _, host := range []string{"db-1", "db-2", "cache-1"} {
		s.put(&Grant{SessionID: sess, Host: host, User: "ops", ExpiresAt: now.Add(time.Minute)})
	}
	// Finishing db-1 must not touch the sibling grants.
	s.removeTarget(sess, "db-1")
	if _, ok := s.get(sess, "db-1"); ok {
		t.Fatal("db-1 grant should have been removed")
	}
	for _, host := range []string{"db-2", "cache-1"} {
		if _, ok := s.get(sess, host); !ok {
			t.Fatalf("sibling grant for %s was wrongly removed", host)
		}
	}
	// Removing the last target drops the whole session bucket.
	s.removeTarget(sess, "db-2")
	s.removeTarget(sess, "cache-1")
	if len(s.snapshot()) != 0 {
		t.Fatalf("expected empty store, got %d grants", len(s.snapshot()))
	}
}

func TestGrantStoreExpiry(t *testing.T) {
	s := newGrantStore()
	s.put(&Grant{SessionID: "x", Host: "h", ExpiresAt: time.Now().Add(-time.Second)})
	if _, ok := s.get("x", "h"); ok {
		t.Fatal("expired grant reported live")
	}
	expired := s.takeExpired(time.Now())
	if len(expired) != 1 || expired[0].SessionID != "x" {
		t.Fatalf("unexpected expired set: %+v", expired)
	}
}

func TestNonceCacheReplay(t *testing.T) {
	c := newNonceCache(time.Minute)
	now := time.Now()
	if c.seenOrAdd("nonce-1", now) {
		t.Fatal("first sighting wrongly treated as replay")
	}
	if !c.seenOrAdd("nonce-1", now.Add(time.Second)) {
		t.Fatal("replay not detected")
	}
	if !c.seenOrAdd("", now) {
		t.Fatal("missing nonce must be rejected")
	}
	// Expired entries age out.
	c2 := newNonceCache(time.Second)
	c2.seenOrAdd("old", now)
	if c2.seenOrAdd("old", now.Add(2*time.Second)) {
		t.Fatal("nonce should have expired out of the cache")
	}
}

func TestBurstTracker(t *testing.T) {
	b := newBurstTracker(30*time.Second, 4)
	now := time.Now()
	tripped := false
	for i, host := range []string{"h1", "h2", "h3", "h4"} {
		if b.record(now.Add(time.Duration(i)*time.Second), host) {
			tripped = true
		}
	}
	if !tripped {
		t.Fatal("burst threshold never tripped")
	}
}
