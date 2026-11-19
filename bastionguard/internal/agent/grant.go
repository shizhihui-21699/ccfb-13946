package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// Grant is one approval, always scoped to a concrete target and chain. The
// worker can only obtain SSH signatures while a matching, unexpired grant
// exists on the laptop.
type Grant struct {
	ID          string
	SessionID   string
	ChainID     string
	Depth       int
	OriginNode  string
	User        string
	Host        string
	Port        int
	Fingerprint string // pinned SSH host key fingerprint, SHA256:...
	Interactive bool
	ScriptHash  string // empty unless batch/script mode
	ExpiresAt   time.Time
	Auto        bool
	RuleName    string
}

func (g *Grant) Live(now time.Time) bool {
	return now.Before(g.ExpiresAt)
}

// FingerprintHost returns the canonical SHA256 fingerprint of an SSH host key.
func FingerprintHost(sshWireKey []byte) string {
	sum := sha256.Sum256(sshWireKey)
	return "SHA256:" + hex.EncodeToString(sum[:])
}

type grantStore struct {
	mu sync.RWMutex
	// sessionID -> target host -> grant. A batch session holds one grant per
	// target under one shared session id, so a plain session-only key would
	// let one target's grant clobber another's.
	bySess map[string]map[string]*Grant
}

func newGrantStore() *grantStore {
	return &grantStore{bySess: map[string]map[string]*Grant{}}
}

func (s *grantStore) put(g *Grant) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bySess[g.SessionID] == nil {
		s.bySess[g.SessionID] = map[string]*Grant{}
	}
	s.bySess[g.SessionID][g.Host] = g
}

// get returns the live grant for one (session, target) pair.
func (s *grantStore) get(sessionID, host string) (*Grant, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	hosts, ok := s.bySess[sessionID]
	if !ok {
		return nil, false
	}
	g, ok := hosts[host]
	if !ok || !g.Live(time.Now()) {
		return nil, false
	}
	return g, true
}

// removeSession drops every grant (all targets) of a session.
func (s *grantStore) remove(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.bySess, sessionID)
}

// removeTarget drops only the grant for one (session, target) pair, so a
// finishing batch member never revokes its still-running siblings.
func (s *grantStore) removeTarget(sessionID, host string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hosts := s.bySess[sessionID]
	if hosts == nil {
		return
	}
	delete(hosts, host)
	if len(hosts) == 0 {
		delete(s.bySess, sessionID)
	}
}

func (s *grantStore) snapshot() []Grant {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Grant, 0)
	for _, hosts := range s.bySess {
		for _, g := range hosts {
			out = append(out, *g)
		}
	}
	return out
}

// takeExpired removes and returns every expired grant, grouped de-duplicated
// by session so the caller tears each tunnel down once.
func (s *grantStore) takeExpired(now time.Time) []Grant {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Grant
	for sessID, hosts := range s.bySess {
		for host, g := range hosts {
			if !g.Live(now) {
				out = append(out, *g)
				delete(hosts, host)
			}
		}
		if len(hosts) == 0 {
			delete(s.bySess, sessID)
		}
	}
	return out
}

// burstTracker watches how many distinct *new* targets appear in a rolling
// window. A jump host being quietly abused looks like a sudden burst of
// targets the operator never opens interactively.
type burstTracker struct {
	mu       sync.Mutex
	window   time.Duration
	limit    int
	events   []burstEvent
	seenHost map[string]struct{}
}

type burstEvent struct {
	at   time.Time
	host string
}

func newBurstTracker(window time.Duration, limit int) *burstTracker {
	return &burstTracker{
		window:   window,
		limit:    limit,
		seenHost: map[string]struct{}{},
	}
}

// record returns true when adding this host crosses the burst threshold.
func (b *burstTracker) record(now time.Time, host string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	cutoff := now.Add(-b.window)
	kept := b.events[:0]
	for _, e := range b.events {
		if e.at.After(cutoff) {
			kept = append(kept, e)
		}
	}
	b.events = kept
	_, isNew := b.seenHost[host]
	b.seenHost[host] = struct{}{}
	b.events = append(b.events, burstEvent{at: now, host: host})
	return !isNew && len(b.events) >= b.limit
}
