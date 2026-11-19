package agent

import (
	"sync"
	"time"
)

// nonceCache rejects replayed control messages. Every worker→agent message
// carries a fresh random nonce; a frame captured on the relay by a root
// attacker can be retransmitted but will be dropped here.
type nonceCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]time.Time
}

func newNonceCache(ttl time.Duration) *nonceCache {
	return &nonceCache{ttl: ttl, entries: map[string]time.Time{}}
}

// seenOrAdd returns true if the nonce was already present (i.e. replay).
func (c *nonceCache) seenOrAdd(nonce string, now time.Time) bool {
	if nonce == "" {
		return true // a missing nonce is treated as invalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := now.Add(-c.ttl)
	for n, at := range c.entries {
		if at.Before(cutoff) {
			delete(c.entries, n)
		}
	}
	if _, ok := c.entries[nonce]; ok {
		return true
	}
	c.entries[nonce] = now
	return false
}
