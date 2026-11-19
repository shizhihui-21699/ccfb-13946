package policy

import (
	"testing"
	"time"
)

func samplePolicy() *Policy {
	return &Policy{
		QuietHours:     [2]string{"22:00", "08:00"},
		BurstThreshold: 4,
		BurstWindow:    "30s",
		DefaultTTL:     1800,
		MaxGrantTTL:    43200,
		Rules: []Rule{
			{Name: "ro", Users: []string{"ops"}, Commands: []string{"hostname", "uptime"}, Mode: ModeAuto, TTLSeconds: 300},
			{Name: "block-zone", Zones: []string{"restricted"}, Mode: ModeDeny},
		},
	}
}

func TestDecideAutoMatch(t *testing.T) {
	p := samplePolicy()
	mode, rule, ttl := p.Decide(Request{User: "ops", Host: "db-1", Command: "hostname"})
	if mode != ModeAuto || rule == nil || rule.Name != "ro" || ttl != 300 {
		t.Fatalf("unexpected decision: mode=%s rule=%v ttl=%d", mode, rule, ttl)
	}
}

func TestDecideDenyZone(t *testing.T) {
	p := samplePolicy()
	// A non-readonly command avoids the first (auto) rule so the zone deny rule
	// is reached; rule evaluation is documented first-match-wins.
	mode, _, _ := p.Decide(Request{User: "ops", Host: "loot", Zone: "restricted", Command: "cat /etc/shadow"})
	if mode != ModeDeny {
		t.Fatalf("expected deny, got %s", mode)
	}
}

func TestDecideDefaultPrompt(t *testing.T) {
	p := samplePolicy()
	mode, rule, _ := p.Decide(Request{User: "ops", Host: "db-1", Command: "rm -rf /"})
	if mode != ModePrompt || rule != nil {
		t.Fatalf("unmatched rule should default to prompt, got mode=%s rule=%v", mode, rule)
	}
}

func TestQuietHoursOvernight(t *testing.T) {
	p := samplePolicy()
	at23 := time.Date(2026, 11, 20, 23, 0, 0, 0, time.Local)
	noon := time.Date(2026, 11, 20, 12, 0, 0, 0, time.Local)
	if !p.InQuietHours(at23) {
		t.Fatal("23:00 should be inside quiet hours")
	}
	if p.InQuietHours(noon) {
		t.Fatal("noon should not be inside quiet hours")
	}
}
