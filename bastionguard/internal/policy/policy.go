// Package policy implements the laptop-side authorization policy. It decides
// whether a borrow request is silently allowed (narrow, explicit auto rules),
// presented to the operator once (per-session grants), or escalated (burst /
// quiet-hours heuristics).
package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Mode is what the policy says to do with a request.
type Mode string

const (
	ModeAuto     Mode = "auto"     // silently allow, but still log
	ModePrompt   Mode = "prompt"   // ask the operator once
	ModeEscalate Mode = "escalate" // ask, and mark the log entry urgent
	ModeDeny     Mode = "deny"     // refuse without prompting
)

// Rule is one explicit policy statement. All set fields must match.
type Rule struct {
	Name        string   `json:"name"`
	Users       []string `json:"users,omitempty"`
	Hosts       []string `json:"hosts,omitempty"` // exact or "*"
	Zones       []string `json:"zones,omitempty"`
	Commands    []string `json:"commands,omitempty"` // prefix match; "*" = any
	Interactive *bool    `json:"interactive,omitempty"`
	Mode        Mode     `json:"mode"`
	TTLSeconds  int      `json:"ttl_seconds,omitempty"` // grant lifetime for auto rules
}

// Policy is the full policy file.
type Policy struct {
	QuietHours     [2]string `json:"quiet_hours"`     // "22:00","08:00" local time
	BurstThreshold int       `json:"burst_threshold"` // distinct new targets in window → escalate
	BurstWindow    string    `json:"burst_window"`    // e.g. "30s"
	DefaultTTL     int       `json:"default_ttl"`     // prompt grants
	MaxGrantTTL    int       `json:"max_grant_ttl"`
	Rules          []Rule    `json:"rules"`
}

// Request is the policy input for a session_open / batch_open.
type Request struct {
	User        string
	Host        string
	Zone        string
	Command     string
	Interactive bool
	OriginNode  string // which relay node forwarded the request
	Depth       int    // hop depth of the chain
}

func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	if p.DefaultTTL == 0 {
		p.DefaultTTL = 3600
	}
	if p.MaxGrantTTL == 0 {
		p.MaxGrantTTL = 12 * 3600
	}
	if p.BurstThreshold == 0 {
		p.BurstThreshold = 5
	}
	if p.BurstWindow == "" {
		p.BurstWindow = "30s"
	}
	return &p, nil
}

// Decide evaluates rules in order; the first match wins. Defaults to prompt.
func (p *Policy) Decide(req Request) (Mode, *Rule, int) {
	for i := range p.Rules {
		r := &p.Rules[i]
		if !matchList(r.Users, req.User) ||
			!matchList(r.Hosts, req.Host) ||
			!matchList(r.Zones, req.Zone) ||
			!matchCommand(r.Commands, req.Command) ||
			!matchInteractive(r.Interactive, req.Interactive) {
			continue
		}
		ttl := r.TTLSeconds
		if ttl == 0 {
			ttl = p.DefaultTTL
		}
		return r.Mode, r, ttl
	}
	return ModePrompt, nil, p.DefaultTTL
}

// InQuietHours reports whether now falls inside the configured quiet window.
func (p *Policy) InQuietHours(now time.Time) bool {
	start, err1 := time.Parse("15:04", p.QuietHours[0])
	end, err2 := time.Parse("15:04", p.QuietHours[1])
	if err1 != nil || err2 != nil {
		return false
	}
	cur := now.Hour()*60 + now.Minute()
	s := start.Hour()*60 + start.Minute()
	e := end.Hour()*60 + end.Minute()
	if s <= e {
		return cur >= s && cur < e
	}
	return cur >= s || cur < e // overnight window
}

func (p *Policy) BurstWindowDuration() time.Duration {
	d, err := time.ParseDuration(p.BurstWindow)
	if err != nil {
		return 30 * time.Second
	}
	return d
}

func matchList(patterns []string, value string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pat := range patterns {
		if pat == "*" || pat == value {
			return true
		}
	}
	return false
}

func matchCommand(patterns []string, cmd string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pat := range patterns {
		if pat == "*" {
			return true
		}
		if strings.HasPrefix(strings.TrimSpace(cmd), pat) {
			return true
		}
	}
	return false
}

func matchInteractive(want *bool, got bool) bool {
	if want == nil {
		return true
	}
	return *want == got
}

// Summarize renders a rule for human approval prompts.
func (r *Rule) Summarize() string {
	if r == nil {
		return "default policy (no rule matched)"
	}
	return fmt.Sprintf("rule %q mode=%s", r.Name, r.Mode)
}
