package agent

import (
	"fmt"
	"os/exec"
	"runtime"
	"sync"
)

// Notifier delivers out-of-band awareness to the operator. Approval itself is
// handled through bgctl over the local control socket; notifications exist so
// the operator notices that something needs attention.
type Notifier interface {
	Notify(title, body string, urgent bool)
}

type noopNotifier struct{}

func (noopNotifier) Notify(string, string, bool) {}

// macNotifier uses osascript on macOS and falls back to stderr elsewhere.
type macNotifier struct {
	mu sync.Mutex
}

func NewNotifier() Notifier {
	if runtime.GOOS == "darwin" {
		return &macNotifier{}
	}
	return noopNotifier{}
}

func (m *macNotifier) Notify(title, body string, urgent bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if urgent {
		title = "⚠️ " + title
	}
	script := fmt.Sprintf(`display notification %q with title %q sound name %q`,
		body, title, map[bool]string{true: "Basso", false: "Glass"}[urgent])
	cmd := exec.Command("osascript", "-e", script)
	_ = cmd.Run() // best effort; headless demo environments may reject it
}
