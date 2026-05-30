// Package audit writes an append-only forensic log of tfnet operations.
//
// One JSON object per line, timestamped, identifying the actor (best-effort:
// OS user + host), the operation and its target hash. The audit log is
// **local to each host** -- never committed to a shared git repo -- so it
// remains an accurate record of what THIS host did, free of merge conflicts.
//
// Default location:
//
//	root            /var/log/tfnet/audit.jsonl
//	non-root        $XDG_STATE_HOME/tfnet/audit.jsonl
//	                (typically ~/.local/state/tfnet/audit.jsonl)
//
// Override via the global `-audit-file <path>` flag or `TFNET_AUDIT_FILE`.
// Set to "-" or "off" to disable file writes (slog mirror still happens).
//
// Audit failures never abort the caller: a degraded log is preferable to a
// failed legitimate operation. Failures are surfaced via slog at WARN level.
package audit

import (
	"encoding/json"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"sync"
	"time"
)

// Event is one audit record.
type Event struct {
	Time      string         `json:"time"`
	Action    string         `json:"action"`
	Actor     string         `json:"actor,omitempty"`
	Host      string         `json:"host,omitempty"`
	LedgerDir string         `json:"ledger_dir,omitempty"`
	Seq       *uint64        `json:"seq,omitempty"`
	Op        string         `json:"op,omitempty"`
	EntryHash string         `json:"entry_hash,omitempty"`
	Target    string         `json:"target,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
	Error     string         `json:"error,omitempty"`
}

var (
	mu       sync.Mutex
	filePath string
)

// Init sets the destination file. Empty / "-" / "off" disables file writes.
// Safe to call from main during process startup.
func Init(path string) {
	mu.Lock()
	defer mu.Unlock()
	if path == "-" || path == "off" {
		filePath = ""
		return
	}
	filePath = path
}

// DefaultPath returns the conventional audit log path for this user/euid,
// or "" if neither root-owned /var/log nor a state dir is determinable.
func DefaultPath() string {
	if env := os.Getenv("TFNET_AUDIT_FILE"); env != "" {
		return env
	}
	if os.Geteuid() == 0 {
		return "/var/log/tfnet/audit.jsonl"
	}
	if xdg := os.Getenv("XDG_STATE_HOME"); xdg != "" {
		return filepath.Join(xdg, "tfnet", "audit.jsonl")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".local", "state", "tfnet", "audit.jsonl")
	}
	return ""
}

// Log emits an audit event. ev.Time / ev.Actor / ev.Host are filled in if absent.
func Log(ev Event) {
	if ev.Time == "" {
		ev.Time = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if ev.Actor == "" {
		if u, err := user.Current(); err == nil {
			ev.Actor = u.Username
		}
	}
	if ev.Host == "" {
		if h, err := os.Hostname(); err == nil {
			ev.Host = h
		}
	}

	// Always mirror to slog so the event is visible even when no audit
	// file is configured.
	args := []any{
		slog.String("action", ev.Action),
		slog.String("actor", ev.Actor),
	}
	if ev.Seq != nil {
		args = append(args, slog.Uint64("seq", *ev.Seq))
	}
	if ev.Op != "" {
		args = append(args, slog.String("op", ev.Op))
	}
	if ev.EntryHash != "" {
		args = append(args, slog.String("entry_hash", short(ev.EntryHash)))
	}
	if ev.Target != "" {
		args = append(args, slog.String("target", ev.Target))
	}
	if ev.Error != "" {
		args = append(args, slog.String("error", ev.Error))
		slog.Warn("audit", args...)
	} else {
		slog.Info("audit", args...)
	}

	mu.Lock()
	p := filePath
	mu.Unlock()
	if p == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		slog.Warn("audit log mkdir failed", "path", p, "error", err)
		return
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		slog.Warn("audit log open failed", "path", p, "error", err)
		return
	}
	defer f.Close()
	b, err := json.Marshal(ev)
	if err != nil {
		slog.Warn("audit log marshal failed", "error", err)
		return
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		slog.Warn("audit log write failed", "path", p, "error", err)
	}
}

// Seq is a helper for taking the address of a literal uint64.
func Seq(v uint64) *uint64 { return &v }

func short(h string) string {
	if len(h) > 16 {
		return h[:16]
	}
	return h
}
