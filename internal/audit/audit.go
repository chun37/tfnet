// Package audit writes an append-only forensic log of ledger operations.
//
// The audit log lives at <ledger_dir>/audit.jsonl. One JSON object per line,
// timestamped, identifying the actor (best-effort: OS user + host), the
// operation and its target hash. It is independent from the operational slog
// stream and is meant to remain in the ledger directory permanently — co-
// distributed with the ledger so reviewers can reconstruct who proposed,
// signed, merged, and committed each entry.
//
// Audit failures never abort the caller: a degraded log is preferable to a
// failed legitimate operation. Failures are surfaced via slog at WARN level.
package audit

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
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

// Log writes ev to <ledgerDir>/audit.jsonl. ledgerDir may be empty if the
// operation is not associated with a specific ledger (audit is then a no-op
// at the file level, but the event is still surfaced via slog so it isn't
// silently lost).
func Log(ledgerDir string, ev Event) {
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
	ev.LedgerDir = ledgerDir

	// Mirror to slog so operators see it on stderr too.
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

	if ledgerDir == "" {
		return
	}
	path := filepath.Join(ledgerDir, "audit.jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		slog.Warn("audit log open failed", "path", path, "error", err)
		return
	}
	defer f.Close()
	b, err := json.Marshal(ev)
	if err != nil {
		slog.Warn("audit log marshal failed", "error", err)
		return
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		slog.Warn("audit log write failed", "path", path, "error", err)
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

// MustNotErr returns a string for the error (or empty if nil) — used by
// callers to populate Event.Error in deferred patterns.
func MustNotErr(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("%v", err)
}
