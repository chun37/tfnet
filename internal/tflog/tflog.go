// Package tflog is the process-wide structured logger for tfnet.
//
// Two log streams exist:
//
//   - "operational" — slog handler attached as the default logger. Writes to
//     stderr (or a file) at the level the user configured. Used freely for
//     informational / diagnostic messages.
//
//   - "audit"       — an append-only JSONL stream written into the ledger
//     directory by package audit. The two are complementary: slog is for
//     humans running the CLI; the audit log is for after-the-fact forensic
//     review of who did what to the ledger.
package tflog

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"sync"
)

// Options configure the operational logger.
type Options struct {
	Level  string // debug | info | warn | error (default info)
	Format string // text | json (default text)
	File   string // path; "" or "-" -> stderr
}

var (
	mu      sync.Mutex
	logFile *os.File
)

// Setup installs slog.Default with the requested options. Safe to call once
// at process startup. Returns the path actually opened (or "stderr").
func Setup(o Options) (string, error) {
	level, err := parseLevel(o.Level)
	if err != nil {
		return "", err
	}
	var w io.Writer = os.Stderr
	dest := "stderr"
	if o.File != "" && o.File != "-" {
		f, err := os.OpenFile(o.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return "", fmt.Errorf("open log file %s: %w", o.File, err)
		}
		mu.Lock()
		logFile = f
		mu.Unlock()
		w = f
		dest = o.File
	}
	handlerOpts := &slog.HandlerOptions{
		Level:     level,
		AddSource: level == slog.LevelDebug,
	}
	var h slog.Handler
	switch strings.ToLower(o.Format) {
	case "", "text":
		h = slog.NewTextHandler(w, handlerOpts)
	case "json":
		h = slog.NewJSONHandler(w, handlerOpts)
	default:
		return "", fmt.Errorf("unknown log format %q (want text|json)", o.Format)
	}
	pid := os.Getpid()
	host, _ := os.Hostname()
	logger := slog.New(h).With(
		slog.Int("pid", pid),
		slog.String("host", host),
		slog.String("goarch", runtime.GOARCH),
	)
	slog.SetDefault(logger)
	return dest, nil
}

// Close flushes/closes any file the logger has open. Safe to defer in main.
func Close() {
	mu.Lock()
	defer mu.Unlock()
	if logFile != nil {
		_ = logFile.Close()
		logFile = nil
	}
}

func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error", "err":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown log level %q", s)
	}
}

// Debug / Info / Warn / Error are thin shortcuts that pin call-site at the
// caller rather than inside this package, so source attribution is useful
// when AddSource is on.
func Debug(msg string, args ...any) { slog.Default().Log(context.Background(), slog.LevelDebug, msg, args...) }
func Info(msg string, args ...any)  { slog.Default().Log(context.Background(), slog.LevelInfo, msg, args...) }
func Warn(msg string, args ...any)  { slog.Default().Log(context.Background(), slog.LevelWarn, msg, args...) }
func Error(msg string, args ...any) { slog.Default().Log(context.Background(), slog.LevelError, msg, args...) }
