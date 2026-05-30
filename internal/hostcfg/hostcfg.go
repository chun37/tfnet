// Package hostcfg loads a small per-host config that lets `tfnet ledger
// approve` (and any future shortcut command) avoid taking the same flags every
// time. The config is purely a defaults bag — every field is also overridable
// via command-line flag, env var, or convention.
//
// Lookup order (first existing file wins):
//
//  1. /etc/tfnet/config.json                 (if euid == 0)
//  2. $XDG_CONFIG_HOME/tfnet/config.json
//  3. $HOME/.config/tfnet/config.json
//  4. /etc/tfnet/config.json                 (non-root fallback for shared installs)
//
// Example:
//
//	{
//	  "self":         "alice",
//	  "identity_key": "/etc/tfnet/alice.id.json",
//	  "repo":         "/var/lib/tfnet/repo",
//	  "ledger_subdir":"ledger",
//	  "branch":       "main",
//	  "remote":       "origin"
//	}
package hostcfg

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config is the on-disk per-host defaults file.
type Config struct {
	Self         string `json:"self,omitempty"`
	IdentityKey  string `json:"identity_key,omitempty"`
	Repo         string `json:"repo,omitempty"`
	LedgerSubdir string `json:"ledger_subdir,omitempty"`
	Branch       string `json:"branch,omitempty"`
	Remote       string `json:"remote,omitempty"`
}

// DefaultPaths returns candidate config paths in priority order.
func DefaultPaths() []string {
	var ps []string
	if os.Geteuid() == 0 {
		ps = append(ps, "/etc/tfnet/config.json")
	}
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		ps = append(ps, filepath.Join(x, "tfnet", "config.json"))
	}
	if h, err := os.UserHomeDir(); err == nil {
		ps = append(ps, filepath.Join(h, ".config", "tfnet", "config.json"))
	}
	if os.Geteuid() != 0 {
		ps = append(ps, "/etc/tfnet/config.json")
	}
	return ps
}

// Load returns the first existing config found in DefaultPaths, plus the path
// it was loaded from. If no file is found, returns (&Config{}, "", nil).
// A malformed file is returned as an error so the caller can surface it
// instead of silently falling back to zero defaults.
func Load() (*Config, string, error) {
	for _, p := range DefaultPaths() {
		b, err := os.ReadFile(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, "", fmt.Errorf("read %s: %w", p, err)
		}
		var c Config
		if err := json.Unmarshal(b, &c); err != nil {
			return nil, p, fmt.Errorf("parse %s: %w", p, err)
		}
		return &c, p, nil
	}
	return &Config{}, "", nil
}
