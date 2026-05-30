package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"tfnet/internal/audit"
	"tfnet/internal/syncer"
)

func runSync(args []string) {
	fs := flag.NewFlagSet("sync", flag.ExitOnError)
	repo := fs.String("repo", "", "git repo path (default $TFNET_REPO or current dir)")
	branch := fs.String("branch", "main", "branch to track")
	remote := fs.String("remote", "origin", "remote name")
	subdir := fs.String("ledger-subdir", "ledger", "ledger path relative to repo root")
	hooks := fs.String("hooks-dir", "", "hooks dir (default: see below; '' to disable)")
	self := fs.String("self", "", "self node_id (passed to hooks as TFNET_SELF)")
	allowNonFF := fs.Bool("allow-non-ff", false, "allow non-fast-forward pulls (DANGEROUS)")
	skipVerify := fs.Bool("no-verify", false, "skip ledger verify (NOT RECOMMENDED)")
	asJSON := fs.Bool("json", false, "print result as JSON instead of human text")
	_ = fs.Parse(args)

	cfg := syncer.Config{
		Repo:         resolveRepo(*repo),
		Branch:       *branch,
		Remote:       *remote,
		LedgerSubdir: *subdir,
		HooksDir:     resolveHooksDir(*hooks),
		SelfNodeID:   *self,
		AllowNonFF:   *allowNonFF,
		SkipVerify:   *skipVerify,
	}
	if cfg.Repo == "" {
		die("sync: -repo is required (or set $TFNET_REPO)")
	}

	auditDir := filepath.Join(cfg.Repo, cfg.LedgerSubdir)
	if fi, err := os.Stat(auditDir); err != nil || !fi.IsDir() {
		auditDir = "" // not a ledger -- still audit via slog
	}

	res, err := syncer.Run(cfg)
	if err != nil {
		audit.Log(audit.Event{LedgerDir: auditDir,
			Action: "sync.failed",
			Actor:  cfg.SelfNodeID,
			Error:  err.Error(),
			Details: map[string]any{
				"repo":      cfg.Repo,
				"branch":    cfg.Branch,
				"hooks_dir": cfg.HooksDir,
			},
		})
		die("sync: %v", err)
	}
	audit.Log(audit.Event{LedgerDir: auditDir,
		Action: ifUpdated(res.Updated, "sync.updated", "sync.no-change"),
		Actor:  cfg.SelfNodeID,
		Details: map[string]any{
			"old_head":  res.OldHead,
			"new_head":  res.NewHead,
			"added":     res.AddedMembers,
			"removed":   res.RemovedMembers,
			"hooks":     res.HooksRan,
			"hooks_dir": cfg.HooksDir,
		},
	})
	if *asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(res)
		return
	}
	printSyncHuman(res)
}

func printSyncHuman(r *syncer.Result) {
	if !r.Updated {
		fmt.Printf("sync: no change (HEAD %s)\n", short12(r.NewHead))
		return
	}
	fmt.Printf("sync: %s -> %s\n", short12(r.OldHead), short12(r.NewHead))
	if len(r.AddedMembers) > 0 {
		fmt.Printf("  added:   %v\n", r.AddedMembers)
	}
	if len(r.RemovedMembers) > 0 {
		fmt.Printf("  removed: %v\n", r.RemovedMembers)
	}
	if len(r.HooksRan) > 0 {
		fmt.Printf("  hooks:   %v\n", r.HooksRan)
	}
	if r.GitLog != "" {
		fmt.Println("  commits:")
		for _, line := range splitLines(r.GitLog) {
			fmt.Println("    " + line)
		}
	}
}

// resolveRepo: -repo > $TFNET_REPO > cwd.
func resolveRepo(flagVal string) string {
	if flagVal != "" {
		return absOrAs(flagVal)
	}
	if env := os.Getenv("TFNET_REPO"); env != "" {
		return absOrAs(env)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}
	return cwd
}

// resolveHooksDir: -hooks-dir > $TFNET_HOOKS_DIR > convention.
//
// Convention (in order):
//   - /etc/tfnet/hooks.d if euid==0
//   - $XDG_CONFIG_HOME/tfnet/hooks.d
//   - $HOME/.config/tfnet/hooks.d
//
// Returns "" only if the user explicitly passed "" (disable).
func resolveHooksDir(flagVal string) string {
	if flagVal != "" {
		// special token "off" disables hooks.
		if flagVal == "off" || flagVal == "-" {
			return ""
		}
		return absOrAs(flagVal)
	}
	if env := os.Getenv("TFNET_HOOKS_DIR"); env != "" {
		return absOrAs(env)
	}
	if os.Geteuid() == 0 {
		return "/etc/tfnet/hooks.d"
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "tfnet", "hooks.d")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".config", "tfnet", "hooks.d")
	}
	return ""
}

func absOrAs(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}

func ifUpdated(b bool, t, f string) string {
	if b {
		return t
	}
	return f
}

func short12(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
