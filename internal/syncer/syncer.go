// Package syncer pulls the ledger from a git remote, verifies it, computes
// what changed, and invokes user-defined hook scripts. Designed to be driven
// from a systemd timer; each invocation is a single shot.
//
// Why this exists: the ledger is the single source of truth, and an obvious
// way to distribute it among the members of a private overlay is a private
// git repo. Each host runs `tfnet sync` periodically; when HEAD advances,
// the host:
//
//  1. Verifies the new ledger (chain integrity + signatures via
//     `tfnet ledger verify` semantics).
//  2. Diffs the member set against the previous state.
//  3. Runs every executable file in <hooks-dir> in lexical order with a
//     tinc-up-style env: TFNET_EVENT, TFNET_OLD_HEAD, TFNET_NEW_HEAD,
//     TFNET_ADDED, TFNET_REMOVED, etc. Users put a single script there to
//     `tfnet start` (the runtime is idempotent), another to notify Slack,
//     another to log, etc.
//
// The git transport is not trusted -- signature verification is what makes
// the ledger authoritative. The sync flow therefore refuses non-fast-forward
// pulls by default (defeats force-push attempts) and hard-fails on verify
// errors.
package syncer

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"tfnet/internal/ledger"
	"tfnet/internal/tflog"
)

// Event names passed to hooks via TFNET_EVENT.
const (
	EventPreSync    = "pre-sync"
	EventNoChange   = "no-change"
	EventPostUpdate = "post-update"
	EventError      = "error"
)

// Config controls a single Run invocation.
type Config struct {
	Repo         string // absolute path to the git working tree
	Branch       string // remote tracking branch; default "main"
	Remote       string // git remote name; default "origin"
	LedgerSubdir string // ledger path relative to Repo; default "ledger"
	HooksDir     string // dir of executable hook scripts; "" disables
	SelfNodeID   string // surfaced to hooks as TFNET_SELF
	AllowNonFF   bool   // if true, accept non-FF pulls (DANGEROUS)
	SkipVerify   bool   // if true, skip ledger verify (NOT RECOMMENDED)
}

func (c *Config) applyDefaults() {
	if c.Branch == "" {
		c.Branch = "main"
	}
	if c.Remote == "" {
		c.Remote = "origin"
	}
	if c.LedgerSubdir == "" {
		c.LedgerSubdir = "ledger"
	}
}

// Result is what Run returns. Updated==false means no change since last pull.
type Result struct {
	Updated      bool
	OldHead      string
	NewHead      string
	AddedMembers []string
	RemovedMembers []string
	GitLog       string // oneline log between OldHead..NewHead, may be empty
	HooksRan     []string
}

// Run executes one sync cycle and runs hooks accordingly.
func Run(cfg Config) (*Result, error) {
	cfg.applyDefaults()
	if cfg.Repo == "" {
		return nil, errors.New("syncer: Repo is required")
	}
	res := &Result{}

	// Pre-sync hook (informational; not allowed to fail the sync).
	runHooks(cfg, EventPreSync, baseEnv(cfg, res))

	// Snapshot pre-pull state for the diff.
	oldHead, err := gitOutput(cfg.Repo, "rev-parse", "HEAD")
	if err != nil {
		return res, hookError(cfg, fmt.Errorf("rev-parse HEAD: %w", err))
	}
	res.OldHead = strings.TrimSpace(oldHead)

	// State diff input: pre-pull member set.
	oldState, _, _ := loadLedger(cfg)

	// fetch + ff-only merge.
	if err := git(cfg.Repo, "fetch", "--prune", cfg.Remote, cfg.Branch); err != nil {
		return res, hookError(cfg, fmt.Errorf("git fetch: %w", err))
	}
	mergeArgs := []string{"merge", "--ff-only", fmt.Sprintf("%s/%s", cfg.Remote, cfg.Branch)}
	if cfg.AllowNonFF {
		mergeArgs = []string{"merge", "--no-edit", fmt.Sprintf("%s/%s", cfg.Remote, cfg.Branch)}
	}
	if err := git(cfg.Repo, mergeArgs...); err != nil {
		return res, hookError(cfg, fmt.Errorf("git merge: %w (this usually means upstream was rewound/force-pushed; investigate before allowing -allow-non-ff)", err))
	}

	newHead, err := gitOutput(cfg.Repo, "rev-parse", "HEAD")
	if err != nil {
		return res, hookError(cfg, fmt.Errorf("rev-parse HEAD: %w", err))
	}
	res.NewHead = strings.TrimSpace(newHead)

	if res.NewHead == res.OldHead {
		tflog.Info("sync: no change", "head", res.NewHead)
		res.HooksRan = runHooks(cfg, EventNoChange, baseEnv(cfg, res))
		return res, nil
	}
	res.Updated = true
	tflog.Info("sync: HEAD advanced",
		"old", short(res.OldHead), "new", short(res.NewHead))

	// Verify the new ledger.
	if !cfg.SkipVerify {
		if _, _, err := loadLedger(cfg); err != nil {
			return res, hookError(cfg, fmt.Errorf("ledger verify failed after pull: %w", err))
		}
	}

	// Member diff.
	newState, _, _ := loadLedger(cfg)
	res.AddedMembers, res.RemovedMembers = diffMembers(oldState, newState)

	// Oneline git log between heads.
	if out, err := gitOutput(cfg.Repo, "log", "--oneline",
		fmt.Sprintf("%s..%s", res.OldHead, res.NewHead)); err == nil {
		res.GitLog = strings.TrimRight(out, "\n")
	}

	tflog.Info("sync: member diff",
		"added", res.AddedMembers, "removed", res.RemovedMembers)
	res.HooksRan = runHooks(cfg, EventPostUpdate, baseEnv(cfg, res))
	return res, nil
}

// hookError fires error hooks and wraps the underlying error.
func hookError(cfg Config, err error) error {
	res := &Result{}
	env := baseEnv(cfg, res)
	env = append(env, "TFNET_ERROR="+err.Error())
	runHooks(cfg, EventError, env)
	return err
}

func loadLedger(cfg Config) (*ledger.State, []ledger.Entry, error) {
	st := &ledger.Store{Dir: filepath.Join(cfg.Repo, cfg.LedgerSubdir)}
	return st.Replay()
}

// diffMembers returns (added, removed) node IDs between two states.
// Either state may be nil (treated as empty).
func diffMembers(before, after *ledger.State) (added, removed []string) {
	bm := map[string]bool{}
	if before != nil {
		for id := range before.Members {
			bm[id] = true
		}
	}
	am := map[string]bool{}
	if after != nil {
		for id := range after.Members {
			am[id] = true
		}
	}
	for id := range am {
		if !bm[id] {
			added = append(added, id)
		}
	}
	for id := range bm {
		if !am[id] {
			removed = append(removed, id)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// baseEnv produces the env slice given to hooks. Always includes the parent
// env so hook scripts have access to PATH, HOME, etc.
func baseEnv(cfg Config, res *Result) []string {
	env := os.Environ()
	add := func(k, v string) { env = append(env, k+"="+v) }
	add("TFNET_REPO", cfg.Repo)
	add("TFNET_LEDGER_DIR", filepath.Join(cfg.Repo, cfg.LedgerSubdir))
	add("TFNET_BRANCH", cfg.Branch)
	add("TFNET_REMOTE", cfg.Remote)
	add("TFNET_SELF", cfg.SelfNodeID)
	add("TFNET_OLD_HEAD", res.OldHead)
	add("TFNET_NEW_HEAD", res.NewHead)
	add("TFNET_ADDED", strings.Join(res.AddedMembers, ","))
	add("TFNET_REMOVED", strings.Join(res.RemovedMembers, ","))
	add("TFNET_GIT_LOG", res.GitLog)
	return env
}

// runHooks invokes every executable file in cfg.HooksDir in lexical order.
// Returns the names of the hooks that were actually run.
//
// TFNET_EVENT is appended last so it overrides any user-supplied value in the
// parent env. Individual hook failures are logged but do not stop the loop --
// a bad notification hook shouldn't block a working restart hook.
func runHooks(cfg Config, event string, env []string) []string {
	if cfg.HooksDir == "" {
		return nil
	}
	entries, err := os.ReadDir(cfg.HooksDir)
	if err != nil {
		if !os.IsNotExist(err) {
			tflog.Warn("read hooks dir", "dir", cfg.HooksDir, "error", err)
		}
		return nil
	}
	env = append(env, "TFNET_EVENT="+event)
	var ran []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(cfg.HooksDir, e.Name())
		info, err := os.Stat(path)
		if err != nil || info.Mode()&0o111 == 0 {
			continue // not executable -- skipped silently (typical for *.example)
		}
		tflog.Info("hook", "event", event, "script", path)
		cmd := exec.Command(path)
		cmd.Env = env
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		cmd.Stdout = os.Stderr // hook output flows to slog destination too
		if err := cmd.Run(); err != nil {
			tflog.Warn("hook failed", "script", path, "error", err,
				"stderr", strings.TrimSpace(stderr.String()))
		}
		ran = append(ran, e.Name())
	}
	return ran
}

// --- thin git wrappers --------------------------------------------------

func git(repo string, args ...string) error {
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git %s: %w: %s",
			strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func gitOutput(repo string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w: %s",
			strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
