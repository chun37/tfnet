package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"tfnet/internal/audit"
	"tfnet/internal/hostcfg"
	"tfnet/internal/keys"
	"tfnet/internal/ledger"
	"tfnet/internal/tflog"
)

// ---- ledger pending --------------------------------------------------------
//
// Lists every directory under <ledger>/pending/ with its op, target, and
// who still needs to sign. Read-only.

func runLedgerPending(args []string) {
	fs := flag.NewFlagSet("ledger pending", flag.ExitOnError)
	dir := fs.String("ledger", "", "ledger directory")
	asJSON := fs.Bool("json", false, "output as JSON")
	_ = fs.Parse(args)
	st := openStore(ledgerDir(*dir))
	state := replay(st)
	pendings, err := listPendings(st)
	if err != nil {
		die("list pending: %v", err)
	}
	if *asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(pendingJSON(state, pendings))
		return
	}
	if len(pendings) == 0 {
		fmt.Println("(no pending entries)")
		return
	}
	printPendingTable(state, pendings)
}

type pendingRow struct {
	Name      string   `json:"name"`
	Path      string   `json:"path"`
	Seq       uint64   `json:"seq"`
	Op        string   `json:"op"`
	Target    string   `json:"target,omitempty"`
	Targets   []string `json:"targets,omitempty"`
	EntryHash string   `json:"entry_hash"`
	Required  []string `json:"required"`
	Signed    []string `json:"signed"`
	Missing   []string `json:"missing"`
}

func pendingJSON(state *ledger.State, pendings []*ledger.Pending) []pendingRow {
	out := make([]pendingRow, 0, len(pendings))
	for _, p := range pendings {
		r := pendingRow{
			Name: filepath.Base(p.Dir),
			Path: p.Dir,
			Seq:  p.Entry.Seq,
			Op:   string(p.Entry.Op),
		}
		if p.Entry.Subject != nil {
			r.Target = p.Entry.Subject.NodeID
		}
		for _, s := range p.Entry.Subjects {
			r.Targets = append(r.Targets, s.NodeID)
		}
		sort.Strings(r.Targets)
		r.EntryHash, _ = p.Entry.HashHex()
		if req, err := state.RequiredApprovers(p.Entry); err == nil {
			for id := range req {
				r.Required = append(r.Required, id)
			}
			sort.Strings(r.Required)
		}
		for id := range p.Entry.Approvals {
			r.Signed = append(r.Signed, id)
		}
		sort.Strings(r.Signed)
		miss, _ := state.MissingApprovers(p.Entry)
		r.Missing = miss
		out = append(out, r)
	}
	return out
}

// listPendings returns every directory under <ledger>/pending/, sorted by seq
// then by name. Unreadable directories are skipped with a warning.
func listPendings(st *ledger.Store) ([]*ledger.Pending, error) {
	entries, err := os.ReadDir(st.PendingDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []*ledger.Pending
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		p, err := ledger.LoadPending(filepath.Join(st.PendingDir(), e.Name()))
		if err != nil {
			tflog.Warn("skip unreadable pending", "dir", e.Name(), "error", err)
			continue
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Entry.Seq != out[j].Entry.Seq {
			return out[i].Entry.Seq < out[j].Entry.Seq
		}
		return filepath.Base(out[i].Dir) < filepath.Base(out[j].Dir)
	})
	return out, nil
}

func printPendingTable(state *ledger.State, pendings []*ledger.Pending) {
	fmt.Printf("%-4s %-22s %-7s %-18s %-25s %s\n", "#", "name", "op", "target", "missing", "signed")
	for i, p := range pendings {
		miss, _ := state.MissingApprovers(p.Entry)
		signed := make([]string, 0, len(p.Entry.Approvals))
		for id := range p.Entry.Approvals {
			signed = append(signed, id)
		}
		sort.Strings(signed)
		fmt.Printf("[%-2d] %-22s %-7s %-18s %-25s %s\n",
			i+1, filepath.Base(p.Dir), p.Entry.Op, targetLabel(p.Entry),
			joinOr(miss, ",", "(ready)"),
			joinOr(signed, ",", "(none)"),
		)
	}
}

func joinOr(xs []string, sep, ifEmpty string) string {
	if len(xs) == 0 {
		return ifEmpty
	}
	return strings.Join(xs, sep)
}

func targetLabel(e *ledger.Entry) string {
	if e.Subject != nil {
		return e.Subject.NodeID
	}
	if len(e.Subjects) > 0 {
		names := make([]string, 0, len(e.Subjects))
		for _, s := range e.Subjects {
			names = append(names, s.NodeID)
		}
		sort.Strings(names)
		return strings.Join(names, ",")
	}
	return "-"
}

// ---- ledger approve --------------------------------------------------------
//
// One-shot "approve a pending and push" for the common case where the operator
// is sitting in front of the ledger repo. The flow is:
//
//  1. git fetch + ff-only merge (skippable).
//  2. List remaining pending entries, prompt for a number (skippable via -pending).
//  3. Sign the chosen entry with the host identity.
//  4. If signing fills the last required slot, also ledger-commit (skippable).
//  5. git add ledger/ && git commit && git push. On non-FF reject, auto-retry
//     once with `git pull --rebase`.
//
// All git knobs (repo / branch / remote / key path) can come from a per-host
// config file (see internal/hostcfg) so the common invocation is just
// `tfnet ledger approve`.

func runLedgerApprove(args []string) {
	fs := flag.NewFlagSet("ledger approve", flag.ExitOnError)
	dir := fs.String("ledger", "", "ledger directory (default <repo>/<ledger_subdir>)")
	repoFlag := fs.String("repo", "", "git repo path (default: hostcfg.repo, $TFNET_REPO, cwd)")
	branch := fs.String("branch", "", "git branch (default 'main' or hostcfg.branch)")
	remote := fs.String("remote", "", "git remote (default 'origin' or hostcfg.remote)")
	keyPath := fs.String("key", "", "identity key file (default hostcfg.identity_key, or /etc/tfnet/<self>.id.json)")
	self := fs.String("self", "", "self node_id (used to discover key file; default hostcfg.self)")
	pending := fs.String("pending", "", "pending directory name (skip interactive picker)")
	yes := fs.Bool("yes", false, "skip the confirmation prompt")
	noPull := fs.Bool("no-pull", false, "skip git pull --ff-only at start")
	noPush := fs.Bool("no-push", false, "skip git add/commit/push at the end")
	noFinalize := fs.Bool("no-finalize", false, "do not ledger-commit even when all approvals are present")
	_ = fs.Parse(args)

	cfg, cfgPath, err := hostcfg.Load()
	if err != nil {
		die("hostcfg: %v", err)
	}
	if cfgPath != "" {
		tflog.Debug("hostcfg loaded", "path", cfgPath)
	}

	repo := firstNonEmpty(*repoFlag, cfg.Repo, os.Getenv("TFNET_REPO"))
	if repo == "" {
		if cwd, err := os.Getwd(); err == nil {
			repo = cwd
		}
	}
	if repo == "" {
		die("approve: cannot determine repo (use -repo, hostcfg.repo, or $TFNET_REPO)")
	}
	repo = absOrAs(repo)

	subdir := firstNonEmpty(cfg.LedgerSubdir, "ledger")
	ldir := *dir
	if ldir == "" {
		ldir = filepath.Join(repo, subdir)
	}

	selfID := firstNonEmpty(*self, cfg.Self)
	kp := firstNonEmpty(*keyPath, cfg.IdentityKey)
	if kp == "" && selfID != "" {
		kp = discoverIdentityKey(selfID)
	}
	if kp == "" {
		die("approve: cannot find identity key (use -key, set identity_key in %s, or place /etc/tfnet/<self>.id.json)",
			configLocationHint(cfgPath))
	}

	br := firstNonEmpty(*branch, cfg.Branch, "main")
	rm := firstNonEmpty(*remote, cfg.Remote, "origin")

	id, err := keys.LoadIdentity(kp)
	if err != nil {
		die("load identity %s: %v", kp, err)
	}
	if selfID != "" && selfID != id.NodeID {
		die("approve: -self/hostcfg.self is %q but key file is for %q", selfID, id.NodeID)
	}

	if !*noPull {
		fmt.Fprintf(os.Stderr, "tfnet: git fetch %s %s && git merge --ff-only\n", rm, br)
		if err := runGit(repo, "fetch", "--prune", rm, br); err != nil {
			die("git fetch: %v", err)
		}
		if err := runGit(repo, "merge", "--ff-only", fmt.Sprintf("%s/%s", rm, br)); err != nil {
			die("git merge --ff-only: %v (upstream may have been rewound/force-pushed)", err)
		}
	}

	st := openStore(ldir)
	state := replay(st)

	pendings, err := listPendings(st)
	if err != nil {
		die("list pending: %v", err)
	}
	if len(pendings) == 0 {
		fmt.Println("no pending entries -- nothing to approve.")
		return
	}

	target := pickPending(state, pendings, *pending, st.PendingDir())
	if target == nil {
		fmt.Println("aborted.")
		return
	}

	req, err := state.RequiredApprovers(target.Entry)
	if err != nil {
		die("required approvers: %v", err)
	}
	if _, ok := req[id.NodeID]; !ok {
		die("approve: %s is not a required approver for this entry", id.NodeID)
	}

	if !*yes {
		if !askYesNo(fmt.Sprintf("approve %s (%s %s) as %s",
			filepath.Base(target.Dir), target.Entry.Op, targetLabel(target.Entry), id.NodeID)) {
			fmt.Println("aborted.")
			return
		}
	}

	signed := false
	if _, already := target.Entry.Approvals[id.NodeID]; already {
		fmt.Printf("already signed by %s -- skipping sign step.\n", id.NodeID)
	} else {
		h, err := target.Entry.Hash()
		if err != nil {
			die("hash entry: %v", err)
		}
		sig, err := id.Sign(h[:])
		if err != nil {
			die("sign: %v", err)
		}
		sf := ledger.SigFile{
			NodeID:    id.NodeID,
			EntryHash: hex32(h),
			Signature: base64.StdEncoding.EncodeToString(sig),
		}
		if err := target.SaveSig(sf); err != nil {
			die("save sig: %v", err)
		}
		audit.Log(audit.Event{LedgerDir: ldir,
			Action:    "ledger.sign.inplace",
			Actor:     id.NodeID,
			EntryHash: hex32(h),
			Details: map[string]any{
				"pending_path": target.Dir,
				"sig_path":     target.SigFilePath(id.NodeID),
				"via":          "approve",
			},
		})
		fmt.Printf("signed %s as %s\n", filepath.Base(target.Dir), id.NodeID)
		signed = true

		// Reload so .Approvals reflects our just-written file for the readiness check.
		if reloaded, err := ledger.LoadPending(target.Dir); err == nil {
			target = reloaded
		}
	}

	finalized := false
	if !*noFinalize {
		miss, _ := state.MissingApprovers(target.Entry)
		if len(miss) == 0 {
			if err := state.Apply(target.Entry); err != nil {
				die("validate: %v", err)
			}
			if err := st.Append(target.Entry); err != nil {
				die("append to log: %v", err)
			}
			_ = target.Remove()
			h, _ := target.Entry.HashHex()
			audit.Log(audit.Event{LedgerDir: ldir,
				Action:    "ledger.commit",
				Seq:       audit.Seq(target.Entry.Seq),
				Op:        string(target.Entry.Op),
				Target:    targetLabel(target.Entry),
				EntryHash: h,
				Details: map[string]any{
					"approvers":    sortedKeys(target.Entry.Approvals),
					"pending_path": target.Dir,
					"via":          "approve",
				},
			})
			fmt.Printf("ledger-commit seq=%d op=%s\n", target.Entry.Seq, target.Entry.Op)
			finalized = true
		}
	}

	if !signed && !finalized {
		return
	}
	if *noPush {
		fmt.Println("(skip git push)")
		return
	}

	if err := gitCommitAndPush(repo, ldir, rm, br, buildCommitMessage(id.NodeID, target.Entry, finalized)); err != nil {
		die("%v", err)
	}
}

func gitCommitAndPush(repo, ldir, remote, branch, msg string) error {
	rel := ledgerRelativePath(repo, ldir)
	if err := runGit(repo, "add", "--", rel); err != nil {
		return fmt.Errorf("git add: %w", err)
	}
	staged, err := runGitOutput(repo, "diff", "--cached", "--name-only")
	if err != nil {
		return fmt.Errorf("git diff --cached: %w", err)
	}
	if strings.TrimSpace(staged) == "" {
		fmt.Println("nothing staged -- skipping commit/push.")
		return nil
	}
	if err := runGit(repo, "commit", "-m", msg); err != nil {
		return fmt.Errorf("git commit: %w", err)
	}
	if err := runGit(repo, "push", remote, branch); err == nil {
		fmt.Printf("pushed: %s\n", msg)
		return nil
	} else {
		fmt.Fprintf(os.Stderr, "tfnet: push rejected (%v) -- retrying with `git pull --rebase`\n", err)
		if err := runGit(repo, "pull", "--rebase", remote, branch); err != nil {
			return fmt.Errorf("git pull --rebase after rejected push: %w", err)
		}
		if err := runGit(repo, "push", remote, branch); err != nil {
			return fmt.Errorf("git push (after rebase): %w", err)
		}
		fmt.Printf("pushed after rebase: %s\n", msg)
		return nil
	}
}

func buildCommitMessage(self string, e *ledger.Entry, finalized bool) string {
	t := targetLabel(e)
	if finalized {
		return fmt.Sprintf("ledger: %s %s (signed by %s, finalised)", e.Op, t, self)
	}
	return fmt.Sprintf("ledger: sign %s %s as %s", e.Op, t, self)
}

func ledgerRelativePath(repo, ldir string) string {
	if rel, err := filepath.Rel(repo, ldir); err == nil {
		return rel
	}
	return ldir
}

func sortedKeys(m map[string]string) []string {
	return slices.Sorted(maps.Keys(m))
}

// pickPending returns the chosen pending. When byName is empty it prints the
// table and prompts on stdin; otherwise it matches exactly or by prefix.
// `state` is only consulted by the interactive table; tests pass it as nil.
func pickPending(state *ledger.State, pendings []*ledger.Pending, byName, pendingDir string) *ledger.Pending {
	if byName != "" {
		for _, p := range pendings {
			name := filepath.Base(p.Dir)
			if name == byName || strings.HasPrefix(name, byName) {
				return p
			}
		}
		die("approve: pending %q not found under %s", byName, pendingDir)
	}
	if state == nil {
		state = ledger.NewState()
	}
	printPendingTable(state, pendings)
	fmt.Printf("\npick a pending [1-%d] (q to quit): ", len(pendings))
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil
	}
	line = strings.TrimSpace(line)
	if line == "" || line == "q" || line == "Q" || line == "0" {
		return nil
	}
	if n, err := strconv.Atoi(line); err == nil {
		if n < 1 || n > len(pendings) {
			fmt.Println("out of range.")
			return nil
		}
		return pendings[n-1]
	}
	for _, p := range pendings {
		name := filepath.Base(p.Dir)
		if name == line || strings.HasPrefix(name, line) {
			return p
		}
	}
	fmt.Println("no match.")
	return nil
}

func askYesNo(prompt string) bool {
	fmt.Printf("%s [y/N]: ", prompt)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes"
}

// discoverIdentityKey searches conventional locations for <self>.id.json.
func discoverIdentityKey(self string) string {
	candidates := []string{
		filepath.Join("/etc/tfnet", self+".id.json"),
	}
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		candidates = append(candidates, filepath.Join(x, "tfnet", self+".id.json"))
	}
	if h, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(h, ".config", "tfnet", self+".id.json"))
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func configLocationHint(loaded string) string {
	if loaded != "" {
		return loaded
	}
	return "$XDG_CONFIG_HOME/tfnet/config.json or /etc/tfnet/config.json"
}

func firstNonEmpty(xs ...string) string {
	for _, s := range xs {
		if s != "" {
			return s
		}
	}
	return ""
}

// ---- thin git wrappers ----------------------------------------------------

func runGit(repo string, args ...string) error {
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git %s: %w: %s",
			strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func runGitOutput(repo string, args ...string) (string, error) {
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
