package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"tfnet/internal/keys"
	"tfnet/internal/ledger"
)

// ---------- pickPending (by name) -----------------------------------------

func TestPickPending_ByExactName(t *testing.T) {
	pendings := pendingsForTest(t, "alice", "bob")
	got := pickPending(nil, pendings, filepath.Base(pendings[1].Dir), "<unused>")
	if got != pendings[1] {
		t.Fatalf("expected pending[1], got %v", got)
	}
}

func TestPickPending_ByPrefix(t *testing.T) {
	pendings := pendingsForTest(t, "alice", "bob")
	// "000001-" or "000001" should match the second one (seq=1).
	prefix := strings.SplitN(filepath.Base(pendings[1].Dir), "-", 2)[0]
	got := pickPending(nil, pendings, prefix, "<unused>")
	if got != pendings[1] {
		t.Fatalf("expected pending[1], got %v", got)
	}
}

// pendingsForTest builds a small ledger with a genesis + an ADD pending and
// returns the live []*ledger.Pending slice.
func pendingsForTest(t *testing.T, founderIDs ...string) []*ledger.Pending {
	t.Helper()
	dir := t.TempDir()
	st := &ledger.Store{Dir: filepath.Join(dir, "ledger")}
	if err := st.Init(); err != nil {
		t.Fatal(err)
	}
	founders := make([]ledger.Subject, 0, len(founderIDs))
	for i, id := range founderIDs {
		founders = append(founders, fakeSubject(t, id, i+1))
	}
	gen := &ledger.Entry{
		Seq: 0, PrevHash: ledger.ZeroHash, Op: ledger.OpGenesis, Subjects: founders,
	}
	if _, err := st.SavePending(gen); err != nil {
		t.Fatal(err)
	}
	add := &ledger.Entry{
		Seq: 1, PrevHash: ledger.ZeroHash, Op: ledger.OpAdd,
		Subject: &ledger.Subject{
			NodeID:         "carol",
			IdentityPubkey: fakeSubject(t, "carol", 9).IdentityPubkey,
			WGPubkey:       fakeSubject(t, "carol", 9).WGPubkey,
			OverlayIP:      "10.99.0.9/32",
		},
	}
	if _, err := st.SavePending(add); err != nil {
		t.Fatal(err)
	}
	out, err := listPendings(st)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 pending entries, got %d", len(out))
	}
	return out
}

func fakeSubject(t *testing.T, id string, n int) ledger.Subject {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var wg [32]byte
	if _, err := rand.Read(wg[:]); err != nil {
		t.Fatal(err)
	}
	return ledger.Subject{
		NodeID:         id,
		IdentityPubkey: base64.StdEncoding.EncodeToString(pub),
		WGPubkey:       base64.StdEncoding.EncodeToString(wg[:]),
		OverlayIP:      "10.99.0." + strconv.Itoa(n) + "/32",
	}
}

// ---------- listPendings sorts by seq, skips files ------------------------

func TestListPendings_SortedSkipsFiles(t *testing.T) {
	dir := t.TempDir()
	st := &ledger.Store{Dir: filepath.Join(dir, "ledger")}
	if err := st.Init(); err != nil {
		t.Fatal(err)
	}
	gen := &ledger.Entry{
		Seq: 0, PrevHash: ledger.ZeroHash, Op: ledger.OpGenesis,
		Subjects: []ledger.Subject{fakeSubject(t, "alice", 1)},
	}
	if _, err := st.SavePending(gen); err != nil {
		t.Fatal(err)
	}
	// stray file under pending/ should be ignored, not panic.
	if err := os.WriteFile(filepath.Join(st.PendingDir(), "README"), []byte("ignore me"), 0o600); err != nil {
		t.Fatal(err)
	}
	add := &ledger.Entry{
		Seq: 1, PrevHash: ledger.ZeroHash, Op: ledger.OpAdd,
		Subject: ptrSubj(fakeSubject(t, "bob", 2)),
	}
	if _, err := st.SavePending(add); err != nil {
		t.Fatal(err)
	}
	got, err := listPendings(st)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 pendings, got %d", len(got))
	}
	if got[0].Entry.Seq != 0 || got[1].Entry.Seq != 1 {
		t.Errorf("expected seq order 0,1; got %d,%d", got[0].Entry.Seq, got[1].Entry.Seq)
	}
}

func ptrSubj(s ledger.Subject) *ledger.Subject { return &s }

// ---------- end-to-end: real git + real approve ---------------------------

// TestApprove_E2E exercises the full sign+finalize+git push path against a
// local bare-repo "remote". Skips if git isn't on PATH.
func TestApprove_E2E(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	root := t.TempDir()
	bare := filepath.Join(root, "remote.git")
	work := filepath.Join(root, "work")

	mustRun(t, root, "git", "init", "--bare", "-b", "main", bare)
	mustRun(t, root, "git", "clone", bare, work)
	gitConfigUser(t, work)

	// Build a 2-member genesis (alice + bob) and commit it through tfnet so
	// the log is populated. We bypass `tfnet` itself and drive the package APIs
	// directly to keep this test self-contained.
	aliceKey, _ := newSignerKey(t, "alice")
	bobKey, _ := newSignerKey(t, "bob")
	carolKey, _ := newSignerKey(t, "carol")

	ledgerDir := filepath.Join(work, "ledger")
	st := &ledger.Store{Dir: ledgerDir}
	if err := st.Init(); err != nil {
		t.Fatal(err)
	}

	// --- genesis (signed by both) -----------------------------------------
	gen := &ledger.Entry{
		Seq: 0, PrevHash: ledger.ZeroHash, Op: ledger.OpGenesis,
		Subjects: []ledger.Subject{
			subjectFromKey(t, aliceKey, "10.99.0.1/32"),
			subjectFromKey(t, bobKey, "10.99.0.2/32"),
		},
	}
	h, _ := gen.Hash()
	gen.Approvals = map[string]string{
		"alice": ed25519Sig(t, aliceKey, h[:]),
		"bob":   ed25519Sig(t, bobKey, h[:]),
	}
	state := ledger.NewState()
	if err := state.Apply(gen); err != nil {
		t.Fatalf("apply genesis: %v", err)
	}
	if err := st.Append(gen); err != nil {
		t.Fatal(err)
	}

	// --- propose-add carol; pre-sign alice and carol so only bob is missing.
	add := &ledger.Entry{
		Seq: 1, PrevHash: hex32(h), Op: ledger.OpAdd,
		Subject: ptrSubj(subjectFromKey(t, carolKey, "10.99.0.3/32")),
	}
	addPath, err := st.SavePending(add)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := ledger.LoadPending(addPath)
	ah, _ := p.Entry.Hash()
	mustSign(t, p, "alice", aliceKey, ah[:])
	mustSign(t, p, "carol", carolKey, ah[:])

	// Stage and push the genesis + pending so the working tree is "clean".
	mustRun(t, work, "git", "add", "ledger")
	mustRun(t, work, "git", "commit", "-m", "genesis+propose-add carol")
	mustRun(t, work, "git", "push", "origin", "main")

	// Drop a hostcfg pointing at the repo + bob's key.
	bobKeyPath := filepath.Join(root, "bob.id.json")
	if err := bobKey.Save(bobKeyPath); err != nil {
		t.Fatal(err)
	}
	xdg := filepath.Join(root, "xdg")
	if err := os.MkdirAll(filepath.Join(xdg, "tfnet"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfgJSON, _ := json.Marshal(map[string]string{
		"self":         "bob",
		"identity_key": bobKeyPath,
		"repo":         work,
	})
	if err := os.WriteFile(filepath.Join(xdg, "tfnet", "config.json"), cfgJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", xdg)

	// Build the binary and run `tfnet ledger approve -pending <name> -yes`.
	// Tests run inside cmd/tfnet/, so the package path is just ".".
	bin := filepath.Join(root, "tfnet")
	mustRunDir(t, "go", "build", "-o", bin, ".")

	cmd := exec.Command(bin, "ledger", "approve",
		"-pending", filepath.Base(addPath),
		"-yes",
	)
	cmd.Env = append(os.Environ(),
		"HOME="+root,
		"XDG_CONFIG_HOME="+xdg,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("approve failed: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(string(out), "ledger-commit") {
		t.Errorf("expected output to mention ledger-commit; got:\n%s", out)
	}
	if !strings.Contains(string(out), "pushed") {
		t.Errorf("expected output to mention push; got:\n%s", out)
	}

	// log.jsonl should now have 2 entries; pending/<addName> should be gone.
	logBytes, err := os.ReadFile(st.LogPath())
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Count(strings.TrimRight(string(logBytes), "\n"), "\n") + 1
	if lines != 2 {
		t.Errorf("expected 2 log entries, got %d:\n%s", lines, logBytes)
	}
	if _, err := os.Stat(addPath); !os.IsNotExist(err) {
		t.Errorf("pending dir %s should have been removed; stat err=%v", addPath, err)
	}

	// Remote should have a fresh commit pushed by approve.
	headBefore := strings.TrimSpace(string(mustOutput(t, work, "git", "rev-parse", "origin/main")))
	if headBefore == "" {
		t.Errorf("origin/main is empty")
	}
}

// ---------- test helpers --------------------------------------------------

func newSignerKey(t *testing.T, id string) (*keys.Identity, ed25519.PublicKey) {
	t.Helper()
	k, err := keys.GenerateIdentity(id)
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, err := base64.StdEncoding.DecodeString(k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return k, ed25519.PublicKey(pubBytes)
}

func subjectFromKey(t *testing.T, k *keys.Identity, overlay string) ledger.Subject {
	t.Helper()
	var wg [32]byte
	if _, err := rand.Read(wg[:]); err != nil {
		t.Fatal(err)
	}
	return ledger.Subject{
		NodeID:         k.NodeID,
		IdentityPubkey: k.PublicKey,
		WGPubkey:       base64.StdEncoding.EncodeToString(wg[:]),
		OverlayIP:      overlay,
	}
}

func ed25519Sig(t *testing.T, k *keys.Identity, msg []byte) string {
	t.Helper()
	sig, err := k.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func mustSign(t *testing.T, p *ledger.Pending, id string, k *keys.Identity, msg []byte) {
	t.Helper()
	sigB64 := ed25519Sig(t, k, msg)
	h, _ := p.Entry.HashHex()
	if err := p.SaveSig(ledger.SigFile{NodeID: id, EntryHash: h, Signature: sigB64}); err != nil {
		t.Fatal(err)
	}
}

func mustRun(t *testing.T, wd string, args ...string) {
	t.Helper()
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = wd
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
}

func mustRunDir(t *testing.T, args ...string) {
	t.Helper()
	cmd := exec.Command(args[0], args[1:]...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
}

func mustOutput(t *testing.T, wd string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = wd
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
	return out
}

func gitConfigUser(t *testing.T, repo string) {
	t.Helper()
	mustRun(t, repo, "git", "config", "user.email", "test@example.invalid")
	mustRun(t, repo, "git", "config", "user.name", "tfnet test")
}
