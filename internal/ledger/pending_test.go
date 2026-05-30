package ledger_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"tfnet/internal/ledger"
)

// Build a self-contained genesis pending dir to drive these tests.
func mkPendingDir(t *testing.T) (string, *ledger.Pending, *testNode, *testNode) {
	t.Helper()
	dir := t.TempDir()
	st := &ledger.Store{Dir: filepath.Join(dir, "ledger")}
	if err := st.Init(); err != nil {
		t.Fatal(err)
	}
	alice := newTestNode(t, "alice", "10.99.0.1/32")
	bob := newTestNode(t, "bob", "10.99.0.2/32")
	e := &ledger.Entry{
		Seq:      0,
		PrevHash: ledger.ZeroHash,
		Op:       ledger.OpGenesis,
		Subjects: []ledger.Subject{alice.Subject(), bob.Subject()},
	}
	path, err := st.SavePending(e)
	if err != nil {
		t.Fatalf("SavePending: %v", err)
	}
	p, err := ledger.LoadPending(path)
	if err != nil {
		t.Fatalf("LoadPending: %v", err)
	}
	return path, p, alice, bob
}

func TestPendingRoundTrip_NoApprovalsInEntryJSON(t *testing.T) {
	dir, _, _, _ := mkPendingDir(t)
	// entry.json must never carry approvals -- those go into sigs/
	b, err := os.ReadFile(filepath.Join(dir, "entry.json"))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	if v, ok := raw["approvals"]; ok && v != nil {
		// omitempty makes it absent or null. A populated map would be a bug.
		if m, isMap := v.(map[string]any); isMap && len(m) > 0 {
			t.Errorf("entry.json should not carry approvals; got %v", v)
		}
	}
}

func TestPending_SaveSigAppendsToSigsDir(t *testing.T) {
	dir, p, alice, _ := mkPendingDir(t)
	h, err := p.Entry.HashHex()
	if err != nil {
		t.Fatal(err)
	}
	// Sign via alice's key, save via SaveSig.
	hb, _ := hex.DecodeString(h)
	sig := ed25519.Sign(alice.IDPriv, hb)
	sf := ledger.SigFile{
		NodeID:    "alice",
		EntryHash: h,
		Signature: base64.StdEncoding.EncodeToString(sig),
	}
	if err := p.SaveSig(sf); err != nil {
		t.Fatalf("SaveSig: %v", err)
	}
	// File must exist at the conventional path.
	if _, err := os.Stat(filepath.Join(dir, "sigs", "alice.json")); err != nil {
		t.Fatalf("sigs/alice.json missing: %v", err)
	}
	// Re-loading should merge that sig into Approvals.
	p2, err := ledger.LoadPending(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p2.Entry.Approvals["alice"]; !ok {
		t.Fatalf("LoadPending did not merge sigs/alice.json into Approvals")
	}
}

func TestPending_MismatchedSigHashIsRejected(t *testing.T) {
	dir, p, _, _ := mkPendingDir(t)
	// Plant a sig file whose entry_hash doesn't match.
	sf := ledger.SigFile{
		NodeID:    "alice",
		EntryHash: "00" + (func() string { h, _ := p.Entry.HashHex(); return h[2:] })(), // tamper one byte
		Signature: base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
	}
	b, _ := json.MarshalIndent(sf, "", "  ")
	_ = os.MkdirAll(filepath.Join(dir, "sigs"), 0o700)
	if err := os.WriteFile(filepath.Join(dir, "sigs", "alice.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.LoadPending(dir); err == nil {
		t.Fatal("expected entry_hash mismatch to be rejected")
	}
}

func TestPending_FullSignThenCommit(t *testing.T) {
	// Walk the whole offband flow: SavePending -> SaveSig (twice) ->
	// LoadPending -> Apply.
	dir := t.TempDir()
	st := &ledger.Store{Dir: filepath.Join(dir, "ledger")}
	if err := st.Init(); err != nil {
		t.Fatal(err)
	}
	alice := newTestNode(t, "alice", "10.99.0.1/32")
	bob := newTestNode(t, "bob", "10.99.0.2/32")
	e := &ledger.Entry{
		Seq: 0, PrevHash: ledger.ZeroHash,
		Op:       ledger.OpGenesis,
		Subjects: []ledger.Subject{alice.Subject(), bob.Subject()},
	}
	pendingDir, err := st.SavePending(e)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := ledger.LoadPending(pendingDir)
	h, _ := p.Entry.Hash()
	for _, n := range []*testNode{alice, bob} {
		sig := ed25519.Sign(n.IDPriv, h[:])
		if err := p.SaveSig(ledger.SigFile{
			NodeID:    n.NodeID,
			EntryHash: hexN(h),
			Signature: base64.StdEncoding.EncodeToString(sig),
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Reload to pick up sigs/, then apply.
	p2, err := ledger.LoadPending(pendingDir)
	if err != nil {
		t.Fatal(err)
	}
	state := ledger.NewState()
	if err := state.Apply(p2.Entry); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(state.Members) != 2 {
		t.Fatalf("want 2 members after apply, got %d", len(state.Members))
	}
}
