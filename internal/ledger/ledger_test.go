package ledger_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"tfnet/internal/ledger"
)

// testNode bundles an Ed25519 identity keypair with a node_id + subject.
type testNode struct {
	NodeID  string
	IDPub   ed25519.PublicKey
	IDPriv  ed25519.PrivateKey
	WGPub   string
	Overlay string
}

func newTestNode(t *testing.T, id, overlay string) *testNode {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen ed25519: %v", err)
	}
	// 32 random bytes for wg "pubkey"; we don't care about its cryptographic
	// validity in ledger tests, only its byte length and stability.
	var wg [32]byte
	if _, err := rand.Read(wg[:]); err != nil {
		t.Fatalf("rand wg: %v", err)
	}
	return &testNode{
		NodeID:  id,
		IDPub:   pub,
		IDPriv:  priv,
		WGPub:   base64.StdEncoding.EncodeToString(wg[:]),
		Overlay: overlay,
	}
}

func (n *testNode) Subject() ledger.Subject {
	return ledger.Subject{
		NodeID:         n.NodeID,
		IdentityPubkey: base64.StdEncoding.EncodeToString(n.IDPub),
		WGPubkey:       n.WGPub,
		OverlayIP:      n.Overlay,
	}
}

func (n *testNode) Sign(t *testing.T, e *ledger.Entry) {
	t.Helper()
	h, err := e.Hash()
	if err != nil {
		t.Fatalf("hash entry: %v", err)
	}
	sig := ed25519.Sign(n.IDPriv, h[:])
	if e.Approvals == nil {
		e.Approvals = map[string]string{}
	}
	e.Approvals[n.NodeID] = base64.StdEncoding.EncodeToString(sig)
}

func TestMemberByOverlayIP(t *testing.T) {
	a := newTestNode(t, "alice", "10.99.0.1/32")
	b := newTestNode(t, "bob", "10.99.0.2/32")
	s := ledger.NewState()
	s.Members[a.NodeID] = a.Subject()
	s.Members[b.NodeID] = b.Subject()

	if got := s.MemberByOverlayIP("10.99.0.2/32"); got != "bob" {
		t.Errorf("hit: got %q, want bob", got)
	}
	if got := s.MemberByOverlayIP("10.99.0.99/32"); got != "" {
		t.Errorf("miss: got %q, want empty", got)
	}
}

func TestCanonicalHashStability(t *testing.T) {
	n := newTestNode(t, "alice", "10.99.0.1/32")
	e1 := &ledger.Entry{
		Seq: 0, PrevHash: ledger.ZeroHash,
		Op: ledger.OpAdd, Subject: ptr(n.Subject()),
	}
	e2 := &ledger.Entry{
		Seq: 0, PrevHash: ledger.ZeroHash,
		Op: ledger.OpAdd, Subject: ptr(n.Subject()),
	}
	// Endpoint must NOT change the hash (§3.4).
	e2.Subject.Endpoint = "203.0.113.1:51820"
	h1, err := e1.HashHex()
	if err != nil {
		t.Fatal(err)
	}
	h2, err := e2.HashHex()
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("endpoint inclusion changed hash: %s vs %s", h1, h2)
	}
}

func TestGenesisRequiresAllSubjectsToSign(t *testing.T) {
	alice := newTestNode(t, "alice", "10.99.0.1/32")
	bob := newTestNode(t, "bob", "10.99.0.2/32")
	e := &ledger.Entry{
		Seq: 0, PrevHash: ledger.ZeroHash,
		Op:       ledger.OpGenesis,
		Subjects: []ledger.Subject{alice.Subject(), bob.Subject()},
	}
	state := ledger.NewState()
	// Missing both sigs: must fail.
	if err := state.Apply(e); err == nil {
		t.Fatal("expected failure with no sigs")
	}
	// Only alice: still fails.
	alice.Sign(t, e)
	if err := state.Apply(e); err == nil {
		t.Fatal("expected failure with only alice's sig")
	}
	// Add bob: must succeed.
	bob.Sign(t, e)
	if err := state.Apply(e); err != nil {
		t.Fatalf("expected success with both sigs: %v", err)
	}
	if len(state.Members) != 2 {
		t.Fatalf("expected 2 members, got %d", len(state.Members))
	}
	if state.NextSeq != 1 {
		t.Fatalf("expected next seq 1, got %d", state.NextSeq)
	}
}

func TestAddRequiresAllExistingMembersPlusNewToSign(t *testing.T) {
	alice := newTestNode(t, "alice", "10.99.0.1/32")
	bob := newTestNode(t, "bob", "10.99.0.2/32")
	carol := newTestNode(t, "carol", "10.99.0.3/32")

	state := ledger.NewState()
	g := &ledger.Entry{
		Seq: 0, PrevHash: ledger.ZeroHash,
		Op:       ledger.OpGenesis,
		Subjects: []ledger.Subject{alice.Subject(), bob.Subject()},
	}
	alice.Sign(t, g)
	bob.Sign(t, g)
	mustApply(t, state, g)

	// Now ADD carol — needs alice + bob + carol.
	addCarol := &ledger.Entry{
		Seq:      state.NextSeq,
		PrevHash: hexN(state.PrevHash),
		Op:       ledger.OpAdd,
		Subject:  ptr(carol.Subject()),
	}
	alice.Sign(t, addCarol)
	if err := state.Apply(addCarol); err == nil {
		t.Fatal("expected fail w/o bob+carol sigs")
	}
	bob.Sign(t, addCarol)
	if err := state.Apply(addCarol); err == nil {
		t.Fatal("expected fail w/o carol sig (new member must consent)")
	}
	carol.Sign(t, addCarol)
	mustApply(t, state, addCarol)
	if _, ok := state.Members["carol"]; !ok {
		t.Fatal("carol not added")
	}
}

func TestRemoveDoesNotRequireRemovedToSign(t *testing.T) {
	alice := newTestNode(t, "alice", "10.99.0.1/32")
	bob := newTestNode(t, "bob", "10.99.0.2/32")
	carol := newTestNode(t, "carol", "10.99.0.3/32")

	state := ledger.NewState()
	g := &ledger.Entry{
		Seq: 0, PrevHash: ledger.ZeroHash,
		Op:       ledger.OpGenesis,
		Subjects: []ledger.Subject{alice.Subject(), bob.Subject(), carol.Subject()},
	}
	alice.Sign(t, g)
	bob.Sign(t, g)
	carol.Sign(t, g)
	mustApply(t, state, g)

	removeBob := &ledger.Entry{
		Seq:      state.NextSeq,
		PrevHash: hexN(state.PrevHash),
		Op:       ledger.OpRemove,
		Subject:  ptr(bob.Subject()),
	}
	// Only alice signs: missing carol.
	alice.Sign(t, removeBob)
	if err := state.Apply(removeBob); err == nil {
		t.Fatal("expected fail without carol")
	}
	carol.Sign(t, removeBob)
	mustApply(t, state, removeBob)
	if _, ok := state.Members["bob"]; ok {
		t.Fatal("bob not removed")
	}
}

func TestForgedSignatureRejected(t *testing.T) {
	alice := newTestNode(t, "alice", "10.99.0.1/32")
	state := ledger.NewState()
	e := &ledger.Entry{
		Seq: 0, PrevHash: ledger.ZeroHash,
		Op: ledger.OpGenesis, Subjects: []ledger.Subject{alice.Subject()},
	}
	// Put garbage in alice's slot.
	e.Approvals = map[string]string{"alice": base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))}
	if err := state.Apply(e); err == nil {
		t.Fatal("expected invalid signature to be rejected")
	}
}

func TestUnknownSignerRejected(t *testing.T) {
	alice := newTestNode(t, "alice", "10.99.0.1/32")
	mallory := newTestNode(t, "mallory", "10.99.0.99/32")
	state := ledger.NewState()
	e := &ledger.Entry{
		Seq: 0, PrevHash: ledger.ZeroHash,
		Op: ledger.OpGenesis, Subjects: []ledger.Subject{alice.Subject()},
	}
	alice.Sign(t, e)
	mallory.Sign(t, e) // mallory is not in the entry; signature is valid bytes but signer is unknown
	if err := state.Apply(e); err == nil {
		t.Fatal("expected rejection of approval from unknown signer")
	}
}

func TestStoreReplayRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st := &ledger.Store{Dir: filepath.Join(dir, "ledger")}
	if err := st.Init(); err != nil {
		t.Fatal(err)
	}

	alice := newTestNode(t, "alice", "10.99.0.1/32")
	bob := newTestNode(t, "bob", "10.99.0.2/32")

	state := ledger.NewState()
	g := &ledger.Entry{
		Seq: 0, PrevHash: ledger.ZeroHash,
		Op: ledger.OpGenesis, Subjects: []ledger.Subject{alice.Subject(), bob.Subject()},
	}
	alice.Sign(t, g)
	bob.Sign(t, g)
	mustApply(t, state, g)
	if err := st.Append(g); err != nil {
		t.Fatal(err)
	}

	state2, entries, err := st.Replay()
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if len(state2.Members) != 2 {
		t.Fatalf("expected 2 members after replay, got %d", len(state2.Members))
	}
	if state2.NextSeq != state.NextSeq {
		t.Fatalf("seq mismatch: replay=%d original=%d", state2.NextSeq, state.NextSeq)
	}
}

func TestTamperedEntryRejected(t *testing.T) {
	alice := newTestNode(t, "alice", "10.99.0.1/32")
	state := ledger.NewState()
	e := &ledger.Entry{
		Seq: 0, PrevHash: ledger.ZeroHash,
		Op: ledger.OpAdd, Subject: ptr(alice.Subject()),
	}
	alice.Sign(t, e)
	// Tamper: change overlay_ip after signing. Hash changes, sig no longer matches.
	e.Subject.OverlayIP = "10.99.0.99/32"
	err := state.Apply(e)
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("expected signature-related rejection, got: %v", err)
	}
}

func ptr[T any](v T) *T { return &v }

func mustApply(t *testing.T, s *ledger.State, e *ledger.Entry) {
	t.Helper()
	if err := s.Apply(e); err != nil {
		t.Fatalf("apply seq=%d op=%s: %v", e.Seq, e.Op, err)
	}
}

func hexN(h [32]byte) string { return hex.EncodeToString(h[:]) }
