package render_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"tfnet/internal/ledger"
	"tfnet/internal/render"
)

func mkSubject(t *testing.T, id, overlay, endpoint string) ledger.Subject {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	var wg [32]byte
	_, _ = rand.Read(wg[:])
	return ledger.Subject{
		NodeID:         id,
		IdentityPubkey: base64.StdEncoding.EncodeToString(pub),
		WGPubkey:       base64.StdEncoding.EncodeToString(wg[:]),
		OverlayIP:      overlay,
		Endpoint:       endpoint,
	}
}

func mkState(t *testing.T, subs ...ledger.Subject) *ledger.State {
	t.Helper()
	s := ledger.NewState()
	for _, sub := range subs {
		s.Members[sub.NodeID] = sub
	}
	return s
}

func TestWireGuardConf_SkipsSelf_IncludesPeers(t *testing.T) {
	state := mkState(t,
		mkSubject(t, "alice", "10.99.0.1/32", "203.0.113.1:51820"),
		mkSubject(t, "bob", "10.99.0.2/32", "203.0.113.2:51820"),
		mkSubject(t, "carol", "10.99.0.3/32", ""),
	)
	conf, err := render.WireGuardConf(state, render.WGOptions{
		SelfNodeID: "alice",
		ListenPort: 51820,
		MTU:        1440,
		Keepalive:  25,
	})
	if err != nil {
		t.Fatal(err)
	}
	// One [Interface] block.
	if n := strings.Count(conf, "[Interface]"); n != 1 {
		t.Fatalf("want 1 [Interface], got %d", n)
	}
	// Two [Peer] blocks (bob + carol), not three.
	if n := strings.Count(conf, "[Peer]"); n != 2 {
		t.Fatalf("want 2 [Peer], got %d -- conf:\n%s", n, conf)
	}
	for _, want := range []string{
		"ListenPort = 51820",
		"MTU = 1440",
		"node_id: bob",
		"node_id: carol",
		"AllowedIPs = 10.99.0.2/32",
		"AllowedIPs = 10.99.0.3/32",
		"Endpoint = 203.0.113.2:51820",
		"PersistentKeepalive = 25",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q in conf:\n%s", want, conf)
		}
	}
	if strings.Contains(conf, "node_id: alice") {
		t.Errorf("self should not appear as peer")
	}
}

func TestWireGuardConf_PlaceholderPrivateKey(t *testing.T) {
	state := mkState(t, mkSubject(t, "alice", "10.99.0.1/32", ""))
	conf, err := render.WireGuardConf(state, render.WGOptions{SelfNodeID: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(conf, "PrivateKey = REPLACE_ME") {
		t.Errorf("expected REPLACE_ME placeholder when no private key supplied")
	}
}

func TestEnsureUniqueOverlayDetectsCollision(t *testing.T) {
	state := mkState(t,
		mkSubject(t, "alice", "10.99.0.1/32", ""),
		mkSubject(t, "bob", "10.99.0.1/32", ""),
	)
	err := render.EnsureUniqueOverlay(state)
	if err == nil || !strings.Contains(err.Error(), "overlay collision") {
		t.Fatalf("expected overlay-collision error, got %v", err)
	}
}

func TestFRRConfMentionsPeersAndBFD(t *testing.T) {
	state := mkState(t,
		mkSubject(t, "alice", "10.99.0.1/32", ""),
		mkSubject(t, "bob", "10.99.0.2/32", ""),
	)
	conf, err := render.FRRConf(state, render.FRROptions{
		SelfNodeID: "alice", ASN: 65010,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"router bgp 65010",
		"bgp router-id 10.99.0.1",
		"neighbor 10.99.0.2 remote-as 65010",
		"neighbor 10.99.0.2 bfd",
		"address-family l2vpn evpn",
		"advertise-all-vni",
		"bfd",
		"peer 10.99.0.2",
		"transmit-interval 300",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q in conf:\n%s", want, conf)
		}
	}
	if strings.Contains(conf, "neighbor 10.99.0.1 remote-as") {
		t.Errorf("self should not appear as own neighbor")
	}
}
