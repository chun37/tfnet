package runtime_test

import (
	"testing"

	"tfnet/internal/runtime"
)

func TestParseWGDump(t *testing.T) {
	// Sample from `wg show wg0 dump` — first line is the interface itself,
	// rest are peers. Fields are tab-separated.
	in := "privkey\tIFPUB===\t51820\toff\n" +
		"PEER1PUB=\t(none)\t203.0.113.2:51820\t10.99.0.2/32\t1717000000\t12345\t67890\t25\n" +
		"PEER2PUB=\t(none)\t(none)\t10.99.0.3/32\t0\t0\t0\toff\n"

	d := runtime.ParseWGDump(in)
	if d.PublicKey != "IFPUB===" {
		t.Errorf("iface pubkey: got %q", d.PublicKey)
	}
	if d.ListenPort != 51820 {
		t.Errorf("listen port: got %d", d.ListenPort)
	}
	if len(d.Peers) != 2 {
		t.Fatalf("want 2 peers, got %d", len(d.Peers))
	}
	p1 := d.Peers[0]
	if p1.PublicKey != "PEER1PUB=" || p1.Endpoint != "203.0.113.2:51820" ||
		p1.LatestHandshake != 1717000000 || p1.RxBytes != 12345 ||
		p1.TxBytes != 67890 || p1.Keepalive != "25" {
		t.Errorf("peer1 parsed wrong: %+v", p1)
	}
	p2 := d.Peers[1]
	if p2.Endpoint != "" || p2.LatestHandshake != 0 || p2.Keepalive != "" {
		t.Errorf("peer2 normalisation failed: %+v", p2)
	}
}

func TestParseWGDumpEmptyAndShort(t *testing.T) {
	if d := runtime.ParseWGDump(""); d.PublicKey != "" || len(d.Peers) != 0 {
		t.Errorf("empty input should yield zero value, got %+v", d)
	}
	// short peer line (only 3 fields) should be skipped, not panic
	in := "priv\tpub\t1\toff\n" + "shortpeer\t\t\n"
	d := runtime.ParseWGDump(in)
	if len(d.Peers) != 0 {
		t.Errorf("malformed peer line should be skipped, got %+v", d.Peers)
	}
}
