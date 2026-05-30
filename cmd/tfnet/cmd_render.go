package main

import (
	"flag"
	"fmt"
	"os"

	"tfnet/internal/audit"
	"tfnet/internal/keys"
	"tfnet/internal/render"
	"tfnet/internal/tflog"
)

func runRender(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "tfnet render: missing subcommand (wg | frr)")
		os.Exit(2)
	}
	switch args[0] {
	case "wg":
		runRenderWG(args[1:])
	case "frr":
		runRenderFRR(args[1:])
	default:
		die("render: unknown subcommand %q", args[0])
	}
}

func runRenderWG(args []string) {
	fs := flag.NewFlagSet("render wg", flag.ExitOnError)
	dir := fs.String("ledger", "", "ledger directory")
	self := fs.String("self", "", "self node_id (required)")
	port := fs.Int("listen-port", 0, "WireGuard ListenPort (0 = omit)")
	mtu := fs.Int("mtu", 1440, "wg0 MTU (§6: 1440 for IPv4/1500 underlay; set 0 to omit)")
	keepalive := fs.Int("keepalive", 25, "PersistentKeepalive seconds")
	wgKeyFile := fs.String("wg-key", "", "WireGuard private key file (otherwise emits REPLACE_ME placeholder)")
	out := fs.String("out", "", "output file (default stdout)")
	_ = fs.Parse(args)
	if *self == "" {
		die("render wg: -self is required")
	}
	st := openStore(ledgerDir(*dir))
	state := replay(st)
	if err := render.EnsureUniqueOverlay(state); err != nil {
		die("ledger inconsistency: %v", err)
	}
	opts := render.WGOptions{
		SelfNodeID: *self,
		ListenPort: *port,
		MTU:        *mtu,
		Keepalive:  *keepalive,
	}
	if *wgKeyFile != "" {
		k, err := keys.LoadWGKey(*wgKeyFile)
		if err != nil {
			die("load wg key: %v", err)
		}
		// Sanity: ensure the public key matches what the ledger has for self.
		if m, ok := state.Members[*self]; ok && m.WGPubkey != k.PublicKey {
			die("wg-key public part (%s) does not match ledger entry for %s (%s)",
				k.PublicKey, opts.SelfNodeID, m.WGPubkey)
		}
		opts.PrivateKey = k.PrivateKey
	}
	conf, err := render.WireGuardConf(state, opts)
	if err != nil {
		die("render: %v", err)
	}
	tflog.Info("rendered wg config",
		"self", *self,
		"peers", len(state.Members)-1,
		"ledger_seq", state.NextSeq,
		"out", outputDest(*out),
	)
	audit.Log(audit.Event{LedgerDir: st.Dir,
		Action: "render.wg",
		Actor:  *self,
		Details: map[string]any{
			"out":        outputDest(*out),
			"ledger_seq": state.NextSeq,
			"peers":      len(state.Members) - 1,
		},
	})
	writeOut(*out, conf)
}

func runRenderFRR(args []string) {
	fs := flag.NewFlagSet("render frr", flag.ExitOnError)
	dir := fs.String("ledger", "", "ledger directory")
	self := fs.String("self", "", "self node_id (required)")
	asn := fs.Uint("asn", 65010, "iBGP private ASN (all peers identical)")
	bfdTx := fs.Int("bfd-tx-ms", 300, "BFD transmit-interval (ms); 1000 ok for large meshes")
	bfdRx := fs.Int("bfd-rx-ms", 300, "BFD receive-interval (ms)")
	bfdMult := fs.Int("bfd-multiplier", 3, "BFD detect-multiplier")
	out := fs.String("out", "", "output file (default stdout)")
	_ = fs.Parse(args)
	if *self == "" {
		die("render frr: -self is required")
	}
	st := openStore(ledgerDir(*dir))
	state := replay(st)
	conf, err := render.FRRConf(state, render.FRROptions{
		SelfNodeID:    *self,
		ASN:           uint32(*asn),
		BFDTxMs:       *bfdTx,
		BFDRxMs:       *bfdRx,
		BFDMultiplier: *bfdMult,
	})
	if err != nil {
		die("render: %v", err)
	}
	tflog.Info("rendered frr config",
		"self", *self,
		"asn", *asn,
		"peers", len(state.Members)-1,
		"ledger_seq", state.NextSeq,
		"out", outputDest(*out),
	)
	audit.Log(audit.Event{LedgerDir: st.Dir,
		Action: "render.frr",
		Actor:  *self,
		Details: map[string]any{
			"asn":        *asn,
			"out":        outputDest(*out),
			"ledger_seq": state.NextSeq,
			"peers":      len(state.Members) - 1,
		},
	})
	writeOut(*out, conf)
}

func outputDest(out string) string {
	if out == "" {
		return "stdout"
	}
	return out
}

func writeOut(path, content string) {
	if path == "" {
		_, _ = os.Stdout.WriteString(content)
		return
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		die("write %s: %v", path, err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", path)
}
