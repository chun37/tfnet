package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"tfnet/internal/audit"
	"tfnet/internal/runtime"
)

// runtimeFlags holds the parsed-but-untyped slice of flags that share between
// start / stop / status. The actual runtime.Config is built from this after
// parsing so we can do small type conversions (uint -> uint32 for ASN).
type runtimeFlags struct {
	ledgerDir   string
	selfNodeID  string
	wgIface     string
	wgKeyFile   string
	wgConfPath  string
	listenPort  int
	wgMTU       int
	keepalive   int
	vxlanIface  string
	vni         int
	dstPort     int
	overlayMTU  int
	bridgeIface string
	skipFRR     bool
	asn         uint
	frrConfPath string
	bfdTxMs     int
	bfdRxMs     int
	bfdMult     int
	dryRun      bool
}

func bindRuntimeFlags(fs *flag.FlagSet) *runtimeFlags {
	f := &runtimeFlags{}
	fs.StringVar(&f.ledgerDir, "ledger", "", "ledger directory (default $TFNET_LEDGER or ./ledger)")
	fs.StringVar(&f.selfNodeID, "self", "", "self node_id (required for start/status)")
	fs.StringVar(&f.wgIface, "wg-iface", runtime.DefaultWGIface, "WireGuard interface name")
	fs.StringVar(&f.wgKeyFile, "wg-key", "", "WireGuard private key file (required for start)")
	fs.StringVar(&f.wgConfPath, "wg-conf", "", "WireGuard conf path (default /etc/wireguard/<iface>.conf)")
	fs.IntVar(&f.listenPort, "listen-port", 0, "WireGuard ListenPort (0 = ephemeral)")
	fs.IntVar(&f.wgMTU, "wg-mtu", runtime.DefaultWGMTU, "wg interface MTU (§6.2)")
	fs.IntVar(&f.keepalive, "keepalive", runtime.DefaultKeepalive, "PersistentKeepalive seconds")
	fs.StringVar(&f.vxlanIface, "vxlan-iface", runtime.DefaultVxlanIface, "VXLAN interface name")
	fs.IntVar(&f.vni, "vni", runtime.DefaultVNI, "VXLAN VNI")
	fs.IntVar(&f.dstPort, "dstport", runtime.DefaultDstPort, "VXLAN UDP dstport")
	fs.IntVar(&f.overlayMTU, "overlay-mtu", 0, "vxlan/bridge MTU (default wg-mtu - 50)")
	fs.StringVar(&f.bridgeIface, "bridge-iface", runtime.DefaultBridgeIface, "Linux bridge name")
	fs.BoolVar(&f.skipFRR, "skip-frr", false, "do not touch FRR (no reload, no vtysh on stop)")
	fs.UintVar(&f.asn, "asn", runtime.DefaultASN, "iBGP private ASN")
	fs.StringVar(&f.frrConfPath, "frr-conf", runtime.DefaultFRRConfPath, "FRR conf path")
	fs.IntVar(&f.bfdTxMs, "bfd-tx-ms", 300, "BFD transmit-interval (ms)")
	fs.IntVar(&f.bfdRxMs, "bfd-rx-ms", 300, "BFD receive-interval (ms)")
	fs.IntVar(&f.bfdMult, "bfd-multiplier", 3, "BFD detect-multiplier")
	fs.BoolVar(&f.dryRun, "dry-run", false, "log every command without executing")
	return f
}

func (f *runtimeFlags) toConfig() runtime.Config {
	return runtime.Config{
		LedgerDir:   ledgerDir(f.ledgerDir),
		SelfNodeID:  f.selfNodeID,
		WGIface:     f.wgIface,
		WGKeyFile:   f.wgKeyFile,
		WGConfPath:  f.wgConfPath,
		ListenPort:  f.listenPort,
		WGMTU:       f.wgMTU,
		Keepalive:   f.keepalive,
		VxlanIface:  f.vxlanIface,
		VNI:         f.vni,
		DstPort:     f.dstPort,
		OverlayMTU:  f.overlayMTU,
		BridgeIface: f.bridgeIface,
		SkipFRR:     f.skipFRR,
		ASN:         uint32(f.asn),
		FRRConfPath: f.frrConfPath,
		BFDTxMs:     f.bfdTxMs,
		BFDRxMs:     f.bfdRxMs,
		BFDMult:     f.bfdMult,
		DryRun:      f.dryRun,
	}
}

func runStart(args []string) {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	f := bindRuntimeFlags(fs)
	_ = fs.Parse(args)
	if f.selfNodeID == "" {
		die("-self is required for start")
	}
	if f.wgKeyFile == "" {
		die("-wg-key is required for start")
	}
	cfg := f.toConfig()
	if err := runtime.Start(cfg); err != nil {
		audit.Log(cfg.LedgerDir, audit.Event{
			Action: "runtime.start.failed",
			Actor:  cfg.SelfNodeID,
			Error:  err.Error(),
			Details: map[string]any{
				"wg_iface":     cfg.WGIface,
				"vxlan_iface":  cfg.VxlanIface,
				"bridge_iface": cfg.BridgeIface,
				"dry_run":      cfg.DryRun,
			},
		})
		die("start: %v", err)
	}
	audit.Log(cfg.LedgerDir, audit.Event{
		Action: "runtime.start",
		Actor:  cfg.SelfNodeID,
		Details: map[string]any{
			"wg_iface":     cfg.WGIface,
			"vxlan_iface":  cfg.VxlanIface,
			"bridge_iface": cfg.BridgeIface,
			"vni":          cfg.VNI,
			"asn":          cfg.ASN,
			"dry_run":      cfg.DryRun,
		},
	})
	fmt.Printf("tfnet started: self=%s wg=%s vxlan=%s bridge=%s vni=%d\n",
		cfg.SelfNodeID, cfg.WGIface, cfg.VxlanIface, cfg.BridgeIface, cfg.VNI)
}

func runStop(args []string) {
	fs := flag.NewFlagSet("stop", flag.ExitOnError)
	f := bindRuntimeFlags(fs)
	_ = fs.Parse(args)
	cfg := f.toConfig()
	if err := runtime.Stop(cfg); err != nil {
		audit.Log(cfg.LedgerDir, audit.Event{
			Action: "runtime.stop.failed",
			Actor:  cfg.SelfNodeID,
			Error:  err.Error(),
		})
		die("stop: %v", err)
	}
	audit.Log(cfg.LedgerDir, audit.Event{
		Action: "runtime.stop",
		Actor:  cfg.SelfNodeID,
		Details: map[string]any{
			"wg_iface":     cfg.WGIface,
			"vxlan_iface":  cfg.VxlanIface,
			"bridge_iface": cfg.BridgeIface,
			"dry_run":      cfg.DryRun,
		},
	})
	fmt.Printf("tfnet stopped: wg=%s vxlan=%s bridge=%s\n",
		cfg.WGIface, cfg.VxlanIface, cfg.BridgeIface)
}

func runStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	f := bindRuntimeFlags(fs)
	asJSON := fs.Bool("json", false, "output as JSON")
	_ = fs.Parse(args)
	if f.selfNodeID == "" {
		die("-self is required for status")
	}
	cfg := f.toConfig()
	rep, err := runtime.Status(cfg)
	if err != nil {
		die("status: %v", err)
	}
	if *asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(rep)
		return
	}
	printStatusHuman(rep)
}

func printStatusHuman(rep *runtime.StatusReport) {
	upMark := func(b bool) string {
		if b {
			return "UP  "
		}
		return "DOWN"
	}
	fmt.Printf("self: %s\n", rep.Self)
	fmt.Printf("  wg     %s  %s  pubkey=%s  listen=%d\n",
		upMark(rep.WGUp), rep.WGIface, rep.WGDump.PublicKey, rep.WGDump.ListenPort)
	fmt.Printf("  vxlan  %s  %s\n", upMark(rep.VxlanUp), rep.VxlanIface)
	fmt.Printf("  bridge %s  %s\n", upMark(rep.BridgeUp), rep.BridgeIface)

	if len(rep.WGDump.Peers) > 0 {
		fmt.Println("\npeers:")
		type row struct {
			id string
			p  runtime.WGPeerStat
		}
		rows := make([]row, 0, len(rep.WGDump.Peers))
		for _, p := range rep.WGDump.Peers {
			id := rep.PeerByPub[p.PublicKey]
			if id == "" {
				id = "(unknown)"
			}
			rows = append(rows, row{id, p})
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].id < rows[j].id })
		fmt.Printf("  %-16s %-21s %-14s %14s %14s\n",
			"NODE", "ENDPOINT", "HANDSHAKE", "RX", "TX")
		for _, r := range rows {
			hs := "-"
			if r.p.LatestHandshake > 0 {
				hs = time.Since(time.Unix(r.p.LatestHandshake, 0)).Round(time.Second).String() + " ago"
			}
			fmt.Printf("  %-16s %-21s %-14s %14d %14d\n",
				r.id, ifelse(r.p.Endpoint, "-"), hs, r.p.RxBytes, r.p.TxBytes)
		}
	}
	if rep.BGPSummary != "" {
		fmt.Println("\nbgp l2vpn evpn summary:")
		fmt.Println(rep.BGPSummary)
	}
}

func ifelse(s, alt string) string {
	if s == "" {
		return alt
	}
	return s
}
