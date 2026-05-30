package runtime

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"

	"tfnet/internal/keys"
	"tfnet/internal/ledger"
	"tfnet/internal/render"
	"tfnet/internal/tflog"
)

// Defaults capture the per-design recommended values.
const (
	DefaultWGIface     = "tfnet0"
	DefaultVxlanIface  = "tfvx0"
	DefaultBridgeIface = "tfbr0"
	DefaultVNI         = 10000
	DefaultDstPort     = 4789
	DefaultWGMTU       = 1440 // IPv4 underlay / 1500 physical (§6.2)
	DefaultKeepalive   = 25
	DefaultASN         = 65010
	DefaultFRRConfPath = "/etc/frr/frr.conf"
	DefaultWGConfDir   = "/etc/wireguard"
)

// Config bundles every parameter Start/Stop/Status need. Zero-valued fields
// fall back to package defaults via applyDefaults.
type Config struct {
	LedgerDir  string
	SelfNodeID string

	// WireGuard
	WGIface    string
	WGKeyFile  string
	WGConfPath string // default /etc/wireguard/<iface>.conf
	ListenPort int    // 0 = let WireGuard pick
	WGMTU      int    // §6: 1440 for IPv4/1500 underlay
	Keepalive  int

	// VXLAN
	VxlanIface string
	VNI        int
	DstPort    int
	OverlayMTU int // 0 -> WGMTU - 50 (§6.1)

	// Bridge
	BridgeIface string

	// FRR
	SkipFRR     bool
	ASN         uint32
	FRRConfPath string
	BFDTxMs     int
	BFDRxMs     int
	BFDMult     int

	DryRun bool
}

func (c *Config) applyDefaults() {
	if c.WGIface == "" {
		c.WGIface = DefaultWGIface
	}
	if c.VxlanIface == "" {
		c.VxlanIface = DefaultVxlanIface
	}
	if c.BridgeIface == "" {
		c.BridgeIface = DefaultBridgeIface
	}
	if c.VNI == 0 {
		c.VNI = DefaultVNI
	}
	if c.DstPort == 0 {
		c.DstPort = DefaultDstPort
	}
	if c.WGMTU == 0 {
		c.WGMTU = DefaultWGMTU
	}
	if c.OverlayMTU == 0 {
		c.OverlayMTU = c.WGMTU - 50
	}
	if c.Keepalive == 0 {
		c.Keepalive = DefaultKeepalive
	}
	if c.ASN == 0 {
		c.ASN = DefaultASN
	}
	if c.FRRConfPath == "" {
		c.FRRConfPath = DefaultFRRConfPath
	}
	if c.WGConfPath == "" {
		c.WGConfPath = filepath.Join(DefaultWGConfDir, c.WGIface+".conf")
	}
}

func loadSelf(cfg *Config) (*ledger.State, ledger.Subject, error) {
	st := &ledger.Store{Dir: cfg.LedgerDir}
	state, _, err := st.Replay()
	if err != nil {
		return nil, ledger.Subject{}, fmt.Errorf("replay ledger %s: %w", cfg.LedgerDir, err)
	}
	self, ok := state.Members[cfg.SelfNodeID]
	if !ok {
		return nil, ledger.Subject{}, fmt.Errorf("self node %q not in current member set (%d members)",
			cfg.SelfNodeID, len(state.Members))
	}
	return state, self, nil
}

func overlayHost(cidr string) (string, error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return "", err
	}
	return p.Addr().String(), nil
}

// Start brings the overlay up: writes the WG conf, executes wg-quick, creates
// the VXLAN device and bridge, attaches them, applies §5.2 bridge knobs,
// renders FRR config and reloads. Idempotent for re-runs.
func Start(cfg Config) error {
	cfg.applyDefaults()
	warnIfNotRoot(cfg.DryRun)

	state, self, err := loadSelf(&cfg)
	if err != nil {
		return err
	}
	if err := render.EnsureUniqueOverlay(state); err != nil {
		return err
	}
	if cfg.WGKeyFile == "" {
		return fmt.Errorf("wg-key file is required for start")
	}
	wgKey, err := keys.LoadWGKey(cfg.WGKeyFile)
	if err != nil {
		return fmt.Errorf("load wg key: %w", err)
	}
	if wgKey.PublicKey != self.WGPubkey {
		return fmt.Errorf("wg-key public part (%s) does not match the ledger entry for %s (%s)",
			wgKey.PublicKey, cfg.SelfNodeID, self.WGPubkey)
	}

	// --- 1. WireGuard conf + interface ----------------------------------
	wgConf, err := render.WireGuardConf(state, render.WGOptions{
		SelfNodeID: cfg.SelfNodeID,
		ListenPort: cfg.ListenPort,
		MTU:        cfg.WGMTU,
		Keepalive:  cfg.Keepalive,
		PrivateKey: wgKey.PrivateKey,
	})
	if err != nil {
		return fmt.Errorf("render wg conf: %w", err)
	}
	if err := writeFile(cfg.DryRun, cfg.WGConfPath, []byte(wgConf), 0o600); err != nil {
		return err
	}

	r := runner{dry: cfg.DryRun}
	if exists, _ := r.ifaceExists(cfg.WGIface); !exists {
		if err := r.run("wg-quick", "up", cfg.WGIface); err != nil {
			return err
		}
	} else {
		tflog.Info("wg iface already up; hot-syncing peers", "iface", cfg.WGIface)
		if err := r.wgSyncConf(cfg.WGIface); err != nil {
			tflog.Warn("wg syncconf failed; consider restarting iface", "error", err)
		}
	}

	// --- 2. VXLAN -------------------------------------------------------
	selfHost, err := overlayHost(self.OverlayIP)
	if err != nil {
		return fmt.Errorf("self overlay_ip: %w", err)
	}
	if exists, _ := r.ifaceExists(cfg.VxlanIface); !exists {
		if err := r.run("ip", "link", "add", cfg.VxlanIface,
			"type", "vxlan",
			"id", itoa(cfg.VNI),
			"dstport", itoa(cfg.DstPort),
			"local", selfHost,
			"nolearning",
		); err != nil {
			return err
		}
	} else {
		tflog.Info("vxlan iface already present", "iface", cfg.VxlanIface)
	}

	// --- 3. Bridge ------------------------------------------------------
	if exists, _ := r.ifaceExists(cfg.BridgeIface); !exists {
		if err := r.run("ip", "link", "add", cfg.BridgeIface, "type", "bridge"); err != nil {
			return err
		}
	} else {
		tflog.Info("bridge iface already present", "iface", cfg.BridgeIface)
	}

	if err := r.run("ip", "link", "set", cfg.VxlanIface, "master", cfg.BridgeIface); err != nil {
		return err
	}
	// §5.2: ARP/ND suppression + disable bridge MAC learning (we let EVPN
	// program the FDB instead of letting the bridge learn from data plane).
	if err := r.run("bridge", "link", "set", "dev", cfg.VxlanIface,
		"neigh_suppress", "on", "learning", "off",
	); err != nil {
		return err
	}
	if err := r.run("ip", "link", "set", cfg.VxlanIface, "mtu", itoa(cfg.OverlayMTU), "up"); err != nil {
		return err
	}
	if err := r.run("ip", "link", "set", cfg.BridgeIface, "mtu", itoa(cfg.OverlayMTU), "up"); err != nil {
		return err
	}

	// --- 4. FRR ---------------------------------------------------------
	if !cfg.SkipFRR {
		frrConf, err := render.FRRConf(state, render.FRROptions{
			SelfNodeID:    cfg.SelfNodeID,
			ASN:           cfg.ASN,
			BFDTxMs:       cfg.BFDTxMs,
			BFDRxMs:       cfg.BFDRxMs,
			BFDMultiplier: cfg.BFDMult,
		})
		if err != nil {
			return fmt.Errorf("render frr conf: %w", err)
		}
		if err := writeFile(cfg.DryRun, cfg.FRRConfPath, []byte(frrConf), 0o640); err != nil {
			return err
		}
		// reload-or-restart so this works whether or not frr is running.
		if err := r.run("systemctl", "reload-or-restart", "frr"); err != nil {
			return fmt.Errorf("reload frr: %w", err)
		}
	}

	tflog.Info("tfnet started",
		"self", cfg.SelfNodeID,
		"wg_iface", cfg.WGIface,
		"vxlan_iface", cfg.VxlanIface,
		"bridge_iface", cfg.BridgeIface,
		"vni", cfg.VNI,
		"asn", cfg.ASN,
	)
	return nil
}

// wgSyncConf hot-reloads peer changes into a live wg interface without
// dropping existing sessions.
func (r *runner) wgSyncConf(iface string) error {
	stripped, err := r.runCapture("wg-quick", "strip", iface)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp("", "tfnet-wgsync-*.conf")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(stripped); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return r.run("wg", "syncconf", iface, tmp.Name())
}

// Stop is the inverse of Start. Best-effort: it logs failures but continues
// so a partially-up state can be cleaned up by a single command.
func Stop(cfg Config) error {
	cfg.applyDefaults()
	warnIfNotRoot(cfg.DryRun)
	r := runner{dry: cfg.DryRun}

	// FRR first so it stops trying to advertise before the data plane goes
	// away. We use vtysh to surgically remove our config rather than
	// trampling the daemon-wide /etc/frr/frr.conf.
	if !cfg.SkipFRR {
		stdin := fmt.Sprintf("configure terminal\nno router bgp %d\nno bfd\nend\nwrite memory\n", cfg.ASN)
		if err := r.runStdin([]byte(stdin), "vtysh"); err != nil {
			tflog.Warn("vtysh cleanup failed; FRR config may need manual removal",
				"asn", cfg.ASN, "error", err)
		}
	}

	if exists, _ := r.ifaceExists(cfg.VxlanIface); exists {
		_ = r.run("ip", "link", "set", cfg.VxlanIface, "down")
		if err := r.run("ip", "link", "del", cfg.VxlanIface); err != nil {
			tflog.Warn("delete vxlan failed", "iface", cfg.VxlanIface, "error", err)
		}
	}
	if exists, _ := r.ifaceExists(cfg.BridgeIface); exists {
		_ = r.run("ip", "link", "set", cfg.BridgeIface, "down")
		if err := r.run("ip", "link", "del", cfg.BridgeIface); err != nil {
			tflog.Warn("delete bridge failed", "iface", cfg.BridgeIface, "error", err)
		}
	}
	if exists, _ := r.ifaceExists(cfg.WGIface); exists {
		if err := r.run("wg-quick", "down", cfg.WGIface); err != nil {
			tflog.Warn("wg-quick down failed", "iface", cfg.WGIface, "error", err)
		}
	}

	tflog.Info("tfnet stopped", "self", cfg.SelfNodeID)
	return nil
}

// StatusReport is the inspectable runtime view.
type StatusReport struct {
	Self        string
	WGIface     string
	WGUp        bool
	WGDump      WGDump
	VxlanIface  string
	VxlanUp     bool
	BridgeIface string
	BridgeUp    bool
	BGPSummary  string
	PeerByPub   map[string]string // wg pubkey -> node_id, for human display
}

// Status gathers live runtime state. Read-only; never modifies anything.
// It does not require root for `ip link show`, but `wg show` and `vtysh`
// generally do.
func Status(cfg Config) (*StatusReport, error) {
	cfg.applyDefaults()
	state, _, err := loadSelf(&cfg)
	if err != nil {
		// Status should still partially work even if the ledger can't be
		// loaded; surface the error but keep going.
		tflog.Warn("status: ledger load failed", "error", err)
		state = ledger.NewState()
	}
	r := runner{dry: false}
	rep := &StatusReport{
		Self:        cfg.SelfNodeID,
		WGIface:     cfg.WGIface,
		VxlanIface:  cfg.VxlanIface,
		BridgeIface: cfg.BridgeIface,
		PeerByPub:   map[string]string{},
	}
	for _, m := range state.Members {
		rep.PeerByPub[m.WGPubkey] = m.NodeID
	}
	rep.WGUp, _ = r.ifaceExists(cfg.WGIface)
	rep.VxlanUp, _ = r.ifaceExists(cfg.VxlanIface)
	rep.BridgeUp, _ = r.ifaceExists(cfg.BridgeIface)
	if rep.WGUp {
		if out, err := r.runCapture("wg", "show", cfg.WGIface, "dump"); err == nil {
			rep.WGDump = ParseWGDump(out)
		} else {
			tflog.Warn("wg show dump failed", "error", err)
		}
	}
	if !cfg.SkipFRR {
		if out, err := r.runCapture("vtysh", "-c", "show bgp l2vpn evpn summary"); err == nil {
			rep.BGPSummary = out
		} else {
			tflog.Debug("vtysh summary failed", "error", err)
		}
	}
	return rep, nil
}

// writeFile is a thin wrapper that respects dry-run.
func writeFile(dryRun bool, path string, data []byte, mode os.FileMode) error {
	tflog.Info("write", "path", path, "bytes", len(data), "mode", mode, "dry_run", dryRun)
	if dryRun {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func warnIfNotRoot(dry bool) {
	if dry {
		return
	}
	if os.Geteuid() != 0 {
		tflog.Warn("not running as root; ip/wg-quick/vtysh will likely fail",
			"euid", os.Geteuid(), "hint", "re-run with sudo, or pass -dry-run to preview")
	}
}

func itoa(i int) string { return strconv.Itoa(i) }
