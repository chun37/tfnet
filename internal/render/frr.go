package render

import (
	"fmt"
	"net/netip"
	"strings"

	"tfnet/internal/ledger"
)

// FRROptions controls FRR config rendering.
type FRROptions struct {
	SelfNodeID    string
	ASN           uint32 // iBGP private ASN (all peers same)
	BFDTxMs       int    // BFD transmit-interval; 0 -> 300
	BFDRxMs       int    // BFD receive-interval;  0 -> 300
	BFDMultiplier int    // BFD detect-multiplier; 0 -> 3
}

// FRRConf renders an FRR (vtysh-style) config for SelfNodeID running iBGP
// EVPN against every other current member.
func FRRConf(state *ledger.State, opts FRROptions) (string, error) {
	self, ok := state.Members[opts.SelfNodeID]
	if !ok {
		return "", fmt.Errorf("self node %q is not a current member", opts.SelfNodeID)
	}
	if opts.ASN == 0 {
		return "", fmt.Errorf("ASN must be set")
	}
	selfIP, err := overlayHostOnly(self.OverlayIP)
	if err != nil {
		return "", fmt.Errorf("self overlay_ip: %w", err)
	}
	tx := opts.BFDTxMs
	if tx == 0 {
		tx = 300
	}
	rx := opts.BFDRxMs
	if rx == 0 {
		rx = 300
	}
	mult := opts.BFDMultiplier
	if mult == 0 {
		mult = 3
	}

	peers := make([]string, 0, len(state.Members))
	for _, id := range state.MemberIDs() {
		if id == opts.SelfNodeID {
			continue
		}
		host, err := overlayHostOnly(state.Members[id].OverlayIP)
		if err != nil {
			return "", fmt.Errorf("peer %s overlay_ip: %w", id, err)
		}
		if _, err := netip.ParseAddr(host); err != nil {
			return "", fmt.Errorf("peer %s overlay_ip not an address: %w", id, err)
		}
		peers = append(peers, host)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "! tfnet FRR config -- generated, do not edit\n")
	fmt.Fprintf(&b, "! self: %s (overlay %s)\n", self.NodeID, self.OverlayIP)
	fmt.Fprintf(&b, "! ledger seq: %d\n!\n", state.NextSeq)

	// BFD section first so router bgp can reference it cleanly.
	b.WriteString("bfd\n")
	for _, p := range peers {
		fmt.Fprintf(&b, " peer %s\n", p)
		fmt.Fprintf(&b, "  transmit-interval %d\n", tx)
		fmt.Fprintf(&b, "  receive-interval %d\n", rx)
		fmt.Fprintf(&b, "  detect-multiplier %d\n", mult)
		b.WriteString("  no shutdown\n")
		b.WriteString(" exit\n")
	}
	b.WriteString("exit\n!\n")

	fmt.Fprintf(&b, "router bgp %d\n", opts.ASN)
	fmt.Fprintf(&b, " bgp router-id %s\n", selfIP)
	b.WriteString(" no bgp default ipv4-unicast\n")
	b.WriteString(" no bgp ebgp-requires-policy\n")
	for _, p := range peers {
		fmt.Fprintf(&b, " neighbor %s remote-as %d\n", p, opts.ASN)
		fmt.Fprintf(&b, " neighbor %s update-source %s\n", p, selfIP)
		fmt.Fprintf(&b, " neighbor %s bfd\n", p)
	}
	b.WriteString(" !\n")
	b.WriteString(" address-family l2vpn evpn\n")
	for _, p := range peers {
		fmt.Fprintf(&b, "  neighbor %s activate\n", p)
	}
	b.WriteString("  advertise-all-vni\n")
	b.WriteString(" exit-address-family\n")
	b.WriteString("exit\n")

	return b.String(), nil
}
