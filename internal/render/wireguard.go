// Package render generates wg-quick / FRR config text from a ledger State.
// The ledger is the single source of truth (§9): config files are derived,
// never authored by hand.
package render

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"tfnet/internal/ledger"
)

// WGOptions controls WireGuard config rendering.
type WGOptions struct {
	SelfNodeID    string // which member this conf is for
	ListenPort    int    // 0 = omit (let WireGuard pick)
	MTU           int    // 0 = omit; recommend 1440 (IPv4) / 1420 (IPv6) per §6
	PrivateKey    string // base64; empty -> writes "REPLACE_ME" placeholder
	Keepalive     int    // seconds; 0 = use design default (25)
	IncludeSelfIP bool   // include Address line on [Interface] (default true)
}

// WireGuardConf renders a wg-quick-compatible config for the member SelfNodeID
// of the supplied state.
func WireGuardConf(state *ledger.State, opts WGOptions) (string, error) {
	self, ok := state.Members[opts.SelfNodeID]
	if !ok {
		return "", fmt.Errorf("self node %q is not a current member", opts.SelfNodeID)
	}
	keep := opts.Keepalive
	if keep == 0 {
		keep = 25
	}
	priv := opts.PrivateKey
	if priv == "" {
		priv = "REPLACE_ME"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# tfnet WireGuard config -- generated, do not edit\n")
	fmt.Fprintf(&b, "# self: %s (overlay %s)\n", self.NodeID, self.OverlayIP)
	fmt.Fprintf(&b, "# ledger seq: %d\n\n", state.NextSeq)

	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", priv)
	if opts.ListenPort > 0 {
		fmt.Fprintf(&b, "ListenPort = %d\n", opts.ListenPort)
	}
	if opts.IncludeSelfIP || opts.SelfNodeID != "" {
		// wg-quick uses Address to assign the IP on the interface.
		fmt.Fprintf(&b, "Address = %s\n", self.OverlayIP)
	}
	if opts.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", opts.MTU)
	}
	b.WriteString("\n")

	for _, id := range state.MemberIDs() {
		if id == opts.SelfNodeID {
			continue
		}
		m := state.Members[id]
		host, err := overlayHostOnly(m.OverlayIP)
		if err != nil {
			return "", fmt.Errorf("peer %s overlay_ip: %w", id, err)
		}
		fmt.Fprintf(&b, "[Peer]\n")
		fmt.Fprintf(&b, "# node_id: %s\n", m.NodeID)
		fmt.Fprintf(&b, "PublicKey = %s\n", m.WGPubkey)
		fmt.Fprintf(&b, "AllowedIPs = %s/32\n", host)
		if m.Endpoint != "" {
			fmt.Fprintf(&b, "Endpoint = %s\n", m.Endpoint)
		}
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n\n", keep)
	}
	return b.String(), nil
}

// overlayHostOnly returns the host portion of an overlay CIDR (e.g. 10.99.0.1
// from 10.99.0.1/32) so that AllowedIPs always carries /32 regardless of
// what mask the ledger entry recorded.
func overlayHostOnly(cidr string) (string, error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return "", err
	}
	return p.Addr().String(), nil
}

// EnsureUniqueOverlay verifies that overlay IPs in the state do not collide.
// Useful as a sanity check before rendering.
func EnsureUniqueOverlay(state *ledger.State) error {
	seen := map[string]string{}
	ids := make([]string, 0, len(state.Members))
	for id := range state.Members {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		host, err := overlayHostOnly(state.Members[id].OverlayIP)
		if err != nil {
			return fmt.Errorf("%s: %w", id, err)
		}
		if other, dup := seen[host]; dup {
			return fmt.Errorf("overlay collision on %s: %s and %s", host, other, id)
		}
		seen[host] = id
	}
	return nil
}
