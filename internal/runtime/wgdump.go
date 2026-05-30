package runtime

import (
	"strconv"
	"strings"
)

// WGPeerStat is a single peer as reported by `wg show <iface> dump`.
type WGPeerStat struct {
	PublicKey       string
	Endpoint        string
	AllowedIPs      string
	LatestHandshake int64 // unix seconds; 0 = never
	RxBytes         uint64
	TxBytes         uint64
	Keepalive       string
}

// WGDump is the structured form of `wg show <iface> dump`.
//
// `wg show <iface> dump` output (TSV):
//
//	Line 1 (interface):   private_key  public_key  listen_port  fwmark
//	Line 2..N  (peers):   public_key  preshared_key  endpoint  allowed_ips
//	                      latest_handshake  transfer_rx  transfer_tx  persistent_keepalive
type WGDump struct {
	PublicKey  string
	ListenPort int
	Peers      []WGPeerStat
}

// ParseWGDump parses the output of `wg show <iface> dump`.
//
// On malformed lines we skip them rather than fail — wg may add columns in
// the future and the diagnostic value of partial data still beats nothing.
func ParseWGDump(out string) WGDump {
	var d WGDump
	first := true
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if first {
			first = false
			if len(fields) >= 3 {
				d.PublicKey = fields[1]
				if p, err := strconv.Atoi(fields[2]); err == nil {
					d.ListenPort = p
				}
			}
			continue
		}
		if len(fields) < 7 {
			continue
		}
		p := WGPeerStat{
			PublicKey:  fields[0],
			Endpoint:   normEmpty(fields[2]),
			AllowedIPs: fields[3],
		}
		p.LatestHandshake, _ = strconv.ParseInt(fields[4], 10, 64)
		p.RxBytes, _ = strconv.ParseUint(fields[5], 10, 64)
		p.TxBytes, _ = strconv.ParseUint(fields[6], 10, 64)
		if len(fields) >= 8 {
			p.Keepalive = normEmpty(fields[7])
		}
		d.Peers = append(d.Peers, p)
	}
	return d
}

func normEmpty(s string) string {
	if s == "(none)" || s == "off" {
		return ""
	}
	return s
}
