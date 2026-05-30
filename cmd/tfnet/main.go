// tfnet is the CLI for the WireGuard/VXLAN/EVPN L2 VPN designed in
// docs/wg-evpn-l2vpn-design.md.
//
// The CLI manages three things:
//
//   - keys      Ed25519 identity keypairs and WireGuard X25519 keypairs.
//   - ledger    The append-only membership ledger (§3): propose, sign, commit.
//   - render    Generate WireGuard / FRR config from the committed ledger.
//
// The ledger is the single source of truth: peer lists, AllowedIPs, and BGP
// neighbors are all derived from it. Hand-editing the rendered configs is not
// supported; re-run `tfnet render ...` whenever the ledger changes.
package main

import (
	"flag"
	"fmt"
	"os"

	"tfnet/internal/tflog"
)

// globalLogOpts are populated from the leading flags consumed by parseGlobalFlags.
var globalLogOpts tflog.Options

// parseGlobalFlags peels off any -log-level / -log-format / -log-file flags
// that appear *before* the subcommand. Returns the remaining args (subcommand
// + its own args). Subcommand-specific flags are parsed separately.
func parseGlobalFlags(args []string) []string {
	fs := flag.NewFlagSet("tfnet", flag.ExitOnError)
	fs.StringVar(&globalLogOpts.Level, "log-level", "info", "log level: debug|info|warn|error")
	fs.StringVar(&globalLogOpts.Format, "log-format", "text", "log format: text|json")
	fs.StringVar(&globalLogOpts.File, "log-file", "", "log destination file ('' or '-' = stderr)")
	// Stop at the first non-flag token: that is the subcommand.
	// flag.FlagSet doesn't natively support that, so we walk args ourselves.
	i := 0
	for i < len(args) {
		a := args[i]
		switch a {
		case "-log-level", "--log-level",
			"-log-format", "--log-format",
			"-log-file", "--log-file":
			if i+1 >= len(args) {
				fmt.Fprintf(os.Stderr, "tfnet: flag %s requires a value\n", a)
				os.Exit(2)
			}
			_ = fs.Set(trimDash(a), args[i+1])
			i += 2
		default:
			// Support -log-level=debug style.
			if eq := indexByte(a, '='); eq > 0 && isGlobalFlag(a[:eq]) {
				_ = fs.Set(trimDash(a[:eq]), a[eq+1:])
				i++
				continue
			}
			return args[i:]
		}
	}
	return nil
}

func trimDash(s string) string {
	for len(s) > 0 && s[0] == '-' {
		s = s[1:]
	}
	return s
}

func isGlobalFlag(s string) bool {
	switch trimDash(s) {
	case "log-level", "log-format", "log-file":
		return true
	}
	return false
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func usage() {
	fmt.Fprintf(os.Stderr, `tfnet -- WireGuard/VXLAN/EVPN L2 VPN CLI

Usage:
  tfnet <command> [subcommand] [flags]

Commands:
  keys      Manage local key material
    gen-identity  Generate an Ed25519 identity keypair
    gen-wg        Generate a WireGuard (X25519) keypair
    pub           Print the public key of an identity / wg key file

  ledger    Operate on the membership ledger
    init          Initialise an empty ledger directory
    genesis       Create the seq=0 genesis entry (one or more initial members)
    propose-add       Propose adding a new member
    propose-remove    Propose removing an existing member
    sign          Sign a pending entry (in place)
    merge         Merge external signatures into a pending entry
    show          Show a pending entry with required/missing approvers
    commit        Validate a fully-signed pending entry and append to the log
    list          List committed entries
    members       List current members
    verify        Replay the entire log and verify

  render    Generate downstream configs from the ledger
    wg            Render wg-quick config for SELF
    frr           Render FRR (BGP/EVPN/BFD) config for SELF

Global flags (must precede the subcommand):
  -log-level  debug|info|warn|error (default info)
  -log-format text|json             (default text)
  -log-file   path                  ('' or '-' = stderr)

Per-subcommand:
  -ledger <dir>   Ledger directory (default $TFNET_LEDGER or ./ledger)

Every ledger-mutating action also appends a structured record to
<ledger>/audit.jsonl for traceability.
`)
}

func main() {
	rest := parseGlobalFlags(os.Args[1:])
	if dest, err := tflog.Setup(globalLogOpts); err != nil {
		fmt.Fprintf(os.Stderr, "tfnet: logger setup: %v\n", err)
		os.Exit(2)
	} else if dest != "stderr" {
		fmt.Fprintf(os.Stderr, "tfnet: logging to %s\n", dest)
	}
	defer tflog.Close()
	if len(rest) == 0 {
		usage()
		os.Exit(2)
	}
	tflog.Debug("invoke", "argv", os.Args)
	switch rest[0] {
	case "keys":
		runKeys(rest[1:])
	case "ledger":
		runLedger(rest[1:])
	case "render":
		runRender(rest[1:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "tfnet: unknown command %q\n\n", rest[0])
		usage()
		os.Exit(2)
	}
}

func die(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	tflog.Error("fatal", "msg", msg)
	fmt.Fprintf(os.Stderr, "tfnet: %s\n", msg)
	os.Exit(1)
}

func ledgerDir(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if env := os.Getenv("TFNET_LEDGER"); env != "" {
		return env
	}
	return "./ledger"
}
