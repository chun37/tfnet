// Package runtime turns the ledger-derived configs into a live overlay by
// driving the host tools that actually do the work:
//
//   - wg-quick(8)   — bring the WireGuard interface up/down with the rendered conf
//   - ip(8)         — create / remove the VXLAN device and bridge
//   - bridge(8)     — enable ARP/ND suppression and disable bridge MAC learning
//   - vtysh(8) /
//     systemctl(8)  — reload FRR with the rendered BGP/EVPN/BFD config
//
// Every external command is funnelled through runner so that every invocation
// is logged (slog INFO) and dry-runnable. Failures bubble up with the exact
// argv that was attempted, so the audit + slog trail is always usable.
package runtime

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"tfnet/internal/tflog"
)

// runner wraps exec.Command with consistent logging and a dry-run mode.
type runner struct {
	dry bool
}

func (r *runner) run(name string, args ...string) error {
	tflog.Info("exec", "cmd", name, "args", args, "dry_run", r.dry)
	if r.dry {
		return nil
	}
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		s := strings.TrimSpace(stderr.String())
		if s != "" {
			return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, s)
		}
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

func (r *runner) runStdin(stdin []byte, name string, args ...string) error {
	tflog.Info("exec",
		"cmd", name, "args", args,
		"stdin_bytes", len(stdin), "dry_run", r.dry,
	)
	if r.dry {
		return nil
	}
	cmd := exec.Command(name, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		s := strings.TrimSpace(stderr.String())
		if s != "" {
			return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, s)
		}
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

// runCapture executes a read-only command and returns stdout. It is intended
// for `wg show ... dump`, `vtysh -c "show ..."` and similar inspection
// commands; dry-run does NOT short-circuit (the caller wants real data).
func (r *runner) runCapture(name string, args ...string) (string, error) {
	tflog.Debug("exec.capture", "cmd", name, "args", args)
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		s := strings.TrimSpace(stderr.String())
		if s != "" {
			return stdout.String(), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, s)
		}
		return stdout.String(), fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return stdout.String(), nil
}

// ifaceExists tests whether a given network interface is present. Uses
// `ip link show dev <iface>`; exit status non-zero means absent.
func (r *runner) ifaceExists(iface string) (bool, error) {
	if r.dry {
		// In dry-run we can't actually probe, so assume absent so that
		// idempotent "create-if-missing" logic still prints commands.
		return false, nil
	}
	cmd := exec.Command("ip", "link", "show", "dev", iface)
	cmd.Stdout = nil
	cmd.Stderr = nil
	err := cmd.Run()
	if err == nil {
		return true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return false, nil
	}
	return false, err
}
