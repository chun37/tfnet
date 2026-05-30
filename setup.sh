#!/usr/bin/env bash
#
# setup.sh — install runtime dependencies for tfnet and build the binary.
#
# Installs:
#   - wireguard, wireguard-tools           (data plane transport)
#   - frr, frr-pythontools                 (EVPN/iBGP/BFD control plane)
#   - iproute2 / iproute  (provides 'ip' and 'bridge')
#   - jq                                   (used by README examples)
#
# Then:
#   - enables 'bgpd' and 'bfdd' in /etc/frr/daemons
#   - load wireguard / vxlan kernel modules
#   - builds ./tfnet (requires Go 1.26+)
#
# Optional:
#   INSTALL=1 ./setup.sh         # also install tfnet to /usr/local/bin
#   SYSTEMD=1 ./setup.sh         # also drop tfnet@.service into /etc/systemd/system
#
# Re-running is safe; every step is idempotent.

set -euo pipefail

log()  { printf '[setup] %s\n' "$*" >&2; }
warn() { printf '[setup] WARN: %s\n' "$*" >&2; }
die()  { printf '[setup] ERROR: %s\n' "$*" >&2; exit 1; }

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        die "run as root, or install sudo"
    fi
fi

# ---- package install -------------------------------------------------------

if command -v apt-get >/dev/null 2>&1; then
    log "package manager: apt"
    $SUDO apt-get update
    $SUDO apt-get install -y --no-install-recommends \
        wireguard wireguard-tools \
        frr frr-pythontools \
        iproute2 \
        jq curl ca-certificates
elif command -v dnf >/dev/null 2>&1; then
    log "package manager: dnf"
    $SUDO dnf install -y \
        wireguard-tools \
        frr \
        iproute \
        jq curl ca-certificates
elif command -v pacman >/dev/null 2>&1; then
    log "package manager: pacman"
    $SUDO pacman -Sy --needed --noconfirm \
        wireguard-tools \
        frr \
        iproute2 \
        jq curl ca-certificates
else
    warn "no supported package manager (apt/dnf/pacman) found"
    warn "install manually: wireguard-tools, frr, iproute2, jq"
fi

# ---- FRR daemons: enable bgpd + bfdd ---------------------------------------
#
# Stock FRR ships with only zebra enabled; the EVPN/BFD config we render
# would silently do nothing without these two daemons turned on.

DAEMONS=/etc/frr/daemons
if [ -f "$DAEMONS" ]; then
    log "enabling bgpd + bfdd in $DAEMONS"
    $SUDO sed -i.bak \
        -e 's/^bgpd=no/bgpd=yes/' \
        -e 's/^bfdd=no/bfdd=yes/' \
        "$DAEMONS"
    if systemctl is-enabled frr >/dev/null 2>&1; then
        $SUDO systemctl restart frr || warn "systemctl restart frr failed; check 'journalctl -u frr'"
    else
        $SUDO systemctl enable --now frr || warn "could not start frr; check 'systemctl status frr'"
    fi
else
    warn "$DAEMONS not found; skip FRR daemons configuration"
fi

# ---- kernel modules --------------------------------------------------------

for mod in wireguard vxlan; do
    if ! lsmod | awk '{print $1}' | grep -qx "$mod"; then
        if $SUDO modprobe "$mod" 2>/dev/null; then
            log "loaded kernel module: $mod"
        else
            warn "could not load kernel module: $mod (may be built-in or absent)"
        fi
    fi
done

# Persist module loading across reboots.
MODLOAD=/etc/modules-load.d/tfnet.conf
if [ ! -f "$MODLOAD" ]; then
    log "writing $MODLOAD"
    printf 'wireguard\nvxlan\n' | $SUDO tee "$MODLOAD" >/dev/null
fi

# ---- build tfnet -----------------------------------------------------------

if command -v go >/dev/null 2>&1; then
    GOVER=$(go version | awk '{print $3}')
    log "go: $GOVER"
    log "building ./tfnet"
    go build -o tfnet ./cmd/tfnet
    if [ "${INSTALL:-0}" = "1" ]; then
        $SUDO install -m 0755 ./tfnet /usr/local/bin/tfnet
        log "installed /usr/local/bin/tfnet"
    fi
else
    warn "go not found; install Go 1.26+ and run: go build -o tfnet ./cmd/tfnet"
fi

# ---- systemd unit (optional) ----------------------------------------------

if [ "${SYSTEMD:-0}" = "1" ]; then
    if [ -f contrib/tfnet@.service ]; then
        log "installing contrib/tfnet@.service -> /etc/systemd/system/tfnet@.service"
        $SUDO install -m 0644 contrib/tfnet@.service /etc/systemd/system/tfnet@.service
        $SUDO systemctl daemon-reload
        log "now: edit /etc/default/tfnet then: systemctl enable --now tfnet@<node_id>"
    else
        warn "contrib/tfnet@.service not present; skipping systemd unit install"
    fi
fi

# ---- done ------------------------------------------------------------------

cat <<'NEXT'

[setup] done. Next steps:

  # 1. Generate this node's keys
  ./tfnet keys gen-identity -node-id <name> -out node.id.json
  ./tfnet keys gen-wg       -out node.wg.json

  # 2. Bootstrap the ledger -- see README for the genesis / N-of-N workflow

  # 3. Bring the overlay up
  sudo ./tfnet start -self <name> -wg-key node.wg.json -ledger ./ledger -asn 65010

  # 4. Inspect
  sudo ./tfnet status -self <name>

  # 5. Stop
  sudo ./tfnet stop -self <name>

Use -dry-run to print every ip/wg/vtysh command without running it.
NEXT
