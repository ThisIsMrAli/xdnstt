#!/usr/bin/env bash
#
# Ubuntu 24.04 one-click installer for xdnstt UDP server
#   https://github.com/ThisIsMrAli/xdnstt
#
# What it does:
#   1. Installs Go 1.24 (if not already present or too old)
#   2. Clones / updates xdnstt from GitHub and compiles dnstt-server
#   3. Generates or reuses a Noise keypair
#   4. Installs and configures Dante SOCKS proxy (optional but recommended)
#   5. Creates a hardened systemd service with auto-restart
#   6. Redirects UDP 53 → 5300 so the service runs without root privileges
#   7. Prints the public key and exact client arguments to copy
#
# Usage:
#   sudo bash ubuntu24-dnstt-udp-server-install.sh --domain t.example.com --dante
#
# SOCKS auth: none by default — multiple devices can connect simultaneously
#             with no username/password and no extra configuration.
#
set -euo pipefail

# ── Tuneable defaults ─────────────────────────────────────────────────────────
REPO_URL="${REPO_URL:-https://github.com/ThisIsMrAli/xdnstt}"
REPO_DIR="${REPO_DIR:-/opt/xdnstt}"
DNSTT_PORT="${DNSTT_PORT:-5300}"          # high-port DNS; iptables redirects 53 → this
LISTEN_ADDR="${LISTEN_ADDR:-0.0.0.0}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/dnstt}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
SERVICE_NAME="${SERVICE_NAME:-dnstt-udp}"
SERVICE_USER="${SERVICE_USER:-dnstt}"
MTU_DEFAULT="${MTU_DEFAULT:-1232}"
GO_VERSION_REQUIRED="1.24"
GO_VERSION_INSTALL="1.24.2"               # patch version to install when missing
GO_INSTALL_DIR="/usr/local/go"

# ── Helpers ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[1;36m'; WHITE='\033[1;37m'; BOLD='\033[1m'; NC='\033[0m'

step()  { echo -e "\n${GREEN}[+]${NC} ${BOLD}$*${NC}"; }
info()  { echo -e "    ${CYAN}→${NC} $*"; }
warn()  { echo -e "    ${YELLOW}[!]${NC} $*"; }
die()   { echo -e "\n${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ── Argument parsing ─────────────────────────────────────────────────────────
usage() {
  cat <<EOF

${BOLD}xdnstt UDP server installer${NC}  (Ubuntu 24.04)

${BOLD}Required:${NC}
  --domain <t.example.com>   Tunnel zone domain (must be delegated as NS to this server)

${BOLD}Upstream (pick one):${NC}
  --dante                    Install Dante SOCKS on 127.0.0.1:1080 (recommended; no auth, multi-device)
  --upstream <ip:port>       Forward streams to an existing service (e.g. 127.0.0.1:1080)

${BOLD}Optional:${NC}
  --mtu <n>                  Server max UDP payload in bytes (default 1232)
                             Client starts at 512 and auto-probes upward — you rarely need to change this.
  --port <n>                 Local UDP port dnstt-server listens on (default 5300)
                             Port 53 is redirected here automatically.
  --no-redirect              Skip iptables redirect (use this only if you run directly on port 53)
  --rebuild                  Force recompile even if binary already exists
  --branch <name>            Git branch to build from (default: main)
  -h, --help                 Show this help

${BOLD}Examples:${NC}
  # Most common: SOCKS proxy + dnstt in one shot
  sudo bash install.sh --domain t.example.com --dante

  # Forward to your own app on port 8000
  sudo bash install.sh --domain t.example.com --upstream 127.0.0.1:8000

${BOLD}After install:${NC}
  systemctl status dnstt-udp
  journalctl -u dnstt-udp -f

${BOLD}Multiple devices:${NC}
  No SOCKS users needed. All devices share the open Dante proxy (localhost-only).
  Each device creates its own independent dnstt session.

EOF
}

DOMAIN=""
UPSTREAM=""
ENABLE_DANTE=false
ENABLE_REDIRECT=true
MTU="$MTU_DEFAULT"
REBUILD=false
GIT_BRANCH="main"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain)     DOMAIN="${2:?'--domain requires a value'}";    shift 2 ;;
    --upstream)   UPSTREAM="${2:?'--upstream requires a value'}"; shift 2 ;;
    --mtu)        MTU="${2:?'--mtu requires a value'}";           shift 2 ;;
    --port)       DNSTT_PORT="${2:?'--port requires a value'}";   shift 2 ;;
    --dante)      ENABLE_DANTE=true;                              shift   ;;
    --no-redirect) ENABLE_REDIRECT=false;                         shift   ;;
    --rebuild)    REBUILD=true;                                   shift   ;;
    --branch)     GIT_BRANCH="${2:?'--branch requires a value'}"; shift 2 ;;
    -h|--help)    usage; exit 0 ;;
    *) die "Unknown argument: $1  (run with --help for usage)" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "Run as root: sudo bash $0 $*"
[[ -n "$DOMAIN" ]] || die "--domain is required."

# Auto-set upstream when --dante is requested
if [[ "$ENABLE_DANTE" == "true" && -z "$UPSTREAM" ]]; then
  UPSTREAM="127.0.0.1:1080"
fi
[[ -n "$UPSTREAM" ]] || die "Provide --upstream <ip:port> or use --dante."

# ── 1. System dependencies ────────────────────────────────────────────────────
step "Installing system dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
  git curl ca-certificates \
  iptables iptables-persistent \
  >/dev/null
systemctl enable netfilter-persistent >/dev/null 2>&1 || true
info "Done"

# ── 2. Go toolchain ────────────────────────────────────────────────────────────
go_version_ok() {
  local gover
  gover="$(go version 2>/dev/null | awk '{print $3}' | sed 's/go//')"
  [[ -z "$gover" ]] && return 1
  # Compare major.minor
  local maj req_maj min req_min
  IFS='.' read -r maj min _ <<< "$gover"
  IFS='.' read -r req_maj req_min _ <<< "$GO_VERSION_REQUIRED"
  (( maj > req_maj )) && return 0
  (( maj == req_maj && min >= req_min )) && return 0
  return 1
}

step "Checking Go toolchain (need >= ${GO_VERSION_REQUIRED})"
if go_version_ok; then
  info "Found $(go version) — OK"
else
  info "Installing Go ${GO_VERSION_INSTALL} from go.dev ..."
  local_arch="$(uname -m)"
  case "$local_arch" in
    x86_64)       GO_ARCH="amd64" ;;
    aarch64|arm64) GO_ARCH="arm64" ;;
    armv7l|armv6l) GO_ARCH="armv6l" ;;
    i386|i686)    GO_ARCH="386" ;;
    *) die "Unsupported CPU: $local_arch" ;;
  esac
  GO_TAR="go${GO_VERSION_INSTALL}.linux-${GO_ARCH}.tar.gz"
  GO_URL="https://go.dev/dl/${GO_TAR}"
  curl -fsSL -o "/tmp/${GO_TAR}" "$GO_URL"
  rm -rf "$GO_INSTALL_DIR"
  tar -C /usr/local -xzf "/tmp/${GO_TAR}"
  rm -f "/tmp/${GO_TAR}"
  # Persist in PATH for current session and future logins
  export PATH="/usr/local/go/bin:$PATH"
  if ! grep -q '/usr/local/go/bin' /etc/profile.d/go.sh 2>/dev/null; then
    echo 'export PATH="/usr/local/go/bin:$PATH"' > /etc/profile.d/go.sh
  fi
  info "Installed $(go version)"
fi

export PATH="/usr/local/go/bin:${PATH}"
export GOPATH="/root/go"
export GOCACHE="/root/.cache/go-build"

# ── 3. Clone / update source from GitHub ─────────────────────────────────────
step "Fetching source from ${REPO_URL}"
if [[ -d "${REPO_DIR}/.git" ]]; then
  info "Repo already cloned — pulling latest from branch '${GIT_BRANCH}'"
  git -C "$REPO_DIR" fetch --quiet origin
  git -C "$REPO_DIR" checkout --quiet "$GIT_BRANCH"
  git -C "$REPO_DIR" reset --quiet --hard "origin/${GIT_BRANCH}"
else
  info "Cloning into ${REPO_DIR}"
  git clone --depth=1 --branch "$GIT_BRANCH" "$REPO_URL" "$REPO_DIR"
fi
info "Current commit: $(git -C "$REPO_DIR" log --oneline -1)"

# ── 4. Compile dnstt-server ────────────────────────────────────────────────────
DNSTT_SERVER_BIN="${INSTALL_DIR}/dnstt-server"

needs_build=false
if [[ ! -x "$DNSTT_SERVER_BIN" ]]; then
  needs_build=true
elif [[ "$REBUILD" == "true" ]]; then
  needs_build=true
fi

if [[ "$needs_build" == "true" ]]; then
  step "Compiling dnstt-server"
  cd "$REPO_DIR"
  go build -o "${DNSTT_SERVER_BIN}" ./dnstt-server/
  chmod 0755 "$DNSTT_SERVER_BIN"
  info "Binary: ${DNSTT_SERVER_BIN}"
else
  info "Binary already exists (use --rebuild to recompile)"
fi
info "Version check: $("$DNSTT_SERVER_BIN" -gen-key 2>&1 | head -1 || true)"

# ── 5. Service user + config dir ─────────────────────────────────────────────
step "Creating service user and config directory"
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd -r -s /usr/sbin/nologin -d /nonexistent -c "dnstt service" "$SERVICE_USER"
  info "Created user: ${SERVICE_USER}"
else
  info "User ${SERVICE_USER} already exists"
fi
mkdir -p "$CONFIG_DIR"
chown -R "${SERVICE_USER}:${SERVICE_USER}" "$CONFIG_DIR"
chmod 750 "$CONFIG_DIR"

# ── 6. Noise keypair ──────────────────────────────────────────────────────────
PRIV="${CONFIG_DIR}/server.key"
PUB="${CONFIG_DIR}/server.pub"

step "Keypair"
if [[ -s "$PRIV" && -s "$PUB" ]]; then
  info "Existing keypair found — reusing"
else
  info "Generating new Noise keypair"
  "$DNSTT_SERVER_BIN" -gen-key -privkey-file "$PRIV" -pubkey-file "$PUB"
  chown "${SERVICE_USER}:${SERVICE_USER}" "$PRIV" "$PUB"
  chmod 600 "$PRIV"
  chmod 644 "$PUB"
  info "Keys written to ${CONFIG_DIR}/"
fi
PUBKEY="$(cat "$PUB")"
info "Public key: ${PUBKEY}"

# ── 7. Dante SOCKS proxy (optional) ──────────────────────────────────────────
if [[ "$ENABLE_DANTE" == "true" ]]; then
  step "Installing Dante SOCKS proxy on 127.0.0.1:1080 (no auth; multi-device OK)"
  apt-get install -y -qq dante-server >/dev/null
  IFACE="$(ip route | awk '/default/ {print $5; exit}')"
  IFACE="${IFACE:-eth0}"
  cat > /etc/danted.conf <<EOF
# dnstt upstream SOCKS proxy — localhost only, no authentication required.
# Multiple devices can connect simultaneously — each gets its own dnstt session.
logoutput: syslog
user.privileged: root
user.unprivileged: nobody

internal: 127.0.0.1 port = 1080
external: ${IFACE}

socksmethod: none
compatibility: sameport
extension: bind

client pass {
    from: 127.0.0.0/8 to: 0.0.0.0/0
    log: error
}
socks pass {
    from: 127.0.0.0/8 to: 0.0.0.0/0
    command: bind connect udpassociate
    log: error
}
socks block  { from: 0.0.0.0/0 to: ::/0 log: error }
client block { from: 0.0.0.0/0 to: ::/0 log: error }
EOF
  systemctl enable --now danted >/dev/null
  info "Dante running on 127.0.0.1:1080"
fi

# ── 8. Firewall — redirect UDP 53 → DNSTT_PORT ───────────────────────────────
if [[ "$ENABLE_REDIRECT" == "true" ]]; then
  step "Firewall: redirecting UDP 53 → ${DNSTT_PORT}"
  IFACE="$(ip route | awk '/default/ {print $5; exit}')"
  IFACE="${IFACE:-eth0}"

  # Clean existing rules to avoid duplicates on re-run
  iptables -D INPUT   -p udp --dport "$DNSTT_PORT" -j ACCEPT            2>/dev/null || true
  iptables -t nat -D PREROUTING -i "$IFACE" -p udp --dport 53 \
           -j REDIRECT --to-ports "$DNSTT_PORT"                          2>/dev/null || true

  iptables -I INPUT   -p udp --dport "$DNSTT_PORT" -j ACCEPT
  iptables -t nat -A PREROUTING -i "$IFACE" -p udp --dport 53 \
           -j REDIRECT --to-ports "$DNSTT_PORT"

  # IPv6
  if command -v ip6tables >/dev/null 2>&1 && [[ -f /proc/net/if_inet6 ]]; then
    ip6tables -D INPUT   -p udp --dport "$DNSTT_PORT" -j ACCEPT         2>/dev/null || true
    ip6tables -t nat -D PREROUTING -i "$IFACE" -p udp --dport 53 \
              -j REDIRECT --to-ports "$DNSTT_PORT"                       2>/dev/null || true
    ip6tables -I INPUT   -p udp --dport "$DNSTT_PORT" -j ACCEPT         2>/dev/null || true
    ip6tables -t nat -A PREROUTING -i "$IFACE" -p udp --dport 53 \
              -j REDIRECT --to-ports "$DNSTT_PORT"                       2>/dev/null || true
  fi

  # Persist
  mkdir -p /etc/iptables
  iptables-save  > /etc/iptables/rules.v4 2>/dev/null || true
  ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
  systemctl reload netfilter-persistent >/dev/null 2>&1 || true
  info "Rules saved"
else
  warn "Skipping iptables redirect. Ensure dnstt-server can bind UDP 53 directly."
fi

# ── 9. Systemd service ────────────────────────────────────────────────────────
step "Creating systemd service: ${SERVICE_NAME}"

# Write env file (easy to edit without touching the unit)
ENV_FILE="${CONFIG_DIR}/server.env"
cat > "$ENV_FILE" <<EOF
# xdnstt server configuration — edit this file and run: systemctl restart dnstt-udp
DNSTT_DOMAIN=${DOMAIN}
DNSTT_LISTEN=${LISTEN_ADDR}:${DNSTT_PORT}
DNSTT_UPSTREAM=${UPSTREAM}
DNSTT_MTU=${MTU}
DNSTT_PRIVKEY=${PRIV}
EOF
chown "root:${SERVICE_USER}" "$ENV_FILE"
chmod 640 "$ENV_FILE"

# Stop existing service quietly before rewriting unit
systemctl stop "$SERVICE_NAME" 2>/dev/null || true

cat > "${SYSTEMD_DIR}/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=xdnstt UDP DNS tunnel server — ${DOMAIN}
Documentation=https://github.com/ThisIsMrAli/xdnstt
After=network-online.target
Wants=network-online.target
# Restart after Dante too if it's installed
After=danted.service
StartLimitIntervalSec=60
StartLimitBurst=30

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
EnvironmentFile=${ENV_FILE}

ExecStart=${DNSTT_SERVER_BIN} \\
    -privkey-file \${DNSTT_PRIVKEY} \\
    -mtu         \${DNSTT_MTU} \\
    \${DNSTT_DOMAIN} \\
    \${DNSTT_LISTEN} \\
    \${DNSTT_UPSTREAM}

# Restart aggressively — if the process dies for any reason, bring it back
# immediately. After 30 crashes within 60s it will slow down to 1/30s pace.
Restart=always
RestartSec=2

# Allow large numbers of concurrent DNS sessions
LimitNOFILE=1048576

# ── Security hardening ─────────────────────────────────────────────────────
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictNamespaces=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
ReadWritePaths=${CONFIG_DIR}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}"
info "Service enabled and started"

# ── 10. Print summary ─────────────────────────────────────────────────────────
SERVER_IP="$(curl -4 -fsSL --max-time 4 https://ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')"

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          xdnstt server installed successfully       ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}Domain:${NC}     ${YELLOW}${DOMAIN}${NC}"
echo -e "  ${BOLD}Server IP:${NC}  ${YELLOW}${SERVER_IP}${NC}"
echo -e "  ${BOLD}UDP port:${NC}   ${YELLOW}${DNSTT_PORT}${NC}  (UDP 53 redirected here)"
echo -e "  ${BOLD}Upstream:${NC}   ${YELLOW}${UPSTREAM}${NC}"
echo -e "  ${BOLD}MTU:${NC}        ${YELLOW}${MTU}${NC}  (client auto-probes from 512 up)"
echo ""
echo -e "  ${CYAN}Public key (copy to every client):${NC}"
echo -e "  ${WHITE}${PUBKEY}${NC}"
echo ""
echo -e "  ${BOLD}DNS records you must add:${NC}"
echo -e "  ${WHITE}  A   ns1.${DOMAIN#*.}  →  ${SERVER_IP}${NC}"
echo -e "  ${WHITE}  NS  ${DOMAIN}          →  ns1.${DOMAIN#*.}${NC}"
echo ""
echo -e "  ${CYAN}Client UDP settings (paste into your client config):${NC}"
echo -e "  ${WHITE}  udp=1.1.1.1:53,8.8.8.8:53${NC}   ← or your preferred resolver"
echo -e "  ${WHITE}  domain=${DOMAIN}${NC}"
echo -e "  ${WHITE}  pubkey=${PUBKEY}${NC}"
echo -e "  ${WHITE}  edns0=512 probeedns0=true cover=true udpsenders=6 jitter=true burst=true${NC}"
echo ""
echo -e "  ${BOLD}Useful commands:${NC}"
echo -e "  ${WHITE}  systemctl status  ${SERVICE_NAME}${NC}"
echo -e "  ${WHITE}  journalctl -u ${SERVICE_NAME} -f${NC}"
echo -e "  ${WHITE}  systemctl restart ${SERVICE_NAME}${NC}"
echo ""
echo -e "  ${BOLD}Update to latest code:${NC}"
echo -e "  ${WHITE}  bash ${BASH_SOURCE[0]} --domain ${DOMAIN} $([ "$ENABLE_DANTE" = true ] && echo "--dante" || echo "--upstream ${UPSTREAM}") --rebuild${NC}"
echo ""
