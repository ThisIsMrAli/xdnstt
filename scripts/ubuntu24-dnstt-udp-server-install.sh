#!/usr/bin/env bash
#
# Ubuntu 24.04 production installer for dnstt UDP server (authoritative NS).
# - Installs/updates dnstt-server binary
# - Generates/loads Noise keypair
# - Optional local SOCKS upstream via Dante (recommended for "VPN-like" usage)
# - Creates a hardened systemd service with auto-restart
# - Opens UDP 53 and redirects it to a high port (default 5300) to avoid CAP_NET_BIND_SERVICE
#
# Usage:
#   sudo ./ubuntu24-dnstt-udp-server-install.sh --domain t.example.com --upstream 127.0.0.1:1080
#
# Notes:
# - You must configure NS + A records so this server is authoritative for --domain.
# - This script is UDP-only by design (Iran-style filtering environments).
#
set -euo pipefail

DNSTT_PORT="${DNSTT_PORT:-5300}"        # local UDP listen port (redirected from 53)
LISTEN_ADDR="${LISTEN_ADDR:-0.0.0.0}"   # bind for dnstt-server
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/dnstt}"
SYSTEMD_UNIT_DIR="${SYSTEMD_UNIT_DIR:-/etc/systemd/system}"
SERVICE_USER="${SERVICE_USER:-dnstt}"
SERVICE_GROUP="${SERVICE_GROUP:-dnstt}"
SERVICE_NAME="${SERVICE_NAME:-dnstt-udp}"
MTU_VALUE_DEFAULT="${MTU_VALUE_DEFAULT:-1232}" # server max UDP payload; client starts at 512 and probes upward

# If you host your own binaries, set these.
RELEASE_BASE_URL="${RELEASE_BASE_URL:-}"
DNSTT_SERVER_BIN="${DNSTT_SERVER_BIN:-${INSTALL_DIR}/dnstt-server}"

print() { printf '%s\n' "$*"; }
die() { print "ERROR: $*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Ubuntu 24.04 dnstt UDP server installer.

Required:
  --domain <t.example.com>          Tunnel domain (zone root)
  --upstream <ip:port>              TCP upstream where streams are forwarded
                                   (use 127.0.0.1:1080 if you enable --dante)

Optional:
  --mtu <n>                          Server max UDP payload (default 1232)
  --listen <ip>                      Bind address (default 0.0.0.0)
  --port <n>                         Local UDP port for dnstt-server (default 5300; UDP 53 is redirected to it)
  --dante                            Install and configure local Dante SOCKS on 127.0.0.1:1080
  --no-redirect                      Do NOT add iptables redirect (you must then bind directly to UDP 53 manually)
  --download-url <baseURL>           Download prebuilt binaries from baseURL
                                     Example:
                                       --download-url https://example.com/releases

Examples:
  sudo ./ubuntu24-dnstt-udp-server-install.sh --domain t.example.com --dante --upstream 127.0.0.1:1080
  sudo ./ubuntu24-dnstt-udp-server-install.sh --domain t.example.com --upstream 127.0.0.1:8000 --mtu 1232

After install:
  systemctl status dnstt-udp
  journalctl -u dnstt-udp -f

Client UDP (recommended defaults in this repo):
  udp=<your-recursive-resolver-ip:53,backup:53>
  domains=<t.example.com,alt.t.example.com>   (optional)
  edns0=512 probeedns0=true cover=true udpsenders=6 jitter=true burst=true

EOF
}

DOMAIN=""
UPSTREAM=""
MTU_VALUE="$MTU_VALUE_DEFAULT"
ENABLE_DANTE=false
ENABLE_REDIRECT=true

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN="${2:-}"; shift 2 ;;
    --upstream) UPSTREAM="${2:-}"; shift 2 ;;
    --mtu) MTU_VALUE="${2:-}"; shift 2 ;;
    --listen) LISTEN_ADDR="${2:-}"; shift 2 ;;
    --port) DNSTT_PORT="${2:-}"; shift 2 ;;
    --dante) ENABLE_DANTE=true; shift ;;
    --no-redirect) ENABLE_REDIRECT=false; shift ;;
    --download-url) RELEASE_BASE_URL="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown argument: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "Run as root."
[[ -n "$DOMAIN" ]] || die "--domain is required."
[[ -n "$UPSTREAM" ]] || die "--upstream is required."

mkdir -p "$CONFIG_DIR"

detect_arch() {
  local m
  m="$(uname -m)"
  case "$m" in
    x86_64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    armv7l|armv6l) echo "arm" ;;
    i386|i686) echo "386" ;;
    *) die "Unsupported architecture: $m" ;;
  esac
}

install_deps() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq curl ca-certificates iptables iptables-persistent >/dev/null || true
  systemctl enable netfilter-persistent >/dev/null 2>&1 || true
}

create_user() {
  if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    useradd -r -s /usr/sbin/nologin -d /nonexistent -c "dnstt service user" "$SERVICE_USER"
  fi
  groupadd -f "$SERVICE_GROUP" >/dev/null 2>&1 || true
  chown -R "$SERVICE_USER:$SERVICE_GROUP" "$CONFIG_DIR"
  chmod 750 "$CONFIG_DIR"
}

download_dnstt_server() {
  local arch
  arch="$(detect_arch)"
  local filename="dnstt-server-linux-${arch}"

  [[ -n "$RELEASE_BASE_URL" ]] || die "No --download-url provided. Either set it, or copy dnstt-server to ${DNSTT_SERVER_BIN} manually."

  print "Downloading ${filename} from ${RELEASE_BASE_URL}"
  curl -fsSL -o "/tmp/${filename}" "${RELEASE_BASE_URL}/${filename}"
  install -m 0755 "/tmp/${filename}" "$DNSTT_SERVER_BIN"
  rm -f "/tmp/${filename}"
}

ensure_dnstt_server() {
  if [[ -x "$DNSTT_SERVER_BIN" ]]; then
    return
  fi
  download_dnstt_server
}

gen_keys() {
  local priv="${CONFIG_DIR}/server.key"
  local pub="${CONFIG_DIR}/server.pub"
  if [[ -s "$priv" && -s "$pub" ]]; then
    return
  fi
  print "Generating keypair under ${CONFIG_DIR}"
  "$DNSTT_SERVER_BIN" -gen-key -privkey-file "$priv" -pubkey-file "$pub"
  chown "$SERVICE_USER:$SERVICE_GROUP" "$priv" "$pub"
  chmod 600 "$priv"
  chmod 644 "$pub"
}

setup_dante() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y -qq dante-server >/dev/null
  local iface
  iface="$(ip route | awk '/default/ {print $5; exit}')"
  iface="${iface:-eth0}"
  cat > /etc/danted.conf <<EOF
logoutput: syslog
user.privileged: root
user.unprivileged: nobody

internal: 127.0.0.1 port = 1080
external: ${iface}

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
socks block {
    from: 0.0.0.0/0 to: ::/0
    log: error
}
client block {
    from: 0.0.0.0/0 to: ::/0
    log: error
}
EOF

  systemctl enable --now danted >/dev/null
}

configure_firewall_redirect() {
  # UDP 53 -> DNSTT_PORT redirect (nft backend is OK via iptables wrapper on Ubuntu 24).
  local iface
  iface="$(ip route | awk '/default/ {print $5; exit}')"
  iface="${iface:-eth0}"

  # Allow incoming DNS.
  iptables -D INPUT -p udp --dport "$DNSTT_PORT" -j ACCEPT 2>/dev/null || true
  iptables -I INPUT -p udp --dport "$DNSTT_PORT" -j ACCEPT

  # Redirect incoming UDP/53 to the high port.
  iptables -t nat -D PREROUTING -i "$iface" -p udp --dport 53 -j REDIRECT --to-ports "$DNSTT_PORT" 2>/dev/null || true
  iptables -t nat -A PREROUTING -i "$iface" -p udp --dport 53 -j REDIRECT --to-ports "$DNSTT_PORT"

  # Persist rules.
  mkdir -p /etc/iptables
  iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
  systemctl reload netfilter-persistent >/dev/null 2>&1 || true
}

write_config() {
  local conf="${CONFIG_DIR}/server.env"
  cat > "$conf" <<EOF
DOMAIN=${DOMAIN}
LISTEN=${LISTEN_ADDR}:${DNSTT_PORT}
UPSTREAM=${UPSTREAM}
MTU=${MTU_VALUE}
PRIVKEY_FILE=${CONFIG_DIR}/server.key
EOF
  chown root:"$SERVICE_GROUP" "$conf"
  chmod 640 "$conf"
}

write_systemd_unit() {
  local unit="${SYSTEMD_UNIT_DIR}/${SERVICE_NAME}.service"
  cat > "$unit" <<EOF
[Unit]
Description=dnstt UDP DNS tunnel server (authoritative)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
EnvironmentFile=${CONFIG_DIR}/server.env
ExecStart=${DNSTT_SERVER_BIN} -privkey-file \${PRIVKEY_FILE} -mtu \${MTU} \${DOMAIN} \${LISTEN} \${UPSTREAM}
Restart=always
RestartSec=2
StartLimitIntervalSec=60
StartLimitBurst=30

# Hardening
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

LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now "${SERVICE_NAME}" >/dev/null
}

install_deps
create_user
ensure_dnstt_server
gen_keys
write_config

if [[ "$ENABLE_DANTE" == "true" ]]; then
  setup_dante
fi

if [[ "$ENABLE_REDIRECT" == "true" ]]; then
  configure_firewall_redirect
else
  print "Skipping iptables redirect (you must bind directly to UDP 53 yourself)."
fi

write_systemd_unit

print ""
print "Installed and started: ${SERVICE_NAME}"
print "  status:  systemctl status ${SERVICE_NAME}"
print "  logs:    journalctl -u ${SERVICE_NAME} -f"
print ""
print "Public key (copy to client):"
cat "${CONFIG_DIR}/server.pub"
print ""
print "Client UDP recommended args (match current repo hardening):"
print "  udp=<resolver1:53,resolver2:53> domains=<${DOMAIN},alt.${DOMAIN#*.}> edns0=512 probeedns0=true cover=true udpsenders=6 jitter=true burst=true"

