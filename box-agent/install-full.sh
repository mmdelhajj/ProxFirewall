#!/usr/bin/env bash
# mes Box — full feature install. One script, no flags, idempotent.
# Installs every module + every dependency the agent needs to be Firewalla-feature-complete.
# Called on first boot via systemd service mes-box-firstboot.service.
set -euo pipefail

CLOUD_URL="${MES_CLOUD:-https://cloud.mes.net.lb}"
LOG=/var/log/mes-box-install.log
exec > >(tee -a "$LOG") 2>&1
echo "════════════════════════════════════════════"
echo "   mes Box — Full Feature Install"
echo "   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "════════════════════════════════════════════"

if [[ $EUID -ne 0 ]]; then echo "Run as root"; exit 1; fi

# ──────────────────────────────────────────────────────────────
# Step 1a — CRITICAL packages only (fast path, ~30-45s)
# Customer can pair + use the box once these are in.
# ──────────────────────────────────────────────────────────────
echo "[1a/6] Installing critical packages (fast path)…"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

CRITICAL_PKGS=(
  curl ca-certificates iproute2 conntrack
  iptables nftables
  dnsmasq
  nodejs
)
apt-get install -y -qq "${CRITICAL_PKGS[@]}" 2>&1 | tail -2 || true

# Node 20 if Debian's default is too old
if ! command -v node &>/dev/null || ! node --version 2>/dev/null | grep -qE 'v(1[89]|2[0-9])'; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash - >/dev/null 2>&1 || true
  apt-get install -y -qq nodejs 2>&1 | tail -2 || true
fi
echo "[1a/6] node $(node --version 2>/dev/null || echo missing)"

# ──────────────────────────────────────────────────────────────
# Step 1b — ADVANCED packages (background, not blocking)
# Box is already usable; these unlock DoH, VPN, app-DPI, etc.
# ──────────────────────────────────────────────────────────────
echo "[1b/6] Queueing advanced packages for background install…"
ADVANCED_PKGS=(
  ebtables bridge-utils
  unbound dnscrypt-proxy
  openvpn wireguard wireguard-tools
  tshark tcpdump nmap arping
  chrony miniupnpd
  hostapd wpasupplicant
  speedtest-cli netcat-openbsd dsniff traceroute
)
nohup bash -c "
  apt-get install -y -qq ${ADVANCED_PKGS[*]} > /var/log/mes-box-bg-install.log 2>&1 || true
  echo '[bg-install] done at '\$(date) >> /var/log/mes-box-bg-install.log
" >/dev/null 2>&1 &
disown
echo "[1b/6] Background install PID=$! — log: /var/log/mes-box-bg-install.log"

# Disable services that would conflict with our managed dnsmasq/dnscrypt-proxy/unbound
systemctl disable --now systemd-resolved 2>/dev/null || true
rm -f /etc/resolv.conf
printf "nameserver 1.1.1.1\nnameserver 8.8.8.8\n" > /etc/resolv.conf

# ──────────────────────────────────────────────────────────────
# Step 2 — fetch all agent modules from cloud
# ──────────────────────────────────────────────────────────────
echo "[2/6] Pulling agent modules from $CLOUD_URL…"
mkdir -p /opt/mes-box /etc/mes-box /var/log/mes-box
cd /opt/mes-box
MODULES=(
  agent.js
  sig-engine.js
  sni-parser.js
  openvpn.js
  dns-stack.js
  multi-wan.js
  ntp-intercept.js
  disturb.js
  bridge-mode.js
  upnp.js
  oui-table.json
)
for m in "${MODULES[@]}"; do
  if curl -fsSL -4 "$CLOUD_URL/box/$m" -o "/opt/mes-box/$m"; then
    echo "  ✓ $m ($(wc -c < /opt/mes-box/$m) bytes)"
  else
    echo "  ⚠ $m not available — skipping"
  fi
done
chmod 755 /opt/mes-box/*.js 2>/dev/null || true

# ──────────────────────────────────────────────────────────────
# Step 3 — dnsmasq baseline (LAN-facing DNS server)
# ──────────────────────────────────────────────────────────────
echo "[3/6] Configuring dnsmasq baseline…"
mkdir -p /etc/dnsmasq.d
if [[ ! -f /etc/dnsmasq.d/mes-box.conf ]] || ! grep -q "interface=eth0" /etc/dnsmasq.d/mes-box.conf 2>/dev/null; then
  cat > /etc/dnsmasq.d/mes-box.conf <<'EOF'
interface=eth0
bind-interfaces
domain-needed
bogus-priv
no-resolv
server=1.1.1.1
server=8.8.8.8
cache-size=10000
log-queries=extra
log-facility=/var/log/dnsmasq.log
no-dhcp-interface=eth0
EOF
fi
touch /etc/dnsmasq.d/mes-box-blocks.conf
touch /etc/dnsmasq.d/mes-box-records.conf
touch /var/log/dnsmasq.log

# ──────────────────────────────────────────────────────────────
# Step 4 — systemd unit for the agent
# ──────────────────────────────────────────────────────────────
echo "[4/6] Installing systemd unit…"
cat > /etc/systemd/system/mes-box-agent.service <<UNIT
[Unit]
Description=mes Network — Box Agent
Wants=network-online.target
After=network-online.target dnsmasq.service

[Service]
ExecStart=/usr/bin/node /opt/mes-box/agent.js
Restart=always
RestartSec=10
User=root
Environment=NODE_ENV=production
Environment=MES_CLOUD=${CLOUD_URL}

[Install]
WantedBy=multi-user.target
UNIT

# ──────────────────────────────────────────────────────────────
# Step 5 — logrotate + sysctl tuning
# ──────────────────────────────────────────────────────────────
echo "[5/6] System tuning…"
# Allow IP forwarding (needed for Router/Bridge mode)
cat > /etc/sysctl.d/99-mes-box.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=0
net.netfilter.nf_conntrack_max=131072
EOF
sysctl --system >/dev/null 2>&1 || true

# Raise file-descriptor limit
mkdir -p /etc/systemd/system/mes-box-agent.service.d
cat > /etc/systemd/system/mes-box-agent.service.d/limits.conf <<'EOF'
[Service]
LimitNOFILE=65536
EOF

# ──────────────────────────────────────────────────────────────
# Step 6 — start everything
# ──────────────────────────────────────────────────────────────
echo "[6/6] Starting services…"
systemctl daemon-reload
systemctl enable --now dnsmasq         2>&1 | tail -2 || true
systemctl enable --now mes-box-agent   2>&1 | tail -2 || true
sleep 3

# Disable the firstboot service after success
systemctl disable mes-box-firstboot.service 2>/dev/null || true

echo
echo "════════════════════════════════════════════"
echo "   ✅ Install complete"
echo "════════════════════════════════════════════"
echo "  Agent log:   journalctl -u mes-box-agent -f"
echo "  Pairing:     watch /var/log/mes-box/pairing-code.txt"
echo "  Modules:     ls -la /opt/mes-box/"
echo "════════════════════════════════════════════"
