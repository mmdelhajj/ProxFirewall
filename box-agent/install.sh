#!/usr/bin/env bash
# mes Box agent installer — runs on the customer device (Linux).
# Usage:  curl -sSL https://cloud.mes.net.lb/box/install.sh | sudo bash -s -- --mac <MAC> --secret <SECRET>

set -euo pipefail

CLOUD_URL="${CLOUD_URL:-https://cloud.mes.net.lb}"
BOX_MAC=""
BOX_SECRET=""
LAN_IF="${LAN_IF:-eth0}"
INSECURE_TLS="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mac)      BOX_MAC="$2"; shift 2;;
    --secret)   BOX_SECRET="$2"; shift 2;;
    --cloud)    CLOUD_URL="$2"; shift 2;;
    --iface)    LAN_IF="$2"; shift 2;;
    --insecure) INSECURE_TLS="true"; shift;;
    *) echo "unknown arg: $1"; exit 1;;
  esac
done

if [[ -z "$BOX_MAC" || -z "$BOX_SECRET" ]]; then
  echo "Usage: $0 --mac <MAC> --secret <SECRET> [--cloud URL] [--iface eth0] [--insecure]"
  echo
  echo "Get the secret from the cloud admin:"
  echo "  curl -u admin:PASS $CLOUD_URL/admin/api/box/secret/<MAC>"
  exit 2
fi

if [[ $EUID -ne 0 ]]; then echo "Run as root"; exit 1; fi

echo "[install] Installing prerequisites…"
if command -v apt-get &>/dev/null; then
  apt-get update -qq
  apt-get install -y -qq curl iproute2 conntrack dnsmasq nodejs ca-certificates speedtest-cli iptables nftables hostapd wpasupplicant netcat-openbsd
fi

echo "[install] Creating /etc/mes-box config…"
mkdir -p /etc/mes-box
cat >/etc/mes-box/agent.json <<JSON
{
  "box_mac":   "${BOX_MAC,,}",
  "box_secret": "$BOX_SECRET",
  "cloud_url": "$CLOUD_URL",
  "lan_iface": "$LAN_IF",
  "insecure_tls": $INSECURE_TLS
}
JSON
chmod 600 /etc/mes-box/agent.json

echo "[install] Installing agent.js → /opt/mes-box/agent.js…"
mkdir -p /opt/mes-box
if [[ -f "$(dirname "$0")/agent.js" ]]; then
  cp "$(dirname "$0")/agent.js" /opt/mes-box/agent.js
else
  curl -fsSL "$CLOUD_URL/box/agent.js" -o /opt/mes-box/agent.js
fi
chmod 755 /opt/mes-box/agent.js

echo "[install] Downloading OUI table (~1MB)…"
curl -fsSL "$CLOUD_URL/box/oui-table.json" -o /opt/mes-box/oui-table.json 2>/dev/null || \
  echo "[install] (OUI table not available, agent will use built-in fallback)"

echo "[install] Configuring dnsmasq baseline…"
mkdir -p /etc/dnsmasq.d
if [[ ! -f /etc/dnsmasq.d/mes-box.conf ]]; then
  cat >/etc/dnsmasq.d/mes-box.conf <<'DNS'
# mes Box — DHCP + DNS server (managed by mes-box agent)
domain-needed
bogus-priv
no-resolv
server=1.1.1.1
server=8.8.8.8
cache-size=10000
log-queries=no
DNS
fi
touch /etc/dnsmasq.d/mes-box-blocks.conf

echo "[install] Installing systemd unit…"
cat >/etc/systemd/system/mes-box-agent.service <<'UNIT'
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

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable mes-box-agent.service
systemctl restart mes-box-agent.service
sleep 2
systemctl --no-pager status mes-box-agent.service | head -20

echo
echo "[install] ✅ Done. Watch logs:   journalctl -u mes-box-agent -f"
echo "[install] Box MAC: ${BOX_MAC,,}"
echo "[install] Cloud:   $CLOUD_URL"
