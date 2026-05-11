#!/usr/bin/env bash
# mes Box quick-install — no flashing needed.
# Works on any Linux box that already has SSH + apt (Pi OS, Ubuntu, Armbian).
#
# Usage:  curl -fsSL https://cloud.mes.net.lb/box/quickinstall.sh | sudo bash
#
# This is the "I already have a Pi running, I just want to make it a mes Box" path.
# For the flash-and-go path, download the .img.xz from /downloads/images/list instead.
set -euo pipefail

CLOUD_URL="${MES_CLOUD:-https://cloud.mes.net.lb}"

if [[ $EUID -ne 0 ]]; then echo "Run as root (sudo)"; exit 1; fi

echo "════════════════════════════════════════════"
echo "   📦 mes Box — Quick Install"
echo "════════════════════════════════════════════"

echo "[1/4] Installing prerequisites…"
apt-get update -qq
if ! command -v node &>/dev/null; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash - >/dev/null 2>&1
fi
apt-get install -y -qq curl iproute2 conntrack dnsmasq nftables iptables ca-certificates nodejs speedtest-cli 2>&1 | tail -3 || true

echo "[2/4] Installing agent + OUI table…"
mkdir -p /opt/mes-box
curl -fsSL "$CLOUD_URL/box/agent.js"        -o /opt/mes-box/agent.js
curl -fsSL "$CLOUD_URL/box/oui-table.json"  -o /opt/mes-box/oui-table.json
chmod 755 /opt/mes-box/agent.js

echo "[3/4] dnsmasq baseline + systemd unit…"
mkdir -p /etc/dnsmasq.d
[[ -f /etc/dnsmasq.d/mes-box.conf ]] || cat >/etc/dnsmasq.d/mes-box.conf <<'DNS'
domain-needed
bogus-priv
no-resolv
server=1.1.1.1
server=8.8.8.8
cache-size=10000
log-queries=no
DNS

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

echo "[4/4] Starting agent — it will self-register in a moment…"
systemctl daemon-reload
systemctl enable --now mes-box-agent.service

# Wait up to 60s for the agent to write the pairing code
for i in {1..60}; do
  if [[ -f /var/log/mes-box/pairing-code.txt ]]; then break; fi
  sleep 1
done

echo
echo "════════════════════════════════════════════"
if [[ -f /var/log/mes-box/pairing-code.txt ]]; then
  cat /var/log/mes-box/pairing-code.txt
else
  echo "Agent is starting; if no code appears within 2 minutes, run:"
  echo "  journalctl -u mes-box-agent -n 50"
fi
echo "════════════════════════════════════════════"
echo
echo "Open ${CLOUD_URL}/pwa/ on your phone, log in, tap '＋ Add' on Home tab,"
echo "and enter the 6-character pairing code above."
