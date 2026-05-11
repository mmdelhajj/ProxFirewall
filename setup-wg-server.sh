#!/usr/bin/env bash
# One-shot: install WireGuard on the VPS host and wire it to /opt/mock-firewalla-cloud/data/state.json
set -euo pipefail

if [[ $EUID -ne 0 ]]; then echo "Run as root"; exit 1; fi

echo "[setup-wg] installing wireguard…"
apt-get update -qq
apt-get install -y -qq wireguard wireguard-tools python3 iptables

echo "[setup-wg] enabling IP forwarding…"
if ! grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf 2>/dev/null; then
  echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
fi
sysctl -w net.ipv4.ip_forward=1

echo "[setup-wg] opening UFW 51820/udp…"
if command -v ufw &>/dev/null; then
  ufw allow 51820/udp || true
fi

echo "[setup-wg] installing wg-sync.sh + systemd timer…"
install -m 755 /opt/mock-firewalla-cloud/wg-sync.sh /usr/local/bin/wg-sync.sh

cat > /etc/systemd/system/wg-sync.service <<'UNIT'
[Unit]
Description=mes Network — sync WireGuard config from cloud state
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/wg-sync.sh
UNIT

cat > /etc/systemd/system/wg-sync.timer <<'UNIT'
[Unit]
Description=Run wg-sync every minute

[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
Unit=wg-sync.service

[Install]
WantedBy=timers.target
UNIT

systemctl daemon-reload
systemctl enable --now wg-sync.timer

echo "[setup-wg] running wg-sync once now…"
/usr/local/bin/wg-sync.sh || true

echo "[setup-wg] done. Status:"
systemctl --no-pager status wg-quick@wg0 2>/dev/null | head -5 || true
wg show 2>/dev/null || true
