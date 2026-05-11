#!/usr/bin/env bash
# Installs the DDNS poller on this DNS LXC. Adds the zone to NSD config.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then echo "Run as root"; exit 1; fi

ZONE_NAME="${ZONE_NAME:-ddns.mes.net.lb}"
ZONE_FILE="/etc/nsd/zones/${ZONE_NAME}.zone"

# 1. Install the poller script
echo "[setup-ddns] installing poller…"
install -m 755 "$(dirname "$0")/ddns-poller.sh" /usr/local/bin/ddns-poller.sh

# 2. Seed the zone file (initial pull will overwrite this)
if [[ ! -f "$ZONE_FILE" ]]; then
  cat > "$ZONE_FILE" <<EOF
\$ORIGIN ${ZONE_NAME}.
\$TTL 60
@	IN	SOA	ns1.mes.net.lb. hostmaster.mes.net.lb. ( $(date +%s) 3600 600 604800 60 )
@	IN	NS	ns1.mes.net.lb.
@	IN	NS	ns2.mes.net.lb.
EOF
  chown nsd:nsd "$ZONE_FILE"
fi

# 3. Add zone to NSD without restart.
#    Two paths:
#      a) If a "default" pattern exists, use `nsd-control addzone` (hot, no restart)
#      b) Otherwise, append to nsd.conf and run `nsd-control reconfig` (hot reload of config)
if ! nsd-control zonestatus "${ZONE_NAME}" 2>/dev/null | grep -q "ok"; then
  # First, ensure a pattern exists (or create one)
  if ! grep -q '^pattern:' /etc/nsd/nsd.conf; then
    cat >> /etc/nsd/nsd.conf <<EOF

pattern:
    name: "default"
EOF
  fi

  # Append the zone definition
  if ! grep -q "name: \"${ZONE_NAME}\"" /etc/nsd/nsd.conf; then
    cat >> /etc/nsd/nsd.conf <<EOF

# DDNS zone — pulled from cloud.mes.net.lb every 60s by ddns-poller
zone:
    name: "${ZONE_NAME}"
    zonefile: "${ZONE_NAME}.zone"
EOF
  fi

  # Hot reconfig — no service restart
  if nsd-control reconfig 2>&1 | grep -q ok; then
    echo "[setup-ddns] zone added via nsd-control reconfig (no restart)"
  else
    echo "[setup-ddns] WARN: nsd-control reconfig failed; zone added to file but not loaded."
    echo "             Run 'nsd-control reconfig' manually when safe."
  fi
fi

# 4. systemd timer
cat > /etc/systemd/system/ddns-poller.service <<'UNIT'
[Unit]
Description=mes Network — pull DDNS zone from cloud
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/ddns-poller.sh
UNIT

cat > /etc/systemd/system/ddns-poller.timer <<'UNIT'
[Unit]
Description=Run DDNS poller every minute

[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
Unit=ddns-poller.service

[Install]
WantedBy=timers.target
UNIT

systemctl daemon-reload
systemctl enable --now ddns-poller.timer

# 5. Run once now
/usr/local/bin/ddns-poller.sh || true

echo "[setup-ddns] done. Cron via systemd. Zone: ${ZONE_NAME}"
echo
echo "Next manual step (Cloudflare, by you):"
echo "  Add NS records on mes.net.lb:"
echo "    ddns NS ns1.mes.net.lb"
echo "    ddns NS ns2.mes.net.lb"
echo
echo "Test: dig +short some-slug.${ZONE_NAME} @ns1.mes.net.lb"
