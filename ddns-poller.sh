#!/usr/bin/env bash
# Pulls the DDNS zone file from the cloud and reloads NSD when it changes.
# Runs on the DNS server LXC (this host) every 60s via systemd timer.
set -euo pipefail

CLOUD_URL="${CLOUD_URL:-https://cloud.mes.net.lb}"
ZONE_FILE="${ZONE_FILE:-/etc/nsd/zones/ddns.mes.net.lb.zone}"
ZONE_NAME="${ZONE_NAME:-ddns.mes.net.lb}"

TMP=$(mktemp)
if ! curl -fsSL --max-time 10 "$CLOUD_URL/ddns/zonefile" -o "$TMP"; then
  rm -f "$TMP"
  exit 0  # silent: cloud may be down briefly
fi

# Validate basic structure (must contain SOA)
if ! grep -q "SOA" "$TMP"; then
  echo "[ddns-poller] zone file missing SOA — refusing to install"
  rm -f "$TMP"
  exit 1
fi

if [[ -f "$ZONE_FILE" ]] && diff -q "$ZONE_FILE" "$TMP" >/dev/null; then
  rm "$TMP"
  exit 0  # no change
fi

install -o nsd -g nsd -m 644 "$TMP" "$ZONE_FILE"
rm -f "$TMP"

# Reload only this zone (no full restart)
nsd-control reload "$ZONE_NAME" 2>&1 || nsd-control reload  # fall back to full reload
echo "[ddns-poller] zone updated, $(grep -c 'IN.A' "$ZONE_FILE") A records"
