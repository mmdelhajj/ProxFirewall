#!/usr/bin/env bash
# One-shot updater for the mes Network cloud. Run on the VPS (109.110.185.106).
# Pulls latest server.js + pwa/ from the bundle and restarts the container.
#
# Usage (from the VPS, after copying firewalla-bundle.zip into /root):
#   bash deploy-update.sh /root/firewalla-bundle.zip

set -euo pipefail

BUNDLE="${1:-/root/firewalla-bundle.zip}"
APP_DIR="/opt/mock-firewalla-cloud"

if [[ ! -f "$BUNDLE" ]]; then
  echo "❌ Bundle not found: $BUNDLE"
  exit 1
fi

echo "▶ Stopping container..."
cd "$APP_DIR"
docker compose stop || true

echo "▶ Backing up state..."
cp "$APP_DIR/data/state.json" "/var/backups/mes-cloud-pre-update-$(date +%Y%m%d-%H%M%S).json" 2>/dev/null || true

echo "▶ Unpacking new code..."
# Preserve data/ — only overwrite code
TMP=$(mktemp -d)
unzip -q "$BUNDLE" -d "$TMP"
# Use rsync to preserve data/ and node_modules/
if command -v rsync &>/dev/null; then
  rsync -a --exclude='data/' --exclude='node_modules/' "$TMP/" "$APP_DIR/"
else
  for f in $(cd "$TMP" && find . -type f); do
    case "$f" in
      ./data/*|./node_modules/*) continue;;
    esac
    mkdir -p "$APP_DIR/$(dirname "$f")"
    cp "$TMP/$f" "$APP_DIR/$f"
  done
fi
rm -rf "$TMP"

echo "▶ Syncing PWA static files to nginx serving dir…"
if [[ -d "$APP_DIR/pwa" ]]; then
  mkdir -p /var/www/mes-pwa
  cp -f "$APP_DIR/pwa/"* /var/www/mes-pwa/ 2>/dev/null || true
fi

echo "▶ Rebuilding image..."
docker compose build --no-cache

echo "▶ Starting container..."
docker compose up -d

echo "▶ Waiting for health..."
for i in {1..20}; do
  if curl -sk -m 3 https://cloud.mes.net.lb/ >/dev/null 2>&1; then
    echo "✅ Cloud is back up."
    break
  fi
  sleep 1
done

echo
echo "▶ Smoke-test new endpoints:"
echo "   curl -sk https://cloud.mes.net.lb/box/install.sh | head -5"
echo "   curl -sk https://cloud.mes.net.lb/box/agent.js | head -3"
echo "   curl -sk -u admin:PASSWORD https://cloud.mes.net.lb/admin/api/boxes"
echo "   curl -sk -u admin:PASSWORD https://cloud.mes.net.lb/admin/api/categories"
echo
echo "▶ Done."
