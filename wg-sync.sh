#!/usr/bin/env bash
# Regenerates /etc/wireguard/wg0.conf from /opt/mock-firewalla-cloud/data/state.json
# and reloads the running wg-quick service. Idempotent. Runs on the VPS host.
set -euo pipefail

STATE="${STATE:-/opt/mock-firewalla-cloud/data/state.json}"
WG_CONF="${WG_CONF:-/etc/wireguard/wg0.conf}"
LISTEN_PORT="${LISTEN_PORT:-51820}"
SUBNET="${SUBNET:-10.99.0.0/24}"
SERVER_ADDR="${SERVER_ADDR:-10.99.0.1/24}"

if [[ ! -f "$STATE" ]]; then
  echo "[wg-sync] no state file at $STATE — nothing to do"
  exit 0
fi

# Extract server keys + peers via python (Node may not be in PATH outside container)
read -r SRV_PRIV SRV_PUB << EOF
$(python3 - <<PYEOF
import json, sys
s = json.load(open("$STATE"))
srv = s.get("wg_server") or {}
print(srv.get("privkey", ""), srv.get("pubkey", ""))
PYEOF
)
EOF

if [[ -z "$SRV_PRIV" || -z "$SRV_PUB" ]]; then
  echo "[wg-sync] no wg_server in state — cloud hasn't initialised yet"
  exit 0
fi

# Build the config
TMP=$(mktemp)
cat > "$TMP" <<INTERFACE
# mes Network — auto-generated. Do not edit by hand.
[Interface]
PrivateKey = $SRV_PRIV
Address = $SERVER_ADDR
ListenPort = $LISTEN_PORT
SaveConfig = false

# NAT traffic from VPN clients out via the public interface
PostUp = iptables -t nat -A POSTROUTING -s $SUBNET -o eth0 -j MASQUERADE; iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -s $SUBNET -o eth0 -j MASQUERADE; iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT

INTERFACE

python3 - <<PYEOF >> "$TMP"
import json
s = json.load(open("$STATE"))
peers = s.get("wg_peers") or {}
for p in peers.values():
    pub  = p.get("pubkey")
    addr = p.get("address")  # e.g. "10.99.0.2/32"
    if not pub or not addr: continue
    print(f"# {p.get('device_label','peer')} (cust={p.get('customer_id','')})")
    print("[Peer]")
    print(f"PublicKey = {pub}")
    print(f"AllowedIPs = {addr}")
    print()
PYEOF

# Only swap + reload if content changed (avoid needless restarts dropping clients)
if [[ -f "$WG_CONF" ]] && diff -q "$WG_CONF" "$TMP" >/dev/null; then
  echo "[wg-sync] no changes"
  rm "$TMP"
  exit 0
fi

install -m 600 "$TMP" "$WG_CONF"
rm "$TMP"

# (Re)start the interface
if systemctl is-active --quiet wg-quick@wg0; then
  echo "[wg-sync] applying changes via wg syncconf"
  wg syncconf wg0 <(wg-quick strip wg0)
else
  echo "[wg-sync] starting wg-quick@wg0"
  systemctl enable --now wg-quick@wg0
fi

echo "[wg-sync] done. Peers: $(grep -c '^\[Peer\]' "$WG_CONF" || echo 0)"
