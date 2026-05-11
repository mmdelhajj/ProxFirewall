#!/usr/bin/env bash
# ============================================================
#  Fake Firewalla App — simulates the mobile app's pairing flow
# ============================================================
#
# Usage:
#   ./fake-app.sh <CLOUD_URL> <RENDEZVOUS_ID>
#
# Example:
#   ./fake-app.sh http://127.0.0.1:18080 9f571ca6-045f-4575-a45d-22eb1af4fd6e
#
# Get the rendezvous ID from your box's FireKick log:
#   sudo grep -oE 'Inviting [a-f0-9-]{36}' /log/firewalla/FireKick.log | tail -1

set -euo pipefail

CLOUD="${1:-http://127.0.0.1:18080}"
RID="${2:?Usage: $0 <CLOUD_URL> <RID>}"

# Re-use a stable keypair so pairing is repeatable
KEYDIR="${HOME}/.fake-app-keys"
mkdir -p "$KEYDIR"
PRIV="$KEYDIR/app.key"
PUB="$KEYDIR/app.pub"
if [ ! -f "$PRIV" ]; then
  echo "Generating fake-app RSA keypair (one-time)…"
  openssl genrsa -out "$PRIV" 2048 2>/dev/null
  openssl rsa -in "$PRIV" -pubout -out "$PUB" 2>/dev/null
fi
APP_PUBKEY=$(cat "$PUB" | sed ':a;N;$!ba;s/\n/\\n/g')

echo "═══════════════════════════════════════════════════════════════"
echo "  Fake Firewalla App"
echo "  Cloud:      $CLOUD"
echo "  Rendezvous: $RID"
echo "═══════════════════════════════════════════════════════════════"

# Step 1 — App eptLogin against mock cloud (with real RSA pubkey)
echo
echo "→ Step 1: App eptLogin (real RSA-2048 keypair)"
LOGIN=$(curl -sS -X POST "$CLOUD/iot/api/v2/login/eptoken" \
  -H "Content-Type: application/json" \
  -d "{
    \"assertion\": {
      \"name\": \"fake-app-user\",
      \"publicKey\": \"$APP_PUBKEY\",
      \"appId\": \"com.test.fakeapp\",
      \"appSecret\": \"test-secret\"
    }
  }")
APP_EID=$(echo "$LOGIN" | grep -oE '"eid":"[^"]+"' | head -1 | cut -d'"' -f4)
echo "  → app eid: $APP_EID"

# Step 2 — POST invite to rendezvous in box-expected schema
echo
echo "→ Step 2: Post invite to rendezvous (schema {value, evalue})"
INVITE_RES=$(curl -sS -X POST "$CLOUD/iot/api/v2/ept/rendezvous/$RID/invite" \
  -H "Content-Type: application/json" \
  -d "{
    \"value\": \"$APP_EID\",
    \"evalue\": \"{\\\"license\\\":\\\"\\\",\\\"name\\\":\\\"FakeApp\\\"}\"
  }")
echo "  → $INVITE_RES"

# Step 3 — Show stored payload
echo
echo "→ Step 3: Verify rendezvous now holds app payload"
curl -sS "$CLOUD/iot/api/v2/ept/rendezvous/$RID" | head -c 300; echo

echo
echo "═══════════════════════════════════════════════════════════════"
echo "  ✓ Fake-app posted invite. Box's next poll picks it up."
echo "    Wait ~5s, then on the box:"
echo "      sudo redis-cli hget sys:ept group_member_cnt"
echo "    Should be 2."
echo "═══════════════════════════════════════════════════════════════"
