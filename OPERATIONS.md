# mes Network — Operations Runbook

This file is for **you** (the ISP operator). It covers everything you'll need to deploy, operate, debug, and grow this system.

---

## 1. Architecture at a glance

```
                 ┌────────────────────────────────────┐
                 │  Customer's phone (PWA)            │
                 │  cloud.mes.net.lb/pwa/             │
                 └─────────────┬──────────────────────┘
                               │ HTTPS + JWT / X-API-Key
                               ▼
              ┌────────────────────────────────────────┐
              │  Cloud (Node + Express)                │
              │  109.110.185.106 :18080 (docker)       │
              │  cloud.mes.net.lb (Cloudflare → nginx) │
              │                                        │
              │  - state.json (single file, JSON)      │
              │  - WireGuard server :51820/udp         │
              │  - daily snapshots → /var/backups      │
              └────┬──────────────────┬────────────────┘
                   │                  │
                   │HMAC-auth + bear  │ HTTP poll for zone file
                   ▼                  ▼
        ┌──────────────────┐   ┌──────────────────────┐
        │  Box agent       │   │  DNS server (NSD)    │
        │  Linux box       │   │  188.93.113.253      │
        │  /opt/mes-box/   │   │  ddns.mes.net.lb     │
        └──────────────────┘   └──────────────────────┘
```

---

## 2. Day-to-day: where to look

| Task | Where |
|---|---|
| See what customers are doing | `https://cloud.mes.net.lb/admin` (admin / pwd in `/root/.mes-cloud-admin-pwd`) |
| See pending things needing action | Admin dashboard → "Pending — needs your action" panel |
| Edit code locally | `/root/mock-firewalla-cloud/` on this LXC |
| See box logs (if you have a real Pi) | `journalctl -u mes-box-agent -f` (on the Pi) |
| Deploy code changes | `bash deploy-update.sh` — see §3 |
| See live request stream | Admin dashboard → bottom |
| Public health page | `https://cloud.mes.net.lb/status` |

---

## 3. Deploying changes

### Standard flow (any code edit)

```bash
# On this LXC (where you edit code):
cd /root/mock-firewalla-cloud
node -c server.js                 # syntax check
rm /root/firewalla-bundle.zip
zip -qr /root/firewalla-bundle.zip . -x 'node_modules/*' 'data/*' '.git/*'

# Upload + deploy on the VPS:
SSHPASS='${SSH_PASSWORD}' sshpass -e scp -o PreferredAuthentications=password -o PubkeyAuthentication=no \
  /root/firewalla-bundle.zip root@109.110.185.106:/root/

SSHPASS='${SSH_PASSWORD}' sshpass -e ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no \
  root@109.110.185.106 'bash /tmp/deploy-update.sh /root/firewalla-bundle.zip'
```

The deploy script:
1. Stops the docker container
2. Backs up `state.json` to `/var/backups/mes-cloud-pre-update-<ts>.json`
3. Unpacks new code (preserves `data/` and `node_modules/`)
4. Rebuilds image
5. Starts container
6. Waits for `cloud.mes.net.lb` to come back

Total: ~30-60 seconds downtime.

### If a deploy fails

```bash
# On VPS:
docker compose logs -f mock-firewalla-cloud  # see what crashed
# If state corrupted, restore from backup:
cp /var/backups/mes-cloud-pre-update-<ts>.json /opt/mock-firewalla-cloud/data/state.json
docker compose restart
```

---

## 4. Customer onboarding (the steady-state flow)

### A. Customer signs up themselves

1. Customer goes to `https://cloud.mes.net.lb/pwa/`
2. Clicks "New customer? Sign up"
3. Enters phone, gets OTP `0000` (until you wire SMS)
4. Lands in PWA, sees onboarding wizard
5. Either: (a) flashes their own Pi, or (b) orders a pre-flashed box from Settings

### B. You invite a customer

```bash
# Pre-register them — returns a WhatsApp deep-link
curl -u admin:$(cat /root/.mes-cloud-admin-pwd) \
  -H 'Content-Type: application/json' \
  -d '{"name":"Ahmad","phone":"+961 70 555 1234","email":"a@x.com","plan":"family"}' \
  https://cloud.mes.net.lb/admin/api/customers/invite

# Response includes whatsapp_url — open it in browser, click "Send", customer gets the invite link
```

### C. Hardware shipping flow

When a customer orders a box (Settings → "Order a pre-flashed box"):

1. Order appears in Admin dashboard "Pending" panel
2. You flash a Pi 4 with `mes-box-pi4-YYYYMMDD.img.xz`
3. Boot it once — it generates a pairing code
4. Write the code on a sticker on the box
5. Update order status: received → prepping → shipping → delivered
6. Customer in PWA enters the code → claims the box

To update status:
```bash
curl -u admin:PASS -H 'Content-Type: application/json' \
  -d '{"id":"hwo-XXX","status":"shipping","note":"DHL tracking ABC123"}' \
  https://cloud.mes.net.lb/admin/api/hw-orders/update-status
```

---

## 5. Common debugging

### "A customer says their box is offline"

1. Admin → Box Fleet table — is it shown as offline? Check `last_heartbeat`.
2. If offline > 10 min, customer should be receiving an `outage` alarm automatically.
3. Tail box logs from cloud:
   ```bash
   curl -u admin:PASS -X POST -H 'Content-Type: application/json' \
     -d '{"lines":200}' \
     https://cloud.mes.net.lb/admin/api/box/<MAC>/tail-logs
   ```
4. If box online but customer says "no internet": check their LAN, not your problem.

### "Cloud is slow / 503s"

1. nginx rate limit may be hitting. Check: `grep limit_req /var/log/nginx/error.log` on VPS.
2. Container OOM? `docker stats mock-firewalla-cloud`.
3. Restart: `docker compose restart` (lose 30s of in-flight requests, no data loss).

### "PWA looks broken"

1. Hard refresh: Ctrl+Shift+R.
2. Open browser console → look for SyntaxError or 404s.
3. Check service worker: chrome://serviceworker-internals → unregister `cloud.mes.net.lb`.

### "WireGuard customer can't connect"

1. Check VPS: `wg show wg0` — is the service running?
2. Force a sync: `bash /usr/local/bin/wg-sync.sh` on VPS.
3. UFW allowing 51820/udp? `ufw status | grep 51820`.

### "DDNS is not resolving externally"

You need to add NS records on Cloudflare:
```
ddns  NS  ns1.mes.net.lb
ddns  NS  ns2.mes.net.lb
```
Without those, only direct queries to `188.93.113.253` work.

---

## 6. Backup & restore

### Daily auto-backups
The cloud writes a backup to `/var/backups/mes-cloud-YYYY-MM-DD.json` daily, retained 14 days.

### Manual snapshots (admin)
```bash
# Create
curl -u admin:PASS -X POST -H 'Content-Type: application/json' \
  -d '{"name":"before-big-change","notes":"about to change rate limits"}' \
  https://cloud.mes.net.lb/admin/api/snapshots/create

# List
curl -u admin:PASS https://cloud.mes.net.lb/admin/api/snapshots

# Restore
curl -u admin:PASS -X POST -H 'Content-Type: application/json' \
  -d '{"name":"before-big-change"}' \
  https://cloud.mes.net.lb/admin/api/snapshots/restore
```

Restore creates a `pre-restore-<ts>` safety snapshot first, so you can roll back the rollback.

### Off-site backups (recommended)
Add to crontab on the VPS:
```cron
0 3 * * * tar czf - /opt/mock-firewalla-cloud/data /var/backups | ssh -p 22 backup@your-other-server 'cat > backups/mes-cloud-$(date +\%F).tar.gz'
```

---

## 7. Things that need your manual action

| Task | When | How |
|---|---|---|
| Cloudflare NS records for ddns.mes.net.lb | Once | Cloudflare → mes.net.lb → DNS → add NS records |
| LBP/USD rate refresh | Auto, but check weekly | `curl -u admin:PASS -X POST .../admin/api/lbp-rate/refresh` |
| Threat-feed refresh | Auto daily | `curl -u admin:PASS -X POST .../admin/api/threat-feed/refresh` |
| Rotate admin password | Before going live | Edit `ADMIN_PASSWORD` env in `/opt/mock-firewalla-cloud/docker-compose.yml`, `docker compose up -d` |
| Replace OTP=0000 with real SMS | Before going live | Wire Twilio or your SMS gateway in `server.js`'s `/api/customer/login` |
| SSH key login on VPS | Before going live | `ssh-copy-id root@109.110.185.106` then disable PasswordAuth in sshd_config |
| Cloudflare → Full (strict) | Anytime | CF → SSL/TLS → set to "Full (strict)". Origin already has Let's Encrypt cert. |

---

## 8. Plan changes

Direct admin edit:
```bash
curl -u admin:PASS -X POST -H 'Content-Type: application/json' \
  -d '{"id":"cust-XXX","plan":"pro"}' \
  https://cloud.mes.net.lb/admin/api/customers/update
```

Customer-initiated:
- They request via PWA → Settings → "Change my plan"
- Admin sees in dashboard "Pending" panel → click Approve/Decline
- All changes recorded in `subscription_history`

---

## 9. Security notes

- Customer JWTs expire in 30 days
- Box session tokens expire in 7 days
- Admin sessions are HTTP Basic — credentials sent on every request (fine over HTTPS)
- Box-cloud HMAC uses SHA-256 with per-MAC secret derived from `state.config.box_secret_root`
- **Never delete `state.config.box_secret_root`** — it would invalidate all installed boxes
- Backups contain the Ed25519 license keypair — protect them
- Customer API keys: scope `read` is GET-only; scope `full` is full

---

## 10. Hardware shipping checklist (per Pi 4)

1. Flash latest `mes-box-pi4-*.img.xz` from `https://cloud.mes.net.lb/downloads/images/list`
2. Boot the Pi once (15 min — first-boot installs deps)
3. SSH in (`pi`/`raspberry`), run `cat /var/log/mes-box/pairing-code.txt`
4. Print/sticker the 6-char code on the bottom of the case
5. Reboot the Pi cleanly: `sudo reboot`
6. Pack with: Pi, microSD card, power supply, ethernet cable, brief sheet with pairing code
7. Update order status to "shipping"
8. After delivery, customer claims via PWA → "+ Add" with the code

Bulk: flash 10 SD cards at once with `dd` parallelism, boot each through a USB hub, collect 10 codes, label, pack.

---

## 11. Pricing math (Lebanon 2026)

Cost: NanoPi R6S retail ~$232 single, ~$180 in bulk-100 with custom case + branding.
At $10/mo Family plan, payback per box: ~18 months retail, ~10 months bulk-OEM.
After that, pure margin minus cloud hosting (~$30/mo for the VPS).

You break even on hardware around customer #5. The cloud is fixed cost — it can serve 5,000 boxes for the same $30/mo.

---

## 12. Quick sanity-check after any deploy

```bash
PWD=$(cat /root/.mes-cloud-admin-pwd)
T=$(date +%s)

# Public surfaces
curl -sk -o /dev/null -w 'landing: %{http_code}\n' "https://cloud.mes.net.lb/?t=$T"
curl -sk -o /dev/null -w 'pwa: %{http_code}\n'     "https://cloud.mes.net.lb/pwa/?t=$T"
curl -sk -o /dev/null -w 'status: %{http_code}\n'  "https://cloud.mes.net.lb/status?t=$T"

# Admin
curl -sk -u admin:$PWD "https://cloud.mes.net.lb/admin/api/state" | head -c 100
echo

# Customer
curl -sk -o /dev/null -w 'customer api docs: %{http_code}\n' "https://cloud.mes.net.lb/api/openapi.json?t=$T"
curl -sk -o /dev/null -w 'box install: %{http_code}\n'       "https://cloud.mes.net.lb/box/install.sh?t=$T"
curl -sk -o /dev/null -w 'image list: %{http_code}\n'        "https://cloud.mes.net.lb/downloads/images/list?t=$T"
```

All should return `200`. If any return `404` or `503`, something is wrong.

---

## 13. Where help lives

- This file: `OPERATIONS.md`
- API spec: `https://cloud.mes.net.lb/api/openapi.json`
- Source: `/root/mock-firewalla-cloud/` on this LXC
- Cloud logs: `docker compose logs -f mock-firewalla-cloud` on the VPS
- nginx logs: `/var/log/nginx/mes-cloud-access.log` and `error.log` on the VPS
- Memory file: `/root/.claude/projects/-root/memory/mes_cloud_vps.md`
