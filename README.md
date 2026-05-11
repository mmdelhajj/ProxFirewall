# Mock Firewalla Cloud

A drop-in stand-in for `firewalla.encipher.io`. Lets you complete the Firewalla pairing flow against your own backend instead of Firewalla's. Useful for:

- **Learning** — watch every protocol step happen in your terminal
- **Building a clone** — develop your own box-side daemon without touching Firewalla's cloud
- **Testing** — deterministic, in-memory backend for integration tests

> ⚠ This mock does **NOT** make the real Firewalla mobile app work — that app talks to the real `firewalla.encipher.io` directly. Use this together with a Firewalla *box* (or your own custom box-side code) plus the included `fake-app.sh` curl-based "app".

---

## What it implements

| Endpoint | Purpose |
|---|---|
| `POST /iot/api/v2/login/eptoken` | Box authenticates, gets eid + token |
| `POST /iot/api/v2/group/:appId` | Box creates a pairing group |
| `GET  /iot/api/v2/ept/:eid/groups` | List groups for an endpoint |
| `POST /iot/api/v2/ept/rendezvous/:rid` | Box stores pairing invitation |
| `GET  /iot/api/v2/ept/rendezvous/:rid` | Box / app polls the invitation |
| `POST /iot/api/v2/ept/rendezvous/:rid/invite` | App posts its acceptance |
| `POST /iot/api/v2/group/:gid/:eid` | Add member to group |
| `POST /iot/api/v2/service/message/...` | Encrypted message relay (POST) |
| `GET  /iot/api/v2/service/message/...` | Encrypted message relay (GET) |
| `POST /bone/api/v3/sys/checkin` | Box telemetry / heartbeat |
| `GET  /license/api/v1/license/issue/:luid` | Issue a (mock) license blob |
| `GET  /` | Status / health |

State is in-memory (groups, rendezvous, endpoints, messages, licenses, checkins). Restart wipes everything — perfect for testing.

---

## How to run

### Option A — Docker (recommended)

```bash
docker compose up -d
docker compose logs -f       # watch the requests as they come in
```

To stop:
```bash
docker compose down
```

### Option B — Plain Node.js

```bash
npm install
node server.js
# logs print to stdout
```

Server listens on `0.0.0.0:8080` by default. Override with `PORT` and `HOST`:

```bash
PORT=9000 HOST=127.0.0.1 node server.js
```

### Option C — As a systemd service (Linux)

```ini
# /etc/systemd/system/mock-firewalla-cloud.service
[Unit]
Description=Mock Firewalla Cloud
After=network.target

[Service]
WorkingDirectory=/opt/mock-firewalla-cloud
ExecStart=/usr/bin/node /opt/mock-firewalla-cloud/server.js
Restart=on-failure
User=mockcloud
Environment=PORT=8080 HOST=0.0.0.0

[Install]
WantedBy=multi-user.target
```
```
systemctl daemon-reload
systemctl enable --now mock-firewalla-cloud
journalctl -u mock-firewalla-cloud -f
```

---

## Connecting a real Firewalla box to this mock

On your Firewalla box (SSH in), override the cloud URLs in Redis:

```bash
sudo redis-cli set sys:bone:url:forced "http://YOUR-VPS-IP:8080/bone/api/v3"
sudo redis-cli publish comm:sys:bone:url "http://YOUR-VPS-IP:8080/bone/api/v3"
sudo systemctl restart firekick firemain
```

> If you also want to override the EPT (group/rendezvous/message) URL, you'll need to patch
> `/home/pi/firewalla/encipher/lib/encipherio.js` (line ~85) and replace the hardcoded
> `https://firewalla.encipher.io/iot/api/v2` with `http://YOUR-VPS-IP:8080/iot/api/v2`.
> Or set the `firewallaGroupServerURL` config in `net2/config.json`.

Then watch:
```bash
sudo tail -f /log/firewalla/FireKick.log
```

You should see successful eptLogin, group creation, and rendezvous registration — all hitting your mock instead of encipher.io.

---

## Simulating the mobile app

Use the included `fake-app.sh`:

```bash
chmod +x fake-app.sh
./fake-app.sh http://YOUR-VPS-IP:8080 <RENDEZVOUS_ID>
```

`<RENDEZVOUS_ID>` = full UUID of the rendezvous the box created. Get it from the box:

```bash
sudo grep "Inviting" /log/firewalla/FireKick.log | tail -1
# extract the UUID after "Inviting "
```

Or from the box's pairing message:

```bash
sudo redis-cli get firekick:pairing:message
# look for "rr": the short prefix; the full rid appears in the FireKick log
```

After running `fake-app.sh`, watch the box log — within a few seconds the box's poll will pick up the app's invite and pairing will complete:

```
group_member_cnt: 1 → 2     ← success!
```

---

## Watching what's happening

Status check:
```bash
curl http://localhost:8080/
```

Returns:
```json
{
  "name": "Mock Firewalla Cloud",
  "uptime_sec": 240,
  "state": {
    "groups": 1,
    "endpoints": 2,
    "rendezvous": 1,
    "messages": 0,
    "checkins": 5
  },
  "endpoints": [...]
}
```

Every request logs to stdout with structured info. Example session:

```
[03:02:32] POST /iot/api/v2/login/eptoken
         body: {"assertion":{"publicKey":"-----BEGIN PUBLIC KEY-----…
         ✓ eptLogin → eid=VYxbf70QbKIjd1IGlYa9iQ
[03:02:33] POST /iot/api/v2/group/com.rottiesoft.pi
         body: {"name":"my-box","info":"…
         ✓ group create → gid=cc5fc328-bff2-4605-b504-f4a110cff34b
[03:02:42] POST /iot/api/v2/ept/rendezvous/3b3a256c-36ae-…
         ✓ rendezvous CREATE → rid=3b3a256c-…
[03:02:45] GET  /iot/api/v2/ept/rendezvous/3b3a256c-…
         · rendezvous GET → rid=3b3a256c-… box payload only (no app yet)
[03:02:58] POST /iot/api/v2/ept/rendezvous/3b3a256c-…/invite
         ★ rendezvous INVITE → rid=3b3a256c-… APP HAS POSTED!
[03:02:59] POST /iot/api/v2/group/cc5fc328-…/<app-eid>
         ★ group MEMBER ADD → gid=cc5fc328 eid=<app-eid> count=2
```

The `★` lines show the magic moments.

---

## What this is NOT

- **Not cryptographically secure.** Symmetric keys are random but never used to actually encrypt anything in the mock. Real boxes will encrypt; the mock relays opaque ciphertext blobs without trying to decrypt.
- **Not persistent.** Restart wipes all state. For dev work, that's a feature.
- **Not WebSocket-complete.** The Firewalla cloud uses Socket.io for real-time message delivery. The mock relies on REST polling instead. Add Socket.io if you need real-time.
- **Not a Bone API replacement.** Only `/sys/checkin` and a few intel stubs are implemented; full Bone API has dozens more endpoints (see `firewalla-audit.md` §3).

---

## Where to go next

1. **Learn** — keep this running and watch every box request flow through. You'll understand the protocol in 30 minutes.
2. **Modify** — add more endpoints as your real box (or clone) hits them. The catch-all 404 handler will tell you which paths are missing.
3. **Replace with libsodium** — when you're ready to build a real (better) crypto layer, fork this and wire in `crypto_secretbox` from libsodium. See `research-pairing.md` in the bundle.
4. **Productize** — when this is good enough, swap the in-memory state for Postgres/Redis, add Cloudflare Workers, and you have the cloud foundation for your ISP-bundled product.

---

## License

MIT. Do whatever you want with it.
