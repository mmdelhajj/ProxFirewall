# mes Box agent

This is the on-premise daemon that turns a Linux device (NanoPi R6S, Raspberry Pi, x86 mini-PC, …) into a "mes Box".

It does the same job as Firewalla's box-side software:
- **Heartbeat** every 60s  → cloud knows the box is alive
- **LAN device discovery** via `ip neigh` and `dnsmasq.leases`
- **Flow capture** via `conntrack` (parses public-destination connections)
- **Policy sync** — pulls blocked-domains from cloud, writes them to dnsmasq
- **Alarm reporting** — fires when a new MAC appears, etc.

## Install on a Linux box

```bash
# 1. On the cloud, authorize the box's MAC and grab its secret:
curl -u admin:PASS https://cloud.mes.net.lb/admin/api/macs/authorize \
  -H 'Content-Type: application/json' \
  -d '{"mac":"aa:bb:cc:11:22:33","customer_id":"cus_xxx","type":"navy"}'
curl -u admin:PASS https://cloud.mes.net.lb/admin/api/box/secret/aa:bb:cc:11:22:33

# 2. SSH into the box and run:
curl -fsSL https://cloud.mes.net.lb/box/install.sh | sudo bash -s -- \
  --mac aa:bb:cc:11:22:33 --secret <SECRET>

# 3. Watch logs
journalctl -u mes-box-agent -f
```

## Config

`/etc/mes-box/agent.json`:
```json
{
  "box_mac": "aa:bb:cc:11:22:33",
  "box_secret": "...",
  "cloud_url": "https://cloud.mes.net.lb",
  "lan_iface": "eth0"
}
```

## What it writes

- `/etc/dnsmasq.d/mes-box-blocks.conf` — blocked-domain rules (auto-managed)
- `/etc/mes-box/agent-state.json` — saved auth token + state

## Limitations of this v1 agent

- **DNS-based blocking only** (no IP-level via iptables yet)
- No traffic shaping / QoS
- No DHCP server (assumes existing dnsmasq is already serving DHCP)
- Conntrack-based flow capture misses blocked-on-DNS flows

These will land in v2. The current scope is: **show what's connected, show flows to public IPs, enforce category-level blocks via DNS.**
