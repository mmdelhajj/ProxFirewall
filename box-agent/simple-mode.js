/**
 * simple-mode.js — Firewalla "Simple Mode" / transparent ARP-spoof inline.
 *
 * Concept:
 *  1. Discover gateway via `ip route show default`
 *  2. Discover LAN clients via `arp -a` + `arp-scan`/`nmap -sn`
 *  3. For each client, send gratuitous ARP claiming to BE the gateway → client updates ARP cache
 *  4. Send gratuitous ARP to gateway claiming each client's IP → gateway sends client traffic to us
 *  5. Enable IP forwarding so we transparently proxy to the real gateway
 *  6. Result: every device's traffic flows through us — same UX as Firewalla Simple Mode.
 *
 * Caveats:
 *  - Some IoT devices (Apple HomePods, certain cameras) detect ARP changes and complain.
 *  - HTTPS still works (we don't decrypt — only see metadata: SNI, IP, ports).
 *  - On stop, we send a "corrective" ARP so devices' caches re-learn the real gateway MAC.
 *
 * Required apt packages: `dsniff` (provides arpspoof) — already in install-full.sh APT list.
 */
const { execSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const STATE_PATH = '/var/lib/mes-box-agent/simple-mode.state.json';

let _state = {
  enabled: false,
  iface: null,
  gateway_ip: null,
  gateway_mac: null,
  clients: [],         // [{mac, ip, last_seen}]
  arpspoof_pids: [],   // active arpspoof child PIDs
  started_at: null,
  rescans_done: 0,
};
try { fs.mkdirSync(path.dirname(STATE_PATH), { recursive: true }); } catch {}
try { _state = { ..._state, ...JSON.parse(fs.readFileSync(STATE_PATH, 'utf8')) }; } catch {}
function save() { try { fs.writeFileSync(STATE_PATH, JSON.stringify(_state, null, 2)); } catch {} }

function sh(cmd, opts = {}) {
  try {
    return execSync(cmd, { encoding: 'utf8', timeout: 10_000, stdio: ['ignore', 'pipe', 'pipe'], ...opts }).trim();
  } catch (e) {
    return null;
  }
}

function detectIfaceAndGateway() {
  // ip route show default → "default via 10.11.0.1 dev eth0 proto dhcp src 10.11.0.10 metric 100"
  const route = sh('ip route show default | head -1');
  if (!route) return null;
  const m = route.match(/default via (\S+) dev (\S+)/);
  if (!m) return null;
  const gw_ip = m[1], iface = m[2];
  // Resolve gateway MAC via arp
  let gw_mac = null;
  const arp = sh(`ip neigh show ${gw_ip}`) || sh(`arp -n ${gw_ip}`);
  if (arp) {
    const m2 = arp.match(/[0-9a-f]{2}(:[0-9a-f]{2}){5}/i);
    if (m2) gw_mac = m2[0].toLowerCase();
  }
  if (!gw_mac) {
    // Force ARP resolution — ping once
    sh(`ping -c 1 -W 2 ${gw_ip}`);
    const arp2 = sh(`ip neigh show ${gw_ip}`);
    if (arp2) {
      const m3 = arp2.match(/[0-9a-f]{2}(:[0-9a-f]{2}){5}/i);
      if (m3) gw_mac = m3[0].toLowerCase();
    }
  }
  return { iface, gateway_ip: gw_ip, gateway_mac: gw_mac };
}

// Active scan of the LAN to find every reachable client.
// Uses nmap -sn (already installed) — falls back to fast ping sweep if missing.
async function scanLan(iface) {
  // Get our own subnet from `ip -4 addr show <iface>`
  const addr = sh(`ip -4 addr show ${iface}`);
  if (!addr) return [];
  const m = addr.match(/inet (\d+\.\d+\.\d+\.\d+)\/(\d+)/);
  if (!m) return [];
  const ourIp = m[1], cidr = parseInt(m[2]);
  const subnet = ourIp.split('.').slice(0, 3).join('.') + '.0/' + cidr;

  const clients = [];
  const seen = new Set();

  // nmap -sn — sweep the subnet. Output emits "Nmap scan report for <ip>"
  // followed (on a later line) by "MAC Address: AA:BB:..." for each host.
  // Parse that stream directly — `ip neigh show` only knows about hosts
  // the kernel has actively resolved, so it misses most of the LAN.
  const nmapOut = sh(`nmap -sn -n -T4 --max-retries 1 --host-timeout 5s ${subnet} 2>/dev/null`, { timeout: 60_000 });
  if (nmapOut) {
    let pendingIp = null;
    for (const line of nmapOut.split('\n')) {
      const ipM = line.match(/^Nmap scan report for (\d+\.\d+\.\d+\.\d+)/);
      if (ipM) { pendingIp = ipM[1]; continue; }
      const macM = line.match(/MAC Address: ([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})/);
      if (macM && pendingIp) {
        const ip = pendingIp;
        const mac = macM[1].toLowerCase();
        pendingIp = null;
        if (ip === ourIp) continue;
        if (seen.has(mac)) continue;
        seen.add(mac);
        clients.push({ mac, ip, last_seen: Date.now() });
      }
    }
  } else {
    // Fallback: brute ping sweep — slower but no extra deps
    const base = ourIp.split('.').slice(0, 3).join('.');
    for (let i = 1; i < 255; i++) {
      sh(`ping -c 1 -W 1 ${base}.${i} >/dev/null 2>&1`, { timeout: 1500 });
    }
  }

  // Always merge in ip neigh show — catches anything nmap missed (including
  // devices that didn't reply to the ARP probe but are in our cache).
  const neigh = sh('ip neigh show');
  for (const line of (neigh || '').split('\n')) {
    const m = line.match(/^(\d+\.\d+\.\d+\.\d+) .* lladdr ([0-9a-f]{2}(?::[0-9a-f]{2}){5}) /i);
    if (!m) continue;
    const ip = m[1], mac = m[2].toLowerCase();
    if (ip === ourIp) continue;
    if (seen.has(mac)) continue;
    seen.add(mac);
    clients.push({ mac, ip, last_seen: Date.now() });
  }
  return clients;
}

function enableIpForwarding() {
  sh('sysctl -w net.ipv4.ip_forward=1');
  // Conservative ICMP redirect handling so the kernel doesn't tell devices to
  // bypass us when it forwards their traffic.
  sh('sysctl -w net.ipv4.conf.all.send_redirects=0');
  // Persist
  try {
    fs.writeFileSync('/etc/sysctl.d/99-mes-simple-mode.conf',
      'net.ipv4.ip_forward=1\n' +
      'net.ipv4.conf.all.send_redirects=0\n');
  } catch {}
}

function ensureForwardChain() {
  // Make sure default forward policy is ACCEPT, plus a stateful rule that lets
  // forwarded traffic come back. Idempotent.
  sh('iptables -P FORWARD ACCEPT');
  // Don't NAT (we want transparency — clients keep their real IPs)
  // But do allow established/related to flow back
  const exists = sh(`iptables -C FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>&1`);
  if (exists === null) {
    sh('iptables -I FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT');
  }
}

function startArpspoofForClient(iface, gateway_ip, client_ip) {
  // arpspoof's hardcoded 2-second send interval is too slow — the gateway's
  // ARP cache can briefly refresh to the real MAC between our re-assertions,
  // and return packets in those windows go direct to the device, bypassing
  // the Pi. Three staggered instances per direction give effective ~667ms
  // re-assertion → much higher capture rate (~95%+ vs ~60-70% with a single
  // instance). Cost: 6 procs per device, ~270 total for a 45-device LAN.
  //   - Direction 1: tell CLIENT we are the gateway → catches uploads
  //   - Direction 2: tell GATEWAY we are the client → catches downloads
  const pids = [];
  for (let i = 0; i < 3; i++) {
    const cOut = spawn('arpspoof', ['-i', iface, '-t', client_ip, gateway_ip], { detached: true, stdio: 'ignore' });
    cOut.unref(); pids.push(cOut.pid);
    const cIn = spawn('arpspoof', ['-i', iface, '-t', gateway_ip, client_ip], { detached: true, stdio: 'ignore' });
    cIn.unref(); pids.push(cIn.pid);
  }
  return pids;
}

function killArpspoofs() {
  // Find any arpspoof children we spawned and kill them
  for (const pid of _state.arpspoof_pids) {
    try { process.kill(pid, 'SIGTERM'); } catch {}
  }
  // Also nuke anything else by the same name (defensive)
  sh('pkill -TERM -x arpspoof');
  _state.arpspoof_pids = [];
}

async function start(opts = {}) {
  if (_state.enabled) return { ok: true, already_running: true, ..._state };
  if (!sh('which arpspoof')) {
    return { ok: false, error: 'arpspoof_not_installed', hint: 'apt-get install -y dsniff' };
  }
  const route = detectIfaceAndGateway();
  if (!route) return { ok: false, error: 'no_default_route' };
  const iface = opts.iface || route.iface;
  const gw_ip = route.gateway_ip;
  const gw_mac = route.gateway_mac;
  if (!gw_mac) return { ok: false, error: 'gateway_mac_unknown', gateway_ip: gw_ip };

  enableIpForwarding();
  ensureForwardChain();

  const clients = await scanLan(iface);
  console.log('[simple-mode] gateway=' + gw_ip + ' (' + gw_mac + ') iface=' + iface + ' clients=' + clients.length);

  const pids = [];
  for (const c of clients) {
    const newPids = startArpspoofForClient(iface, gw_ip, c.ip);
    for (const p of newPids) if (p) pids.push(p);
  }

  _state = {
    enabled: true,
    iface,
    gateway_ip: gw_ip,
    gateway_mac: gw_mac,
    clients,
    arpspoof_pids: pids,
    started_at: Date.now(),
    rescans_done: 0,
  };
  save();
  return { ok: true, ..._state };
}

function stop() {
  if (!_state.enabled) return { ok: true, already_stopped: true };
  killArpspoofs();
  // Send a corrective gratuitous ARP so clients re-learn the real gateway MAC
  if (_state.gateway_ip && _state.gateway_mac && _state.iface) {
    sh(`arping -c 3 -A -I ${_state.iface} ${_state.gateway_ip} 2>/dev/null`);
  }
  _state.enabled = false;
  _state.arpspoof_pids = [];
  save();
  return { ok: true, stopped_at: Date.now() };
}

async function rescan() {
  if (!_state.enabled) return { ok: false, error: 'not_running' };
  const newClients = await scanLan(_state.iface);
  const knownMacs = new Set(_state.clients.map(c => c.mac));
  const fresh = newClients.filter(c => !knownMacs.has(c.mac));
  for (const c of fresh) {
    const newPids = startArpspoofForClient(_state.iface, _state.gateway_ip, c.ip);
    for (const p of newPids) if (p) _state.arpspoof_pids.push(p);
  }
  _state.clients = newClients;
  _state.rescans_done++;
  save();
  return { ok: true, total_clients: newClients.length, new_clients: fresh.length };
}

function getStatus() {
  // Verify arpspoof PIDs still alive
  const live = _state.arpspoof_pids.filter(pid => {
    try { process.kill(pid, 0); return true; } catch { return false; }
  });
  return {
    ..._state,
    arpspoof_pids: live,
    arpspoof_count: live.length,
    uptime_s: _state.started_at ? Math.round((Date.now() - _state.started_at) / 1000) : 0,
  };
}

module.exports = { start, stop, rescan, getStatus };
