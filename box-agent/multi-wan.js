/*
 * multi-wan.js — Multi-WAN failover & load-balancing manager
 *
 * Mirrors Firewalla's multi-WAN feature on a Pi-based router.
 *  - Maintains per-WAN routing tables (rt_tables)
 *  - Health-probes each WAN (ICMP + HTTP) every 5s
 *  - Swaps default route on failover (active/passive)
 *  - Installs ECMP nexthop default route for load-balance mode
 *  - Pins specific MACs to a WAN via iptables MARK + ip rule fwmark
 *
 * Designed to be self-contained: shell-outs only, no native deps.
 */

'use strict';

const { execSync } = require('child_process');
const fs = require('fs');

const RT_TABLES_FILE = '/etc/iproute2/rt_tables';
const PROBE_INTERVAL_MS = 5000;
const PROBE_TIMEOUT_S = 2;
const FAIL_THRESHOLD = 3;          // consecutive failures => DOWN
const RECOVER_THRESHOLD = 2;       // consecutive successes => UP
const HISTORY_WINDOW = 20;         // for success_pct calc
const MARK_BASE = 0x100;           // fwmarks start here, +i per WAN
const DEVICE_CHAIN = 'MWAN_DEVICES';

// ---------------- internal state ----------------
const state = {
  wans: [],                  // [{name, iface, table_id, gateway, probe_targets, weight, mark, up, fails, ok, history, lastProbeMs}]
  mode: 'failover',          // 'failover' | 'balance' | 'primary-only'
  currentDefault: null,      // name of WAN owning the main-table default route
  deviceRoutes: {},          // { mac -> wan_name }
  probeTimer: null,
  running: false,
};

// ---------------- shell helper ----------------
function sh(cmd, opts) {
  try {
    const out = execSync(cmd, Object.assign({ stdio: ['ignore', 'pipe', 'pipe'] }, opts || {}));
    return { ok: true, stdout: out.toString().trim(), stderr: '' };
  } catch (err) {
    return {
      ok: false,
      stdout: (err.stdout || '').toString(),
      stderr: (err.stderr || err.message || '').toString().trim(),
      code: err.status,
    };
  }
}

function log(msg) {
  // light-weight: prefix so caller can grep
  // eslint-disable-next-line no-console
  console.log(`[multi-wan] ${msg}`);
}

// ---------------- rt_tables persistence ----------------
function ensureRtTable(name, id) {
  let txt = '';
  try { txt = fs.readFileSync(RT_TABLES_FILE, 'utf8'); } catch (_) { txt = ''; }
  const lines = txt.split('\n');
  // strip any old entries with same id or same name
  const filtered = lines.filter((l) => {
    const t = l.trim();
    if (!t || t.startsWith('#')) return true;
    const parts = t.split(/\s+/);
    if (parts.length < 2) return true;
    return parts[0] !== String(id) && parts[1] !== name;
  });
  filtered.push(`${id}\t${name}`);
  // dedupe trailing blank lines
  const out = filtered.join('\n').replace(/\n{3,}/g, '\n\n').trimEnd() + '\n';
  try {
    fs.writeFileSync(RT_TABLES_FILE, out);
  } catch (e) {
    log(`WARN cannot write ${RT_TABLES_FILE}: ${e.message}`);
  }
}

// ---------------- gateway autodiscovery ----------------
function detectGateway(iface) {
  // Try DHCP lease first
  const lease = sh(`cat /var/lib/dhcp/dhclient.${iface}.leases 2>/dev/null | grep routers | tail -1`);
  if (lease.ok && lease.stdout) {
    const m = lease.stdout.match(/routers\s+([0-9.]+)/);
    if (m) return m[1];
  }
  // Fall back to whatever the kernel currently has on that iface
  const r = sh(`ip route show dev ${iface} | grep -m1 default`);
  if (r.ok && r.stdout) {
    const m = r.stdout.match(/via\s+([0-9.]+)/);
    if (m) return m[1];
  }
  // Last resort: assume .1 of the iface's /24
  const addr = sh(`ip -4 -o addr show dev ${iface} | awk '{print $4}' | head -1`);
  if (addr.ok && addr.stdout) {
    const m = addr.stdout.match(/^(\d+\.\d+\.\d+)\.\d+\//);
    if (m) return `${m[1]}.1`;
  }
  return null;
}

// ---------------- per-WAN routing table setup ----------------
function installWanTable(w) {
  // flush any prior default
  sh(`ip route flush table ${w.table_id} 2>/dev/null`);
  // add default route via this WAN's gateway
  const r1 = sh(`ip route add default via ${w.gateway} dev ${w.iface} table ${w.table_id}`);
  if (!r1.ok) log(`WARN add default ${w.name}: ${r1.stderr}`);
  // remove any matching ip-rule then re-add
  sh(`ip rule del fwmark ${w.mark} table ${w.table_id} 2>/dev/null`);
  const r2 = sh(`ip rule add fwmark ${w.mark} table ${w.table_id}`);
  if (!r2.ok) log(`WARN add rule ${w.name}: ${r2.stderr}`);
}

function teardownWanTable(w) {
  sh(`ip rule del fwmark ${w.mark} table ${w.table_id} 2>/dev/null`);
  sh(`ip route flush table ${w.table_id} 2>/dev/null`);
}

// ---------------- iptables device-pinning chain ----------------
function ensureDeviceChain() {
  // create chain if missing
  const exists = sh(`iptables -t mangle -nL ${DEVICE_CHAIN}`);
  if (!exists.ok) {
    sh(`iptables -t mangle -N ${DEVICE_CHAIN}`);
  } else {
    sh(`iptables -t mangle -F ${DEVICE_CHAIN}`);
  }
  // hook PREROUTING -> our chain (idempotent: try delete first)
  sh(`iptables -t mangle -D PREROUTING -j ${DEVICE_CHAIN} 2>/dev/null`);
  sh(`iptables -t mangle -I PREROUTING -j ${DEVICE_CHAIN}`);
}

function rebuildDeviceChain() {
  sh(`iptables -t mangle -F ${DEVICE_CHAIN}`);
  for (const mac of Object.keys(state.deviceRoutes)) {
    const wanName = state.deviceRoutes[mac];
    const w = state.wans.find((x) => x.name === wanName);
    if (!w) continue;
    const r = sh(`iptables -t mangle -A ${DEVICE_CHAIN} -m mac --mac-source ${mac} -j MARK --set-mark ${w.mark}`);
    if (!r.ok) log(`WARN mangle rule ${mac}: ${r.stderr}`);
  }
}

// ---------------- default-route management ----------------
function setDefaultRoute(wanName) {
  if (state.mode === 'balance') return setBalancedDefault();
  const w = state.wans.find((x) => x.name === wanName);
  if (!w) return;
  // replace = atomic delete+add
  const r = sh(`ip route replace default via ${w.gateway} dev ${w.iface}`);
  if (!r.ok) {
    log(`WARN replace default via ${w.name}: ${r.stderr}`);
    return;
  }
  state.currentDefault = w.name;
  log(`default route -> ${w.name} (${w.iface} via ${w.gateway})`);
  // flush conntrack so existing flows pick the new path
  sh(`conntrack -F 2>/dev/null`);
}

function setBalancedDefault() {
  const upWans = state.wans.filter((w) => w.up);
  if (upWans.length === 0) {
    log('balance: no WANs up, skipping');
    return;
  }
  if (upWans.length === 1) {
    return setDefaultRoute(upWans[0].name); // fall back to single
  }
  const hops = upWans
    .map((w) => `nexthop via ${w.gateway} dev ${w.iface} weight ${w.weight || 1}`)
    .join(' ');
  // delete old default, add ECMP
  sh(`ip route del default 2>/dev/null`);
  const r = sh(`ip route add default scope global ${hops}`);
  if (!r.ok) {
    log(`WARN ECMP default: ${r.stderr}`);
    return;
  }
  state.currentDefault = '__balanced__';
  log(`default route -> balanced across ${upWans.map((x) => x.name).join(',')}`);
  sh(`conntrack -F 2>/dev/null`);
}

function pickActiveWan() {
  // primary-only: always wans[0] if up, else nothing
  if (state.mode === 'primary-only') {
    return state.wans[0] && state.wans[0].up ? state.wans[0] : null;
  }
  // failover: first up wan in declared order
  return state.wans.find((w) => w.up) || null;
}

function reconcileRouting() {
  if (state.wans.length === 0) return;
  if (state.mode === 'balance') {
    setBalancedDefault();
    return;
  }
  const pick = pickActiveWan();
  if (!pick) {
    log('no WAN up — leaving default route alone');
    return;
  }
  if (state.currentDefault !== pick.name) setDefaultRoute(pick.name);
}

// ---------------- health probe ----------------
function probeOne(w, target) {
  // ICMP through the specific iface
  const r = sh(`ping -c 1 -W ${PROBE_TIMEOUT_S} -I ${w.iface} ${target}`);
  return r.ok;
}

function probeHttp(w) {
  // light HTTP HEAD via curl bound to the iface
  const r = sh(`curl -s -o /dev/null -w '%{http_code}' --max-time ${PROBE_TIMEOUT_S} --interface ${w.iface} http://www.gstatic.com/generate_204`);
  if (!r.ok) return false;
  const code = parseInt(r.stdout, 10);
  return code >= 200 && code < 500;
}

function probeWan(w) {
  const start = Date.now();
  let success = false;
  // Try each ICMP target until one works
  for (const t of (w.probe_targets || [])) {
    if (probeOne(w, t)) { success = true; break; }
  }
  // If ICMP all failed, try HTTP as a tiebreak (some ISPs drop ICMP)
  if (!success) success = probeHttp(w);

  w.lastProbeMs = Date.now() - start;
  w.history.push(success ? 1 : 0);
  while (w.history.length > HISTORY_WINDOW) w.history.shift();

  if (success) {
    w.ok += 1;
    w.fails = 0;
    if (!w.up && w.ok >= RECOVER_THRESHOLD) {
      w.up = true;
      log(`${w.name} -> UP`);
      reconcileRouting();
    }
  } else {
    w.fails += 1;
    w.ok = 0;
    if (w.up && w.fails >= FAIL_THRESHOLD) {
      w.up = false;
      log(`${w.name} -> DOWN (after ${w.fails} fails)`);
      reconcileRouting();
    }
  }
}

function runProbes() {
  for (const w of state.wans) {
    try { probeWan(w); }
    catch (e) { log(`probe error ${w.name}: ${e.message}`); }
  }
}

// ---------------- public API ----------------
function configure(wans) {
  if (!Array.isArray(wans) || wans.length === 0) {
    throw new Error('configure: wans must be a non-empty array');
  }
  // tear down anything we set up previously
  for (const w of state.wans) teardownWanTable(w);

  state.wans = wans.map((cfg, i) => {
    if (!cfg.name || !cfg.iface || !cfg.table_id) {
      throw new Error(`wan[${i}] missing required name/iface/table_id`);
    }
    const gateway = cfg.gateway || detectGateway(cfg.iface);
    if (!gateway) log(`WARN ${cfg.name}: could not auto-detect gateway`);
    return {
      name: cfg.name,
      iface: cfg.iface,
      table_id: cfg.table_id,
      gateway: gateway,
      probe_targets: cfg.probe_targets && cfg.probe_targets.length ? cfg.probe_targets : ['8.8.8.8', '1.1.1.1'],
      weight: cfg.weight || 1,
      mark: MARK_BASE + i,
      up: true,           // optimistic; first probe will correct
      fails: 0,
      ok: 0,
      history: [],
      lastProbeMs: 0,
    };
  });

  // persist rt_tables and install routing tables + rules
  for (const w of state.wans) {
    ensureRtTable(w.name, w.table_id);
    if (w.gateway) installWanTable(w);
  }

  ensureDeviceChain();
  rebuildDeviceChain();
  reconcileRouting();
  return state.wans.map((w) => ({ name: w.name, iface: w.iface, gateway: w.gateway, mark: w.mark }));
}

function getStatus() {
  return {
    mode: state.mode,
    running: state.running,
    current_default: state.currentDefault,
    wans: state.wans.map((w) => {
      const total = w.history.length || 1;
      const succ = w.history.reduce((a, b) => a + b, 0);
      return {
        name: w.name,
        iface: w.iface,
        gateway: w.gateway,
        up: w.up,
        last_probe_ms: w.lastProbeMs,
        success_pct: Math.round((succ / total) * 100),
        current_default: state.currentDefault === w.name ||
          (state.currentDefault === '__balanced__' && w.up),
      };
    }),
  };
}

function setMode(mode) {
  const allowed = ['failover', 'balance', 'primary-only'];
  if (!allowed.includes(mode)) throw new Error(`setMode: unknown mode ${mode}`);
  state.mode = mode;
  log(`mode -> ${mode}`);
  reconcileRouting();
  return state.mode;
}

function routeDevice(mac, wanName) {
  if (!mac || typeof mac !== 'string') throw new Error('routeDevice: mac required');
  const w = state.wans.find((x) => x.name === wanName);
  if (!w) throw new Error(`routeDevice: unknown wan ${wanName}`);
  const m = mac.toLowerCase();
  state.deviceRoutes[m] = wanName;
  rebuildDeviceChain();
  log(`pin ${m} -> ${wanName}`);
  return true;
}

function unrouteDevice(mac) {
  if (!mac) return false;
  const m = mac.toLowerCase();
  if (!state.deviceRoutes[m]) return false;
  delete state.deviceRoutes[m];
  rebuildDeviceChain();
  log(`unpin ${m}`);
  return true;
}

function getDeviceRoutes() {
  return Object.keys(state.deviceRoutes).map((mac) => ({
    mac: mac,
    wan_name: state.deviceRoutes[mac],
  }));
}

function start() {
  if (state.running) return false;
  if (state.wans.length === 0) {
    log('start: no WANs configured');
    return false;
  }
  state.running = true;
  // immediate kick-off so we don't sit on optimistic state for 5s
  try { runProbes(); } catch (e) { log(`initial probe error: ${e.message}`); }
  state.probeTimer = setInterval(runProbes, PROBE_INTERVAL_MS);
  if (state.probeTimer.unref) state.probeTimer.unref();
  log(`probes started (interval=${PROBE_INTERVAL_MS}ms)`);
  return true;
}

function stop() {
  if (!state.running) return false;
  if (state.probeTimer) clearInterval(state.probeTimer);
  state.probeTimer = null;
  state.running = false;
  log('probes stopped');
  return true;
}

module.exports = {
  configure,
  getStatus,
  setMode,
  routeDevice,
  unrouteDevice,
  getDeviceRoutes,
  start,
  stop,
};
