// disturb.js - Firewalla-style "Disturb" feature
//
// Instead of cleanly blocking traffic (which is obvious to the user and easy
// to detect), we degrade the connection: drop a fraction of packets, add
// large delay/jitter, and let TCP/QUIC do the rest. The result feels like
// "the internet is being weird today" - Netflix buffers forever, TikTok
// videos won't start, app updates fail and retry. Much harder to attribute
// to a deliberate parental-control / policy action than a hard block.
//
// Mechanism:
//   1. Build an HTB root qdisc on the WAN interface with a default class.
//   2. For each disturb policy, allocate a child class + a netem qdisc with
//      loss/delay/jitter configured per intensity level.
//   3. Mark matching packets in iptables mangle (FORWARD chain) using either
//      `-m mac --mac-source <mac>` (per-device) or `-d <ip>` (per-target).
//   4. A tc filter maps the fwmark to the child class.
//
// Idempotent: every policy gets a stable id (handle/classid/fwmark derived
// from a counter); apply() de-dups on (device_mac, target_ip, target_domain);
// remove() tears down only that policy's tc/iptables rules.
//
// NOTE: target_domain is resolved to A records at apply() time. Long-lived
// domains (CDN-fronted) may rotate IPs; for production you'd want to hook
// into the DNS path. For this mock we resolve once and store the IPs.

'use strict';

const { execSync } = require('child_process');
const dns = require('dns').promises;

const WAN_IFACE = process.env.DISTURB_WAN || 'eth0';
const ROOT_HANDLE = '1:';
const DEFAULT_CLASSID = '1:1';
const HTB_RATE = '1000mbit'; // ceiling - we're not rate limiting, just shaping loss/delay
const MANGLE_CHAIN = 'FORWARD';

// Intensity presets - (loss%, delay_ms, jitter_ms)
const INTENSITY = {
  mild:       { loss: 10, delay: 200, jitter: 50,  corrupt: 0 },
  medium:     { loss: 30, delay: 500, jitter: 150, corrupt: 1 },
  aggressive: { loss: 60, delay: 1500, jitter: 400, corrupt: 3 },
};

let defaultIntensity = 'medium';

// In-memory state. Each policy:
//   { id, label, device_mac, target_ips, target_domain, intensity,
//     classid, qdisc_handle, fwmark, applied_at }
const policies = new Map(); // id -> policy
let nextId = 10;            // also used as classid minor + fwmark
let rootInstalled = false;

// ---------- shell helpers ----------

function sh(cmd, { ignoreFail = false } = {}) {
  try {
    const out = execSync(cmd, { stdio: ['ignore', 'pipe', 'pipe'] });
    return { ok: true, out: out.toString().trim() };
  } catch (e) {
    if (!ignoreFail) {
      const stderr = e.stderr ? e.stderr.toString().trim() : '';
      throw new Error(`cmd failed: ${cmd}\n${stderr}`);
    }
    return { ok: false, out: '', err: e.stderr ? e.stderr.toString().trim() : String(e) };
  }
}

function shTry(cmd) { return sh(cmd, { ignoreFail: true }); }

// ---------- root qdisc lifecycle ----------

function ensureRootQdisc() {
  if (rootInstalled) return;
  // Tear down any stale root and rebuild. `tc qdisc del root` is idempotent
  // enough when wrapped in ignoreFail.
  shTry(`tc qdisc del dev ${WAN_IFACE} root`);
  sh(`tc qdisc add dev ${WAN_IFACE} root handle ${ROOT_HANDLE} htb default 1`);
  // Default class - everything not matched by a filter passes through here at
  // line rate with no impairment.
  sh(`tc class add dev ${WAN_IFACE} parent ${ROOT_HANDLE} classid ${DEFAULT_CLASSID} htb rate ${HTB_RATE} ceil ${HTB_RATE}`);
  rootInstalled = true;
}

function teardownRootQdisc() {
  shTry(`tc qdisc del dev ${WAN_IFACE} root`);
  rootInstalled = false;
}

// ---------- policy install / uninstall ----------

function netemArgs(level) {
  const cfg = INTENSITY[level] || INTENSITY[defaultIntensity];
  const parts = [`delay ${cfg.delay}ms ${cfg.jitter}ms distribution normal`];
  if (cfg.loss > 0) parts.push(`loss ${cfg.loss}%`);
  if (cfg.corrupt > 0) parts.push(`corrupt ${cfg.corrupt}%`);
  // small reorder makes TCP fast-retransmit fire spuriously - extra annoyance
  parts.push('reorder 5%');
  return parts.join(' ');
}

function installTcForPolicy(p) {
  ensureRootQdisc();
  const minor = p.classid.split(':')[1];
  // Class to hold the netem qdisc
  sh(`tc class add dev ${WAN_IFACE} parent ${ROOT_HANDLE} classid ${p.classid} htb rate ${HTB_RATE} ceil ${HTB_RATE}`);
  // Netem qdisc attached to that class
  sh(`tc qdisc add dev ${WAN_IFACE} parent ${p.classid} handle ${p.qdisc_handle} netem ${netemArgs(p.intensity)}`);
  // fw filter: any packet whose fwmark matches goes to our class
  sh(`tc filter add dev ${WAN_IFACE} protocol ip parent ${ROOT_HANDLE}0 prio 1 handle ${p.fwmark} fw classid ${p.classid}`);
  // IPv6 too - same fwmark bridges both families
  shTry(`tc filter add dev ${WAN_IFACE} protocol ipv6 parent ${ROOT_HANDLE}0 prio 1 handle ${p.fwmark} fw classid ${p.classid}`);
}

function uninstallTcForPolicy(p) {
  shTry(`tc filter del dev ${WAN_IFACE} protocol ip parent ${ROOT_HANDLE}0 prio 1 handle ${p.fwmark} fw`);
  shTry(`tc filter del dev ${WAN_IFACE} protocol ipv6 parent ${ROOT_HANDLE}0 prio 1 handle ${p.fwmark} fw`);
  shTry(`tc qdisc del dev ${WAN_IFACE} parent ${p.classid} handle ${p.qdisc_handle}`);
  shTry(`tc class del dev ${WAN_IFACE} parent ${ROOT_HANDLE} classid ${p.classid}`);
}

function installIptablesForPolicy(p) {
  // MARK matching packets so the tc fw filter can pick them up.
  if (p.device_mac) {
    sh(`iptables -t mangle -A ${MANGLE_CHAIN} -m mac --mac-source ${p.device_mac} -j MARK --set-mark ${p.fwmark}`);
  }
  for (const ip of p.target_ips) {
    const isV6 = ip.includes(':');
    const bin = isV6 ? 'ip6tables' : 'iptables';
    if (p.device_mac) {
      sh(`${bin} -t mangle -A ${MANGLE_CHAIN} -m mac --mac-source ${p.device_mac} -d ${ip} -j MARK --set-mark ${p.fwmark}`);
    } else {
      sh(`${bin} -t mangle -A ${MANGLE_CHAIN} -d ${ip} -j MARK --set-mark ${p.fwmark}`);
    }
  }
}

function uninstallIptablesForPolicy(p) {
  if (p.device_mac) {
    shTry(`iptables -t mangle -D ${MANGLE_CHAIN} -m mac --mac-source ${p.device_mac} -j MARK --set-mark ${p.fwmark}`);
  }
  for (const ip of p.target_ips) {
    const bin = ip.includes(':') ? 'ip6tables' : 'iptables';
    if (p.device_mac) {
      shTry(`${bin} -t mangle -D ${MANGLE_CHAIN} -m mac --mac-source ${p.device_mac} -d ${ip} -j MARK --set-mark ${p.fwmark}`);
    } else {
      shTry(`${bin} -t mangle -D ${MANGLE_CHAIN} -d ${ip} -j MARK --set-mark ${p.fwmark}`);
    }
  }
}

// ---------- domain resolution ----------

async function resolveDomain(domain) {
  const ips = new Set();
  try {
    const a = await dns.resolve4(domain);
    a.forEach(ip => ips.add(ip));
  } catch (_) { /* ignore */ }
  try {
    const aaaa = await dns.resolve6(domain);
    aaaa.forEach(ip => ips.add(ip));
  } catch (_) { /* ignore */ }
  return Array.from(ips);
}

// ---------- policy lookup ----------

function findExisting({ device_mac, target_ip, target_domain }) {
  for (const p of policies.values()) {
    if (p.device_mac === (device_mac || null)
        && p.target_domain === (target_domain || null)
        && (target_ip ? p.target_ips.includes(target_ip) : !target_ip)) {
      return p;
    }
  }
  return null;
}

// ---------- public API ----------

async function apply(opts = {}) {
  const { device_mac = null, target_ip = null, target_domain = null,
          intensity = defaultIntensity, label = null } = opts;

  if (!device_mac && !target_ip && !target_domain) {
    throw new Error('apply: need at least one of device_mac, target_ip, target_domain');
  }
  if (!INTENSITY[intensity]) {
    throw new Error(`apply: unknown intensity '${intensity}' (use mild|medium|aggressive)`);
  }

  const existing = findExisting({ device_mac, target_ip, target_domain });
  if (existing) {
    // idempotent: bump intensity if changed, else no-op
    if (existing.intensity !== intensity) {
      shTry(`tc qdisc change dev ${WAN_IFACE} parent ${existing.classid} handle ${existing.qdisc_handle} netem ${netemArgs(intensity)}`);
      existing.intensity = intensity;
    }
    return { id: existing.id, status: 'already-applied', policy: snapshot(existing) };
  }

  let target_ips = [];
  if (target_ip) target_ips.push(target_ip);
  if (target_domain) {
    const resolved = await resolveDomain(target_domain);
    if (resolved.length === 0 && !target_ip && !device_mac) {
      throw new Error(`apply: could not resolve ${target_domain}`);
    }
    target_ips = target_ips.concat(resolved);
  }

  const id = nextId++;
  const policy = {
    id,
    label: label || `disturb-${id}`,
    device_mac,
    target_ips,
    target_domain,
    intensity,
    classid: `1:${id}`,
    qdisc_handle: `${id}:`,
    fwmark: id,
    applied_at: Date.now(),
  };

  try {
    installTcForPolicy(policy);
    installIptablesForPolicy(policy);
  } catch (e) {
    // Best-effort rollback so we don't leave half-installed state.
    uninstallIptablesForPolicy(policy);
    uninstallTcForPolicy(policy);
    throw e;
  }

  policies.set(id, policy);
  return { id, status: 'applied', policy: snapshot(policy) };
}

function remove(opts = {}) {
  const { id = null } = opts;
  let target;
  if (id != null) {
    target = policies.get(id);
  } else {
    target = findExisting(opts);
  }
  if (!target) return { status: 'not-found' };

  uninstallIptablesForPolicy(target);
  uninstallTcForPolicy(target);
  policies.delete(target.id);

  if (policies.size === 0) teardownRootQdisc();
  return { status: 'removed', id: target.id };
}

function list() {
  return Array.from(policies.values()).map(snapshot);
}

function getStatus() {
  const qdiscState = shTry(`tc -s qdisc show dev ${WAN_IFACE}`).out;
  const filterState = shTry(`tc filter show dev ${WAN_IFACE}`).out;
  return {
    iface: WAN_IFACE,
    active_policies: policies.size,
    default_intensity: defaultIntensity,
    root_installed: rootInstalled,
    qdisc_state: qdiscState,
    filter_state: filterState,
  };
}

function setIntensity(level) {
  if (!INTENSITY[level]) {
    throw new Error(`setIntensity: unknown level '${level}'`);
  }
  defaultIntensity = level;
  return { default_intensity: defaultIntensity, params: INTENSITY[level] };
}

function snapshot(p) {
  return {
    id: p.id,
    label: p.label,
    device_mac: p.device_mac,
    target_ips: p.target_ips.slice(),
    target_domain: p.target_domain,
    intensity: p.intensity,
    classid: p.classid,
    fwmark: p.fwmark,
    applied_at: p.applied_at,
  };
}

module.exports = {
  apply,
  remove,
  list,
  getStatus,
  setIntensity,
  // exposed for tests / agent introspection
  _intensities: INTENSITY,
  _iface: WAN_IFACE,
};
