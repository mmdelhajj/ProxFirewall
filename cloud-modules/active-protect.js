/*
 * active-protect.js
 *
 * Mock cloud-side implementation of Firewalla's "Device Active Protect"
 * (a.k.a. IoT lockdown) feature.
 *
 * Lifecycle per (customer, device_mac):
 *   1. enable()           -> state = 'learning' for opts.learning_days (default 7).
 *   2. ingestFlow()       -> during learning, every dst_domain/dst_ip is recorded
 *                            into the allowlist with a last_seen timestamp.
 *   3. learning ends      -> automatic transition (lazy, on next ingest/getStatus
 *                            call) to state = 'enforcing'. Or call
 *                            finishLearningEarly() to skip the wait.
 *   4. enforcing          -> ingestFlow returns {action: 'allow'|'deny', matched}.
 *                            allowlist.last_seen is bumped on every allowed hit.
 *   5. user can add/remove allowlist entries at any time.
 *   6. exportPolicyForBox() flattens allowlists into the per-MAC ipset payload
 *      consumed by the Firewalla box's policy bundle.
 *   7. pruneOld() drops entries unseen for >30 days so stale endpoints don't
 *      stay whitelisted forever.
 *
 * Persistence: this module is stateless on its own; init(globalState) attaches
 * its working state to the host server's `state` object as
 * `state.active_protect[customer_id][mac]`.
 */

'use strict';

const DAY_MS = 24 * 60 * 60 * 1000;
const DEFAULT_LEARNING_DAYS = 7;
const PRUNE_AFTER_DAYS = 30;

let state = null; // host server's global state, set via init()

// ---------------------------------------------------------------------------
// internal helpers
// ---------------------------------------------------------------------------

function ensureInited() {
  if (!state) {
    throw new Error('active-protect: init(globalState) must be called first');
  }
}

function ensureCustomer(customer_id) {
  if (!state.active_protect[customer_id]) {
    state.active_protect[customer_id] = {};
  }
  return state.active_protect[customer_id];
}

function getEntry(customer_id, device_mac) {
  ensureInited();
  const cust = state.active_protect[customer_id];
  if (!cust) return null;
  return cust[device_mac] || null;
}

function normMac(mac) {
  return String(mac || '').trim().toLowerCase();
}

function normDomain(d) {
  if (!d) return null;
  d = String(d).trim().toLowerCase();
  if (d.endsWith('.')) d = d.slice(0, -1);
  return d || null;
}

function normIp(ip) {
  if (!ip) return null;
  ip = String(ip).trim();
  return ip || null;
}

// Domain match: exact or suffix (allowlist "googleapis.com" matches
// "fonts.googleapis.com"). IPs are exact-match.
function domainMatches(allowSet, candidate) {
  if (!candidate) return null;
  if (allowSet.has(candidate)) return candidate;
  const parts = candidate.split('.');
  for (let i = 1; i < parts.length - 1; i++) {
    const suffix = parts.slice(i).join('.');
    if (allowSet.has(suffix)) return suffix;
  }
  return null;
}

// Lazily transition learning -> enforcing once the timer is up. Idempotent.
function maybeFinishLearning(ap, now) {
  if (ap.state === 'learning' && now >= ap.learning_ends_at) {
    ap.state = 'enforcing';
  }
}

function recordSeen(ap, key, now) {
  ap.allowlist.last_seen[key] = now;
}

// ---------------------------------------------------------------------------
// public API
// ---------------------------------------------------------------------------

function init(globalState) {
  if (!globalState || typeof globalState !== 'object') {
    throw new Error('active-protect: init requires a state object');
  }
  state = globalState;
  if (!state.active_protect) state.active_protect = {};
  return module.exports;
}

function enable(customer_id, device_mac, opts) {
  ensureInited();
  opts = opts || {};
  const mac = normMac(device_mac);
  if (!customer_id || !mac) {
    throw new Error('active-protect.enable: customer_id and device_mac required');
  }

  const days = Number.isFinite(opts.learning_days) && opts.learning_days >= 0
    ? opts.learning_days
    : DEFAULT_LEARNING_DAYS;

  const now = Date.now();
  const cust = ensureCustomer(customer_id);

  cust[mac] = {
    enabled: true,
    state: days === 0 ? 'enforcing' : 'learning',
    learning_started_at: now,
    learning_ends_at: now + days * DAY_MS,
    allowlist: {
      domains: new Set(),
      ips: new Set(),
      last_seen: {}, // key -> timestamp; key is the domain or ip string
    },
    blocked_count: 0,
    total_seen: 0,
    samples: [], // small ring of recent (deny + allow) flow samples for UI
  };

  return getStatus(customer_id, mac);
}

function disable(customer_id, device_mac) {
  ensureInited();
  const mac = normMac(device_mac);
  const ap = getEntry(customer_id, mac);
  if (!ap) return null;
  ap.enabled = false;
  ap.state = 'off';
  return getStatus(customer_id, mac);
}

/**
 * Ingest a single flow record observed by the box and uploaded to cloud.
 * Expected shape (lenient): { device_mac, dst_domain?, dst_ip?, ts? }.
 *
 * Behaviour:
 *   - off       : pass-through (returns {action:'allow', matched:null}).
 *   - learning  : records dst_domain + dst_ip in allowlist, returns 'allow'.
 *   - enforcing : checks against allowlist, returns 'allow' or 'deny'.
 */
function ingestFlow(flow) {
  ensureInited();
  if (!flow || typeof flow !== 'object') {
    return { action: 'allow', matched: null };
  }
  const mac = normMac(flow.device_mac || flow.mac);
  const customer_id = flow.customer_id;
  if (!customer_id || !mac) {
    return { action: 'allow', matched: null };
  }
  const ap = getEntry(customer_id, mac);
  if (!ap || !ap.enabled || ap.state === 'off') {
    return { action: 'allow', matched: null };
  }

  const now = Number.isFinite(flow.ts) ? flow.ts : Date.now();
  maybeFinishLearning(ap, now);

  const domain = normDomain(flow.dst_domain || flow.domain);
  const ip = normIp(flow.dst_ip || flow.ip);

  ap.total_seen += 1;

  if (ap.state === 'learning') {
    if (domain) {
      ap.allowlist.domains.add(domain);
      recordSeen(ap, domain, now);
    }
    if (ip) {
      ap.allowlist.ips.add(ip);
      recordSeen(ap, ip, now);
    }
    return { action: 'allow', matched: domain || ip || null, learning: true };
  }

  // enforcing
  let matched = null;
  if (domain) {
    const m = domainMatches(ap.allowlist.domains, domain);
    if (m) matched = m;
  }
  if (!matched && ip && ap.allowlist.ips.has(ip)) {
    matched = ip;
  }

  if (matched) {
    recordSeen(ap, matched, now);
    pushSample(ap, { ts: now, domain, ip, action: 'allow', matched });
    return { action: 'allow', matched };
  }

  ap.blocked_count += 1;
  pushSample(ap, { ts: now, domain, ip, action: 'deny', matched: null });
  return { action: 'deny', matched: null };
}

function pushSample(ap, sample) {
  ap.samples.push(sample);
  if (ap.samples.length > 50) ap.samples.shift();
}

function getStatus(customer_id, device_mac) {
  ensureInited();
  const mac = normMac(device_mac);
  const ap = getEntry(customer_id, mac);
  if (!ap) return null;

  maybeFinishLearning(ap, Date.now());

  return {
    state: ap.state,
    enabled: ap.enabled,
    learning_started_at: ap.learning_started_at,
    learning_ends_at: ap.learning_ends_at,
    allowlist: [
      ...Array.from(ap.allowlist.domains).map(d => ({ type: 'domain', value: d, last_seen: ap.allowlist.last_seen[d] || null })),
      ...Array.from(ap.allowlist.ips).map(i => ({ type: 'ip', value: i, last_seen: ap.allowlist.last_seen[i] || null })),
    ],
    blocked_count: ap.blocked_count,
    total_seen: ap.total_seen,
    samples: ap.samples.slice(-20),
  };
}

function finishLearningEarly(customer_id, device_mac) {
  ensureInited();
  const mac = normMac(device_mac);
  const ap = getEntry(customer_id, mac);
  if (!ap) return null;
  if (ap.state === 'learning') {
    ap.state = 'enforcing';
    ap.learning_ends_at = Date.now();
  }
  return getStatus(customer_id, mac);
}

// entry: string ("example.com" / "1.2.3.4") or {type:'domain'|'ip', value}
function _classifyEntry(entry) {
  if (entry && typeof entry === 'object') {
    if (entry.type === 'ip') return { type: 'ip', value: normIp(entry.value) };
    if (entry.type === 'domain') return { type: 'domain', value: normDomain(entry.value) };
    entry = entry.value;
  }
  const s = String(entry || '').trim();
  if (!s) return null;
  // crude: looks like an IPv4 or IPv6 address?
  if (/^[0-9.]+$/.test(s) || s.includes(':')) {
    return { type: 'ip', value: normIp(s) };
  }
  return { type: 'domain', value: normDomain(s) };
}

function addToAllowlist(customer_id, device_mac, entry) {
  ensureInited();
  const mac = normMac(device_mac);
  const ap = getEntry(customer_id, mac);
  if (!ap) return null;
  const c = _classifyEntry(entry);
  if (!c || !c.value) return getStatus(customer_id, mac);
  if (c.type === 'ip') ap.allowlist.ips.add(c.value);
  else ap.allowlist.domains.add(c.value);
  ap.allowlist.last_seen[c.value] = Date.now();
  return getStatus(customer_id, mac);
}

function removeFromAllowlist(customer_id, device_mac, entry) {
  ensureInited();
  const mac = normMac(device_mac);
  const ap = getEntry(customer_id, mac);
  if (!ap) return null;
  const c = _classifyEntry(entry);
  if (!c || !c.value) return getStatus(customer_id, mac);
  if (c.type === 'ip') ap.allowlist.ips.delete(c.value);
  else ap.allowlist.domains.delete(c.value);
  delete ap.allowlist.last_seen[c.value];
  return getStatus(customer_id, mac);
}

/**
 * Build the per-MAC payload that gets bundled into the box policy push.
 * One row per device that has Active Protect enabled (learning OR enforcing).
 * The box only enforces when state==='enforcing'; learning rows are sent so the
 * box can pre-stage the ipset (kernel ipset creation is async).
 */
function exportPolicyForBox(customer_id) {
  ensureInited();
  const cust = state.active_protect[customer_id];
  if (!cust) return [];
  const out = [];
  const now = Date.now();
  for (const mac of Object.keys(cust)) {
    const ap = cust[mac];
    if (!ap || !ap.enabled) continue;
    maybeFinishLearning(ap, now);
    out.push({
      device_mac: mac,
      mode: ap.state, // 'learning' | 'enforcing'
      enforce: ap.state === 'enforcing',
      allowed_domains: Array.from(ap.allowlist.domains).sort(),
      allowed_ips: Array.from(ap.allowlist.ips).sort(),
    });
  }
  return out;
}

/**
 * Drop allowlist entries not seen in PRUNE_AFTER_DAYS. Returns count removed.
 * Does not touch entries with no last_seen (e.g. just-added manual entries
 * before any traffic) for the first PRUNE_AFTER_DAYS after their addition --
 * we record last_seen on add, so this happens to be safe.
 */
function pruneOld(customer_id) {
  ensureInited();
  const cust = state.active_protect[customer_id];
  if (!cust) return 0;
  const cutoff = Date.now() - PRUNE_AFTER_DAYS * DAY_MS;
  let removed = 0;
  for (const mac of Object.keys(cust)) {
    const ap = cust[mac];
    if (!ap) continue;
    for (const d of Array.from(ap.allowlist.domains)) {
      const ls = ap.allowlist.last_seen[d];
      if (!ls || ls < cutoff) {
        ap.allowlist.domains.delete(d);
        delete ap.allowlist.last_seen[d];
        removed += 1;
      }
    }
    for (const ip of Array.from(ap.allowlist.ips)) {
      const ls = ap.allowlist.last_seen[ip];
      if (!ls || ls < cutoff) {
        ap.allowlist.ips.delete(ip);
        delete ap.allowlist.last_seen[ip];
        removed += 1;
      }
    }
  }
  return removed;
}

module.exports = {
  init,
  enable,
  disable,
  ingestFlow,
  getStatus,
  finishLearningEarly,
  addToAllowlist,
  removeFromAllowlist,
  exportPolicyForBox,
  pruneOld,
};
