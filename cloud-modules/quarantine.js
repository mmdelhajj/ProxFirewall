/*
 * quarantine.js
 *
 * Mock cloud-side implementation of Firewalla's "Quarantine new device"
 * workflow.
 *
 * When auto-quarantine is enabled for a customer, every brand-new MAC that
 * appears on their LAN is parked in a restricted state until the user makes
 * a decision via the mobile app:
 *
 *   - Approve : device leaves quarantine, joins normal allowlist on the box.
 *   - Block   : device is moved to a permanent blocklist.
 *   - Ignore  : the decision is deferred for N hours; if the user still
 *               hasn't decided when the timer expires, pruneExpired() flips
 *               the device to 'blocked' (fail-closed).
 *
 * While quarantined, the box only lets the device reach a small "essentials"
 * list (captive-portal probes + login flows) so phones don't show a broken
 * Wi-Fi indicator while the user reviews the device.
 *
 * Persistence: this module is stateless on its own; init(globalState) hangs
 * its working state off the host server's `state` object as
 * `state.quarantine`.
 */

'use strict';

const HOUR_MS = 60 * 60 * 1000;
const DEFAULT_DECISION_AFTER_H = 24;

const DEFAULT_ESSENTIALS_DOMAINS = Object.freeze([
  'captive.apple.com',          // Apple captive portal probe
  'detectportal.firefox.com',   // Firefox captive portal probe
  'connectivitycheck.gstatic.com', // Android / ChromeOS probe
  'www.msftconnecttest.com',    // Windows captive portal probe
  'accounts.google.com',        // login flow during onboarding
]);

const VALID_STATUSES = new Set(['pending', 'approved', 'blocked']);

let state = null; // host server's global state, set via init()

// optional notification sink, wired by host server (push fan-out, email, etc.)
let _notifyFn = null;

// ---------------------------------------------------------------------------
// internal helpers
// ---------------------------------------------------------------------------

function ensureInited() {
  if (!state) {
    throw new Error('quarantine: init(globalState) must be called first');
  }
}

function normMac(mac) {
  return String(mac || '').trim().toLowerCase();
}

// Accept "aa:bb:cc:dd:ee:ff" or "aabb.ccdd.eeff" or "aabbccddeeff"
function isValidMac(mac) {
  if (!mac) return false;
  return /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/.test(mac);
}

function ensureCustomerSettings(cid) {
  ensureInited();
  if (!state.quarantine.customer_settings[cid]) {
    state.quarantine.customer_settings[cid] = {
      enabled: false,
      default_decision_after_h: DEFAULT_DECISION_AFTER_H,
      essentials_domains: DEFAULT_ESSENTIALS_DOMAINS.slice(),
    };
  }
  return state.quarantine.customer_settings[cid];
}

function ensureCustomerBucket(cid) {
  ensureInited();
  if (!state.quarantine.quarantined[cid]) {
    state.quarantine.quarantined[cid] = {};
  }
  return state.quarantine.quarantined[cid];
}

function emit(event, payload) {
  if (typeof _notifyFn === 'function') {
    try { _notifyFn(event, payload); }
    catch (_) { /* never let a notifier crash the workflow */ }
  }
}

// ---------------------------------------------------------------------------
// public API
// ---------------------------------------------------------------------------

function init(globalState) {
  if (!globalState || typeof globalState !== 'object') {
    throw new Error('quarantine: init requires a state object');
  }
  state = globalState;
  if (!state.quarantine) {
    state.quarantine = {
      customer_settings: {},
      quarantined: {},
    };
  } else {
    if (!state.quarantine.customer_settings) state.quarantine.customer_settings = {};
    if (!state.quarantine.quarantined)       state.quarantine.quarantined = {};
  }
  return module.exports;
}

// host server can wire push-notification fan-out: notifyFn(event, payload)
function setNotifier(fn) {
  _notifyFn = (typeof fn === 'function') ? fn : null;
}

function enableForCustomer(cid, opts) {
  ensureInited();
  if (!cid) throw new Error('quarantine.enableForCustomer: cid required');
  opts = opts || {};
  const s = ensureCustomerSettings(cid);
  s.enabled = true;
  if (Number.isFinite(opts.default_decision_after_h) && opts.default_decision_after_h > 0) {
    s.default_decision_after_h = opts.default_decision_after_h;
  }
  if (Array.isArray(opts.essentials_domains) && opts.essentials_domains.length) {
    s.essentials_domains = opts.essentials_domains
      .map(d => String(d || '').trim().toLowerCase())
      .filter(Boolean);
  }
  return Object.assign({}, s);
}

function disableForCustomer(cid) {
  ensureInited();
  const s = ensureCustomerSettings(cid);
  s.enabled = false;
  return Object.assign({}, s);
}

function isEnabled(cid) {
  ensureInited();
  const s = state.quarantine.customer_settings[cid];
  return !!(s && s.enabled);
}

/**
 * Called when the box reports a brand-new MAC.
 * Returns the quarantine entry, or null if auto-quarantine is off for the cid.
 *
 * Idempotent: re-ingesting an already-tracked MAC just refreshes hostname/vendor
 * if they were previously unknown, and never overwrites a non-pending status.
 */
function ingestNewDevice(cid, mac, hostname, vendor) {
  ensureInited();
  if (!cid) throw new Error('quarantine.ingestNewDevice: cid required');

  const m = normMac(mac);
  if (!isValidMac(m)) {
    throw new Error('quarantine.ingestNewDevice: invalid mac: ' + mac);
  }

  const settings = ensureCustomerSettings(cid);
  if (!settings.enabled) return null;

  const bucket = ensureCustomerBucket(cid);
  const now = Date.now();

  if (bucket[m]) {
    // already tracked - fill in late-arriving metadata, leave status alone
    const e = bucket[m];
    if (!e.hostname && hostname) e.hostname = String(hostname);
    if (!e.vendor && vendor)     e.vendor   = String(vendor);
    return Object.assign({ mac: m }, e);
  }

  const ttlMs = settings.default_decision_after_h * HOUR_MS;
  const entry = {
    hostname: hostname ? String(hostname) : null,
    vendor:   vendor   ? String(vendor)   : null,
    first_seen: now,
    expires_at: now + ttlMs,
    status: 'pending',
    last_decision_ts: null,
  };
  bucket[m] = entry;

  emit('quarantine.new_device', {
    customer_id: cid,
    mac: m,
    hostname: entry.hostname,
    vendor: entry.vendor,
    first_seen: entry.first_seen,
    expires_at: entry.expires_at,
    // mobile app shows this as: "New device joined - review and approve"
    push_title: 'New device joined',
    push_body: 'Review and approve ' + (entry.hostname || entry.vendor || m),
  });

  return Object.assign({ mac: m }, entry);
}

function _setStatus(cid, mac, status) {
  ensureInited();
  if (!VALID_STATUSES.has(status)) {
    throw new Error('quarantine: invalid status: ' + status);
  }
  const m = normMac(mac);
  const bucket = state.quarantine.quarantined[cid];
  if (!bucket || !bucket[m]) return null;
  bucket[m].status = status;
  bucket[m].last_decision_ts = Date.now();
  return Object.assign({ mac: m }, bucket[m]);
}

function approve(cid, mac) {
  const m = normMac(mac);
  const updated = _setStatus(cid, m, 'approved');
  if (!updated) return null;

  // Approved devices leave quarantine entirely - they're handed back to the
  // box's normal allowlist. We delete the entry so exportPolicyForBox()
  // immediately stops including them in the quarantine ipset.
  delete state.quarantine.quarantined[cid][m];

  emit('quarantine.approved', { customer_id: cid, mac: m });
  return updated;
}

function block(cid, mac) {
  const updated = _setStatus(cid, mac, 'blocked');
  if (!updated) return null;
  // Blocked entries stay in the bucket so the box keeps refusing them
  // until the user explicitly removes the device from their network.
  emit('quarantine.blocked', { customer_id: cid, mac: updated.mac });
  return updated;
}

function ignoreFor(cid, mac, hours) {
  ensureInited();
  const m = normMac(mac);
  const bucket = state.quarantine.quarantined[cid];
  if (!bucket || !bucket[m]) return null;

  const h = (Number.isFinite(hours) && hours > 0) ? hours : DEFAULT_DECISION_AFTER_H;
  bucket[m].expires_at = Date.now() + h * HOUR_MS;
  bucket[m].last_decision_ts = Date.now();
  // status stays 'pending' - just pushing the deadline out

  emit('quarantine.ignored', {
    customer_id: cid,
    mac: m,
    expires_at: bucket[m].expires_at,
  });
  return Object.assign({ mac: m }, bucket[m]);
}

function getQuarantined(cid) {
  ensureInited();
  const bucket = state.quarantine.quarantined[cid];
  if (!bucket) return [];
  const out = [];
  for (const mac of Object.keys(bucket)) {
    const e = bucket[mac];
    out.push({
      mac,
      hostname: e.hostname,
      vendor: e.vendor,
      first_seen: e.first_seen,
      expires_at: e.expires_at,
      status: e.status,
      last_decision_ts: e.last_decision_ts,
    });
  }
  // newest first - most relevant for the app's review screen
  out.sort((a, b) => b.first_seen - a.first_seen);
  return out;
}

/**
 * Flatten current quarantine state into the box-side policy bundle.
 * The box translates this into an nftables ipset: any packet from a MAC
 * in the set is dropped unless dst is in `essentials_domains`.
 *
 * Approved devices are already removed from the bucket, so they won't
 * appear here.
 */
function exportPolicyForBox(cid) {
  ensureInited();
  const settings = state.quarantine.customer_settings[cid];
  const bucket = state.quarantine.quarantined[cid];
  const out = {
    enabled: !!(settings && settings.enabled),
    essentials_domains: (settings && settings.essentials_domains)
      ? settings.essentials_domains.slice()
      : DEFAULT_ESSENTIALS_DOMAINS.slice(),
    quarantined_macs: [],
    blocked_macs: [],
  };
  if (!bucket) return out;

  for (const mac of Object.keys(bucket)) {
    const e = bucket[mac];
    if (e.status === 'pending')      out.quarantined_macs.push(mac);
    else if (e.status === 'blocked') out.blocked_macs.push(mac);
    // 'approved' shouldn't be present (approve() deletes the row), but skip
    // defensively just in case.
  }
  out.quarantined_macs.sort();
  out.blocked_macs.sort();
  return out;
}

/**
 * Run periodically (recommend hourly). Any pending device whose expires_at
 * is now in the past flips to 'blocked' (fail-closed - users who never
 * respond to the push almost certainly don't want a random device on
 * their network).
 *
 * Returns the list of MACs that were just auto-blocked, so the caller can
 * surface them in an audit log.
 */
function pruneExpired(cid) {
  ensureInited();
  const bucket = state.quarantine.quarantined[cid];
  if (!bucket) return [];

  const now = Date.now();
  const flipped = [];
  for (const mac of Object.keys(bucket)) {
    const e = bucket[mac];
    if (e.status !== 'pending') continue;
    if (e.expires_at && e.expires_at <= now) {
      e.status = 'blocked';
      e.last_decision_ts = now;
      flipped.push(mac);
      emit('quarantine.auto_blocked', {
        customer_id: cid,
        mac,
        reason: 'no_decision_within_window',
      });
    }
  }
  return flipped;
}

module.exports = {
  init,
  setNotifier,
  enableForCustomer,
  disableForCustomer,
  isEnabled,
  ingestNewDevice,
  approve,
  block,
  ignoreFor,
  getQuarantined,
  exportPolicyForBox,
  pruneExpired,
  // exposed for tests / introspection
  DEFAULT_ESSENTIALS_DOMAINS,
  DEFAULT_DECISION_AFTER_H,
};
