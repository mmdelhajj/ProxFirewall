// device-throughput.js — per-MAC live bytes/sec sampling.
//
// Strategy:
//   For each LAN device, install one iptables FORWARD rule that matches
//   src=<device_ip> (upstream) and another matching dst=<device_ip> (downstream).
//   These rules don't ACCEPT/DROP — just count and continue. Sampling reads
//   the byte counters, diffs them since the last sample, and reports bytes/sec
//   per direction per MAC.
//
// Why src/dst IP (not MAC) for the match:
//   `-m mac --mac-source` only works on bridges, not regular forwarding. In
//   Simple Mode the box forwards via IP, so source MAC isn't preserved through
//   the FORWARD chain by default. Matching on src/dst IP (the device's LAN IP)
//   is reliable and the agent already knows IP↔MAC from `ip neigh`.
//
// Rules are reconciled on every sample call so new devices get rules added,
// and stale-IP devices (DHCP'd a new address) get refreshed.
'use strict';
const { execSync } = require('child_process');

const COMMENT_PREFIX = 'mes-devtp-';
const MAX_DEVICES = 200;

let _last = new Map();   // mac → { up_bytes, down_bytes, ts, ip }
let _devices = new Map(); // mac → ip (current install state)

function sh(cmd, opts = {}) {
  try { return execSync(cmd, { encoding: 'utf8', timeout: 4000, stdio: ['ignore', 'pipe', 'pipe'], ...opts }).trim(); }
  catch { return null; }
}

function _readArpTable() {
  const out = sh('ip neigh show');
  if (!out) return new Map();
  const m = new Map();
  for (const line of out.split('\n')) {
    const r = line.match(/^(\d+\.\d+\.\d+\.\d+) .* lladdr ([0-9a-f:]{17}) /i);
    if (r) m.set(r[2].toLowerCase(), r[1]);
  }
  return m;
}

function _readCounters() {
  // iptables -L FORWARD -v -n -x — preserve byte counts, find lines with our comment
  const out = sh('iptables -L FORWARD -v -n -x');
  if (!out) return new Map();
  const m = new Map();
  for (const line of out.split('\n')) {
    const tagM = line.match(/mes-devtp-(up|down)-([0-9a-f-]+)/);
    if (!tagM) continue;
    const parts = line.trim().split(/\s+/);
    const bytes = parseInt(parts[1]) || 0;
    const macKey = tagM[2].replace(/-/g, ':');
    const dir = tagM[1];
    const cur = m.get(macKey) || { up: 0, down: 0 };
    cur[dir] = bytes;
    m.set(macKey, cur);
  }
  return m;
}

function _macToTag(mac) { return mac.replace(/:/g, '-'); }

function _installRule(mac, ip) {
  const tag = _macToTag(mac);
  // `iptables -C` exits 0 if rule exists (sh returns ""). Exits non-zero if not
  // (sh returns null because execSync throws). Bug fix: empty string is falsy,
  // so `!sh(check)` was true for BOTH cases — added the rule every time and
  // produced duplicates over hundreds of sample cycles. Must compare to null.
  const upCheck = sh(`iptables -C FORWARD -s ${ip} -m comment --comment "${COMMENT_PREFIX}up-${tag}" 2>/dev/null`);
  const dnCheck = sh(`iptables -C FORWARD -d ${ip} -m comment --comment "${COMMENT_PREFIX}down-${tag}" 2>/dev/null`);
  if (upCheck === null) sh(`iptables -I FORWARD -s ${ip} -m comment --comment "${COMMENT_PREFIX}up-${tag}"`);
  if (dnCheck === null) sh(`iptables -I FORWARD -d ${ip} -m comment --comment "${COMMENT_PREFIX}down-${tag}"`);
}

// Wipe ALL mes-devtp rules in FORWARD before reconciling from scratch.
// Called once per agent boot to clear duplicates accumulated by old buggy
// installs. After this, the idempotency check above keeps things clean.
function _flushAllRules() {
  let lines;
  try { lines = execSync('iptables -L FORWARD --line-numbers -n -v -x', { encoding: 'utf8' }).split('\n'); }
  catch { return; }
  // Walk lines bottom-up so deletes don't shift remaining indexes
  const toDelete = [];
  for (const line of lines) {
    if (!/mes-devtp-/.test(line)) continue;
    const m = line.match(/^\s*(\d+)\s/);
    if (m) toDelete.push(parseInt(m[1]));
  }
  toDelete.sort((a, b) => b - a);  // descending
  for (const num of toDelete) sh(`iptables -D FORWARD ${num}`);
}

function _removeRule(mac, ip) {
  const tag = _macToTag(mac);
  sh(`iptables -D FORWARD -s ${ip} -m comment --comment "${COMMENT_PREFIX}up-${tag}" 2>/dev/null`);
  sh(`iptables -D FORWARD -d ${ip} -m comment --comment "${COMMENT_PREFIX}down-${tag}" 2>/dev/null`);
}

function _reconcileRules() {
  const arp = _readArpTable();
  // Add rules for new devices and IPs that changed
  let count = 0;
  for (const [mac, ip] of arp) {
    if (count >= MAX_DEVICES) break;
    const prev = _devices.get(mac);
    if (prev !== ip) {
      if (prev) _removeRule(mac, prev);
      _installRule(mac, ip);
      _devices.set(mac, ip);
    }
    count++;
  }
  // Remove rules for devices that disappeared
  for (const [mac, ip] of _devices) {
    if (!arp.has(mac)) {
      _removeRule(mac, ip);
      _devices.delete(mac);
      _last.delete(mac);
    }
  }
}

// Returns [{mac, ip, rx_bps, tx_bps, bytes_rx_delta, bytes_tx_delta}] for
// devices with any change since last call. The byte deltas are the raw
// counted bytes since the last sample — cloud sums them into monthly usage.
function sample() {
  try { _reconcileRules(); } catch {}
  const counters = _readCounters();
  const now = Date.now();
  const out = [];
  for (const [mac, c] of counters) {
    const prev = _last.get(mac);
    _last.set(mac, { up: c.up, down: c.down, ts: now });
    if (!prev) continue;
    const elapsed = (now - prev.ts) / 1000;
    if (elapsed < 0.5) continue;
    const bytes_rx_delta = Math.max(0, c.down - prev.down);
    const bytes_tx_delta = Math.max(0, c.up   - prev.up);
    const rx_bps = Math.round(bytes_rx_delta / elapsed);
    const tx_bps = Math.round(bytes_tx_delta / elapsed);
    if (bytes_rx_delta === 0 && bytes_tx_delta === 0) continue;
    out.push({ mac, ip: _devices.get(mac), rx_bps, tx_bps, bytes_rx_delta, bytes_tx_delta });
  }
  return out;
}

function clearAll() {
  for (const [mac, ip] of _devices) _removeRule(mac, ip);
  _devices.clear();
  _last.clear();
}

module.exports = { sample, clearAll, flushAllRules: _flushAllRules };
