'use strict';
/*
 * quarantine.js — Quarantine new (never-before-seen) devices.
 *
 * Maintains /var/lib/mes-box-agent/known-macs.json. When a never-seen MAC
 * shows up (caller passes it in via maybeQuarantineNew()), we add it to the
 * nft set `mes_quarantine`. Egress rule drops everything from quarantined
 * MACs except DNS to the box itself (for resolution).
 *
 * Auto-quarantine is OPT-IN per customer (cloud-side flag). The agent only
 * acts when called explicitly. That keeps the default friction low.
 */

const fs   = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const STATE_DIR  = '/var/lib/mes-box-agent';
const KNOWN_PATH = path.join(STATE_DIR, 'known-macs.json');
const STATE_PATH = path.join(STATE_DIR, 'quarantine.state.json');
const TABLE      = 'mes_quarantine_t';
const SET        = 'mes_quarantine';

try { fs.mkdirSync(STATE_DIR, { recursive: true }); } catch {}

function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { return fallback; }
}
function writeJson(file, obj) { try { fs.writeFileSync(file, JSON.stringify(obj, null, 2)); } catch {} }

let _known = readJson(KNOWN_PATH, { macs: [] });
let _state = readJson(STATE_PATH, { quarantined: [] });

function sh(cmd) {
  try { return execSync(cmd, { encoding: 'utf8', timeout: 8_000, stdio: ['ignore', 'pipe', 'pipe'] }).trim(); }
  catch { return null; }
}
function have(bin) { return !!sh(`which ${bin}`); }
function normMac(m) {
  if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(m || '')) return null;
  return m.toLowerCase();
}

function ensureSet() {
  if (!have('nft')) return false;
  if (sh(`nft list table inet ${TABLE} 2>/dev/null`) === null) {
    sh(`nft add table inet ${TABLE}`);
  }
  if (sh(`nft list set inet ${TABLE} ${SET} 2>/dev/null`) === null) {
    sh(`nft 'add set inet ${TABLE} ${SET} { type ether_addr ; }'`);
  }
  if (sh(`nft list chain inet ${TABLE} forward 2>/dev/null`) === null) {
    sh(`nft 'add chain inet ${TABLE} forward { type filter hook forward priority -10 ; policy accept ; }'`);
    // Allow DNS to the box itself (we treat the default gateway src as DNS host); simpler:
    // Allow UDP/TCP port 53 through, drop everything else from quarantined MACs.
    sh(`nft 'add rule inet ${TABLE} forward ether saddr @${SET} udp dport 53 accept'`);
    sh(`nft 'add rule inet ${TABLE} forward ether saddr @${SET} tcp dport 53 accept'`);
    sh(`nft 'add rule inet ${TABLE} forward ether saddr @${SET} drop'`);
  }
  return true;
}

function isKnown(mac) {
  const m = normMac(mac);
  if (!m) return true;   // bad MAC = treat as known so we don't crash
  return _known.macs.includes(m);
}

function recordKnown(mac) {
  const m = normMac(mac);
  if (!m) return;
  if (!_known.macs.includes(m)) {
    _known.macs.push(m);
    writeJson(KNOWN_PATH, _known);
  }
}

function quarantine({ mac } = {}) {
  const m = normMac(mac);
  if (!m) return { ok: false, error: 'bad_mac' };
  if (!ensureSet()) return { ok: false, error: 'nft_not_installed' };
  sh(`nft add element inet ${TABLE} ${SET} { ${m} }`);
  if (!_state.quarantined.includes(m)) {
    _state.quarantined.push(m);
    writeJson(STATE_PATH, _state);
  }
  return { ok: true, mac: m, quarantined: true };
}

function approve({ mac } = {}) {
  const m = normMac(mac);
  if (!m) return { ok: false, error: 'bad_mac' };
  if (have('nft')) sh(`nft delete element inet ${TABLE} ${SET} { ${m} } 2>/dev/null`);
  recordKnown(m);
  _state.quarantined = _state.quarantined.filter(x => x !== m);
  writeJson(STATE_PATH, _state);
  return { ok: true, mac: m, approved: true };
}

function maybeQuarantineNew({ mac } = {}) {
  // Caller (agent.js) calls this when it detects a new MAC AND the cloud says
  // auto_quarantine is on for this customer.
  const m = normMac(mac);
  if (!m) return { ok: false, error: 'bad_mac' };
  if (isKnown(m)) return { ok: true, mac: m, action: 'already_known' };
  return quarantine({ mac: m });
}

function listQuarantined() {
  return { quarantined: _state.quarantined.slice(), known_count: _known.macs.length };
}

function listKnown() {
  return { known: _known.macs.slice() };
}

module.exports = {
  quarantine, approve, maybeQuarantineNew,
  listQuarantined, listKnown, isKnown, recordKnown,
};
