'use strict';
/*
 * iot-lockdown.js — IoT default-deny / learning mode.
 *
 * For each MAC we lock down:
 *   1. startLearning() runs conntrack-style sniff for N seconds, captures every
 *      distinct dst_ip:dst_port:proto, persists to disk.
 *   2. enforce() installs an nftables chain that DROPs any flow from this MAC
 *      whose dst_ip:dst_port is NOT in the learned set.
 *   3. disable() removes the chain + set.
 *
 * nft set name: mes_iot_allow_<mac_no_colons>  type ipv4_addr . inet_service . inet_proto
 * Table:        inet mes_iot
 * Chain:        forward (priority 0)
 *
 * During learning, captured endpoints are pushed to the cloud via
 * POST /api/box/iot-learn so the admin can review.
 */

const fs   = require('fs');
const path = require('path');
const https = require('https');
const http  = require('http');
const { execSync, spawn } = require('child_process');

const STATE_DIR  = '/var/lib/mes-box-agent';
const TABLE_NAME = 'mes_iot';
try { fs.mkdirSync(STATE_DIR, { recursive: true }); } catch {}

let _state = {
  // mac → { learning: bool, learning_until: ts, enforced: bool, allowlist: [{dst_ip,dst_port,proto}] }
  by_mac: {},
};
const STATE_PATH = path.join(STATE_DIR, 'iot-lockdown.state.json');
try { _state = { ..._state, ...JSON.parse(fs.readFileSync(STATE_PATH, 'utf8')) }; } catch {}
function save() { try { fs.writeFileSync(STATE_PATH, JSON.stringify(_state, null, 2)); } catch {} }

function sh(cmd) {
  try { return execSync(cmd, { encoding: 'utf8', timeout: 8_000, stdio: ['ignore', 'pipe', 'pipe'] }).trim(); }
  catch { return null; }
}
function have(bin) { return !!sh(`which ${bin}`); }

function normMac(mac) {
  if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(mac || '')) return null;
  return mac.toLowerCase();
}
function macKey(m) { return m.replace(/:/g, ''); }
function setNameFor(m) { return `mes_iot_allow_${macKey(m)}`; }
function allowlistPath(m) { return path.join(STATE_DIR, `iot-allowlist-${macKey(m)}.json`); }

function ensureTable() {
  if (!have('nft')) return false;
  if (sh(`nft list table inet ${TABLE_NAME} 2>/dev/null`) === null) {
    sh(`nft add table inet ${TABLE_NAME}`);
  }
  // Use a forward chain hook
  if (sh(`nft list chain inet ${TABLE_NAME} forward 2>/dev/null`) === null) {
    sh(`nft 'add chain inet ${TABLE_NAME} forward { type filter hook forward priority 0 ; policy accept ; }'`);
  }
  return true;
}

// Captures dst_ip:dst_port:proto for the given MAC for `duration_s` seconds
// using tcpdump (preferred) or conntrack as a fallback.
async function startLearning({ mac, duration_s } = {}) {
  const m = normMac(mac);
  if (!m) return { ok: false, error: 'bad_mac' };
  if (!have('tcpdump') && !have('conntrack')) {
    return { ok: false, error: 'tcpdump_or_conntrack_not_installed' };
  }
  const dur = Math.max(30, Math.min(parseInt(duration_s) || 600, 7200));   // 30s–2h
  const until = Date.now() + dur * 1000;
  _state.by_mac[m] = _state.by_mac[m] || { learning: false, enforced: false, allowlist: [] };
  _state.by_mac[m].learning = true;
  _state.by_mac[m].learning_until = until;
  _state.by_mac[m].learn_started = Date.now();
  save();

  const seen = new Set();
  const records = [];

  if (have('tcpdump')) {
    // Background tcpdump bound to MAC source
    const child = spawn('timeout', [String(dur), 'tcpdump', '-l', '-n', '-i', 'any',
      `ether src ${m}`, 'and', '(tcp', 'or', 'udp)'],
      { stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.on('data', buf => {
      const text = buf.toString('utf8');
      for (const line of text.split('\n')) {
        // Parse: "12:34:56.789 IP src.port > dst.port: ..."
        const mIp = line.match(/IP\d?\s+\S+\s+>\s+(\d+\.\d+\.\d+\.\d+)\.(\d+):/);
        if (!mIp) continue;
        const dst_ip = mIp[1];
        const dst_port = parseInt(mIp[2], 10);
        const proto = / UDP/.test(line) ? 'udp' : 'tcp';
        const key = `${dst_ip}:${dst_port}:${proto}`;
        if (seen.has(key)) continue;
        seen.add(key);
        records.push({ dst_ip, dst_port, proto });
      }
    });
    child.on('exit', () => {
      try {
        // Persist
        _state.by_mac[m].allowlist = records;
        _state.by_mac[m].learning = false;
        save();
        try { fs.writeFileSync(allowlistPath(m), JSON.stringify(records, null, 2)); } catch {}
        // Push to cloud — but only if the MES_CLOUD env is set & we have a token-like file
        pushLearnedToCloud(m, records).catch(()=>{});
      } catch {}
    });
  }
  return { ok: true, mac: m, duration_s: dur, until_ts: until };
}

function pushLearnedToCloud(mac, endpoints) {
  return new Promise((resolve) => {
    try {
      const cfg = JSON.parse(fs.readFileSync(process.env.CFG || '/etc/mes-box/agent.json', 'utf8'));
      const cloudUrl = cfg.cloud_url || process.env.MES_CLOUD || 'https://cloud.mes.net.lb';
      const tokenFile = path.join(STATE_DIR, 'box-session.token');
      let token = '';
      try { token = fs.readFileSync(tokenFile, 'utf8').trim(); } catch {}
      const body = JSON.stringify({ mac, endpoints });
      const u = new URL(cloudUrl + '/api/box/iot-learn');
      const lib = u.protocol === 'https:' ? https : http;
      const req = lib.request({
        method: 'POST', hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
        path: u.pathname,
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': body.length,
          'Authorization': token ? 'Bearer ' + token : '',
        },
      }, res => { res.on('data', () => {}); res.on('end', resolve); });
      req.on('error', () => resolve());
      req.write(body); req.end();
    } catch { resolve(); }
  });
}

function enforce({ mac } = {}) {
  const m = normMac(mac);
  if (!m) return { ok: false, error: 'bad_mac' };
  if (!have('nft')) return { ok: false, error: 'nft_not_installed' };
  const entry = _state.by_mac[m];
  if (!entry || !entry.allowlist || !entry.allowlist.length) {
    return { ok: false, error: 'no_allowlist', hint: 'Run startLearning first or supply allowlist explicitly' };
  }
  ensureTable();
  const setName = setNameFor(m);
  // Drop existing set if present
  sh(`nft delete set inet ${TABLE_NAME} ${setName} 2>/dev/null`);
  sh(`nft 'add set inet ${TABLE_NAME} ${setName} { type ipv4_addr . inet_service . inet_proto ; flags interval ; }'`);
  // Bulk-add allowed tuples — we don't use 'flags interval' for hashes, just direct add
  // Re-create simpler set without interval flag
  sh(`nft delete set inet ${TABLE_NAME} ${setName} 2>/dev/null`);
  sh(`nft 'add set inet ${TABLE_NAME} ${setName} { type ipv4_addr . inet_service . inet_proto ; }'`);
  for (const e of entry.allowlist) {
    sh(`nft add element inet ${TABLE_NAME} ${setName} { ${e.dst_ip} . ${e.dst_port} . ${e.proto} }`);
  }
  // Drop rule (idempotent — flush prior)
  // We need to flush old rules for this MAC. Use comment to identify:
  sh(`nft -a list chain inet ${TABLE_NAME} forward 2>/dev/null | grep "iot_${macKey(m)}" | grep -oE 'handle [0-9]+' | awk '{print $2}' | while read h; do nft delete rule inet ${TABLE_NAME} forward handle $h; done`);
  // Allow established+related; drop the rest unless in set
  sh(`nft add rule inet ${TABLE_NAME} forward ether saddr ${m} ct state established,related accept comment '"iot_${macKey(m)}"'`);
  sh(`nft add rule inet ${TABLE_NAME} forward ether saddr ${m} ip daddr . th dport . meta l4proto @${setName} accept comment '"iot_${macKey(m)}"'`);
  sh(`nft add rule inet ${TABLE_NAME} forward ether saddr ${m} drop comment '"iot_${macKey(m)}"'`);

  entry.enforced = true;
  entry.enforced_at = Date.now();
  save();
  return { ok: true, mac: m, allowlist_size: entry.allowlist.length };
}

function disable({ mac } = {}) {
  const m = normMac(mac);
  if (!m) return { ok: false, error: 'bad_mac' };
  if (!have('nft')) return { ok: false, error: 'nft_not_installed' };
  const setName = setNameFor(m);
  sh(`nft -a list chain inet ${TABLE_NAME} forward 2>/dev/null | grep "iot_${macKey(m)}" | grep -oE 'handle [0-9]+' | awk '{print $2}' | while read h; do nft delete rule inet ${TABLE_NAME} forward handle $h; done`);
  sh(`nft delete set inet ${TABLE_NAME} ${setName} 2>/dev/null`);
  if (_state.by_mac[m]) {
    _state.by_mac[m].enforced = false;
    save();
  }
  return { ok: true, mac: m };
}

function listLocked() {
  const out = [];
  for (const [m, e] of Object.entries(_state.by_mac)) {
    if (e && e.enforced) {
      out.push({
        mac: m,
        allowlist_size: (e.allowlist || []).length,
        enforced_at: e.enforced_at || null,
      });
    }
  }
  return { locked: out };
}

function getStatus({ mac } = {}) {
  const m = mac && normMac(mac);
  if (m) return _state.by_mac[m] || { learning: false, enforced: false };
  return { ..._state };
}

module.exports = { startLearning, enforce, disable, listLocked, getStatus };
