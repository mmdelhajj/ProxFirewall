/**
 * wg-client.js — WireGuard CLIENT mode.
 *
 * Lets the box route LAN traffic OUT through a commercial VPN provider
 * (Mullvad, ProtonVPN, NordVPN, AzireVPN, custom). The customer pastes
 * a .conf file from their provider; we drop it into /etc/wireguard,
 * bring it up with wg-quick, and add policy routing so marked packets
 * exit via the WG interface.
 *
 * Mutually exclusive with wg-server: only ONE client profile can be
 * active at a time. start() auto-stops any other active profile first.
 *
 * Per-device routing: tag a MAC with `routeDevice(mac, profile_id)` to
 * mark its packets (fwmark 1) so they hit the policy route. Pass null
 * to drop the mark.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const WG_DIR    = '/etc/wireguard';
const PREFIX    = 'mes-client-';            // our profiles only
const FWMARK    = '1';
const RT_TABLE  = '200';

function sh(cmd, opts = {}) {
  try { return execSync(cmd, { encoding: 'utf8', timeout: 8_000, stdio: ['ignore', 'pipe', 'pipe'], ...opts }).trim(); }
  catch (e) { return null; }
}

function shThrow(cmd) {
  return execSync(cmd, { encoding: 'utf8', timeout: 8_000, stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

function safeLabel(label) {
  // Filename-safe slug — wg-quick interface names ≤ 15 chars, "mes-client-" is 11 → leave 4 for label
  const s = String(label || '').toLowerCase().replace(/[^a-z0-9]+/g, '').slice(0, 4);
  if (!s) throw new Error('label must contain at least one alphanumeric character');
  return s;
}

function profileIdFromLabel(label) { return PREFIX + safeLabel(label); }
function ifaceFromId(profile_id)   { return profile_id; }
function confPathFromId(profile_id){ return path.join(WG_DIR, profile_id + '.conf'); }

function isInterfaceUp(iface) {
  return !!sh(`wg show ${iface} 2>/dev/null`);
}

function listActiveInterfaces() {
  const out = sh('wg show interfaces') || '';
  return out.split(/\s+/).filter(n => n.startsWith(PREFIX));
}

// ─── public API ──────────────────────────────────────────────────────────

function addProfile({ label, conf_text }) {
  if (!label || typeof label !== 'string') return { ok: false, error: 'label_required' };
  if (!conf_text || typeof conf_text !== 'string') return { ok: false, error: 'conf_text_required' };

  // Sanity-check the conf has the four mandatory tokens
  const checks = ['[Interface]', 'PrivateKey', '[Peer]', 'Endpoint'];
  for (const tok of checks) {
    if (conf_text.indexOf(tok) === -1) {
      return { ok: false, error: `conf_missing_${tok.replace(/[^a-z]/gi,'').toLowerCase()}` };
    }
  }

  let profile_id;
  try { profile_id = profileIdFromLabel(label); }
  catch (e) { return { ok: false, error: e.message }; }

  try { fs.mkdirSync(WG_DIR, { recursive: true }); } catch {}
  const p = confPathFromId(profile_id);
  if (fs.existsSync(p)) return { ok: false, error: 'profile_exists', profile_id };

  fs.writeFileSync(p, conf_text, { mode: 0o600 });
  try { fs.chmodSync(p, 0o600); } catch {}
  return { ok: true, profile_id };
}

function removeProfile(profile_id) {
  if (!profile_id || !profile_id.startsWith(PREFIX)) return { ok: false, error: 'bad_profile_id' };
  const iface = ifaceFromId(profile_id);
  // Bring down first if up
  if (isInterfaceUp(iface)) {
    try { stop(profile_id); } catch {}
  }
  const p = confPathFromId(profile_id);
  if (fs.existsSync(p)) { try { fs.unlinkSync(p); } catch {} }
  return { ok: true };
}

function listProfiles() {
  let files = [];
  try { files = fs.readdirSync(WG_DIR).filter(f => f.startsWith(PREFIX) && f.endsWith('.conf')); }
  catch { return []; }

  const active = new Set(listActiveInterfaces());
  return files.map(f => {
    const profile_id = f.replace(/\.conf$/, '');
    const label = profile_id.slice(PREFIX.length);
    let endpoint = '', last_handshake = 0;
    try {
      const conf = fs.readFileSync(path.join(WG_DIR, f), 'utf8');
      const m = conf.match(/^\s*Endpoint\s*=\s*(.+)$/mi);
      if (m) endpoint = m[1].trim();
    } catch {}
    if (active.has(profile_id)) {
      const out = sh(`wg show ${profile_id} latest-handshakes`) || '';
      const m = out.match(/\s+(\d+)\s*$/);
      if (m) last_handshake = parseInt(m[1], 10) * 1000;  // wg gives seconds-epoch
    }
    return { id: profile_id, label, active: active.has(profile_id), endpoint, last_handshake };
  });
}

function applyPolicyRouting(iface) {
  // fwmark on PREROUTING from LAN — userspace can later refine which MACs get marked
  // Idempotent: -C check before -A append
  const lanIf = process.env.LAN_IF || 'eth0';
  try {
    if (sh(`iptables -t mangle -C PREROUTING -i ${lanIf} -j MARK --set-mark ${FWMARK} 2>/dev/null`) === null) {
      sh(`iptables -t mangle -A PREROUTING -i ${lanIf} -j MARK --set-mark ${FWMARK}`);
    }
  } catch {}
  try {
    if (!sh(`ip rule list fwmark ${FWMARK}`)?.includes(`lookup ${RT_TABLE}`)) {
      sh(`ip rule add fwmark ${FWMARK} table ${RT_TABLE}`);
    }
  } catch {}
  try { sh(`ip route flush table ${RT_TABLE} 2>/dev/null`); } catch {}
  try { sh(`ip route add default dev ${iface} table ${RT_TABLE}`); } catch {}
}

function clearPolicyRouting() {
  const lanIf = process.env.LAN_IF || 'eth0';
  // Remove the catch-all PREROUTING mark; per-MAC marks (added by routeDevice) live separately.
  while (sh(`iptables -t mangle -C PREROUTING -i ${lanIf} -j MARK --set-mark ${FWMARK} 2>/dev/null`) !== null) {
    if (sh(`iptables -t mangle -D PREROUTING -i ${lanIf} -j MARK --set-mark ${FWMARK}`) === null) break;
  }
  while (sh(`ip rule list fwmark ${FWMARK}`)?.includes(`lookup ${RT_TABLE}`)) {
    if (sh(`ip rule del fwmark ${FWMARK} table ${RT_TABLE}`) === null) break;
  }
  try { sh(`ip route flush table ${RT_TABLE} 2>/dev/null`); } catch {}
}

function stopOthers(except_id) {
  for (const iface of listActiveInterfaces()) {
    if (iface === except_id) continue;
    try { sh(`wg-quick down ${iface}`); } catch {}
  }
}

function start(profile_id) {
  if (!profile_id || !profile_id.startsWith(PREFIX)) return { ok: false, error: 'bad_profile_id' };
  const p = confPathFromId(profile_id);
  if (!fs.existsSync(p)) return { ok: false, error: 'profile_not_found' };
  const iface = ifaceFromId(profile_id);

  // Only one active at a time
  stopOthers(profile_id);

  if (!isInterfaceUp(iface)) {
    try { shThrow(`wg-quick up ${iface}`); }
    catch (e) { return { ok: false, error: 'wg_quick_up_failed', detail: (e.message || '').slice(0, 500) }; }
  }
  applyPolicyRouting(iface);
  return { ok: true, profile_id, active: true };
}

function stop(profile_id) {
  if (!profile_id || !profile_id.startsWith(PREFIX)) return { ok: false, error: 'bad_profile_id' };
  const iface = ifaceFromId(profile_id);
  if (isInterfaceUp(iface)) {
    try { sh(`wg-quick down ${iface}`); } catch {}
  }
  // Only clear global policy routing if no other client is active
  if (listActiveInterfaces().length === 0) clearPolicyRouting();
  return { ok: true, profile_id, active: false };
}

function getStatus() {
  const ifaces = listActiveInterfaces();
  if (!ifaces.length) return { active_profile: null };
  const iface = ifaces[0];
  const dump = sh(`wg show ${iface} dump`) || '';
  // dump format: first line = interface; subsequent lines = peers
  // peer cols: pubkey psk endpoint allowed-ips latest_handshake rx_bytes tx_bytes keepalive
  const lines = dump.split('\n').filter(Boolean);
  let last_handshake = 0, bytes_rx = 0, bytes_tx = 0;
  for (let i = 1; i < lines.length; i++) {
    const cols = lines[i].split('\t');
    if (cols.length >= 7) {
      last_handshake = Math.max(last_handshake, parseInt(cols[4], 10) * 1000 || 0);
      bytes_rx += parseInt(cols[5], 10) || 0;
      bytes_tx += parseInt(cols[6], 10) || 0;
    }
  }
  return { active_profile: iface, last_handshake, bytes_rx, bytes_tx };
}

function routeDevice(mac, profile_id_or_null) {
  if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(mac)) return { ok: false, error: 'bad_mac' };
  const m = mac.toLowerCase();
  // Always remove any existing per-MAC mark first (idempotent)
  while (sh(`iptables -t mangle -C PREROUTING -m mac --mac-source ${m} -j MARK --set-mark ${FWMARK} 2>/dev/null`) !== null) {
    if (sh(`iptables -t mangle -D PREROUTING -m mac --mac-source ${m} -j MARK --set-mark ${FWMARK}`) === null) break;
  }
  if (profile_id_or_null === null || profile_id_or_null === undefined) {
    return { ok: true, mac: m, routed: false };
  }
  if (!String(profile_id_or_null).startsWith(PREFIX)) return { ok: false, error: 'bad_profile_id' };
  // Ensure the rule + table exist (in case nobody started a profile yet — packets will just have no route until then)
  if (!sh(`ip rule list fwmark ${FWMARK}`)?.includes(`lookup ${RT_TABLE}`)) {
    sh(`ip rule add fwmark ${FWMARK} table ${RT_TABLE}`);
  }
  sh(`iptables -t mangle -A PREROUTING -m mac --mac-source ${m} -j MARK --set-mark ${FWMARK}`);
  return { ok: true, mac: m, routed: true, profile_id: profile_id_or_null };
}

module.exports = {
  addProfile,
  removeProfile,
  listProfiles,
  start,
  stop,
  getStatus,
  routeDevice,
};
