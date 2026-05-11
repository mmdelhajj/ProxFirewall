'use strict';
/*
 * openvpn-client.js — OpenVPN CLIENT mode.
 *
 * Lets the box route LAN traffic OUT through a commercial OpenVPN provider.
 * Customer pastes a .ovpn file; we drop it into /etc/openvpn/client/, bring
 * it up with `openvpn --daemon`, and let it install its own routes.
 *
 * IMPORTANT: per-device routing is NOT supported here. OpenVPN uses TUN with
 * its own routing table, which doesn't play nicely with iptables fwmark
 * policy routing without significant kernel-side fiddling. So this is
 * all-or-nothing: when active, ALL outbound LAN traffic exits via the tunnel.
 *
 * Mirrors wg-client.js shape: addProfile, removeProfile, listProfiles,
 * start, stop, getStatus.
 */

const fs   = require('fs');
const path = require('path');
const { execSync, spawn } = require('child_process');

const OVPN_DIR = '/etc/openvpn/client';
const PREFIX   = 'mes-';
const STATE_DIR = '/var/lib/mes-box-agent';
try { fs.mkdirSync(OVPN_DIR, { recursive: true }); } catch {}
try { fs.mkdirSync(STATE_DIR, { recursive: true }); } catch {}
const STATE_PATH = path.join(STATE_DIR, 'openvpn-client.state.json');

let _state = { active_id: null };
try { _state = { ..._state, ...JSON.parse(fs.readFileSync(STATE_PATH, 'utf8')) }; } catch {}
function save() { try { fs.writeFileSync(STATE_PATH, JSON.stringify(_state, null, 2)); } catch {} }

function sh(cmd) {
  try { return execSync(cmd, { encoding: 'utf8', timeout: 8_000, stdio: ['ignore', 'pipe', 'pipe'] }).trim(); }
  catch { return null; }
}
function have(bin) { return !!sh(`which ${bin}`); }

function safeLabel(label) {
  const s = String(label || '').toLowerCase().replace(/[^a-z0-9]+/g, '').slice(0, 12);
  if (!s) throw new Error('label must contain at least one alphanumeric character');
  return s;
}
function profileIdFromLabel(label) { return PREFIX + safeLabel(label); }
function confPath(profile_id) { return path.join(OVPN_DIR, profile_id + '.conf'); }
function pidPath(profile_id)  { return path.join(STATE_DIR, profile_id + '.pid'); }

function listProfileFiles() {
  try { return fs.readdirSync(OVPN_DIR).filter(f => f.startsWith(PREFIX) && f.endsWith('.conf')); }
  catch { return []; }
}

function isRunning(profile_id) {
  try {
    const pid = parseInt(fs.readFileSync(pidPath(profile_id), 'utf8'), 10);
    if (!pid) return false;
    process.kill(pid, 0);
    return true;
  } catch { return false; }
}

function addProfile({ label, ovpn_text } = {}) {
  if (!label || typeof label !== 'string') return { ok: false, error: 'label_required' };
  if (!ovpn_text || typeof ovpn_text !== 'string') return { ok: false, error: 'ovpn_text_required' };
  // Sanity-check: must have at least 'remote' and 'dev tun'
  if (ovpn_text.indexOf('remote ') === -1) return { ok: false, error: 'ovpn_missing_remote' };
  let profile_id;
  try { profile_id = profileIdFromLabel(label); }
  catch (e) { return { ok: false, error: e.message }; }
  const p = confPath(profile_id);
  if (fs.existsSync(p)) return { ok: false, error: 'profile_exists', profile_id };
  fs.writeFileSync(p, ovpn_text, { mode: 0o600 });
  return { ok: true, profile_id };
}

function removeProfile(profile_id) {
  if (!profile_id || !profile_id.startsWith(PREFIX)) return { ok: false, error: 'bad_profile_id' };
  if (isRunning(profile_id)) {
    try { stop(profile_id); } catch {}
  }
  try { fs.unlinkSync(confPath(profile_id)); } catch {}
  return { ok: true };
}

function listProfiles() {
  return listProfileFiles().map(f => {
    const profile_id = f.replace(/\.conf$/, '');
    const label = profile_id.slice(PREFIX.length);
    let endpoint = '';
    try {
      const conf = fs.readFileSync(path.join(OVPN_DIR, f), 'utf8');
      const m = conf.match(/^\s*remote\s+(\S+)\s+(\d+)/m);
      if (m) endpoint = `${m[1]}:${m[2]}`;
    } catch {}
    return { id: profile_id, label, active: isRunning(profile_id), endpoint };
  });
}

function stopOthers(except_id) {
  for (const f of listProfileFiles()) {
    const id = f.replace(/\.conf$/, '');
    if (id === except_id) continue;
    if (isRunning(id)) { try { stop(id); } catch {} }
  }
}

function start(profile_id) {
  if (!profile_id || !profile_id.startsWith(PREFIX)) return { ok: false, error: 'bad_profile_id' };
  if (!have('openvpn')) return { ok: false, error: 'openvpn_not_installed', hint: 'apt-get install -y openvpn' };
  const p = confPath(profile_id);
  if (!fs.existsSync(p)) return { ok: false, error: 'profile_not_found' };
  // Only one active at a time
  stopOthers(profile_id);
  if (isRunning(profile_id)) return { ok: true, already_running: true, profile_id };
  // Spawn as daemon. --writepid lets us track it.
  const log = path.join('/var/log', 'mes-' + profile_id + '.log');
  const args = ['--config', p, '--daemon', 'mes-' + profile_id,
                '--writepid', pidPath(profile_id), '--log', log];
  try {
    execSync(`openvpn ${args.map(a => `"${a.replace(/"/g, '\\"')}"`).join(' ')}`, { timeout: 10_000 });
  } catch (e) { return { ok: false, error: 'openvpn_start_failed', detail: (e.message || '').slice(0, 400) }; }
  _state.active_id = profile_id;
  save();
  return { ok: true, profile_id, log };
}

function stop(profile_id) {
  if (!profile_id || !profile_id.startsWith(PREFIX)) return { ok: false, error: 'bad_profile_id' };
  try {
    const pid = parseInt(fs.readFileSync(pidPath(profile_id), 'utf8'), 10);
    if (pid) { try { process.kill(pid, 'SIGTERM'); } catch {} }
  } catch {}
  try { fs.unlinkSync(pidPath(profile_id)); } catch {}
  if (_state.active_id === profile_id) { _state.active_id = null; save(); }
  return { ok: true, profile_id, active: false };
}

function getStatus() {
  const profiles = listProfiles();
  const active = profiles.find(p => p.active) || null;
  return {
    active_profile: active ? active.id : null,
    profiles,
    openvpn_installed: have('openvpn'),
  };
}

module.exports = { addProfile, removeProfile, listProfiles, start, stop, getStatus };
