'use strict';

/*
 * router-mode.js — Box replaces the customer's router entirely.
 *
 * Responsibilities:
 *   - IP forwarding (sysctl + persisted)
 *   - NAT/MASQUERADE on the WAN interface
 *   - Permissive FORWARD rule on the LAN side
 *   - DHCP+DNS for the LAN (delegated to dhcp-mode, with router_mode=true so
 *     the box advertises *itself* as default gateway in DHCP option 3)
 *
 * WAN/LAN auto-detection: the iface carrying the default route is WAN. The
 * first other physical iface (excluding lo / docker / virtual bridges that
 * are not ours) is LAN. Caller can override via opts.wan_iface / opts.lan_iface.
 *
 * Idempotent: every iptables rule is added with `-C` first; sysctl writes are
 * always safe to repeat. Running install twice on the same config is a no-op.
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const SYSCTL_PATH = '/etc/sysctl.d/99-mes-router.conf';
const STATE_PATH = '/var/lib/mes-box-agent/router-mode.state.json';

let dhcpMode = null;
try { dhcpMode = require('./dhcp-mode'); } catch (e) { /* loaded lazily — install will surface error */ }

try { fs.mkdirSync(path.dirname(STATE_PATH), { recursive: true }); } catch {}

let _state = { enabled: false, wan_iface: null, lan_iface: null, started_at: null };
try { _state = { ..._state, ...JSON.parse(fs.readFileSync(STATE_PATH, 'utf8')) }; } catch {}
function save() { try { fs.writeFileSync(STATE_PATH, JSON.stringify(_state, null, 2)); } catch {} }

function sh(cmd, opts = {}) {
  try {
    return execSync(cmd, { encoding: 'utf8', timeout: 10_000, stdio: ['ignore', 'pipe', 'pipe'], ...opts }).trim();
  } catch { return null; }
}

function shOk(cmd) {
  try { execSync(cmd, { stdio: 'ignore', timeout: 10_000 }); return true; }
  catch { return false; }
}

function dnsmasqInstalled() { return !!sh('which dnsmasq'); }
function iptablesInstalled() { return !!sh('which iptables'); }

// Parse /proc/net/route. Default route = destination 00000000.
// Everything else points us at LAN-side interfaces.
function detectInterfaces() {
  let routes;
  try { routes = fs.readFileSync('/proc/net/route', 'utf8').trim().split('\n').slice(1); }
  catch { return { wan: null, lans: [] }; }

  let wan = null;
  const ifaces = new Set();
  for (const line of routes) {
    const cols = line.split(/\s+/);
    const [iface, dest] = cols;
    if (!iface || iface === 'lo') continue;
    ifaces.add(iface);
    if (dest === '00000000' && !wan) wan = iface;
  }
  const lans = [...ifaces].filter(i => i !== wan && !/^(docker|br-|veth|virbr|tun|tap|wg)/.test(i));
  return { wan, lans };
}

function enableIpForward() {
  shOk('sysctl -w net.ipv4.ip_forward=1');
  try {
    fs.writeFileSync(SYSCTL_PATH, 'net.ipv4.ip_forward=1\n');
  } catch {}
}

function disableIpForward() {
  shOk('sysctl -w net.ipv4.ip_forward=0');
  try { fs.unlinkSync(SYSCTL_PATH); } catch {}
}

// iptables -C returns exit 0 if the rule exists, non-zero otherwise.
// We only -A when -C says it's missing — keeps repeated installs from stacking duplicate rules.
function ensureRule(table, chain, ruleArgs) {
  const tableFlag = table ? `-t ${table} ` : '';
  const check = `iptables ${tableFlag}-C ${chain} ${ruleArgs} 2>/dev/null`;
  if (shOk(check)) return false;
  shOk(`iptables ${tableFlag}-A ${chain} ${ruleArgs}`);
  return true;
}

function removeRule(table, chain, ruleArgs) {
  const tableFlag = table ? `-t ${table} ` : '';
  // Loop in case duplicates somehow accumulated from earlier non-idempotent versions.
  for (let i = 0; i < 5; i++) {
    if (!shOk(`iptables ${tableFlag}-C ${chain} ${ruleArgs} 2>/dev/null`)) break;
    shOk(`iptables ${tableFlag}-D ${chain} ${ruleArgs}`);
  }
}

function installAndConfigure(opts = {}) {
  if (!iptablesInstalled()) return { ok: false, error: 'iptables_not_installed' };
  if (!dnsmasqInstalled()) return { ok: false, error: 'dnsmasq_not_installed', hint: 'apt-get install -y dnsmasq' };
  if (!dhcpMode) {
    try { dhcpMode = require('./dhcp-mode'); }
    catch (e) { return { ok: false, error: 'dhcp_mode_module_missing', detail: e.message }; }
  }

  const detected = detectInterfaces();
  const wan_iface = opts.wan_iface || detected.wan;
  const lan_iface = opts.lan_iface || detected.lans[0] || detected.wan;
  if (!wan_iface) return { ok: false, error: 'wan_iface_unknown', hint: 'no default route' };
  if (!lan_iface) return { ok: false, error: 'lan_iface_unknown' };

  enableIpForward();

  const addedNat = ensureRule('nat', 'POSTROUTING', `-o ${wan_iface} -j MASQUERADE`);
  const addedFwd = ensureRule(null, 'FORWARD', `-i ${lan_iface} -j ACCEPT`);
  // Return path so reply traffic flows back to LAN clients.
  const addedReturn = ensureRule(null, 'FORWARD', `-i ${wan_iface} -o ${lan_iface} -m state --state ESTABLISHED,RELATED -j ACCEPT`);

  const dhcpRes = dhcpMode.installAndConfigure({ lan_iface, router_mode: true });

  _state = { enabled: true, wan_iface, lan_iface, started_at: Date.now() };
  save();

  return {
    ok: dhcpRes.ok,
    wan_iface,
    lan_iface,
    rules_added: { masquerade: addedNat, lan_forward: addedFwd, return_path: addedReturn },
    dhcp: dhcpRes,
  };
}

function getStatus() {
  const detected = detectInterfaces();
  const wan_iface = _state.wan_iface || detected.wan;
  const lan_iface = _state.lan_iface || detected.lans[0];
  const ip_forward = sh('cat /proc/sys/net/ipv4/ip_forward') === '1';
  const masquerade = wan_iface && shOk(`iptables -t nat -C POSTROUTING -o ${wan_iface} -j MASQUERADE 2>/dev/null`);
  const lan_accept = lan_iface && shOk(`iptables -C FORWARD -i ${lan_iface} -j ACCEPT 2>/dev/null`);
  const dhcpStatus = dhcpMode ? dhcpMode.getStatus() : { dnsmasq_active: false };
  return {
    ..._state,
    detected_wan: detected.wan,
    detected_lans: detected.lans,
    ip_forward,
    masquerade_active: !!masquerade,
    lan_forward_active: !!lan_accept,
    dhcp: dhcpStatus,
  };
}

function uninstall() {
  const wan_iface = _state.wan_iface;
  const lan_iface = _state.lan_iface;

  if (wan_iface) removeRule('nat', 'POSTROUTING', `-o ${wan_iface} -j MASQUERADE`);
  if (lan_iface) removeRule(null, 'FORWARD', `-i ${lan_iface} -j ACCEPT`);
  if (wan_iface && lan_iface) {
    removeRule(null, 'FORWARD', `-i ${wan_iface} -o ${lan_iface} -m state --state ESTABLISHED,RELATED -j ACCEPT`);
  }

  disableIpForward();

  let dhcpRes = { ok: true, skipped: true };
  if (dhcpMode) dhcpRes = dhcpMode.uninstall();

  _state.enabled = false;
  save();
  return { ok: true, dhcp: dhcpRes };
}

module.exports = { installAndConfigure, getStatus, uninstall };
