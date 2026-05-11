'use strict';

/*
 * dhcp-mode.js — Box runs as the LAN's DHCP + DNS server.
 *
 * Existing customer router still does WAN/NAT; we just take over DHCP so every
 * client picks up the box itself as their DNS resolver (lets us apply
 * dnsmasq-level blocking + flow visibility without ARP spoofing).
 *
 * Writes a single managed conf at /etc/dnsmasq.d/mes-box-dhcp.conf so other
 * mes-box dnsmasq snippets (blocks, records) keep working unmodified. We
 * always restart (never reload) dnsmasq — dnsmasq has a long-standing bug
 * where SIGHUP picks up dhcp-host changes but NOT dhcp-range edits.
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const CONF_PATH = '/etc/dnsmasq.d/mes-box-dhcp.conf';
const STATE_PATH = '/var/lib/mes-box-agent/dhcp-mode.state.json';
const LEASES_PATH = '/var/lib/misc/dnsmasq.leases';

try { fs.mkdirSync(path.dirname(STATE_PATH), { recursive: true }); } catch {}

let _state = { enabled: false, conf_path: CONF_PATH, lan_iface: null, gateway_ip: null,
               dns_ip: null, range_start: null, range_end: null, started_at: null };
try { _state = { ..._state, ...JSON.parse(fs.readFileSync(STATE_PATH, 'utf8')) }; } catch {}
function save() { try { fs.writeFileSync(STATE_PATH, JSON.stringify(_state, null, 2)); } catch {} }

function sh(cmd, opts = {}) {
  try {
    return execSync(cmd, { encoding: 'utf8', timeout: 10_000, stdio: ['ignore', 'pipe', 'pipe'], ...opts }).trim();
  } catch { return null; }
}

function dnsmasqInstalled() {
  return !!sh('which dnsmasq');
}

// Returns { iface, ip, prefix, network, broadcast, range_start, range_end } for the
// requested iface (defaults to eth0). Range = .100 → .200 within the iface's /24-or-narrower
// subnet — wide enough for a typical home, narrow enough to leave room for static IPs.
function detectSubnet(iface) {
  const out = sh(`ip -4 addr show ${iface}`);
  if (!out) return null;
  const m = out.match(/inet (\d+\.\d+\.\d+\.\d+)\/(\d+)/);
  if (!m) return null;
  const ip = m[1];
  const prefix = parseInt(m[2], 10);
  const octets = ip.split('.').map(n => parseInt(n, 10));
  // For prefixes /24 or longer we just stuff the range in the last octet between .100 and .200.
  // Anything wider than /24 we still constrain to the third-octet network containing our IP —
  // production deployments are virtually always /24 anyway.
  const base = `${octets[0]}.${octets[1]}.${octets[2]}`;
  return {
    iface, ip, prefix,
    range_start: `${base}.100`,
    range_end: `${base}.200`,
    network: `${base}.0`,
  };
}

function detectDefaultGateway() {
  const r = sh('ip route show default | head -1');
  if (!r) return null;
  const m = r.match(/default via (\S+)/);
  return m ? m[1] : null;
}

function buildConf({ range_start, range_end, gateway_ip, dns_ip }) {
  return [
    '# mes-box DHCP mode — managed by box agent (dhcp-mode.js). Do not hand-edit.',
    `dhcp-range=${range_start},${range_end},12h`,
    `dhcp-option=3,${gateway_ip}`,
    `dhcp-option=6,${dns_ip}`,
    'dhcp-authoritative',
    'log-dhcp',
    'log-queries',
    'log-facility=/var/log/dnsmasq.log',
    '',
  ].join('\n');
}

function restartDnsmasq() {
  // Always restart — dnsmasq's SIGHUP path does not re-read dhcp-range changes.
  const r = sh('systemctl restart dnsmasq 2>&1');
  if (r === null) return { ok: false, error: 'dnsmasq_restart_failed' };
  // Give it a beat to come up, then verify
  const active = sh('systemctl is-active dnsmasq');
  return { ok: active === 'active', active };
}

function installAndConfigure(opts = {}) {
  if (!dnsmasqInstalled()) return { ok: false, error: 'dnsmasq_not_installed', hint: 'apt-get install -y dnsmasq' };

  const lan_iface = opts.lan_iface || 'eth0';
  const sub = detectSubnet(lan_iface);
  if (!sub) return { ok: false, error: 'subnet_detect_failed', lan_iface };

  // Gateway: explicit override > existing default route > the box itself (router-mode)
  const gateway_ip = opts.gateway_ip || (opts.router_mode ? sub.ip : (detectDefaultGateway() || sub.ip));
  // DNS always points back to the box so we can intercept name resolution.
  const dns_ip = opts.dns_ip || sub.ip;

  const conf = buildConf({
    range_start: sub.range_start,
    range_end: sub.range_end,
    gateway_ip,
    dns_ip,
  });

  try { fs.writeFileSync(CONF_PATH, conf); }
  catch (e) { return { ok: false, error: 'conf_write_failed', detail: e.message }; }

  const r = restartDnsmasq();

  _state = {
    enabled: true,
    conf_path: CONF_PATH,
    lan_iface,
    gateway_ip,
    dns_ip,
    range_start: sub.range_start,
    range_end: sub.range_end,
    started_at: Date.now(),
  };
  save();

  return { ok: r.ok, conf_path: CONF_PATH, ..._state, dnsmasq_active: r.active };
}

function readLeases() {
  try {
    const txt = fs.readFileSync(LEASES_PATH, 'utf8');
    // dnsmasq lease format: <expiry-epoch> <mac> <ip> <hostname> <client-id>
    return txt.trim().split('\n').filter(Boolean).map(line => {
      const f = line.split(/\s+/);
      return { expires_at: parseInt(f[0], 10) * 1000, mac: (f[1] || '').toLowerCase(),
               ip: f[2], hostname: f[3] || '', client_id: f[4] || '' };
    });
  } catch { return []; }
}

function getStatus() {
  const installed = dnsmasqInstalled();
  const active = installed ? sh('systemctl is-active dnsmasq') : 'not_installed';
  return {
    ..._state,
    dnsmasq_installed: installed,
    dnsmasq_active: active === 'active',
    dnsmasq_state: active,
    leases: readLeases(),
    conf_present: (() => { try { fs.accessSync(CONF_PATH); return true; } catch { return false; } })(),
  };
}

function uninstall() {
  if (!dnsmasqInstalled()) return { ok: false, error: 'dnsmasq_not_installed' };
  try { fs.unlinkSync(CONF_PATH); } catch {}
  const r = restartDnsmasq();
  _state.enabled = false;
  save();
  return { ok: true, dnsmasq_active: r.active };
}

module.exports = { installAndConfigure, getStatus, uninstall };
