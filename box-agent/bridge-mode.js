'use strict';

/*
 * bridge-mode.js
 *
 * Transparent / Simple Mode bridging for the mes-box agent.
 *
 * Joins two physical interfaces (typ. eth0 = WAN side, eth1 = LAN side via
 * USB-Ethernet) into a Linux software bridge so the box sits inline at L2
 * between the modem and the rest of the network. The bridge itself can pick
 * up an IP via DHCP (for management/SSH), but client traffic flows through
 * transparently. ebtables provides L2 ACLs for blocking / isolating MACs.
 *
 * Idempotent: running installAndConfigure twice is a no-op on the second run.
 * uninstall() restores the pre-bridge interface configuration so SSH access
 * does not get stranded on a torn-down interface.
 */

const { execFileSync, execSync, spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const STATE_DIR = '/var/lib/mes-box-agent';
const STATE_FILE = path.join(STATE_DIR, 'pre-bridge-config.json');
const RUNTIME_FILE = path.join(STATE_DIR, 'bridge-runtime.json');

// ---------------------------------------------------------------------------
// small shell helpers
// ---------------------------------------------------------------------------

function run(cmd, args, opts) {
  opts = opts || {};
  const r = spawnSync(cmd, args, { encoding: 'utf8' });
  if (r.status !== 0 && !opts.allowFail) {
    const e = new Error(
      'cmd failed: ' + cmd + ' ' + args.join(' ') +
      '\n  stderr: ' + (r.stderr || '').trim()
    );
    e.stderr = r.stderr;
    e.stdout = r.stdout;
    e.code = r.status;
    throw e;
  }
  return { code: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}

function tryRun(cmd, args) {
  return run(cmd, args, { allowFail: true });
}

function ensureRoot() {
  if (typeof process.getuid === 'function' && process.getuid() !== 0) {
    throw new Error('bridge-mode: must run as root');
  }
}

function ensureStateDir() {
  if (!fs.existsSync(STATE_DIR)) {
    fs.mkdirSync(STATE_DIR, { recursive: true, mode: 0o750 });
  }
}

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    return fallback;
  }
}

function writeJson(file, obj) {
  ensureStateDir();
  fs.writeFileSync(file, JSON.stringify(obj, null, 2));
}

// ---------------------------------------------------------------------------
// pkg / kernel module bring-up
// ---------------------------------------------------------------------------

function ensurePackages() {
  // bridge-utils + ebtables, isc-dhcp-client for dhclient.
  const have = (bin) => tryRun('which', [bin]).code === 0;
  const missing = [];
  if (!have('brctl')) missing.push('bridge-utils');
  if (!have('ebtables')) missing.push('ebtables');
  if (!have('dhclient')) missing.push('isc-dhcp-client');
  if (missing.length === 0) return;
  // non-interactive apt
  const env = Object.assign({}, process.env, { DEBIAN_FRONTEND: 'noninteractive' });
  spawnSync('apt-get', ['update', '-qq'], { env, stdio: 'ignore' });
  const r = spawnSync('apt-get', ['install', '-y', '-qq'].concat(missing), {
    env, stdio: 'inherit',
  });
  if (r.status !== 0) throw new Error('apt-get install failed: ' + missing.join(' '));
}

function ensureBridgeModule() {
  tryRun('modprobe', ['bridge']);
  tryRun('modprobe', ['br_netfilter']);
}

// ---------------------------------------------------------------------------
// interface introspection
// ---------------------------------------------------------------------------

function ifaceExists(name) {
  return tryRun('ip', ['link', 'show', 'dev', name]).code === 0;
}

function ifaceIsBridgeMember(name, bridge) {
  const r = tryRun('ip', ['-o', 'link', 'show', 'dev', name]);
  if (r.code !== 0) return false;
  return r.stdout.indexOf('master ' + bridge) !== -1;
}

function getIfaceAddrs(name) {
  const r = tryRun('ip', ['-o', '-4', 'addr', 'show', 'dev', name]);
  if (r.code !== 0) return [];
  const out = [];
  r.stdout.split('\n').forEach((line) => {
    const m = line.match(/inet\s+(\S+)/);
    if (m) out.push(m[1]);
  });
  return out;
}

function getDefaultRoute() {
  const r = tryRun('ip', ['-4', 'route', 'show', 'default']);
  if (r.code !== 0) return null;
  const m = r.stdout.match(/default\s+via\s+(\S+)\s+dev\s+(\S+)/);
  return m ? { gateway: m[1], dev: m[2] } : null;
}

function snapshotIface(name) {
  if (!ifaceExists(name)) return null;
  return {
    name,
    addrs: getIfaceAddrs(name),
    link_up: tryRun('ip', ['link', 'show', 'dev', name]).stdout.indexOf('state UP') !== -1,
  };
}

// ---------------------------------------------------------------------------
// bridge lifecycle
// ---------------------------------------------------------------------------

function bridgeExists(name) {
  return ifaceExists(name) &&
    tryRun('ip', ['-d', 'link', 'show', 'dev', name]).stdout.indexOf('bridge ') !== -1;
}

function createBridge(name) {
  if (bridgeExists(name)) return;
  run('ip', ['link', 'add', 'name', name, 'type', 'bridge']);
}

function attachIface(iface, bridge) {
  if (!ifaceExists(iface)) {
    throw new Error('interface ' + iface + ' does not exist');
  }
  if (ifaceIsBridgeMember(iface, bridge)) return;
  // bridge members must not carry their own L3 addresses
  tryRun('ip', ['addr', 'flush', 'dev', iface]);
  run('ip', ['link', 'set', 'dev', iface, 'master', bridge]);
  run('ip', ['link', 'set', 'dev', iface, 'up']);
}

function detachIface(iface) {
  if (!ifaceExists(iface)) return;
  tryRun('ip', ['link', 'set', 'dev', iface, 'nomaster']);
}

function bringBridgeUp(name) {
  run('ip', ['link', 'set', 'dev', name, 'up']);
}

function configureBridgeIp(name, opts) {
  if (opts && opts.static_ip) {
    tryRun('ip', ['addr', 'flush', 'dev', name]);
    run('ip', ['addr', 'add', opts.static_ip, 'dev', name]);
    if (opts.gateway) {
      tryRun('ip', ['route', 'del', 'default']);
      run('ip', ['route', 'add', 'default', 'via', opts.gateway, 'dev', name]);
    }
    return;
  }
  // DHCP: kill any existing dhclient on the bridge first, then re-arm.
  tryRun('pkill', ['-f', 'dhclient.*' + name]);
  // -nw = don't wait, background; succeed even if no lease yet (link may still
  // be coming up). The bridge will get an address asynchronously.
  tryRun('dhclient', ['-nw', name]);
}

// ---------------------------------------------------------------------------
// ebtables helpers
// ---------------------------------------------------------------------------

function normalizeMac(mac) {
  if (typeof mac !== 'string') throw new Error('mac must be a string');
  const m = mac.trim().toLowerCase();
  if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(m)) {
    throw new Error('invalid MAC: ' + mac);
  }
  return m;
}

function ebtablesHas(ruleArgs) {
  // -L FORWARD --Lmac2 prints normalized MACs; we just grep the rule list.
  const r = tryRun('ebtables', ['-L', 'FORWARD', '--Lmac2']);
  if (r.code !== 0) return false;
  const needle = ruleArgs.join(' ');
  return r.stdout.toLowerCase().indexOf(needle.toLowerCase()) !== -1;
}

function ebtablesAdd(ruleArgs) {
  if (ebtablesHas(ruleArgs)) return;
  run('ebtables', ['-A', 'FORWARD'].concat(ruleArgs));
}

function ebtablesDel(ruleArgs) {
  // Delete may need to be run multiple times if rule was added twice.
  while (ebtablesHas(ruleArgs)) {
    const r = tryRun('ebtables', ['-D', 'FORWARD'].concat(ruleArgs));
    if (r.code !== 0) break;
  }
}

function ebtablesFlush() {
  tryRun('ebtables', ['-F', 'FORWARD']);
}

function getGatewayMac() {
  const def = getDefaultRoute();
  if (!def) return null;
  // make sure ARP is populated
  tryRun('ping', ['-c', '1', '-W', '1', def.gateway]);
  const r = tryRun('ip', ['neigh', 'show', def.gateway]);
  if (r.code !== 0) return null;
  const m = r.stdout.match(/lladdr\s+([0-9a-f:]{17})/i);
  return m ? normalizeMac(m[1]) : null;
}

// ---------------------------------------------------------------------------
// runtime state tracking (blocked / isolated MACs)
// ---------------------------------------------------------------------------

function loadRuntime() {
  return readJson(RUNTIME_FILE, {
    bridge_name: 'br0',
    wan_iface: null,
    lan_iface: null,
    blocked: [],
    isolated: [],
  });
}

function saveRuntime(rt) {
  writeJson(RUNTIME_FILE, rt);
}

// ---------------------------------------------------------------------------
// public API
// ---------------------------------------------------------------------------

// Auto-detect WAN/LAN ifaces. WAN = iface holding the default route. LAN = the
// next available "real" iface (excluding loopback, the bridge itself, and any
// virtual wg/tun/docker/veth interfaces).
function autoDetectIfaces(bridgeName) {
  const def = getDefaultRoute();
  let wan = def && def.dev || null;
  // Enumerate real ethernet ifaces
  const r = tryRun('ip', ['-o', 'link', 'show']);
  const real = [];
  (r.stdout || '').split('\n').forEach(line => {
    const m = line.match(/^\d+:\s+(\S+?):/);
    if (!m) return;
    const name = m[1].replace(/@.*/, '');
    if (name === 'lo' || name === bridgeName) return;
    if (/^(wg|tun|docker|veth|br-|vir)/.test(name)) return;
    real.push(name);
  });
  if (!wan && real.length) wan = real[0];
  let lan = real.find(n => n !== wan) || null;
  return { wan, lan };
}

function installAndConfigure(opts) {
  ensureRoot();
  opts = opts || {};
  const bridge = opts.bridge_name || 'br0';
  const auto = autoDetectIfaces(bridge);
  const wan = opts.wan_iface || auto.wan || 'eth0';
  const lan = opts.lan_iface || auto.lan || 'eth1';
  const useDhcp = opts.use_dhcp !== false && !opts.static_ip;

  ensureStateDir();

  // 1. Snapshot pre-bridge config (only if we haven't already — first run wins).
  if (!fs.existsSync(STATE_FILE)) {
    const snapshot = {
      created_at: new Date().toISOString(),
      bridge_name: bridge,
      wan_iface: wan,
      lan_iface: lan,
      ifaces: {
        [wan]: snapshotIface(wan),
        [lan]: snapshotIface(lan),
      },
      default_route: getDefaultRoute(),
    };
    writeJson(STATE_FILE, snapshot);
  }

  // 2. Packages + kernel module.
  ensurePackages();
  ensureBridgeModule();

  // 3. Build the bridge.
  createBridge(bridge);
  attachIface(wan, bridge);
  attachIface(lan, bridge);
  bringBridgeUp(bridge);

  // 4. Get an IP on the bridge for management.
  configureBridgeIp(bridge, {
    static_ip: opts.static_ip,
    gateway: opts.gateway,
  });
  if (useDhcp) {
    // give dhclient a brief window to come back with a lease (non-blocking
    // fallback already started in configureBridgeIp).
  }

  // 5. Initialize ebtables FORWARD chain (don't flush — preserve user rules
  // across reconfigure, but make sure default policy is ACCEPT so traffic
  // flows transparently).
  tryRun('ebtables', ['-P', 'FORWARD', 'ACCEPT']);
  // 5a. Enable BROUTING redirect for IPv4 — this is the "L2 inspection" bit
  // that lets iptables/conntrack still see L2-bridged traffic. Idempotent.
  const brouteCheck = tryRun('ebtables', ['-t', 'broute', '-L', 'BROUTING']);
  if (brouteCheck.code === 0 && brouteCheck.stdout.indexOf('redirect') === -1) {
    tryRun('ebtables', ['-t', 'broute', '-A', 'BROUTING',
                        '-p', 'IPv4', '-j', 'redirect', '--redirect-target', 'ACCEPT']);
  }

  // 6. Persist runtime.
  const rt = loadRuntime();
  rt.bridge_name = bridge;
  rt.wan_iface = wan;
  rt.lan_iface = lan;
  saveRuntime(rt);

  return getStatus();
}

function setIface(role, name) {
  ensureRoot();
  if (role !== 'wan' && role !== 'lan') {
    throw new Error('role must be "wan" or "lan"');
  }
  const rt = loadRuntime();
  const bridge = rt.bridge_name || 'br0';
  const oldName = role === 'wan' ? rt.wan_iface : rt.lan_iface;

  if (oldName && oldName !== name) {
    detachIface(oldName);
  }
  attachIface(name, bridge);

  if (role === 'wan') rt.wan_iface = name;
  else rt.lan_iface = name;
  saveRuntime(rt);
  return getStatus();
}

function block(mac) {
  ensureRoot();
  const m = normalizeMac(mac);
  ebtablesAdd(['-s', m, '-j', 'DROP']);
  ebtablesAdd(['-d', m, '-j', 'DROP']);
  const rt = loadRuntime();
  if (rt.blocked.indexOf(m) === -1) rt.blocked.push(m);
  saveRuntime(rt);
  return { blocked: m };
}

function unblock(mac) {
  ensureRoot();
  const m = normalizeMac(mac);
  ebtablesDel(['-s', m, '-j', 'DROP']);
  ebtablesDel(['-d', m, '-j', 'DROP']);
  const rt = loadRuntime();
  rt.blocked = rt.blocked.filter((x) => x !== m);
  // also drop any isolation rules for this MAC
  rt.isolated = rt.isolated.filter((entry) => {
    if (entry.mac !== m) return true;
    ebtablesDel(['-s', m, '-d', '!', entry.gateway_mac, '-j', 'DROP']);
    return false;
  });
  saveRuntime(rt);
  return { unblocked: m };
}

function isolate(mac) {
  ensureRoot();
  const m = normalizeMac(mac);
  const gwMac = getGatewayMac();
  if (!gwMac) {
    throw new Error('cannot determine gateway MAC; ensure default route is up');
  }
  // drop any L2 frame from this MAC whose dest is NOT the gateway
  ebtablesAdd(['-s', m, '-d', '!', gwMac, '-j', 'DROP']);
  const rt = loadRuntime();
  rt.isolated = rt.isolated.filter((e) => e.mac !== m);
  rt.isolated.push({ mac: m, gateway_mac: gwMac, since: new Date().toISOString() });
  saveRuntime(rt);
  return { isolated: m, gateway_mac: gwMac };
}

function getStatus() {
  const rt = loadRuntime();
  const bridge = rt.bridge_name || 'br0';
  const status = {
    bridge_up: false,
    bridge_name: bridge,
    member_ifaces: [],
    wan_iface: rt.wan_iface || null,
    lan_iface: rt.lan_iface || null,
    ip: null,
    blocked_macs: rt.blocked.slice(),
    isolated_macs: rt.isolated.slice(),
    traffic_bytes: { rx: 0, tx: 0 },
    uptime_s: 0,
  };
  // Bridge uptime = bridge link sysfs ctime
  try {
    const st = fs.statSync('/sys/class/net/' + bridge);
    status.uptime_s = Math.round((Date.now() - st.ctimeMs) / 1000);
  } catch {}
  if (!bridgeExists(bridge)) return status;

  status.bridge_up = tryRun('ip', ['link', 'show', 'dev', bridge])
    .stdout.indexOf('state UP') !== -1;

  // member ifaces
  const r = tryRun('ip', ['-o', 'link', 'show']);
  if (r.code === 0) {
    r.stdout.split('\n').forEach((line) => {
      const m = line.match(/^\d+:\s+(\S+?):.*master\s+(\S+)/);
      if (m && m[2] === bridge) status.member_ifaces.push(m[1].replace(/@.*/, ''));
    });
  }

  status.ip = getIfaceAddrs(bridge)[0] || null;

  // traffic counters via /sys/class/net
  try {
    const base = '/sys/class/net/' + bridge + '/statistics/';
    status.traffic_bytes.rx = parseInt(fs.readFileSync(base + 'rx_bytes', 'utf8'), 10);
    status.traffic_bytes.tx = parseInt(fs.readFileSync(base + 'tx_bytes', 'utf8'), 10);
  } catch (e) { /* ignore */ }

  return status;
}

function uninstall() {
  ensureRoot();
  const rt = loadRuntime();
  const bridge = rt.bridge_name || 'br0';
  const snap = readJson(STATE_FILE, null);

  // 1. Flush ebtables FORWARD rules we might have added.
  ebtablesFlush();

  // 2. Stop dhclient on the bridge.
  tryRun('pkill', ['-f', 'dhclient.*' + bridge]);

  // 3. Detach members.
  if (bridgeExists(bridge)) {
    const r = tryRun('ip', ['-o', 'link', 'show']);
    (r.stdout || '').split('\n').forEach((line) => {
      const m = line.match(/^\d+:\s+(\S+?):.*master\s+(\S+)/);
      if (m && m[2] === bridge) {
        const ifname = m[1].replace(/@.*/, '');
        tryRun('ip', ['link', 'set', 'dev', ifname, 'nomaster']);
      }
    });
    // 4. Tear down the bridge itself.
    tryRun('ip', ['link', 'set', 'dev', bridge, 'down']);
    tryRun('ip', ['link', 'delete', bridge, 'type', 'bridge']);
  }

  // 5. Restore pre-bridge iface configuration so SSH does not get stranded.
  if (snap && snap.ifaces) {
    Object.keys(snap.ifaces).forEach((ifname) => {
      const conf = snap.ifaces[ifname];
      if (!conf || !ifaceExists(ifname)) return;
      tryRun('ip', ['addr', 'flush', 'dev', ifname]);
      (conf.addrs || []).forEach((cidr) => {
        tryRun('ip', ['addr', 'add', cidr, 'dev', ifname]);
      });
      if (conf.link_up) tryRun('ip', ['link', 'set', 'dev', ifname, 'up']);
    });
    if (snap.default_route) {
      tryRun('ip', ['route', 'del', 'default']);
      tryRun('ip', [
        'route', 'add', 'default',
        'via', snap.default_route.gateway,
        'dev', snap.default_route.dev,
      ]);
    }
    // If the original WAN iface had no static address, kick dhclient to
    // re-acquire on it so management connectivity is restored.
    const wan = snap.wan_iface;
    if (wan && (!snap.ifaces[wan] || !snap.ifaces[wan].addrs.length)) {
      tryRun('pkill', ['-f', 'dhclient.*' + wan]);
      tryRun('dhclient', ['-nw', wan]);
    }
  }

  // 6. Wipe runtime state (keep STATE_FILE so a future reinstall could still
  // see the original snapshot — but mark uninstalled).
  try { fs.unlinkSync(RUNTIME_FILE); } catch (e) { /* ignore */ }

  return { uninstalled: true, bridge_name: bridge };
}

module.exports = {
  installAndConfigure,
  setIface,
  block,
  unblock,
  isolate,
  getStatus,
  uninstall,
};
