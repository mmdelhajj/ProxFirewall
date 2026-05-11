// ntp-intercept.js — Mock Firewalla "NTP intercept" feature.
//
// Forces every device on the LAN to use the local chrony server, even when
// they hard-code time.apple.com / pool.ntp.org / etc. This is a privacy +
// integrity feature: rogue IoT firmware can use NTP as a covert channel
// (timestamps as low-bandwidth exfil, or just leaking online/offline
// patterns), and inconsistent clocks break TLS / log correlation.
//
// Strategy:
//   1. apt install chrony (idempotent — apt is fine on re-runs).
//   2. Write /etc/chrony/chrony.conf with our pool + LAN allow rules.
//   3. systemctl enable+restart chrony.
//   4. iptables -t nat -A PREROUTING ... DNAT to the box's LAN IP.
//      Rule is tagged with a comment so we can find + delete it later
//      without having to remember every flag.
//
// Pi 4, Debian, root. No external npm deps.

'use strict';

const { execSync, spawnSync } = require('child_process');
const fs    = require('fs');
const os    = require('os');

const CHRONY_CONF   = '/etc/chrony/chrony.conf';
const RULE_COMMENT  = 'mfc-ntp-intercept';
const DEFAULT_IFACE = 'eth0';
const DEFAULT_POOL  = 'pool.ntp.org';

// ---------------------------------------------------------------- helpers ---

function sh(cmd, { check = true, quiet = true } = {}) {
  try {
    const out = execSync(cmd, {
      stdio: quiet ? ['ignore', 'pipe', 'pipe'] : 'inherit',
      encoding: 'utf8',
    });
    return { ok: true, stdout: out || '', stderr: '' };
  } catch (e) {
    if (check) throw new Error(`cmd failed: ${cmd}\n${e.stderr || e.message}`);
    return { ok: false, stdout: e.stdout || '', stderr: e.stderr || e.message };
  }
}

function getBoxIp(iface) {
  const ifs = os.networkInterfaces()[iface] || [];
  const v4  = ifs.find(a => a.family === 'IPv4' && !a.internal);
  if (!v4) throw new Error(`no IPv4 address on ${iface}`);
  return v4.address;
}

function renderConf(pool) {
  return [
    '# Managed by mock-firewalla-cloud / ntp-intercept.js',
    `pool ${pool} iburst`,
    '',
    '# Drift / state',
    'driftfile /var/lib/chrony/chrony.drift',
    'makestep 1.0 3',
    'rtcsync',
    '',
    '# Serve LAN clients (all RFC1918)',
    'allow 192.168.0.0/16',
    'allow 10.0.0.0/8',
    'allow 172.16.0.0/12',
    '',
    '# Be a usable last-resort source even if upstream is unreachable',
    'local stratum 10',
    '',
    'logdir /var/log/chrony',
    '',
  ].join('\n');
}

// --- iptables idempotency ---
//
// We tag the NAT rule with a -m comment so we can detect + remove it without
// caring about argument order. iptables -C is the canonical idempotency check
// but it's strict about exact arg order, so we use a comment grep instead.

function redirectExists() {
  const r = sh(`iptables -t nat -S PREROUTING`, { check: false });
  return r.ok && r.stdout.split('\n').some(l => l.includes(RULE_COMMENT));
}

function addRedirect(iface, boxIp) {
  if (redirectExists()) return false;
  sh(
    `iptables -t nat -A PREROUTING -i ${iface} -p udp --dport 123 ` +
    `! -d ${boxIp} -j DNAT --to-destination ${boxIp}:123 ` +
    `-m comment --comment ${RULE_COMMENT}`
  );
  return true;
}

function removeRedirect() {
  // Loop in case multiple stale copies got installed by older versions.
  let removed = 0;
  while (redirectExists() && removed < 10) {
    const list = sh(`iptables -t nat -S PREROUTING`, { check: false }).stdout;
    const line = list.split('\n').find(l => l.includes(RULE_COMMENT));
    if (!line) break;
    // Replace leading "-A" with "-D" to delete the exact rule.
    const del  = line.replace(/^-A /, '-D ');
    sh(`iptables -t nat ${del}`, { check: false });
    removed++;
  }
  return removed;
}

// --- chrony service ---

function chronyInstalled() {
  return spawnSync('which', ['chronyd']).status === 0;
}

function aptInstallChrony() {
  if (chronyInstalled()) return false;
  // noninteractive — we're root, no tty
  sh('DEBIAN_FRONTEND=noninteractive apt-get update -y',           { quiet: true });
  sh('DEBIAN_FRONTEND=noninteractive apt-get install -y chrony',   { quiet: true });
  return true;
}

function writeConfIfChanged(pool) {
  const next = renderConf(pool);
  let prev = '';
  try { prev = fs.readFileSync(CHRONY_CONF, 'utf8'); } catch (_) {}
  if (prev === next) return false;
  fs.writeFileSync(CHRONY_CONF, next, { mode: 0o644 });
  return true;
}

function restartChrony() {
  sh('systemctl enable chrony',  { check: false });
  sh('systemctl restart chrony', { check: true  });
}

// ----------------------------------------------------------------- public ---

function installAndStart(opts = {}) {
  const iface = opts.iface || DEFAULT_IFACE;
  const pool  = opts.pool  || DEFAULT_POOL;
  const boxIp = opts.boxIp || getBoxIp(iface);

  const installedNow = aptInstallChrony();
  const confChanged  = writeConfIfChanged(pool);
  if (installedNow || confChanged) restartChrony();

  const ruleAdded = addRedirect(iface, boxIp);

  return { installedNow, confChanged, ruleAdded, iface, boxIp, pool };
}

function stop() {
  // Tear down the redirect but leave chrony running — clients on the LAN
  // that point at us directly (via DHCP option 42) still get served.
  const removed = removeRedirect();
  return { rules_removed: removed };
}

function uninstall() {
  removeRedirect();
  sh('systemctl stop chrony',    { check: false });
  sh('systemctl disable chrony', { check: false });
  // Don't apt-purge — operator may want chrony for the box itself.
  return { ok: true };
}

function getStatus() {
  const running = spawnSync('systemctl', ['is-active', '--quiet', 'chrony']).status === 0;

  // chronyc sources -n: parse "^* server 1.2.3.4   2  6  ..." style lines.
  const sourcesOut = sh('chronyc -n sources', { check: false }).stdout;
  const sources = sourcesOut.split('\n')
    .filter(l => /^[\^=#]/.test(l))                  // chronyc data rows start with ^/=/#
    .map(l => {
      const parts = l.trim().split(/\s+/);
      return { state: parts[0], host: parts[1], stratum: Number(parts[2]) || null };
    });

  // chronyc tracking: pull "System time" line for drift in ms.
  let drift_ms = null;
  const tracking = sh('chronyc -n tracking', { check: false }).stdout;
  const m = tracking.match(/System time\s*:\s*([0-9.]+)\s+seconds/);
  if (m) drift_ms = Math.round(parseFloat(m[1]) * 1000);

  return {
    running,
    port: 123,
    redirect_active: redirectExists(),
    sources,
    drift_ms,
  };
}

function setUpstreamPool(pool) {
  if (!pool || typeof pool !== 'string') throw new Error('pool must be a string');
  // Crude but safe sanity check — no shell metacharacters in a pool name.
  if (!/^[a-z0-9.\-]+$/i.test(pool)) throw new Error(`refusing suspicious pool: ${pool}`);
  const changed = writeConfIfChanged(pool);
  if (changed) restartChrony();
  return { changed, pool };
}

module.exports = {
  installAndStart,
  stop,
  uninstall,
  getStatus,
  setUpstreamPool,
};
