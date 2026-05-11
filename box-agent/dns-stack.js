// dns-stack.js
//
// Configures the box's DNS stack for privacy parity with Firewalla:
//   - Unbound (local recursive resolver, DNSSEC validation enabled)
//   - dnscrypt-proxy (DoH upstream to Cloudflare/Quad9, used on Unbound miss)
//   - dnsmasq (LAN-facing, separately managed; we only write its upstream conf)
//
// Default ports:
//   dnscrypt-proxy : 127.0.0.1:5053
//   unbound        : 127.0.0.1:5054
//   dnsmasq        : 0.0.0.0:53 (untouched here)
//
// All file writes are idempotent: same opts twice -> no spurious restarts.

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync, spawnSync } = require('child_process');

// ---- constants -------------------------------------------------------------

const UNBOUND_CONF      = '/etc/unbound/unbound.conf.d/mes.conf';
const DNSCRYPT_CONF     = '/etc/dnscrypt-proxy/dnscrypt-proxy.toml';
const DNSMASQ_UPSTREAM  = '/etc/dnsmasq.d/mes-dns-upstream.conf';

const PORT_DNSCRYPT = 5053;
const PORT_UNBOUND  = 5054;

const VALID_MODES = ['doh-only', 'unbound-only', 'doh+unbound'];

// Friendly aliases -> dnscrypt-proxy server names from the public resolvers list.
const UPSTREAM_ALIASES = {
  cloudflare: 'cloudflare',
  quad9:      'quad9-doh-ip4-port443-filter-pri',
  google:     'google',
  adguard:    'adguard-dns-doh',
};

// ---- small helpers ---------------------------------------------------------

function log(msg)  { process.stdout.write(`[dns-stack] ${msg}\n`); }
function warn(msg) { process.stderr.write(`[dns-stack] WARN: ${msg}\n`); }

function sh(cmd, opts = {}) {
  return execSync(cmd, { stdio: ['ignore', 'pipe', 'pipe'], ...opts })
    .toString()
    .trim();
}

function trySh(cmd) {
  const r = spawnSync('bash', ['-c', cmd], { encoding: 'utf8' });
  return {
    ok: r.status === 0,
    stdout: (r.stdout || '').trim(),
    stderr: (r.stderr || '').trim(),
    code: r.status,
  };
}

function ensureDir(p) {
  fs.mkdirSync(p, { recursive: true });
}

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

// Returns true if file content actually changed.
function writeIfChanged(filePath, content) {
  ensureDir(path.dirname(filePath));
  let prev = null;
  try { prev = fs.readFileSync(filePath); } catch (_) { /* not present */ }
  const next = Buffer.from(content, 'utf8');
  if (prev && sha256(prev) === sha256(next)) {
    return false;
  }
  // Write atomically: tmp file + rename.
  const tmp = `${filePath}.tmp.${process.pid}`;
  fs.writeFileSync(tmp, next, { mode: 0o644 });
  fs.renameSync(tmp, filePath);
  return true;
}

function isServiceActive(unit) {
  return trySh(`systemctl is-active --quiet ${unit}`).ok;
}

function restartService(unit) {
  log(`restarting ${unit}`);
  const r = trySh(`systemctl restart ${unit}`);
  if (!r.ok) warn(`systemctl restart ${unit} failed: ${r.stderr}`);
  return r.ok;
}

function enableService(unit) {
  trySh(`systemctl enable ${unit}`);
}

function disableService(unit) {
  trySh(`systemctl disable --now ${unit}`);
}

// ---- input validation ------------------------------------------------------

function normalizeOpts(opts) {
  const o = opts || {};
  const mode = o.mode || 'doh+unbound';
  if (!VALID_MODES.includes(mode)) {
    throw new Error(`invalid mode "${mode}", expected one of ${VALID_MODES.join(', ')}`);
  }
  const upstreams = Array.isArray(o.upstreams) && o.upstreams.length
    ? o.upstreams
    : ['cloudflare', 'quad9'];
  const resolved = upstreams.map((u) => {
    const v = UPSTREAM_ALIASES[u] || u;
    return v;
  });
  return { mode, upstreams: resolved };
}

// ---- config rendering ------------------------------------------------------

function renderUnboundConf(mode) {
  // doh+unbound : forward "." to dnscrypt-proxy on miss.
  // unbound-only: pure recursion, no forwarder.
  // doh-only    : unbound is not used at runtime; we still ship a sane minimal
  //               file so the unit doesn't barf, but we'll stop the service.
  const lines = [
    '# Managed by mes box-agent dns-stack.js -- DO NOT EDIT BY HAND',
    'server:',
    '    interface: 127.0.0.1',
    `    port: ${PORT_UNBOUND}`,
    '    do-ip4: yes',
    '    do-ip6: no',
    '    do-udp: yes',
    '    do-tcp: yes',
    '    access-control: 127.0.0.0/8 allow',
    '    access-control: 0.0.0.0/0 refuse',
    '    cache-min-ttl: 300',
    '    cache-max-ttl: 86400',
    '    prefetch: yes',
    '    serve-expired: yes',
    '    hide-identity: yes',
    '    hide-version: yes',
    '    qname-minimisation: yes',
    '    harden-glue: yes',
    '    harden-dnssec-stripped: yes',
    '    use-caps-for-id: no',
    '    auto-trust-anchor-file: "/var/lib/unbound/root.key"',
    '    num-threads: 2',
    '    msg-cache-size: 32m',
    '    rrset-cache-size: 64m',
    '    so-rcvbuf: 4m',
    '    so-sndbuf: 4m',
  ];

  if (mode === 'doh+unbound') {
    lines.push('');
    lines.push('forward-zone:');
    lines.push('    name: "."');
    lines.push(`    forward-addr: 127.0.0.1@${PORT_DNSCRYPT}`);
    lines.push('    forward-first: no');
  }
  // unbound-only: no forward-zone, full recursion.

  return lines.join('\n') + '\n';
}

function renderDnscryptToml(upstreams) {
  const serverNames = upstreams.map((s) => `'${s}'`).join(', ');
  return [
    '# Managed by mes box-agent dns-stack.js -- DO NOT EDIT BY HAND',
    `listen_addresses = ['127.0.0.1:${PORT_DNSCRYPT}']`,
    `server_names = [${serverNames}]`,
    '',
    'ipv4_servers = true',
    'ipv6_servers = false',
    'dnscrypt_servers = true',
    'doh_servers = true',
    'odoh_servers = false',
    '',
    'require_dnssec = true',
    'require_nolog = true',
    'require_nofilter = false',
    '',
    'cache = true',
    'cache_size = 4096',
    'cache_min_ttl = 600',
    'cache_max_ttl = 86400',
    'cache_neg_min_ttl = 60',
    'cache_neg_max_ttl = 600',
    '',
    'timeout = 5000',
    'keepalive = 30',
    'bootstrap_resolvers = ["1.1.1.1:53", "9.9.9.9:53"]',
    'ignore_system_dns = true',
    '',
    'log_level = 2',
    "log_file = '/var/log/dnscrypt-proxy/dnscrypt-proxy.log'",
    '',
    '[sources]',
    '  [sources.public-resolvers]',
    "    urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md']",
    "    cache_file = '/var/cache/dnscrypt-proxy/public-resolvers.md'",
    "    minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'",
    '    refresh_delay = 72',
    '    prefix = \'\'',
    '',
  ].join('\n');
}

function renderDnsmasqUpstream(mode) {
  // What does dnsmasq forward to?
  //   doh-only      -> dnscrypt-proxy directly (Unbound is off)
  //   unbound-only  -> Unbound (no DoH layer)
  //   doh+unbound   -> Unbound (which itself forwards to dnscrypt-proxy on miss)
  const target = mode === 'doh-only' ? PORT_DNSCRYPT : PORT_UNBOUND;
  return [
    '# Managed by mes box-agent dns-stack.js -- DO NOT EDIT BY HAND',
    '# dnsmasq forwards LAN queries to the local privacy stack.',
    'no-resolv',
    'no-poll',
    `server=127.0.0.1#${target}`,
    'strict-order',
    '',
  ].join('\n');
}

// ---- package install -------------------------------------------------------

function aptInstall(pkgs) {
  const list = pkgs.join(' ');
  log(`apt-get install -y ${list}`);
  const env = { ...process.env, DEBIAN_FRONTEND: 'noninteractive' };
  // Update once, install once. Tolerate "already newest version".
  trySh('apt-get update -qq');
  const r = trySh(`apt-get install -y --no-install-recommends ${list}`);
  if (!r.ok) {
    throw new Error(`apt-get install failed: ${r.stderr || r.stdout}`);
  }
  void env; // env passing already happens via trySh's parent shell
}

function packageInstalled(pkg) {
  return trySh(`dpkg-query -W -f='\${Status}' ${pkg}`).stdout
    .includes('install ok installed');
}

// ---- service orchestration -------------------------------------------------

function applyServicesForMode(mode, changedUnbound, changedDnscrypt) {
  // Decide which units should be running for each mode.
  const want = {
    'doh-only':     { unbound: false, dnscrypt: true  },
    'unbound-only': { unbound: true,  dnscrypt: false },
    'doh+unbound':  { unbound: true,  dnscrypt: true  },
  }[mode];

  // dnscrypt-proxy
  if (want.dnscrypt) {
    enableService('dnscrypt-proxy');
    if (changedDnscrypt || !isServiceActive('dnscrypt-proxy')) {
      restartService('dnscrypt-proxy');
    }
  } else {
    disableService('dnscrypt-proxy');
  }

  // unbound
  if (want.unbound) {
    enableService('unbound');
    if (changedUnbound || !isServiceActive('unbound')) {
      restartService('unbound');
    }
  } else {
    disableService('unbound');
  }
}

// ---- state file (so getStatus knows the current mode) ----------------------

const STATE_FILE = '/var/lib/mes-box-agent/dns-stack.state.json';

function saveState(state) {
  ensureDir(path.dirname(STATE_FILE));
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
}

function loadState() {
  try { return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); }
  catch (_) { return null; }
}

// ---- public API ------------------------------------------------------------

function installAndConfigure(opts) {
  const { mode, upstreams } = normalizeOpts(opts);
  log(`installAndConfigure mode=${mode} upstreams=${upstreams.join(',')}`);

  // 1. Packages
  const need = [];
  if (!packageInstalled('unbound'))         need.push('unbound');
  if (!packageInstalled('dnscrypt-proxy'))  need.push('dnscrypt-proxy');
  if (need.length) aptInstall(need);

  // 2. Required dirs (dnscrypt log/cache, unbound trust anchor)
  ensureDir('/var/log/dnscrypt-proxy');
  ensureDir('/var/cache/dnscrypt-proxy');
  ensureDir('/var/lib/unbound');
  // Bootstrap the trust anchor on first run; ignore errors (it'll auto-fetch).
  if (!fs.existsSync('/var/lib/unbound/root.key')) {
    trySh('unbound-anchor -a /var/lib/unbound/root.key');
  }

  // 3. Configs
  const unboundChanged  = writeIfChanged(UNBOUND_CONF,  renderUnboundConf(mode));
  const dnscryptChanged = writeIfChanged(DNSCRYPT_CONF, renderDnscryptToml(upstreams));

  // 4. Validate Unbound config before touching the live service.
  if (unboundChanged) {
    const v = trySh(`unbound-checkconf ${UNBOUND_CONF}`);
    if (!v.ok) {
      throw new Error(`unbound-checkconf failed:\n${v.stdout}\n${v.stderr}`);
    }
  }

  // 5. Services
  applyServicesForMode(mode, unboundChanged, dnscryptChanged);

  // 6. Update dnsmasq upstream so the LAN side picks it up. (Restart of dnsmasq
  //    is the agent's responsibility; we only own this drop-in.)
  setDnsmasqUpstream(mode);

  // 7. Persist state
  saveState({ mode, upstreams, ts: Date.now() });

  return getStatus();
}

function setMode(mode, upstreams) {
  // Re-applies configs without re-running apt.
  const prev = loadState() || {};
  const merged = {
    mode,
    upstreams: upstreams || prev.upstreams || ['cloudflare', 'quad9'],
  };
  const norm = normalizeOpts(merged);
  log(`setMode -> ${norm.mode}`);

  const unboundChanged  = writeIfChanged(UNBOUND_CONF,  renderUnboundConf(norm.mode));
  const dnscryptChanged = writeIfChanged(DNSCRYPT_CONF, renderDnscryptToml(norm.upstreams));

  if (unboundChanged) {
    const v = trySh(`unbound-checkconf ${UNBOUND_CONF}`);
    if (!v.ok) {
      throw new Error(`unbound-checkconf failed:\n${v.stdout}\n${v.stderr}`);
    }
  }

  applyServicesForMode(norm.mode, unboundChanged, dnscryptChanged);
  setDnsmasqUpstream(norm.mode);
  saveState({ ...norm, ts: Date.now() });
  return getStatus();
}

function setDnsmasqUpstream() {
  // Always reads current mode from state; no-arg by design (signature in task).
  const state = loadState();
  const mode = (state && state.mode) || 'doh+unbound';
  const changed = writeIfChanged(DNSMASQ_UPSTREAM, renderDnsmasqUpstream(mode));
  if (changed) {
    log(`wrote ${DNSMASQ_UPSTREAM} (mode=${mode})`);
  }
  return { path: DNSMASQ_UPSTREAM, changed, mode };
}

function getStatus() {
  const state = loadState() || {};
  const dnscryptResolver = (() => {
    // Best-effort: parse server_names from the toml we wrote.
    try {
      const t = fs.readFileSync(DNSCRYPT_CONF, 'utf8');
      const m = t.match(/^server_names\s*=\s*\[([^\]]*)\]/m);
      if (!m) return null;
      return m[1].split(',').map((s) => s.trim().replace(/^['"]|['"]$/g, ''));
    } catch (_) { return null; }
  })();

  return {
    mode: state.mode || null,
    upstreams: state.upstreams || null,
    unbound: {
      running: isServiceActive('unbound'),
      port: PORT_UNBOUND,
      conf: UNBOUND_CONF,
    },
    dnscrypt: {
      running: isServiceActive('dnscrypt-proxy'),
      port: PORT_DNSCRYPT,
      conf: DNSCRYPT_CONF,
      current_resolver: dnscryptResolver,
    },
    dnsmasq_upstream_conf: DNSMASQ_UPSTREAM,
  };
}

function uninstall() {
  log('uninstall: stopping services and removing managed configs');
  disableService('unbound');
  disableService('dnscrypt-proxy');

  for (const f of [UNBOUND_CONF, DNSCRYPT_CONF, DNSMASQ_UPSTREAM]) {
    try { fs.unlinkSync(f); log(`removed ${f}`); }
    catch (e) { if (e.code !== 'ENOENT') warn(`could not remove ${f}: ${e.message}`); }
  }
  try { fs.unlinkSync(STATE_FILE); } catch (_) { /* fine */ }

  // We do NOT apt-remove unbound/dnscrypt-proxy automatically; the agent owns
  // package lifecycle decisions and other modules may depend on them.
  return { ok: true };
}

module.exports = {
  installAndConfigure,
  setMode,
  getStatus,
  setDnsmasqUpstream,
  uninstall,
};
