// sni-parser.js
//
// Live TLS ClientHello capture for app-identification visibility.
// Strategy: spawn `tshark` on the LAN interface, filter for TLS handshake
// type 1 (ClientHello), pull SNI + JA3 fullstring as TSV, MD5 the JA3 string,
// stash results in a ring buffer + emit events.
//
// Why tshark vs node-pcap:
//   - node-pcap requires libpcap-dev + native build, fragile on Pi userland.
//   - tshark already has a battle-tested TLS dissector that handles
//     fragmentation, reassembly, GREASE, and the JA3 ordering rules.
//   - One apt install (`tshark`) is the only dependency.
//
// We do NOT decrypt anything. SNI in TLS 1.0-1.2 is cleartext; in TLS 1.3
// SNI is also cleartext unless ECH is in use (rare on home networks today).
//
// Usage:
//   const sni = require('./sni-parser');
//   sni.on('sni', (rec) => console.log(rec.src_ip, '->', rec.sni));
//   sni.start({ iface: 'eth0', ringSize: 5000 });

'use strict';

const { spawn, execSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const { EventEmitter } = require('events');

const DEFAULT_IFACE = 'eth0';
const DEFAULT_RING = 2000;
const RESTART_BACKOFF_MS = 5000;
const MAX_RESTARTS_PER_MIN = 6;

const emitter = new EventEmitter();

let child = null;
let janitorTimer = null;
let running = false;
let stopping = false;
let ring = [];
let ringSize = DEFAULT_RING;
let stats = {
  captures: 0,
  sni_extracted: 0,
  ja3_extracted: 0,
  parse_errors: 0,
  restarts: 0,
  started_at: null,
  last_event_at: null,
};
let opts = {};
let restartTimestamps = [];
let stderrBuf = '';

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function which(bin) {
  try {
    const out = execSync(`command -v ${bin}`, { stdio: ['ignore', 'pipe', 'ignore'] })
      .toString()
      .trim();
    return out || null;
  } catch (_) {
    return null;
  }
}

function ifaceExists(name) {
  try {
    return fs.existsSync(`/sys/class/net/${name}`);
  } catch (_) {
    return false;
  }
}

function pickFallbackIface() {
  // Try common Pi LAN ifaces in order. Skip lo.
  try {
    const all = fs.readdirSync('/sys/class/net').filter((n) => n !== 'lo');
    const preferred = ['eth0', 'enp0s1', 'wlan0', 'br0'];
    for (const p of preferred) if (all.includes(p)) return p;
    return all[0] || null;
  } catch (_) {
    return null;
  }
}

function md5(s) {
  return crypto.createHash('md5').update(s).digest('hex');
}

function pushRing(rec) {
  ring.push(rec);
  if (ring.length > ringSize) ring.splice(0, ring.length - ringSize);
}

function nowEpoch() {
  return Date.now() / 1000;
}

function shouldRestart() {
  const cutoff = Date.now() - 60_000;
  restartTimestamps = restartTimestamps.filter((t) => t > cutoff);
  return restartTimestamps.length < MAX_RESTARTS_PER_MIN;
}

// ---------------------------------------------------------------------------
// tshark line parser
//
// Field order (matches the spawn args below):
//   0 frame.time_epoch
//   1 ip.src
//   2 ip.dst
//   3 tcp.dstport
//   4 tls.handshake.extensions_server_name
//   5 tls.handshake.ja3_fullstring
//
// tshark separates fields with TAB by default. A single ClientHello may have
// multiple SNI extension entries (rare) — tshark joins repeats with ',' inside
// one field, so we just take the first.
// ---------------------------------------------------------------------------

function parseLine(line) {
  if (!line) return null;
  const parts = line.split('\t');
  if (parts.length < 4) return null;

  const ts = parseFloat(parts[0]);
  const src_ip = parts[1] || '';
  const dst_ip = parts[2] || '';
  const dst_port = parseInt(parts[3], 10) || 0;
  const sniRaw = (parts[4] || '').trim();
  const ja3Raw = (parts[5] || '').trim();

  if (!src_ip || !dst_ip) return null;

  const sni = sniRaw ? sniRaw.split(',')[0].toLowerCase() : null;
  const ja3_fullstring = ja3Raw || null;
  const ja3_md5 = ja3_fullstring ? md5(ja3_fullstring) : null;

  return {
    ts: isFinite(ts) ? ts : nowEpoch(),
    src_ip,
    dst_ip,
    dst_port,
    sni,
    ja3_md5,
    ja3_fullstring, // kept for debugging; drop if you want to slim payload
  };
}

function handleLine(line) {
  const rec = parseLine(line);
  if (!rec) {
    stats.parse_errors++;
    return;
  }
  stats.captures++;
  stats.last_event_at = Date.now();
  if (rec.sni) {
    stats.sni_extracted++;
    emitter.emit('sni', rec);
  }
  if (rec.ja3_md5) {
    stats.ja3_extracted++;
    emitter.emit('ja3', rec);
  }
  pushRing(rec);
  emitter.emit('flow', rec);
}

// ---------------------------------------------------------------------------
// tshark process management
// ---------------------------------------------------------------------------

// Dedicated scratch dir for tshark's internal capture buffer. Without
// --temp-dir, tshark/dumpcap writes /tmp/wireshark_<iface>XXXXXX.pcapng files
// and rotates them, but historical bugs (and our restart loop) have left
// stale pcaps filling /tmp. Pointing temp-dir somewhere we control lets the
// boot-time cleanup wipe ONLY tshark's artefacts safely.
const TSHARK_TMPDIR = '/var/tmp/mes-tshark';

function ensureTmpdir() {
  try { fs.mkdirSync(TSHARK_TMPDIR, { recursive: true }); } catch (_) {}
}

// Wipe stale pcap files left over from earlier (crashed) tshark runs.
// Called on agent boot AND each time we (re)spawn tshark.
function cleanupStalePcaps() {
  const dirs = ['/tmp', TSHARK_TMPDIR];
  for (const d of dirs) {
    let names;
    try { names = fs.readdirSync(d); } catch (_) { continue; }
    for (const n of names) {
      if (!/^wireshark_.*\.pcapng/.test(n) && !/^wireshark_.*\.pcap$/.test(n)) continue;
      try { fs.unlinkSync(`${d}/${n}`); } catch (_) {}
    }
  }
}

function buildArgs(iface) {
  // Note: tls.handshake.ja3_fullstring was removed in tshark/Wireshark ≥4.0 in
  // favor of out-of-tree JA3 plugins. We skip it here so tshark starts cleanly
  // on stock Debian/Raspbian. SNI alone is enough for category attribution.
  //
  // Key flags for pcap-bloat avoidance:
  //   -f 'tcp dst port 443 and (tcp[((tcp[12]&0xf0)>>2):1] = 0x16)'
  //                BPF capture filter applied IN THE KERNEL — only TLS
  //                handshake records flowing to port 443 ever reach userspace.
  //                Drops ~99% of LAN traffic at the source and is the single
  //                biggest factor in keeping tshark's scratch pcap small.
  //   --temp-dir   keep dumpcap's scratch pcap OUT of /tmp; we control this
  //                dir and clean it on every spawn so a crashed tshark cannot
  //                wedge the Pi by filling tmpfs.
  //   -B 2         2 MiB kernel capture buffer (smaller = faster turnover).
  //   -n           no name resolution (saves CPU + DNS storm on Pi).
  //   -Q           quiet startup (no packet-count summary).
  return [
    '-i', iface,
    '-l',
    '-n',
    '-Q',
    '--temp-dir', TSHARK_TMPDIR,
    '-B', '2',
    '-f', 'tcp dst port 443 and (tcp[((tcp[12]&0xf0)>>2):1] = 0x16)',
    '-Y', 'tls.handshake.type==1',  // ClientHello only (dissection-time)
    '-T', 'fields',
    '-e', 'frame.time_epoch',
    '-e', 'ip.src',
    '-e', 'ip.dst',
    '-e', 'tcp.dstport',
    '-e', 'tls.handshake.extensions_server_name',
    '-E', 'header=n',
    '-E', 'separator=/t',
    '-E', 'occurrence=f',
  ];
}

// Periodic janitor: even with a tight BPF, tshark's scratch pcap can creep
// up. Rather than truncating the open file (which kills tshark), we monitor
// size and force a clean parser restart if it exceeds JANITOR_MAX_SCRATCH.
// Caller wires this via setInterval.
const JANITOR_MAX_SCRATCH = 200 * 1024 * 1024; // 200 MiB ceiling per scratch file
function janitorCheckOnce(onOversize) {
  try {
    const names = fs.readdirSync(TSHARK_TMPDIR);
    for (const n of names) {
      if (!/^wireshark_.*\.pcapng/.test(n)) continue;
      const p = `${TSHARK_TMPDIR}/${n}`;
      const st = fs.statSync(p);
      if (st.size > JANITOR_MAX_SCRATCH) {
        console.error(`[sni-parser] scratch pcap ${n} = ${(st.size/1024/1024)|0} MiB, recycling tshark`);
        if (typeof onOversize === 'function') onOversize();
        return true;
      }
    }
  } catch (_) {}
  return false;
}

function spawnTshark(iface) {
  const bin = which('tshark');
  if (!bin) {
    console.error('[sni-parser] tshark not installed; run: apt-get install -y tshark');
    return null;
  }

  ensureTmpdir();
  cleanupStalePcaps();

  let proc;
  try {
    proc = spawn(bin, buildArgs(iface), {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: Object.assign({}, process.env, { TMPDIR: TSHARK_TMPDIR }),
    });
  } catch (e) {
    console.error('[sni-parser] failed to spawn tshark:', e.message);
    return null;
  }

  let stdoutBuf = '';
  proc.stdout.setEncoding('utf8');
  proc.stdout.on('data', (chunk) => {
    stdoutBuf += chunk;
    let idx;
    while ((idx = stdoutBuf.indexOf('\n')) !== -1) {
      const line = stdoutBuf.slice(0, idx).replace(/\r$/, '');
      stdoutBuf = stdoutBuf.slice(idx + 1);
      if (line) {
        try { handleLine(line); }
        catch (e) { stats.parse_errors++; }
      }
    }
    // Cap pathological backlogs (e.g. stuck reader)
    if (stdoutBuf.length > 1_000_000) stdoutBuf = '';
  });

  proc.stderr.setEncoding('utf8');
  proc.stderr.on('data', (chunk) => {
    stderrBuf += chunk;
    if (stderrBuf.length > 8192) stderrBuf = stderrBuf.slice(-4096);
    // tshark prints "Capturing on 'eth0'" to stderr; only surface real errors
    const lower = chunk.toLowerCase();
    if (lower.includes('permission') || lower.includes('error') || lower.includes('no such')) {
      console.error('[sni-parser] tshark:', chunk.trim());
    }
  });

  proc.on('error', (err) => {
    console.error('[sni-parser] tshark process error:', err.message);
  });

  proc.on('exit', (code, signal) => {
    child = null;
    if (stopping) return;
    console.error(`[sni-parser] tshark exited (code=${code} signal=${signal}); stderr tail: ${stderrBuf.slice(-300).trim()}`);
    if (!shouldRestart()) {
      console.error('[sni-parser] too many restarts in last minute; giving up');
      running = false;
      emitter.emit('fatal', new Error('tshark restart loop'));
      return;
    }
    restartTimestamps.push(Date.now());
    stats.restarts++;
    setTimeout(() => {
      if (!running || stopping) return;
      const newChild = spawnTshark(opts.iface);
      if (newChild) child = newChild;
    }, RESTART_BACKOFF_MS);
  });

  return proc;
}

// ---------------------------------------------------------------------------
// public API
// ---------------------------------------------------------------------------

function start(userOpts) {
  if (running) {
    console.error('[sni-parser] already running');
    return false;
  }
  opts = Object.assign({ iface: DEFAULT_IFACE, ringSize: DEFAULT_RING }, userOpts || {});
  ringSize = Math.max(100, parseInt(opts.ringSize, 10) || DEFAULT_RING);

  if (!ifaceExists(opts.iface)) {
    const fb = pickFallbackIface();
    if (!fb) {
      console.error(`[sni-parser] iface ${opts.iface} not found and no fallback available`);
      return false;
    }
    console.error(`[sni-parser] iface ${opts.iface} not found, falling back to ${fb}`);
    opts.iface = fb;
  }

  if (!which('tshark')) {
    console.error('[sni-parser] tshark binary missing; install with: apt-get install -y tshark');
    return false;
  }

  stopping = false;
  running = true;
  stats.started_at = Date.now();
  // Reset the restart-loop guard so this fresh start() is not bounced by
  // a prior session's accumulated restart timestamps.
  restartTimestamps = [];
  ensureTmpdir();
  cleanupStalePcaps();
  child = spawnTshark(opts.iface);
  if (!child) {
    running = false;
    return false;
  }
  // Janitor: check scratch pcap size every 60s; if oversize, kill the child
  // so the existing watchdog re-spawns it with a fresh (empty) scratch file.
  if (!janitorTimer) {
    janitorTimer = setInterval(() => {
      if (!running) return;
      janitorCheckOnce(() => {
        if (child) { try { child.kill('SIGTERM'); } catch (_) {} }
      });
    }, 60_000);
    janitorTimer.unref && janitorTimer.unref();
  }
  console.error(`[sni-parser] capturing TLS ClientHellos on ${opts.iface} (ring=${ringSize})`);
  return true;
}

function stop() {
  stopping = true;
  running = false;
  if (janitorTimer) { clearInterval(janitorTimer); janitorTimer = null; }
  if (child) {
    try { child.kill('SIGTERM'); } catch (_) {}
    // hard kill if it lingers
    setTimeout(() => {
      if (child) {
        try { child.kill('SIGKILL'); } catch (_) {}
      }
    }, 2000).unref();
  }
}

function getRecent(n) {
  if (!n || n <= 0 || n > ring.length) return ring.slice();
  return ring.slice(ring.length - n);
}

function getStats() {
  return Object.assign({}, stats, {
    running,
    iface: opts.iface || null,
    ring_len: ring.length,
    ring_max: ringSize,
  });
}

function clear() {
  ring = [];
}

module.exports = {
  start,
  stop,
  getRecent,
  getStats,
  clear,
  on: (event, fn) => emitter.on(event, fn),
  off: (event, fn) => emitter.off(event, fn),
  once: (event, fn) => emitter.once(event, fn),
  // exposed for unit tests
  _parseLine: parseLine,
};

// If run directly, dump events to stdout for quick smoke testing:
//   node sni-parser.js eth0
if (require.main === module) {
  const iface = process.argv[2] || DEFAULT_IFACE;
  if (!start({ iface })) process.exit(1);
  emitter.on('sni', (r) => {
    console.log(JSON.stringify({
      ts: r.ts, src: r.src_ip, dst: `${r.dst_ip}:${r.dst_port}`,
      sni: r.sni, ja3: r.ja3_md5,
    }));
  });
  setInterval(() => {
    const s = getStats();
    console.error(`[sni-parser] captures=${s.captures} sni=${s.sni_extracted} ja3=${s.ja3_extracted} ring=${s.ring_len}`);
  }, 30_000).unref();
  process.on('SIGINT', () => { stop(); setTimeout(() => process.exit(0), 500); });
  process.on('SIGTERM', () => { stop(); setTimeout(() => process.exit(0), 500); });
}
