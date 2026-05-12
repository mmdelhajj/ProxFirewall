// pcap-capture.js — Auto packet capture for high-severity alarms (Tier 2 Feature D)
//
// PRIVACY NOTE:
//   PCAPs contain raw packet payloads. The cloud-side caller MUST refuse to
//   trigger this for any alarm whose dst_domain matches financial / health /
//   government TLDs (`*.bank`, `*.health`, `*.gov`). The box itself enforces a
//   second-line filter (see SKIP_DOMAIN_RE below) so even a misconfigured
//   cloud can't accidentally capture banking traffic.
//
// captureFlow({ alarm_id, src_ip, dst_ip, duration_s, max_packets, dst_domain? })
//   runs `tcpdump -i <LAN_IF> -c <max_packets> -w /var/tmp/mes-pcap/<alarm_id>.pcap
//        host <src_ip> and host <dst_ip>` for up to `duration_s` seconds.
//   Returns { ok, path, size, packets, alarm_id }.
//
// uploadPcap(alarm_id, cloudUrl, token, fetchLikeApi):
//   reads the file, base64-encodes, POSTs to /api/box/pcap-upload/:alarm_id.

'use strict';

const fs = require('fs');
const path = require('path');
const { execSync, spawn } = require('child_process');

const PCAP_DIR = '/var/tmp/mes-pcap';
// Sensitive TLDs: never capture (privacy + legal). Lowercase, no leading dot.
const SKIP_DOMAIN_RE = /(^|\.)(bank|health|gov|mil|nhs\.uk)(\.|$)/i;

function ensureDir() {
  try { fs.mkdirSync(PCAP_DIR, { recursive: true }); } catch {}
}

function isSensitive(domain) {
  if (!domain) return false;
  return SKIP_DOMAIN_RE.test(String(domain).toLowerCase());
}

function safeIp(ip) {
  return typeof ip === 'string' && /^[0-9a-fA-F:.]{3,45}$/.test(ip);
}

function safeId(id) {
  return typeof id === 'string' && /^[a-zA-Z0-9_-]{1,40}$/.test(id);
}

// Run tcpdump synchronously with a timeout. We rely on -c (packet count) AND
// timeout(1) to bound runtime. Even if no traffic flows we'll exit cleanly.
function captureFlow(opts) {
  ensureDir();
  const alarm_id = String(opts.alarm_id || '').trim();
  if (!safeId(alarm_id)) return { ok: false, error: 'bad alarm_id' };
  if (!safeIp(opts.src_ip) || !safeIp(opts.dst_ip)) return { ok: false, error: 'bad ip' };
  if (isSensitive(opts.dst_domain)) {
    return { ok: false, error: 'skip_sensitive_tld', dst_domain: opts.dst_domain };
  }
  const duration_s = Math.min(Math.max(parseInt(opts.duration_s) || 8, 1), 60);
  const max_packets = Math.min(Math.max(parseInt(opts.max_packets) || 100, 5), 500);
  const iface = (opts.iface || process.env.LAN_IF || 'eth0').replace(/[^a-z0-9]/gi, '');
  const file = path.join(PCAP_DIR, alarm_id + '.pcap');
  try {
    // Need tcpdump installed. If missing, surface a clean error.
    execSync('command -v tcpdump >/dev/null 2>&1');
  } catch {
    return { ok: false, error: 'tcpdump_not_installed' };
  }
  const cmd = `timeout ${duration_s} tcpdump -i ${iface} -nn -c ${max_packets} -w ${file} ` +
              `host ${opts.src_ip} and host ${opts.dst_ip} 2>/dev/null || true`;
  try {
    execSync(cmd, { timeout: (duration_s + 5) * 1000 });
  } catch (e) {
    // tcpdump exits non-zero when -c is hit AND timeout fires; treat as success
    // if the file exists with non-zero size.
  }
  let size = 0, packets = 0;
  try { size = fs.statSync(file).size; } catch {}
  if (size > 0) {
    try {
      const out = execSync(`tcpdump -r ${file} 2>/dev/null | wc -l`, { encoding: 'utf8', timeout: 10_000 });
      packets = parseInt(out.trim()) || 0;
    } catch {}
  }
  return { ok: size > 0, path: file, size, packets, alarm_id };
}

// Upload as base64 in JSON. The cloud endpoint handles ≤10MB.
async function uploadPcap(alarm_id, apiFn) {
  if (!safeId(alarm_id)) return { ok: false, error: 'bad_alarm_id' };
  const file = path.join(PCAP_DIR, alarm_id + '.pcap');
  if (!fs.existsSync(file)) return { ok: false, error: 'pcap_not_found' };
  let buf;
  try { buf = fs.readFileSync(file); } catch (e) { return { ok: false, error: e.message }; }
  if (buf.length === 0) return { ok: false, error: 'pcap_empty' };
  if (buf.length > 8 * 1024 * 1024) buf = buf.subarray(0, 8 * 1024 * 1024);
  const b64 = buf.toString('base64');
  try {
    const r = await apiFn('POST', `/api/box/pcap-upload/${encodeURIComponent(alarm_id)}`, {
      alarm_id, size: buf.length, b64,
    });
    return { ok: true, alarm_id, size: buf.length, server: r };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

function listLocalPcaps() {
  ensureDir();
  try {
    return fs.readdirSync(PCAP_DIR).filter(f => f.endsWith('.pcap')).map(f => {
      const p = path.join(PCAP_DIR, f);
      let size = 0; try { size = fs.statSync(p).size; } catch {}
      return { alarm_id: f.replace(/\.pcap$/, ''), path: p, size };
    });
  } catch { return []; }
}

module.exports = { captureFlow, uploadPcap, listLocalPcaps, isSensitive, PCAP_DIR };
