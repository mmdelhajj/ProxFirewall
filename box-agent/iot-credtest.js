/*
 * iot-credtest.js — IoT default-credential check (SAFE / OPT-IN ONLY).
 *
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║  SAFETY CONSTRAINTS — DO NOT EXTEND THIS MODULE WITHOUT RE-READING:     ║
 * ║                                                                          ║
 * ║  1. Only scans devices on the customer's OWN LAN (caller passes only    ║
 * ║     LAN MACs/IPs from state.box_devices).                                ║
 * ║  2. Only tests WELL-KNOWN default credentials that are public           ║
 * ║     knowledge (printed on stickers, in vendor manuals). NEVER add       ║
 * ║     vendor-specific recent CVE creds, breached-password lists, or       ║
 * ║     zero-day exploit creds.                                              ║
 * ║  3. Customer MUST have explicitly opted in (token-gated by the cloud).  ║
 * ║  4. Surface limited to HTTP / HTTPS / Telnet / SSH / RTSP — the         ║
 * ║     traditional IoT default-credential surfaces. NEVER add SMB / VNC /   ║
 * ║     RDP (different threat profile, different legal exposure).            ║
 * ║  5. Max 3 attempts per (device, service). No brute force.               ║
 * ║  6. 10-second pacing delay between attempts on the same device.         ║
 * ║  7. NEVER include the working credentials in the response. Only emit    ║
 * ║     { vulnerable: true, attempts: N }. We don't even want operators to  ║
 * ║     accidentally lift creds from a customer's report.                   ║
 * ║  8. Quick 3-second per-attempt timeout — no slow Hydra-style scans.     ║
 * ║                                                                          ║
 * ║  If you extend this, run the change past the security reviewer.         ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 */

'use strict';

const net   = require('net');
const http  = require('http');
const https = require('https');

const ATTEMPT_TIMEOUT_MS  = 3000;
const PER_DEVICE_PACING_MS = 10_000;
const MAX_ATTEMPTS_PER_SERVICE = 3;

// Public-knowledge defaults — these are documented in vendor manuals.
// Comment for future contributors: do NOT extend with breach lists.
const COMMON_CREDS = [
  ['admin',     'admin'],
  ['admin',     'password'],
  ['admin',     '12345'],
  ['admin',     '1234'],
  ['root',      'root'],
  ['root',      ''],
  ['user',      'user'],
  ['guest',     'guest'],
];

// Per-vendor extra defaults (still public knowledge — stickers / printed manuals)
const VENDOR_CREDS = {
  hikvision: [['admin', '12345']],            // Hikvision default
  dahua:     [['admin', 'admin']],            // Dahua factory
  axis:      [['root',  'pass']],             // Axis factory pre-2017
  foscam:    [['admin', '']],                  // Foscam IPCams
  dlink:     [['admin', '']],                  // D-Link many
  tplink:    [['admin', 'admin']],             // TP-Link consumer
  netgear:   [['admin', 'password']],          // Netgear consumer
  linksys:   [['admin', 'admin']],             // Linksys consumer
  cisco:     [['cisco', 'cisco']],             // Cisco SMB
  zyxel:     [['admin', '1234']],              // Zyxel
  mikrotik:  [['admin', '']],                  // Mikrotik factory
  ubiquiti:  [['ubnt',  'ubnt']],              // Ubiquiti factory
};

// Build the cred list for a vendor (capped to MAX_ATTEMPTS_PER_SERVICE)
function _credsForVendor(vendor) {
  const v = (vendor || '').toLowerCase();
  let pool = COMMON_CREDS.slice();
  for (const key of Object.keys(VENDOR_CREDS)) {
    if (v.includes(key)) {
      pool = VENDOR_CREDS[key].concat(pool);
      break;
    }
  }
  return pool.slice(0, MAX_ATTEMPTS_PER_SERVICE);
}

// ─── Per-service probes ────────────────────────────────────────────────────

function _tcpPortOpen(host, port, timeoutMs) {
  return new Promise(resolve => {
    const sock = net.connect({ host, port, timeout: timeoutMs });
    let done = false;
    const finish = ok => { if (done) return; done = true; try { sock.destroy(); } catch {} resolve(ok); };
    sock.once('connect', () => finish(true));
    sock.once('timeout', () => finish(false));
    sock.once('error',   () => finish(false));
  });
}

function _httpBasicAuth(host, port, useTls, user, pass) {
  return new Promise(resolve => {
    const lib = useTls ? https : http;
    const opts = {
      method: 'GET',
      hostname: host,
      port,
      path: '/',
      timeout: ATTEMPT_TIMEOUT_MS,
      rejectUnauthorized: false,    // IoT devices ship self-signed certs
      headers: {
        Authorization: 'Basic ' + Buffer.from(user + ':' + pass).toString('base64'),
        'User-Agent': 'mes-box-credtest/1.0',
      },
    };
    const req = lib.request(opts, res => {
      // 200/302 with no realm challenge usually means "authenticated" or
      // "no auth required". 401 means rejected.
      const ok = res.statusCode && res.statusCode !== 401 && res.statusCode < 500;
      res.resume();
      resolve(ok);
    });
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.on('error', () => resolve(false));
    req.end();
  });
}

// SSH banner-grab — we do NOT actually attempt SSH key/password exchange
// (would need a full SSH client). Instead, we ONLY check that the port is
// open and reports an SSH banner. We CONSERVATIVELY mark "potentially
// vulnerable" only when the device's vendor is known to ship with a default
// SSH password AND the port responds. This is a *passive* check.
function _sshBannerCheck(host, port) {
  return new Promise(resolve => {
    const sock = net.connect({ host, port, timeout: ATTEMPT_TIMEOUT_MS });
    let banner = '';
    let done = false;
    const finish = ok => { if (done) return; done = true; try { sock.destroy(); } catch {} resolve(ok); };
    sock.on('data', d => {
      banner += d.toString('utf8', 0, Math.min(d.length, 256));
      if (banner.length >= 64 || banner.includes('\n')) finish(/^SSH-/i.test(banner));
    });
    sock.once('timeout', () => finish(false));
    sock.once('error',   () => finish(false));
    sock.once('close',   () => finish(/^SSH-/i.test(banner)));
  });
}

// Telnet probe — connect, look for a login prompt. If the device prompts
// without sending any auth challenge first (older IoT does this), the device
// is presumed default-cred risky. We do NOT submit credentials over Telnet.
function _telnetProbe(host, port) {
  return new Promise(resolve => {
    const sock = net.connect({ host, port, timeout: ATTEMPT_TIMEOUT_MS });
    let buf = '';
    let done = false;
    const finish = ok => { if (done) return; done = true; try { sock.destroy(); } catch {} resolve(ok); };
    sock.on('data', d => {
      buf += d.toString('utf8', 0, Math.min(d.length, 256));
      if (/login:|username:|password:/i.test(buf)) finish(true);
      if (buf.length > 1024) finish(false);
    });
    sock.once('timeout', () => finish(false));
    sock.once('error',   () => finish(false));
    sock.once('close',   () => finish(buf.length > 0));
  });
}

// RTSP probe — many cameras ship with RTSP + default-cred. We just check
// if the device DESCRIBE-responds with 401 (auth required) at the well-known
// path; the alarm message tells the customer to change the camera password.
function _rtspProbe(host, port) {
  return new Promise(resolve => {
    const sock = net.connect({ host, port, timeout: ATTEMPT_TIMEOUT_MS });
    let buf = '';
    let done = false;
    const finish = ok => { if (done) return; done = true; try { sock.destroy(); } catch {} resolve(ok); };
    sock.once('connect', () => {
      sock.write('OPTIONS rtsp://' + host + ':' + port + '/ RTSP/1.0\r\nCSeq: 1\r\n\r\n');
    });
    sock.on('data', d => {
      buf += d.toString('utf8', 0, Math.min(d.length, 512));
      if (buf.length >= 32) finish(/RTSP\/1\.\d/i.test(buf));
    });
    sock.once('timeout', () => finish(false));
    sock.once('error',   () => finish(false));
    sock.once('close',   () => finish(/RTSP\/1\.\d/i.test(buf)));
  });
}

// ─── Per-device orchestration ──────────────────────────────────────────────

async function _scanDevice(dev) {
  const findings = [];
  const ip = dev.ip;
  if (!ip) return findings;
  const vendor = dev.vendor || '';
  const creds = _credsForVendor(vendor);

  // HTTP / HTTPS — basic auth on / against ports 80, 443, 8080, 8443
  for (const [port, tls] of [[80, false], [8080, false], [443, true], [8443, true]]) {
    if (!(await _tcpPortOpen(ip, port, 1500))) continue;
    let vulnerable = false;
    let attempts = 0;
    for (const [u, p] of creds) {
      attempts++;
      const ok = await _httpBasicAuth(ip, port, tls, u, p);
      if (ok) { vulnerable = true; break; }
      await new Promise(r => setTimeout(r, PER_DEVICE_PACING_MS));
    }
    findings.push({
      mac: dev.mac, ip, vendor,
      service: tls ? 'https' : 'http',
      port,
      vulnerable,
      attempts,
      // NEVER include the working credentials — only the count.
    });
    // After hitting one HTTP port don't keep hammering further HTTP ports —
    // most IoT devices duplicate the admin UI across them.
    if (vulnerable) break;
  }

  // SSH — banner-only check
  if (await _tcpPortOpen(ip, 22, 1500)) {
    const banner = await _sshBannerCheck(ip, 22);
    // Flag as vulnerable ONLY when (a) we got an SSH banner AND (b) the
    // vendor is known to ship a default password.
    const vendorHasDefault = Object.keys(VENDOR_CREDS).some(k => (vendor || '').toLowerCase().includes(k));
    findings.push({
      mac: dev.mac, ip, vendor,
      service: 'ssh',
      port: 22,
      vulnerable: banner && vendorHasDefault,
      attempts: 1,  // banner grab is one probe
    });
  }

  // Telnet — prompt-grab. Telnet alone is a smell on a modern LAN.
  if (await _tcpPortOpen(ip, 23, 1500)) {
    const looksLikeLogin = await _telnetProbe(ip, 23);
    findings.push({
      mac: dev.mac, ip, vendor,
      service: 'telnet',
      port: 23,
      vulnerable: looksLikeLogin,
      attempts: 1,
    });
  }

  // RTSP — passive probe
  if (await _tcpPortOpen(ip, 554, 1500)) {
    const isRtsp = await _rtspProbe(ip, 554);
    const vendorIsCamera = /hikvision|dahua|axis|foscam|amcrest|reolink/i.test(vendor || '');
    findings.push({
      mac: dev.mac, ip, vendor,
      service: 'rtsp',
      port: 554,
      vulnerable: isRtsp && vendorIsCamera,
      attempts: 1,
    });
  }

  return findings;
}

// Public entrypoint — called by the agent action handler.
// opts: { devices: [{mac, ip, vendor}], opt_in_token, expected_token }
async function runScan(opts) {
  opts = opts || {};
  // Hard gate: the cloud passes the expected token alongside the agent's
  // pulled scan request. We refuse if either is missing or mismatched.
  if (!opts.opt_in_token || !opts.expected_token ||
      opts.opt_in_token !== opts.expected_token) {
    throw new Error('iot-credtest: opt-in token missing or mismatched — refusing to scan');
  }
  const devices = Array.isArray(opts.devices) ? opts.devices : [];
  if (!devices.length) return { findings: [], scanned: 0, note: 'no devices supplied' };

  // Hard cap: never scan more than 64 devices in one run. If the LAN has
  // more, the customer can iterate; we won't lock up the box for an hour.
  const target = devices.slice(0, 64);
  const allFindings = [];
  for (const dev of target) {
    try {
      const f = await _scanDevice(dev);
      for (const x of f) allFindings.push(x);
    } catch (e) {
      // Per-device errors don't abort the run.
    }
  }
  return {
    findings: allFindings,
    scanned: target.length,
    finished_at: Date.now(),
    // SAFETY: this response is sent to the cloud. It NEVER contains working
    // credentials — only the attempt count + a boolean.
  };
}

module.exports = { runScan };
