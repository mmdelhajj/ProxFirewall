/**
 * portscan.js - External & internal port/vulnerability scan engine
 *
 * Mirrors Firewalla "External Port Scan" + "Internal Vulnerability Scan".
 *  - External: cloud runs `nmap` against a customer's public IP.
 *  - Internal: cloud queues a scan command on the box; the on-box agent
 *    executes the LAN scan and POSTs the result back via its normal
 *    command-result channel (handled elsewhere in server.js).
 *
 * Exposed via require() from the main Express server. This module
 * does not register any HTTP routes itself.
 */

'use strict';

const { execSync } = require('child_process');

// ---------------------------------------------------------------------------
// Defaults / safety caps
// ---------------------------------------------------------------------------
const DEFAULTS = {
  timeout_ms:       60 * 1000,   // 60s wall-clock cap on nmap
  top_ports:        1024,        // max ports to probe
  max_output_bytes: 10 * 1024,   // 10KB cap on captured XML/stderr
  history_size:     20,          // ring-buffer entries per target
};

// IPv4 / simple hostname guard. We refuse anything else before shelling out.
const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$/;
const HOST_RE = /^[a-zA-Z0-9.-]{1,253}$/;

// CIDR for internal subnets (e.g. 192.168.1.0/24)
const CIDR_RE = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\/(?:[0-9]|[12]\d|3[0-2])$/;

// ---------------------------------------------------------------------------
// In-memory ring buffer for scan history, keyed by target string.
// ---------------------------------------------------------------------------
const _history = new Map();   // target -> [{result, scanned_at}, ...]

function recordScan(target, result) {
  if (!target) return;
  let arr = _history.get(target);
  if (!arr) { arr = []; _history.set(target, arr); }
  arr.push({ result, scanned_at: result.scanned_at || new Date().toISOString() });
  if (arr.length > DEFAULTS.history_size) arr.splice(0, arr.length - DEFAULTS.history_size);
}

function getScanHistory(target) {
  if (!target) return [];
  return (_history.get(target) || []).slice();
}

// ---------------------------------------------------------------------------
// XML parser (no external deps - regex-based for nmap's stable output).
// Extracts <port> elements with state="open" plus service name/product/version.
// ---------------------------------------------------------------------------
function parseNmapXml(xml) {
  const open_ports = [];
  if (typeof xml !== 'string' || !xml.length) return open_ports;

  const portRe  = /<port\s+protocol="([^"]+)"\s+portid="(\d+)">([\s\S]*?)<\/port>/g;
  const stateRe = /<state\s+state="([^"]+)"/;
  const svcRe   = /<service\b([^/>]*?)\/?>/;
  const attrRe  = /(\w+)="([^"]*)"/g;

  let m;
  while ((m = portRe.exec(xml)) !== null) {
    const proto = m[1];
    const port  = parseInt(m[2], 10);
    const inner = m[3];
    const st = inner.match(stateRe);
    if (!st || st[1] !== 'open') continue;

    let service = '', product = '', version = '';
    const sv = inner.match(svcRe);
    if (sv) {
      let am;
      while ((am = attrRe.exec(sv[1])) !== null) {
        if (am[1] === 'name')    service = am[2];
        if (am[1] === 'product') product = am[2];
        if (am[1] === 'version') version = am[2];
      }
    }
    open_ports.push({ port, proto, service, product, version });
  }
  return open_ports;
}

// ---------------------------------------------------------------------------
// External scan: cloud-side nmap against a public IP / hostname.
// ---------------------------------------------------------------------------
function scanExternal(public_ip, opts) {
  return new Promise((resolve, reject) => {
    const target = String(public_ip || '').trim();
    if (!target || (!IPV4_RE.test(target) && !HOST_RE.test(target))) {
      return reject(new Error('invalid target: ' + target));
    }

    const o = Object.assign({}, DEFAULTS, opts || {});
    const top = Math.min(parseInt(o.top_ports, 10) || DEFAULTS.top_ports, 1024);
    const cmd = `nmap -Pn -T4 --open --top-ports ${top} -oX - ${target}`;

    const t0 = Date.now();
    let xml = '';
    try {
      xml = execSync(cmd, {
        timeout:     o.timeout_ms,
        maxBuffer:   o.max_output_bytes,
        encoding:    'utf8',
        stdio:       ['ignore', 'pipe', 'pipe'],
      });
    } catch (err) {
      // execSync throws on non-zero exit OR timeout. Capture whatever stdout
      // we got so a partial scan is still useful.
      xml = (err && err.stdout && err.stdout.toString()) || '';
      if (!xml) return reject(new Error('nmap failed: ' + (err.message || 'unknown')));
    }

    if (xml.length > o.max_output_bytes) xml = xml.slice(0, o.max_output_bytes);

    const open_ports = parseNmapXml(xml);
    const result = {
      target,
      open_ports,
      scan_duration_s: Math.round((Date.now() - t0) / 100) / 10,
      scanned_at:      new Date().toISOString(),
      scan_type:       'external',
    };
    recordScan(target, result);
    resolve(result);
  });
}

// ---------------------------------------------------------------------------
// Internal scan: queue a "scan" command on the box. The box's persistent
// agent polls box_commands and runs nmap on its own LAN, then POSTs back
// the result via the existing command-result endpoint (server.js is
// expected to call recordScan() with the returned payload).
//
// `boxRegistry` is injected lazily so this module stays decoupled from
// server.js storage. Caller passes in the registry/queue helpers.
// ---------------------------------------------------------------------------
let _boxQueueFn = null;   // function(box_mac, command_obj) -> command_id

function setBoxQueue(fn) { _boxQueueFn = fn; }

function scanInternalSubnet(box_mac, subnet, opts) {
  return new Promise((resolve, reject) => {
    const mac = String(box_mac || '').trim().toLowerCase();
    if (!/^[0-9a-f:]{17}$/.test(mac)) return reject(new Error('invalid box_mac: ' + mac));

    const sn = String(subnet || '').trim();
    if (!CIDR_RE.test(sn)) return reject(new Error('invalid subnet (need CIDR): ' + sn));

    if (typeof _boxQueueFn !== 'function') {
      return reject(new Error('box command queue not wired (call setBoxQueue first)'));
    }

    const o = Object.assign({}, DEFAULTS, opts || {});
    const top = Math.min(parseInt(o.top_ports, 10) || DEFAULTS.top_ports, 1024);

    const command = {
      type:       'port_scan_internal',
      created_at: new Date().toISOString(),
      params: {
        subnet:           sn,
        top_ports:        top,
        timeout_ms:       o.timeout_ms,
        max_output_bytes: o.max_output_bytes,
        // The agent should run roughly:
        //   nmap -Pn -T4 --open --top-ports <top> -oX - <subnet>
        // and POST the parsed result back to the cloud.
        nmap_args: ['-Pn', '-T4', '--open', '--top-ports', String(top), '-oX', '-', sn],
      },
    };

    let command_id;
    try {
      command_id = _boxQueueFn(mac, command);
    } catch (e) {
      return reject(new Error('failed to queue command: ' + e.message));
    }

    resolve({
      queued:       true,
      command_id,
      box_mac:      mac,
      subnet:       sn,
      scan_type:    'internal',
      queued_at:    command.created_at,
      // result will land asynchronously; consumers should poll
      // getScanHistory(subnet) or the box-command result channel.
    });
  });
}

// ---------------------------------------------------------------------------
module.exports = {
  scanExternal,
  scanInternalSubnet,
  parseNmapXml,
  getScanHistory,
  recordScan,
  setBoxQueue,
  DEFAULTS,
};
