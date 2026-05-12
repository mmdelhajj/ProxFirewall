/*
 * siem-forwarder.js — ship alarms (+ optionally flows) to a customer's SIEM.
 *
 * Transports:
 *   - 'tcp'              : one JSON line per event over a new TCP connection
 *                          (we keep things stateless — open, send, close)
 *   - 'udp'              : one JSON line per event over a UDP datagram
 *   - 'syslog-rfc5424'   : RFC 5424 syslog framed message over TCP
 *
 * Formats:
 *   - 'json' (default)   : JSON.stringify(event) + '\n'
 *   - 'cef'              : CEF:0|mes-network|firewalla-mock|1.0|<kind>|<title>|<sev>|<extras>
 *
 * Retry: exponential backoff up to 3 attempts, then drop with a logged
 * message. We don't queue indefinitely — SIEMs are usually highly available;
 * if your endpoint is down for 20s, you accept the loss.
 *
 * Rate cap: 1000 events / customer / minute (sliding window). Above that we
 * count drops in `state.siem_config[cid].dropped_today` and return early.
 *
 * Config (per-customer, in state.siem_config[cid]):
 *   { enabled, transport, host, port, format,
 *     forward_alarms (default true), forward_flows (default false),
 *     forwarded_today, dropped_today, day_key,    // counters
 *     last_error, last_error_at, last_success_at } // for status UI
 */

'use strict';

const net    = require('net');
const dgram  = require('dgram');

const MAX_PER_MIN = 1000;
const MAX_RETRIES = 3;
const SOCKET_TIMEOUT_MS = 5000;

let _state = null;
function init(globalState) {
  _state = globalState;
  if (!_state.siem_config) _state.siem_config = {};
  if (!_state.siem_rate)   _state.siem_rate   = {};   // {cid: [ts...]} sliding window
}

function _ensureCfg(cid) {
  if (!_state.siem_config[cid]) {
    _state.siem_config[cid] = {
      enabled: false,
      transport: 'tcp',
      host: '',
      port: 0,
      format: 'json',
      forward_alarms: true,
      forward_flows: false,
      forwarded_today: 0,
      dropped_today: 0,
      day_key: '',
      last_error: null,
      last_error_at: 0,
      last_success_at: 0,
    };
  }
  return _state.siem_config[cid];
}

function _dayKey() {
  const d = new Date();
  return `${d.getUTCFullYear()}-${d.getUTCMonth()+1}-${d.getUTCDate()}`;
}

function _rollDay(cfg) {
  const dk = _dayKey();
  if (cfg.day_key !== dk) {
    cfg.day_key = dk;
    cfg.forwarded_today = 0;
    cfg.dropped_today = 0;
  }
}

function configure({ customer_id, transport, host, port, format,
                     enabled, forward_alarms, forward_flows }) {
  if (!_state) throw new Error('siem-forwarder: init() must be called first');
  if (!customer_id) throw new Error('customer_id required');
  const cfg = _ensureCfg(customer_id);
  if (transport !== undefined) {
    if (!['tcp', 'udp', 'syslog-rfc5424'].includes(transport)) throw new Error('bad transport');
    cfg.transport = transport;
  }
  if (host !== undefined) cfg.host = String(host).slice(0, 253);
  if (port !== undefined) {
    const p = parseInt(port);
    if (!Number.isInteger(p) || p < 1 || p > 65535) throw new Error('bad port');
    cfg.port = p;
  }
  if (format !== undefined) {
    if (!['json', 'cef'].includes(format)) throw new Error('bad format');
    cfg.format = format;
  }
  if (enabled !== undefined) cfg.enabled = !!enabled;
  if (forward_alarms !== undefined) cfg.forward_alarms = !!forward_alarms;
  if (forward_flows !== undefined) cfg.forward_flows  = !!forward_flows;
  return cfg;
}

function getConfig(customer_id) {
  if (!_state) return null;
  return _state.siem_config[customer_id] || null;
}

// Rate cap check — 1000 events / minute per customer, sliding 60s window.
function _withinRate(cid) {
  const now = Date.now();
  const arr = _state.siem_rate[cid] = _state.siem_rate[cid] || [];
  // Trim entries older than 60s
  while (arr.length && arr[0] < now - 60_000) arr.shift();
  if (arr.length >= MAX_PER_MIN) return false;
  arr.push(now);
  return true;
}

function _renderJson(event) {
  // Include a `_meta` for SIEMs that want quick filtering
  const payload = {
    _meta: { source: 'mes-network', schema: 'v1', emitted_at: Date.now() },
    ...event,
  };
  return JSON.stringify(payload) + '\n';
}

function _renderCef(event) {
  // CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
  const sev = ({ low: 3, medium: 5, high: 7, critical: 9 })[event.severity] || 5;
  const kind  = String(event.kind  || event.type || 'event').replace(/[|=]/g, '_');
  const title = String(event.title || event.message || '').replace(/[|=\r\n]/g, '_');
  const ext = [];
  if (event.customer_id) ext.push('cs1Label=customer_id cs1=' + event.customer_id);
  if (event.box_mac)     ext.push('dvc=' + event.box_mac);
  if (event.device_mac)  ext.push('smac=' + event.device_mac);
  if (event.dst_ip)      ext.push('dst=' + event.dst_ip);
  if (event.dst_domain)  ext.push('dhost=' + event.dst_domain);
  return `CEF:0|mes-network|firewalla-mock|1.0|${kind}|${title}|${sev}|${ext.join(' ')}\n`;
}

function _renderRfc5424(payload) {
  // PRI = facility 16 (local0) * 8 + severity (user-info 6) = 134
  const ts = new Date().toISOString();
  const host = 'cloud.mes.net.lb';
  // STRUCTURED-DATA = "-" (none); the JSON goes in the MSG part
  return `<134>1 ${ts} ${host} mes-network - - - ${payload.replace(/\n+$/, '')}\n`;
}

function _send(cfg, frame) {
  return new Promise((resolve, reject) => {
    if (cfg.transport === 'udp') {
      const sock = dgram.createSocket('udp4');
      const timer = setTimeout(() => {
        try { sock.close(); } catch {}
        reject(new Error('udp send timeout'));
      }, SOCKET_TIMEOUT_MS);
      sock.send(Buffer.from(frame), cfg.port, cfg.host, err => {
        clearTimeout(timer);
        try { sock.close(); } catch {}
        if (err) reject(err); else resolve();
      });
      return;
    }
    // tcp / syslog-rfc5424 — both ride on TCP, just different framing
    const sock = net.connect({ host: cfg.host, port: cfg.port, timeout: SOCKET_TIMEOUT_MS });
    let settled = false;
    const done = (err) => {
      if (settled) return;
      settled = true;
      try { sock.destroy(); } catch {}
      if (err) reject(err); else resolve();
    };
    sock.once('connect', () => {
      sock.write(frame, err => {
        if (err) return done(err);
        // Half-close to flush; some SIEMs require it
        sock.end();
      });
    });
    sock.once('end', () => done(null));
    sock.once('timeout', () => done(new Error('tcp socket timeout')));
    sock.once('error', err => done(err));
  });
}

// Forward one event. Returns a promise that resolves to a result object — we
// do NOT await this from the alarm hot path; we fire-and-forget.
async function forward(customer_id, event) {
  if (!_state) return { ok: false, error: 'not_initialized' };
  const cfg = _state.siem_config[customer_id];
  if (!cfg || !cfg.enabled) return { ok: false, error: 'not_enabled' };
  if (!cfg.host || !cfg.port) return { ok: false, error: 'incomplete_config' };

  _rollDay(cfg);

  // Type-based gating
  const t = event && event.type;
  if (t === 'alarm' && !cfg.forward_alarms) return { ok: false, error: 'alarms_disabled' };
  if (t === 'flow'  && !cfg.forward_flows)  return { ok: false, error: 'flows_disabled' };

  // Rate cap
  if (!_withinRate(customer_id)) {
    cfg.dropped_today = (cfg.dropped_today || 0) + 1;
    return { ok: false, error: 'rate_capped' };
  }

  // Frame the payload
  let frame;
  if (cfg.format === 'cef') frame = _renderCef(event);
  else                      frame = _renderJson(event);
  if (cfg.transport === 'syslog-rfc5424') frame = _renderRfc5424(frame);

  // Retry with exponential backoff
  let lastErr;
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      await _send(cfg, frame);
      cfg.forwarded_today = (cfg.forwarded_today || 0) + 1;
      cfg.last_success_at = Date.now();
      cfg.last_error = null;
      return { ok: true, attempts: attempt };
    } catch (e) {
      lastErr = e;
      if (attempt < MAX_RETRIES) {
        await new Promise(r => setTimeout(r, 200 * Math.pow(2, attempt - 1)));
      }
    }
  }
  cfg.dropped_today = (cfg.dropped_today || 0) + 1;
  cfg.last_error = lastErr && lastErr.message ? lastErr.message : String(lastErr);
  cfg.last_error_at = Date.now();
  console.log(`         ⚠️  SIEM forward failed for cust=${customer_id}: ${cfg.last_error}`);
  return { ok: false, error: cfg.last_error, attempts: MAX_RETRIES };
}

module.exports = { init, configure, getConfig, forward };
