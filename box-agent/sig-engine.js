/**
 * sig-engine.js — Suricata-style signature engine (pure JS)
 *
 * Lightweight pattern-matching for network flows. No libsuricata dep.
 * Designed to run on a Raspberry Pi 4 box agent alongside dnsmasq + nftables.
 *
 * A "flow" is a normalized object built from netflow/conntrack/dnsmasq logs:
 *   {
 *     ts:         <unix-seconds>,
 *     src_ip:     '192.168.1.50',
 *     dst_ip:     '1.2.3.4',
 *     dst_domain: 'evil.tld'      | undefined,
 *     dst_port:   443,
 *     proto:      'tcp'|'udp'|'icmp',
 *     bytes:      <int>,
 *     pkts:       <int>,
 *     kind:       'flow'|'dns',
 *   }
 *
 * Signatures use AND-of-matchers by default; set `any: true` for OR.
 */

'use strict';

// ---------- internal state ----------
const SIGS = new Map();           // id -> sig
const HITS = [];                  // ring buffer, capped
const HITS_MAX = 200;
const BEACON_HIST = new Map();    // key: srcIp|dstIp|sigId -> [ts,...]
const BEACON_HIST_MAX = 16;       // keep last 16 timestamps per pair/sig

// ---------- helpers ----------
function pushHit(hit) {
  HITS.push(hit);
  if (HITS.length > HITS_MAX) HITS.shift();
}

function nowSec() { return Math.floor(Date.now() / 1000); }

function matchDomain(flowDom, want, mode) {
  if (!flowDom) return false;
  const a = String(flowDom).toLowerCase();
  const b = String(want).toLowerCase();
  if (mode === 'suffix') return a === b || a.endsWith('.' + b);
  return a === b; // exact
}

function cmpOp(op, a, b) {
  switch (op) {
    case 'gte': return a >= b;
    case 'lte': return a <= b;
    case 'gt':  return a >  b;
    case 'lt':  return a <  b;
    case 'eq':  return a === b;
    default:    return false;
  }
}

// Periodicity / beacon detector. Records ts in a per-(src,dst,sig) ring.
// Hits when >=3 samples are within `interval_s ± jitter_s`.
function checkBeacon(sig, matcherCfg, flow) {
  const key = `${flow.src_ip || '?'}|${flow.dst_ip || flow.dst_domain || '?'}|${sig.id}`;
  const ts = flow.ts || nowSec();
  let hist = BEACON_HIST.get(key);
  if (!hist) { hist = []; BEACON_HIST.set(key, hist); }
  hist.push(ts);
  if (hist.length > BEACON_HIST_MAX) hist.shift();
  if (hist.length < 3) return false;

  const interval = matcherCfg.interval_s;
  const jitter   = matcherCfg.jitter_s || Math.max(5, interval * 0.1);
  let consecutive = 0;
  for (let i = 1; i < hist.length; i++) {
    const dt = hist[i] - hist[i - 1];
    if (Math.abs(dt - interval) <= jitter) consecutive++;
    else consecutive = 0;
    if (consecutive >= 2) return true; // 3 timestamps with 2 matching gaps
  }
  return false;
}

function evalMatcher(m, flow, sig) {
  switch (m.type) {
    case 'dst_ip':
      return flow.dst_ip && flow.dst_ip === m.value;
    case 'src_ip':
      return flow.src_ip && flow.src_ip === m.value;
    case 'dst_domain':
      return matchDomain(flow.dst_domain, m.value, m.mode || 'exact');
    case 'dst_port':
      return Number(flow.dst_port) === Number(m.value);
    case 'proto':
      return flow.proto && flow.proto.toLowerCase() === String(m.value).toLowerCase();
    case 'flow_size':
      return typeof flow.bytes === 'number' && cmpOp(m.op || 'gte', flow.bytes, m.value);
    case 'pkt_count':
      return typeof flow.pkts === 'number' && cmpOp(m.op || 'gte', flow.pkts, m.value);
    case 'periodicity':
      return checkBeacon(sig, m, flow);
    default:
      return false;
  }
}

// ---------- public API ----------
function loadSignatures(arr) {
  if (!Array.isArray(arr)) throw new Error('loadSignatures: expected array');
  SIGS.clear();
  let n = 0;
  for (const s of arr) {
    if (!s || !s.id || !Array.isArray(s.matchers)) continue;
    SIGS.set(s.id, {
      id: s.id,
      name: s.name || s.id,
      severity: s.severity || 'medium',
      category: s.category || 'malware',
      matchers: s.matchers,
      any: !!s.any,
      enabled: s.enabled !== false,
    });
    n++;
  }
  return n;
}

function evalFlow(flow) {
  if (!flow || typeof flow !== 'object') return [];
  const hits = [];
  for (const sig of SIGS.values()) {
    if (!sig.enabled) continue;
    let matched;
    if (sig.any) {
      matched = sig.matchers.some(m => evalMatcher(m, flow, sig));
    } else {
      matched = sig.matchers.every(m => evalMatcher(m, flow, sig));
    }
    if (matched) {
      const hit = {
        ts: flow.ts || nowSec(),
        sig_id: sig.id,
        sig_name: sig.name,
        severity: sig.severity,
        category: sig.category,
        src_ip: flow.src_ip,
        dst_ip: flow.dst_ip,
        dst_domain: flow.dst_domain,
        dst_port: flow.dst_port,
      };
      hits.push(hit);
      pushHit(hit);
    }
  }
  return hits;
}

// Parse a syslog-ish line into a flow-like object.
// Supports two common shapes seen on the box:
//   1) dnsmasq: "... dnsmasq[pid]: query[A] foo.example.com from 192.168.1.50"
//   2) nftables/iptables LOG: "... SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP SPT=12345 DPT=443 LEN=1500"
// Returns null if it can't extract anything useful.
function ingestSyslog(line) {
  if (!line || typeof line !== 'string') return null;
  const ts = nowSec();

  // dnsmasq query line
  const dnsq = line.match(/dnsmasq\S*:\s*query\[[A-Z]+\]\s+(\S+)\s+from\s+(\d+\.\d+\.\d+\.\d+)/i);
  if (dnsq) {
    return {
      ts,
      kind: 'dns',
      src_ip: dnsq[2],
      dst_domain: dnsq[1].toLowerCase().replace(/\.$/, ''),
      dst_port: 53,
      proto: 'udp',
      bytes: 0,
      pkts: 1,
    };
  }

  // dnsmasq reply (cached/forwarded)
  const dnsr = line.match(/dnsmasq\S*:\s*(?:reply|cached)\s+(\S+)\s+is\s+(\d+\.\d+\.\d+\.\d+)/i);
  if (dnsr) {
    return {
      ts,
      kind: 'dns',
      dst_domain: dnsr[1].toLowerCase().replace(/\.$/, ''),
      dst_ip: dnsr[2],
      dst_port: 53,
      proto: 'udp',
      bytes: 0,
      pkts: 1,
    };
  }

  // nftables / iptables LOG line
  const src = line.match(/SRC=(\d+\.\d+\.\d+\.\d+)/);
  const dst = line.match(/DST=(\d+\.\d+\.\d+\.\d+)/);
  if (src && dst) {
    const proto = (line.match(/PROTO=(\w+)/) || [])[1];
    const dpt   = (line.match(/DPT=(\d+)/)   || [])[1];
    const len   = (line.match(/LEN=(\d+)/)   || [])[1];
    return {
      ts,
      kind: 'flow',
      src_ip: src[1],
      dst_ip: dst[1],
      dst_port: dpt ? Number(dpt) : undefined,
      proto: proto ? proto.toLowerCase() : undefined,
      bytes: len ? Number(len) : 0,
      pkts: 1,
    };
  }

  return null;
}

function signatureCount() { return SIGS.size; }
function hitsRecent() { return HITS.slice(); }

// ---------- starter signatures ----------
// These are illustrative examples, not exhaustive threat intel.
// Replace/augment from a cloud feed in production.
const STARTER_SIGS = [
  {
    id: 'SIG-1001',
    name: 'IRC C2 channel (legacy botnet beacon port)',
    severity: 'high', category: 'malware',
    matchers: [
      { type: 'dst_port', value: 6667 },
      { type: 'proto', value: 'tcp' },
    ],
  },
  {
    id: 'SIG-1002',
    name: 'Cobalt Strike default beacon port',
    severity: 'critical', category: 'malware',
    matchers: [
      { type: 'dst_port', value: 50050 },
      { type: 'proto', value: 'tcp' },
    ],
  },
  {
    id: 'SIG-1003',
    name: 'DNS lookup of known sinkhole/C2 domain (no-ip dyn)',
    severity: 'high', category: 'malware',
    matchers: [
      { type: 'dst_domain', value: 'duckdns.org', mode: 'suffix' },
    ],
  },
  {
    id: 'SIG-1004',
    name: 'XMRig / Monero mining pool (default port)',
    severity: 'medium', category: 'crypto',
    matchers: [
      { type: 'dst_port', value: 3333 },
      { type: 'proto', value: 'tcp' },
    ],
  },
  {
    id: 'SIG-1005',
    name: 'Stratum mining protocol pool',
    severity: 'medium', category: 'crypto',
    matchers: [
      { type: 'dst_domain', value: 'minexmr.com', mode: 'suffix' },
    ],
  },
  {
    id: 'SIG-1006',
    name: 'Telnet to internet (Mirai-style recon/spread)',
    severity: 'high', category: 'recon',
    matchers: [
      { type: 'dst_port', value: 23 },
      { type: 'proto', value: 'tcp' },
    ],
  },
  {
    id: 'SIG-1007',
    name: 'SMB exposed to WAN (EternalBlue surface)',
    severity: 'high', category: 'recon',
    matchers: [
      { type: 'dst_port', value: 445 },
      { type: 'proto', value: 'tcp' },
    ],
  },
  {
    id: 'SIG-1008',
    name: 'Periodic beacon ~5min (low jitter)',
    severity: 'high', category: 'malware',
    matchers: [
      { type: 'periodicity', interval_s: 300, jitter_s: 20 },
      { type: 'flow_size', op: 'lte', value: 4096 },
    ],
  },
  {
    id: 'SIG-1009',
    name: 'Phishing kit hosting (free TLD lookup)',
    severity: 'medium', category: 'phishing',
    matchers: [
      { type: 'dst_domain', value: 'tk', mode: 'suffix' },
    ],
    any: false,
    enabled: true,
  },
  {
    id: 'SIG-1010',
    name: 'Large outbound flow to non-standard port (exfil heuristic)',
    severity: 'medium', category: 'malware',
    matchers: [
      { type: 'flow_size', op: 'gte', value: 10_000_000 },
      { type: 'proto', value: 'tcp' },
    ],
  },
  {
    id: 'SIG-1011',
    name: 'Tor directory authority contact',
    severity: 'low', category: 'recon',
    matchers: [
      { type: 'dst_port', value: 9001 },
      { type: 'proto', value: 'tcp' },
    ],
  },
];

// auto-load starter set so the engine is usable out-of-the-box
loadSignatures(STARTER_SIGS);

module.exports = {
  loadSignatures,
  evalFlow,
  ingestSyslog,
  signatureCount,
  hitsRecent,
  // exposed for tests / introspection
  _starterSignatures: STARTER_SIGS,
};
