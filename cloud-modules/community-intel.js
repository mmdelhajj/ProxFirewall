/*
 * community-intel.js — CrowdSec-style community threat intel (PULL ONLY).
 *
 * The customer does NOT share their attack data publicly. We just consume
 * widely-used free OSS feeds, merge into a single dedup'd blocked-IP/domain
 * set, and bolt it on to the per-customer policy bundle.
 *
 * State (attached to global `state` via init):
 *   state.community_intel = {
 *     ips: Set<string>,          // dedup'd v4 IPs
 *     domains: Set<string>,      // dedup'd lowercased domains
 *     last_refresh_at: number,   // epoch ms
 *     source_counts: { url: number },  // per-source line counts last time
 *     errors: { url: string },   // last error per failing source
 *   }
 *
 * Refresh cadence: every 6h (caller wires the setInterval), but `refresh()`
 * is also safe to call ad-hoc from an admin endpoint.
 *
 * Resilience: any failing source is logged and skipped; the others still
 * contribute. We never overwrite an existing successful refresh with empty
 * data — if all sources fail we keep the previous merged set intact.
 */

'use strict';

const https = require('https');
const http  = require('http');
const { URL } = require('url');

const SOURCES = [
  { url: 'https://lists.blocklist.de/lists/all.txt',                     kind: 'ips'           },
  { url: 'https://www.dshield.org/feeds/suspiciousdomains_Low.txt',      kind: 'domains'       },
  { url: 'https://reputation.alienvault.com/reputation.generic',         kind: 'ips-alienvault'},
  { url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',      kind: 'ips'           },
  { url: 'https://urlhaus.abuse.ch/downloads/text/',                     kind: 'urls'          },
  { url: 'https://hosts.gho.st/',                                        kind: 'hosts-file'    },
];

const FETCH_TIMEOUT_MS = 20_000;
// Cap how much we let any one source contribute so a malicious / runaway
// feed can't blow up cloud memory.
const MAX_LINES_PER_SOURCE = 250_000;

let _state = null;

function init(globalState) {
  _state = globalState;
  if (!_state.community_intel) {
    _state.community_intel = {
      ips: new Set(),
      domains: new Set(),
      last_refresh_at: 0,
      source_counts: {},
      errors: {},
    };
  } else {
    // Persisted state hydrates Sets back from arrays
    if (Array.isArray(_state.community_intel.ips)) {
      _state.community_intel.ips = new Set(_state.community_intel.ips);
    }
    if (Array.isArray(_state.community_intel.domains)) {
      _state.community_intel.domains = new Set(_state.community_intel.domains);
    }
    if (!_state.community_intel.source_counts) _state.community_intel.source_counts = {};
    if (!_state.community_intel.errors) _state.community_intel.errors = {};
  }
}

function _fetch(url) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(url); } catch (e) { return reject(e); }
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.request({
      method: 'GET',
      hostname: u.hostname,
      port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search,
      headers: { 'User-Agent': 'mes-network-cloud/1.0 (community-intel; pull-only)' },
      timeout: FETCH_TIMEOUT_MS,
    }, res => {
      if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return _fetch(new URL(res.headers.location, u).toString()).then(resolve, reject);
      }
      if (!res.statusCode || res.statusCode >= 400) {
        return reject(new Error('HTTP ' + res.statusCode));
      }
      const chunks = [];
      let total = 0;
      res.on('data', d => {
        total += d.length;
        if (total > 50 * 1024 * 1024) {
          req.destroy();
          return reject(new Error('feed too large (>50MB)'));
        }
        chunks.push(d);
      });
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      res.on('error', reject);
    });
    req.on('timeout', () => { req.destroy(new Error('timeout')); });
    req.on('error', reject);
    req.end();
  });
}

// Parsers — each tolerant: skip comments, blank lines, and lines that don't
// match the expected shape. Cap at MAX_LINES_PER_SOURCE.
function _parse(text, kind) {
  const ips = [];
  const domains = [];
  const lines = text.split(/\r?\n/);
  let count = 0;
  for (const raw of lines) {
    if (count >= MAX_LINES_PER_SOURCE) break;
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith(';') || line.startsWith('//')) continue;

    if (kind === 'ips') {
      // plain IPv4-per-line
      const m = line.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
      if (m) { ips.push(m[1]); count++; }
    } else if (kind === 'ips-alienvault') {
      // alienvault OTX format: "IP #score #...". First column is the IP.
      const tok = line.split(/[\s#]+/)[0];
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(tok)) { ips.push(tok); count++; }
    } else if (kind === 'domains') {
      // Internet Storm Center: "site.example.tld" per line, optional "Site"
      // header. Strip any leading "Site\n" header.
      if (/^site$/i.test(line)) continue;
      const tok = line.split(/\s+/)[0].toLowerCase();
      if (/^[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}$/.test(tok)) { domains.push(tok); count++; }
    } else if (kind === 'urls') {
      // URLhaus: "id,date,url,status,threat,tags,..." OR plain URL lines.
      // Extract just the hostname/domain.
      let urlStr = line;
      if (line.includes(',')) {
        // CSV-ish: take the column that looks like a URL
        const parts = line.split(',').map(s => s.replace(/^"|"$/g, ''));
        urlStr = parts.find(p => /^https?:\/\//i.test(p)) || '';
      }
      if (!urlStr) continue;
      try {
        const u = new URL(urlStr);
        const host = u.hostname.toLowerCase();
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) {
          ips.push(host); count++;
        } else if (/^[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}$/.test(host)) {
          domains.push(host); count++;
        }
      } catch {}
    } else if (kind === 'hosts-file') {
      // Standard /etc/hosts-style: "0.0.0.0 bad-domain.tld"
      const parts = line.split(/\s+/);
      if (parts.length >= 2) {
        const dom = parts[1].toLowerCase();
        if (/^[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}$/.test(dom) &&
            dom !== 'localhost') {
          domains.push(dom); count++;
        }
      }
    }
  }
  return { ips, domains };
}

async function refresh() {
  if (!_state) throw new Error('community-intel: init() must be called first');
  const ci = _state.community_intel;
  const newIps = new Set();
  const newDomains = new Set();
  const counts = {};
  const errors = {};
  let anySuccess = false;

  for (const src of SOURCES) {
    try {
      const text = await _fetch(src.url);
      const { ips, domains } = _parse(text, src.kind);
      for (const ip of ips) newIps.add(ip);
      for (const d of domains) newDomains.add(d);
      counts[src.url] = ips.length + domains.length;
      anySuccess = true;
      console.log(`         📡 community-intel ${src.url}: ${ips.length} IPs, ${domains.length} domains`);
    } catch (e) {
      errors[src.url] = e.message || String(e);
      console.log(`         ⚠️  community-intel ${src.url} failed: ${errors[src.url]}`);
    }
  }

  if (!anySuccess) {
    // Don't wipe a previously-good merged set if every source is down today.
    ci.errors = errors;
    return { ok: false, kept_existing: true, total_ips: ci.ips.size, total_domains: ci.domains.size };
  }

  ci.ips = newIps;
  ci.domains = newDomains;
  ci.last_refresh_at = Date.now();
  ci.source_counts = counts;
  ci.errors = errors;

  return {
    ok: true,
    last_refresh_at: ci.last_refresh_at,
    total_ips: ci.ips.size,
    total_domains: ci.domains.size,
    source_counts: counts,
    errors,
  };
}

function status() {
  if (!_state) return { enabled: false };
  const ci = _state.community_intel || {};
  return {
    last_refresh_at: ci.last_refresh_at || 0,
    total_ips: (ci.ips && ci.ips.size) || 0,
    total_domains: (ci.domains && ci.domains.size) || 0,
    source_counts: ci.source_counts || {},
    errors: ci.errors || {},
  };
}

// Return the top-N entries (by current set iteration order — Sets retain
// insertion order in V8, which roughly tracks recency since we rebuild fresh
// on each refresh). Caller caps to keep per-bundle payload sane.
function getIpsArray() {
  if (!_state || !_state.community_intel) return [];
  return Array.from(_state.community_intel.ips);
}
function getDomainsArray(cap = 50000) {
  if (!_state || !_state.community_intel) return [];
  const arr = Array.from(_state.community_intel.domains);
  return arr.length > cap ? arr.slice(0, cap) : arr;
}

module.exports = { init, refresh, status, getIpsArray, getDomainsArray, SOURCES };
