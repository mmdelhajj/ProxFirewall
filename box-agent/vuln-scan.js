'use strict';
/*
 * vuln-scan.js — Internal vulnerability scan via `nmap -sV -O --open <subnet>`.
 *
 * Returns a parsed structure:
 *   [{ ip, mac, os, services: [{ port, service, version }] }]
 *
 * CVE matching is intentionally skipped — that requires a CVE feed. Customers
 * can paste service banners into a CVE search engine if they want.
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const STATE_DIR = '/var/lib/mes-box-agent';
try { fs.mkdirSync(STATE_DIR, { recursive: true }); } catch {}
const SCAN_PATH = path.join(STATE_DIR, 'vuln-scan.last.json');

function sh(cmd, timeout) {
  try { return execSync(cmd, { encoding: 'utf8', timeout: timeout || 8_000, stdio: ['ignore', 'pipe', 'pipe'] }).trim(); }
  catch { return null; }
}
function have(bin) { return !!sh(`which ${bin}`); }

function detectLanSubnet() {
  // Use the iface that holds the default route (or eth0 fallback)
  const iface = (() => {
    const out = sh('ip route show default | head -1');
    if (!out) return 'eth0';
    const m = out.match(/dev (\S+)/);
    return m ? m[1] : 'eth0';
  })();
  const addr = sh(`ip -4 addr show ${iface}`);
  if (!addr) return null;
  const m = addr.match(/inet (\d+\.\d+\.\d+\.\d+)\/(\d+)/);
  if (!m) return null;
  const ip = m[1], prefix = m[2];
  // Use the network from `ip route`. Cheap fallback: assume /24
  const base = ip.split('.').slice(0, 3).join('.');
  return `${base}.0/24`;   // be friendly to scans
}

function parseNmapOutput(out) {
  // Parse default text output from `nmap -sV -O --open <subnet>`
  const hosts = [];
  const sections = out.split(/\n(?=Nmap scan report for )/);
  for (const sec of sections) {
    if (!/^Nmap scan report for/.test(sec)) continue;
    const ipM = sec.match(/Nmap scan report for(?:\s+\S+)?\s+\(?(\d+\.\d+\.\d+\.\d+)\)?/);
    const macM = sec.match(/MAC Address: ([0-9A-Fa-f:]{17})/);
    const osM = sec.match(/(?:OS details|Aggressive OS guesses|Running):\s+(.+)/);
    const services = [];
    const reSvc = /^(\d+)\/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?$/gm;
    let mm;
    while ((mm = reSvc.exec(sec)) !== null) {
      services.push({
        port: parseInt(mm[1], 10),
        proto: mm[2],
        service: mm[3],
        version: (mm[4] || '').trim(),
      });
    }
    if (ipM) {
      hosts.push({
        ip: ipM[1],
        mac: macM ? macM[1].toLowerCase() : null,
        os: osM ? osM[1].trim().slice(0, 200) : null,
        services,
      });
    }
  }
  return hosts;
}

function runScan({ subnet } = {}) {
  if (!have('nmap')) return { ok: false, error: 'nmap_not_installed', hint: 'apt-get install -y nmap' };
  const sub = subnet || detectLanSubnet();
  if (!sub) return { ok: false, error: 'subnet_detect_failed' };
  const started = Date.now();
  // -sV service version, -O OS guess, --open only show open ports
  // Cap to 5 minutes; aggressive enough for a /24 home LAN.
  const out = sh(`nmap -sV -O --open --max-retries 1 --host-timeout 60s -T4 ${sub}`, 300_000);
  if (out === null) return { ok: false, error: 'nmap_run_failed' };
  const hosts = parseNmapOutput(out);
  const result = { ok: true, subnet: sub, hosts, scanned_at: started, duration_ms: Date.now() - started };
  try { fs.writeFileSync(SCAN_PATH, JSON.stringify(result, null, 2)); } catch {}
  return result;
}

function getLast() {
  try { return JSON.parse(fs.readFileSync(SCAN_PATH, 'utf8')); }
  catch { return null; }
}

module.exports = { runScan, getLast };
