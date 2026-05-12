#!/usr/bin/env node
// mes Box agent — runs on the customer's on-premise device.
// Talks to the cloud (cloud.mes.net.lb), discovers LAN devices, reports flows,
// pulls policy, applies blocking rules via local DNS.

'use strict';

const fs    = require('fs');
const os    = require('os');
const path  = require('path');
const https = require('https');
const http  = require('http');
const crypto = require('crypto');
const { execSync, spawn } = require('child_process');

// ─── Config ───────────────────────────────────────────────────────────────
const CFG_PATH = process.env.CFG || '/etc/mes-box/agent.json';
const VERSION = '1.3.0';
// Optional box-side modules (gracefully missing if files not present)
let sigEngine = null, sniParser = null, ovpn = null, dnsStack = null, multiWan = null;
let ntpIntercept = null, disturbMod = null, bridgeMode = null, upnpMod = null;
try { sigEngine    = require('./sig-engine');    } catch (e) { console.error('[agent] sig-engine missing:', e.message); }
try { sniParser    = require('./sni-parser');    } catch (e) { console.error('[agent] sni-parser missing:', e.message); }
try { ovpn         = require('./openvpn');       } catch (e) { console.error('[agent] openvpn missing:', e.message); }
try { dnsStack     = require('./dns-stack');     } catch (e) { console.error('[agent] dns-stack missing:', e.message); }
try { multiWan     = require('./multi-wan');     } catch (e) { console.error('[agent] multi-wan missing:', e.message); }
try { ntpIntercept = require('./ntp-intercept'); } catch (e) { console.error('[agent] ntp-intercept missing:', e.message); }
try { disturbMod   = require('./disturb');       } catch (e) { console.error('[agent] disturb missing:', e.message); }
try { bridgeMode   = require('./bridge-mode');   } catch (e) { console.error('[agent] bridge-mode missing:', e.message); }
try { upnpMod      = require('./upnp');          } catch (e) { console.error('[agent] upnp missing:', e.message); }
let simpleMode = null;
try { simpleMode   = require('./simple-mode');   } catch (e) { console.error('[agent] simple-mode missing:', e.message); }
let wgClient = null;
try { wgClient = require('./wg-client'); } catch (e) { console.error('[agent] wg-client missing:', e.message); }
let dhcpMode = null;
try { dhcpMode     = require('./dhcp-mode');     } catch (e) { console.error('[agent] dhcp-mode missing:', e.message); }
let routerMode = null;
try { routerMode   = require('./router-mode');   } catch (e) { console.error('[agent] router-mode missing:', e.message); }
let qos = null;
try { qos          = require('./qos');           } catch (e) { console.error('[agent] qos missing:', e.message); }
let iotLockdown = null;
try { iotLockdown  = require('./iot-lockdown');  } catch (e) { console.error('[agent] iot-lockdown missing:', e.message); }
let quarantine = null;
try { quarantine   = require('./quarantine');    } catch (e) { console.error('[agent] quarantine missing:', e.message); }
let vulnScan = null;
try { vulnScan     = require('./vuln-scan');     } catch (e) { console.error('[agent] vuln-scan missing:', e.message); }
let openvpnClient = null;
try { openvpnClient = require('./openvpn-client'); } catch (e) { console.error('[agent] openvpn-client missing:', e.message); }
let devThroughput = null;
try { devThroughput = require('./device-throughput'); } catch (e) { console.error('[agent] device-throughput missing:', e.message); }
// Tier 2 — Suricata IDS/IPS + per-alarm pcap capture
let suricata = null;
try { suricata     = require('./suricata');     } catch (e) { console.error('[agent] suricata missing:', e.message); }
let pcapCapture = null;
try { pcapCapture  = require('./pcap-capture'); } catch (e) { console.error('[agent] pcap-capture missing:', e.message); }

// Read MAC of the requested interface (defaults to eth0)
function readMac(iface) {
  try { return fs.readFileSync(`/sys/class/net/${iface}/address`, 'utf8').trim().toLowerCase(); }
  catch { return ''; }
}

// First-boot self-registration: if no config exists, generate one by calling the cloud
async function selfRegisterFirstBoot() {
  const ifaceCandidates = ['eth0', 'enp0s3', 'enp1s0'];
  let mac = '';
  for (const i of ifaceCandidates) { mac = readMac(i); if (mac) break; }
  if (!mac) throw new Error('no MAC available — no usable network interface found');

  const cloudUrl = process.env.MES_CLOUD || 'https://cloud.mes.net.lb';
  const body = JSON.stringify({ mac, model: 'pi4', hostname: os.hostname() });
  const u = new URL(cloudUrl + '/api/box/self-register');
  const lib = u.protocol === 'https:' ? https : http;

  console.log(`[agent] First boot — self-registering MAC=${mac} with ${cloudUrl}…`);
  const result = await new Promise((resolve, reject) => {
    const req = lib.request({
      method: 'POST', hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname, headers: { 'Content-Type': 'application/json', 'Content-Length': body.length },
    }, res => {
      let chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
        catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.write(body); req.end();
  });

  if (result.status === 'claimed') {
    // MAC already authorized & claimed (rare — re-flash scenario). Need secret another way.
    console.error('[agent] MAC is already claimed but we have no secret. Manual re-pairing required.');
    process.exit(2);
  }
  if (!result.code || !result.secret) {
    throw new Error('self-register did not return code+secret: ' + JSON.stringify(result));
  }

  // Persist config so we don't re-register
  const cfg = {
    box_mac: mac,
    box_secret: result.secret,
    cloud_url: cloudUrl,
    lan_iface: ifaceCandidates.find(readMac) || 'eth0',
    pairing_code: result.code,
    pairing_expires_at: result.expires_at,
    self_registered: true,
  };
  fs.mkdirSync(path.dirname(CFG_PATH), { recursive: true });
  fs.writeFileSync(CFG_PATH, JSON.stringify(cfg, null, 2));
  fs.chmodSync(CFG_PATH, 0o600);

  // Display the pairing code prominently — first thing customer needs
  displayPairingCode(result.code);

  return cfg;
}

function displayPairingCode(code) {
  // 1. Write to a well-known file so users can SSH in and `cat` it if they need to
  try {
    fs.mkdirSync('/var/log/mes-box', { recursive: true });
    fs.writeFileSync('/var/log/mes-box/pairing-code.txt',
      `Pairing code: ${code}\nEnter this in cloud.mes.net.lb/pwa → "Add a box"\n`);
  } catch {}
  // 2. Pretty-print to console (visible if a monitor is attached or via journalctl)
  const banner = '\n' +
    '╔══════════════════════════════════════════════╗\n' +
    '║                                              ║\n' +
    '║      mes Network — your pairing code:        ║\n' +
    '║                                              ║\n' +
    `║              ${code}                          ║\n` +
    '║                                              ║\n' +
    '║  Enter at: cloud.mes.net.lb/pwa              ║\n' +
    '║            → "Add a box"                     ║\n' +
    '║                                              ║\n' +
    '╚══════════════════════════════════════════════╝\n';
  console.log(banner);
  // 3. Also blink the activity LED in a Morse-like pattern (best-effort)
  blinkPairingCode(code);
}

function blinkPairingCode(code) {
  try {
    const ledPath = '/sys/class/leds/ACT/brightness';  // Pi 4 onboard activity LED
    if (!fs.existsSync(ledPath)) return;
    // Disable kernel-driven blinking
    try { fs.writeFileSync('/sys/class/leds/ACT/trigger', 'none'); } catch {}
    // Blink each character: each digit/letter mapped to (charCode % 9) + 1 short blinks
    let i = 0;
    const blinkOnce = (n, then) => {
      if (n === 0) return then();
      fs.writeFileSync(ledPath, '1');
      setTimeout(() => {
        fs.writeFileSync(ledPath, '0');
        setTimeout(() => blinkOnce(n - 1, then), 200);
      }, 200);
    };
    const next = () => {
      if (i >= code.length) { setTimeout(() => blinkPairingCode(code), 5000); return; }
      const n = (code.charCodeAt(i) - 48) % 9 + 1;
      i++;
      blinkOnce(n, () => setTimeout(next, 700));
    };
    next();
  } catch {}
}

let cfg;
function loadConfig() {
  if (fs.existsSync(CFG_PATH)) {
    return JSON.parse(fs.readFileSync(CFG_PATH, 'utf8'));
  }
  return null;
}

const STATE_PATH = path.dirname(CFG_PATH) + '/agent-state.json';
let agentState = {};
function saveAgentState() {
  fs.writeFileSync(STATE_PATH, JSON.stringify(agentState, null, 2));
}

let BOX_MAC, CLOUD, SECRET, LAN_IF;
async function bootstrap() {
  cfg = loadConfig();
  if (!cfg) {
    cfg = await selfRegisterFirstBoot();
    console.log('[agent] Self-registration complete. Code displayed; waiting for customer claim…');
  }
  if (fs.existsSync(STATE_PATH)) {
    try { agentState = JSON.parse(fs.readFileSync(STATE_PATH, 'utf8')); } catch {}
  }
  BOX_MAC = (cfg.box_mac || '').toLowerCase();
  CLOUD   = (cfg.cloud_url || 'https://cloud.mes.net.lb').replace(/\/+$/, '');
  SECRET  = cfg.box_secret;
  LAN_IF  = cfg.lan_iface || 'eth0';

  if (!BOX_MAC || !SECRET) {
    console.error('[agent] config still missing box_mac or box_secret after bootstrap');
    process.exit(2);
  }
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────
function api(method, urlPath, body, opts = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(CLOUD + urlPath);
    const data = body ? Buffer.from(JSON.stringify(body)) : null;
    const headers = { 'User-Agent': `mes-box/${VERSION}`, ...(opts.headers || {}) };
    if (data) {
      headers['Content-Type']   = 'application/json';
      headers['Content-Length'] = data.length;
    }
    if (agentState.token && !opts.no_auth) headers['Authorization'] = `Bearer ${agentState.token}`;
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.request({
      method, hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + (u.search || ''), headers,
      // For local dev, allow self-signed
      rejectUnauthorized: !cfg.insecure_tls,
    }, res => {
      let chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const buf = Buffer.concat(chunks);
        const body = buf.toString('utf8');
        if (res.statusCode >= 400) return reject(new Error(`HTTP ${res.statusCode}: ${body.slice(0, 200)}`));
        try { resolve(JSON.parse(body)); }
        catch { resolve({ raw: body, status: res.statusCode, headers: res.headers }); }
      });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

// ─── Auth ─────────────────────────────────────────────────────────────────
async function ensureAuth() {
  if (agentState.token && agentState.token_expires_at > Date.now() + 30 * 60_000) return;
  const ts  = Date.now();
  const sig = crypto.createHmac('sha256', SECRET).update(`${BOX_MAC}:${ts}`).digest('hex');
  const r = await api('POST', '/api/box/auth', { mac: BOX_MAC, ts, sig }, { no_auth: true });
  agentState.token = r.token;
  agentState.token_expires_at = Date.now() + (r.expires_in - 3600) * 1000;
  saveAgentState();
  console.log(`[agent] Authenticated. Token expires in ${(r.expires_in / 3600).toFixed(0)}h.`);
}

// ─── LAN device discovery (ARP + ip neigh) ────────────────────────────────
function scanArp() {
  const out = [];
  try {
    const txt = execSync(`ip neigh show dev ${LAN_IF}`, { encoding: 'utf8' });
    for (const line of txt.split('\n')) {
      // 192.168.1.42 lladdr aa:bb:cc:dd:ee:ff REACHABLE
      const m = line.match(/^(\S+)\s+lladdr\s+([0-9a-f:]{17})\s+(\w+)/i);
      if (!m) continue;
      const [, ip, mac, state] = m;
      if (state === 'FAILED') continue;
      out.push({ ip, mac: mac.toLowerCase(), online: state !== 'STALE' });
    }
  } catch (e) { /* ignore — interface may not exist on test rigs */ }
  // Enrich with hostname from /etc/hosts or DHCP leases
  try {
    if (fs.existsSync('/var/lib/misc/dnsmasq.leases')) {
      const leases = fs.readFileSync('/var/lib/misc/dnsmasq.leases', 'utf8');
      for (const line of leases.split('\n')) {
        const f = line.split(' ');
        if (f.length < 4) continue;
        const [, mac, ip, hostname] = f;
        const d = out.find(x => x.mac === mac.toLowerCase());
        if (d) d.hostname = hostname;
        else out.push({ ip, mac: mac.toLowerCase(), hostname, online: true });
      }
    }
  } catch {}
  // Vendor lookup from MAC OUI (just first 3 bytes)
  for (const d of out) {
    d.vendor = vendorOf(d.mac);
  }
  return out;
}

// OUI table loaded from /opt/mes-box/oui-table.json (installed alongside agent).
// Falls back to a tiny built-in if the file is missing.
const OUI_FALLBACK = {
  'aa:bb:cc': 'Mock', '20:6d:31': 'Firewalla', '78:9a:18': 'Apple',
  'b8:27:eb': 'RaspberryPi', 'dc:a6:32': 'RaspberryPi', '00:e0:4c': 'Realtek',
  '54:60:09': 'TpLink', '00:1a:2b': 'Cisco', '00:1d:0f': 'Samsung',
};
let OUI_TABLE = OUI_FALLBACK;
try {
  for (const p of ['/opt/mes-box/oui-table.json', path.join(__dirname, 'oui-table.json')]) {
    if (fs.existsSync(p)) {
      OUI_TABLE = JSON.parse(fs.readFileSync(p, 'utf8'));
      console.log(`[agent] OUI table loaded: ${Object.keys(OUI_TABLE).length} entries`);
      break;
    }
  }
} catch (e) { console.error('[agent] OUI load failed:', e.message); }
function vendorOf(mac) {
  return OUI_TABLE[mac.toLowerCase().slice(0, 8)] || '';
}

// ─── Flow capture (parse conntrack -L -o extended) ───────────────────────
// Requires net.netfilter.nf_conntrack_acct=1 sysctl (otherwise bytes=0 for all
// flows). Agent sets this on startup. Conntrack reports each connection with
// TWO `bytes=` and `packets=` fields: first is the original direction
// (src→dst, i.e. device→internet = upload), second is the reply direction
// (dst→src = download).
function captureFlows() {
  const flows = [];
  try {
    const txt = execSync('conntrack -L -o extended 2>/dev/null || cat /proc/net/nf_conntrack 2>/dev/null', { encoding: 'utf8' });
    for (const line of txt.split('\n').slice(0, 1000)) {
      if (!line.includes('src=')) continue;
      const src = (line.match(/src=([\d.]+)/) || [])[1];
      const dst = (line.match(/dst=([\d.]+)/) || [])[1];
      const dport = parseInt((line.match(/dport=(\d+)/) || [])[1] || 0);
      const proto = line.includes('proto=tcp') || line.startsWith('tcp') ? 'tcp' :
                    line.includes('proto=udp') || line.startsWith('udp') ? 'udp' : 'other';
      // Pull ALL bytes= matches — first is original-dir (upload), second is reply-dir (download).
      const byteMatches = [...line.matchAll(/bytes=(\d+)/g)];
      const bytes_up   = parseInt(byteMatches[0] ? byteMatches[0][1] : 0) || 0;
      const bytes_down = parseInt(byteMatches[1] ? byteMatches[1][1] : 0) || 0;
      // Skip LAN-to-LAN noise (only report flows leaving the network)
      if (!src || !dst || isPrivate(dst)) continue;
      // Skip zero-byte flows (still mid-handshake / no data exchanged yet)
      if (bytes_up === 0 && bytes_down === 0) continue;
      flows.push({
        ts: Date.now(),
        src_ip: src, dst_ip: dst, dst_port: dport, proto,
        bytes_up, bytes_down,
        src_mac: macForIp(src),
      });
    }
  } catch {}
  return flows;
}
function isPrivate(ip) {
  if (!ip) return true;
  const o = ip.split('.').map(Number);
  if (o[0] === 10) return true;
  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true;
  if (o[0] === 192 && o[1] === 168) return true;
  if (o[0] === 127) return true;
  if (o[0] === 0)   return true;
  return false;
}
let arpIpToMac = {};
function macForIp(ip) { return arpIpToMac[ip] || ''; }

// ─── Apply full policy bundle from cloud ──────────────────────────────────
const DNSMASQ_BLOCKS    = '/etc/dnsmasq.d/mes-box-blocks.conf';
const DNSMASQ_LEASES    = '/etc/dnsmasq.d/mes-box-dhcp.conf';
const DNSMASQ_UPSTREAMS = '/etc/dnsmasq.d/mes-box-upstreams.conf';
const DNSMASQ_PER_DEV_DNS = '/etc/dnsmasq.d/mes-box-per-device-dns.conf';   // Tier-1 Feature A
const NFT_TABLE = 'mes_box';
const NFT_BLOCK_SET   = 'blocked_ips';
const NFT_QUOTA_SET   = 'quota_blocked_macs';

function writeIfChanged(path, content) {
  let prev = '';
  try { prev = fs.readFileSync(path, 'utf8'); } catch {}
  if (prev === content) return false;
  fs.writeFileSync(path, content);
  return true;
}

// dnsmasq SIGHUP only re-reads /etc/hosts + leases, NOT /etc/dnsmasq.d/*.conf
// (which is where we put block/upstream/safe-search configs). Restart is the
// only way to make dnsmasq actually pick up changes there. It takes ~200ms.
// Debounced 1s to coalesce bursts when many config files change at once.
let _dnsmasqReloadTimer = null;
function reloadDnsmasq() {
  if (_dnsmasqReloadTimer) return;
  _dnsmasqReloadTimer = setTimeout(() => {
    _dnsmasqReloadTimer = null;
    try { execSync('systemctl restart dnsmasq 2>/dev/null || pkill -HUP dnsmasq 2>/dev/null || true'); } catch {}
  }, 1000);
}

function applyPolicy(p) {
  if (!p) return;
  let dnsmasqDirty = false;
  let nftablesDirty = false;

  // 1. dnsmasq blocks (domains + categories + Safe Search CNAMEs)
  const blockedDomains = new Set(p.blocked_domains || []);
  // Captive-portal target IP — agent serves on this on the LAN
  const portalIp = (cfg.lan_ip_for_portal || localIpFor(LAN_IF) || '0.0.0.0');
  const lines = ['# mes Network — auto-generated. Do not edit by hand.'];
  for (const d of blockedDomains) {
    if (!d || d.length > 200) continue;
    lines.push(`address=/${d}/${portalIp}`);
  }
  // Tier-1 Smart Block: domain pattern matches (suffix / prefix / contains).
  // dnsmasq's `address=/X/IP` already matches X and all its subdomains, so for
  // 'suffix' we just emit address=/value/0.0.0.0. For 'prefix' / 'contains' we
  // synthesise wildcard hostnames as best we can with dnsmasq syntax.
  for (const pat of (p.blocked_domain_patterns || [])) {
    const v = (pat && pat.value || '').toLowerCase().replace(/[^a-z0-9.\-*]/g, '');
    if (!v) continue;
    if (pat.pattern_type === 'suffix') {
      // Block live.tiktok.com AND every subdomain of live.tiktok.com (but NOT tiktok.com itself)
      lines.push(`address=/*.${v}/${portalIp}`);
      lines.push(`address=/${v}/${portalIp}`);
    } else if (pat.pattern_type === 'prefix') {
      // dnsmasq cannot truly do prefix matching; treat as a suffix on the leftmost label
      lines.push(`address=/${v}/${portalIp}`);
    } else if (pat.pattern_type === 'contains') {
      // No native dnsmasq support; emit the literal so at least exact hits drop
      lines.push(`address=/${v}/${portalIp}`);
    }
  }
  // Safe Search rewrites (cname-style: rewrite query for X to return Y)
  for (const [host, target] of Object.entries(p.safe_search || {})) {
    lines.push(`cname=${host},${target}`);
  }
  // Schedule-based blocking: write a tag-block file. dnsmasq doesn't natively do time
  // ranges per host, so the agent does it: every minute, recompute who's currently
  // blocked by schedule and write 'address=/0/' for them. Implemented in tickSchedules().
  if (writeIfChanged(DNSMASQ_BLOCKS, lines.join('\n') + '\n')) dnsmasqDirty = true;

  // 2. dnsmasq custom upstreams (per-customer)
  if ((p.dns_upstreams || []).length > 0) {
    const upstreamLines = ['# mes Network — custom DNS upstreams', 'no-resolv', ...p.dns_upstreams.map(u => `server=${u}`)];
    if (writeIfChanged(DNSMASQ_UPSTREAMS, upstreamLines.join('\n') + '\n')) dnsmasqDirty = true;
  } else {
    // Remove if previously set
    try { if (fs.existsSync(DNSMASQ_UPSTREAMS)) { fs.unlinkSync(DNSMASQ_UPSTREAMS); dnsmasqDirty = true; } } catch {}
  }

  // 2b. Custom DNS records (hostname → IP overrides) — like /etc/hosts entries
  const DNSMASQ_RECORDS = '/etc/dnsmasq.d/mes-box-records.conf';
  if ((p.dns_records || []).length > 0) {
    const recLines = ['# mes Network — custom DNS records'];
    for (const r of p.dns_records) {
      if (!r.hostname || !r.ip) continue;
      recLines.push(`address=/${r.hostname}/${r.ip}`);
    }
    if (writeIfChanged(DNSMASQ_RECORDS, recLines.join('\n') + '\n')) dnsmasqDirty = true;
  } else {
    try { if (fs.existsSync(DNSMASQ_RECORDS)) { fs.unlinkSync(DNSMASQ_RECORDS); dnsmasqDirty = true; } } catch {}
  }

  // 3. Static DHCP leases
  if ((p.dhcp_leases || []).length > 0) {
    const leaseLines = ['# mes Network — static DHCP leases'];
    for (const l of p.dhcp_leases) {
      if (!l.mac || !l.ip) continue;
      const host = l.hostname ? `,${l.hostname.replace(/[^a-z0-9-]/gi, '')}` : '';
      leaseLines.push(`dhcp-host=${l.mac},${l.ip}${host}`);
    }
    if (writeIfChanged(DNSMASQ_LEASES, leaseLines.join('\n') + '\n')) dnsmasqDirty = true;
  } else {
    try { if (fs.existsSync(DNSMASQ_LEASES)) { fs.unlinkSync(DNSMASQ_LEASES); dnsmasqDirty = true; } } catch {}
  }

  // 3b. Tier-1 Feature A: per-device DNS upstream via DHCP option 6.
  // For each (mac → upstream IP), emit a tagged dhcp-host + dhcp-option line
  // so dnsmasq hands out a different resolver to that device.
  const perDevDns = p.per_device_dns_upstream || {};
  const perDevMacs = Object.keys(perDevDns);
  if (perDevMacs.length > 0) {
    const out = ['# mes Network — per-device DNS upstream (option 6 by MAC)'];
    let i = 0;
    for (const mac of perDevMacs) {
      const ip = perDevDns[mac];
      if (!ip || !/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) continue;
      const tag = `mesdns${i++}`;
      out.push(`dhcp-host=${mac},set:${tag}`);
      out.push(`dhcp-option=tag:${tag},option:dns-server,${ip}`);
    }
    if (writeIfChanged(DNSMASQ_PER_DEV_DNS, out.join('\n') + '\n')) dnsmasqDirty = true;
  } else {
    try { if (fs.existsSync(DNSMASQ_PER_DEV_DNS)) { fs.unlinkSync(DNSMASQ_PER_DEV_DNS); dnsmasqDirty = true; } } catch {}
  }

  if (dnsmasqDirty) {
    reloadDnsmasq();
    console.log(`[agent] dnsmasq reloaded (blocks=${blockedDomains.size}, upstreams=${(p.dns_upstreams||[]).length}, leases=${(p.dhcp_leases||[]).length}, per_dev_dns=${perDevMacs.length})`);
  }

  // 4. nftables IP blocking + quota-blocked-MAC blocking + port forwards
  applyNftables(p);

  // 5. tc/htb bandwidth throttling per device
  applyQos(p);

  // 6. VLANs
  applyVlans(p);

  // 7. Guest WiFi
  applyGuestWifi(p);

  // 8. Site-to-site VPN (one wg interface per tunnel)
  applyS2sTunnels(p);

  // 9. Per-device VPN routing (route specific MACs through wg)
  applyVpnRouting(p);

  // 10. Schedule timer
  agentState.schedules = p.schedules || [];
  saveAgentState();

  // 11. Tier-1 Smart Block: cache SNI patterns for live matching by sni-parser.
  agentState.blocked_sni_patterns = Array.isArray(p.blocked_sni_patterns) ? p.blocked_sni_patterns : [];
}

// Tier-1 Smart Block — match a TLS SNI against the cached pattern list.
// Returns the matching pattern object or null. Called from the sni-parser
// hook so we can drop matching connections via iptables connbytes.
function _matchSniPattern(sni) {
  if (!sni) return null;
  const sniL = String(sni).toLowerCase();
  for (const p of (agentState.blocked_sni_patterns || [])) {
    const v = (p && p.value || '').toLowerCase();
    if (!v) continue;
    if (p.pattern_type === 'sni-prefix') {
      if (sniL.startsWith(v)) return p;
    } else if (p.pattern_type === 'suffix') {
      if (sniL === v || sniL.endsWith('.' + v)) return p;
    } else if (p.pattern_type === 'contains') {
      if (sniL.includes(v)) return p;
    } else if (p.pattern_type === 'exact') {
      if (sniL === v) return p;
    }
  }
  return null;
}
function _dropTcpForSni(src_ip, dst_ip, dst_port) {
  // Best-effort post-hoc drop. The first packet of the connection has already
  // gone through; iptables connbytes ensures subsequent packets of this flow
  // are dropped without keeping a per-flow rule forever.
  if (!src_ip || !dst_ip) return;
  try {
    execSync(`iptables -I FORWARD -s ${src_ip} -d ${dst_ip} -p tcp --dport ${dst_port||443} -m connbytes --connbytes 1: --connbytes-mode packets --connbytes-dir original -j DROP 2>/dev/null`, { stdio: 'ignore' });
  } catch {}
}

function applyVlans(p) {
  const vlans = p.vlans || [];
  if (!vlans.length) return;
  try { execSync('command -v ip', { stdio: 'ignore' }); } catch { return; }
  const lines = ['# mes Network — auto-generated VLANs'];
  for (const v of vlans) {
    if (!v.vlan_id || !v.subnet) continue;
    const ifname = `${LAN_IF}.${v.vlan_id}`;
    try {
      execSync(`ip link show ${ifname} 2>/dev/null || ip link add link ${LAN_IF} name ${ifname} type vlan id ${v.vlan_id}`, { stdio: 'pipe' });
      execSync(`ip addr replace ${v.gateway}/24 dev ${ifname}`, { stdio: 'pipe' });
      execSync(`ip link set ${ifname} up`, { stdio: 'pipe' });
    } catch {}
    lines.push(`# VLAN ${v.vlan_id}: ${v.name}`);
    lines.push(`interface=${ifname}`);
    lines.push(`dhcp-range=set:${ifname},${v.dhcp_start},${v.dhcp_end},12h`);
    if (v.isolated_from_main) {
      // Drop forwarding between vlan and lan via nft
      try { execSync(`nft add rule inet ${NFT_TABLE} forward iifname ${ifname} oifname ${LAN_IF} drop 2>/dev/null`, { stdio: 'ignore' }); } catch {}
      try { execSync(`nft add rule inet ${NFT_TABLE} forward iifname ${LAN_IF} oifname ${ifname} drop 2>/dev/null`, { stdio: 'ignore' }); } catch {}
    }
  }
  if (writeIfChanged('/etc/dnsmasq.d/mes-box-vlans.conf', lines.join('\n') + '\n')) {
    try { reloadDnsmasq(); } catch {}
  }
}

function applyGuestWifi(p) {
  const g = p.guest_wifi || {};
  const HOSTAPD_GUEST = '/etc/hostapd/hostapd-guest.conf';
  if (!g.enabled || !g.ssid) {
    // Tear down if previously enabled
    try { execSync('systemctl stop hostapd-guest 2>/dev/null', { stdio: 'ignore' }); } catch {}
    try { fs.unlinkSync(HOSTAPD_GUEST); } catch {}
    return;
  }
  const conf = [
    `# Guest WiFi — auto-generated`,
    `interface=wlan1`,                  // requires a 2nd radio or wlan virtual
    `driver=nl80211`,
    `ssid=${g.ssid}`,
    `hw_mode=g`,
    `channel=11`,
    `auth_algs=1`,
    `wpa=2`,
    `wpa_passphrase=${g.password}`,
    `wpa_key_mgmt=WPA-PSK`,
    `rsn_pairwise=CCMP`,
    `ap_isolate=${g.isolate_from_lan ? 1 : 0}`,
  ].join('\n') + '\n';
  if (writeIfChanged(HOSTAPD_GUEST, conf)) {
    try { execSync(`hostapd -B ${HOSTAPD_GUEST} 2>/dev/null`, { stdio: 'ignore' }); } catch {}
  }
}

function applyS2sTunnels(p) {
  const tunnels = p.s2s_tunnels || [];
  for (const t of tunnels) {
    const ifname = `wgs2s${t.id.slice(0, 6)}`;
    const conf = [
      `[Interface]`,
      `PrivateKey = ${t.my_priv}`,
      `Address = ${t.my_addr}`,
      `ListenPort = ${t.listen_port}`,
      ``,
      `[Peer]`,
      `PublicKey = ${t.peer_pub}`,
      `AllowedIPs = ${t.peer_subnet}`,
      t.peer_endpoint ? `Endpoint = ${t.peer_endpoint}` : '# peer endpoint pending — peer hasn\'t reported public IP yet',
      `PersistentKeepalive = 25`,
    ].join('\n') + '\n';
    const path = `/etc/wireguard/${ifname}.conf`;
    if (writeIfChanged(path, conf)) {
      try {
        execSync(`wg-quick down ${ifname} 2>/dev/null || true`, { stdio: 'ignore' });
        execSync(`wg-quick up ${ifname}`, { stdio: 'pipe' });
        console.log(`[agent] s2s tunnel ${t.name} (${ifname}) up`);
      } catch (e) { console.error(`[agent] s2s ${ifname} failed:`, e.message); }
    }
  }
}

function applyVpnRouting(p) {
  const macs = p.vpn_routed_macs || [];
  if (!macs.length) return;
  // Mark packets from these MACs and route through table 50 which has wg as default
  try {
    execSync('ip rule del fwmark 50 table 50 2>/dev/null', { stdio: 'ignore' });
    execSync('ip rule add fwmark 50 table 50', { stdio: 'pipe' });
    execSync('ip route add default dev wg0 table 50 2>/dev/null', { stdio: 'ignore' });
    // Mark traffic from each MAC
    execSync(`nft add chain inet ${NFT_TABLE} mangle { type filter hook prerouting priority -150; } 2>/dev/null`, { stdio: 'ignore' });
    for (const mac of macs) {
      try { execSync(`nft add rule inet ${NFT_TABLE} mangle ether saddr ${mac} meta mark set 50 2>/dev/null`, { stdio: 'ignore' }); } catch {}
    }
    console.log(`[agent] VPN-routing applied for ${macs.length} MACs`);
  } catch (e) { console.error('[agent] vpn routing failed:', e.message); }
}

function applyQos(p) {
  const rules = p.qos_rules || [];
  if (!rules.length) return;
  // Skip if `tc` not available
  try { execSync('command -v tc', { stdio: 'ignore' }); }
  catch { return; }
  const iface = LAN_IF;
  // Reset egress qdisc
  try { execSync(`tc qdisc del dev ${iface} root 2>/dev/null`, { stdio: 'ignore' }); } catch {}
  try { execSync(`tc qdisc add dev ${iface} root handle 1: htb default 10`); } catch (e) { return; }
  // Default class: full speed
  execSync(`tc class add dev ${iface} parent 1: classid 1:10 htb rate 1000mbit ceil 1000mbit`);
  let classId = 100;
  for (const r of rules) {
    if (!r.device_mac || !r.down_kbps) continue;
    const cid = classId++;
    try {
      execSync(`tc class add dev ${iface} parent 1: classid 1:${cid} htb rate ${r.down_kbps}kbit ceil ${r.down_kbps}kbit`);
      // Filter by destination MAC for download direction (traffic leaving the box towards the device)
      execSync(`tc filter add dev ${iface} protocol ip parent 1: prio 1 u32 match ether dst ${r.device_mac} flowid 1:${cid}`);
    } catch (e) {
      console.error(`[agent] qos rule failed for ${r.device_mac}:`, e.message);
    }
  }
  console.log(`[agent] QoS applied: ${rules.length} rules`);
}

function applyNftables(p) {
  // Build the desired nft script and apply atomically
  // Accept both bare IPv4 (1.2.3.4) and CIDR (1.2.3.0/24) — nft interval sets
  // handle both. CIDRs come in via geo-block expansion (Fix 6) where the cloud
  // turns each country code into a list of network ranges.
  const blockedIps  = (p.blocked_ips || []).filter(ip => /^\d+\.\d+\.\d+\.\d+(\/\d+)?$/.test(ip)).slice(0, 10000);
  const blockedIp6s = (p.blocked_ips || []).filter(ip => ip.includes(':') && /^[0-9a-f:]+$/i.test(ip)).slice(0, 5000);
  const quotaMacs   = (p.quota_blocked || []).filter(m => /^[0-9a-f:]{17}$/.test(m));
  const forwards    = (p.port_forwards || []);

  // Skip nftables work if `nft` is unavailable (test environments)
  try { execSync('command -v nft', { stdio: 'ignore' }); }
  catch { return; }

  const NFT_BLOCK_SET6 = NFT_BLOCK_SET + '6';
  // `flush table` keeps set elements alive — must `delete table` + re-create
  // for elements to disappear when the policy bundle drops them.
  const script = [
    `add table inet ${NFT_TABLE}`,
    `delete table inet ${NFT_TABLE}`,
    `add table inet ${NFT_TABLE}`,
    `add set inet ${NFT_TABLE} ${NFT_BLOCK_SET}  { type ipv4_addr; flags interval; }`,
    `add set inet ${NFT_TABLE} ${NFT_BLOCK_SET6} { type ipv6_addr; flags interval; }`,
    `add set inet ${NFT_TABLE} ${NFT_QUOTA_SET}  { type ether_addr; }`,
    `add chain inet ${NFT_TABLE} forward { type filter hook forward priority 0; }`,
    `add rule  inet ${NFT_TABLE} forward ip  daddr @${NFT_BLOCK_SET}  drop`,
    `add rule  inet ${NFT_TABLE} forward ip6 daddr @${NFT_BLOCK_SET6} drop`,
    `add rule  inet ${NFT_TABLE} forward ether saddr @${NFT_QUOTA_SET} drop`,
  ];
  if (blockedIps.length) {
    script.push(`add element inet ${NFT_TABLE} ${NFT_BLOCK_SET} { ${blockedIps.join(', ')} }`);
  }
  if (blockedIp6s.length) {
    script.push(`add element inet ${NFT_TABLE} ${NFT_BLOCK_SET6} { ${blockedIp6s.join(', ')} }`);
  }
  if (quotaMacs.length) {
    script.push(`add element inet ${NFT_TABLE} ${NFT_QUOTA_SET} { ${quotaMacs.join(', ')} }`);
  }
  // Geo block via NFT IP set — cloud provides countries, agent doesn't have geo table on box,
  // so it relies on cloud to push expanded IPs in blocked_ips. (Future: ship GeoIP DB to box.)

  // Port forwards (NAT)
  if (forwards.length) {
    script.push(`add table ip ${NFT_TABLE}_nat`);
    script.push(`flush table ip ${NFT_TABLE}_nat`);
    script.push(`add table ip ${NFT_TABLE}_nat`);
    script.push(`add chain ip ${NFT_TABLE}_nat prerouting { type nat hook prerouting priority -100; }`);
    for (const f of forwards) {
      const protos = f.proto === 'both' ? ['tcp','udp'] : [f.proto || 'tcp'];
      for (const proto of protos) {
        script.push(`add rule ip ${NFT_TABLE}_nat prerouting ${proto} dport ${f.ext_port} dnat to ${f.int_ip}:${f.int_port}`);
      }
    }
  }

  const tmp = '/tmp/.mes-box-nft.script';
  fs.writeFileSync(tmp, script.join('\n') + '\n');
  try {
    execSync(`nft -f ${tmp}`, { stdio: 'pipe' });
    console.log(`[agent] nftables applied (block_ips=${blockedIps.length}, quota_macs=${quotaMacs.length}, fwds=${forwards.length})`);
  } catch (e) {
    console.error('[agent] nftables apply failed:', String(e.stderr || e.message).slice(0, 200));
  }
}

// ─── Schedule enforcement (per-minute tick) ───────────────────────────────
const DNSMASQ_SCHEDULE_BLOCKS = '/etc/dnsmasq.d/mes-box-schedule.conf';
function tickSchedules() {
  const schedules = agentState.schedules || [];
  if (!schedules.length) {
    try { if (fs.existsSync(DNSMASQ_SCHEDULE_BLOCKS)) { fs.unlinkSync(DNSMASQ_SCHEDULE_BLOCKS); reloadDnsmasq(); } } catch {}
    return;
  }
  const now = new Date();
  const day = ['sun','mon','tue','wed','thu','fri','sat'][now.getDay()];
  const hhmm = now.toTimeString().slice(0,5);
  const blockedMacs = new Set();
  for (const s of schedules) {
    if (s.enabled === false) continue;
    if (Array.isArray(s.days) && !s.days.includes(day)) continue;
    if (!isNowBetween(hhmm, s.start_hhmm, s.end_hhmm)) continue;
    for (const mac of (s.effective_macs || s.device_macs || [])) blockedMacs.add(mac);
  }
  // Apply by adding MACs to the nft quota set (reuses the same chain)
  if (blockedMacs.size) {
    try {
      const macList = Array.from(blockedMacs).join(', ');
      execSync(`nft add element inet ${NFT_TABLE} ${NFT_QUOTA_SET} { ${macList} } 2>/dev/null || true`);
    } catch {}
  }
}
function isNowBetween(now, start, end) {
  if (!start || !end) return false;
  if (start <= end) return now >= start && now < end;
  // Wraps midnight (e.g. 21:00 - 07:00)
  return now >= start || now < end;
}

// ─── Captive portal (tiny http server on box LAN IP, port 8082) ───────────
function startCaptivePortal() {
  if (cfg.captive_portal === false) return;
  const portal = http.createServer((req, res) => {
    const host = (req.headers.host || '').split(':')[0];
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`<!DOCTYPE html><html><head><title>Blocked</title>
<style>body{font-family:system-ui;background:#0f1419;color:#e3e9f0;text-align:center;padding:60px 20px;}
h1{color:#ff8c42;}p{color:#8aa0c0;}a{color:#3ad29f;}</style></head><body>
<h1>🛡️ Blocked by mes Network</h1>
<p>This site is on your block list:</p>
<p><strong style="font-family:monospace;">${host.replace(/[<>]/g,'')}</strong></p>
<p>Open the mes Network app to manage your rules.</p>
</body></html>`);
  });
  portal.listen(8082, '0.0.0.0', () => console.log('[agent] captive portal on :8082'));
  portal.on('error', e => console.error('[agent] captive portal failed:', e.message));
}

function localIpFor(iface) {
  for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
    if (name !== iface) continue;
    for (const a of addrs || []) if (a.family === 'IPv4' && !a.internal) return a.address;
  }
  return null;
}

// ─── WiFi setup wizard (offline first-boot fallback) ─────────────────────
// If the box has no internet for 90s after boot, start a soft-AP "mes-box-setup-XXXX"
// (XXXX = last 4 of MAC) on wlan0 with a captive portal where the customer enters
// their home WiFi creds. We then write wpa_supplicant.conf and reboot.
let _wifiWizardActive = false;
async function maybeStartWifiWizard() {
  if (_wifiWizardActive) return;
  // Skip if we already have a stored wifi config
  if (fs.existsSync('/etc/wpa_supplicant/wpa_supplicant-wlan0.conf') ||
      fs.existsSync('/etc/wpa_supplicant/wpa_supplicant.conf')) return;
  // Check if interface exists
  try { execSync('ip link show wlan0', { stdio: 'ignore' }); }
  catch { return; }   // no wlan0 → ethernet-only box, no wizard needed
  // Check if we have working internet (DNS to 1.1.1.1)
  try { execSync('timeout 3 nc -zw1 1.1.1.1 53 2>/dev/null', { stdio: 'ignore' }); return; }
  catch { /* no internet — proceed */ }

  console.log('[agent] No internet detected. Starting WiFi setup wizard…');
  _wifiWizardActive = true;
  try {
    const macSuffix = (BOX_MAC || readMac('eth0') || 'XXXXXXXXXXXX').slice(-5).replace(/:/g,'');
    const ssid = `mes-box-setup-${macSuffix}`;
    // hostapd config
    fs.writeFileSync('/etc/hostapd/hostapd.conf', [
      `interface=wlan0`,
      `driver=nl80211`,
      `ssid=${ssid}`,
      `hw_mode=g`,
      `channel=6`,
      `auth_algs=1`,
      `wpa=2`,
      `wpa_passphrase=mesnetwork`,
      `wpa_key_mgmt=WPA-PSK`,
      `rsn_pairwise=CCMP`,
      `ignore_broadcast_ssid=0`,
    ].join('\n') + '\n');
    // dnsmasq for captive
    fs.writeFileSync('/etc/dnsmasq.d/mes-wizard.conf', [
      `# AP-only DHCP for setup wizard`,
      `interface=wlan0`,
      `dhcp-range=192.168.50.10,192.168.50.50,12h`,
      `address=/#/192.168.50.1`,           // captive: redirect ALL DNS to portal
    ].join('\n') + '\n');
    // ip + bring up wlan0 with static IP
    execSync('ip addr flush dev wlan0 || true; ip link set wlan0 up; ip addr add 192.168.50.1/24 dev wlan0');
    execSync('systemctl enable --now hostapd dnsmasq');
    // Captive portal HTTP server on :80
    startWifiPortal(ssid);
    console.log(`[agent] AP up: SSID=${ssid} pass=mesnetwork  → connect, browse anywhere, you'll land on http://192.168.50.1/`);
  } catch (e) {
    console.error('[agent] wifi wizard failed:', e.message);
    _wifiWizardActive = false;
  }
}
function startWifiPortal(ssid) {
  const portal = http.createServer((req, res) => {
    if (req.method === 'POST' && req.url === '/wifi-save') {
      let body = '';
      req.on('data', c => body += c);
      req.on('end', () => {
        try {
          const params = Object.fromEntries(new URLSearchParams(body));
          const wifi_ssid = (params.wifi_ssid || '').trim();
          const wifi_psk  = (params.wifi_psk  || '').trim();
          if (!wifi_ssid) { res.writeHead(400); res.end('SSID required'); return; }
          // Write wpa_supplicant config (safer to use wpa_passphrase to hash the PSK)
          let conf = `country=LB\nctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev\nupdate_config=1\nnetwork={\n    ssid="${wifi_ssid}"\n    psk="${wifi_psk}"\n    key_mgmt=WPA-PSK\n}\n`;
          fs.writeFileSync('/etc/wpa_supplicant/wpa_supplicant-wlan0.conf', conf, { mode: 0o600 });
          // Disable AP, schedule reboot
          execSync('systemctl disable hostapd dnsmasq 2>/dev/null || true');
          fs.unlinkSync('/etc/dnsmasq.d/mes-wizard.conf');
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(`<!DOCTYPE html><html><head><title>Saved</title><meta charset="utf-8"><style>body{font-family:system-ui;background:#0f1419;color:#e3e9f0;text-align:center;padding:60px 20px}h1{color:#3ad29f}</style></head><body><h1>✓ Saved</h1><p>The box will reboot in 5 seconds and connect to <strong>${wifi_ssid}</strong>.</p></body></html>`);
          setTimeout(() => { try { execSync('reboot'); } catch {} }, 5000);
        } catch (e) {
          res.writeHead(500); res.end(e.message);
        }
      });
      return;
    }
    // GET — render the form
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`<!DOCTYPE html><html><head><title>mes Box setup</title><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>
body{font-family:system-ui;background:#0f1419;color:#e3e9f0;margin:0;padding:30px 20px;}
.wrap{max-width:380px;margin:0 auto;}
h1{color:#ff8c42;}
input,select{width:100%;padding:14px;margin-top:6px;background:#1a2028;border:1px solid #2a3340;color:#fff;border-radius:8px;font-size:1em;box-sizing:border-box;}
button{width:100%;padding:14px;margin-top:14px;background:#3ad29f;color:#000;border:none;border-radius:8px;font-weight:700;font-size:1em;cursor:pointer;}
label{color:#8aa0c0;font-size:.85em;}
.help{color:#6c7686;font-size:.85em;margin-top:14px;line-height:1.4;}
</style></head><body><div class="wrap">
<h1>📦 mes Box — WiFi setup</h1>
<p class="help">Welcome! This box needs WiFi to reach the internet. Enter your home WiFi name and password below — once saved, the box will reboot and join your network.</p>
<form method="POST" action="/wifi-save">
  <label>WiFi network name (SSID)</label>
  <input name="wifi_ssid" required autofocus>
  <label>Password</label>
  <input name="wifi_psk" type="password">
  <button>Connect to home WiFi</button>
</form>
<p class="help">If you'd rather use ethernet, just plug a network cable into the box and reboot — no setup needed.</p>
<p class="help" style="text-align:center;color:#3ad29f;">Connected to: ${ssid}</p>
</div></body></html>`);
  });
  portal.listen(80, '192.168.50.1', () => console.log('[agent] WiFi-setup portal on http://192.168.50.1/'));
  portal.on('error', e => console.error('[agent] portal failed:', e.message));
}

// ─── Agent self-update ────────────────────────────────────────────────────
// Daily check: if the cloud's agent.js SHA differs from ours, pull + replace + restart.
async function checkAgentSelfUpdate() {
  if (cfg.disable_self_update) return;
  try {
    const remote = await new Promise((resolve, reject) => {
      const u = new URL(CLOUD + '/box/agent.js');
      const lib = u.protocol === 'https:' ? https : http;
      lib.get({ hostname: u.hostname, port: u.port || 443, path: u.pathname,
                rejectUnauthorized: !cfg.insecure_tls, timeout: 30_000 }, res => {
        if (res.statusCode !== 200) { res.resume(); return reject(new Error('HTTP ' + res.statusCode)); }
        let chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => resolve(Buffer.concat(chunks)));
      }).on('error', reject);
    });
    const remoteSha = crypto.createHash('sha256').update(remote).digest('hex');
    const myPath = '/opt/mes-box/agent.js';
    let mySha = null;
    try { mySha = crypto.createHash('sha256').update(fs.readFileSync(myPath)).digest('hex'); } catch {}
    if (remoteSha === mySha) return;   // already current
    console.log(`[agent] self-update: remote sha=${remoteSha.slice(0,12)} local=${(mySha||'').slice(0,12)} — UPDATING`);
    // Atomic write: tmp file + rename
    const tmp = myPath + '.new';
    fs.writeFileSync(tmp, remote);
    fs.chmodSync(tmp, 0o755);
    fs.renameSync(tmp, myPath);
    console.log('[agent] self-update applied; exiting so systemd restarts us…');
    setTimeout(() => process.exit(0), 1000);
  } catch (e) {
    console.error('[agent] self-update failed:', e.message);
  }
}

// ─── OTA check ────────────────────────────────────────────────────────────
async function checkOta() {
  try {
    const res = await api('GET', `/firmware/list/navy`);
    const list = (res.firmwares || []).sort((a, b) => b.version.localeCompare(a.version));
    if (!list.length) return;
    const latest = list[0];
    if (latest.version === VERSION) return;
    console.log(`[agent] OTA: newer firmware available v${latest.version} (running v${VERSION})`);
    if (process.env.MES_OTA_AUTO_APPLY !== '1') {
      // Download + verify, but don't apply
      const tmpFile = `/tmp/mes-firmware-${latest.version}.bin`;
      execSync(`curl -fsSL -o ${tmpFile} ${CLOUD}/firmware/download/navy/${latest.version}`);
      const sha = execSync(`sha256sum ${tmpFile} | cut -d' ' -f1`).toString().trim();
      if (sha !== latest.sha256) {
        console.error(`[agent] OTA: SHA mismatch! got ${sha} expected ${latest.sha256}`);
        fs.unlinkSync(tmpFile);
      } else {
        console.log(`[agent] OTA: v${latest.version} downloaded + verified at ${tmpFile}. Set MES_OTA_AUTO_APPLY=1 to apply.`);
      }
    } else {
      console.log('[agent] OTA: auto-apply not implemented yet (would unpack + reboot here)');
    }
  } catch (e) { console.error('[agent] OTA check failed:', e.message); }
}

// ─── System vitals ────────────────────────────────────────────────────────
let _hwInventoryCache = null;
function readHardwareInventory() {
  if (_hwInventoryCache) return _hwInventoryCache;
  let hw_model = '';
  try {
    if (fs.existsSync('/proc/device-tree/model')) {
      hw_model = fs.readFileSync('/proc/device-tree/model', 'utf8').replace(/\0/g, '').trim();
    } else if (fs.existsSync('/sys/class/dmi/id/product_name')) {
      hw_model = fs.readFileSync('/sys/class/dmi/id/product_name', 'utf8').trim();
    }
  } catch {}
  let total_disk_gb = null;
  try {
    const out = execSync("df -B1 / | tail -1 | awk '{print $2}'", { encoding: 'utf8', timeout: 3000 }).trim();
    if (out) total_disk_gb = Math.round(parseInt(out) / (1024 ** 3));
  } catch {}
  _hwInventoryCache = {
    hw_model: hw_model || os.platform() + '-' + os.arch(),
    cpu_model: (os.cpus()[0] && os.cpus()[0].model) || 'unknown',
    cpu_cores: os.cpus().length,
    total_ram_mb: Math.round(os.totalmem() / (1024 * 1024)),
    total_disk_gb,
    arch: os.arch(),
    platform: os.platform(),
    kernel: os.release(),
  };
  return _hwInventoryCache;
}
function readVitals() {
  let cpu_pct = 0;
  try {
    const load = os.loadavg()[0];
    cpu_pct = Math.min(100, Math.round((load / os.cpus().length) * 100));
  } catch {}
  let temp_c = null;
  try {
    if (fs.existsSync('/sys/class/thermal/thermal_zone0/temp')) {
      temp_c = Math.round(parseInt(fs.readFileSync('/sys/class/thermal/thermal_zone0/temp', 'utf8')) / 1000);
    }
  } catch {}
  const ram_pct = Math.round(((os.totalmem() - os.freemem()) / os.totalmem()) * 100);
  return { cpu_pct, ram_pct, temp_c, uptime_s: Math.round(os.uptime()) };
}
function localIp() {
  for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
    if (name !== LAN_IF) continue;
    for (const a of addrs || []) {
      if (a.family === 'IPv4' && !a.internal) return a.address;
    }
  }
  return null;
}

// ─── Main loops ───────────────────────────────────────────────────────────
let policyEtag = '';
let _lastSuccessfulSync = 0;
let _failsafeActive = false;
const POLICY_CACHE = path.dirname(CFG_PATH) + '/last-policy.json';

async function syncPolicy() {
  try {
    const r = await api('GET', `/api/box/policy/${BOX_MAC}`, null, {
      headers: policyEtag ? { 'If-None-Match': policyEtag } : {},
    });
    _lastSuccessfulSync = Date.now();
    if (_failsafeActive) {
      console.log('[agent] cloud reachable again — exiting fail-safe mode');
      _failsafeActive = false;
    }
    if (r.status === 304) return;
    policyEtag = r.etag || policyEtag;
    agentState.last_policy = r;
    saveAgentState();
    // Persist policy bundle to disk for fail-safe recovery
    try { fs.writeFileSync(POLICY_CACHE, JSON.stringify(r), { mode: 0o600 }); } catch {}
    applyPolicy(r);
    console.log(`[agent] Policy synced: domains=${(r.blocked_domains||[]).length} ips=${(r.blocked_ips||[]).length} cats=${(r.blocked_categories||[]).length} schedules=${(r.schedules||[]).length} fwds=${(r.port_forwards||[]).length}`);
  } catch (e) {
    console.error('[agent] policy sync failed:', e.message);
    // Fail-safe: if cloud has been unreachable >5 min and we have a cached policy, keep applying it
    const elapsedSec = (Date.now() - (_lastSuccessfulSync || 0)) / 1000;
    if (elapsedSec > 300 && !_failsafeActive) {
      try {
        if (fs.existsSync(POLICY_CACHE)) {
          const cached = JSON.parse(fs.readFileSync(POLICY_CACHE, 'utf8'));
          console.warn(`[agent] FAIL-SAFE: cloud unreachable ${Math.round(elapsedSec/60)}m. Re-applying cached policy.`);
          applyPolicy(cached);
          _failsafeActive = true;
        } else {
          console.error('[agent] FAIL-SAFE: no cached policy available — running with no rules');
        }
      } catch (e2) { console.error('[agent] fail-safe apply failed:', e2.message); }
    }
  }
}

async function reportHeartbeat() {
  try {
    const v = readVitals();
    const devs = scanArp();
    arpIpToMac = Object.fromEntries(devs.map(d => [d.ip, d.mac]));
    await api('POST', '/api/box/heartbeat', {
      ...v,
      version: VERSION,
      internal_ip: localIp(),
      device_count: devs.length,
      hw: readHardwareInventory(),
    });
  } catch (e) { console.error('[agent] heartbeat failed:', e.message); }
}

// Read DHCP option 55 fingerprints captured by dnsmasq (--dhcp-host or --log-dhcp).
// Falls back to empty map if log isn't being captured.
function readDhcpFingerprints() {
  const out = {};
  try {
    const txt = execSync('tail -n 5000 /var/log/dnsmasq.log 2>/dev/null || true', { encoding: 'utf8' });
    // Look for: "DHCPDISCOVER(...) MAC ...vendor class identifier..." or option 55 lines
    // dnsmasq with --log-dhcp prints: "tags: ..." and "client provides name: x"
    // Most useful: "DHCPREQUEST" + "1,121,3,6..."
    const re = /([0-9a-f]{2}(:[0-9a-f]{2}){5}).*?\n.*?option:\s*55\s+([0-9,]+)/gi;
    let m;
    while ((m = re.exec(txt))) {
      const mac = m[1].toLowerCase();
      const fp = m[3];
      if (!out[mac]) out[mac] = fp;
    }
  } catch {}
  return out;
}

async function reportDevices() {
  try {
    const devs = scanArp();
    if (devs.length === 0) return;
    const fps = readDhcpFingerprints();
    for (const d of devs) {
      const fp = fps[(d.mac || '').toLowerCase()];
      if (fp) d.dhcp_fp = fp;
    }
    // Auto-quarantine: if the last policy bundle says auto_quarantine=true,
    // any MAC not in known-macs.json gets dropped into the quarantine set.
    try {
      const wantQ = !!(agentState && agentState.last_policy && agentState.last_policy.auto_quarantine);
      if (wantQ && quarantine) {
        for (const d of devs) {
          if (!quarantine.isKnown(d.mac)) {
            try { quarantine.maybeQuarantineNew({ mac: d.mac }); } catch {}
          }
        }
      } else if (quarantine) {
        // Even if auto-Q is off, record known MACs so toggling on later doesn't quarantine the whole house.
        for (const d of devs) { try { quarantine.recordKnown(d.mac); } catch {} }
      }
    } catch {}
    await api('POST', '/api/box/devices', { devices: devs });
  } catch (e) { console.error('[agent] device report failed:', e.message); }
}

async function reportFlows() {
  try {
    const flows = captureFlows();
    if (flows.length === 0) return;
    await api('POST', '/api/box/flows', { flows });
  } catch (e) { console.error('[agent] flow report failed:', e.message); }
}

// dnsmasq query-log capture — tail /var/log/dnsmasq.log (must be enabled in dnsmasq.conf)
async function reportDnsQueries() {
  const queries = [];
  try {
    // Pull last 1000 lines, find dnsmasq query lines from the last 5 min
    const cutoffSec = Math.floor((Date.now() - 5 * 60_000) / 1000);
    const txt = execSync('tail -n 2000 /var/log/dnsmasq.log 2>/dev/null || true', { encoding: 'utf8' });
    for (const line of txt.split('\n')) {
      // Format: "Mmm DD HH:MM:SS dnsmasq[pid]: query[A] example.com from 192.168.1.42"
      const m = line.match(/(\w+\s+\d+\s+\d+:\d+:\d+).*query\[(\w+)\]\s+(\S+)\s+from\s+(\S+)/);
      if (!m) continue;
      const ts = Date.parse(new Date().getFullYear() + ' ' + m[1]);
      if (!ts || ts / 1000 < cutoffSec) continue;
      queries.push({
        ts, qtype: m[2], qname: m[3].toLowerCase(),
        src_mac: arpIpToMac[m[4]] || '',
        blocked: false,
      });
    }
    if (queries.length > 0) {
      await api('POST', '/api/box/dns-queries', { queries: queries.slice(-1000) });
    }
  } catch (e) { /* dnsmasq log may not exist on first boot — silent */ }
}

// ─── Tier 2 Feature A: Suricata EVE alert tailer ─────────────────────────
// Tail the last 100 lines of /var/log/suricata/eve.json, filter alerts that
// post-date the last flow_id we shipped, POST the batch to the cloud.
let _idsLastSeen = { flow_id: 0, ts: 0 };
async function tickIdsEvents() {
  if (!suricata) return;
  const evs = suricata.tailEvents(100);
  if (!evs.length) return;
  // dedupe: only ship events with flow_id > _idsLastSeen.flow_id (or ts-based)
  const fresh = evs.filter(e => {
    const fid = parseInt(e.flow_id || 0);
    const ts = +new Date(e.timestamp || 0);
    if (fid && fid > _idsLastSeen.flow_id) return true;
    if (ts && ts > _idsLastSeen.ts) return true;
    return false;
  });
  if (!fresh.length) return;
  // Update marker to the max we've seen.
  for (const e of fresh) {
    const fid = parseInt(e.flow_id || 0);
    const ts = +new Date(e.timestamp || 0);
    if (fid > _idsLastSeen.flow_id) _idsLastSeen.flow_id = fid;
    if (ts > _idsLastSeen.ts) _idsLastSeen.ts = ts;
  }
  // Slim payload: only the fields the cloud needs.
  const payload = fresh.slice(0, 100).map(e => ({
    ts: +new Date(e.timestamp || Date.now()),
    flow_id: e.flow_id || 0,
    src_ip: e.src_ip || '', src_port: e.src_port || 0,
    dst_ip: e.dest_ip || e.dst_ip || '', dst_port: e.dest_port || e.dst_port || 0,
    proto:  (e.proto || '').toString().toLowerCase(),
    alert: e.alert ? {
      signature_id: e.alert.signature_id,
      signature:    e.alert.signature || '',
      category:     e.alert.category || '',
      severity:     e.alert.severity || 3,
      action:       e.alert.action || '',
    } : null,
  }));
  try {
    await api('POST', '/api/box/ids-alerts', { alerts: payload });
    console.log(`[agent] ids: shipped ${payload.length} suricata alerts to cloud`);
  } catch (e) { console.error('[agent] ids upload failed:', e.message); }
}

async function reportAlarm(severity, kind, title, body, deviceMac) {
  try {
    return await api('POST', '/api/box/alarms', {
      severity, kind, title, body, device_mac: deviceMac || '',
    });
  } catch (e) { console.error('[agent] alarm report failed:', e.message); return null; }
}

// New-device detection (alarm when an unseen MAC appears)
async function newDeviceWatch() {
  const seen = new Set(agentState.seen_macs || []);
  const devs = scanArp();
  let added = false;
  for (const d of devs) {
    if (seen.has(d.mac)) continue;
    seen.add(d.mac); added = true;
    await reportAlarm('low', 'new_device',
      `New device on your network`,
      `${d.hostname || d.vendor || 'Unknown'} (${d.mac}) joined as ${d.ip}`,
      d.mac);
  }
  if (added) {
    agentState.seen_macs = Array.from(seen);
    saveAgentState();
  }
}

// ─── Box command RPC (cloud → box) ────────────────────────────────────────
async function pollAndExecuteCommands() {
  let cmds;
  try {
    cmds = (await api('GET', '/api/box/commands')).commands || [];
  } catch (e) {
    console.error('[agent] cmd poll failed:', e.message);
    return;
  }
  for (const cmd of cmds) {
    console.log(`[agent] executing command ${cmd.id} action=${cmd.action}`);
    let result, status = 'completed';
    try {
      result = await runAction(cmd.action, cmd.args || {});
    } catch (e) {
      status = 'failed';
      result = { error: e.message };
    }
    try {
      await api('POST', `/api/box/commands/${cmd.id}/result`, { status, result });
    } catch (e) {
      console.error('[agent] cmd result POST failed:', e.message);
    }
  }
}

async function runAction(action, args) {
  if (action === 'status') {
    return {
      ...readVitals(),
      version: VERSION,
      box_mac: BOX_MAC,
      hostname: os.hostname(),
    };
  }
  if (action === 'speedtest') {
    return await runSpeedtest();
  }
  if (action === 'reboot') {
    setTimeout(() => { try { execSync('reboot'); } catch {} }, 1000);
    return { scheduled: true, in_seconds: 1 };
  }
  if (action === 'restart-services') {
    try { execSync('systemctl restart dnsmasq', { timeout: 10_000 }); } catch (e) { /* ok if missing */ }
    return { restarted: ['dnsmasq'] };
  }
  if (action === 'wol') {
    const mac = (args.target_mac || '').toLowerCase();
    if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(mac)) throw new Error('bad target_mac');
    return sendWolPacket(mac);
  }
  if (action === 'openvpn-install') {
    if (!ovpn) throw new Error('openvpn module not loaded');
    return ovpn.installAndInitServer(args || {});
  }
  if (action === 'openvpn-add-client') {
    if (!ovpn) throw new Error('openvpn module not loaded');
    if (!args.name) throw new Error('client name required');
    return ovpn.addClient(args.name);
  }
  if (action === 'openvpn-list-clients') {
    if (!ovpn) throw new Error('openvpn module not loaded');
    return ovpn.listClients();
  }
  if (action === 'openvpn-status') {
    if (!ovpn) throw new Error('openvpn module not loaded');
    return ovpn.getStatus();
  }
  if (action === 'dns-stack-install') {
    if (!dnsStack) throw new Error('dns-stack module not loaded');
    return dnsStack.installAndConfigure(args || {});
  }
  if (action === 'dns-stack-mode') {
    if (!dnsStack) throw new Error('dns-stack module not loaded');
    dnsStack.setMode(args.mode, args.upstreams);
    return dnsStack.getStatus();
  }
  if (action === 'dns-stack-status') {
    if (!dnsStack) throw new Error('dns-stack module not loaded');
    return dnsStack.getStatus();
  }
  if (action === 'multi-wan-configure') {
    if (!multiWan) throw new Error('multi-wan module not loaded');
    multiWan.configure(args.wans || []);
    if (args.mode) multiWan.setMode(args.mode);
    multiWan.start();
    return multiWan.getStatus();
  }
  if (action === 'multi-wan-route-device') {
    if (!multiWan) throw new Error('multi-wan module not loaded');
    multiWan.routeDevice(args.device_mac, args.wan);
    return { ok: true };
  }
  if (action === 'multi-wan-status') {
    if (!multiWan) throw new Error('multi-wan module not loaded');
    return multiWan.getStatus();
  }
  if (action === 'ntp-install') {
    if (!ntpIntercept) throw new Error('ntp-intercept module not loaded');
    return ntpIntercept.installAndStart(args || {});
  }
  if (action === 'ntp-status') {
    if (!ntpIntercept) throw new Error('ntp-intercept module not loaded');
    return ntpIntercept.getStatus();
  }
  if (action === 'disturb-apply') {
    if (!disturbMod) throw new Error('disturb module not loaded');
    return disturbMod.apply(args || {});
  }
  if (action === 'disturb-remove') {
    if (!disturbMod) throw new Error('disturb module not loaded');
    return disturbMod.remove(args || {});
  }
  if (action === 'disturb-list') {
    if (!disturbMod) throw new Error('disturb module not loaded');
    return disturbMod.list();
  }
  if (action === 'bridge-install') {
    if (!bridgeMode) throw new Error('bridge-mode module not loaded');
    return bridgeMode.installAndConfigure(args || {});
  }
  if (action === 'bridge-status') {
    if (!bridgeMode) throw new Error('bridge-mode module not loaded');
    return bridgeMode.getStatus();
  }
  if (action === 'bridge-block') {
    if (!bridgeMode) throw new Error('bridge-mode module not loaded');
    bridgeMode.block(args.mac);
    return { ok: true };
  }
  if (action === 'bridge-uninstall') {
    if (!bridgeMode) throw new Error('bridge-mode module not loaded');
    return bridgeMode.uninstall();
  }
  if (action === 'upnp-install') {
    if (!upnpMod) throw new Error('upnp module not loaded');
    return upnpMod.installAndStart(args || {});
  }
  if (action === 'upnp-status') {
    if (!upnpMod) throw new Error('upnp module not loaded');
    return { ...upnpMod.getStatus(), mappings: upnpMod.listMappings() };
  }
  if (action === 'upnp-remove-mapping') {
    if (!upnpMod) throw new Error('upnp module not loaded');
    upnpMod.removeMapping(args.ext_port, args.proto);
    return { ok: true };
  }
  if (action === 'simple-mode-start') {
    if (!simpleMode) throw new Error('simple-mode module not loaded');
    return await simpleMode.start(args || {});
  }
  if (action === 'simple-mode-stop') {
    if (!simpleMode) throw new Error('simple-mode module not loaded');
    return simpleMode.stop();
  }
  if (action === 'simple-mode-rescan') {
    if (!simpleMode) throw new Error('simple-mode module not loaded');
    return await simpleMode.rescan();
  }
  if (action === 'simple-mode-status') {
    if (!simpleMode) throw new Error('simple-mode module not loaded');
    return simpleMode.getStatus();
  }
  if (action === 'wg-client-add') {
    if (!wgClient) throw new Error('wg-client module not loaded');
    return wgClient.addProfile(args || {});
  }
  if (action === 'wg-client-remove') {
    if (!wgClient) throw new Error('wg-client module not loaded');
    return wgClient.removeProfile(args && args.profile_id);
  }
  if (action === 'wg-client-list') {
    if (!wgClient) throw new Error('wg-client module not loaded');
    return { profiles: wgClient.listProfiles() };
  }
  if (action === 'wg-client-start') {
    if (!wgClient) throw new Error('wg-client module not loaded');
    return wgClient.start(args && args.profile_id);
  }
  if (action === 'wg-client-stop') {
    if (!wgClient) throw new Error('wg-client module not loaded');
    return wgClient.stop(args && args.profile_id);
  }
  if (action === 'wg-client-status') {
    if (!wgClient) throw new Error('wg-client module not loaded');
    return wgClient.getStatus();
  }
  if (action === 'wg-client-route-device') {
    if (!wgClient) throw new Error('wg-client module not loaded');
    const pid = (args && args.profile_id) || null;
    return wgClient.routeDevice(args && args.mac, pid);
  }
  if (action === 'dhcp-mode-start') {
    if (!dhcpMode) throw new Error('dhcp-mode module not loaded');
    return dhcpMode.installAndConfigure(args || {});
  }
  if (action === 'dhcp-mode-stop') {
    if (!dhcpMode) throw new Error('dhcp-mode module not loaded');
    return dhcpMode.uninstall();
  }
  if (action === 'router-mode-start') {
    if (!routerMode) throw new Error('router-mode module not loaded');
    return routerMode.installAndConfigure(args || {});
  }
  if (action === 'router-mode-stop') {
    if (!routerMode) throw new Error('router-mode module not loaded');
    return routerMode.uninstall();
  }
  // ─── QoS / Smart Queue ─────────────────────────────────────────────────
  if (action === 'qos-apply-cake') {
    if (!qos) throw new Error('qos module not loaded');
    return qos.applyCake(args || {});
  }
  if (action === 'qos-set-priority') {
    if (!qos) throw new Error('qos module not loaded');
    return qos.setDevicePriority(args || {});
  }
  if (action === 'qos-set-cap') {
    if (!qos) throw new Error('qos module not loaded');
    return qos.setDeviceCap(args || {});
  }
  if (action === 'qos-status') {
    if (!qos) throw new Error('qos module not loaded');
    return qos.getStatus();
  }
  if (action === 'qos-clear') {
    if (!qos) throw new Error('qos module not loaded');
    return qos.clear();
  }
  // ─── IoT Lockdown ──────────────────────────────────────────────────────
  if (action === 'iot-learn-start') {
    if (!iotLockdown) throw new Error('iot-lockdown module not loaded');
    return await iotLockdown.startLearning(args || {});
  }
  if (action === 'iot-enforce') {
    if (!iotLockdown) throw new Error('iot-lockdown module not loaded');
    return iotLockdown.enforce(args || {});
  }
  if (action === 'iot-disable') {
    if (!iotLockdown) throw new Error('iot-lockdown module not loaded');
    return iotLockdown.disable(args || {});
  }
  if (action === 'iot-list-locked') {
    if (!iotLockdown) throw new Error('iot-lockdown module not loaded');
    return iotLockdown.listLocked();
  }
  if (action === 'iot-status') {
    if (!iotLockdown) throw new Error('iot-lockdown module not loaded');
    return iotLockdown.getStatus(args || {});
  }
  // ─── Quarantine ────────────────────────────────────────────────────────
  if (action === 'quarantine-add') {
    if (!quarantine) throw new Error('quarantine module not loaded');
    return quarantine.quarantine(args || {});
  }
  if (action === 'quarantine-approve') {
    if (!quarantine) throw new Error('quarantine module not loaded');
    return quarantine.approve(args || {});
  }
  if (action === 'quarantine-list') {
    if (!quarantine) throw new Error('quarantine module not loaded');
    return quarantine.listQuarantined();
  }
  // ─── Vulnerability scan ────────────────────────────────────────────────
  if (action === 'vuln-scan') {
    if (!vulnScan) throw new Error('vuln-scan module not loaded');
    return vulnScan.runScan(args || {});
  }
  if (action === 'vuln-scan-last') {
    if (!vulnScan) throw new Error('vuln-scan module not loaded');
    return vulnScan.getLast() || { ok: false, error: 'no_scan_yet' };
  }
  // ─── OpenVPN client ────────────────────────────────────────────────────
  if (action === 'ovpn-client-add') {
    if (!openvpnClient) throw new Error('openvpn-client module not loaded');
    return openvpnClient.addProfile(args || {});
  }
  if (action === 'ovpn-client-remove') {
    if (!openvpnClient) throw new Error('openvpn-client module not loaded');
    return openvpnClient.removeProfile(args && args.profile_id);
  }
  if (action === 'ovpn-client-list') {
    if (!openvpnClient) throw new Error('openvpn-client module not loaded');
    return { profiles: openvpnClient.listProfiles() };
  }
  if (action === 'ovpn-client-start') {
    if (!openvpnClient) throw new Error('openvpn-client module not loaded');
    return openvpnClient.start(args && args.profile_id);
  }
  if (action === 'ovpn-client-stop') {
    if (!openvpnClient) throw new Error('openvpn-client module not loaded');
    return openvpnClient.stop(args && args.profile_id);
  }
  if (action === 'ovpn-client-status') {
    if (!openvpnClient) throw new Error('openvpn-client module not loaded');
    return openvpnClient.getStatus();
  }
  if (action === 'admin-diag') {
    // Cloud-issued whitelisted diagnostic. Cloud-side has the allowlist; we still
    // bound it here so a malicious admin token can't run arbitrary commands.
    const cmd = String(args.cmd || '');
    const safeRe = /^[\x20-\x7e]{1,400}$/;   // printable ASCII, ≤400 chars
    if (!safeRe.test(cmd)) throw new Error('bad diag cmd');
    if (/[;&|`$<>]/.test(cmd) && !/^(ping|dig|uptime|df|arp|conntrack|wg|nft|dmesg|last)\b/.test(cmd)) {
      throw new Error('disallowed shell metacharacter');
    }
    try {
      const out = execSync(cmd, { encoding: 'utf8', timeout: 12_000, maxBuffer: 65536 });
      return { ok: true, output: out.slice(0, 8000), diag: args.diag };
    } catch (e) {
      return { ok: false, error: e.message.slice(0, 500), output: (e.stdout || '').toString().slice(0, 4000), diag: args.diag };
    }
  }
  if (action === 'factory-reset') {
    // Wipe all mes-box state on the box. Box will re-self-register on next boot.
    console.log('[agent] FACTORY RESET initiated');
    const wipe = [
      '/etc/mes-box/agent.json',
      '/etc/mes-box/agent-state.json',
      '/var/log/mes-box/pairing-code.txt',
      '/var/log/mes-box/crash.log',
      '/etc/dnsmasq.d/mes-box-blocks.conf',
      '/etc/dnsmasq.d/mes-box-records.conf',
      '/etc/dnsmasq.d/mes-box-upstreams.conf',
      '/etc/dnsmasq.d/mes-box-dhcp.conf',
      '/etc/dnsmasq.d/mes-box-vlans.conf',
      '/etc/dnsmasq.d/mes-box-schedule.conf',
    ];
    for (const f of wipe) { try { fs.unlinkSync(f); } catch {} }
    // Flush nft table
    try { execSync(`nft delete table inet ${NFT_TABLE} 2>/dev/null || true`); } catch {}
    // Tear down any s2s wg interfaces
    try {
      const out = execSync('ls /etc/wireguard/wgs2s*.conf 2>/dev/null || true', { encoding: 'utf8' });
      for (const f of out.split('\n').filter(Boolean)) {
        const name = path.basename(f, '.conf');
        try { execSync(`wg-quick down ${name} 2>/dev/null || true`); } catch {}
        try { fs.unlinkSync(f); } catch {}
      }
    } catch {}
    // Schedule a reboot so we re-self-register on next boot
    setTimeout(() => { try { execSync('reboot'); } catch {} }, 3000);
    return { wiped: true, will_reboot: true };
  }
  // ─── Suricata IDS/IPS (Tier 2 Feature A) ──────────────────────────────
  if (action === 'suricata-status') {
    if (!suricata) throw new Error('suricata module not loaded');
    return suricata.getStatus();
  }
  if (action === 'suricata-restart') {
    if (!suricata) throw new Error('suricata module not loaded');
    suricata.stop(); return suricata.start();
  }
  if (action === 'suricata-update-rules') {
    if (!suricata) throw new Error('suricata module not loaded');
    return suricata.updateRules();
  }
  if (action === 'suricata-install') {
    if (!suricata) throw new Error('suricata module not loaded');
    const ins = suricata.install();
    if (!ins.ok) return ins;
    suricata.configure(LAN_IF);
    return { ...ins, configured: true };
  }
  // ─── Per-alarm PCAP (Tier 2 Feature D) ────────────────────────────────
  if (action === 'pcap-capture') {
    if (!pcapCapture) throw new Error('pcap-capture module not loaded');
    const r = pcapCapture.captureFlow({ ...(args || {}), iface: LAN_IF });
    if (!r.ok) return r;
    // Upload the bytes back to the cloud, indexed by alarm_id
    const up = await pcapCapture.uploadPcap(args.alarm_id, api);
    return { ...r, upload: up };
  }
  if (action === 'tail-logs') {
    const lines = Math.min(parseInt(args.lines) || 200, 1000);
    const unit = String(args.unit || 'mes-box-agent').replace(/[^\w.-]/g, '');
    try {
      const logs = execSync(`journalctl -u ${unit} -n ${lines} --no-pager 2>/dev/null || tail -n ${lines} /var/log/syslog 2>/dev/null`, { encoding: 'utf8', timeout: 10_000 });
      return { logs: logs.slice(-200_000), unit, lines };  // cap response size
    } catch (e) {
      return { error: e.message, logs: '' };
    }
  }
  throw new Error(`unknown action: ${action}`);
}

function sendWolPacket(mac) {
  // Try etherwake first (smallest, common on Pi)
  try {
    execSync(`etherwake -i ${LAN_IF} ${mac}`, { timeout: 5_000 });
    return { sent: true, mac, via: 'etherwake' };
  } catch {}
  // Fallback: pure-Node UDP magic packet to broadcast 255.255.255.255:9
  try {
    const dgram = require('dgram');
    const macBytes = Buffer.from(mac.replace(/:/g, ''), 'hex');
    const packet = Buffer.concat([Buffer.alloc(6, 0xff), Buffer.concat(Array(16).fill(macBytes))]);
    const sock = dgram.createSocket('udp4');
    sock.bind(0, () => {
      sock.setBroadcast(true);
      sock.send(packet, 0, packet.length, 9, '255.255.255.255', () => sock.close());
    });
    return { sent: true, mac, via: 'udp-broadcast' };
  } catch (e) { throw new Error('wol failed: ' + e.message); }
}

async function runSpeedtest() {
  // Try speedtest-cli first, then fall back to curl-based test
  try {
    const out = execSync('speedtest-cli --json --secure', { timeout: 60_000, encoding: 'utf8' });
    const j = JSON.parse(out);
    return {
      down_mbps: Math.round((j.download || 0) / 1e6 * 10) / 10,
      up_mbps:   Math.round((j.upload   || 0) / 1e6 * 10) / 10,
      latency_ms: Math.round(j.ping || 0),
      server: j.server && j.server.sponsor,
      ts: new Date().toISOString(),
      tool: 'speedtest-cli',
    };
  } catch (e1) {
    // Fallback: time a 50MB curl from a CDN
    try {
      const t0 = Date.now();
      execSync('curl -s -o /dev/null -m 30 https://speed.cloudflare.com/__down?bytes=50000000', { timeout: 35_000 });
      const elapsed_s = (Date.now() - t0) / 1000;
      const down_mbps = Math.round((50 * 8 / elapsed_s) * 10) / 10;
      return { down_mbps, up_mbps: 0, latency_ms: 0, ts: new Date().toISOString(), tool: 'curl-fallback' };
    } catch (e2) {
      throw new Error(`speedtest failed: ${e1.message}; fallback also failed: ${e2.message}`);
    }
  }
}

// ─── Log rotation (prevents SD card from filling) ─────────────────────────
// On startup, write /etc/logrotate.d/mes-box so daily logrotate keeps
// /var/log/mes-box-*.log and /var/log/dnsmasq.log under control.
function ensureLogrotateConfig() {
  const conf = `/var/log/mes-box/*.log /var/log/mes-box-*.log /var/log/dnsmasq.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    maxsize 50M
    create 0640 root root
}
`;
  try {
    const target = '/etc/logrotate.d/mes-box';
    let existing = '';
    try { existing = fs.readFileSync(target, 'utf8'); } catch {}
    if (existing !== conf) {
      fs.writeFileSync(target, conf, { mode: 0o644 });
      console.log('[agent] wrote logrotate config →', target);
    }
  } catch (e) {
    console.error('[agent] logrotate config write failed:', e.message);
  }
}

// ─── Tick scheduler ───────────────────────────────────────────────────────
async function safe(fn) { try { await fn(); } catch (e) { console.error(e.message); } }

// ─── Real-time throughput sampler ────────────────────────────────────────
// In SIMPLE mode the Pi forwards all LAN traffic. We can't trust /sys eth0
// counters because (a) every forwarded packet shows up on eth0 twice (once rx
// from gateway, once tx to client) AND (b) once tshark/sni-parser turns on
// promiscuous mode, eth0.rx_bytes counts every LAN frame, including broadcasts
// and frames addressed to other MACs that the Pi has no business with.
//
// Truth source: iptables FORWARD chain byte counters. Two accounting rules,
// one matching src∈LAN-subnet (upload), one matching dst∈LAN-subnet (download).
// These rules don't ACCEPT/DROP — they just count and fall through. Every
// forwarded packet hits exactly one of them, so no double-counting.
//
// In other modes (peer/dhcp/router/bridge) we still read eth0 counters; only
// Simple Mode has the doubling problem.
let _lastIfStat = null;
let _lastFwdStat = null;
let _acctRulesInstalled = false;
let _acctSubnet = null;

function _detectLanCidr() {
  try {
    const out = execSync(`ip -4 -o addr show ${LAN_IF}`, { encoding: 'utf8' });
    const m = out.match(/inet (\d+\.\d+\.\d+)\.\d+\/(\d+)/);
    if (!m) return null;
    return `${m[1]}.0/${m[2]}`;
  } catch { return null; }
}

function _ensureAcctRules() {
  const cidr = _detectLanCidr();
  if (!cidr) return false;
  if (_acctRulesInstalled && _acctSubnet === cidr) return true;
  // Drop any prior rules (subnet may have changed)
  try { execSync(`iptables -S FORWARD | grep -E "mes-acct-(up|down)" | sed 's/^-A /-D /' | xargs -L1 -r iptables`, { shell: '/bin/bash' }); } catch {}
  try {
    execSync(`iptables -I FORWARD -s ${cidr} -m comment --comment mes-acct-up`);
    execSync(`iptables -I FORWARD -d ${cidr} -m comment --comment mes-acct-down`);
    _acctRulesInstalled = true;
    _acctSubnet = cidr;
    return true;
  } catch (e) {
    return false;
  }
}

function _readFwdCounters() {
  // iptables -L FORWARD -v -n -x output: line per rule, cols: pkts bytes target ...
  try {
    const out = execSync('iptables -L FORWARD -v -n -x', { encoding: 'utf8' });
    let up = 0, down = 0;
    for (const line of out.split('\n')) {
      const f = line.trim().split(/\s+/);
      if (f.length < 3) continue;
      if (line.includes('mes-acct-up'))   up   = parseInt(f[1]) || 0;
      if (line.includes('mes-acct-down')) down = parseInt(f[1]) || 0;
    }
    return { up, down };
  } catch { return null; }
}

async function sampleThroughput() {
  try {
    const now = Date.now();
    let rx_bps = 0, tx_bps = 0, mode = 'peer';
    const inSimple = !!(simpleMode && simpleMode.getStatus
      && simpleMode.getStatus().enabled
      && (simpleMode.getStatus().arpspoof_count || 0) > 0);

    if (inSimple && _ensureAcctRules()) {
      mode = 'simple';
      const c = _readFwdCounters();
      if (!c) return;
      if (!_lastFwdStat) { _lastFwdStat = { up: c.up, down: c.down, ts: now }; return; }
      const elapsed = (now - _lastFwdStat.ts) / 1000;
      if (elapsed < 0.5) return;
      // up   = LAN-side source = client uploading to internet (= tx from user POV)
      // down = LAN-side dest   = internet to client          (= rx from user POV)
      tx_bps = Math.max(0, Math.round((c.up   - _lastFwdStat.up)   / elapsed));
      rx_bps = Math.max(0, Math.round((c.down - _lastFwdStat.down) / elapsed));
      _lastFwdStat = { up: c.up, down: c.down, ts: now };
    } else {
      // Non-simple modes: use raw eth0 counters
      const path = `/sys/class/net/${LAN_IF}/statistics`;
      const rx = parseInt(fs.readFileSync(`${path}/rx_bytes`, 'utf8'));
      const tx = parseInt(fs.readFileSync(`${path}/tx_bytes`, 'utf8'));
      if (!_lastIfStat) { _lastIfStat = { rx, tx, ts: now }; return; }
      const elapsed = (now - _lastIfStat.ts) / 1000;
      if (elapsed < 0.5) return;
      rx_bps = Math.max(0, Math.round((rx - _lastIfStat.rx) / elapsed));
      tx_bps = Math.max(0, Math.round((tx - _lastIfStat.tx) / elapsed));
      _lastIfStat = { rx, tx, ts: now };
    }
    await api('POST', '/api/box/throughput', { rx_bps, tx_bps, ts: now, mode });
  } catch (e) {
    // Silent — interface might not exist on first run
  }
}

async function tick5s() {
  await safe(sampleThroughput);
  await safe(sampleDeviceThroughput);
}

async function sampleDeviceThroughput() {
  if (!devThroughput) return;
  const devs = devThroughput.sample();
  if (!devs.length) return;
  try { await api('POST', '/api/box/device-throughput', { devices: devs, ts: Date.now() }); } catch {}
}

async function tick60s() {
  await safe(ensureAuth);
  await safe(reportHeartbeat);
  await safe(syncPolicy);
  await safe(pollAndExecuteCommands);
  // Schedule ticker — runs every 60s to enforce time-based blocks
  try { tickSchedules(); } catch (e) { console.error('[agent] schedule tick failed:', e.message); }
}
async function tick5min() {
  await safe(reportDevices);
  await safe(newDeviceWatch);
  await safe(reportFlows);
  await safe(reportDnsQueries);
  // Run latency probes if policy specifies targets
  const targets = (agentState.last_policy && agentState.last_policy.latency_probes) || [];
  if (targets.length) await safe(() => runLatencyProbes(targets));
  // mDNS discovery (richer device names than ARP)
  await safe(reportMdnsDevices);
}

// ─── mDNS / SSDP enrichment ──────────────────────────────────────────────
// Use avahi-browse if available; otherwise UPnP M-SEARCH (one shot) for SSDP.
// Reports as device "hostname hints" so cloud can override empty hostnames.
async function reportMdnsDevices() {
  const hints = {};   // mac → { hostname?, vendor? }
  // avahi (mDNS): -t terminate, -r resolve, -p parsable
  try {
    const out = execSync('avahi-browse -atrkp -p 2>/dev/null | head -200', { encoding: 'utf8', timeout: 10_000 });
    for (const line of out.split('\n')) {
      // Format: =;eth0;IPv4;Living-Room-TV;_googlecast._tcp;local;Living-Room-TV.local;192.168.1.50;8009;txt
      const cols = line.split(';');
      if (cols[0] !== '=') continue;
      const ip = cols[7];
      const name = cols[3];
      if (!ip || !name) continue;
      const mac = (arpIpToMac && arpIpToMac[ip]) || '';
      if (mac) hints[mac] = { ...(hints[mac] || {}), hostname: name };
    }
  } catch {}
  // SSDP: send 1 M-SEARCH, collect for 2s
  try {
    const dgram = require('dgram');
    const s = dgram.createSocket('udp4');
    const msg = Buffer.from(
      'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n'
    );
    s.bind(0, () => s.send(msg, 0, msg.length, 1900, '239.255.255.250'));
    s.on('message', (buf, rinfo) => {
      const txt = buf.toString('utf8');
      const server = (txt.match(/SERVER:\s*(.+)/i) || [])[1];
      const mac = (arpIpToMac && arpIpToMac[rinfo.address]) || '';
      if (mac && server) hints[mac] = { ...(hints[mac] || {}), vendor: server.slice(0, 80) };
    });
    await new Promise(r => setTimeout(r, 2200));
    s.close();
  } catch {}
  if (!Object.keys(hints).length) return;
  // Attach as device updates (only fields that have hints)
  const devices = Object.entries(hints).map(([mac, h]) => ({ mac, ...h }));
  try { await api('POST', '/api/box/devices', { devices }); } catch {}
}
async function tick6h() {
  await safe(checkOta);
  await safe(checkAgentSelfUpdate);
  await safe(uploadConfigSnapshot);
  await safe(integritySelfCheck);
  await safe(checkUpstreamRouteChange);
}

// ─── Upstream route monitoring ───────────────────────────────────────────
// Traceroute to anchor IPs; first 3 hops should be stable. If they change between
// runs, upstream routing changed (ISP swap, BGP change). Cloud is informed via alarm.
const ROUTE_ANCHORS = ['8.8.8.8', '1.1.1.1', '9.9.9.9'];
let _lastRouteFingerprint = '';
async function checkUpstreamRouteChange() {
  const hops = [];
  for (const target of ROUTE_ANCHORS) {
    try {
      const out = execSync(`traceroute -n -w 1 -q 1 -m 3 ${target}`, { encoding: 'utf8', timeout: 8000 });
      // Pick out the IPs of the first 3 hops
      const ips = (out.match(/\b\d+\.\d+\.\d+\.\d+\b/g) || []).slice(0, 3);
      hops.push(`${target}->${ips.join(',')}`);
    } catch (e) {
      hops.push(`${target}->ERR`);
    }
  }
  const fp = hops.join('|');
  if (_lastRouteFingerprint && fp !== _lastRouteFingerprint) {
    try {
      await api('POST', '/api/box/route-change', {
        previous: _lastRouteFingerprint,
        current: fp,
        ts: Date.now(),
      });
    } catch {}
    console.log(`[agent] upstream route changed: was=${_lastRouteFingerprint} now=${fp}`);
  }
  _lastRouteFingerprint = fp;
}

// ─── Firmware integrity self-check ───────────────────────────────────────
// SHA-256 our key files and report. Cloud compares to expected values.
async function integritySelfCheck() {
  const files = [
    '/opt/mes-box/agent.js',
    '/opt/mes-box/install.sh',
    '/etc/systemd/system/mes-box-agent.service',
  ];
  const hashes = {};
  for (const f of files) {
    try {
      const buf = fs.readFileSync(f);
      hashes[f] = crypto.createHash('sha256').update(buf).digest('hex');
    } catch (e) {
      hashes[f] = `ERR:${e.code || 'unknown'}`;
    }
  }
  try {
    await api('POST', '/api/box/integrity-report', {
      ts: Date.now(),
      version: VERSION,
      hashes,
    });
  } catch (e) {
    console.error('[agent] integrity report failed:', e.message);
  }
}

// ─── Latency probes ──────────────────────────────────────────────────────
// Cloud sends a list of targets in policy bundle as `latency_probes: [host, ...]`.
// Every 5 min, ping each, batch-upload results.
async function runLatencyProbes(targets) {
  if (!Array.isArray(targets) || targets.length === 0) return;
  const results = [];
  for (const t of targets.slice(0, 10)) {
    try {
      const out = execSync(`ping -c 3 -W 2 -q ${t.replace(/[^a-z0-9._-]/gi, '')}`, { encoding: 'utf8', timeout: 8000 });
      const m = out.match(/min\/avg\/max\/[a-z]+\s*=\s*([\d.]+)\/([\d.]+)\/([\d.]+)/);
      const lossM = out.match(/(\d+)% packet loss/);
      results.push({
        target: t,
        min_ms: m ? parseFloat(m[1]) : null,
        avg_ms: m ? parseFloat(m[2]) : null,
        max_ms: m ? parseFloat(m[3]) : null,
        loss_pct: lossM ? parseInt(lossM[1]) : 100,
        ts: Date.now(),
      });
    } catch (e) {
      results.push({ target: t, error: e.message.slice(0, 100), loss_pct: 100, ts: Date.now() });
    }
  }
  try { await api('POST', '/api/box/latency-probes', { results }); } catch {}
}

// ─── Daily config snapshot upload ────────────────────────────────────────
// Cloud uses these for: post-mortem support, drift detection, audit.
async function uploadConfigSnapshot() {
  const readSafe = (p, max) => {
    try { return fs.readFileSync(p, 'utf8').slice(-max); } catch { return null; }
  };
  const runSafe = (cmd, max) => {
    try { return execSync(cmd, { encoding: 'utf8', timeout: 5000 }).slice(-max); } catch (e) { return null; }
  };
  const snapshot = {
    ts: Date.now(),
    version: VERSION,
    last_policy: (() => { try { return JSON.parse(fs.readFileSync(POLICY_CACHE, 'utf8')); } catch { return null; } })(),
    dnsmasq_conf: readSafe('/etc/dnsmasq.d/mes-box.conf', 4000),
    dnsmasq_dhcp: readSafe('/etc/dnsmasq.d/mes-box-dhcp.conf', 4000),
    nft_ruleset: runSafe('nft list ruleset 2>/dev/null', 8000),
    wg_conf:     readSafe('/etc/wireguard/wg-mesh.conf', 2000),
    iptables_nat: runSafe('iptables -t nat -L -n 2>/dev/null', 4000),
    hostname: os.hostname(),
    uname: runSafe('uname -a', 200),
    disk_free: runSafe('df -h /', 500),
  };
  try {
    await api('POST', '/api/box/config-snapshot', snapshot);
    console.log('[agent] config snapshot uploaded');
  } catch (e) {
    console.error('[agent] config snapshot upload failed:', e.message);
  }
}

(async () => {
  console.log(`[agent] mes Box agent v${VERSION} starting…`);

  // Bootstrap: self-register on first boot if no config exists
  try {
    await bootstrap();
  } catch (e) {
    console.error('[agent] bootstrap failed:', e.message);
    // Likely no internet. Try the WiFi setup wizard if there's a wlan0.
    try { await maybeStartWifiWizard(); } catch (we) { console.error('[agent] wizard:', we.message); }
    console.error('[agent] will retry in 30s…');
    setTimeout(() => process.exit(2), 30_000);  // systemd will restart us
    return;
  }

  console.log(`[agent] cloud=${CLOUD} mac=${BOX_MAC} iface=${LAN_IF}`);

  startCaptivePortal();
  ensureLogrotateConfig();
  // Enable conntrack byte/packet accounting — needed for accurate per-flow
  // bytes_up/bytes_down in captureFlows(). Default kernel value is 0
  // (counters disabled). Persisted to /etc/sysctl.d so it survives reboot.
  try {
    execSync('sysctl -w net.netfilter.nf_conntrack_acct=1 >/dev/null 2>&1');
    fs.writeFileSync('/etc/sysctl.d/99-mes-conntrack.conf', 'net.netfilter.nf_conntrack_acct=1\n');
  } catch {}
  await safe(uploadCrashIfAny);

  // Sig engine: STARTER_SIGS auto-load at require() time. Don't pass [] — that
  // wipes them. Customer-custom sigs are merged in by syncPolicy() when the
  // policy bundle arrives.
  if (sigEngine) {
    try { console.log('[agent] sig-engine loaded:', sigEngine.signatureCount(), 'sigs'); } catch (e) { console.error('[agent] sig-engine init:', e.message); }
  }
  // SNI/JA3 parser: passive capture on LAN iface
  if (sniParser) {
    try {
      sniParser.start({ iface: LAN_IF });
      const flushSni = async () => {
        const recent = sniParser.getRecent ? sniParser.getRecent() : [];
        if (!recent.length) return;
        try { await api('POST', '/api/box/sni-handshakes', { handshakes: recent }); } catch {}
      };
      setInterval(flushSni, 60_000);
      // Tier-1 Smart Block: live SNI matching against blocked_sni_patterns.
      // Note: post-hoc — first connection slips through, subsequent packets
      // of the same flow are dropped via iptables connbytes.
      if (typeof sniParser.on === 'function') {
        sniParser.on('sni', (rec) => {
          try {
            const match = _matchSniPattern(rec && rec.sni);
            if (!match) return;
            _dropTcpForSni(rec.src_ip, rec.dst_ip, rec.dst_port);
            // Surface as a fake "blocked" flow so the cloud shows it
            api('POST', '/api/box/flows', { flows: [{
              ts: Date.now(), src_ip: rec.src_ip, src_mac: macForIp(rec.src_ip),
              dst_ip: rec.dst_ip, dst_port: rec.dst_port || 443, proto: 'tcp',
              sni: rec.sni, blocked: true, reason: `smart_block:${match.pattern_type}:${match.value}`,
            }]}).catch(()=>{});
          } catch {}
        });
      }
      console.log('[agent] sni-parser started on', LAN_IF);
    } catch (e) { console.error('[agent] sni-parser start:', e.message); }
  }

  // ─── Tier 2 Feature A: Suricata IDS/IPS bootstrap ───────────────────────
  // On every boot: idempotent install (skip if already present), write/refresh
  // config, ensure ET-OPEN rules are present (first-run download + reload),
  // make sure suricata is running. EVE JSON events are tailed by tickIdsEvents.
  if (suricata) {
    (async () => {
      try {
        const ins = suricata.install();
        if (!ins.ok) { console.error('[agent] suricata install failed:', ins.error); return; }
        suricata.configure(LAN_IF);
        // First-run rule download. If we've never updated, do it now (blocking-ish).
        const st0 = suricata.getStatus();
        if (!st0.last_update || st0.rule_count < 50) {
          console.log('[agent] suricata: pulling ET-OPEN rules (first run)…');
          const r = suricata.updateRules();
          console.log('[agent] suricata rule update:', r.ok ? `${r.rule_count} rules` : `failed: ${r.error}`);
        }
        const st = suricata.start();
        console.log('[agent] suricata:', st.ok ? 'running' : `start failed: ${st.error}`);
      } catch (e) { console.error('[agent] suricata bootstrap:', e.message); }
    })();
    // Tail eve.json every 60s, ship new alerts to cloud
    setInterval(() => safe(tickIdsEvents), 60_000);
    setTimeout(() => safe(tickIdsEvents), 30_000);   // first sample after 30s
    // Daily rule refresh — 03:17 local-ish. We approximate via 24h interval.
    setInterval(() => {
      try {
        console.log('[agent] suricata: daily rule refresh');
        const r = suricata.updateRules();
        console.log('[agent] suricata rule refresh:', r.ok ? `${r.rule_count} rules` : `failed: ${r.error}`);
      } catch (e) { console.error('[agent] suricata rule refresh err:', e.message); }
    }, 24 * 3600_000);
  }

  // Boot-time auto-mode: if /etc/mes-box/preferred-mode says "simple", start
  // Simple Mode (ARP-spoof) right away so the box sees every LAN device after
  // a fresh flash with zero user interaction. Also self-heal: if persisted
  // state says enabled=true but no arpspoof procs are alive (e.g. agent
  // restarted, leaving orphan state on disk), force a fresh stop+start.
  // Boot-time hygiene: wipe stale per-device iptables rules that may have
  // duplicated under the old idempotency bug. Fresh reconcile happens on first
  // sample tick (5s later).
  if (devThroughput && devThroughput.flushAllRules) {
    try { devThroughput.flushAllRules(); console.log('[agent] device-throughput rules flushed for clean reconcile'); } catch {}
  }
  try {
    const preferred = (fs.readFileSync('/etc/mes-box/preferred-mode', 'utf8') || '').trim();
    if (preferred === 'simple' && simpleMode) {
      const status = simpleMode.getStatus ? simpleMode.getStatus() : { enabled: false, arpspoof_count: 0 };
      const needsStart = !status.enabled || (status.arpspoof_count || 0) === 0;
      if (needsStart) {
        // If state says enabled but no procs, clear state first so start() doesn't short-circuit
        if (status.enabled && (status.arpspoof_count || 0) === 0 && simpleMode.stop) {
          console.log('[agent] simple-mode state stale (no arpspoof procs); clearing before restart');
          try { simpleMode.stop(); } catch {}
        }
        console.log('[agent] auto-starting Simple Mode (preferred-mode=simple)');
        simpleMode.start({}).then(r => {
          console.log('[agent] simple-mode start:', r.ok ? `ok (${(r.clients||[]).length} clients)` : `failed: ${r.error}`);
          if (r.ok && simpleMode.rescan) {
            setTimeout(() => simpleMode.rescan().then(rs => console.log('[agent] simple-mode rescan:', rs)).catch(()=>{}), 30_000);
          }
        }).catch(e => console.error('[agent] simple-mode start error:', e.message));
      }
      // Periodic rescan AND self-heal every 10 min
      setInterval(() => {
        try {
          const s = simpleMode.getStatus ? simpleMode.getStatus() : { enabled: false, arpspoof_count: 0 };
          if (s.enabled && (s.arpspoof_count || 0) === 0) {
            console.log('[agent] simple-mode self-heal: arpspoof procs died, restarting');
            try { simpleMode.stop(); } catch {}
            simpleMode.start({}).catch(()=>{});
          } else if (simpleMode.rescan) {
            simpleMode.rescan().catch(()=>{});
          }
        } catch {}
      }, 10 * 60_000);
    }
    if (preferred === 'dhcp' && dhcpMode) {
      console.log('[agent] auto-starting DHCP Mode (preferred-mode=dhcp)');
      try {
        const r = dhcpMode.installAndConfigure({ lan_iface: 'eth0' });
        console.log('[agent] dhcp-mode start:', r.ok ? 'ok' : `failed: ${r.error}`);
      } catch (e) { console.error('[agent] dhcp-mode start error:', e.message); }
    }
    if (preferred === 'router' && routerMode) {
      console.log('[agent] auto-starting Router Mode (preferred-mode=router)');
      try {
        const r = routerMode.installAndConfigure({});
        console.log('[agent] router-mode start:', r.ok ? `ok (wan=${r.wan_iface} lan=${r.lan_iface})` : `failed: ${r.error}`);
      } catch (e) { console.error('[agent] router-mode start error:', e.message); }
    }
  } catch { /* preferred-mode file missing — stay passive */ }

  await tick60s();
  await tick5min();
  await tick6h();
  setInterval(tick60s,  60_000);
  setInterval(tick5min, 5 * 60_000);
  setInterval(tick6h,   6 * 3600_000);
  // Throughput sampler — 5s cadence for live speedometer
  await sampleThroughput();   // prime baseline
  setInterval(tick5s, 5_000);
})();

// Graceful shutdown
process.on('SIGTERM', () => { console.log('[agent] SIGTERM, exiting'); process.exit(0); });
process.on('SIGINT',  () => { console.log('[agent] SIGINT, exiting');  process.exit(0); });

// Crash report — write to disk + upload on next boot
const CRASH_LOG = '/var/log/mes-box/crash.log';
process.on('uncaughtException', (err) => {
  try {
    fs.mkdirSync('/var/log/mes-box', { recursive: true });
    const entry = `\n[crash ${new Date().toISOString()}] uncaughtException: ${err.stack || err.message}\n`;
    fs.appendFileSync(CRASH_LOG, entry);
    console.error('[agent] crash:', err.message);
  } catch {}
  process.exit(2);
});
process.on('unhandledRejection', (err) => {
  try {
    fs.mkdirSync('/var/log/mes-box', { recursive: true });
    fs.appendFileSync(CRASH_LOG, `\n[unhandledRejection ${new Date().toISOString()}] ${err && (err.stack || err.message || err)}\n`);
  } catch {}
});

// On boot: if there's a crash log, ship it then truncate
async function uploadCrashIfAny() {
  try {
    if (!fs.existsSync(CRASH_LOG)) return;
    const text = fs.readFileSync(CRASH_LOG, 'utf8');
    if (text.length < 10) return;
    await api('POST', '/api/box/crash', {
      version: VERSION,
      crash_log: text.slice(-50_000),  // last 50 KB
      uname: (() => { try { return execSync('uname -a', { encoding: 'utf8', timeout: 5000 }).trim(); } catch { return ''; } })(),
      uptime: os.uptime(),
    });
    fs.truncateSync(CRASH_LOG, 0);
    console.log('[agent] crash log uploaded + cleared');
  } catch (e) { console.error('[agent] crash upload failed:', e.message); }
}
