/*
 * Mock Firewalla Cloud
 * --------------------
 * A drop-in stand-in for firewalla.encipher.io that logs every request
 * and returns plausible responses so a real Firewalla box (or your custom
 * clone) can complete pairing, check-in, and message-relay flows.
 *
 * What it implements:
 *   POST /iot/api/v2/login/eptoken               (box authenticates)
 *   POST /iot/api/v2/group/{appId}                (box creates group)
 *   GET  /iot/api/v2/ept/{eid}/groups             (list groups)
 *   POST /iot/api/v2/ept/rendezvous/{rid}         (box stores invitation)
 *   GET  /iot/api/v2/ept/rendezvous/{rid}         (anyone fetches it)
 *   POST /iot/api/v2/ept/rendezvous/{rid}/invite  (app posts join request)
 *   POST /iot/api/v2/group/{gid}/{eid}            (add member)
 *   POST /iot/api/v2/service/message/...          (message relay POST)
 *   GET  /iot/api/v2/service/message/...          (message relay GET)
 *   POST /bone/api/v3/sys/checkin                 (box telemetry)
 *   GET  /license/api/v1/license/issue/{luid}     (issue license)
 *   GET  /                                        (status / health)
 *
 * What it does NOT do:
 *   - Real cryptographic verification of license signatures
 *   - Real RSA decryption of group keys (it stubs symmetric keys)
 *   - WebSocket relay (basic stub only - extend if needed)
 *   - Persistence (state is in-memory; restart wipes it)
 *
 * Use cases:
 *   - Learn the Firewalla pairing protocol by watching real requests
 *   - Develop a custom Firewalla-clone without touching firewalla.encipher.io
 *   - Run integration tests against a deterministic backend
 *
 * License: MIT (do what you want)
 */

const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const app = express();
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true }));

// ─── Persistence (state survives restarts) ───
const STATE_FILE = process.env.STATE_FILE || '/data/state.json';
const ED25519_DIR = process.env.ED25519_DIR || '/data';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'mes-cloud-admin';

// ─── License-server keypair (Ed25519) ───
let licenseKeys = null;
function loadOrCreateLicenseKeys() {
  const privPath = path.join(ED25519_DIR, 'license.priv.pem');
  const pubPath = path.join(ED25519_DIR, 'license.pub.pem');
  try {
    if (!fs.existsSync(ED25519_DIR)) fs.mkdirSync(ED25519_DIR, { recursive: true });
    if (fs.existsSync(privPath)) {
      const privPem = fs.readFileSync(privPath, 'utf8');
      const pubPem = fs.readFileSync(pubPath, 'utf8');
      console.log(`Loaded license keypair from ${ED25519_DIR}`);
      return {
        privateKey: crypto.createPrivateKey(privPem),
        publicKey: crypto.createPublicKey(pubPem),
        privPem, pubPem,
      };
    }
    // Generate a new Ed25519 keypair
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    const pubPem = publicKey.export({ type: 'spki', format: 'pem' });
    fs.writeFileSync(privPath, privPem, { mode: 0o600 });
    fs.writeFileSync(pubPath, pubPem);
    console.log(`Generated new Ed25519 license keypair in ${ED25519_DIR}`);
    return { privateKey, publicKey, privPem, pubPem };
  } catch (e) {
    console.error('License keypair init failed:', e.message);
    return null;
  }
}

function signLicense(licenseDataObj) {
  if (!licenseKeys) return 'no-key-available';
  const message = Buffer.from(JSON.stringify(licenseDataObj));
  const sig = crypto.sign(null, message, licenseKeys.privateKey);
  return sig.toString('base64');
}

let state;
function loadState() {
  try {
    if (fs.existsSync(STATE_FILE)) {
      const raw = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
      // Deserialize Sets (they get serialized as arrays)
      for (const g of Object.values(raw.groups || {})) {
        g.eids = new Set(g.eids || []);
      }
      console.log(`Loaded state from ${STATE_FILE} (groups=${Object.keys(raw.groups||{}).length})`);
      return raw;
    }
  } catch (e) {
    console.error(`Failed to load state: ${e.message}`);
  }
  return {
    groups: {}, rendezvous: {}, endpoints: {},
    licenses: {}, messages: [], checkins: [],
    events: [],  // recent request log for dashboard
    authorized_macs: {},  // { "20:6d:31:11:15:f8": { mac, customer_id, customer_name, type, authorized_at, ... } }
    issued_licenses: {},  // { mac: license_object }
    customers: {},  // { id: { id, name, phone, email, plan, address, notes, created_at } }
  };
}
function saveState() {
  try {
    if (!fs.existsSync(path.dirname(STATE_FILE))) {
      fs.mkdirSync(path.dirname(STATE_FILE), { recursive: true });
    }
    const serializable = JSON.parse(JSON.stringify(state, (k, v) =>
      v instanceof Set ? Array.from(v) : v));
    fs.writeFileSync(STATE_FILE, JSON.stringify(serializable, null, 2));
  } catch (e) {
    console.error(`Failed to save state: ${e.message}`);
  }
}

state = loadState();
if (!state.events) state.events = [];
if (!state.authorized_macs) state.authorized_macs = {};
if (!state.issued_licenses) state.issued_licenses = {};
if (!state.customers) state.customers = {};
if (!state.family_members) state.family_members = {};   // { customer_id: [ {id, name, role, icon, device_macs[]} ] }
if (!state.schedules) state.schedules = {};             // { customer_id: [ {id, name, device_macs[], days[], start_hhmm, end_hhmm, enabled} ] }
if (!state.notifications) state.notifications = {};     // { customer_id: [ {id, kind, title, body, ts, read} ] }
if (!state.support_threads) state.support_threads = {};  // { customer_id: [ {id, from, body, ts, read_by_admin, read_by_customer} ] }
if (!state.admins) state.admins = {};                     // { username: { username, name, role, password_hash, created_at } }
if (!state.webhooks) state.webhooks = [];                 // [ { id, name, url, events: [], enabled, secret, created_at } ]
if (!state.admin_actions) state.admin_actions = [];       // [ { ts, admin, action, target, ... } ]
if (!state.box_sessions) state.box_sessions = {};          // { token: { mac, customer_id, issued_at, last_seen } }
if (!state.box_state) state.box_state = {};                // { mac: { last_heartbeat, public_ip, internal_ip, version, uptime_s, cpu, ram, temp } }
if (!state.flows) state.flows = [];                        // ring-buffer: [ { ts, mac (box), src_mac, src_ip, dst_ip, dst_port, dst_domain, proto, bytes_up, bytes_down, blocked, category } ]
const FLOWS_MAX = 100000;
if (!state.box_devices) state.box_devices = {};            // { box_mac: { device_mac: { mac, ip, hostname, vendor, first_seen, last_seen, blocked } } }
if (!state.alarms) state.alarms = [];                      // [ { id, ts, customer_id, box_mac, severity, kind, title, body, device_mac, acked } ]
if (!state.rules) state.rules = {};                        // { customer_id: [ { id, scope: 'all'|'device'|'family', target, type: 'category'|'domain'|'ip', value, action: 'block'|'allow', enabled, created_at } ] }
if (!state.app_categories) state.app_categories = null;    // initialized below from APP_CATEGORIES default
if (!state.ddns) state.ddns = {};                          // { slug: { customer_id, current_ip, last_update, ttl } }
if (!state.sites) state.sites = {};                        // { id: { id, customer_id, name, address, box_macs: [] } }
if (!state.wg_peers) state.wg_peers = {};                  // { peer_id: { id, customer_id, device_label, pubkey, privkey, address, created_at } }
if (!state.wg_server) state.wg_server = null;              // { pubkey, privkey, listen_port, network_cidr, dns }
if (!state.vpn_clients) state.vpn_clients = {};            // { customer_id: [ { id, label, provider, endpoint, country, active, created_at } ] }  — conf_text NEVER stored cloud-side
if (!state.config) state.config = {
  auto_approve_signups: true,
  signup_enabled: true,
  email_enabled: false,
  email_from: 'noreply@mes.net.lb',
  admin_email: 'admin@mes.net.lb',
  brand_domain: 'cloud.mes.net.lb',
  brand_name: 'mes Network',
  brand_color: '#ff8c42',
  brand_accent: '#3ad29f',
  brand_logo_url: '',
  brand_support_phone: '',
};

// Plan limits — feature gating per tier
const PLAN_LIMITS = {
  basic:    { max_family_members: 0,  max_schedules: 1,  vpn: false, ids: false, max_devices_seen: 15,  max_rules: 5,   multi_site: false, max_sites: 1, max_wg_peers: 0  },
  family:   { max_family_members: 6,  max_schedules: 8,  vpn: false, ids: false, max_devices_seen: 50,  max_rules: 30,  multi_site: false, max_sites: 1, max_wg_peers: 0  },
  pro:      { max_family_members: 10, max_schedules: 20, vpn: true,  ids: true,  max_devices_seen: 150, max_rules: 100, multi_site: false, max_sites: 1, max_wg_peers: 5  },
  business: { max_family_members: 25, max_schedules: 50, vpn: true,  ids: true,  max_devices_seen: 500, max_rules: 500, multi_site: true,  max_sites: 10, max_wg_peers: 50 },
};
function planLimits(plan) {
  return PLAN_LIMITS[plan] || PLAN_LIMITS.basic;
}

// Plan pricing — monthly, with USD + LBP variants
// LBP rate: ~89,500 LBP / USD (May 2026 — update via state.config.lbp_per_usd)
const PLAN_PRICES = {
  basic:    { monthly_usd: 5,  label: 'Basic — DNS filter + per-device control' },
  family:   { monthly_usd: 10, label: 'Family — schedules + parental controls' },
  pro:      { monthly_usd: 20, label: 'Pro — VPN + IDS + advanced' },
  business: { monthly_usd: 50, label: 'Business — multi-network + priority support' },
};
function lbpPerUsd() {
  return state.config.lbp_per_usd || 89500;
}
// Pull live LBP/USD rate from a public free API. Falls back to last known if it fails.
async function fetchLbpRate() {
  return new Promise((resolve) => {
    https.get('https://open.er-api.com/v6/latest/USD', { timeout: 10_000 }, res => {
      let chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        try {
          const json = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          const rate = json.rates && json.rates.LBP;
          if (rate && rate > 0) {
            state.config.lbp_per_usd = Math.round(rate);
            state.config.lbp_rate_updated = Date.now();
            saveState();
            console.log(`         💱 LBP rate updated: 1 USD = ${state.config.lbp_per_usd} LBP`);
            resolve(state.config.lbp_per_usd);
          } else resolve(null);
        } catch (e) { console.error('lbp rate parse:', e.message); resolve(null); }
      });
    }).on('error', e => { console.error('lbp rate fetch:', e.message); resolve(null); });
  });
}
// Refresh once a day
setTimeout(fetchLbpRate, 60_000);
setInterval(fetchLbpRate, 24 * 3600_000);
app.get('/api/branding/lbp-rate', (req, res) => {
  res.json({ lbp_per_usd: lbpPerUsd(), updated_at: state.config.lbp_rate_updated || null });
});
app.post('/admin/api/lbp-rate/refresh', adminAuth, async (req, res) => {
  const r = await fetchLbpRate();
  res.json({ ok: !!r, lbp_per_usd: lbpPerUsd() });
});
function planPrice(plan, currency) {
  const base = PLAN_PRICES[plan] || PLAN_PRICES.basic;
  if (currency === 'LBP') {
    return {
      monthly: Math.round(base.monthly_usd * lbpPerUsd() / 1000) * 1000,  // round to nearest 1000 LBP
      currency: 'LBP',
      label: base.label,
    };
  }
  return { monthly: base.monthly_usd, currency: 'USD', label: base.label };
}

// Promo code lookup + apply
function applyPromoCode(code, baseAmount, currency, plan, customerTenantId) {
  if (!code) return { amount: baseAmount, discount: 0 };
  const promo = state.promo_codes[code];
  if (!promo) return { amount: baseAmount, discount: 0, error: 'unknown code' };
  if (promo.expires_at && Date.now() > new Date(promo.expires_at).getTime()) return { amount: baseAmount, discount: 0, error: 'expired' };
  if (promo.max_uses && promo.uses >= promo.max_uses) return { amount: baseAmount, discount: 0, error: 'max uses reached' };
  if (promo.applies_to_plans && promo.applies_to_plans.length && !promo.applies_to_plans.includes(plan)) return { amount: baseAmount, discount: 0, error: 'not for this plan' };
  // Tenant scoping: tenant-specific codes only valid for matching customers
  if (promo.tenant_id && promo.tenant_id !== customerTenantId) return { amount: baseAmount, discount: 0, error: 'not for your account' };
  let discount = 0;
  if (promo.type === 'percent') discount = Math.round(baseAmount * (promo.value / 100));
  else if (promo.type === 'fixed' && (!promo.currency || promo.currency === currency)) discount = promo.value;
  return {
    amount: Math.max(0, baseAmount - discount),
    discount,
    code: promo.code,
    description: promo.description || promo.code,
  };
}

// Load license keypair
licenseKeys = loadOrCreateLicenseKeys();

// ─── VAPID keypair (P-256) for Web Push ───
let vapidKeys = null;
function loadOrCreateVapidKeys() {
  const privPath = path.join(ED25519_DIR, 'vapid.priv.pem');
  const pubPath = path.join(ED25519_DIR, 'vapid.pub.pem');
  try {
    if (fs.existsSync(privPath)) {
      return {
        privateKey: crypto.createPrivateKey(fs.readFileSync(privPath)),
        publicKey: crypto.createPublicKey(fs.readFileSync(pubPath)),
      };
    }
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    fs.writeFileSync(privPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    fs.writeFileSync(pubPath, publicKey.export({ type: 'spki', format: 'pem' }));
    console.log('Generated VAPID keypair in ' + ED25519_DIR);
    return { publicKey, privateKey };
  } catch (e) {
    console.error('VAPID init failed:', e.message);
    return null;
  }
}
vapidKeys = loadOrCreateVapidKeys();

function urlBase64(buf) {
  return Buffer.from(buf).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function vapidPubBytes() {
  if (!vapidKeys) return Buffer.alloc(0);
  const jwk = vapidKeys.publicKey.export({ format: 'jwk' });
  return Buffer.concat([
    Buffer.from([0x04]),
    Buffer.from(jwk.x, 'base64url'),
    Buffer.from(jwk.y, 'base64url'),
  ]);
}

// VAPID JWT (ES256) for the push endpoint's origin
function vapidJwt(endpoint) {
  if (!vapidKeys) return null;
  const u = new URL(endpoint);
  const aud = u.protocol + '//' + u.host;
  const header = urlBase64(JSON.stringify({ typ: 'JWT', alg: 'ES256' }));
  const payload = urlBase64(JSON.stringify({
    aud,
    exp: Math.floor(Date.now() / 1000) + 12 * 3600,
    sub: 'mailto:' + (state.config.admin_email || 'admin@mes.net.lb'),
  }));
  const data = Buffer.from(header + '.' + payload);
  const sig = crypto.sign('sha256', data, { key: vapidKeys.privateKey, dsaEncoding: 'ieee-p1363' });
  return header + '.' + payload + '.' + urlBase64(sig);
}

// RFC 8291 aes128gcm Web Push payload encryption
function encryptWebPushPayload(payload, p256dhB64, authB64) {
  const subscriberPub = Buffer.from(p256dhB64, 'base64url');
  if (subscriberPub.length !== 65 || subscriberPub[0] !== 0x04) {
    throw new Error('subscriber p256dh public key must be 65-byte uncompressed');
  }
  const auth = Buffer.from(authB64, 'base64url');

  // Generate ephemeral ECDH keypair
  const ep = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const epJwk = ep.publicKey.export({ format: 'jwk' });
  const epPubBytes = Buffer.concat([
    Buffer.from([0x04]),
    Buffer.from(epJwk.x, 'base64url'),
    Buffer.from(epJwk.y, 'base64url'),
  ]);

  // Subscriber public key as KeyObject
  const subPubKey = crypto.createPublicKey({
    key: {
      kty: 'EC', crv: 'P-256',
      x: subscriberPub.slice(1, 33).toString('base64url'),
      y: subscriberPub.slice(33, 65).toString('base64url'),
    },
    format: 'jwk',
  });

  // ECDH shared secret
  const ecdh = crypto.diffieHellman({ privateKey: ep.privateKey, publicKey: subPubKey });

  const salt = crypto.randomBytes(16);

  // PRK_key = HMAC-SHA256(auth, ecdh)
  const prkKey = crypto.createHmac('sha256', auth).update(ecdh).digest();
  // key_info = "WebPush: info\0" || ua_pub || as_pub
  const keyInfo = Buffer.concat([
    Buffer.from('WebPush: info\0', 'utf8'),
    subscriberPub,
    epPubBytes,
  ]);
  // IKM = HKDF-Expand(prkKey, key_info || 0x01, 32)
  const ikm = crypto.createHmac('sha256', prkKey)
    .update(Buffer.concat([keyInfo, Buffer.from([0x01])]))
    .digest();
  // PRK = HMAC-SHA256(salt, IKM)
  const prk = crypto.createHmac('sha256', salt).update(ikm).digest();
  // CEK = HKDF-Expand(prk, "Content-Encoding: aes128gcm\0" || 0x01)[:16]
  const cek = crypto.createHmac('sha256', prk)
    .update(Buffer.from('Content-Encoding: aes128gcm\0\x01'))
    .digest()
    .slice(0, 16);
  // NONCE = HKDF-Expand(prk, "Content-Encoding: nonce\0" || 0x01)[:12]
  const nonce = crypto.createHmac('sha256', prk)
    .update(Buffer.from('Content-Encoding: nonce\0\x01'))
    .digest()
    .slice(0, 12);

  // Padded plaintext: payload || 0x02 (last record marker)
  const padded = Buffer.concat([Buffer.from(payload), Buffer.from([0x02])]);
  const cipher = crypto.createCipheriv('aes-128-gcm', cek, nonce);
  const ct = Buffer.concat([cipher.update(padded), cipher.final()]);
  const tag = cipher.getAuthTag();

  // Body: salt(16) || rs(4) || idlen(1) || keyid || ciphertext_with_tag
  const rs = Buffer.alloc(4);
  rs.writeUInt32BE(4096, 0);
  return Buffer.concat([
    salt,
    rs,
    Buffer.from([epPubBytes.length]),  // 65
    epPubBytes,
    ct,
    tag,
  ]);
}

// Send a Web Push to a single subscription
function sendWebPush(subscription, payloadString) {
  return new Promise((resolve) => {
    try {
      const jwt = vapidJwt(subscription.endpoint);
      if (!jwt) return resolve({ ok: false, error: 'no vapid keys' });
      const body = encryptWebPushPayload(payloadString, subscription.keys.p256dh, subscription.keys.auth);
      const u = new URL(subscription.endpoint);
      const httpModule = u.protocol === 'https:' ? require('https') : require('http');
      const req = httpModule.request({
        method: 'POST',
        hostname: u.hostname,
        port: u.port || (u.protocol === 'https:' ? 443 : 80),
        path: u.pathname + u.search,
        headers: {
          'Content-Type': 'application/octet-stream',
          'Content-Encoding': 'aes128gcm',
          'Authorization': 'vapid t=' + jwt + ', k=' + urlBase64(vapidPubBytes()),
          'TTL': '86400',
          'Content-Length': body.length,
        },
        timeout: 10000,
      }, res => {
        res.on('data', () => {});
        res.on('end', () => resolve({
          ok: res.statusCode >= 200 && res.statusCode < 300,
          status: res.statusCode,
        }));
      });
      req.on('error', e => resolve({ ok: false, error: e.message }));
      req.on('timeout', () => { req.destroy(); resolve({ ok: false, error: 'timeout' }); });
      req.write(body);
      req.end();
    } catch (e) {
      resolve({ ok: false, error: e.message });
    }
  });
}

// Save state every 30 seconds
setInterval(saveState, 30000);

// ─── Encrypted state.json backup (daily) ─────────────────────────────────
// AES-256-GCM with key from MES_BACKUP_KEY env (or derived from ADMIN_PASSWORD).
// Backups land in /data/backups/, retain last 30.
function dailyEncryptedBackup() {
  try {
    if (!fs.existsSync(STATE_FILE)) return;
    const backupDir = path.dirname(STATE_FILE) + '/backups';
    fs.mkdirSync(backupDir, { recursive: true });
    const passphrase = process.env.MES_BACKUP_KEY || process.env.ADMIN_PASSWORD || 'unset';
    const key = crypto.createHash('sha256').update(passphrase).digest();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const plaintext = fs.readFileSync(STATE_FILE);
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    // Format: 12-byte IV | 16-byte tag | ciphertext
    const out = Buffer.concat([iv, tag, encrypted]);
    const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const fn = `${backupDir}/state-${ts}.bin`;
    fs.writeFileSync(fn, out);
    // Retention: keep last 30
    const files = fs.readdirSync(backupDir).filter(f => f.startsWith('state-') && f.endsWith('.bin')).sort();
    while (files.length > 30) {
      try { fs.unlinkSync(`${backupDir}/${files.shift()}`); } catch {}
    }
    if (!state.backup_log) state.backup_log = [];
    state.backup_log.unshift({ ts: Date.now(), file: fn, bytes: out.length, count_kept: files.length + 1 });
    if (state.backup_log.length > 60) state.backup_log.length = 60;
    console.log(`         💾 ENCRYPTED BACKUP → ${fn} (${(out.length/1024).toFixed(1)} KB)`);
  } catch (e) {
    console.error('encrypted backup failed:', e.message);
  }
}
setTimeout(dailyEncryptedBackup, 5 * 60_000);          // 5 min after boot
setInterval(dailyEncryptedBackup, 24 * 3600_000);      // every 24h

// Admin: list backups + manually trigger one
app.get('/admin/api/backups', (req, res, next) => adminAuth(req, res, next), (req, res) => {
  const dir = path.dirname(STATE_FILE) + '/backups';
  let files = [];
  try {
    files = fs.readdirSync(dir)
      .filter(f => f.startsWith('state-') && f.endsWith('.bin'))
      .map(f => {
        const st = fs.statSync(`${dir}/${f}`);
        return { file: f, bytes: st.size, mtime: st.mtime.toISOString() };
      })
      .sort((a, b) => b.mtime.localeCompare(a.mtime));
  } catch {}
  res.json({ backups: files, log: state.backup_log || [], dir });
});
app.post('/admin/api/backups/run-now', (req, res, next) => adminAuth(req, res, next), (req, res) => {
  dailyEncryptedBackup();
  res.json({ ok: true });
});

// ─── Helpers ───
function uuid() {
  // RFC4122 v4
  return crypto.randomUUID ? crypto.randomUUID()
    : 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
        const r = Math.random() * 16 | 0;
        const v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
      });
}

function shortId(len = 22) {
  return crypto.randomBytes(Math.ceil(len * 3 / 4)).toString('base64')
    .replace(/[^a-zA-Z0-9]/g, '').slice(0, len);
}

function fakeJwt(payload) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
    .toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
  const body = Buffer.from(JSON.stringify(payload))
    .toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
  const sig = 'mock-cloud-not-a-real-signature';
  return `${header}.${body}.${sig}`;
}

function logReq(req, msg) {
  const time = new Date().toISOString().slice(11, 19);
  console.log(`[${time}] ${req.method.padEnd(4)} ${req.path}  ${msg || ''}`);
}

// ─── Logging + event-recording middleware ───
app.use((req, res, next) => {
  logReq(req);
  // Record event for dashboard (skip /admin to avoid noise)
  if (!req.path.startsWith('/admin')) {
    state.events.push({
      ts: Date.now(),
      method: req.method,
      path: req.path,
      ip: req.ip,
    });
    if (state.events.length > 500) state.events = state.events.slice(-300);
  }
  if (req.body && Object.keys(req.body).length) {
    const preview = JSON.stringify(req.body).slice(0, 250);
    console.log(`         body: ${preview}${preview.length === 250 ? '…' : ''}`);
  }
  next();
});

// ═══════════════════════════════════════════════════════════════════
// PHASE 1 — Box logs in to cloud
// ═══════════════════════════════════════════════════════════════════
app.post('/iot/api/v2/login/eptoken', (req, res) => {
  const assertion = (req.body && req.body.assertion) || {};
  const eid = shortId(22);
  const aid = uuid();
  const accessToken = fakeJwt({
    id: eid, eid, aid,
    iss: 'mock-cloud',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 86400 * 1000,
  });

  state.endpoints[eid] = {
    publicKey: assertion.publicKey,
    name: assertion.name,
    appId: assertion.appId,
    license: assertion.license,
    createdAt: Date.now(),
  };

  console.log(`         ✓ eptLogin → eid=${eid}`);
  res.json({ access_token: accessToken, eid, groups: [], aid });
});

// ═══════════════════════════════════════════════════════════════════
// PHASE 2 — Box creates a group (first run only)
// ═══════════════════════════════════════════════════════════════════
app.post('/iot/api/v2/group/:appId', (req, res) => {
  const gid = uuid();
  const eid = getRequestingEid(req);
  const ep = state.endpoints[eid] || {};
  const rawKey = crypto.randomBytes(32);
  const enc = ep.publicKey
    ? rsaEncryptForPubkey(rawKey, ep.publicKey)
    : rawKey.toString('base64');

  state.groups[gid] = {
    _id: gid,
    gid,
    appId: req.params.appId,
    name: req.body.name || 'Mock Group',
    info: req.body.info,
    xname: req.body.xname,
    eids: eid ? new Set([eid]) : new Set(),
    createdAt: new Date().toISOString(),
    symmetricKeys: eid ? [{
      gid,
      eid,
      key: enc,
      name: '',
      expires: 0,
      effective: 0,
      createdAt: new Date().toISOString(),
    }] : [],
  };

  console.log(`         ✓ group create → gid=${gid}  (creator eid=${eid || '?'})`);
  res.json(groupResponse(state.groups[gid]));
});

// List groups for an endpoint
app.get('/iot/api/v2/ept/:eid/groups', (req, res) => {
  const groups = Object.values(state.groups)
    .filter(g => g.eids.has(req.params.eid) || true)  // permissive in mock
    .map(g => ({ ...g, eids: Array.from(g.eids) }));
  res.json({ groups });
});

// Lookup endpoint info
app.get('/iot/api/v2/ept/:eid', (req, res) => {
  const ep = state.endpoints[req.params.eid];
  if (!ep) return res.status(404).json({ error: 'endpoint not found' });
  res.json({ ...ep, license: '<redacted>' });
});

// Helpers for crypto-aware auto-creation
function getRequestingEid(req) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) return null;
  const token = auth.slice(7);
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const pad = '='.repeat((4 - b64.length % 4) % 4);
    const payload = JSON.parse(Buffer.from(b64 + pad, 'base64').toString());
    return payload.eid;
  } catch { return null; }
}

function rsaEncryptForPubkey(plaintextBuf, pemPubKey) {
  if (!pemPubKey || !pemPubKey.includes('BEGIN')) {
    return plaintextBuf.toString('base64');
  }
  try {
    // Firewalla expects OAEP padding (default in node-forge / box-side privateDecrypt)
    const enc = crypto.publicEncrypt({
      key: pemPubKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha1',
    }, plaintextBuf);
    return enc.toString('base64');
  } catch (e) {
    console.error('rsaEncrypt failed:', e.message);
    return plaintextBuf.toString('base64');
  }
}

// Ensure a group exists AND has a symKey for the requesting eid (RSA-encrypted with their pubkey)
function ensureGroupForEid(gid, appId, eid) {
  if (!state.groups[gid]) {
    state.groups[gid] = {
      _id: gid,
      gid,
      appId: appId || 'unknown',
      name: 'auto-created',
      info: 'auto-created group',
      xname: '',
      eids: new Set(),
      createdAt: new Date().toISOString(),
      symmetricKeys: [],
    };
    console.log(`         ⚡ group AUTO-CREATED → gid=${gid}`);
  }
  const g = state.groups[gid];

  if (eid && !g.symmetricKeys.find(sk => sk.eid === eid)) {
    const ep = state.endpoints[eid];
    const rawKey = crypto.randomBytes(32);
    const enc = ep && ep.publicKey
      ? rsaEncryptForPubkey(rawKey, ep.publicKey)
      : rawKey.toString('base64');
    g.symmetricKeys.push({
      gid,
      eid,
      key: enc,
      name: '',          // peer display name (empty in mock)
      expires: 0,
      effective: 0,
      createdAt: new Date().toISOString(),
    });
    g.eids.add(eid);
    console.log(`         ⚡ symKey added for eid=${eid} (${ep && ep.publicKey ? 'RSA-encrypted with box pubkey' : 'plain'})`);
  }
  return g;
}

// Backwards-compat alias
const ensureGroup = (gid, appId) => ensureGroupForEid(gid, appId, null);

function groupResponse(g) {
  return {
    ...g,
    eids: Array.from(g.eids),
    members: Array.from(g.eids),
  };
}

// groupFind — GET /iot/api/v2/group/{appId}/{gid}
app.get('/iot/api/v2/group/:appId/:gid', (req, res) => {
  const eid = getRequestingEid(req);
  const g = ensureGroupForEid(req.params.gid, req.params.appId, eid);
  console.log(`         ✓ groupFind → gid=${req.params.gid}  (requester eid=${eid || '?'})`);
  res.json(groupResponse(g));
});

// group update — POST /iot/api/v2/group/{appId}/{gid}
app.post('/iot/api/v2/group/:appId/:gid', (req, res) => {
  const eid = getRequestingEid(req);
  const g = ensureGroupForEid(req.params.gid, req.params.appId, eid);
  Object.assign(g, req.body);
  console.log(`         ✓ group UPDATE → gid=${req.params.gid}`);
  res.json(groupResponse(g));
});

// group delete (or list) — /iot/api/v2/group/{gid}
app.get('/iot/api/v2/group/:gid', (req, res) => {
  const g = ensureGroup(req.params.gid);
  res.json({ ...g, eids: Array.from(g.eids) });
});
app.delete('/iot/api/v2/group/:gid', (req, res) => {
  delete state.groups[req.params.gid];
  res.json({ ok: true });
});

// group rekey — POST /iot/api/v2/group/rekey/{appId}/{gid}
app.post('/iot/api/v2/group/rekey/:appId/:gid', (req, res) => {
  const g = ensureGroup(req.params.gid, req.params.appId);
  const newKey = {
    gid: req.params.gid,
    key: crypto.randomBytes(32).toString('base64'),
    expires: 0,
    effective: 0,
    createdAt: new Date().toISOString(),
  };
  g.symmetricKeys = [newKey, ...g.symmetricKeys];
  console.log(`         ✓ group REKEY → gid=${req.params.gid}`);
  res.json({ ok: true, key: newKey });
});

// group pubkeys — GET /iot/api/v2/group/pubkeys/{appId}/{gid}
app.get('/iot/api/v2/group/pubkeys/:appId/:gid', (req, res) => {
  const g = ensureGroup(req.params.gid, req.params.appId);
  // Return pubkeys for all members (mocked)
  const members = Array.from(g.eids).map(eid => ({
    eid,
    publicKey: state.endpoints[eid]?.publicKey || 'mock-pubkey',
  }));
  res.json({ members });
});

// invite/add member — POST /iot/api/v2/group/{appId}/{gid}/{eid}
app.post('/iot/api/v2/group/:appId/:gid/:eid', (req, res) => {
  const g = ensureGroup(req.params.gid, req.params.appId);
  g.eids.add(req.params.eid);
  console.log(`         ★ group ADD member → gid=${req.params.gid} eid=${req.params.eid} count=${g.eids.size}`);
  res.json({ ok: true, member_count: g.eids.size });
});

// message storage — POST /iot/api/v2/service/message/storage/{gid}
app.post('/iot/api/v2/service/message/storage/:gid', (req, res) => {
  console.log(`         ✓ message storage init → gid=${req.params.gid}`);
  res.json({ ok: true, size: req.query.size || 1024, expires: req.query.expires || 3600 });
});

// ═══════════════════════════════════════════════════════════════════
// PHASE 3 — Rendezvous (the QR-driven pairing handshake)
// ═══════════════════════════════════════════════════════════════════

// Box creates the rendezvous
app.post('/iot/api/v2/ept/rendezvous/:rid', (req, res) => {
  state.rendezvous[req.params.rid] = {
    boxPayload: req.body,
    appPayload: null,
    createdAt: Date.now(),
    expiresAt: Date.now() + 1800 * 1000,
  };
  console.log(`         ✓ rendezvous CREATE → rid=${req.params.rid}`);
  res.json({ ok: true, ttl: 1800 });
});

// Anyone fetches the rendezvous (poll loop)
app.get('/iot/api/v2/ept/rendezvous/:rid', (req, res) => {
  const r = state.rendezvous[req.params.rid];
  // If app has posted an invite, return it (so box's poll picks it up)
  if (r && r.appPayload) {
    console.log(`         ★ rendezvous GET → rid=${req.params.rid} returning APP PAYLOAD!`);
    return res.json(r.appPayload);
  }
  // No app yet — return 404, box's poll loop handles this gracefully (matches real cloud behavior)
  res.status(404).json({ error: 'not found' });
});

// App posts its invite to rendezvous (this is the magic step!)
// Auto-create the rendezvous slot if it doesn't exist (so the app can pair without
// the box ever explicitly creating one).
app.post('/iot/api/v2/ept/rendezvous/:rid/invite', (req, res) => {
  if (!state.rendezvous[req.params.rid]) {
    state.rendezvous[req.params.rid] = {
      boxPayload: null,
      appPayload: null,
      createdAt: Date.now(),
      expiresAt: Date.now() + 1800 * 1000,
    };
  }
  state.rendezvous[req.params.rid].appPayload = req.body;
  console.log(`         ★ rendezvous INVITE → rid=${req.params.rid} APP HAS POSTED!`);
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════════════════
// PHASE 4 — Add app to group
// ═══════════════════════════════════════════════════════════════════
app.post('/iot/api/v2/group/:gid/:eid', (req, res) => {
  const g = state.groups[req.params.gid];
  if (!g) return res.status(404).json({ error: 'group not found' });
  g.eids.add(req.params.eid);
  console.log(`         ★ group MEMBER ADD → gid=${req.params.gid} eid=${req.params.eid}  count=${g.eids.size}`);
  res.json({ ok: true, member_count: g.eids.size });
});

// Remove member
app.delete('/iot/api/v2/group/:gid/:eid', (req, res) => {
  const g = state.groups[req.params.gid];
  if (!g) return res.status(404).json({ error: 'group not found' });
  g.eids.delete(req.params.eid);
  res.json({ ok: true, member_count: g.eids.size });
});

// ═══════════════════════════════════════════════════════════════════
// PHASE 5 — Encrypted message relay (post-pairing)
// ═══════════════════════════════════════════════════════════════════
app.post('/iot/api/v2/service/message/:appId/:gid/eptgroup/:peer', (req, res) => {
  const msg = {
    ts: Date.now(),
    mid: uuid(),
    gid: req.params.gid,
    peer: req.params.peer,
    payload: req.body,
  };
  state.messages.push(msg);
  // Cap memory
  if (state.messages.length > 1000) state.messages = state.messages.slice(-500);
  console.log(`         ✓ message RELAY → gid=${req.params.gid} → ${req.params.peer}`);
  res.json({ ok: true, mid: msg.mid });
});

app.get('/iot/api/v2/service/message/:appId/:gid/eptgroup/:peer', (req, res) => {
  const since = parseInt(req.query.since) || 0;
  const limit = parseInt(req.query.count) || 100;
  const msgs = state.messages
    .filter(m => m.ts > since && m.peer === req.params.peer)
    .slice(0, limit);
  res.json({ messages: msgs });
});

// ═══════════════════════════════════════════════════════════════════
// BONE API — Box telemetry / check-in
// ═══════════════════════════════════════════════════════════════════
app.post('/bone/api/v3/sys/checkin', (req, res) => {
  const mac = normalizeMac((req.body && req.body.mac) || 'unknown');
  state.checkins.push({ ts: Date.now(), mac, payload: req.body });
  if (state.checkins.length > 100) state.checkins = state.checkins.slice(-50);

  // Update last_seen on the authorized_macs record (for online/offline tracking)
  if (state.authorized_macs[mac]) {
    state.authorized_macs[mac].last_seen = Date.now();
    state.authorized_macs[mac].last_ip = req.ip;
  }

  console.log(`         ✓ bone CHECKIN ← MAC=${mac}`);
  res.json({
    status: 200,
    needUpgrade: false,
    jwt: fakeJwt({ iss: 'mock-bone', mac, iat: Math.floor(Date.now() / 1000) }),
    config: {},
  });
});

// Bone intel + device + flowgraph stubs (so the box doesn't error on these)
app.post('/bone/api/v3/intel/host/:ip/:action', (req, res) => {
  res.json({ class: 'unknown', threat: 0 });
});
app.post('/bone/api/v3/intel/feedback/', (req, res) => {
  res.json({ ok: true });
});
app.get('/bone/api/v3/intel/finger/:target', (req, res) => {
  res.json({ result: 'ok' });
});
app.post('/bone/api/v3/intel/advice', (req, res) => {
  res.json({ advice: [] });
});
app.post('/bone/api/v3/intel/checkmember', (req, res) => {
  res.json({ member: false });
});
app.get('/bone/api/v3/intel/hashset/:hashsetid', (req, res) => {
  res.json({ data: [] });
});
app.post('/bone/api/v3/device/:cmd', (req, res) => {
  console.log(`         ✓ bone device cmd → ${req.params.cmd}`);
  res.json({ ok: true });
});
app.post('/bone/api/v3/device/log/:cmd', (req, res) => {
  res.json({ ok: true });
});
app.post('/bone/api/v3/flowgraph/:action', (req, res) => {
  res.json({ ok: true, action: req.params.action });
});
app.post('/bone/api/v3/finger/arbitration', (req, res) => {
  res.json({ ok: true });
});
app.post('/bone/api/v3/cloud/actionCallback', (req, res) => {
  res.json({ ok: true });
});
app.get('/bone/api/v3/service/config', (req, res) => {
  res.json({});
});

// ═══════════════════════════════════════════════════════════════════
// LICENSE API — Issue an Ed25519-signed license for an authorized MAC
// ═══════════════════════════════════════════════════════════════════
function normalizeMac(m) {
  return (m || '').toLowerCase().replace(/[^a-f0-9]/g, '').match(/.{1,2}/g)?.join(':') || m;
}

app.get('/license/api/v1/license/issue/:luid', (req, res) => {
  const macRaw = req.query.mac || 'unknown';
  const mac = normalizeMac(macRaw);
  const auth = state.authorized_macs[mac];

  if (!auth) {
    console.log(`         ✗ license DENIED → MAC=${mac} (not authorized)`);
    return res.status(403).json({
      error: 'mac not authorized',
      mac,
      hint: 'Authorize this MAC via POST /admin/api/macs/authorize first',
    });
  }

  // Re-issue the same license if already issued (idempotent)
  if (state.issued_licenses[mac]) {
    console.log(`         ✓ license REISSUE → MAC=${mac}`);
    return res.json(state.issued_licenses[mac]);
  }

  const data = {
    UUID: uuid(),
    SUUID: shortId(8),
    MAC: mac,
    EID: auth.eid || ('mes-' + shortId(10)),
    LICENSE: crypto.randomBytes(16).toString('hex'),
    LUID: req.params.luid,
    TYPE: auth.type || 'navy',
    CUSTOMER: auth.customer_name || '',
    ISSUED_AT: new Date().toISOString(),
    ISSUER: 'mes-cloud',
  };

  const license = {
    DATA: data,
    SIGN: signLicense(data),
  };
  state.issued_licenses[mac] = license;
  state.licenses[mac] = license;  // back-compat with old field name
  console.log(`         ✓ license ISSUE → MAC=${mac} customer=${data.CUSTOMER || '(none)'}`);
  fireWebhooks('license.issued', { mac, customer: data.CUSTOMER, uuid: data.UUID });
  res.json(license);
});

// Public: get the license-server's Ed25519 public key (for boxes/clients to verify)
app.get('/license/api/v1/pubkey', (req, res) => {
  res.type('text/plain').send(licenseKeys ? licenseKeys.pubPem : 'no key');
});

// ═══════════════════════════════════════════════════════════════════
// STATUS / HEALTH
// ═══════════════════════════════════════════════════════════════════

// Prometheus /metrics — standard exposition format
app.get('/metrics', (req, res) => {
  const ONLINE_THRESHOLD_MS = 30 * 60 * 1000;
  const now = Date.now();
  const onlineBoxes = Object.values(state.authorized_macs).filter(m => m.last_seen && (now - m.last_seen < ONLINE_THRESHOLD_MS)).length;
  const totalBoxes = Object.keys(state.authorized_macs).length;
  const customers = Object.values(state.customers);
  const customersByStatus = {};
  for (const c of customers) {
    const s = c.status || 'active';
    customersByStatus[s] = (customersByStatus[s] || 0) + 1;
  }
  const customersByPlan = {};
  for (const c of customers) {
    customersByPlan[c.plan || 'unknown'] = (customersByPlan[c.plan || 'unknown'] || 0) + 1;
  }
  const checkins24h = state.checkins.filter(c => Date.now() - c.ts < 86400000).length;
  const events24h = state.events.filter(e => Date.now() - e.ts < 86400000).length;
  const invoicesPaid = Object.values(state.invoices).filter(i => i.status === 'paid').length;
  const invoicesUnpaid = Object.values(state.invoices).filter(i => i.status !== 'paid').length;

  const lines = [];
  const m = (name, help, type, value, labels) => {
    lines.push(`# HELP ${name} ${help}`);
    lines.push(`# TYPE ${name} ${type}`);
    if (Array.isArray(value)) {
      for (const [labelStr, v] of value) lines.push(`${name}{${labelStr}} ${v}`);
    } else {
      lines.push(`${name} ${value}`);
    }
  };

  m('mes_cloud_uptime_seconds', 'Process uptime', 'gauge', Math.round(process.uptime()));
  m('mes_cloud_customers_total', 'Total customers', 'gauge', customers.length);
  m('mes_cloud_customers_by_status', 'Customers by status', 'gauge',
    Object.entries(customersByStatus).map(([s, n]) => [`status="${s}"`, n]));
  m('mes_cloud_customers_by_plan', 'Customers by plan', 'gauge',
    Object.entries(customersByPlan).map(([p, n]) => [`plan="${p}"`, n]));
  m('mes_cloud_boxes_total', 'Total authorized boxes', 'gauge', totalBoxes);
  m('mes_cloud_boxes_online', 'Boxes online (last seen <30 min)', 'gauge', onlineBoxes);
  m('mes_cloud_licenses_issued', 'Total issued licenses', 'gauge', Object.keys(state.issued_licenses).length);
  m('mes_cloud_checkins_24h', 'Box check-ins in last 24 hours', 'gauge', checkins24h);
  m('mes_cloud_events_24h', 'Recorded events in last 24 hours', 'gauge', events24h);
  m('mes_cloud_invoices_paid', 'Paid invoices', 'gauge', invoicesPaid);
  m('mes_cloud_invoices_unpaid', 'Unpaid invoices', 'gauge', invoicesUnpaid);
  m('mes_cloud_webhook_queue_length', 'Pending webhook deliveries', 'gauge', state.webhook_queue.length);
  m('mes_cloud_push_subscriptions', 'Active Web Push subscriptions', 'gauge',
    Object.values(state.push_subscriptions).reduce((n, arr) => n + arr.length, 0));
  m('mes_cloud_pending_customers', 'Customers awaiting approval', 'gauge',
    customers.filter(c => c.status === 'pending').length);
  m('mes_cloud_admins', 'Sub-admin users', 'gauge', Object.keys(state.admins).length);
  m('mes_cloud_api_keys', 'Active API keys', 'gauge',
    Object.values(state.api_keys).filter(k => k.active !== false).length);
  m('mes_cloud_firmwares', 'Firmware versions stored', 'gauge', Object.keys(state.firmwares).length);
  // Process metrics
  const mem = process.memoryUsage();
  m('mes_cloud_process_rss_bytes', 'Resident set size', 'gauge', mem.rss);
  m('mes_cloud_process_heap_used_bytes', 'Heap used', 'gauge', mem.heapUsed);
  m('mes_cloud_process_heap_total_bytes', 'Heap total', 'gauge', mem.heapTotal);

  res.set('Content-Type', 'text/plain; version=0.0.4');
  res.send(lines.join('\n') + '\n');
});

// PUBLIC: VAPID public key (PWA needs this to subscribe)
app.get('/api/vapid-public-key', (req, res) => {
  res.json({
    public_key: urlBase64(vapidPubBytes()),
    public_key_pem: vapidKeys ? vapidKeys.publicKey.export({ type: 'spki', format: 'pem' }) : '',
  });
});

// Customer subscribes a Web Push subscription (called from the PWA after permission)
app.post('/api/customer/push/subscribe', customerAuth, (req, res) => {
  const c = req.customer;
  const sub = req.body.subscription;
  if (!sub || !sub.endpoint || !sub.keys || !sub.keys.p256dh || !sub.keys.auth) {
    return res.status(400).json({ error: 'invalid subscription — must include endpoint + keys.{p256dh,auth}' });
  }
  if (!state.push_subscriptions[c.id]) state.push_subscriptions[c.id] = [];
  // Replace any subscription with the same endpoint
  state.push_subscriptions[c.id] = state.push_subscriptions[c.id].filter(s => s.endpoint !== sub.endpoint);
  const stored = {
    id: 'push-' + shortId(8),
    endpoint: sub.endpoint,
    keys: { p256dh: sub.keys.p256dh, auth: sub.keys.auth },
    ua: req.headers['user-agent'] || '',
    created_at: new Date().toISOString(),
  };
  state.push_subscriptions[c.id].push(stored);
  saveState();
  console.log(`         🔔 push SUBSCRIBE → ${c.name}  endpoint=${sub.endpoint.slice(0, 60)}…`);
  res.json({ ok: true, subscription_id: stored.id });
});

app.post('/api/customer/push/unsubscribe', customerAuth, (req, res) => {
  const c = req.customer;
  state.push_subscriptions[c.id] = (state.push_subscriptions[c.id] || []).filter(s => s.endpoint !== req.body.endpoint);
  saveState();
  res.json({ ok: true });
});

app.post('/api/customer/push/test', customerAuth, (req, res) => {
  pushNotification(req.customer.id, 'info', '🔔 Test notification',
    'This is a test push. If you saw a notification on your device, Web Push is working.');
  res.json({ ok: true });
});

// PUBLIC: branding config (used by PWA + status page)
// Multi-tenant: lookup tenant by request host or query param
function tenantForRequest(req) {
  const host = (req.query && req.query.host) || (req.headers && req.headers.host) || '';
  const cleanHost = host.split(':')[0].toLowerCase();
  // Direct match: tenant.brand_domain or any of its aliases
  if (state.tenants) {
    for (const t of Object.values(state.tenants)) {
      if (!t) continue;
      if (t.brand_domain === cleanHost) return t;
      if (Array.isArray(t.aliases) && t.aliases.includes(cleanHost)) return t;
    }
  }
  return null;
}
function effectiveBranding(tenant) {
  const fallback = state.config || {};
  const t = tenant || {};
  return {
    tenant_id:   t.id || null,
    brand_name:  t.brand_name  || fallback.brand_name  || 'mes Network',
    brand_color: t.brand_color || fallback.brand_color || '#ff8c42',
    brand_accent: t.brand_accent || fallback.brand_accent || '#3ad29f',
    brand_logo_url: t.brand_logo_url || fallback.brand_logo_url || '',
    brand_support_phone: t.brand_support_phone || fallback.brand_support_phone || '',
    brand_domain: t.brand_domain || fallback.brand_domain || '',
  };
}

app.get('/api/branding', (req, res) => {
  res.json(effectiveBranding(tenantForRequest(req)));
});

// ─── Tenants (admin CRUD; super-admin only) ───
if (!state.tenants) state.tenants = {};
app.get('/admin/api/tenants', adminAuth, (req, res) => {
  const tenants = Object.values(state.tenants).map(t => {
    const customer_count = Object.values(state.customers).filter(c => c.tenant_id === t.id).length;
    return { ...t, customer_count };
  });
  res.json({ tenants });
});
app.post('/admin/api/tenants/create', adminAuth, (req, res) => {
  if (req.adminRole && req.adminRole !== 'super') return res.status(403).json({ error: 'super-admin only' });
  const id = 'tenant-' + shortId(8);
  const t = {
    id,
    name: String(req.body.name || 'New Tenant').slice(0, 80),
    brand_name: String(req.body.brand_name || req.body.name || '').slice(0, 80),
    brand_color: req.body.brand_color || '#ff8c42',
    brand_accent: req.body.brand_accent || '#3ad29f',
    brand_logo_url: req.body.brand_logo_url || '',
    brand_support_phone: req.body.brand_support_phone || '',
    brand_domain: String(req.body.brand_domain || '').toLowerCase(),
    aliases: Array.isArray(req.body.aliases) ? req.body.aliases.map(s => String(s).toLowerCase()) : [],
    owner_email: req.body.owner_email || '',
    // Resource caps (0 = unlimited)
    max_customers: parseInt(req.body.max_customers) || 0,
    max_boxes:     parseInt(req.body.max_boxes)     || 0,
    max_storage_gb: parseInt(req.body.max_storage_gb) || 0,
    created_at: Date.now(),
  };
  state.tenants[id] = t;
  saveState();
  logAdminAction(req, 'tenant.create', id, t.name);
  res.json({ ok: true, tenant: t });
});
app.post('/admin/api/tenants/update', adminAuth, (req, res) => {
  if (req.adminRole && req.adminRole !== 'super') return res.status(403).json({ error: 'super-admin only' });
  const t = state.tenants[req.body.id];
  if (!t) return res.status(404).json({ error: 'not found' });
  for (const k of ['name','brand_name','brand_color','brand_accent','brand_logo_url','brand_support_phone','brand_domain','owner_email']) {
    if (req.body[k] !== undefined) t[k] = String(req.body[k]).slice(0, 200);
  }
  if (Array.isArray(req.body.aliases)) t.aliases = req.body.aliases.map(s => String(s).toLowerCase());
  // Resource caps (0 = unlimited)
  for (const k of ['max_customers','max_boxes','max_storage_gb']) {
    if (req.body[k] !== undefined) t[k] = parseInt(req.body[k]) || 0;
  }
  // Landing page overrides
  for (const k of ['landing_hero_title','landing_hero_sub','landing_cta_text','landing_video_url']) {
    if (req.body[k] !== undefined) t[k] = String(req.body[k]).slice(0, 500);
  }
  saveState();
  logAdminAction(req, 'tenant.update', t.id, t.name);
  res.json({ ok: true, tenant: t });
});
app.post('/admin/api/tenants/delete', adminAuth, (req, res) => {
  if (req.adminRole && req.adminRole !== 'super') return res.status(403).json({ error: 'super-admin only' });
  const t = state.tenants[req.body.id];
  if (!t) return res.status(404).json({ error: 'not found' });
  // Don't actually delete if customers are bound
  const bound = Object.values(state.customers).filter(c => c.tenant_id === t.id).length;
  if (bound > 0) return res.status(409).json({ error: 'has_customers', count: bound });
  delete state.tenants[req.body.id];
  saveState();
  logAdminAction(req, 'tenant.delete', t.id);
  res.json({ ok: true });
});
// Tenant resource usage (admin-only)
app.get('/admin/api/tenants/:id/usage', adminAuth, (req, res) => {
  const t = state.tenants[req.params.id];
  if (!t) return res.status(404).json({ error: 'not found' });
  const myCustomers = Object.values(state.customers).filter(c => c.tenant_id === t.id && !c.demo);
  const myMacs = Object.values(state.authorized_macs).filter(m => myCustomers.some(c => c.id === m.customer_id));
  res.json({
    tenant_id: t.id,
    name: t.name,
    caps: {
      max_customers: t.max_customers,
      max_boxes: t.max_boxes,
      max_storage_gb: t.max_storage_gb,
    },
    usage: {
      customers: myCustomers.length,
      boxes: myMacs.length,
      // storage is a rough estimate
      flows_count: state.flows.filter(f => myCustomers.some(c => c.id === f.customer_id)).length,
    },
    over_limit: {
      customers: t.max_customers > 0 && myCustomers.length >= t.max_customers,
      boxes: t.max_boxes > 0 && myMacs.length >= t.max_boxes,
    },
  });
});

// Helper to call from signup before creating
function tenantCapAllowsNewCustomer(tenantId) {
  if (!tenantId) return true;   // default tenant = unlimited
  const t = state.tenants[tenantId];
  if (!t || !t.max_customers) return true;
  const cur = Object.values(state.customers).filter(c => c.tenant_id === tenantId && !c.demo).length;
  return cur < t.max_customers;
}

app.post('/admin/api/tenants/assign-customer', adminAuth, (req, res) => {
  const t = state.tenants[req.body.tenant_id];
  const c = state.customers[req.body.customer_id];
  if (!t || !c) return res.status(404).json({ error: 'tenant or customer not found' });
  c.tenant_id = t.id;
  saveState();
  res.json({ ok: true });
});

// API documentation — public, lists endpoints + auth model
app.get('/api/docs', (req, res) => {
  const html = `<!DOCTYPE html>
<html><head>
<meta charset="UTF-8"><title>mes Cloud — API Reference</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body { font-family: -apple-system, system-ui, sans-serif; margin:0; background:#0f1419; color:#e3e9f0; }
.wrap { max-width: 920px; margin: 0 auto; padding: 28px 22px; }
h1 { color:#ff8c42; margin: 0 0 4px 0; }
h2 { color:#3ad29f; border-bottom: 1px solid #2a3340; padding-bottom: 6px; margin-top: 30px; }
h3 { color:#e3e9f0; font-size: 1em; margin: 14px 0 6px 0; }
.sub { color:#6c7686; margin-bottom: 22px; font-size: .9em; }
.method { display:inline-block; padding:2px 8px; border-radius:4px; font-size:.7em; font-family: monospace; font-weight:600; margin-right:6px; vertical-align: middle; }
.GET { background:#1f4f3d; color:#3ad29f; }
.POST { background:#3a3520; color:#ff8c42; }
.PUT, .DELETE { background:#4a2020; color:#ff5c5c; }
.path { font-family: 'SF Mono', Menlo, monospace; color:#fff; font-size:.9em; }
.endpoint { background:#1a2028; border-left: 3px solid #2a3340; padding: 10px 14px; margin: 6px 0; border-radius: 4px; }
.endpoint.public { border-left-color:#3ad29f; }
.endpoint.cust { border-left-color:#5a8cdc; }
.endpoint.admin { border-left-color:#ff8c42; }
.endpoint .desc { color:#8aa0c0; font-size:.85em; margin-top:4px; }
.auth-pill { display:inline-block; padding:1px 6px; border-radius:3px; font-size:.7em; margin-${'inline-start'}:8px; vertical-align:middle; }
.auth-pill.basic { background:#3a3520; color:#ff8c42; }
.auth-pill.bearer { background:#1f3a5e; color:#5a8cdc; }
.auth-pill.public { background:#1f4f3d; color:#3ad29f; }
pre { background:#0f1419; border:1px solid #2a3340; border-radius:6px; padding:12px; overflow-x:auto; font-size:.85em; }
code { font-family: monospace; color:#3ad29f; }
.toc { background:#1a2028; padding: 14px 18px; border-radius:8px; margin: 14px 0; font-size:.9em; }
.toc a { color:#3ad29f; text-decoration:none; margin-${'inline-end'}:14px; }
</style>
</head><body>
<div class="wrap">
  <h1>📡 mes Cloud — API Reference</h1>
  <p class="sub">Base URL: <code>https://cloud.mes.net.lb</code> · Generated: ${new Date().toISOString()}</p>

  <div class="toc">
    <a href="#public">Public</a>
    <a href="#customer">Customer (Bearer JWT)</a>
    <a href="#admin">Admin (Basic auth)</a>
    <a href="#box">Box-facing (encipher protocol)</a>
    <a href="#webhooks">Webhooks</a>
  </div>

  <h2 id="public">Public endpoints (no auth)</h2>
  <div class="endpoint public"><span class="method GET">GET</span><span class="path">/health</span><span class="auth-pill public">public</span><div class="desc">Returns <code>ok</code>. Use for monitoring.</div></div>
  <div class="endpoint public"><span class="method GET">GET</span><span class="path">/status</span><span class="auth-pill public">public</span><div class="desc">Public status page (HTML) — boxes online, active customers, uptime.</div></div>
  <div class="endpoint public"><span class="method GET">GET</span><span class="path">/license/api/v1/pubkey</span><span class="auth-pill public">public</span><div class="desc">Returns the cloud's Ed25519 public key (PEM). Use it to verify license signatures.</div></div>
  <div class="endpoint public"><span class="method GET">GET</span><span class="path">/api/docs</span><span class="auth-pill public">public</span><div class="desc">This page.</div></div>

  <h2 id="customer">Customer endpoints <small style="font-weight:normal;color:#6c7686;">(Bearer JWT — get from /verify)</small></h2>
  <h3>Auth flow</h3>
  <div class="endpoint cust"><span class="method POST">POST</span><span class="path">/api/customer/signup</span><span class="auth-pill public">public</span><div class="desc">Register. Body: <code>{name, phone, email?, plan?, address?}</code> → status <code>pending</code> or <code>active</code>.</div></div>
  <div class="endpoint cust"><span class="method POST">POST</span><span class="path">/api/customer/login</span><span class="auth-pill public">public</span><div class="desc">Send OTP. Body: <code>{phone}</code>. Rate-limited (5 fails / 10 min / IP).</div></div>
  <div class="endpoint cust"><span class="method POST">POST</span><span class="path">/api/customer/verify</span><span class="auth-pill public">public</span><div class="desc">Verify OTP. Body: <code>{phone, code}</code>. Demo OTP = <code>0000</code>. Returns <code>{token, customer}</code>.</div></div>

  <h3>Profile + boxes</h3>
  <div class="endpoint cust"><span class="method GET">GET</span><span class="path">/api/customer/me</span><span class="auth-pill bearer">bearer</span><div class="desc">Customer profile + assigned boxes.</div></div>
  <div class="endpoint cust"><span class="method GET">GET</span><span class="path">/api/customer/devices</span><span class="auth-pill bearer">bearer</span><div class="desc">Devices on customer's network with 24h usage sparklines.</div></div>
  <div class="endpoint cust"><span class="method POST">POST</span><span class="path">/api/customer/device/assign</span><span class="auth-pill bearer">bearer</span><div class="desc">Body: <code>{mac, family_id?}</code>. Assign a device to a family member.</div></div>

  <h3>Family + schedules</h3>
  <div class="endpoint cust"><span class="method GET">GET</span><span class="path">/api/customer/family</span><span class="auth-pill bearer">bearer</span><div class="desc">List family members.</div></div>
  <div class="endpoint cust"><span class="method POST">POST</span><span class="path">/api/customer/family/{add|update|delete}</span><span class="auth-pill bearer">bearer</span><div class="desc">Manage family members.</div></div>
  <div class="endpoint cust"><span class="method GET">GET</span><span class="path">/api/customer/schedules</span><span class="auth-pill bearer">bearer</span><div class="desc">List schedule blocks.</div></div>
  <div class="endpoint cust"><span class="method POST">POST</span><span class="path">/api/customer/schedules/{add|update|delete}</span><span class="auth-pill bearer">bearer</span><div class="desc">Manage schedule blocks.</div></div>

  <h3>Actions</h3>
  <div class="endpoint cust"><span class="method POST">POST</span><span class="path">/api/customer/pause</span><span class="auth-pill bearer">bearer</span><div class="desc">Body: <code>{duration_min}</code>. Pause internet temporarily.</div></div>
  <div class="endpoint cust"><span class="method POST">POST</span><span class="path">/api/customer/box/action</span><span class="auth-pill bearer">bearer</span><div class="desc">Body: <code>{action: "reboot"|"speedtest"|"status"|"restart-services"}</code>.</div></div>
  <div class="endpoint cust"><span class="method GET">GET</span><span class="path">/api/customer/vpn</span><span class="auth-pill bearer">bearer</span><div class="desc">Download <code>.ovpn</code> config (per-customer).</div></div>
  <div class="endpoint cust"><span class="method GET">GET</span><span class="path">/api/customer/report</span><span class="auth-pill bearer">bearer</span><div class="desc">Monthly usage report (printable HTML).</div></div>
  <div class="endpoint cust"><span class="method GET">GET</span><span class="path">/api/customer/notifications</span><span class="auth-pill bearer">bearer</span><div class="desc">Customer's in-app notifications.</div></div>
  <div class="endpoint cust"><span class="method GET">GET</span><span class="path">/api/customer/activity</span><span class="auth-pill bearer">bearer</span><div class="desc">Customer's own action log.</div></div>
  <div class="endpoint cust"><span class="method GET">GET</span><span class="path">/api/customer/support</span><span class="auth-pill bearer">bearer</span><div class="desc">Support chat thread.</div></div>
  <div class="endpoint cust"><span class="method POST">POST</span><span class="path">/api/customer/support</span><span class="auth-pill bearer">bearer</span><div class="desc">Body: <code>{body}</code>. Send a support message to the admin team.</div></div>

  <h2 id="admin">Admin endpoints <small style="font-weight:normal;color:#6c7686;">(HTTP Basic auth)</small></h2>
  <div class="endpoint admin"><span class="method GET">GET</span><span class="path">/admin</span><span class="auth-pill basic">basic</span><div class="desc">Admin dashboard (HTML).</div></div>
  <div class="endpoint admin"><span class="method GET">GET</span><span class="path">/admin/api/state</span><span class="auth-pill basic">basic</span><div class="desc">Live JSON of everything (counts, customers, boxes, events).</div></div>
  <div class="endpoint admin"><span class="method GET">GET</span><span class="path">/admin/api/sysmetrics</span><span class="auth-pill basic">basic</span><div class="desc">Memory / load / disk / uptime.</div></div>
  <div class="endpoint admin"><span class="method GET">GET</span><span class="path">/admin/api/audit</span><span class="auth-pill basic">basic</span><div class="desc">Last 100 admin actions.</div></div>

  <h3>Customers</h3>
  <div class="endpoint admin"><span class="method POST">POST</span><span class="path">/admin/api/customers/{create|update|delete|set-status|assign-box|bulk-import}</span><span class="auth-pill basic">basic</span><div class="desc">Customer CRUD.</div></div>
  <div class="endpoint admin"><span class="method GET">GET</span><span class="path">/admin/api/export/{customers|events|licenses}.csv</span><span class="auth-pill basic">basic</span><div class="desc">CSV exports.</div></div>

  <h3>License management</h3>
  <div class="endpoint admin"><span class="method POST">POST</span><span class="path">/admin/api/macs/{authorize|revoke}</span><span class="auth-pill basic">basic</span><div class="desc">Manage authorized MACs.</div></div>

  <h3>Multi-admin</h3>
  <div class="endpoint admin"><span class="method GET">GET</span><span class="path">/admin/api/admins</span><span class="auth-pill basic">basic</span><div class="desc">List all admins.</div></div>
  <div class="endpoint admin"><span class="method POST">POST</span><span class="path">/admin/api/admins/{create|update|delete}</span><span class="auth-pill basic">basic</span><div class="desc">Manage admin users (super-admin only).</div></div>

  <h3>Webhooks</h3>
  <div class="endpoint admin"><span class="method GET">GET</span><span class="path">/admin/api/webhooks</span><span class="auth-pill basic">basic</span><div class="desc">List configured webhooks.</div></div>
  <div class="endpoint admin"><span class="method POST">POST</span><span class="path">/admin/api/webhooks</span><span class="auth-pill basic">basic</span><div class="desc">Body: <code>{name, url, events: ["*"|"customer.signup"|...]}</code>.</div></div>

  <h3>Backup / restore</h3>
  <div class="endpoint admin"><span class="method GET">GET</span><span class="path">/admin/api/backup</span><span class="auth-pill basic">basic</span><div class="desc">Download full backup (state + Ed25519 keys).</div></div>
  <div class="endpoint admin"><span class="method POST">POST</span><span class="path">/admin/api/restore</span><span class="auth-pill basic">basic</span><div class="desc">Upload backup JSON to restore.</div></div>

  <h2 id="box">Box-facing (encipher protocol)</h2>
  <div class="endpoint"><span class="method POST">POST</span><span class="path">/iot/api/v2/login/eptoken</span><div class="desc">Box authenticates with RSA pubkey + license.</div></div>
  <div class="endpoint"><span class="method GET">GET</span><span class="path">/iot/api/v2/group/:appId/:gid</span><div class="desc">groupFind — auto-creates if not exists.</div></div>
  <div class="endpoint"><span class="method GET">GET</span><span class="path">/iot/api/v2/ept/rendezvous/:rid</span><div class="desc">Pairing rendezvous poll.</div></div>
  <div class="endpoint"><span class="method POST">POST</span><span class="path">/bone/api/v3/sys/checkin</span><div class="desc">Box telemetry heartbeat.</div></div>
  <div class="endpoint"><span class="method GET">GET</span><span class="path">/license/api/v1/license/issue/:luid?mac=&serial=</span><div class="desc">Box requests its Ed25519-signed license.</div></div>

  <h2 id="webhooks">Webhook events</h2>
  <p style="color:#8aa0c0;font-size:.9em">Configure URLs in admin → "Webhooks". Each event POSTs JSON: <code>{event, ts, payload}</code>. If the webhook has a secret, the body is signed with HMAC-SHA256 in the <code>X-MES-Signature</code> header (format <code>sha256=&lt;hex&gt;</code>).</p>
  <ul style="color:#8aa0c0;font-size:.9em">
    <li><code>customer.signup</code> — new customer registered</li>
    <li><code>customer.status_changed</code> — admin approved/suspended a customer</li>
    <li><code>mac.authorized</code> — admin authorized a new MAC</li>
    <li><code>license.issued</code> — license was minted for a box</li>
    <li><code>customers.bulk_import</code> — bulk import completed</li>
    <li><code>test.ping</code> — manual test</li>
    <li><code>*</code> — receive all events</li>
  </ul>

  <h2>Bearer-token shape (Customer JWT)</h2>
  <pre>HEADER: { "alg":"EdDSA","typ":"JWT" }
PAYLOAD: { "sub":"cust-xxx","name":"...","phone":"...","plan":"...","iat":...,"exp":... }
SIGNATURE: Ed25519 over header.payload (raw form, base64url)</pre>
  <p style="color:#8aa0c0;font-size:.9em">Verify with the public key from <code>/license/api/v1/pubkey</code>.</p>

</div>
</body></html>`;
  res.type('html').send(html);
});

// Public status page (no auth) — for customers/world to see
// Embeddable status badge (SVG) — for tenants to put on their own marketing site.
// Usage: <img src="https://cloud.mes.net.lb/status-badge/<tenant>.svg" alt="status">
app.get('/status-badge/:tenant_slug.svg', (req, res) => {
  const slug = req.params.tenant_slug.toLowerCase();
  let tenant = null;
  if (state.tenants) {
    tenant = Object.values(state.tenants).find(t => t.brand_domain === slug || t.id === slug || (t.aliases||[]).includes(slug));
  }
  let label = 'mes Network', pct = null, color = '#6c7686', text = 'unknown';
  if (tenant) {
    label = tenant.brand_name || tenant.name;
    const tenantCustomerIds = new Set(Object.values(state.customers).filter(c => c.tenant_id === tenant.id).map(c => c.id));
    const myMacs = Object.values(state.authorized_macs).filter(m => tenantCustomerIds.has(m.customer_id));
    const onlineCount = myMacs.filter(m => {
      const s = state.box_state[m.mac];
      return s && s.last_heartbeat && (Date.now() - s.last_heartbeat) < 5*60_000;
    }).length;
    if (myMacs.length > 0) {
      pct = Math.round((onlineCount / myMacs.length) * 100);
      color = pct >= 95 ? '#3ad29f' : (pct >= 75 ? '#ffb84a' : '#ff5c5c');
      text = pct + '% online';
    } else {
      text = 'no boxes yet';
      color = '#3ad29f';
    }
  }
  res.set('Content-Type', 'image/svg+xml');
  res.set('Cache-Control', 'public, max-age=60');
  // shields.io-style pill badge
  const labelW = label.length * 6 + 14, valueW = text.length * 6 + 14;
  const total = labelW + valueW;
  res.send(`<svg xmlns="http://www.w3.org/2000/svg" width="${total}" height="20" role="img" aria-label="${label}: ${text}">
<linearGradient id="g" x2="0" y2="100%"><stop offset="0" stop-color="#fff" stop-opacity=".05"/><stop offset="1" stop-opacity=".15"/></linearGradient>
<rect width="${total}" height="20" rx="3" fill="#444"/>
<rect x="${labelW}" width="${valueW}" height="20" rx="3" fill="${color}"/>
<rect width="${total}" height="20" rx="3" fill="url(#g)"/>
<g fill="#fff" font-family="Verdana,sans-serif" font-size="11">
<text x="${labelW/2}" y="14" text-anchor="middle">${label}</text>
<text x="${labelW + valueW/2}" y="14" text-anchor="middle">${text}</text>
</g></svg>`);
});

// Per-tenant public status page
app.get('/status/:tenant_slug', (req, res) => {
  const slug = String(req.params.tenant_slug || '').toLowerCase();
  let tenant = null;
  if (state.tenants) {
    tenant = Object.values(state.tenants).find(t =>
      t.brand_domain === slug || (t.aliases || []).includes(slug) || t.id === slug
    );
  }
  if (!tenant) return res.status(404).send('<h1>Tenant not found</h1>');

  const branding = effectiveBranding(tenant);
  const tenantCustomerIds = new Set(Object.values(state.customers).filter(c => c.tenant_id === tenant.id).map(c => c.id));
  const myMacs = Object.values(state.authorized_macs).filter(m => tenantCustomerIds.has(m.customer_id));
  const onlineCount = myMacs.filter(m => {
    const s = state.box_state[m.mac];
    return s && s.last_heartbeat && (Date.now() - s.last_heartbeat) < 5*60_000;
  }).length;
  const total = myMacs.length;
  const pct = total > 0 ? Math.round((onlineCount / total) * 100) : null;

  // Recent alarms (severity high or critical) for this tenant
  const incidents = state.alarms.filter(a => tenantCustomerIds.has(a.customer_id) && (a.severity === 'high' || a.severity === 'critical')).slice(0, 10);

  res.type('html').send(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${branding.brand_name} — System Status</title>
<style>
body{font-family:system-ui;background:#0f1419;color:#e3e9f0;margin:0;padding:40px 20px;}
.wrap{max-width:760px;margin:0 auto;}
h1{color:${branding.brand_color};}
.statbar{padding:24px;border-radius:12px;margin:24px 0;border-left:4px solid ${pct === null || pct >= 90 ? '#3ad29f' : (pct >= 50 ? '#ff8c42' : '#ff5c5c')};background:#1a2028;}
.statbar h2{color:#fff;margin:0 0 6px 0;}
.statbar p{color:#aab2c0;margin:0;}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;background:#3ad29f;margin-right:6px;animation:p 2s infinite;vertical-align:middle;}
@keyframes p{0%,100%{opacity:1}50%{opacity:.4}}
table{width:100%;border-collapse:collapse;margin-top:8px;font-size:.92em;}
td{padding:10px 0;border-bottom:1px solid #1f2530;color:#aab2c0;}
td:first-child{color:#fff;}
.sev{padding:2px 8px;border-radius:99px;font-size:.75em;background:#2a3340;}
.sev.high{background:#5a2c20;color:#ff8c42;}
.sev.critical{background:#5a1c20;color:#ff5c5c;}
footer{text-align:center;color:#6c7686;font-size:.8em;margin-top:30px;}
</style></head><body><div class="wrap">
<h1>📦 ${branding.brand_name}</h1>
<div style="color:#6c7686;"><span class="dot"></span> Live as of ${new Date().toLocaleString()}</div>

<div class="statbar">
  <h2>${pct === null ? 'No boxes deployed yet' : (pct >= 90 ? '✓ All systems operational' : (pct >= 50 ? '⚠ Partial outage' : '✗ Major outage'))}</h2>
  <p>${onlineCount} of ${total} customer boxes are online (${pct === null ? 'n/a' : pct + '%'})</p>
</div>

<h3 style="color:#8aa0c0;margin-top:32px;font-weight:500;text-transform:uppercase;letter-spacing:1px;font-size:.85em;">Recent incidents (24 h)</h3>
${incidents.length === 0
  ? '<p style="color:#6c7686;padding:14px;">No incidents reported.</p>'
  : '<table>' + incidents.map(a => `
    <tr>
      <td>${a.title || a.kind}</td>
      <td style="text-align:right;"><span class="sev ${a.severity}">${a.severity}</span></td>
      <td style="text-align:right;width:140px;">${new Date(a.ts).toLocaleString()}</td>
    </tr>`).join('') + '</table>'
}

<footer>
  ${branding.brand_name} · Powered by mes Network · This page updates every 60 seconds.
  ${branding.brand_support_phone ? '· Support: ' + branding.brand_support_phone : ''}
</footer>
</div></body></html>`);
});

app.get('/status', (req, res) => {
  const ONLINE_THRESHOLD_MS = 30 * 60 * 1000;
  const now = Date.now();
  const totalBoxes = Object.keys(state.authorized_macs).length;
  const onlineBoxes = Object.values(state.authorized_macs).filter(m => m.last_seen && (now - m.last_seen < ONLINE_THRESHOLD_MS)).length;
  const totalCustomers = Object.values(state.customers).filter(c => (!c.status || c.status === 'active')).length;
  const html = `<!DOCTYPE html>
<html><head>
<meta charset="UTF-8"><title>mes Network — System Status</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body { font-family: -apple-system, system-ui, sans-serif; margin: 0; background: #0f1419; color: #e3e9f0; min-height: 100vh; }
.wrap { max-width: 720px; margin: 0 auto; padding: 40px 20px; }
h1 { color: #ff8c42; margin: 0 0 4px 0; }
.sub { color: #6c7686; margin-bottom: 30px; }
.row { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 14px; margin-bottom: 20px; }
.card { background: #1a2028; border: 1px solid #2a3340; border-radius: 12px; padding: 18px; }
.card.ok { border-left: 4px solid #3ad29f; }
.card.warn { border-left: 4px solid #ff8c42; }
.card h2 { margin: 0 0 8px 0; font-size: .8em; color: #8aa0c0; text-transform: uppercase; letter-spacing: 1px; }
.card .v { font-size: 1.6em; font-weight: 700; color: #fff; }
.dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: #3ad29f; margin-right: 6px; vertical-align: middle; animation: p 2s infinite; }
@keyframes p { 0%,100%{opacity:1}50%{opacity:.4} }
table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: .9em; }
td { padding: 8px 0; border-bottom: 1px solid #1f2530; }
td.r { text-align: right; }
footer { color: #4a5366; font-size: .8em; margin-top: 30px; text-align: center; }
</style>
</head><body>
<div class="wrap">
<h1>📦 mes Network</h1>
<div class="sub"><span class="dot"></span> All systems operational · ${new Date().toLocaleString()}</div>

<div class="row">
  <div class="card ok"><h2>Cloud</h2><div class="v">Operational</div></div>
  <div class="card ${onlineBoxes >= totalBoxes - 1 ? 'ok' : 'warn'}"><h2>Boxes online</h2><div class="v">${onlineBoxes} / ${totalBoxes}</div></div>
  <div class="card ok"><h2>Active customers</h2><div class="v">${totalCustomers}</div></div>
  <div class="card ok"><h2>Cloud uptime</h2><div class="v">${Math.round(process.uptime() / 3600)}h</div></div>
</div>

<div class="card">
  <h2>Recent activity (last 24h)</h2>
  <table>
    <tr><td>Box check-ins</td><td class="r"><strong>${state.checkins.filter(c => Date.now() - c.ts < 86400000).length}</strong></td></tr>
    <tr><td>Customer actions</td><td class="r"><strong>${state.events.filter(e => e.method === 'CUSTOMER' && Date.now() - e.ts < 86400000).length}</strong></td></tr>
    <tr><td>Pairing handshakes</td><td class="r"><strong>${state.events.filter(e => e.path && e.path.includes('eptoken') && Date.now() - e.ts < 86400000).length}</strong></td></tr>
  </table>
</div>

<footer>For account issues, sign in at <strong>cloud.mes.net.lb/pwa/</strong></footer>
</div>
</body></html>`;
  res.type('html').send(html);
});

// System metrics — admin only
app.get('/admin/api/sysmetrics', adminAuth, (req, res) => {
  const out = {};
  try {
    const meminfo = fs.readFileSync('/proc/meminfo', 'utf8');
    const total = parseInt((meminfo.match(/MemTotal:\s+(\d+)/) || [])[1] || 0);
    const avail = parseInt((meminfo.match(/MemAvailable:\s+(\d+)/) || [])[1] || 0);
    out.mem_total_mb = Math.round(total / 1024);
    out.mem_used_mb = Math.round((total - avail) / 1024);
    out.mem_pct = total ? Math.round((1 - avail / total) * 100) : 0;
  } catch {}
  try {
    const loadavg = fs.readFileSync('/proc/loadavg', 'utf8').trim().split(/\s+/);
    out.load_1m = parseFloat(loadavg[0]);
    out.load_5m = parseFloat(loadavg[1]);
    out.load_15m = parseFloat(loadavg[2]);
  } catch {}
  out.process_uptime_h = Math.round(process.uptime() / 3600);
  out.process_rss_mb = Math.round(process.memoryUsage().rss / 1024 / 1024);
  try {
    const s = fs.statfsSync('/data');
    out.disk_total_mb = Math.round(s.blocks * s.bsize / 1024 / 1024);
    out.disk_free_mb = Math.round(s.bavail * s.bsize / 1024 / 1024);
    out.disk_pct = s.blocks ? Math.round((1 - s.bavail / s.blocks) * 100) : 0;
  } catch {}
  res.json(out);
});

// Tenant-aware PWA manifest — overrides static one when accessed via tenant domain
app.get('/pwa/manifest.json', (req, res) => {
  const tenant = tenantForRequest(req);
  const branding = effectiveBranding(tenant);
  res.set('Cache-Control', 'public, max-age=3600');
  res.json({
    name:        branding.brand_name + ' — Home Network Guardian',
    short_name:  branding.brand_name.slice(0, 12),
    description: 'Manage your home network: block ads, set kid screen time, control VPN, monitor everything.',
    start_url:   '/pwa/',
    scope:       '/pwa/',
    display:     'standalone',
    orientation: 'portrait',
    background_color: '#0f1419',
    theme_color: branding.brand_color,
    categories: ['utilities', 'productivity'],
    lang: 'en',
    dir: 'ltr',
    shortcuts: [
      { name: 'Pause Internet', short_name: 'Pause', url: '/pwa/?action=pause', icons: [{ src: '/pwa/icon.svg', sizes: 'any' }] },
      { name: 'Add a box',      short_name: 'Add box', url: '/pwa/?action=add-box', icons: [{ src: '/pwa/icon.svg', sizes: 'any' }] },
    ],
    icons: [
      { src: branding.brand_logo_url || '/pwa/icon.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'any maskable' },
    ],
  });
});

// Box agent installer + agent.js (for `curl ... | sudo bash` install on customer boxes)
const BOX_AGENT_DIR = path.join(__dirname, 'box-agent');
app.get('/box/install.sh', (req, res) => {
  const p = path.join(BOX_AGENT_DIR, 'install.sh');
  if (!fs.existsSync(p)) return res.status(404).send('# install.sh not found\n');
  res.set('Content-Type', 'text/x-shellscript');
  res.sendFile(p);
});
app.get('/box/agent.js', (req, res) => {
  const p = path.join(BOX_AGENT_DIR, 'agent.js');
  if (!fs.existsSync(p)) return res.status(404).send('// agent.js not found\n');
  res.set('Content-Type', 'application/javascript');
  res.sendFile(p);
});
app.get('/box/oui-table.json', (req, res) => {
  const p = path.join(__dirname, 'oui-table.json');
  if (!fs.existsSync(p)) return res.status(404).json({ error: 'oui table not found' });
  res.set('Content-Type', 'application/json');
  res.set('Cache-Control', 'public, max-age=86400');
  res.sendFile(p);
});
app.get('/box/quickinstall.sh', (req, res) => {
  const p = path.join(BOX_AGENT_DIR, 'quickinstall.sh');
  if (!fs.existsSync(p)) return res.status(404).send('# quickinstall not found\n');
  res.set('Content-Type', 'text/x-shellscript');
  res.sendFile(p);
});
// Generic box-agent file fetcher — serves any .js file from box-agent/
// Used by sig-engine.js, sni-parser.js, openvpn.js (modules added in v1.1.0).
app.get('/box/:fname', (req, res, next) => {
  const fname = req.params.fname;
  // Only allow safe filenames (no path traversal)
  if (!/^[a-zA-Z0-9_-]+\.(js|sh|json)$/.test(fname)) return next();
  // Skip ones already explicitly handled above
  if (['install.sh', 'agent.js', 'quickinstall.sh', 'oui-table.json'].includes(fname)) return next();
  const p = path.join(BOX_AGENT_DIR, fname);
  if (!fs.existsSync(p)) return res.status(404).send('# not found: ' + fname + '\n');
  const ct = fname.endsWith('.js') ? 'application/javascript'
           : fname.endsWith('.sh') ? 'text/x-shellscript'
           : 'application/json';
  res.set('Content-Type', ct);
  res.sendFile(p);
});
// Locally-hosted qrcode lib (avoids tracking-prevention blocks on third-party CDN)
function serveQrcodeLib(req, res) {
  const p = path.join(__dirname, 'qrcode.min.js');
  if (!fs.existsSync(p)) return res.status(404).send('// qrcode lib not found\n');
  res.set('Content-Type', 'application/javascript');
  res.set('Cache-Control', 'public, max-age=86400');
  res.sendFile(p);
}
app.get('/admin/qrcode.min.js', serveQrcodeLib);
app.get('/api/qrcode.min.js', serveQrcodeLib);

// Pre-built flashable Pi 4 image (~600 MB). Built by build-image.sh on the VPS.
const IMAGES_DIR = process.env.IMAGES_DIR || '/data/images';
app.get('/downloads/images/list', (req, res) => {
  if (!fs.existsSync(IMAGES_DIR)) return res.json({ images: [] });
  const files = fs.readdirSync(IMAGES_DIR).filter(f => /\.img\.xz$/.test(f));
  const out = files.map(f => {
    const stat = fs.statSync(path.join(IMAGES_DIR, f));
    let sha256 = null;
    try { sha256 = fs.readFileSync(path.join(IMAGES_DIR, f + '.sha256'), 'utf8').split(' ')[0]; } catch {}
    return { file: f, size: stat.size, mtime: stat.mtime, sha256, url: `/downloads/images/${f}` };
  });
  out.sort((a, b) => b.mtime - a.mtime);
  res.json({ images: out });
});
app.get('/downloads/images/:file', (req, res) => {
  if (!/^[\w.-]+\.(img\.xz|sha256)$/.test(req.params.file)) return res.status(400).json({ error: 'bad name' });
  const p = path.join(IMAGES_DIR, req.params.file);
  if (!fs.existsSync(p)) return res.status(404).json({ error: 'not found' });
  console.log(`         📥 IMAGE DOWNLOAD → ${req.params.file}  ip=${req.ip}`);
  res.sendFile(path.resolve(p));
});

// JSON status (same data as before — kept for monitoring)
app.get('/api/status.json', (req, res) => {
  res.json({
    name: 'mes Network Cloud',
    version: '1.0.0',
    uptime_sec: Math.round(process.uptime()),
    state: {
      groups: Object.keys(state.groups).length,
      endpoints: Object.keys(state.endpoints).length,
      customers: Object.keys(state.customers).length,
      authorized_macs: Object.keys(state.authorized_macs).length,
    },
  });
});

// ─── Legal pages: privacy policy + terms of service ─────
const LEGAL_VERSION = '1.0.0';
const LEGAL_LAST_UPDATED = '2026-05-08';

function legalPage(title, body, branding) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title} — ${branding.brand_name}</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;background:#0f1419;color:#e3e9f0;margin:0;padding:30px 20px;}
.wrap{max-width:760px;margin:0 auto;line-height:1.65;}
h1{color:${branding.brand_color};border-bottom:1px solid #2a3340;padding-bottom:14px;}
h2{color:#fff;margin-top:32px;}
p,li{color:#aab2c0;}
.meta{color:#6c7686;font-size:.85em;}
a{color:${branding.brand_accent};}
ul{padding-left:20px;}
footer{margin-top:40px;padding-top:20px;border-top:1px solid #2a3340;color:#6c7686;font-size:.8em;text-align:center;}
</style></head><body><div class="wrap">
${body}
<footer>
  <a href="/legal/privacy">Privacy</a> · <a href="/legal/terms">Terms</a> · <a href="/">Home</a> · <a href="/pwa/">Sign in</a>
  <br>Version ${LEGAL_VERSION} · last updated ${LEGAL_LAST_UPDATED}
</footer>
</div></body></html>`;
}

app.get('/legal/privacy', (req, res) => {
  const branding = effectiveBranding(tenantForRequest(req));
  const body = `<h1>Privacy Policy</h1>
<p class="meta">Effective ${LEGAL_LAST_UPDATED} · Version ${LEGAL_VERSION}</p>
<p>${branding.brand_name} ("we") respects your privacy. This policy explains what we collect, why, and your rights.</p>

<h2>What we collect</h2>
<ul>
  <li><strong>Account:</strong> phone number, optional email, optional address. Used to identify you and contact you.</li>
  <li><strong>Network telemetry:</strong> from your box — device list (MAC + hostname), connection flows (source/destination IP, port, domain, byte counts), DNS queries (last 24h, capped). Used to provide blocking, parental controls, alerts.</li>
  <li><strong>Box vitals:</strong> CPU, RAM, temperature, uptime. Used to detect hardware issues.</li>
  <li><strong>Login activity:</strong> IP, browser, timestamp. Used to detect suspicious access.</li>
</ul>

<h2>What we do NOT collect</h2>
<ul>
  <li>The CONTENT of your traffic — only metadata (who-talked-to-whom, how much, when). HTTPS payloads are never inspected.</li>
  <li>Location data unless you give us a shipping address.</li>
  <li>Third-party identifiers, fingerprinting, advertising IDs.</li>
</ul>

<h2>How long we keep it</h2>
<ul>
  <li>DNS query log: 24 hours</li>
  <li>Flow records: ring buffer (~100,000 most recent)</li>
  <li>Speedtest history: 365 entries per box</li>
  <li>Account profile: until you delete it (7-day recoverable grace period)</li>
</ul>

<h2>Who we share with</h2>
<p>We don't sell your data. We share with:</p>
<ul>
  <li><strong>Cloudflare</strong> — fronts our cloud (TLS, anti-DDoS).</li>
  <li><strong>Lebanese authorities</strong> — only with valid legal process.</li>
</ul>

<h2>Your rights</h2>
<ul>
  <li><strong>Export everything we have:</strong> Settings → "Download my data".</li>
  <li><strong>Delete your account:</strong> Settings → "Delete my account". 7-day recoverable grace, then irreversible wipe.</li>
  <li><strong>Disable notifications</strong> per category and set quiet hours.</li>
</ul>

<h2>Contact</h2>
<p>Questions? Email ${state.config.admin_email || 'admin@mes.net.lb'}.</p>`;
  res.type('html').send(legalPage('Privacy', body, branding));
});

app.get('/legal/terms', (req, res) => {
  const branding = effectiveBranding(tenantForRequest(req));
  const body = `<h1>Terms of Service</h1>
<p class="meta">Effective ${LEGAL_LAST_UPDATED} · Version ${LEGAL_VERSION}</p>

<h2>1. Service</h2>
<p>${branding.brand_name} provides a cloud service that controls a network device ("box") on your network. The service includes content filtering, parental controls, VPN, alerts, and monitoring.</p>

<h2>2. Your account</h2>
<ul>
  <li>You're responsible for keeping your phone number / email working — we send security alerts there.</li>
  <li>One account per person. Don't share login credentials.</li>
  <li>You may not use the service for illegal purposes.</li>
</ul>

<h2>3. Plans &amp; payment</h2>
<ul>
  <li>Plans are billed monthly. Prices in USD; we accept LBP at the day's rate.</li>
  <li>Cancel anytime — service continues to the end of the paid period.</li>
  <li>We may change prices with 30 days notice.</li>
</ul>

<h2>4. Hardware</h2>
<ul>
  <li>If you order a pre-flashed box, you own it after delivery.</li>
  <li>You may flash your own hardware (Raspberry Pi 4) — we don't sell licenses; the agent software is open use.</li>
</ul>

<h2>5. Disclaimers</h2>
<ul>
  <li>The service is provided "as is". We make a best effort but don't guarantee 100% uptime.</li>
  <li>Content blocking is not a substitute for parental supervision.</li>
  <li>VPN does not make you anonymous to your ISP — only encrypts the traffic between your device and your box.</li>
</ul>

<h2>6. Liability</h2>
<p>Our maximum liability is limited to one month of subscription fees. We're not liable for indirect or consequential damages.</p>

<h2>7. Changes</h2>
<p>We may update these terms. We'll email you and show a banner in the app. Continued use after 30 days = acceptance.</p>

<h2>8. Termination</h2>
<p>Either side can terminate. We may terminate for: non-payment, abuse, illegal use. You may terminate at any time via Settings → Delete my account.</p>

<h2>9. Governing law</h2>
<p>Lebanese law. Disputes are settled in Beirut courts.</p>

<h2>10. Contact</h2>
<p>${state.config.admin_email || 'admin@mes.net.lb'}</p>`;
  res.type('html').send(legalPage('Terms of Service', body, branding));
});

app.get('/api/legal/version', (req, res) => {
  res.json({ version: LEGAL_VERSION, last_updated: LEGAL_LAST_UPDATED });
});

// Track ToS acceptance on signup
function recordToSAcceptance(customerId) {
  const c = state.customers[customerId];
  if (!c) return;
  c.tos_accepted = { version: LEGAL_VERSION, at: Date.now() };
}

// OpenAPI 3.0 spec — auto-generated subset of the public API for integrators
app.get('/api/openapi.json', (req, res) => {
  const branding = effectiveBranding(tenantForRequest(req));
  const baseUrl = state.config.brand_domain ? 'https://' + state.config.brand_domain : '';
  const spec = {
    openapi: '3.0.3',
    info: {
      title: branding.brand_name + ' API',
      version: '1.0.0',
      description: 'mes Network customer + box + admin API. Paste this URL into Postman/Insomnia/Stoplight to auto-generate clients.',
      contact: { email: state.config.admin_email || '' },
    },
    servers: [{ url: baseUrl, description: 'Production' }],
    components: {
      securitySchemes: {
        bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
        basicAuth:  { type: 'http', scheme: 'basic', description: 'Admin: admin:<password>' },
      },
    },
    paths: {
      // Auth
      '/api/customer/login':  { post: { summary: 'Request OTP for phone', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', properties: { phone: { type: 'string' } }, required: ['phone'] } } } } } },
      '/api/customer/verify': { post: { summary: 'Verify OTP, get JWT', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', properties: { phone: { type: 'string' }, code: { type: 'string' } }, required: ['phone','code'] } } } } } },
      '/api/customer/me':     { get: { summary: 'Current customer profile', security: [{ bearerAuth: [] }] } },

      // Boxes + devices
      '/api/customer/boxes':   { get: { summary: 'My boxes (status + vitals)', security: [{ bearerAuth: [] }] } },
      '/api/customer/devices': { get: { summary: 'Devices on my network', security: [{ bearerAuth: [] }] } },

      // Rules + categories
      '/api/customer/rules':       { get:  { summary: 'My rules', security: [{ bearerAuth: [] }] } },
      '/api/customer/rules/add':   { post: { summary: 'Add a rule', security: [{ bearerAuth: [] }] } },
      '/api/customer/categories':  { get:  { summary: 'Available block categories', security: [{ bearerAuth: [] }] } },

      // Schedules + family
      '/api/customer/schedules':            { get:  { summary: 'My schedules', security: [{ bearerAuth: [] }] } },
      '/api/customer/schedules/presets':    { get:  { summary: 'Schedule preset templates', security: [{ bearerAuth: [] }] } },
      '/api/customer/schedules/from-preset':{ post: { summary: 'Apply preset', security: [{ bearerAuth: [] }] } },
      '/api/customer/family':               { get:  { summary: 'Family members', security: [{ bearerAuth: [] }] } },
      '/api/customer/family/assign-device': { post: { summary: 'Assign device to member', security: [{ bearerAuth: [] }] } },

      // VPN + DDNS
      '/api/customer/wg/peers':                  { get:  { summary: 'WireGuard peers', security: [{ bearerAuth: [] }] } },
      '/api/customer/wg/peers/create':           { post: { summary: 'Create WG peer', security: [{ bearerAuth: [] }] } },
      '/api/customer/wg/peers/{id}.conf':        { get:  { summary: 'Download peer .conf', security: [{ bearerAuth: [] }] } },
      '/api/customer/ddns':                      { get:  { summary: 'My DDNS records', security: [{ bearerAuth: [] }] } },
      '/api/customer/ddns/claim':                { post: { summary: 'Claim a DDNS slug', security: [{ bearerAuth: [] }] } },

      // Quotas + time bank
      '/api/customer/quotas':         { get:  { summary: 'Bandwidth quotas', security: [{ bearerAuth: [] }] } },
      '/api/customer/quotas/set':     { post: { summary: 'Set per-device quota', security: [{ bearerAuth: [] }] } },
      '/api/customer/time-bank':      { get:  { summary: 'Time bank entries', security: [{ bearerAuth: [] }] } },
      '/api/customer/time-bank/set':  { post: { summary: 'Set daily-minutes for device', security: [{ bearerAuth: [] }] } },

      // Stats
      '/api/customer/usage':                 { get: { summary: 'Monthly usage totals', security: [{ bearerAuth: [] }] } },
      '/api/customer/usage-daily':           { get: { summary: '30-day usage by day', security: [{ bearerAuth: [] }] } },
      '/api/customer/heatmap':               { get: { summary: 'Activity heatmap (7×24)', security: [{ bearerAuth: [] }] } },
      '/api/customer/top-sites':             { get: { summary: 'Top sites per device, last 24h', security: [{ bearerAuth: [] }] } },
      '/api/customer/uptime':                { get: { summary: '30-day box uptime %', security: [{ bearerAuth: [] }] } },
      '/api/customer/speedtest-history':     { get: { summary: 'Recent speedtests', security: [{ bearerAuth: [] }] } },
      '/api/customer/dns-queries':           { get: { summary: 'DNS query log (last 24h)', security: [{ bearerAuth: [] }] } },
      '/api/customer/flows':                 { get: { summary: 'Recent flows', security: [{ bearerAuth: [] }] } },
      '/api/customer/alarms':                { get: { summary: 'Alarms', security: [{ bearerAuth: [] }] } },
      '/api/customer/device/{mac}/flows.csv':{ get: { summary: 'Per-device flow CSV (24h)', security: [{ bearerAuth: [] }] } },

      // Box agent
      '/api/box/self-register':       { post: { summary: 'Box self-register on first boot — returns pairing code' } },
      '/api/box/auth':                { post: { summary: 'HMAC auth → session token' } },
      '/api/box/heartbeat':           { post: { summary: 'Periodic heartbeat (every 60s)', security: [{ bearerAuth: [] }] } },
      '/api/box/flows':               { post: { summary: 'Upload flow batch', security: [{ bearerAuth: [] }] } },
      '/api/box/devices':             { post: { summary: 'Report LAN devices', security: [{ bearerAuth: [] }] } },
      '/api/box/alarms':              { post: { summary: 'Report alarm', security: [{ bearerAuth: [] }] } },
      '/api/box/policy/{mac}':        { get:  { summary: 'Pull policy bundle' } },
      '/api/box/commands':            { get:  { summary: 'Pending commands queue', security: [{ bearerAuth: [] }] } },
      '/api/box/commands/{id}/result':{ post: { summary: 'Report command result', security: [{ bearerAuth: [] }] } },

      // Public
      '/nic/update':           { get: { summary: 'NoIP-compatible DDNS update', security: [{ basicAuth: [] }] } },
      '/api/branding':         { get: { summary: 'Tenant branding by hostname' } },
      '/api/branding/lbp-rate':{ get: { summary: 'Live LBP/USD rate' } },
      '/ddns/{slug}':          { get: { summary: 'Public DDNS lookup (JSON)' } },
      '/ddns/zonefile':        { get: { summary: 'BIND-format zone file (consumed by NSD pollers)' } },
    },
  };
  res.json(spec);
});

// Public landing page
app.get('/', (req, res) => {
  const t = tenantForRequest(req);
  const branding = effectiveBranding(t);
  const brandName = branding.brand_name;
  const accent = branding.brand_color;
  const accent2 = branding.brand_accent;
  const wa = (t && t.brand_support_phone) || state.config.brand_support_phone || '';
  const waLink = wa ? 'https://wa.me/' + wa.replace(/[^\d]/g, '') : '';
  const customers = Object.keys(state.customers || {}).length;
  const onlineBoxes = Object.values(state.box_state || {}).filter(b => b.last_heartbeat && (Date.now() - b.last_heartbeat) < 5*60_000).length;
  // Tenant-customized landing copy
  const heroTitle = (t && t.landing_hero_title) || 'Network protection for <span>every</span> device in your home.';
  const heroSub   = (t && t.landing_hero_sub)   || 'Block ads, control kids\' screen time, stop malware, set up VPN — all from one Lebanon-hosted cloud and one small box. No subscription games. No data sold.';
  const ctaText   = (t && t.landing_cta_text)   || 'Start free trial →';

  res.type('html').send(`<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${brandName} — protect every device on your home network</title>
<meta name="description" content="${brandName} brings Firewalla-class network protection to Lebanese homes and offices. Block ads, parental controls, VPN, threat blocking — all in one box.">
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;background:#0f1419;color:#e3e9f0;line-height:1.6;}
  a{color:${accent2};text-decoration:none}
  .wrap{max-width:1100px;margin:0 auto;padding:24px}
  header{display:flex;justify-content:space-between;align-items:center;padding:20px 0;border-bottom:1px solid #1f2530}
  header h1{font-size:1.4em;color:${accent};font-weight:700}
  header nav{display:flex;gap:18px;font-size:.95em}
  .hero{padding:80px 0;text-align:center}
  .hero h2{font-size:2.6em;font-weight:800;line-height:1.2;color:#fff;margin-bottom:18px}
  .hero h2 span{color:${accent}}
  .hero p{color:#aab2c0;font-size:1.15em;max-width:640px;margin:0 auto 32px}
  .cta{display:inline-block;background:${accent};color:#000;padding:14px 28px;border-radius:8px;font-weight:700;font-size:1em;cursor:pointer;border:none;margin:6px}
  .cta-2{display:inline-block;background:transparent;color:#fff;padding:14px 28px;border-radius:8px;font-weight:600;font-size:1em;border:1px solid #2a3340;margin:6px}
  .cta:hover{filter:brightness(1.1)}
  .stats{display:flex;justify-content:center;gap:28px;flex-wrap:wrap;margin-top:50px;color:#6c7686;font-size:.9em}
  .stats strong{color:${accent2};font-size:1.3em;display:block}
  section{padding:80px 0;border-top:1px solid #1f2530}
  section h3{font-size:1.8em;color:#fff;margin-bottom:36px;text-align:center}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:20px}
  .card{background:#1a2028;padding:24px;border-radius:12px;border:1px solid #2a3340}
  .card h4{color:${accent2};font-size:1.1em;margin-bottom:8px}
  .card p{color:#aab2c0;font-size:.95em}
  .price-tier{padding:28px 22px;text-align:center}
  .price-tier .tier-name{color:#8aa0c0;text-transform:uppercase;letter-spacing:1px;font-size:.8em}
  .price-tier .price{font-size:2em;color:#fff;font-weight:700;margin:8px 0 4px}
  .price-tier .price small{font-size:.4em;color:#6c7686;font-weight:400}
  .price-tier ul{list-style:none;text-align:left;margin:18px 0}
  .price-tier li{color:#aab2c0;font-size:.9em;padding:4px 0}
  .price-tier li:before{content:"✓";color:${accent2};margin-right:8px;font-weight:700}
  .price-tier.featured{border:2px solid ${accent}}
  footer{padding:30px 0;border-top:1px solid #1f2530;text-align:center;color:#6c7686;font-size:.85em}
  @media (max-width:640px){.hero h2{font-size:1.8em}.hero p{font-size:1em}}
</style>
</head><body>
<div class="wrap">
<header>
  <h1>📦 ${brandName}</h1>
  <nav>
    <a href="/pwa/">Sign in</a>
    <a href="/status">Status</a>
    ${waLink ? `<a href="${waLink}" target="_blank">📱 WhatsApp</a>` : ''}
  </nav>
</header>

<div class="hero">
  <h2>${heroTitle}</h2>
  <p>${heroSub}</p>
  <a class="cta" href="/pwa/">${ctaText}</a>
  <a class="cta-2" href="/downloads/images/list">Flash on your own Pi</a>
  <div class="stats">
    <span><strong>${customers}</strong> customers</span>
    <span><strong>${onlineBoxes}</strong> boxes online</span>
    <span><strong>${(state.threat_feeds.domains || []).length.toLocaleString()}</strong> threats blocked</span>
  </div>
</div>

<section>
  <h3>Everything Firewalla does — built for Lebanon</h3>
  <div class="grid">
    <div class="card"><h4>👨‍👩‍👧 Parental controls</h4><p>Bedtime schedules, daily screen-time minutes, block adult content with one tap. Per-kid, not per-router.</p></div>
    <div class="card"><h4>🛡️ Threat blocking</h4><p>140,000+ malware domains blocked daily, refreshed from public feeds. Zero-trust DNS.</p></div>
    <div class="card"><h4>📊 See everything</h4><p>What's each device talking to. How much bandwidth. Which countries. All in real-time.</p></div>
    <div class="card"><h4>🔒 WireGuard VPN</h4><p>One tap, scan QR, secure browsing from anywhere. Your home is your VPN.</p></div>
    <div class="card"><h4>📱 Per-device limits</h4><p>5 GB/month for the smart TV. 60 minutes/day for the kid's iPad. Done.</p></div>
    <div class="card"><h4>🌍 Ad + geo blocking</h4><p>Stop talking to ad networks. Block traffic to specific countries. Your bandwidth, your rules.</p></div>
  </div>
</section>

<section>
  <h3>Pricing</h3>
  <div class="grid">
    <div class="card price-tier">
      <div class="tier-name">Basic</div>
      <div class="price">$5<small>/month</small></div>
      <ul>
        <li>DNS filter + per-device control</li>
        <li>Up to 5 devices monitored</li>
        <li>1 schedule</li>
        <li>Email support</li>
      </ul>
    </div>
    <div class="card price-tier featured">
      <div class="tier-name">Family ★</div>
      <div class="price">$10<small>/month</small></div>
      <ul>
        <li>Everything in Basic</li>
        <li>Up to 6 family members</li>
        <li>8 schedules + presets (Bedtime, School)</li>
        <li>Up to 20 devices monitored</li>
      </ul>
    </div>
    <div class="card price-tier">
      <div class="tier-name">Pro</div>
      <div class="price">$20<small>/month</small></div>
      <ul>
        <li>Everything in Family</li>
        <li>WireGuard VPN (5 peers)</li>
        <li>IDS / threat detection</li>
        <li>50 devices monitored</li>
      </ul>
    </div>
    <div class="card price-tier">
      <div class="tier-name">Business</div>
      <div class="price">$50<small>/month</small></div>
      <ul>
        <li>Everything in Pro</li>
        <li>Multi-site (10 locations)</li>
        <li>50 VPN peers</li>
        <li>Priority support</li>
      </ul>
    </div>
  </div>
  <p style="text-align:center;color:#6c7686;font-size:.9em;margin-top:30px;">Prices in USD; pay in LBP at the day's rate. Cancel anytime.</p>
</section>

<section>
  <h3>Two ways to get started</h3>
  <div class="grid">
    <div class="card">
      <h4>📦 Order a pre-flashed box</h4>
      <p>We ship a Raspberry Pi 4, ready to plug in and pair. Contact us via WhatsApp. Setup takes 3 minutes.</p>
      ${waLink ? `<a class="cta" href="${waLink}" target="_blank" style="margin-top:14px;">📱 Chat with us</a>` : ''}
    </div>
    <div class="card">
      <h4>💾 Already have a Pi 4?</h4>
      <p>Download our flashable image. Burn to SD card. Plug in. Pair via 6-character code. No SSH needed.</p>
      <a class="cta" href="/downloads/images/list" style="margin-top:14px;">Download image →</a>
    </div>
  </div>
</section>

<footer>
  © ${new Date().getFullYear()} ${brandName} · <a href="/api/docs">API docs</a> · <a href="/status">Status</a> · <a href="/pwa/">Customer portal</a> · <a href="/legal/privacy">Privacy</a> · <a href="/legal/terms">Terms</a>
</footer>
</div></body></html>`);
});

// ═══════════════════════════════════════════════════════════════════
// ADMIN DASHBOARD (basic auth, served at /admin)
// ═══════════════════════════════════════════════════════════════════
// ─── TOTP (RFC 6238) — no external library ───
function base32Encode(buf) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, value = 0, out = '';
  for (let i = 0; i < buf.length; i++) {
    value = (value << 8) | buf[i];
    bits += 8;
    while (bits >= 5) { out += A[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += A[(value << (5 - bits)) & 31];
  return out;
}
function base32Decode(s) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  s = s.replace(/=+$/, '').toUpperCase();
  let bits = 0, value = 0; const out = [];
  for (const ch of s) {
    const idx = A.indexOf(ch);
    if (idx < 0) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Buffer.from(out);
}
function totpAt(secret, counter) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', secret).update(buf).digest();
  const offset = h[h.length - 1] & 0x0f;
  const code = (
    ((h[offset] & 0x7f) << 24) |
    ((h[offset + 1] & 0xff) << 16) |
    ((h[offset + 2] & 0xff) << 8) |
    (h[offset + 3] & 0xff)
  ) % 1_000_000;
  return String(code).padStart(6, '0');
}
function totpVerify(base32Secret, code, window = 1) {
  const secret = base32Decode(base32Secret);
  const counter = Math.floor(Date.now() / 30000);
  for (let i = -window; i <= window; i++) {
    if (totpAt(secret, counter + i) === code) return true;
  }
  return false;
}

function hashPassword(pw, salt) {
  salt = salt || crypto.randomBytes(8).toString('hex');
  const hash = crypto.scryptSync(pw, salt, 32).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(pw, stored) {
  const [salt, hash] = String(stored).split(':');
  if (!salt || !hash) return false;
  const test = crypto.scryptSync(pw, salt, 32).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(test));
}

// IP allowlist check — if state.config.admin_ip_allowlist is non-empty, the
// requesting IP (or any IP in X-Forwarded-For) must match one of the listed
// CIDRs / single IPs. Otherwise reject before auth.
function _adminIpAllowed(req) {
  const list = (state.config && state.config.admin_ip_allowlist) || [];
  if (!Array.isArray(list) || list.length === 0) return true;
  const candidates = [];
  if (req.headers['x-forwarded-for']) {
    candidates.push(...String(req.headers['x-forwarded-for']).split(',').map(s => s.trim()).filter(Boolean));
  }
  if (req.ip) candidates.push(req.ip.replace(/^::ffff:/, ''));
  for (const ip of candidates) {
    for (const allowed of list) {
      if (_ipInCidr(ip, allowed)) return true;
    }
  }
  return false;
}
function _ipInCidr(ip, cidr) {
  if (!cidr) return false;
  if (!cidr.includes('/')) return ip === cidr;
  const [net, bitsStr] = cidr.split('/');
  const bits = parseInt(bitsStr, 10);
  if (isNaN(bits) || bits < 0 || bits > 32) return false;
  const ipNum = _ipToNum(ip), netNum = _ipToNum(net);
  if (ipNum == null || netNum == null) return false;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipNum & mask) === (netNum & mask);
}
function _ipToNum(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    const x = parseInt(p, 10);
    if (isNaN(x) || x < 0 || x > 255) return null;
    n = (n << 8 | x) >>> 0;
  }
  return n;
}

function adminAuth(req, res, next) {
  if (!_adminIpAllowed(req)) {
    console.log(`         🚫 admin IP blocked: ${req.ip} (allowlist active)`);
    return res.status(403).json({ error: 'ip_not_allowed', message: 'Your IP is not in the admin allowlist.' });
  }
  // 1. API key auth (X-API-Key header)
  const apiKey = req.headers['x-api-key'];
  if (apiKey) {
    const keyHash = crypto.createHash('sha256').update(apiKey).digest('hex');
    for (const k of Object.values(state.api_keys || {})) {
      if (k.hashed === keyHash && k.active !== false) {
        k.last_used_at = Date.now();
        k.last_used_ip = req.ip;
        req.adminUser = 'apikey:' + k.name;
        req.adminName = 'API key: ' + k.name;
        req.adminRole = k.role || 'admin';
        req.apiKeyScopes = k.scopes || ['*'];
        const denied = _adminPermissionCheck(req);
        if (denied) return res.status(403).json(denied);
        return next();
      }
    }
    return res.status(401).json({ error: 'invalid api key' });
  }

  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Basic ')) {
    res.set('WWW-Authenticate', 'Basic realm="mes-cloud admin"');
    return res.status(401).send('Auth required');
  }
  const decoded = Buffer.from(auth.slice(6), 'base64').toString();
  const idx = decoded.indexOf(':');
  const user = idx >= 0 ? decoded.slice(0, idx) : decoded;
  const pass = idx >= 0 ? decoded.slice(idx + 1) : '';

  // 1. Try sub-admin from state.admins
  if (state.admins[user] && state.admins[user].active !== false) {
    const a = state.admins[user];
    if (verifyPassword(pass, a.password_hash)) {
      // 2FA check — if admin has totp_secret, require X-Admin-OTP header
      if (a.totp_secret) {
        const otp = req.headers['x-admin-otp'] || '';
        if (!otp || !totpVerify(a.totp_secret, String(otp), 1)) {
          res.set('WWW-Authenticate', 'Basic realm="mes-cloud admin"');
          return res.status(401).json({ error: '2FA required (set header X-Admin-OTP)', requires_2fa: true });
        }
      }
      req.adminUser = user;
      req.adminName = a.name || user;
      req.adminRole = a.role || 'admin';
      const denied1 = _adminPermissionCheck(req);
      if (denied1) return res.status(403).json(denied1);
      return next();
    }
  }

  // 2. Bootstrap admin via env ADMIN_PASSWORD (only when no sub-admins exist OR user='admin')
  if (user === 'admin' && pass === ADMIN_PASSWORD) {
    req.adminUser = 'admin';
    req.adminName = 'admin (bootstrap)';
    req.adminRole = 'super';
    return next();
  }

  res.set('WWW-Authenticate', 'Basic realm="mes-cloud admin"');
  return res.status(401).send('Wrong credentials');
}

// Helper: filter customers based on admin's role/scope.
// Per-role method/path enforcement. Returns null if allowed, else { error, message }.
// Roles: super, admin, support, read_only, reseller. super/admin → no extra restrictions.
function _adminPermissionCheck(req) {
  const role = req.adminRole || 'admin';
  const path = req.path || '';
  const method = req.method;
  if (role === 'super' || role === 'admin') return null;

  if (role === 'read_only') {
    if (method === 'GET' || method === 'HEAD') return null;
    return { error: 'forbidden', message: 'read_only role cannot perform mutations' };
  }

  if (role === 'support') {
    // GETs always OK
    if (method === 'GET' || method === 'HEAD') return null;
    // Allow specific support-operational POSTs:
    const allowed = [
      '/admin/api/customers/note',
      '/admin/api/tickets/reply',
      '/admin/api/tickets/status',
      '/admin/api/customers/impersonate',
      '/admin/api/alarms/ack',
      '/admin/api/notifications/send',
    ];
    if (allowed.some(p => path === p || path.startsWith(p + '/'))) return null;
    return { error: 'forbidden', message: `support role cannot ${method} ${path}` };
  }

  // reseller: existing canAccessCustomer guards on per-resource basis; no method restriction here
  return null;
}

// Resellers only see their assigned customers; super/admin/support see all.
function visibleCustomers(req) {
  if (req.adminRole === 'reseller') {
    const a = state.admins[req.adminUser];
    const assigned = (a && a.assigned_customer_ids) || [];
    return Object.values(state.customers).filter(c => assigned.includes(c.id));
  }
  return Object.values(state.customers);
}
function canAccessCustomer(req, customer_id) {
  if (req.adminRole !== 'reseller') return true;
  const a = state.admins[req.adminUser];
  return !!(a && a.assigned_customer_ids && a.assigned_customer_ids.includes(customer_id));
}

// Helper: record admin action for audit
function logAdminAction(req, action, target, details) {
  // Hash-chained: each entry's hash includes prev entry's hash, so any tampering
  // breaks the chain from that point forward.
  const prev = state.admin_actions[0];
  const prevHash = prev ? prev.hash : '0'.repeat(64);
  const entry = {
    ts: Date.now(),
    admin: req.adminUser || 'unknown',
    role: req.adminRole || '?',
    action,
    target: target || '',
    details: details || '',
    ip: req.ip,
    prev_hash: prevHash,
  };
  // Compute hash over the entry (excluding hash field itself)
  entry.hash = crypto.createHash('sha256')
    .update(JSON.stringify({ ts: entry.ts, admin: entry.admin, action: entry.action, target: entry.target, details: entry.details, prev_hash: prevHash }))
    .digest('hex');
  state.admin_actions.unshift(entry);
  // When truncating, the new oldest entry's prev_hash would point to a dropped entry,
  // breaking the chain. Re-anchor it to the genesis hash and re-sign so the chain stays valid.
  if (state.admin_actions.length > 5000) {
    state.admin_actions = state.admin_actions.slice(0, 3000);
    const newOldest = state.admin_actions[state.admin_actions.length - 1];
    if (newOldest) {
      newOldest.prev_hash = '0'.repeat(64);
      newOldest.truncated_anchor = true;   // marker so verification knows
      newOldest.hash = crypto.createHash('sha256').update(JSON.stringify({
        ts: newOldest.ts, admin: newOldest.admin, action: newOldest.action,
        target: newOldest.target, details: newOldest.details, prev_hash: newOldest.prev_hash,
      })).digest('hex');
      // Walk forward (newer-ward) to refresh hashes since the chain changed at the bottom
      for (let i = state.admin_actions.length - 2; i >= 0; i--) {
        const e = state.admin_actions[i];
        e.prev_hash = state.admin_actions[i + 1].hash;
        e.hash = crypto.createHash('sha256').update(JSON.stringify({
          ts: e.ts, admin: e.admin, action: e.action,
          target: e.target, details: e.details, prev_hash: e.prev_hash,
        })).digest('hex');
      }
    }
  }
}

// On startup: detect broken audit chain (e.g. from legacy lossy truncation) and
// repair automatically. Logs the fact so it shows in audit history.
setTimeout(() => {
  try {
    const v = verifyAuditChain();
    if (v.intact === false) {
      const fixed = repairAuditChain();
      console.log(`         🔧 AUDIT CHAIN AUTO-REPAIR on boot: fixed ${fixed} entry hashes (was broken at index ${v.broken_at})`);
      // Append a self-signed marker entry
      const prev = state.admin_actions[0];
      const prevHash = prev ? prev.hash : '0'.repeat(64);
      const entry = {
        ts: Date.now(), admin: 'system', role: 'system',
        action: 'audit.chain_auto_repaired',
        target: '', details: `repaired ${fixed} entries on boot`,
        ip: '127.0.0.1', prev_hash: prevHash,
      };
      entry.hash = crypto.createHash('sha256').update(JSON.stringify({
        ts: entry.ts, admin: entry.admin, action: entry.action, target: entry.target, details: entry.details, prev_hash: prevHash,
      })).digest('hex');
      state.admin_actions.unshift(entry);
      saveState();
    }
  } catch (e) {
    console.error('audit chain auto-repair failed:', e.message);
  }
}, 5000);

// One-shot repair: walks oldest→newest, fixing prev_hash + hash where they don't match.
// Use after legacy data import or to recover from a manual edit.
function repairAuditChain() {
  const arr = state.admin_actions;
  let fixed = 0;
  for (let i = arr.length - 1; i >= 0; i--) {
    const e = arr[i];
    const expectedPrev = (i === arr.length - 1) ? '0'.repeat(64) : arr[i + 1].hash;
    const expectedHash = crypto.createHash('sha256').update(JSON.stringify({
      ts: e.ts, admin: e.admin, action: e.action, target: e.target, details: e.details, prev_hash: expectedPrev,
    })).digest('hex');
    if (e.prev_hash !== expectedPrev || e.hash !== expectedHash) {
      e.prev_hash = expectedPrev;
      e.hash = expectedHash;
      fixed++;
    }
  }
  return fixed;
}

// Verify the chain — returns first broken-index, or null if intact
function verifyAuditChain() {
  // newest is at [0], oldest at [n-1] — verify backwards from oldest
  const arr = state.admin_actions;
  if (!arr || arr.length === 0) return { intact: true, count: 0 };
  for (let i = arr.length - 1; i >= 0; i--) {
    const e = arr[i];
    // Genesis or post-truncation anchor → prev_hash should be zeros
    const expectedPrev = (i === arr.length - 1) ? '0'.repeat(64) : arr[i+1].hash;
    if (e.prev_hash !== expectedPrev && e.prev_hash) {
      // Tolerate legacy entries without prev_hash
      return { intact: false, broken_at: i, ts: e.ts, action: e.action };
    }
    if (e.hash) {
      const recomputed = crypto.createHash('sha256').update(JSON.stringify({
        ts: e.ts, admin: e.admin, action: e.action, target: e.target, details: e.details, prev_hash: e.prev_hash || '0'.repeat(64),
      })).digest('hex');
      if (recomputed !== e.hash) return { intact: false, broken_at: i, ts: e.ts, action: e.action, reason: 'hash mismatch' };
    }
  }
  return { intact: true, count: arr.length };
}

app.get('/admin/api/audit/verify', adminAuth, (req, res) => {
  res.json(verifyAuditChain());
});

// One-shot repair endpoint — recomputes prev_hash + hash chain forward from oldest.
// Records a special "[CHAIN REBUILT]" entry at the top noting the repair.
app.post('/admin/api/audit/repair', adminAuth, (req, res) => {
  const before = verifyAuditChain();
  if (before.intact) return res.json({ ok: true, already_intact: true, count: before.count });
  const fixed = repairAuditChain();
  // Append a rebuild-marker entry (hash chain continues from current top)
  if (fixed > 0) {
    if (typeof logAdminAction === 'function') {
      logAdminAction(req, 'audit.chain_rebuilt', '', `repaired ${fixed} entries; first break was at index ${before.broken_at}`);
    }
  }
  saveState();
  res.json({ ok: true, fixed_entries: fixed, after: verifyAuditChain() });
});

app.get('/admin/api/audit.csv', adminAuth, (req, res) => {
  const rows = state.admin_actions.map(a => ({
    ts: new Date(a.ts).toISOString(),
    admin: a.admin,
    role: a.role,
    action: a.action,
    target: a.target,
    details: a.details,
    ip: a.ip,
    hash: (a.hash || '').slice(0, 16),
    chain_intact: 'yes',  // we trust intact at export time
  }));
  // Optional date filter: ?from=YYYY-MM-DD&to=YYYY-MM-DD
  const from = req.query.from ? new Date(req.query.from).getTime() : 0;
  const to   = req.query.to   ? new Date(req.query.to).getTime() : Infinity;
  const filtered = rows.filter(r => {
    const t = new Date(r.ts).getTime();
    return t >= from && t <= to;
  });
  const csv = toCSV(filtered, ['ts','admin','role','action','target','details','ip','hash','chain_intact']);
  res.set('Content-Type', 'text/csv');
  res.set('Content-Disposition', `attachment; filename="audit-${new Date().toISOString().slice(0, 10)}.csv"`);
  res.send(csv);
});

// Helper: enqueue webhook delivery (with retries via background worker)
function fireWebhooks(eventName, payload) {
  const enabled = (state.webhooks || []).filter(h => h.enabled && (h.events.includes('*') || h.events.includes(eventName)));
  for (const h of enabled) {
    state.webhook_queue.push({
      id: 'wq-' + shortId(8),
      hook_id: h.id,
      url: h.url,
      secret: h.secret,
      template: h.template || null,
      event: eventName,
      payload,
      attempts: 0,
      next_at: Date.now(),
      created_at: Date.now(),
    });
  }
  // Cap queue size
  if (state.webhook_queue.length > 500) state.webhook_queue = state.webhook_queue.slice(-300);
}

// Worker: processes the webhook queue. Exponential backoff: 0, 30s, 2m, 10m, 1h, give up after 5 attempts.
const WEBHOOK_BACKOFF = [0, 30_000, 120_000, 600_000, 3_600_000];
// Mustache-style {{var}} substitution. Supports nested paths like {{payload.title}}.
function renderTemplate(tpl, ctx) {
  return tpl.replace(/\{\{\s*([a-zA-Z0-9_.]+)\s*\}\}/g, (_, path) => {
    let v = ctx;
    for (const part of path.split('.')) {
      if (v == null) return '';
      v = v[part];
    }
    if (v === undefined || v === null) return '';
    return typeof v === 'object' ? JSON.stringify(v) : String(v);
  });
}
// Tiny schema validator: requires top-level keys + optional type per key.
// schema example: { required: ['event','title'], types: { event: 'string', count: 'number' } }
function webhookSchemaValidates(schema, obj) {
  if (!schema) return { ok: true };
  try { if (typeof schema === 'string') schema = JSON.parse(schema); } catch { return { ok: false, error: 'invalid schema JSON' }; }
  for (const k of (schema.required || [])) {
    if (obj[k] === undefined || obj[k] === null) return { ok: false, error: `missing key: ${k}` };
  }
  for (const [k, t] of Object.entries(schema.types || {})) {
    if (obj[k] === undefined) continue;
    const got = typeof obj[k];
    if (got !== t) return { ok: false, error: `${k}: expected ${t}, got ${got}` };
  }
  return { ok: true };
}

function deliverOne(item) {
  return new Promise(resolve => {
    try {
      const ctx = { event: item.event, ts: Date.now(), payload: item.payload, attempt: item.attempts + 1 };
      // Schema validation: customer-defined; if it fails, we mark delivery failed without sending.
      if (item.schema) {
        const v = webhookSchemaValidates(item.schema, ctx);
        if (!v.ok) {
          return resolve({ ok: false, error: 'schema_violation: ' + v.error, status: 0 });
        }
      }
      let body;
      if (item.template) {
        try {
          body = renderTemplate(item.template, ctx);
        } catch { body = JSON.stringify(ctx); }
      } else {
        body = JSON.stringify(ctx);
      }
      const sig = item.secret ? crypto.createHmac('sha256', item.secret).update(body).digest('hex') : '';
      const u = new URL(item.url);
      const httpModule = u.protocol === 'https:' ? require('https') : require('http');
      const r = httpModule.request({
        method: 'POST',
        hostname: u.hostname,
        port: u.port || (u.protocol === 'https:' ? 443 : 80),
        path: u.pathname + u.search,
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
          'X-MES-Event': item.event,
          'X-MES-Signature': sig ? 'sha256=' + sig : '',
          'X-MES-Attempt': String(item.attempts + 1),
          'User-Agent': 'mes-cloud-webhook/1.1',
        },
        timeout: 8000,
      }, (res) => {
        // Drain and check status
        res.on('data', () => {});
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            console.log(`         📡 webhook OK → ${item.event} status=${res.statusCode} attempt=${item.attempts + 1}`);
            resolve({ ok: true });
          } else {
            resolve({ ok: false, error: 'HTTP ' + res.statusCode });
          }
        });
      });
      r.on('error', e => resolve({ ok: false, error: e.message }));
      r.on('timeout', () => { r.destroy(); resolve({ ok: false, error: 'timeout' }); });
      r.write(body);
      r.end();
    } catch (e) {
      resolve({ ok: false, error: e.message });
    }
  });
}

if (!state.webhook_deliveries) state.webhook_deliveries = [];   // ring buffer of recent deliveries
function recordDelivery(item, result, finalState) {
  state.webhook_deliveries.unshift({
    id: item.id,
    hook_id: item.hook_id,
    url: item.url,
    event: item.event,
    attempts: item.attempts + (result.ok ? 1 : 0),
    ok: !!result.ok,
    status: result.status || null,
    error: result.error || null,
    state: finalState,   // 'success' | 'gave_up' | 'retry'
    ts: Date.now(),
  });
  if (state.webhook_deliveries.length > 1000) state.webhook_deliveries.length = 1000;
}

async function processWebhookQueue() {
  const now = Date.now();
  for (let i = 0; i < state.webhook_queue.length; i++) {
    const item = state.webhook_queue[i];
    if (item.next_at > now) continue;
    const result = await deliverOne(item);
    if (result.ok) {
      recordDelivery(item, result, 'success');
      state.webhook_queue.splice(i, 1);
      i--;
    } else {
      item.attempts++;
      item.last_error = result.error;
      if (item.attempts >= WEBHOOK_BACKOFF.length) {
        recordDelivery(item, result, 'gave_up');
        console.log(`         ⚠ webhook GIVE UP → ${item.event} (after ${item.attempts} attempts): ${item.last_error}`);
        state.webhook_queue.splice(i, 1);
        i--;
      } else {
        item.next_at = now + WEBHOOK_BACKOFF[item.attempts];
        console.log(`         ⏳ webhook RETRY → ${item.event} attempt=${item.attempts} next in ${WEBHOOK_BACKOFF[item.attempts]/1000}s: ${item.last_error}`);
      }
    }
  }
}
setInterval(processWebhookQueue, 5000);  // every 5 seconds

// Admin: peek at queue
app.get('/admin/api/webhook-queue', (req, res, next) => adminAuth(req, res, next), (req, res) => {
  res.json({
    queued: state.webhook_queue.length,
    items: state.webhook_queue.slice(0, 30).map(i => ({
      id: i.id, hook_id: i.hook_id, event: i.event, url: i.url,
      attempts: i.attempts,
      next_in_sec: Math.max(0, Math.round((i.next_at - Date.now()) / 1000)),
      last_error: i.last_error,
      created_at: new Date(i.created_at).toISOString(),
    })),
  });
});

// Admin: anonymized fleet analytics — aggregate-only stats across all customers.
// No customer IDs leak; useful for ISP-level dashboards and investor reporting.
app.get('/admin/api/fleet-analytics', adminAuth, (req, res) => {
  const cutoff7d = Date.now() - 7 * 86400_000;
  // 1. Top blocked categories (by hit count)
  const catHits = {};
  for (const r of Object.values(state.rules || {}).flat()) {
    if (r.action !== 'block' || r.type !== 'category') continue;
    const h = (state.rule_hits && state.rule_hits[r.id] && state.rule_hits[r.id].total) || 0;
    if (!h) continue;
    catHits[r.value] = (catHits[r.value] || 0) + h;
  }
  const top_categories = Object.entries(catHits).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([cat, hits]) => ({ cat, hits }));

  // 2. Device vendor mix
  const vendorCount = {};
  let totalDevices = 0;
  for (const bucket of Object.values(state.box_devices || {})) {
    for (const d of Object.values(bucket)) {
      totalDevices++;
      const v = (d.vendor || 'unknown').slice(0, 30);
      vendorCount[v] = (vendorCount[v] || 0) + 1;
    }
  }
  const top_vendors = Object.entries(vendorCount).sort((a, b) => b[1] - a[1]).slice(0, 15)
    .map(([vendor, count]) => ({ vendor, count, pct: Math.round((count / totalDevices) * 1000) / 10 }));

  // 3. Plan distribution
  const planCount = { basic: 0, family: 0, pro: 0, business: 0 };
  let activeCustomers = 0;
  for (const c of Object.values(state.customers)) {
    if (c.status === 'archived') continue;
    activeCustomers++;
    if (planCount[c.plan] !== undefined) planCount[c.plan]++;
  }

  // 4. Box hardware mix
  const hwCount = {};
  for (const b of Object.values(state.box_state || {})) {
    if (!b.hw) continue;
    const k = b.hw.hw_model || 'unknown';
    hwCount[k] = (hwCount[k] || 0) + 1;
  }

  // 5. Country mix from heartbeats (where boxes are physically located)
  const countryCount = {};
  for (const b of Object.values(state.box_state || {})) {
    const cc = b._last_country || 'XX';
    countryCount[cc] = (countryCount[cc] || 0) + 1;
  }

  // 6. Total flows last 7 days + blocked %
  const recent7 = state.flows.filter(f => f.ts >= cutoff7d);
  const blocked7 = recent7.filter(f => f.blocked).length;

  res.json({
    generated_at: new Date().toISOString(),
    customers: { total: activeCustomers, by_plan: planCount },
    devices: { total: totalDevices, top_vendors },
    box_hardware: hwCount,
    countries: countryCount,
    rules: { top_blocked_categories: top_categories },
    flows_7d: { total: recent7.length, blocked: blocked7,
      block_rate_pct: recent7.length > 0 ? Math.round((blocked7 / recent7.length) * 1000) / 10 : 0 },
    threat_feed: {
      domain_count: (state.threat_feeds.domains || []).length,
      sources: state.threat_feeds.sources || [],
    },
  });
});

// Admin: webhook delivery dashboard — success rate, retries, recent deliveries
app.get('/admin/api/webhook-deliveries', adminAuth, (req, res) => {
  const all = state.webhook_deliveries || [];
  const cutoff24h = Date.now() - 24 * 3600_000;
  const recent24h = all.filter(d => d.ts >= cutoff24h);
  const success24 = recent24h.filter(d => d.ok).length;
  const failed24  = recent24h.filter(d => !d.ok).length;
  const total24   = recent24h.length;
  // Per-hook stats
  const byHook = {};
  for (const d of recent24h) {
    if (!byHook[d.hook_id]) byHook[d.hook_id] = { hook_id: d.hook_id, success: 0, failed: 0, gave_up: 0 };
    if (d.ok) byHook[d.hook_id].success++;
    else if (d.state === 'gave_up') byHook[d.hook_id].gave_up++;
    else byHook[d.hook_id].failed++;
  }
  const limit = Math.min(parseInt(req.query.limit || 100), 500);
  res.json({
    summary_24h: {
      total: total24, success: success24, failed: failed24,
      success_rate: total24 > 0 ? Math.round((success24 / total24) * 1000) / 10 : null,
    },
    by_hook: Object.values(byHook).sort((a, b) => (b.failed + b.gave_up) - (a.failed + a.gave_up)),
    queued: state.webhook_queue.length,
    recent: all.slice(0, limit).map(d => ({ ...d, ts_iso: new Date(d.ts).toISOString() })),
  });
});

// ═══════════════════════════════════════════════════════════════════
// CUSTOMER-FACING API (used by the PWA)
// ═══════════════════════════════════════════════════════════════════
//
// Auth model:
//   POST /api/customer/login    body { phone }                 → 200 if customer exists; sends "OTP" (mocked)
//   POST /api/customer/verify   body { phone, code }            → 200 + { token }
//   GET  /api/customer/me                                       → customer profile + boxes  (Bearer)
//   GET  /api/customer/devices                                  → mocked device list        (Bearer)
//   POST /api/customer/pause                                    → emits a customer-action   (Bearer)
//   POST /api/customer/block-device  body { mac, name }         → emits a block             (Bearer)
//
// The "OTP" in this mock is fixed at "0000" so the demo is reproducible.
// Replace with Twilio/Vonage in production.

const FIXED_OTP = '0000';

function customerJwt(customer) {
  if (!licenseKeys) {
    // fallback to base64 if no keypair (shouldn't happen)
    return Buffer.from(JSON.stringify(customer)).toString('base64url');
  }
  const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' }))
    .toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    sub: customer.id,
    name: customer.name,
    phone: customer.phone,
    plan: customer.plan,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 30 * 86400,  // 30 days
  })).toString('base64url');
  const signature = crypto.sign(null, Buffer.from(header + '.' + payload), licenseKeys.privateKey)
    .toString('base64url');
  return `${header}.${payload}.${signature}`;
}

function verifyCustomerJwt(token) {
  if (!licenseKeys || !token) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const [h, p, s] = parts;
    const ok = crypto.verify(null,
      Buffer.from(h + '.' + p),
      licenseKeys.publicKey,
      Buffer.from(s, 'base64url'));
    if (!ok) return null;
    const payload = JSON.parse(Buffer.from(p, 'base64url').toString());
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    // Session revocation: customer can invalidate all tokens issued before their _jwt_min_iat
    const c = state.customers && state.customers[payload.sub];
    if (c && c._jwt_min_iat && payload.iat && payload.iat < c._jwt_min_iat) return null;
    return payload;
  } catch { return null; }
}

function customerAuth(req, res, next) {
  // Try API key path first
  const apiKey = req.headers['x-api-key'];
  if (apiKey) {
    const k = state.customer_api_keys && state.customer_api_keys[apiKey];
    if (k) {
      const c = state.customers[k.customer_id];
      if (!c) return res.status(401).json({ error: 'customer not found' });
      if (k.scope === 'read' && req.method !== 'GET') return res.status(403).json({ error: 'read-only api key cannot mutate' });
      k.last_used_at = Date.now();
      req.customer = c;
      req.apiKey = apiKey;
      _recordCustomerAudit(req);
      return _customerRateLimitInline(req, res, next);
    }
    return res.status(401).json({ error: 'invalid api key' });
  }
  // JWT path — Authorization header preferred; ?token= query param accepted on GET only
  // (used by EventSource which can't set custom headers)
  const auth = req.headers.authorization || '';
  let bearer = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!bearer && req.method === 'GET' && req.query && req.query.token) {
    bearer = String(req.query.token);
  }
  if (!bearer) return res.status(401).json({ error: 'no token' });
  const payload = verifyCustomerJwt(bearer);
  if (!payload) return res.status(401).json({ error: 'invalid or expired token' });
  const customer = state.customers[payload.sub];
  if (!customer) return res.status(404).json({ error: 'customer no longer exists' });
  // family_share JWT is read-only — block mutations
  if (payload.family_share && req.method !== 'GET' && req.method !== 'HEAD') {
    return res.status(403).json({ error: 'read_only_share', message: 'Family-share access is read-only.' });
  }
  req.customer = customer;
  req.familyShare = !!payload.family_share;
  _recordCustomerAudit(req);
  return _customerRateLimitInline(req, res, next);
}

// ─── Per-customer audit log ───────────────────────────────────────────────
// Records every mutation a customer performs. Read in /api/customer/audit.
function _recordCustomerAudit(req) {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') return;
  if (!state.customer_audit) state.customer_audit = {};
  const cid = req.customer.id;
  if (!state.customer_audit[cid]) state.customer_audit[cid] = [];
  state.customer_audit[cid].push({
    ts: Date.now(),
    method: req.method,
    path: req.path,
    ip: (req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim(),
    via: req.apiKey ? 'api_key' : 'jwt',
  });
  // Cap at 500 per customer
  if (state.customer_audit[cid].length > 500) {
    state.customer_audit[cid] = state.customer_audit[cid].slice(-300);
  }
}

// Inline rate-limiter — defined here so customerAuth can use it without forward ref issues
function _customerRateLimitInline(req, res, next) {
  if (!req.customer) return next();
  if (typeof PLAN_RATE_LIMITS === 'undefined') return next();   // before that block loads
  // Admin can exempt a customer from rate limiting (e.g. during diagnostic windows).
  if (req.customer.rate_limit_exempt) {
    res.set('X-RateLimit-Limit', 'unlimited');
    return next();
  }
  const cid = req.customer.id;
  const now = Date.now();
  const limit = PLAN_RATE_LIMITS[req.customer.plan] || 60;
  if (!_custRateBuckets) _custRateBuckets = new Map();
  let b = _custRateBuckets.get(cid);
  if (!b || b.resetAt < now) {
    b = { count: 0, resetAt: now + 60_000 };
    _custRateBuckets.set(cid, b);
  }
  b.count++;
  res.set('X-RateLimit-Limit', limit);
  res.set('X-RateLimit-Remaining', Math.max(0, limit - b.count));
  res.set('X-RateLimit-Reset', Math.ceil(b.resetAt / 1000));
  if (b.count > limit) {
    res.set('Retry-After', Math.ceil((b.resetAt - now) / 1000));
    return res.status(429).json({ error: 'rate_limited', limit_per_min: limit, plan: req.customer.plan });
  }
  next();
}
let _custRateBuckets = null;
let PLAN_RATE_LIMITS;

function findCustomerByPhone(phone) {
  // Normalize: strip whitespace, keep + and digits
  const norm = (phone || '').replace(/[^\d+]/g, '');
  return Object.values(state.customers).find(c => {
    return (c.phone || '').replace(/[^\d+]/g, '') === norm;
  });
}

// ─── Email — try nodemailer SMTP first, fall back to local sendmail ───
let _nodemailer = null;
try { _nodemailer = require('nodemailer'); } catch { /* nodemailer not installed; fallback to sendmail */ }

let _smtpTransport = null;
function _getSmtpTransport() {
  if (!_nodemailer) return null;
  const cfg = state.config.smtp || {};
  if (!cfg.host || !cfg.port) return null;
  if (_smtpTransport && _smtpTransport._cfgKey === cfg.host + cfg.port + (cfg.user || '')) return _smtpTransport;
  try {
    _smtpTransport = _nodemailer.createTransport({
      host: cfg.host,
      port: parseInt(cfg.port, 10),
      secure: !!cfg.secure,
      auth: cfg.user ? { user: cfg.user, pass: cfg.pass || '' } : undefined,
    });
    _smtpTransport._cfgKey = cfg.host + cfg.port + (cfg.user || '');
    return _smtpTransport;
  } catch (e) {
    console.error('smtp transport init failed:', e.message);
    return null;
  }
}

async function sendEmailViaSmtp(to, subject, body) {
  const t = _getSmtpTransport();
  if (!t) return { ok: false, error: 'smtp_not_configured_or_nodemailer_missing' };
  try {
    const from = (state.config.smtp && state.config.smtp.from) || state.config.email_from || 'noreply@mes.net.lb';
    const info = await t.sendMail({ from, to, subject, text: body });
    return { ok: true, message_id: info.messageId };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

function sendEmail(to, subject, body) {
  if (!to) return;
  if (!state.config.email_enabled) return;  // gated by admin config
  // 1) Try SMTP via nodemailer first
  if (_nodemailer && state.config.smtp && state.config.smtp.host) {
    sendEmailViaSmtp(to, subject, body).then(r => {
      if (r.ok) console.log(`         ✉ EMAIL (smtp) → ${to} "${subject}"`);
      else console.error('smtp send failed:', r.error);
    });
    return;
  }
  // 2) Fall back to local sendmail
  try {
    const sm = spawn('sendmail', ['-t', '-f', state.config.email_from || 'noreply@mes.net.lb'], {
      stdio: ['pipe', 'ignore', 'ignore'],
    });
    sm.on('error', () => {});  // sendmail not installed → silently no-op
    sm.stdin.write(
`To: ${to}
From: ${state.config.email_from || 'noreply@mes.net.lb'}
Subject: ${subject}
Content-Type: text/plain; charset=UTF-8
MIME-Version: 1.0

${body}
`);
    sm.stdin.end();
    console.log(`         ✉ EMAIL (sendmail) → ${to} "${subject}"`);
  } catch (e) {
    console.error('sendmail failed:', e.message);
  }
}

// ─── Login rate limiter (in-memory, sliding window) ───
const loginAttempts = new Map();  // ip → { count, firstAt }
const LOGIN_WINDOW_MS = 10 * 60 * 1000;  // 10 minutes
const LOGIN_MAX_ATTEMPTS = 5;

function checkRateLimit(ip) {
  const now = Date.now();
  const rec = loginAttempts.get(ip);
  if (rec && now - rec.firstAt > LOGIN_WINDOW_MS) {
    loginAttempts.delete(ip);
    return { allowed: true, remaining: LOGIN_MAX_ATTEMPTS };
  }
  if (rec && rec.count >= LOGIN_MAX_ATTEMPTS) {
    return { allowed: false, retry_after_sec: Math.round((LOGIN_WINDOW_MS - (now - rec.firstAt)) / 1000) };
  }
  return { allowed: true, remaining: LOGIN_MAX_ATTEMPTS - (rec ? rec.count : 0) };
}

function recordFailure(ip) {
  const now = Date.now();
  const rec = loginAttempts.get(ip);
  if (!rec) loginAttempts.set(ip, { count: 1, firstAt: now });
  else rec.count++;
}

// Cleanup expired records every minute
setInterval(() => {
  const now = Date.now();
  for (const [ip, rec] of loginAttempts.entries()) {
    if (now - rec.firstAt > LOGIN_WINDOW_MS) loginAttempts.delete(ip);
  }
}, 60_000);

// Map a notification (kind, title) to a category for prefs filtering
function notificationCategory(kind, title) {
  const t = (title || '').toLowerCase();
  if (kind === 'warn' && (t.includes('offline') || t.includes('alarm') || t.includes('block') || t.includes('intel'))) return 'security';
  if (t.includes('schedule') || t.includes('family') || t.includes('kid') || t.includes('pause')) return 'family';
  if (t.includes('invoice') || t.includes('payment') || t.includes('paid')) return 'billing';
  if (kind === 'system' || t.includes('approval') || t.includes('account')) return 'system';
  return 'system';
}

// Helper: push an in-app notification (also dispatches a Web Push if subscribed)
// Notification text translations (en + ar)
const NOTIF_I18N = {
  en: {
    'Welcome to mes Network': 'Welcome to mes Network',
    'Internet paused for 1 hour': 'Internet paused for 1 hour',
    'New device joined': 'New device on your network',
    'Box online': 'Your box is online',
    'Plan upgraded': 'Plan upgraded',
    'Plan request declined': 'Plan request declined',
    'Vacation mode on': 'Vacation mode on',
    'Vacation mode off': 'Vacation mode off',
    'WireGuard peer created': 'WireGuard peer created',
    'Box order update': 'Box order update',
    '✓ Network back online': '✓ Network back online',
    'New box added': 'New box added',
    'Possible internet outage at your home': 'Possible internet outage at your home',
    'Box moved to a new country': 'Box moved to a new country',
    'Heavy data transfer detected': 'Heavy data transfer detected',
    'Possible port scan from your network': 'Possible port scan from your network',
    'Bandwidth 80% used': 'Bandwidth 80% used',
    'Bandwidth 90% used': 'Bandwidth 90% used',
    'Bandwidth 100% used': 'Bandwidth 100% used',
    'Box is offline': 'Your mes Box is offline',
    'Box is overheating': 'Box is overheating',
    'Box memory pressure': 'Box memory pressure',
    'Box CPU is busy': 'Box CPU is busy',
    'Rule added': 'Rule added',
  },
  ar: {
    'Welcome to mes Network': 'مرحبًا في شبكة mes',
    'Internet paused for 1 hour': 'تم إيقاف الإنترنت لساعة',
    'New device joined': 'جهاز جديد على شبكتك',
    'Box online': 'الجهاز متصل',
    'Plan upgraded': 'تم ترقية الباقة',
    'Plan request declined': 'تم رفض طلب تغيير الباقة',
    'Vacation mode on': 'وضع العطلة مفعّل',
    'Vacation mode off': 'وضع العطلة معطّل',
    'WireGuard peer created': 'تم إنشاء WireGuard peer',
    'Box order update': 'تحديث على طلب الجهاز',
    '✓ Network back online': '✓ الشبكة عادت',
    'New box added': 'تمت إضافة جهاز جديد',
    'Possible internet outage at your home': 'انقطاع محتمل للإنترنت في منزلك',
    'Box moved to a new country': 'انتقل الجهاز إلى دولة جديدة',
    'Heavy data transfer detected': 'تم رصد نقل بيانات كثيف',
    'Possible port scan from your network': 'محاولة scan على شبكتك',
    'Bandwidth 80% used': 'تم استخدام 80% من الحصة',
    'Bandwidth 90% used': 'تم استخدام 90% من الحصة',
    'Bandwidth 100% used': 'تم استخدام 100% من الحصة',
    'Box is offline': 'الجهاز غير متصل',
    'Box is overheating': 'الجهاز يسخن أكثر من اللازم',
    'Box memory pressure': 'ضغط على ذاكرة الجهاز',
    'Box CPU is busy': 'معالج الجهاز مشغول',
    'Rule added': 'تمت إضافة قاعدة',
  },
};
function localizeNotif(customer_id, title) {
  const c = state.customers[customer_id];
  const lang = (c && c.preferred_lang) || 'en';
  if (!NOTIF_I18N[lang] || !NOTIF_I18N[lang][title]) return title;
  return NOTIF_I18N[lang][title];
}

// Customer can set their preferred language (used for notifs + emails)
app.post('/api/customer/preferred-lang', customerAuth, (req, res) => {
  const lang = String(req.body.lang || 'en').toLowerCase().slice(0, 5);
  if (!['en','ar'].includes(lang)) return res.status(400).json({ error: 'unsupported lang' });
  state.customers[req.customer.id].preferred_lang = lang;
  saveState();
  res.json({ ok: true, lang });
});

// Customer theme preference (auto/dark/light) — PWA reads on login.
app.get('/api/customer/preferences', customerAuth, (req, res) => {
  const c = req.customer;
  res.json({
    lang: c.preferred_lang || 'en',
    theme: c.preferred_theme || 'auto',
    density: c.preferred_density || 'normal',
    timezone: c.preferred_timezone || 'Asia/Beirut',
  });
});
app.post('/api/customer/preferences', customerAuth, (req, res) => {
  const c = state.customers[req.customer.id];
  if (req.body.theme !== undefined) {
    const t = String(req.body.theme).toLowerCase();
    if (!['auto', 'dark', 'light'].includes(t)) return res.status(400).json({ error: 'theme must be auto|dark|light' });
    c.preferred_theme = t;
  }
  if (req.body.density !== undefined) {
    const d = String(req.body.density).toLowerCase();
    if (!['compact', 'normal', 'comfortable'].includes(d)) return res.status(400).json({ error: 'density must be compact|normal|comfortable' });
    c.preferred_density = d;
  }
  if (req.body.timezone !== undefined) {
    const tz = String(req.body.timezone).slice(0, 60);
    // Quick sanity check: Intl.supportedValuesOf if available, else allow common formats
    try {
      new Intl.DateTimeFormat('en', { timeZone: tz });
      c.preferred_timezone = tz;
    } catch { return res.status(400).json({ error: 'invalid timezone' }); }
  }
  saveState();
  res.json({ ok: true, theme: c.preferred_theme, density: c.preferred_density, timezone: c.preferred_timezone });
});

function pushNotification(customer_id, kind, title, body) {
  // Localize title/body to customer's preferred language
  title = localizeNotif(customer_id, title);
  // Check customer's notification preferences
  const prefs = state.notif_prefs[customer_id] || {};
  const category = notificationCategory(kind, title);
  if (prefs[category] === false) {
    console.log(`         🔕 notif suppressed (category=${category} muted) → ${customer_id}`);
    return null;
  }
  // Quiet hours — only suppress non-critical (skip security/critical)
  if (prefs.quiet_start && prefs.quiet_end && category !== 'security') {
    const now = new Date();
    const hhmm = now.getHours().toString().padStart(2,'0') + ':' + now.getMinutes().toString().padStart(2,'0');
    const inWindow = prefs.quiet_start <= prefs.quiet_end
      ? (hhmm >= prefs.quiet_start && hhmm < prefs.quiet_end)
      : (hhmm >= prefs.quiet_start || hhmm < prefs.quiet_end);  // wraps midnight
    if (inWindow) {
      console.log(`         🌙 quiet hours suppress → ${customer_id} (${prefs.quiet_start}-${prefs.quiet_end})`);
      // Still log the in-app notification, just don't web-push
      if (!state.notifications[customer_id]) state.notifications[customer_id] = [];
      state.notifications[customer_id].unshift({
        id: 'notif-' + shortId(8), kind: kind || 'info', title, body,
        ts: Date.now(), read: false, suppressed_quiet: true,
      });
      saveState();
      return null;
    }
  }

  if (!state.notifications[customer_id]) state.notifications[customer_id] = [];
  const n = {
    id: 'notif-' + shortId(8),
    kind: kind || 'info',  // info | warn | success | system
    title: title || '',
    body: body || '',
    ts: Date.now(),
    read: false,
  };
  state.notifications[customer_id].unshift(n);
  if (state.notifications[customer_id].length > 100) {
    state.notifications[customer_id] = state.notifications[customer_id].slice(0, 100);
  }

  // Email delivery — if customer has email + email channel enabled for this category
  try {
    const emailAllowed = (typeof notifChannelEnabled === 'function')
      ? notifChannelEnabled(customer_id, category, 'email') : false;
    const cust = state.customers && state.customers[customer_id];
    if (emailAllowed && cust && cust.email && state.config.email_enabled) {
      sendEmail(cust.email, '[mes] ' + (title || 'Notification'), (body || '') + '\n');
    }
  } catch {}

  // Web Push delivery to all this customer's subscribed browsers
  // Gated on per-channel push flag (default on).
  const pushAllowed = (typeof notifChannelEnabled === 'function')
    ? notifChannelEnabled(customer_id, category, 'push') : true;
  const subs = pushAllowed ? (state.push_subscriptions[customer_id] || []) : [];
  if (subs.length && vapidKeys) {
    const payload = JSON.stringify({ title, body, kind, ts: n.ts, url: '/pwa/' });
    for (const sub of [...subs]) {
      sendWebPush(sub, payload).then(result => {
        if (!result.ok) {
          // 404/410 = subscription expired, remove it
          if (result.status === 404 || result.status === 410) {
            state.push_subscriptions[customer_id] =
              (state.push_subscriptions[customer_id] || []).filter(s => s.id !== sub.id);
            console.log(`         🔕 push subscription expired/removed: ${sub.id}`);
          } else {
            console.log(`         ⚠ web push failed: ${sub.id} → ${result.error || result.status}`);
          }
        } else {
          console.log(`         🔔 web push OK → customer=${customer_id} status=${result.status}`);
        }
      });
    }
  }

  return n;
}

// Signup rate limit: 3 signups per IP per hour
const signupAttempts = new Map();  // ip → { count, firstAt }
const SIGNUP_WINDOW_MS = 60 * 60 * 1000;
const SIGNUP_MAX = 3;
setInterval(() => {
  const now = Date.now();
  for (const [ip, rec] of signupAttempts.entries()) {
    if (now - rec.firstAt > SIGNUP_WINDOW_MS) signupAttempts.delete(ip);
  }
}, 60_000);

// POST /api/customer/signup — public; creates a customer record (pending or active depending on config)
app.post('/api/customer/signup', (req, res) => {
  if (!state.config.signup_enabled) {
    return res.status(403).json({ error: 'self-signup is disabled' });
  }
  // Rate-limit per IP
  const ip = req.ip;
  const now = Date.now();
  const rec = signupAttempts.get(ip);
  if (rec && now - rec.firstAt > SIGNUP_WINDOW_MS) signupAttempts.delete(ip);
  const cur = signupAttempts.get(ip);
  if (cur && cur.count >= SIGNUP_MAX) {
    return res.status(429).json({
      error: 'too many signups from this IP — try again later',
      retry_after_sec: Math.round((SIGNUP_WINDOW_MS - (now - cur.firstAt)) / 1000),
    });
  }
  if (!cur) signupAttempts.set(ip, { count: 1, firstAt: now });
  else cur.count++;
  const phone = (req.body.phone || '').trim();
  const name = (req.body.name || '').trim();
  if (!phone || !name) return res.status(400).json({ error: 'name and phone required' });
  if (findCustomerByPhone(phone)) return res.status(409).json({ error: 'phone already registered — please sign in' });

  const id = 'cust-' + shortId(8);
  const status = state.config.auto_approve_signups ? 'active' : 'pending';
  state.customers[id] = {
    id,
    name,
    phone,
    email: (req.body.email || '').trim(),
    plan: req.body.plan || 'basic',
    address: (req.body.address || '').trim(),
    notes: (req.body.notes || '').trim(),
    status,
    self_signup: true,
    // Capture UTM / acquisition source if provided
    utm: {
      source:   String(req.body.utm_source   || '').slice(0, 60),
      medium:   String(req.body.utm_medium   || '').slice(0, 60),
      campaign: String(req.body.utm_campaign || '').slice(0, 60),
      content:  String(req.body.utm_content  || '').slice(0, 60),
      term:     String(req.body.utm_term     || '').slice(0, 60),
      referrer: String(req.body.referrer     || req.headers.referer || '').slice(0, 200),
    },
    created_at: new Date().toISOString(),
  };
  // Auto-enroll new self-signups in 14-day trial
  if (state.config.trial_days_default !== 0) {
    const trialDays = state.config.trial_days_default || 14;
    state.customers[id].trial_until = Date.now() + trialDays * 24 * 3600_000;
    state.customers[id].trial_status = 'active';
  }
  // Generate the new customer's own referral code
  state.customers[id].referral_code = 'MES-' + shortId(6).toUpperCase();
  // Process inbound referral if they signed up with a code
  const inboundCode = String(req.body.referral_code || '').toUpperCase().trim();
  if (inboundCode) {
    const referrer = Object.values(state.customers).find(c => c.referral_code === inboundCode && c.id !== id);
    if (referrer) {
      state.customers[id].referred_by = referrer.id;
      // Credit referrer with 1 month free
      if (!referrer.referral_credits) referrer.referral_credits = 0;
      referrer.referral_credits++;
      if (!state.customers[id].referral_signup_at) state.customers[id].referral_signup_at = Date.now();
      pushNotification(referrer.id, 'billing', '🎁 You got a free month!',
        `${state.customers[id].name} signed up with your referral code. Your next month is on us.`);
      console.log(`         🎁 REFERRAL → ${state.customers[id].name} via ${referrer.name}`);
      fireWebhooks('customer.referred', { referrer_id: referrer.id, new_customer_id: id });
    }
  }
  recordToSAcceptance(id);
  saveState();

  state.events.push({ ts: Date.now(), method: 'CUSTOMER', path: `[SIGNUP] ${name} (${phone}) → ${status}`, ip: req.ip });
  console.log(`         🆕 SIGNUP → ${name} (${phone})  status=${status}`);
  fireWebhooks('customer.signup', { customer: state.customers[id] });

  pushNotification(id, 'system', 'Welcome to mes Network',
    status === 'active'
      ? 'Your account is active. Plug in your box and we\'ll have you online in a minute.'
      : 'Your signup is being reviewed by our team. We\'ll notify you when approved.');

  // Email customer
  if (state.customers[id].email) {
    sendEmail(state.customers[id].email, 'Welcome to mes Network',
      `Hi ${name},\n\n${status === 'active'
        ? 'Your account is active. Plug in your box and you should be online within a minute.'
        : 'Thanks for signing up — your account is being reviewed by our team. We\'ll email you when approved.'}\n\n` +
      `If you need help, reply to this email.\n\nmes Network team`);
  }
  // Email admin
  sendEmail(state.config.admin_email, 'New signup: ' + name,
    `Phone: ${phone}\nEmail: ${state.customers[id].email || '(none)'}\nPlan: ${state.customers[id].plan}\nStatus: ${status}\nCustomer ID: ${id}\n`);

  res.json({
    ok: true,
    status,
    message: status === 'active' ? 'Welcome! You can sign in now.' : 'Pending approval.',
  });
});

// POST /api/customer/login
app.post('/api/customer/login', (req, res) => {
  const ip = req.ip;
  const limit = checkRateLimit(ip);
  if (!limit.allowed) {
    return res.status(429).json({ error: 'too many attempts — try again later', retry_after_sec: limit.retry_after_sec });
  }
  const phone = (req.body.phone || '').trim();
  const customer = findCustomerByPhone(phone);
  if (!customer) {
    recordFailure(ip);
    return res.status(404).json({ error: 'phone not registered' });
  }
  if (customer.status === 'pending') return res.status(403).json({ error: 'account pending approval — please wait' });
  if (customer.status === 'suspended') return res.status(403).json({ error: 'account suspended — contact support' });
  console.log(`         ✓ customer LOGIN INIT → ${phone} (${customer.name})`);
  res.json({ ok: true, message: 'Code sent (demo: use 0000)' });
});

// Magic-link login — alternative to phone+OTP (email-based)
if (!state.magic_links) state.magic_links = {};   // { token: { customer_id, expires_at, used_at } }

app.post('/api/customer/login/magic', (req, res) => {
  const ip = req.ip;
  const limit = checkRateLimit(ip);
  if (!limit.allowed) return res.status(429).json({ error: 'too many attempts' });

  const email = String(req.body.email || '').trim().toLowerCase();
  if (!email) return res.status(400).json({ error: 'email required' });
  // Find customer by email (case-insensitive)
  const customer = Object.values(state.customers).find(c => (c.email || '').toLowerCase() === email);
  if (!customer) {
    // Don't leak which emails exist
    return res.json({ ok: true, message: 'If that email is registered, a login link has been sent.' });
  }
  const token = crypto.randomBytes(24).toString('base64url');
  state.magic_links[token] = {
    customer_id: customer.id,
    expires_at: Date.now() + 15 * 60_000,   // 15 min
    used_at: null,
  };
  saveState();
  // Clean up old links periodically
  for (const [t, m] of Object.entries(state.magic_links)) {
    if (m.expires_at < Date.now() - 86400_000) delete state.magic_links[t];
  }
  const baseUrl = state.config.brand_domain ? 'https://' + state.config.brand_domain : '';
  const link = `${baseUrl}/api/customer/login/magic/claim?t=${token}`;
  sendEmail(customer.email, '[mes Network] Your login link',
    `Hi ${customer.name},\n\nClick to sign in (valid 15 minutes):\n\n${link}\n\nIf you didn't request this, ignore this email.\n\nmes Network team`);
  console.log(`         🔗 magic link sent → ${customer.name} (${customer.email})`);
  res.json({ ok: true, message: 'Login link sent. Check your email.' });
});

app.get('/api/customer/login/magic/claim', (req, res) => {
  const token = String(req.query.t || '');
  const m = state.magic_links[token];
  if (!m) return res.status(404).type('html').send('<h1>Invalid or expired link.</h1>');
  if (m.expires_at < Date.now()) return res.status(410).type('html').send('<h1>Link expired.</h1> Request a new one from the sign-in page.');
  if (m.used_at) return res.status(410).type('html').send('<h1>Link already used.</h1>');
  const customer = state.customers[m.customer_id];
  if (!customer) return res.status(404).type('html').send('<h1>Account no longer exists.</h1>');
  m.used_at = Date.now();
  saveState();
  // Issue a JWT and redirect into PWA with it as fragment (#token=…)
  const jwt = customerJwt(customer);
  res.type('html').send(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Signing you in…</title></head>
<body><script>
  localStorage.setItem('mes_token', ${JSON.stringify(jwt)});
  location.href = '/pwa/';
</script>
<noscript>Click <a href="/pwa/?magic=${encodeURIComponent(jwt)}">here</a> to continue.</noscript>
</body></html>`);
});

// POST /api/customer/verify
app.post('/api/customer/verify', (req, res) => {
  const ip = req.ip;
  const limit = checkRateLimit(ip);
  if (!limit.allowed) {
    return res.status(429).json({ error: 'too many attempts — try again later', retry_after_sec: limit.retry_after_sec });
  }
  const phone = (req.body.phone || '').trim();
  const code = (req.body.code || '').trim();
  const customer = findCustomerByPhone(phone);
  if (code !== FIXED_OTP) {
    recordFailure(ip);
    return res.status(401).json({ error: 'wrong code' });
  }
  if (!customer) {
    recordFailure(ip);
    return res.status(404).json({ error: 'phone not registered' });
  }

  // Trusted-IP allowlist: if non-empty, only those IPs can log in.
  if (Array.isArray(customer.login_ip_allowlist) && customer.login_ip_allowlist.length > 0) {
    const reqIp = (ip || '').replace(/^::ffff:/, '');
    if (!customer.login_ip_allowlist.some(c => _ipInCidr(reqIp, c))) {
      console.log(`         🚫 LOGIN-IP-DENIED → ${customer.name} from ${reqIp}`);
      return res.status(403).json({ error: 'ip_not_allowed', message: 'Your IP is not in the account allowlist.' });
    }
  }
  // If customer has 2FA enabled, require the second factor (or a recovery code)
  if (customer.totp_secret) {
    const totp = (req.body.totp || '').trim();
    const recovery = (req.body.recovery || '').trim();
    if (!totp && !recovery) {
      return res.status(401).json({ error: '2fa_required', message: 'TOTP code or recovery code required' });
    }
    let ok = false;
    if (totp && totpVerify(customer.totp_secret, totp, 1)) ok = true;
    else if (recovery) {
      const h = crypto.createHash('sha256').update(recovery).digest('hex');
      const idx = (customer.totp_recovery_hashes || []).indexOf(h);
      if (idx >= 0) {
        customer.totp_recovery_hashes.splice(idx, 1);   // single-use
        ok = true;
      }
    }
    if (!ok) {
      recordFailure(ip);
      return res.status(401).json({ error: 'wrong 2fa code or recovery' });
    }
  }

  loginAttempts.delete(ip);
  const token = customerJwt(customer);

  // Record successful login
  if (!state.customer_logins[customer.id]) state.customer_logins[customer.id] = [];
  state.customer_logins[customer.id].push({
    ts: Date.now(), ip, ua: req.headers['user-agent'] || '', success: true,
  });
  if (state.customer_logins[customer.id].length > 100) {
    state.customer_logins[customer.id] = state.customer_logins[customer.id].slice(-100);
  }

  console.log(`         ★ customer VERIFIED → ${customer.name}`);
  res.json({ ok: true, token, customer: { id: customer.id, name: customer.name, plan: customer.plan } });
});

// Customer 2FA setup
app.post('/api/customer/2fa/setup', customerAuth, (req, res) => {
  const c = req.customer;
  const secret = crypto.randomBytes(20);
  const b32 = base32Encode(secret);
  c._pending_totp = b32;
  saveState();
  const issuer = encodeURIComponent(state.config.brand_name || 'mes Network');
  const account = encodeURIComponent(c.phone);
  res.json({
    secret: b32,
    otpauth_url: `otpauth://totp/${issuer}:${account}?secret=${b32}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`,
  });
});

app.post('/api/customer/2fa/verify', customerAuth, (req, res) => {
  const c = req.customer;
  if (!c._pending_totp) return res.status(400).json({ error: 'run /setup first' });
  if (!totpVerify(c._pending_totp, String(req.body.code || ''), 1)) {
    return res.status(401).json({ error: 'wrong code' });
  }
  c.totp_secret = c._pending_totp;
  delete c._pending_totp;
  // Generate 8 single-use recovery codes (formatted abcd-efgh-ijkl)
  const codes = [];
  for (let i = 0; i < 8; i++) {
    const raw = crypto.randomBytes(8).toString('hex');
    codes.push(`${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}`);
  }
  // Store hashes only (don't keep cleartext) so a state.json leak doesn't reveal codes
  c.totp_recovery_hashes = codes.map(c => crypto.createHash('sha256').update(c).digest('hex'));
  saveState();
  pushNotification(c.id, 'system', '🔐 2FA enabled', 'Your account is now protected with two-factor authentication. Save your recovery codes!');
  // Return the cleartext codes ONCE — the user must save them now
  res.json({ ok: true, recovery_codes: codes, save_now: 'These codes are shown once. Store them somewhere safe.' });
});
app.post('/api/customer/2fa/disable', customerAuth, (req, res) => {
  const c = state.customers[req.customer.id];
  if (!c.totp_secret) return res.status(400).json({ error: '2fa_not_enabled' });
  // Require current TOTP or recovery code as proof
  const code = String(req.body.code || '').trim();
  const recovery = String(req.body.recovery || '').trim();
  let ok = false;
  if (code && totpVerify(c.totp_secret, code, 1)) ok = true;
  else if (recovery) {
    const h = crypto.createHash('sha256').update(recovery).digest('hex');
    const idx = (c.totp_recovery_hashes || []).indexOf(h);
    if (idx >= 0) { c.totp_recovery_hashes.splice(idx, 1); ok = true; }
  }
  if (!ok) return res.status(401).json({ error: 'wrong_code_or_recovery' });
  delete c.totp_secret;
  delete c.totp_recovery_hashes;
  saveState();
  pushNotification(c.id, 'security', '🔓 2FA disabled', 'Two-factor auth was turned off on your account.');
  res.json({ ok: true });
});
// Regenerate recovery codes (requires TOTP code)
app.post('/api/customer/2fa/recovery-regenerate', customerAuth, (req, res) => {
  const c = state.customers[req.customer.id];
  if (!c.totp_secret) return res.status(400).json({ error: '2fa_not_enabled' });
  if (!totpVerify(c.totp_secret, String(req.body.code || ''), 1)) return res.status(401).json({ error: 'wrong_code' });
  const codes = [];
  for (let i = 0; i < 8; i++) {
    const raw = crypto.randomBytes(8).toString('hex');
    codes.push(`${raw.slice(0,4)}-${raw.slice(4,8)}-${raw.slice(8,12)}-${raw.slice(12,16)}`);
  }
  c.totp_recovery_hashes = codes.map(x => crypto.createHash('sha256').update(x).digest('hex'));
  saveState();
  res.json({ ok: true, recovery_codes: codes });
});

app.post('/api/customer/2fa/disable', customerAuth, (req, res) => {
  const c = req.customer;
  delete c.totp_secret;
  delete c._pending_totp;
  saveState();
  res.json({ ok: true });
});

// Customer login history
app.get('/api/customer/login-history', customerAuth, (req, res) => {
  const list = (state.customer_logins[req.customer.id] || []).slice().reverse().slice(0, 30);
  res.json({ logins: list });
});

// GET /api/customer/me
app.get('/api/customer/me', customerAuth, (req, res) => {
  const c = req.customer;
  const boxes = Object.values(state.authorized_macs).filter(m => m.customer_id === c.id).map(m => ({
    mac: m.mac,
    type: m.type,
    license_issued: !!state.issued_licenses[m.mac],
    paired: Object.values(state.groups).some(g =>
      (g.eids instanceof Set ? g.eids.has(m.mac) : (g.eids || []).includes(m.mac))
    ),
  }));
  // Strip admin-only fields before returning to the customer
  const { staff_notes, ...safeCustomer } = c;
  res.json({
    customer: safeCustomer,
    boxes,
    plan_limits: planLimits(c.plan),
    plan_usage: {
      family_members: (state.family_members[c.id] || []).length,
      schedules: (state.schedules[c.id] || []).length,
    },
  });
});

// Deterministic 24-point sparkline for a MAC (for demo charts)
function fakeUsage24h(mac, scaleFactor = 1) {
  // Stable seeded series so the chart doesn't flicker on every refresh
  const seed = mac.split('').reduce((a, c) => (a * 31 + c.charCodeAt(0)) >>> 0, 5381);
  const rng = (i) => ((seed * 9301 + i * 49297) % 233280) / 233280;
  return Array.from({ length: 24 }, (_, i) => {
    // Higher in evenings (peak 20:00-23:00), lower in early morning
    const hour = (new Date().getHours() - 23 + i + 24) % 24;
    const peak = hour >= 19 && hour <= 23 ? 0.9 : hour >= 6 && hour <= 9 ? 0.5 : 0.2;
    return Math.round((rng(i) * peak * 50 + 5) * scaleFactor);  // MB
  });
}

// GET /api/customer/devices — devices on the customer's box
// In a real system this would RPC the actual Navy. We return a deterministic mocked list keyed off the MAC.
app.get('/api/customer/devices', customerAuth, (req, res) => {
  const c = req.customer;
  const myBoxes = Object.values(state.authorized_macs).filter(m => m.customer_id === c.id);
  if (!myBoxes.length) return res.json({ devices: [], message: 'No box assigned' });

  // Real devices reported by the customer's box(es) via POST /api/box/devices.
  // Merge across boxes (deduped by MAC, last-seen wins on conflict).
  const realByMac = {};
  for (const b of myBoxes) {
    const bucket = state.box_devices[b.mac] || {};
    for (const d of Object.values(bucket)) {
      const prev = realByMac[d.mac];
      if (!prev || (d.last_seen || 0) > (prev.last_seen || 0)) realByMac[d.mac] = d;
    }
  }
  const realDevices = Object.values(realByMac);
  // Map box-stored shape → PWA-expected shape, computing a friendly "last seen" string.
  const fmtAge = ms => {
    if (ms < 60_000) return 'now';
    if (ms < 3600_000) return Math.round(ms / 60_000) + ' min';
    if (ms < 86_400_000) return Math.round(ms / 3600_000) + 'h';
    return Math.round(ms / 86_400_000) + 'd';
  };
  const now = Date.now();
  let devices;
  if (realDevices.length) {
    const ONLINE_CUTOFF_MS = 10 * 60 * 1000;
    // Build set of MAC-blocked addresses from rules. The PWA "Block" button
    // creates `{type:'mac', action:'block'}` rules — they don't flip the
    // `box_devices[].blocked` field, so the device list needs to check both
    // signals. (Previously: device blocked via rule → didn't show as blocked
    // in the list / filter chip, even though enforcement was working.)
    const blockedMacsFromRules = new Set();
    for (const r of (state.rules[c.id] || [])) {
      if (r.action === 'block' && r.type === 'mac' && r.value && r.enabled !== false) {
        if (!r.expires_at || r.expires_at > now) {
          blockedMacsFromRules.add(String(r.value).toLowerCase());
        }
      }
    }
    devices = realDevices.map(d => ({
      name:    d.hostname || d.device_label || d.vendor || d.mac,
      icon:    d.device_icon || (d.device_type === 'phone' ? '📱' : d.device_type === 'tv' ? '📺' : d.device_type === 'console' ? '🎮' : d.device_type === 'iot' ? '💡' : d.device_type === 'router' ? '📡' : '💻'),
      mac:     d.mac,
      ip:      d.ip || '',
      vendor:  d.vendor || '',
      hostname: d.hostname || '',
      online:  d.last_seen ? (now - d.last_seen) < ONLINE_CUTOFF_MS : (d.online !== false),
      last:    d.last_seen ? fmtAge(now - d.last_seen) : 'now',
      blocked: !!d.blocked || blockedMacsFromRules.has((d.mac || '').toLowerCase()),
      weight:  1.0,
    }));
  } else {
    // No reports yet (fresh box, no devices seen) — show empty rather than fake.
    devices = [];
  }

  // Attach family ownership + custom name override + REAL usage (was fakeUsage24h)
  const fam = state.family_members[c.id] || [];
  const renames = state.device_renames[c.id] || {};
  const period = (typeof currentPeriod === 'function') ? currentPeriod() : null;
  const monthlyUsage = (period && state.usage_monthly && state.usage_monthly[c.id] && state.usage_monthly[c.id][period]) || {};
  devices = devices.map(d => {
    const owner = fam.find(f => (f.device_macs || []).includes(d.mac));
    const mu = monthlyUsage[d.mac] || { bytes_up: 0, bytes_down: 0 };
    const total_month_mb = ((mu.bytes_up || 0) + (mu.bytes_down || 0)) / (1024 * 1024);
    return {
      ...d,
      name: renames[d.mac] || d.name,
      default_name: d.name,
      custom_name: !!renames[d.mac],
      owner_id: owner ? owner.id : null,
      owner_name: owner ? owner.name : null,
      owner_role: owner ? owner.role : null,
      total_month_mb,
      total_month_gb: total_month_mb / 1024,
      bytes_up_month:   mu.bytes_up   || 0,
      bytes_down_month: mu.bytes_down || 0,
      period,
    };
  });

  // Plan limit: cap visible devices
  const limits = planLimits(c.plan);
  const total = devices.length;
  const trimmed = devices.slice(0, limits.max_devices_seen);
  const truncated = total > limits.max_devices_seen;
  res.json({
    devices: trimmed,
    total,
    visible: trimmed.length,
    plan_limit: limits.max_devices_seen,
    truncated,
    upgrade_hint: truncated ? `Your '${c.plan}' plan shows up to ${limits.max_devices_seen} devices. Upgrade to see all ${total}.` : null,
    box: myBoxes[0].mac,
  });
});

// Per-device detail (24h chart points)
app.get('/api/customer/device/:mac', customerAuth, (req, res) => {
  const usage = fakeUsage24h(req.params.mac, 1);
  res.json({
    mac: req.params.mac,
    usage_24h_mb: usage,
    total_24h_mb: usage.reduce((a, b) => a + b, 0),
    peak_hour: usage.indexOf(Math.max(...usage)),
  });
});

// Customer renames a device (overrides auto-detected name)
app.post('/api/customer/device/rename', customerAuth, (req, res) => {
  const c = req.customer;
  const mac = req.body.mac;
  const name = String(req.body.name || '').slice(0, 60).trim();
  if (!mac) return res.status(400).json({ error: 'mac required' });
  if (!state.device_renames[c.id]) state.device_renames[c.id] = {};
  if (name) {
    state.device_renames[c.id][mac] = name;
  } else {
    delete state.device_renames[c.id][mac];  // empty name = revert to default
  }
  saveState();
  state.events.push({ ts: Date.now(), method: 'CUSTOMER', path: `[DEVICE-RENAME] ${c.name} → ${mac} = "${name}"`, ip: req.ip });
  res.json({ ok: true });
});

// Today's total bytes — sums state.usage_daily for the current day across
// all the customer's devices. More accurate than summing state.flows
// (which only contains a 5-min window and depends on flow capture).
app.get('/api/customer/usage-today', customerAuth, (req, res) => {
  const c = req.customer;
  const day = (typeof currentDay === 'function') ? currentDay() : new Date().toISOString().slice(0, 10);
  const dayBucket = ((state.usage_daily || {})[c.id] || {})[day] || {};
  let bytes_up = 0, bytes_down = 0;
  let device_count = 0;
  for (const v of Object.values(dayBucket)) {
    bytes_up   += (v.bytes_up   || 0);
    bytes_down += (v.bytes_down || 0);
    device_count++;
  }
  const total_bytes = bytes_up + bytes_down;
  res.json({
    day,
    total_bytes,
    total_mb: total_bytes / (1024 * 1024),
    total_gb: total_bytes / (1024 * 1024 * 1024),
    bytes_up, bytes_down,
    device_count,
  });
});

// Forget device — fully removes a device record across the customer's boxes
// and clears all associated per-device state (rename, icon, family assignment,
// quotas, time-bank, bandwidth caps, block rules). If the device comes back
// online it'll be discovered fresh (Firewalla "Forget" semantics).
app.post('/api/customer/device/forget', customerAuth, (req, res) => {
  const c = req.customer;
  const dmac = normalizeMac(String(req.body.mac || ''));
  if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(dmac)) return res.status(400).json({ error: 'mac required' });
  const myBoxes = Object.values(state.authorized_macs).filter(m => m.customer_id === c.id);
  let removedFromBoxes = 0;
  for (const b of myBoxes) {
    const bucket = state.box_devices[b.mac];
    if (bucket && bucket[dmac]) { delete bucket[dmac]; removedFromBoxes++; }
  }
  // Strip per-device state
  if (state.device_renames[c.id]) delete state.device_renames[c.id][dmac];
  if (state.device_icons   && state.device_icons[c.id])   delete state.device_icons[c.id][dmac];
  if (state.device_tags    && state.device_tags[c.id])    delete state.device_tags[c.id][dmac];
  if (state.device_bw_caps && state.device_bw_caps[c.id]) state.device_bw_caps[c.id] = state.device_bw_caps[c.id].filter(x => x.mac !== dmac);
  if (state.quotas[c.id])     state.quotas[c.id]     = state.quotas[c.id].filter(q => (q.device_mac || '').toLowerCase() !== dmac);
  if (state.time_bank[c.id])  state.time_bank[c.id]  = state.time_bank[c.id].filter(t => (t.device_mac || '').toLowerCase() !== dmac);
  // Remove from family assignments
  for (const m of (state.family_members[c.id] || [])) {
    m.device_macs = (m.device_macs || []).filter(x => x.toLowerCase() !== dmac);
  }
  // Drop any rules targeting this MAC (block/allow)
  if (state.rules[c.id]) {
    state.rules[c.id] = state.rules[c.id].filter(r =>
      !(r.type === 'mac' && (r.value || '').toLowerCase() === dmac)
    );
  }
  if (typeof bumpPolicyEtag === 'function') bumpPolicyEtag(c.id, 'device-forget');
  saveState();
  state.events.push({ ts: Date.now(), method: 'CUSTOMER', path: `[DEVICE-FORGET] ${c.name} forgot ${dmac}`, ip: req.ip });
  console.log(`         🗑  CUSTOMER FORGET → ${c.name}  device=${dmac}  (removed from ${removedFromBoxes} box(es))`);
  res.json({ ok: true, mac: dmac, removed_from_boxes: removedFromBoxes });
});

// Scheduled WoL — customer schedules wake-on-lan pings.
// state.scheduled_wol = { customer_id: [{id, target_mac, days[0..6], hhmm, enabled}] }
if (!state.scheduled_wol) state.scheduled_wol = {};
app.get('/api/customer/scheduled-wol', customerAuth, (req, res) => {
  res.json({ schedules: state.scheduled_wol[req.customer.id] || [] });
});
app.post('/api/customer/scheduled-wol/add', customerAuth, (req, res) => {
  const cid = req.customer.id;
  const target_mac = normalizeMac(req.body.target_mac || '');
  if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(target_mac)) return res.status(400).json({ error: 'invalid target_mac' });
  const days = Array.isArray(req.body.days) ? req.body.days.filter(d => Number.isInteger(d) && d >= 0 && d <= 6) : [];
  const hhmm = String(req.body.hhmm || '');
  if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(hhmm)) return res.status(400).json({ error: 'hhmm must be HH:MM' });
  if (!state.scheduled_wol[cid]) state.scheduled_wol[cid] = [];
  if (state.scheduled_wol[cid].length >= 30) return res.status(429).json({ error: 'max 30' });
  const s = { id: 'wols-' + shortId(8), target_mac, days, hhmm, enabled: true, created_at: Date.now() };
  state.scheduled_wol[cid].push(s);
  saveState();
  res.json({ ok: true, schedule: s });
});
app.post('/api/customer/scheduled-wol/delete', customerAuth, (req, res) => {
  const list = state.scheduled_wol[req.customer.id] || [];
  const i = list.findIndex(x => x.id === req.body.id);
  if (i < 0) return res.status(404).json({ error: 'not found' });
  list.splice(i, 1);
  saveState();
  res.json({ ok: true });
});
// Cron: minute-resolution
function fireScheduledWol() {
  const lbt = new Date(Date.now() + 3 * 3600_000);
  const dayIdx = lbt.getUTCDay();   // 0=Sun
  const hhmm = `${lbt.getUTCHours().toString().padStart(2,'0')}:${lbt.getUTCMinutes().toString().padStart(2,'0')}`;
  for (const [cid, list] of Object.entries(state.scheduled_wol)) {
    for (const s of list) {
      if (!s.enabled) continue;
      if (!s.days.includes(dayIdx)) continue;
      if (s.hhmm !== hhmm) continue;
      // Enqueue WoL action on customer's first online box
      const myBoxes = Object.values(state.authorized_macs).filter(m => m.customer_id === cid);
      const target = myBoxes.find(b => {
        const bs = state.box_state[b.mac];
        return bs && (Date.now() - bs.last_heartbeat) < 5 * 60_000;
      });
      if (!target) continue;
      if (!state.box_commands[target.mac]) state.box_commands[target.mac] = [];
      state.box_commands[target.mac].push({
        id: shortId(16), action: 'wol', args: { target_mac: s.target_mac },
        status: 'pending', created_at: Date.now(), result: null, completed_at: null,
        scheduled: true,
      });
      console.log(`         ⏰ SCHEDULED-WOL ${cid} → ${s.target_mac}`);
    }
  }
}
setInterval(fireScheduledWol, 60_000);

// Bulk device tagging by hostname regex.
app.post('/api/customer/devices/bulk-tag', customerAuth, (req, res) => {
  const cid = req.customer.id;
  const re_str = String(req.body.regex || '');
  const tag = String(req.body.tag || '').slice(0, 30).trim();
  if (!re_str || !tag) return res.status(400).json({ error: 'regex + tag required' });
  let re;
  try { re = new RegExp(re_str, 'i'); } catch (e) { return res.status(400).json({ error: 'invalid regex: ' + e.message }); }
  const myMacs = Object.values(state.authorized_macs).filter(m => m.customer_id === cid).map(m => m.mac);
  if (!state.device_tags[cid]) state.device_tags[cid] = {};
  let tagged = 0;
  const matched = [];
  for (const boxMac of myMacs) {
    for (const d of Object.values(state.box_devices[boxMac] || {})) {
      const haystack = `${d.hostname || ''} ${d.vendor || ''}`;
      if (!re.test(haystack)) continue;
      const existing = state.device_tags[cid][d.mac] || [];
      if (!existing.includes(tag)) {
        existing.push(tag);
        state.device_tags[cid][d.mac] = existing;
        tagged++;
        matched.push({ mac: d.mac, hostname: d.hostname, vendor: d.vendor });
      }
    }
  }
  saveState();
  res.json({ ok: true, tag, tagged, matched: matched.slice(0, 50) });
});

// Customer overrides a device's icon emoji.
if (!state.device_icons) state.device_icons = {};   // { customer_id: { mac: emoji } }
app.post('/api/customer/device/icon', customerAuth, (req, res) => {
  const cid = req.customer.id;
  const mac = normalizeMac(req.body.mac || '');
  const icon = String(req.body.icon || '').slice(0, 4);   // emoji is up to 4 bytes
  if (!mac) return res.status(400).json({ error: 'mac required' });
  if (!state.device_icons[cid]) state.device_icons[cid] = {};
  if (icon) state.device_icons[cid][mac] = icon;
  else delete state.device_icons[cid][mac];
  saveState();
  res.json({ ok: true, mac, icon });
});
app.get('/api/customer/device-icons', customerAuth, (req, res) => {
  res.json({ icons: state.device_icons[req.customer.id] || {} });
});

// Assign a device to a family member
app.post('/api/customer/device/assign', customerAuth, (req, res) => {
  const { mac, family_id } = req.body;
  if (!mac) return res.status(400).json({ error: 'mac required' });
  const fam = state.family_members[req.customer.id] || [];

  // Remove this MAC from any other family member first
  for (const m of fam) {
    m.device_macs = (m.device_macs || []).filter(x => x !== mac);
  }
  // Add to the selected one (if any)
  if (family_id) {
    const target = fam.find(m => m.id === family_id);
    if (!target) return res.status(404).json({ error: 'family member not found' });
    if (!target.device_macs) target.device_macs = [];
    target.device_macs.push(mac);
  }
  saveState();
  console.log(`         📲 device ASSIGN → ${req.customer.name} ${mac} → ${family_id || '(unassigned)'}`);
  res.json({ ok: true });
});

// POST /api/customer/pause — pauses the internet on the customer's box
//   { duration_min: number }   sets pause_until = now + duration_min*60_000
//   { resume: true }           clears pause_until
// The policy bundle already exposes `pause.until` and forces every customer
// device into `quota_blocked` (see /api/box/policy/:mac).
app.post('/api/customer/pause', customerAuth, (req, res) => {
  const c = req.customer;
  if (req.body && req.body.resume) {
    c.pause_until = null;
    state.events.push({
      ts: Date.now(), method: 'CUSTOMER',
      path: `[RESUME] ${c.name} resumed internet`, ip: req.ip,
    });
    console.log(`         ▶ CUSTOMER RESUME → ${c.name}`);
    saveState();
    return res.json({ ok: true, paused_until: null });
  }
  const duration = Math.min(parseInt(req.body.duration_min) || 60, 720);
  c.pause_until = Date.now() + duration * 60 * 1000;
  state.events.push({
    ts: Date.now(),
    method: 'CUSTOMER',
    path: `[PAUSE] ${c.name} paused internet for ${duration}m`,
    ip: req.ip,
  });
  console.log(`         ⏸ CUSTOMER PAUSE → ${c.name}  ${duration}m`);
  saveState();
  res.json({ ok: true, paused_until: new Date(c.pause_until).toISOString() });
});

// POST /api/customer/box/action — enqueues a real RPC; waits for box to ack
// state.box_commands = { mac: [ {id, action, args, status, created_at, result, completed_at} ] }
if (!state.box_commands) state.box_commands = {};

app.post('/api/customer/box/action', customerAuth, async (req, res) => {
  const c = req.customer;
  const action = String(req.body.action || '').slice(0, 20);
  const allowed = ['reboot', 'speedtest', 'status', 'restart-services', 'wol', 'tail-logs', 'factory-reset'];
  if (!allowed.includes(action)) {
    return res.status(400).json({ error: 'unknown action', allowed });
  }
  // WoL needs a target MAC in args
  if (action === 'wol') {
    const targetMac = normalizeMac((req.body.args && req.body.args.target_mac) || '');
    if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(targetMac)) {
      return res.status(400).json({ error: 'wol requires args.target_mac' });
    }
    req.body.args = { target_mac: targetMac };
  }
  // Find the customer's box (use the requested mac if specified)
  const myBoxes = Object.values(state.authorized_macs).filter(m => m.customer_id === c.id);
  if (myBoxes.length === 0) return res.status(404).json({ error: 'no_box_assigned' });
  const targetMac = req.body.mac && myBoxes.find(b => b.mac === normalizeMac(req.body.mac))
    ? normalizeMac(req.body.mac) : myBoxes[0].mac;
  // Is the box online?
  const bs = state.box_state[targetMac];
  const online = bs && (Date.now() - bs.last_heartbeat) < 5 * 60_000;
  if (!online) {
    return res.status(503).json({ error: 'box_offline', message: 'Box has not checked in recently. Action cannot be delivered.', last_heartbeat: bs && bs.last_heartbeat });
  }
  // Enqueue
  const cmd = {
    id: shortId(16),
    action,
    args: req.body.args || {},
    status: 'pending',
    created_at: Date.now(),
    result: null,
    completed_at: null,
  };
  if (!state.box_commands[targetMac]) state.box_commands[targetMac] = [];
  state.box_commands[targetMac].push(cmd);
  // Cap queue at 100 per box
  if (state.box_commands[targetMac].length > 100) state.box_commands[targetMac].shift();
  saveState();
  state.events.push({ ts: Date.now(), method: 'CUSTOMER', path: `[BOX:${action.toUpperCase()}] ${c.name} → ${targetMac}`, ip: req.ip });
  console.log(`         📦 BOX RPC enqueued → ${c.name} ${action} on ${targetMac} cmd=${cmd.id}`);

  // Wait up to 15s for the box to report back
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    await new Promise(r => setTimeout(r, 250));
    const c2 = (state.box_commands[targetMac] || []).find(x => x.id === cmd.id);
    if (c2 && c2.status === 'completed') {
      return res.json({ ok: true, action, mac: targetMac, status: 'completed', result: c2.result, took_ms: c2.completed_at - c2.created_at });
    }
    if (c2 && c2.status === 'failed') {
      return res.json({ ok: false, action, mac: targetMac, status: 'failed', error: c2.result && c2.result.error });
    }
  }
  // Timeout — box still hasn't reported back. Return queued status.
  res.json({ ok: true, action, mac: targetMac, status: 'queued', message: 'Command queued. Box will execute on next poll.' });
});

// Box-side: poll for pending commands
app.get('/api/box/commands', boxAuth, (req, res) => {
  const queue = (state.box_commands[req.boxMac] || []).filter(c => c.status === 'pending');
  // Mark them as in_progress when delivered (so we don't re-deliver)
  for (const c of queue) c.status = 'in_progress';
  if (queue.length > 0) saveState();
  res.json({ commands: queue.map(c => ({ id: c.id, action: c.action, args: c.args })) });
});

// Box-side: report command result
app.post('/api/box/commands/:id/result', boxAuth, (req, res) => {
  const queue = state.box_commands[req.boxMac] || [];
  const cmd = queue.find(c => c.id === req.params.id);
  if (!cmd) return res.status(404).json({ error: 'unknown_command' });
  cmd.status = req.body.status === 'failed' ? 'failed' : 'completed';
  cmd.result = req.body.result || null;
  cmd.completed_at = Date.now();

  // Stash internal vuln-scan results into a per-box ring
  if (cmd.action === 'vuln-scan' && cmd.status === 'completed' && cmd.result) {
    state.box_internal_scans[req.boxMac] = {
      ts: cmd.completed_at,
      ok: !!cmd.result.ok,
      subnet: cmd.result.subnet || null,
      hosts: cmd.result.hosts || [],
      duration_ms: cmd.result.duration_ms || 0,
      error: cmd.result.error || null,
    };
  }

  // If this was a speedtest, store the result in history
  if (cmd.action === 'speedtest' && cmd.status === 'completed' && cmd.result) {
    if (!state.speedtest_history) state.speedtest_history = {};
    if (!state.speedtest_history[req.boxMac]) state.speedtest_history[req.boxMac] = [];
    state.speedtest_history[req.boxMac].push({
      ts: cmd.completed_at,
      down_mbps: cmd.result.down_mbps || 0,
      up_mbps: cmd.result.up_mbps || 0,
      latency_ms: cmd.result.latency_ms || 0,
      server: cmd.result.server || '',
      tool: cmd.result.tool || 'unknown',
      scheduled: !!cmd.args && cmd.args.scheduled === true,
    });
    // Cap at last 365 entries per box
    if (state.speedtest_history[req.boxMac].length > 365) {
      state.speedtest_history[req.boxMac].shift();
    }
    console.log(`         ⚡ SPEEDTEST recorded: ${req.boxMac} ↓${cmd.result.down_mbps}/${cmd.result.up_mbps} ${cmd.result.latency_ms}ms`);
  }

  saveState();
  console.log(`         ✓ BOX RPC result ← ${req.boxMac} cmd=${req.params.id} ${cmd.status}`);
  res.json({ ok: true });
});

// ─── Speed-test history (customer + admin) ───
app.get('/api/customer/speedtest-history', customerAuth, (req, res) => {
  const myMacs = Object.values(state.authorized_macs).filter(m => m.customer_id === req.customer.id).map(m => m.mac);
  const out = {};
  for (const mac of myMacs) out[mac] = (state.speedtest_history && state.speedtest_history[mac]) || [];
  res.json({ history: out });
});

// Uptime % calculation from heartbeat_history. Box heartbeats every 60s; assume
// "online" for any 5-minute bucket containing >=1 heartbeat. Uptime = online_buckets / total_buckets.
function computeUptime(mac, windowMs) {
  const hb = (state.heartbeat_history && state.heartbeat_history[mac]) || [];
  if (!hb.length) return { uptime_pct: null, samples: 0, window_ms: windowMs };
  const now = Date.now();
  const cutoff = now - windowMs;
  const bucketMs = 5 * 60_000;
  const totalBuckets = Math.floor(windowMs / bucketMs);
  const occupied = new Set();
  for (const ts of hb) {
    if (ts < cutoff) continue;
    occupied.add(Math.floor((ts - cutoff) / bucketMs));
  }
  const onlinePct = totalBuckets > 0 ? (occupied.size / totalBuckets) * 100 : 0;
  return {
    uptime_pct: Math.round(onlinePct * 100) / 100,
    online_buckets: occupied.size,
    total_buckets: totalBuckets,
    window_ms: windowMs,
  };
}
app.get('/api/customer/box-uptime', customerAuth, (req, res) => {
  const myMacs = Object.values(state.authorized_macs).filter(m => m.customer_id === req.customer.id).map(m => m.mac);
  const out = {};
  for (const mac of myMacs) {
    out[mac] = {
      day:   computeUptime(mac, 24 * 3600_000),
      week:  computeUptime(mac, 7 * 24 * 3600_000),
      month: computeUptime(mac, 30 * 24 * 3600_000),
    };
  }
  res.json({ uptime: out });
});
app.get('/admin/api/box-uptime', adminAuth, (req, res) => {
  const fleet = Object.keys(state.heartbeat_history || {}).map(mac => {
    const m = state.authorized_macs[mac] || {};
    const c = m.customer_id ? state.customers[m.customer_id] : null;
    return {
      mac,
      customer_id: m.customer_id || null,
      customer_name: c ? c.name : null,
      day:   computeUptime(mac, 24 * 3600_000),
      week:  computeUptime(mac, 7 * 24 * 3600_000),
      month: computeUptime(mac, 30 * 24 * 3600_000),
    };
  });
  fleet.sort((a, b) => (a.month.uptime_pct || 0) - (b.month.uptime_pct || 0));
  res.json({ fleet });
});

// Admin: extend a customer's trial by N days (1-180)
app.post('/admin/api/customers/extend-trial', adminAuth, (req, res) => {
  const c = state.customers[req.body.id];
  if (!c) return res.status(404).json({ error: 'customer not found' });
  if (c.trial_status === 'converted' || c.trial_status === 'cancelled') {
    return res.status(400).json({ error: `trial is ${c.trial_status} — cannot extend` });
  }
  const days = parseInt(req.body.days);
  if (!Number.isInteger(days) || days < 1 || days > 180) return res.status(400).json({ error: 'days must be 1-180' });
  const base = (c.trial_until && c.trial_until > Date.now()) ? c.trial_until : Date.now();
  c.trial_until = base + days * 86400_000;
  c.trial_status = 'active';
  if (!c.trial_extensions) c.trial_extensions = [];
  c.trial_extensions.push({ ts: Date.now(), days, by: req.adminUser || 'admin' });
  saveState();
  if (typeof logAdminAction === 'function') logAdminAction(req, 'trial.extend', c.id, `+${days} days`);
  if (typeof pushNotification === 'function') {
    pushNotification(c.id, 'billing', '🎁 Trial extended',
      `We extended your trial by ${days} day${days > 1 ? 's' : ''}. New end date: ${new Date(c.trial_until).toLocaleDateString()}.`);
  }
  res.json({ ok: true, trial_until: c.trial_until, extensions: c.trial_extensions });
});

// Admin: toggle rate-limit exemption per customer
app.post('/admin/api/customers/rate-limit-exempt', adminAuth, (req, res) => {
  const c = state.customers[req.body.id];
  if (!c) return res.status(404).json({ error: 'customer not found' });
  c.rate_limit_exempt = !!req.body.exempt;
  if (c.rate_limit_exempt) c.rate_limit_exempt_set_at = Date.now();
  saveState();
  if (typeof logAdminAction === 'function') logAdminAction(req, 'rate_limit_exempt', c.id, String(c.rate_limit_exempt));
  res.json({ ok: true, rate_limit_exempt: c.rate_limit_exempt });
});

// Admin remote-shell relay — runs a whitelisted diagnostic command on the box via the
// existing command queue. Box already polls /api/box/commands; we just register a new action.
const ADMIN_DIAG_COMMANDS = {
  ping_test:    { cmd: 'ping -c 4 -W 2 8.8.8.8' },
  dns_test:     { cmd: 'dig +short google.com @1.1.1.1' },
  uptime:       { cmd: 'uptime' },
  disk_free:    { cmd: 'df -h' },
  list_devices: { cmd: 'arp -a' },
  conntrack:    { cmd: 'conntrack -L 2>/dev/null | head -50' },
  wg_status:    { cmd: 'wg show 2>/dev/null || echo "no wg"' },
  nft_dump:     { cmd: 'nft list ruleset 2>/dev/null | head -100' },
  dmesg_tail:   { cmd: 'dmesg | tail -50' },
  reboot_check: { cmd: 'last reboot | head -5' },
};
app.post('/admin/api/box/:mac/diag', adminAuth, async (req, res) => {
  const mac = normalizeMac(req.params.mac);
  if (!state.authorized_macs[mac]) return res.status(404).json({ error: 'unknown_box' });
  const action = String(req.body.action || '');
  if (!ADMIN_DIAG_COMMANDS[action]) {
    return res.status(400).json({ error: 'unknown_diag', allowed: Object.keys(ADMIN_DIAG_COMMANDS) });
  }
  const bs = state.box_state[mac];
  if (!bs || (Date.now() - bs.last_heartbeat) > 5 * 60_000) {
    return res.status(503).json({ error: 'box_offline' });
  }
  const cmd = {
    id: shortId(16),
    action: 'admin-diag',
    args: { diag: action, cmd: ADMIN_DIAG_COMMANDS[action].cmd },
    status: 'pending',
    created_at: Date.now(),
    result: null,
    completed_at: null,
    issued_by: req.adminUser || 'admin',
  };
  if (!state.box_commands[mac]) state.box_commands[mac] = [];
  state.box_commands[mac].push(cmd);
  if (typeof logAdminAction === 'function') logAdminAction(req, 'box.diag', mac, action);
  // Wait up to 15s for result
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    await new Promise(r => setTimeout(r, 500));
    const c2 = (state.box_commands[mac] || []).find(x => x.id === cmd.id);
    if (c2 && c2.status === 'completed') {
      return res.json({ ok: true, result: c2.result, completed_at: c2.completed_at });
    }
  }
  res.json({ ok: true, status: 'pending', command_id: cmd.id, note: 'still running, poll later' });
});

// Admin: impersonate a customer — issues a 30-minute customer JWT.
// Use case: support diagnoses what customer sees in PWA.
app.post('/admin/api/customers/impersonate', adminAuth, (req, res) => {
  const c = state.customers[req.body.id];
  if (!c) return res.status(404).json({ error: 'customer not found' });
  if (typeof canAccessCustomer === 'function' && !canAccessCustomer(req, c.id)) {
    return res.status(403).json({ error: 'reseller cannot access this customer' });
  }
  // Build a 30-minute impersonation JWT
  if (!licenseKeys) return res.status(500).json({ error: 'no_signing_key' });
  const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    sub: c.id, name: c.name, phone: c.phone, plan: c.plan,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 1800,  // 30 minutes
    impersonator: req.adminUser || 'admin',
    impersonator_role: req.adminRole || 'admin',
  })).toString('base64url');
  const signature = crypto.sign(null, Buffer.from(header + '.' + payload), licenseKeys.privateKey).toString('base64url');
  const token = `${header}.${payload}.${signature}`;
  if (typeof logAdminAction === 'function') {
    logAdminAction(req, 'customer.impersonate', c.id, `${c.name} (${c.phone})`);
  }
  // Notify the customer that their account was accessed by support (transparency)
  if (typeof pushNotification === 'function') {
    pushNotification(c.id, 'security',
      '🛠️ Support staff accessed your account',
      `${req.adminUser || 'admin'} viewed your account for support purposes. If this was unexpected, contact us.`);
  }
  res.json({ ok: true, token, expires_in_sec: 1800,
    pwa_url: `https://cloud.mes.net.lb/pwa/?impersonate_token=${token}` });
});

// Admin broadcast announcement — sends a push notification + adds an in-app banner.
// Filters: all | plan=basic|family|... | tag=<tag> (matches a customer.tags entry)
if (!state.announcements) state.announcements = [];   // ring buffer
app.post('/admin/api/announcements', adminAuth, (req, res) => {
  const title = String(req.body.title || '').trim().slice(0, 120);
  const body  = String(req.body.body || '').trim().slice(0, 2000);
  const filter = req.body.filter || { type: 'all' };
  const severity = ['info','warn','urgent'].includes(req.body.severity) ? req.body.severity : 'info';
  const expiresAt = req.body.expires_at ? Number(req.body.expires_at) : Date.now() + 7 * 86400_000;
  if (!title || !body) return res.status(400).json({ error: 'title + body required' });

  const matches = (c) => {
    if (c.status === 'archived') return false;
    if (filter.type === 'all') return true;
    if (filter.type === 'plan' && filter.plan) return c.plan === filter.plan;
    if (filter.type === 'tag'  && filter.tag)  return Array.isArray(c.tags) && c.tags.includes(filter.tag);
    if (filter.type === 'ids'  && Array.isArray(filter.customer_ids)) return filter.customer_ids.includes(c.id);
    return false;
  };
  const targets = Object.values(state.customers).filter(matches);
  const announcement = {
    id: 'anc-' + shortId(10), title, body, severity,
    filter, target_count: targets.length, expires_at: expiresAt,
    created_at: Date.now(), created_by: req.adminUser || 'admin',
    dismissed_by: [],
  };
  state.announcements.unshift(announcement);
  if (state.announcements.length > 100) state.announcements.length = 100;

  for (const c of targets) {
    if (typeof pushNotification === 'function') {
      pushNotification(c.id, severity === 'urgent' ? 'security' : 'system', `📢 ${title}`, body);
    }
  }
  saveState();
  if (typeof logAdminAction === 'function') logAdminAction(req, 'announcement.send', announcement.id, `${targets.length} targets`);
  res.json({ ok: true, announcement, sent_to: targets.length });
});
app.get('/admin/api/announcements', adminAuth, (req, res) => {
  res.json({ announcements: state.announcements });
});
// Customer reads active (not-dismissed, not-expired) announcements
app.get('/api/customer/announcements', customerAuth, (req, res) => {
  const cid = req.customer.id;
  const c = req.customer;
  const matches = (a) => {
    const f = a.filter || { type: 'all' };
    if (f.type === 'all') return true;
    if (f.type === 'plan') return c.plan === f.plan;
    if (f.type === 'tag')  return Array.isArray(c.tags) && c.tags.includes(f.tag);
    if (f.type === 'ids')  return Array.isArray(f.customer_ids) && f.customer_ids.includes(c.id);
    return false;
  };
  const active = (state.announcements || []).filter(a =>
    a.expires_at > Date.now()
    && !a.dismissed_by.includes(cid)
    && matches(a)
  );
  res.json({ announcements: active });
});
app.post('/api/customer/announcements/dismiss', customerAuth, (req, res) => {
  const a = (state.announcements || []).find(x => x.id === req.body.id);
  if (!a) return res.status(404).json({ error: 'not found' });
  if (!a.dismissed_by.includes(req.customer.id)) a.dismissed_by.push(req.customer.id);
  saveState();
  res.json({ ok: true });
});

// Detailed system-health endpoint — ops/monitoring view of internal state.
app.get('/health/detailed', (req, res) => {
  const memUsed = process.memoryUsage();
  let stateBytes = null;
  try { stateBytes = fs.statSync(STATE_FILE).size; } catch {}
  let backupAgeS = null;
  try {
    const dir = path.dirname(STATE_FILE) + '/backups';
    const files = fs.readdirSync(dir).filter(f => f.startsWith('state-')).sort();
    if (files.length) {
      const newest = files[files.length - 1];
      backupAgeS = Math.round((Date.now() - fs.statSync(`${dir}/${newest}`).mtime.getTime()) / 1000);
    }
  } catch {}
  const integrity = typeof verifyAuditChain === 'function' ? verifyAuditChain() : null;
  res.json({
    ok: true,
    version: typeof VERSION !== 'undefined' ? VERSION : LEGAL_VERSION || '?',
    uptime_s: Math.round(process.uptime()),
    memory_mb: {
      rss: Math.round(memUsed.rss / 1048576),
      heap_used: Math.round(memUsed.heapUsed / 1048576),
      heap_total: Math.round(memUsed.heapTotal / 1048576),
    },
    state: {
      file_bytes: stateBytes,
      customers: Object.keys(state.customers || {}).length,
      boxes: Object.keys(state.authorized_macs || {}).length,
      flows_buffered: state.flows.length,
      alarms: state.alarms.length,
      audit_entries: (state.admin_actions || []).length,
      audit_chain_intact: integrity ? integrity.intact : null,
    },
    queues: {
      webhook_queue: (state.webhook_queue || []).length,
      box_commands_pending: Object.values(state.box_commands || {}).flat().filter(c => c.status === 'pending').length,
      announcements_active: (state.announcements || []).filter(a => a.expires_at > Date.now()).length,
    },
    backup: {
      newest_age_s: backupAgeS,
      newest_age_h: backupAgeS != null ? Math.round(backupAgeS / 3600) : null,
      stale: backupAgeS != null && backupAgeS > 30 * 3600,    // > 30h is stale (>1 day late)
    },
    threat_feed: {
      domains: (state.threat_feeds.domains || []).length,
      ips: (state.threat_feeds.ips || []).length,
      last_update_s: state.threat_feeds.last_update ? Math.round((Date.now() - state.threat_feeds.last_update) / 1000) : null,
    },
  });
});

// Admin global IP ban list — IPs here get injected into every customer's policy bundle.
// Useful when a single bad host needs to be blocked fleet-wide regardless of category.
if (!state.global_ip_bans) state.global_ip_bans = [];
if (!state.global_ip_ban_meta) state.global_ip_ban_meta = {};   // ip → {added_at, by, reason}
app.get('/admin/api/global-ip-bans', adminAuth, (req, res) => {
  const out = state.global_ip_bans.map(ip => ({ ip, ...state.global_ip_ban_meta[ip] }));
  res.json({ bans: out });
});
app.post('/admin/api/global-ip-bans/add', adminAuth, (req, res) => {
  const ip = String(req.body.ip || '').trim();
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return res.status(400).json({ error: 'invalid ipv4' });
  if (state.global_ip_bans.includes(ip)) return res.status(409).json({ error: 'already banned' });
  state.global_ip_bans.push(ip);
  state.global_ip_ban_meta[ip] = {
    added_at: Date.now(),
    by: req.adminUser || 'admin',
    reason: String(req.body.reason || '').slice(0, 200),
  };
  saveState();
  if (typeof logAdminAction === 'function') logAdminAction(req, 'global_ip_ban.add', ip, req.body.reason || '');
  if (typeof bumpPolicyEtagGlobal === 'function') bumpPolicyEtagGlobal(`global_ip_ban_added:${ip}`);
  res.json({ ok: true, count: state.global_ip_bans.length });
});
app.post('/admin/api/global-ip-bans/delete', adminAuth, (req, res) => {
  const ip = String(req.body.ip || '');
  const i = state.global_ip_bans.indexOf(ip);
  if (i < 0) return res.status(404).json({ error: 'not banned' });
  state.global_ip_bans.splice(i, 1);
  delete state.global_ip_ban_meta[ip];
  saveState();
  if (typeof logAdminAction === 'function') logAdminAction(req, 'global_ip_ban.delete', ip);
  if (typeof bumpPolicyEtagGlobal === 'function') bumpPolicyEtagGlobal(`global_ip_ban_removed:${ip}`);
  res.json({ ok: true });
});

// IP reputation lookup — combines threat-feed match, GeoIP, recent flow stats.
// Public-ish (admin-gated) so support can quickly assess "is this IP shady?"
app.get('/admin/api/ip-reputation', adminAuth, (req, res) => {
  const ip = String(req.query.ip || '').trim();
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return res.status(400).json({ error: 'invalid ipv4' });
  const inThreatFeed = (state.threat_feeds && state.threat_feeds.ips || []).includes(ip);
  const country = typeof geoCountryFor === 'function' ? geoCountryFor(ip) : 'XX';
  const recent = state.flows.filter(f => f.dst_ip === ip).slice(-200);
  const recentByCustomer = {};
  let recentBlocked = 0, recentBytes = 0;
  for (const f of recent) {
    if (f.blocked) recentBlocked++;
    recentBytes += (f.bytes_up || 0) + (f.bytes_down || 0);
    if (f.customer_id) recentByCustomer[f.customer_id] = (recentByCustomer[f.customer_id] || 0) + 1;
  }
  const inRules = [];
  for (const [cid, rules] of Object.entries(state.rules || {})) {
    for (const r of rules) {
      if (r.type === 'ip' && r.value === ip) inRules.push({ cid, rule_id: r.id, action: r.action, enabled: r.enabled !== false });
    }
  }
  res.json({
    ip, country,
    in_threat_feed: inThreatFeed,
    in_customer_rules: inRules,
    recent_flows: recent.length,
    recent_blocked: recentBlocked,
    recent_bytes: recentBytes,
    affected_customers: Object.keys(recentByCustomer).length,
    verdict: inThreatFeed ? 'malicious'
      : (recentBlocked / Math.max(recent.length, 1) > 0.5) ? 'suspicious'
      : recent.length > 0 ? 'observed' : 'unknown',
  });
});

// Admin: global search across customers, boxes, alarms, tickets, invoices
app.get('/admin/api/search', adminAuth, (req, res) => {
  const q = String(req.query.q || '').toLowerCase().trim();
  if (!q || q.length < 2) return res.json({ q, results: { customers: [], boxes: [], alarms: [], tickets: [], invoices: [] } });
  const matches = (s) => s && String(s).toLowerCase().includes(q);

  const customers = Object.values(state.customers)
    .filter(c => matches(c.name) || matches(c.email) || matches(c.phone) || matches(c.id) || matches(c.address))
    .slice(0, 20)
    .map(c => ({ id: c.id, name: c.name, email: c.email, phone: c.phone, plan: c.plan, status: c.status }));

  const boxes = Object.values(state.authorized_macs)
    .filter(m => matches(m.mac) || matches(m.customer_name) || matches(m.customer_id))
    .slice(0, 20)
    .map(m => ({ mac: m.mac, customer_id: m.customer_id, customer_name: m.customer_name, last_seen: m.last_seen }));

  const alarms = state.alarms
    .filter(a => matches(a.title) || matches(a.body) || matches(a.kind) || matches(a.customer_id))
    .slice(0, 20)
    .map(a => ({ id: a.id, ts: a.ts, severity: a.severity, kind: a.kind, title: a.title, customer_id: a.customer_id }));

  const tickets = Object.values(state.support_tickets || {})
    .filter(t => matches(t.subject) || matches(t.customer_name) || matches(t.id) ||
      (t.messages || []).some(m => matches(m.body)))
    .slice(0, 20)
    .map(t => ({ id: t.id, subject: t.subject, customer_id: t.customer_id, status: t.status, updated_at: t.updated_at }));

  const invoices = Object.values(state.invoices || {})
    .filter(i => matches(i.id) || matches(i.customer_id) || matches(i.period))
    .slice(0, 20)
    .map(i => ({ id: i.id, customer_id: i.customer_id, period: i.period, status: i.status, amount_usd: i.amount_usd }));

  res.json({ q, results: { customers, boxes, alarms, tickets, invoices },
    counts: { customers: customers.length, boxes: boxes.length, alarms: alarms.length, tickets: tickets.length, invoices: invoices.length }
  });
});

// Admin: fleet hardware inventory — summary by model + per-box list
app.get('/admin/api/box-inventory', adminAuth, (req, res) => {
  const fleet = [];
  const byModel = {};
  for (const [mac, b] of Object.entries(state.box_state || {})) {
    if (!b.hw) continue;
    const m = state.authorized_macs[mac] || {};
    const c = m.customer_id ? state.customers[m.customer_id] : null;
    fleet.push({ mac, customer_id: m.customer_id || null, customer_name: c ? c.name : null, hw: b.hw, version: b.version });
    const key = b.hw.hw_model || 'unknown';
    if (!byModel[key]) byModel[key] = { model: key, count: 0, total_ram_mb: 0, total_disk_gb: 0, arches: new Set() };
    byModel[key].count++;
    byModel[key].total_ram_mb += (b.hw.total_ram_mb || 0);
    byModel[key].total_disk_gb += (b.hw.total_disk_gb || 0);
    if (b.hw.arch) byModel[key].arches.add(b.hw.arch);
  }
  const summary = Object.values(byModel).map(m => ({
    model: m.model, count: m.count,
    total_ram_mb: m.total_ram_mb,
    total_disk_gb: m.total_disk_gb,
    arches: Array.from(m.arches),
  })).sort((a, b) => b.count - a.count);
  res.json({ summary, fleet, total_boxes: fleet.length });
});

// Customer-facing list of recent box commands (history of reboots, speedtests, etc.)
app.get('/api/customer/box/commands', customerAuth, (req, res) => {
  const myMacs = Object.values(state.authorized_macs)
    .filter(m => m.customer_id === req.customer.id).map(m => m.mac);
  const limit = Math.min(parseInt(req.query.limit || 50), 200);
  const all = [];
  for (const mac of myMacs) {
    for (const cmd of (state.box_commands[mac] || [])) {
      all.push({ ...cmd, box_mac: mac });
    }
  }
  all.sort((a, b) => b.created_at - a.created_at);
  res.json({ commands: all.slice(0, limit), total: all.length });
});

app.get('/admin/api/speedtest-fleet', adminAuth, (req, res) => {
  const fleet = Object.entries(state.speedtest_history || {}).map(([mac, history]) => {
    const latest = history[history.length - 1];
    const m = state.authorized_macs[mac] || {};
    const c = m.customer_id ? state.customers[m.customer_id] : null;
    // Stats over last 7 days
    const cutoff = Date.now() - 7 * 24 * 3600_000;
    const week = history.filter(h => h.ts >= cutoff);
    const avgDown = week.length ? week.reduce((s, h) => s + h.down_mbps, 0) / week.length : 0;
    const avgUp   = week.length ? week.reduce((s, h) => s + h.up_mbps, 0) / week.length : 0;
    return {
      mac,
      customer_id: m.customer_id,
      customer_name: c ? c.name : null,
      latest,
      total_tests: history.length,
      week_avg_down: Math.round(avgDown * 10) / 10,
      week_avg_up:   Math.round(avgUp   * 10) / 10,
    };
  });
  fleet.sort((a, b) => (b.latest && b.latest.ts || 0) - (a.latest && a.latest.ts || 0));
  res.json({ fleet });
});

// Scheduled bulk speedtest — every 24 hours, queue speedtest commands for all online boxes
function scheduleBulkSpeedtest() {
  const onlineBoxes = Object.entries(state.box_state || {})
    .filter(([_, s]) => s.last_heartbeat && (Date.now() - s.last_heartbeat) < 5 * 60_000)
    .map(([mac]) => mac);
  if (!onlineBoxes.length) return;
  if (!state.box_commands) state.box_commands = {};
  for (const mac of onlineBoxes) {
    if (!state.box_commands[mac]) state.box_commands[mac] = [];
    // Don't queue if there's already a pending speedtest
    if (state.box_commands[mac].some(c => c.action === 'speedtest' && c.status === 'pending')) continue;
    state.box_commands[mac].push({
      id: shortId(16),
      action: 'speedtest',
      args: { scheduled: true },
      status: 'pending',
      created_at: Date.now(),
      result: null,
      completed_at: null,
    });
  }
  saveState();
  console.log(`         ⚡ scheduled bulk speedtest for ${onlineBoxes.length} online boxes`);
}
// First run after 1 hour, then every 24h
setTimeout(scheduleBulkSpeedtest, 3600_000);
setInterval(scheduleBulkSpeedtest, 24 * 3600_000);

// Admin: trigger bulk speedtest now
app.post('/admin/api/speedtest-fleet/run-now', adminAuth, (req, res) => {
  scheduleBulkSpeedtest();
  res.json({ ok: true });
});

// Admin: tail logs from a specific box
app.post('/admin/api/box/:mac/tail-logs', adminAuth, async (req, res) => {
  const mac = normalizeMac(req.params.mac);
  if (!state.authorized_macs[mac]) return res.status(404).json({ error: 'unknown_box' });
  const bs = state.box_state[mac];
  if (!bs || (Date.now() - bs.last_heartbeat) > 5 * 60_000) return res.status(503).json({ error: 'box_offline' });
  const cmd = {
    id: shortId(16), action: 'tail-logs',
    args: { lines: Math.min(parseInt(req.body.lines) || 200, 1000), unit: String(req.body.unit || 'mes-box-agent').slice(0, 60) },
    status: 'pending', created_at: Date.now(), result: null, completed_at: null,
  };
  if (!state.box_commands[mac]) state.box_commands[mac] = [];
  state.box_commands[mac].push(cmd);
  saveState();
  // Wait up to 30s for box to respond
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    await new Promise(r => setTimeout(r, 500));
    const c2 = (state.box_commands[mac] || []).find(c => c.id === cmd.id);
    if (c2 && c2.status === 'completed') return res.json({ ok: true, logs: (c2.result && c2.result.logs) || '' });
    if (c2 && c2.status === 'failed') return res.json({ ok: false, error: (c2.result && c2.result.error) || 'unknown' });
  }
  res.json({ ok: false, error: 'timeout', message: 'Box did not respond within 30s' });
});

// Admin: send a command to all online boxes
app.post('/admin/api/fleet/command', adminAuth, (req, res) => {
  if (req.adminRole !== 'super' && req.adminRole !== 'admin') return res.status(403).json({ error: 'admin or super only' });
  const action = String(req.body.action || '').slice(0, 20);
  const allowed = ['reboot', 'restart-services', 'speedtest', 'status'];
  if (!allowed.includes(action)) return res.status(400).json({ error: 'unknown action', allowed });
  const onlineBoxes = Object.entries(state.box_state || {})
    .filter(([_, s]) => s.last_heartbeat && (Date.now() - s.last_heartbeat) < 5 * 60_000)
    .map(([mac]) => mac);
  if (!state.box_commands) state.box_commands = {};
  let queued = 0;
  for (const mac of onlineBoxes) {
    if (!state.box_commands[mac]) state.box_commands[mac] = [];
    if (state.box_commands[mac].some(c => c.action === action && c.status === 'pending')) continue;
    state.box_commands[mac].push({
      id: shortId(16), action, args: { fleet_op: true },
      status: 'pending', created_at: Date.now(), result: null, completed_at: null,
    });
    queued++;
  }
  saveState();
  logAdminAction(req, 'fleet.command.' + action, '', `queued=${queued}/${onlineBoxes.length}`);
  console.log(`         🚀 FLEET COMMAND: ${action} → queued for ${queued} boxes`);
  res.json({ ok: true, queued, online_total: onlineBoxes.length });
});

// Weekly email digest — per-customer summary of speedtest history
function sendWeeklyDigest() {
  const cutoff = Date.now() - 7 * 24 * 3600_000;
  for (const c of Object.values(state.customers)) {
    if (!c.email || c.status === 'archived') continue;
    const myMacs = Object.values(state.authorized_macs).filter(m => m.customer_id === c.id).map(m => m.mac);
    if (!myMacs.length) continue;
    const allTests = [];
    for (const mac of myMacs) {
      for (const t of (state.speedtest_history && state.speedtest_history[mac]) || []) {
        if (t.ts >= cutoff) allTests.push({ ...t, mac });
      }
    }
    if (!allTests.length) continue;
    const downs = allTests.map(t => t.down_mbps);
    const ups   = allTests.map(t => t.up_mbps);
    const lats  = allTests.map(t => t.latency_ms);
    const avg = a => (a.reduce((s,x) => s+x, 0) / a.length).toFixed(1);
    const min = a => Math.min(...a).toFixed(1);
    const max = a => Math.max(...a).toFixed(1);
    const slowCount = downs.filter(d => d < 10).length;

    const subject = `📊 Your weekly internet quality report`;
    const body = `Hi ${c.name},

Here's your internet quality summary for the past 7 days:

  ⬇ Download:  avg ${avg(downs)} Mbps · min ${min(downs)} · max ${max(downs)}
  ⬆ Upload:    avg ${avg(ups)} Mbps · min ${min(ups)} · max ${max(ups)}
  📡 Latency:  avg ${avg(lats)} ms · max ${max(lats)} ms

  Total tests: ${allTests.length}
  ${slowCount > 0 ? `⚠️ Slow periods (< 10 Mbps): ${slowCount}` : '✓ Speeds were consistent'}

${(c.vacation_active && c.vacation_until > Date.now())
   ? '🏖️  Vacation mode is currently active — extra blocking is on while you\'re away.'
   : ''}

See full charts: https://${state.config.brand_domain || 'cloud.mes.net.lb'}/pwa/

— mes Network`;

    sendEmail(c.email, subject, body);
  }
  console.log(`         📧 weekly digest sent to ${Object.values(state.customers).filter(c => c.email).length} customers`);
}
// Run every 7 days, after a 1-hour startup delay
setTimeout(sendWeeklyDigest, 3600_000);
setInterval(sendWeeklyDigest, 7 * 24 * 3600_000);

// Welcome drip emails — day 1, 3, 7 from signup
function runWelcomeDrip() {
  const now = Date.now();
  for (const c of Object.values(state.customers)) {
    if (!c.email || c.status === 'archived' || c.demo) continue;
    if (!c._drip) c._drip = {};
    const ageMs = now - new Date(c.created_at).getTime();
    const ageDays = Math.floor(ageMs / (24 * 3600_000));

    // Day 1 — welcome + setup
    if (ageDays >= 1 && !c._drip.day1) {
      sendEmail(c.email, 'Welcome to mes Network 👋',
        `Hi ${c.name},\n\nWelcome aboard! Three things to do today:\n\n` +
        `1. Open https://${state.config.brand_domain || 'cloud.mes.net.lb'}/pwa/ on your phone.\n` +
        `2. Add your box (or order a pre-flashed Pi from Settings).\n` +
        `3. Block adult + malware in one tap (Rules tab).\n\nReply if you get stuck.\n\nmes Network team`);
      c._drip.day1 = now;
    }
    // Day 3 — feature reminder
    if (ageDays >= 3 && !c._drip.day3) {
      const myMacs = Object.values(state.authorized_macs).filter(m => m.customer_id === c.id);
      const hasBox = myMacs.length > 0;
      sendEmail(c.email, 'Have you set up parental controls yet? 👨‍👩‍👧',
        `Hi ${c.name},\n\n${hasBox ? "Your box is set up — great!" : "Looks like you haven't claimed a box yet. Tap '+ Add' on the Home tab when ready."}\n\n` +
        `Quick tip: in the Family tab, add each kid + apply the "Bedtime" preset. Internet auto-pauses 21:00–07:00 for their devices only.\n\nmes Network team`);
      c._drip.day3 = now;
    }
    // Day 7 — engagement check + weekly digest preview
    if (ageDays >= 7 && !c._drip.day7) {
      sendEmail(c.email, 'How is your first week going? 📊',
        `Hi ${c.name},\n\nYou've been with us for a week! From now on you'll get a weekly summary email of your network's activity, speed, and any alerts.\n\n` +
        `If you have any feedback or questions, just reply to this email.\n\nmes Network team`);
      c._drip.day7 = now;
    }
  }
  saveState();
}
setInterval(runWelcomeDrip, 60 * 60_000);   // hourly check
setTimeout(runWelcomeDrip, 30 * 60_000);    // 30 min after boot

// Admin: trigger now
app.post('/admin/api/digest/weekly/send', adminAuth, (req, res) => {
  sendWeeklyDigest();
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════════════════════════
//  TIER-1 VISIBILITY — Weekly emailed digest (Feature A)
//                      Long-term flow archive (Feature B)
// ═══════════════════════════════════════════════════════════════════════════
if (!state.weekly_digests) state.weekly_digests = {};       // { cid: [ { id, ts, week_start, html, delivery_status } ] }
if (!state.flow_archive)   state.flow_archive   = {};       // { cid: [ {ts, src_mac, dst_domain, dst_ip, dst_port, proto, bytes_up, bytes_down, blocked, category, country} ] }
const FLOW_ARCHIVE_MAX_PER_CUSTOMER = 200_000;
const FLOW_ARCHIVE_RETENTION_MS     = 90 * 24 * 3600_000;

// Build HTML digest for ONE customer covering the last 7 days. Pulls from:
//   • state.usage_daily — per-device bytes per day (truth for "total this week")
//   • state.alarms      — alarm count by severity in window
//   • state.flow_archive — top domains in window (falls back to state.flows)
//   • state.family_members — to map device_mac → owner
//   • state.box_devices — to map MAC → friendly name
function buildWeeklyDigest(customer_id) {
  const c = state.customers[customer_id];
  if (!c) return null;
  const now = Date.now();
  const weekAgoMs = now - 7 * 24 * 3600_000;
  const weekStartISO = new Date(weekAgoMs).toISOString().slice(0, 10);
  const weekEndISO   = new Date(now).toISOString().slice(0, 10);

  // ── Aggregate per-device bytes over the last 7 days from usage_daily ──
  const dailyMap = (state.usage_daily && state.usage_daily[customer_id]) || {};
  const perDeviceBytes = {};
  let totalBytes = 0;
  for (let i = 0; i < 7; i++) {
    const d = new Date(now - i * 86400_000).toISOString().slice(0, 10);
    const dayBucket = dailyMap[d] || {};
    for (const [mac, b] of Object.entries(dayBucket)) {
      const total = (b.bytes_up || 0) + (b.bytes_down || 0);
      perDeviceBytes[mac] = (perDeviceBytes[mac] || 0) + total;
      totalBytes += total;
    }
  }

  // Map MAC → friendly name
  const myBoxes = Object.values(state.authorized_macs).filter(m => m.customer_id === customer_id).map(m => m.mac);
  const renames = (state.device_renames && state.device_renames[customer_id]) || {};
  const nameForMac = (mac) => {
    if (renames[mac]) return renames[mac];
    for (const bmac of myBoxes) {
      const d = (state.box_devices[bmac] || {})[mac];
      if (d) return d.hostname || d.vendor || mac;
    }
    return mac;
  };

  // Per-family-member byte totals
  const fam = (state.family_members && state.family_members[customer_id]) || [];
  const perFamilyBytes = [];
  const assignedMacs = new Set();
  for (const f of fam) {
    let bytes = 0;
    for (const m of (f.device_macs || [])) {
      bytes += perDeviceBytes[m] || 0;
      assignedMacs.add(m);
    }
    perFamilyBytes.push({ name: f.name, role: f.role || '', icon: f.icon || '👤', bytes });
  }
  let unassignedBytes = 0;
  for (const [mac, b] of Object.entries(perDeviceBytes)) {
    if (!assignedMacs.has(mac)) unassignedBytes += b;
  }
  if (unassignedBytes > 0) perFamilyBytes.push({ name: 'Unassigned devices', role: '', icon: '📱', bytes: unassignedBytes });
  perFamilyBytes.sort((a, b) => b.bytes - a.bytes);

  // Top 5 devices
  const top5Devices = Object.entries(perDeviceBytes)
    .map(([mac, bytes]) => ({ mac, name: nameForMac(mac), bytes }))
    .sort((a, b) => b.bytes - a.bytes)
    .slice(0, 5);

  // Top 5 domains (from archive, fallback to ring buffer)
  const archive = (state.flow_archive[customer_id] || []).filter(f => f.ts >= weekAgoMs);
  const archiveSource = archive.length
    ? archive
    : state.flows.filter(f => f.customer_id === customer_id && f.ts >= weekAgoMs);
  const domainBytes = {};
  for (const f of archiveSource) {
    const d = f.dst_domain || '(direct IP)';
    domainBytes[d] = (domainBytes[d] || 0) + (f.bytes_up || 0) + (f.bytes_down || 0);
  }
  const top5Domains = Object.entries(domainBytes)
    .map(([domain, bytes]) => ({ domain, bytes }))
    .sort((a, b) => b.bytes - a.bytes)
    .slice(0, 5);

  // Alarm counts by severity
  const alarmsWeek = (state.alarms || []).filter(a => a.customer_id === customer_id && a.ts >= weekAgoMs);
  const alarmCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const a of alarmsWeek) {
    const k = (a.severity || 'medium').toLowerCase();
    if (alarmCounts[k] !== undefined) alarmCounts[k]++;
  }
  const blockedFlowCount = archiveSource.filter(f => f.blocked).length;

  // New devices
  const newDevices = [];
  for (const bmac of myBoxes) {
    const bucket = state.box_devices[bmac] || {};
    for (const d of Object.values(bucket)) {
      if ((d.first_seen || 0) >= weekAgoMs) {
        newDevices.push({ mac: d.mac, name: d.hostname || d.vendor || d.mac, first_seen: d.first_seen });
      }
    }
  }
  newDevices.sort((a, b) => b.first_seen - a.first_seen);

  const fmtBytes = (b) => {
    if (b < 1024) return b + ' B';
    if (b < 1024 * 1024) return (b / 1024).toFixed(1) + ' KB';
    if (b < 1024 * 1024 * 1024) return (b / (1024 * 1024)).toFixed(1) + ' MB';
    return (b / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
  };
  const escH = (s) => String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

  const brand = (state.config && state.config.brand_name) || 'mes Network';
  const domain = (state.config && state.config.brand_domain) || 'cloud.mes.net.lb';

  let html = `<div style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:640px;margin:0 auto;color:#222">
    <h1 style="color:#ff8c42;margin:0 0 4px 0">📊 Your weekly digest</h1>
    <div style="color:#666;font-size:13px;margin-bottom:18px">${escH(brand)} · ${escH(weekStartISO)} → ${escH(weekEndISO)}</div>
    <p>Hi ${escH(c.name || 'there')}, here's what happened on your network this week:</p>
    <h2 style="border-bottom:2px solid #3ad29f;padding-bottom:4px">📦 Total data: ${fmtBytes(totalBytes)}</h2>`;

  if (perFamilyBytes.length) {
    html += `<h3>👨‍👩‍👧 By family member</h3><ul style="list-style:none;padding:0">`;
    for (const f of perFamilyBytes) {
      const pct = totalBytes > 0 ? ((f.bytes / totalBytes) * 100).toFixed(1) : '0.0';
      html += `<li style="padding:6px 0;border-bottom:1px solid #eee">
        ${escH(f.icon)} <strong>${escH(f.name)}</strong>${f.role ? ` <span style="color:#888;font-size:12px">(${escH(f.role)})</span>` : ''}
        — ${fmtBytes(f.bytes)} <span style="color:#888;font-size:12px">(${pct}%)</span></li>`;
    }
    html += `</ul>`;
  } else {
    html += `<p style="color:#888"><em>No family members configured.</em></p>`;
  }

  html += `<h3>🏆 Top 5 most-active devices</h3>`;
  if (top5Devices.length) {
    html += `<table style="width:100%;border-collapse:collapse">`;
    for (const d of top5Devices) {
      html += `<tr><td style="padding:4px 8px 4px 0">${escH(d.name)}</td>
        <td style="color:#888;font-family:monospace;font-size:11px">${escH(d.mac)}</td>
        <td style="text-align:right;font-weight:600">${fmtBytes(d.bytes)}</td></tr>`;
    }
    html += `</table>`;
  } else {
    html += `<p style="color:#888"><em>No device usage recorded this week.</em></p>`;
  }

  html += `<h3>🌐 Top 5 visited domains</h3>`;
  if (top5Domains.length) {
    html += `<table style="width:100%;border-collapse:collapse">`;
    for (const d of top5Domains) {
      html += `<tr><td style="padding:4px 8px 4px 0">${escH(d.domain)}</td>
        <td style="text-align:right;font-weight:600">${fmtBytes(d.bytes)}</td></tr>`;
    }
    html += `</table>`;
  } else {
    html += `<p style="color:#888"><em>No flow records this week.</em></p>`;
  }

  html += `<h3>🚨 Alarms (${alarmsWeek.length} total)</h3>
    <table style="width:100%;border-collapse:collapse">
      <tr><td>🔴 Critical</td><td style="text-align:right;font-weight:600">${alarmCounts.critical}</td></tr>
      <tr><td>🟠 High</td><td style="text-align:right;font-weight:600">${alarmCounts.high}</td></tr>
      <tr><td>🟡 Medium</td><td style="text-align:right;font-weight:600">${alarmCounts.medium}</td></tr>
      <tr><td>🟢 Low</td><td style="text-align:right;font-weight:600">${alarmCounts.low}</td></tr>
    </table>
    <h3>🛑 Blocks this week</h3>
    <p>Connections blocked by rules or threat intel: <strong>${blockedFlowCount.toLocaleString()}</strong></p>`;

  if (newDevices.length) {
    html += `<h3>🆕 New devices joined this week</h3><ul>`;
    for (const d of newDevices.slice(0, 10)) {
      html += `<li>${escH(d.name)} <span style="font-family:monospace;font-size:11px;color:#888">(${escH(d.mac)})</span></li>`;
    }
    html += `</ul>`;
  }

  html += `<hr style="margin:20px 0;border:none;border-top:1px solid #eee">
    <p style="color:#888;font-size:12px">View live stats: <a href="https://${escH(domain)}/pwa/">${escH(domain)}/pwa</a></p>
    <p style="color:#888;font-size:12px">— ${escH(brand)}</p></div>`;

  return {
    html,
    plain_summary: `Week ${weekStartISO}→${weekEndISO}: ${fmtBytes(totalBytes)} total, ${alarmsWeek.length} alarms, ${blockedFlowCount} blocks.`,
    stats: {
      total_bytes: totalBytes,
      top_devices: top5Devices,
      top_domains: top5Domains,
      alarm_counts: alarmCounts,
      blocked_flow_count: blockedFlowCount,
      new_device_count: newDevices.length,
      family_breakdown: perFamilyBytes,
    },
    week_start: weekStartISO,
    week_end: weekEndISO,
  };
}

// Daily scheduler — on Sunday, build + store + (optionally) email each customer's digest.
function runWeeklyDigestJob(force = false) {
  const now = new Date();
  const isSunday = now.getDay() === 0;
  if (!force && !isSunday) return { skipped: true, reason: 'not_sunday', day: now.getDay() };
  if (!state.weekly_digest_runs) state.weekly_digest_runs = {};
  const today = now.toISOString().slice(0, 10);
  let built = 0, emailed = 0, stored = 0;
  for (const c of Object.values(state.customers)) {
    if (c.status === 'archived' || c.demo) continue;
    if (!force && state.weekly_digest_runs[c.id] === today) continue;
    const digest = buildWeeklyDigest(c.id);
    if (!digest) continue;
    built++;
    const prefs = state.notif_prefs[c.id] || {};
    const wantEmail = prefs.weekly_digest_email === true && !!c.email;
    let delivery_status = 'stored';
    if (wantEmail) {
      try {
        sendEmail(c.email, '📊 Your weekly mes Network digest', digest.html);
        delivery_status = 'sent_to_smtp';
        emailed++;
      } catch (e) {
        delivery_status = 'send_failed:' + e.message;
      }
    }
    if (!state.weekly_digests[c.id]) state.weekly_digests[c.id] = [];
    state.weekly_digests[c.id].unshift({
      id: 'wd-' + shortId(10),
      ts: Date.now(),
      week_start: digest.week_start,
      week_end: digest.week_end,
      html: digest.html,
      summary: digest.plain_summary,
      stats: digest.stats,
      delivery_status,
    });
    if (state.weekly_digests[c.id].length > 26) {
      state.weekly_digests[c.id] = state.weekly_digests[c.id].slice(0, 26);
    }
    state.weekly_digest_runs[c.id] = today;
    stored++;
  }
  saveState();
  console.log(`         📨 weekly digest run: built=${built} stored=${stored} emailed=${emailed} force=${force}`);
  return { ok: true, built, stored, emailed };
}
setTimeout(() => runWeeklyDigestJob(false), 10 * 60_000);
setInterval(() => runWeeklyDigestJob(false), 24 * 3600_000);

// Customer endpoint: list recent digests
app.get('/api/customer/digests/weekly', customerAuth, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 10, 50);
  const list = (state.weekly_digests[req.customer.id] || []).slice(0, limit)
    .map(d => ({ id: d.id, ts: d.ts, week_start: d.week_start, week_end: d.week_end,
                 summary: d.summary, delivery_status: d.delivery_status, html: d.html }));
  res.json({ digests: list });
});

// Preview THIS WEEK's digest without saving
app.get('/api/customer/digests/weekly/preview', customerAuth, (req, res) => {
  const digest = buildWeeklyDigest(req.customer.id);
  if (!digest) return res.status(404).json({ error: 'no_customer' });
  res.json({ digest });
});

// Admin: force-run for everyone
app.post('/admin/api/digest/weekly-tier1/run', adminAuth, (req, res) => {
  const r = runWeeklyDigestJob(true);
  res.json(r);
});

// Toggle the digest email pref (stored on notif_prefs[cid].weekly_digest_email)
app.post('/api/customer/digests/weekly/prefs', customerAuth, (req, res) => {
  const c = req.customer;
  if (!state.notif_prefs[c.id]) state.notif_prefs[c.id] = {};
  if (req.body.weekly_digest_email !== undefined) {
    state.notif_prefs[c.id].weekly_digest_email = !!req.body.weekly_digest_email;
  }
  saveState();
  res.json({ ok: true, weekly_digest_email: !!state.notif_prefs[c.id].weekly_digest_email });
});

// ─── FLOW ARCHIVE (Feature B) ───
function appendFlowToArchive(cid, f) {
  if (!cid) return;
  if (!state.flow_archive[cid]) state.flow_archive[cid] = [];
  state.flow_archive[cid].push({
    ts: f.ts,
    src_mac: f.src_mac,
    dst_domain: f.dst_domain || '',
    dst_ip: f.dst_ip || '',
    dst_port: f.dst_port || 0,
    proto: f.proto || 'tcp',
    bytes_up: f.bytes_up || 0,
    bytes_down: f.bytes_down || 0,
    blocked: !!f.blocked,
    category: f.category || '',
    country: f.country || null,
  });
  if (state.flow_archive[cid].length > FLOW_ARCHIVE_MAX_PER_CUSTOMER) {
    state.flow_archive[cid].splice(0, state.flow_archive[cid].length - FLOW_ARCHIVE_MAX_PER_CUSTOMER);
  }
}
function gcFlowArchive() {
  const cutoff = Date.now() - FLOW_ARCHIVE_RETENTION_MS;
  let dropped = 0;
  for (const [cid, arr] of Object.entries(state.flow_archive)) {
    let i = 0;
    while (i < arr.length && arr[i].ts < cutoff) i++;
    if (i > 0) { arr.splice(0, i); dropped += i; }
  }
  if (dropped > 0) console.log(`         🗑 flow_archive GC: dropped ${dropped} entries older than 90d`);
}
setInterval(gcFlowArchive, 3600_000);
setTimeout(gcFlowArchive, 5 * 60_000);

// Query archive — JSON or CSV. Date filters 'YYYY-MM-DD' inclusive.
app.get('/api/customer/flows/archive', customerAuth, (req, res) => {
  const cid = req.customer.id;
  const arr = state.flow_archive[cid] || [];
  let fromMs, toMs;
  if (req.query.from) {
    const t = Date.parse(req.query.from + 'T00:00:00Z');
    if (!isNaN(t)) fromMs = t;
  }
  if (req.query.to) {
    const t = Date.parse(req.query.to + 'T23:59:59Z');
    if (!isNaN(t)) toMs = t;
  }
  if (!fromMs && !toMs && req.query.days) {
    const days = Math.min(Math.max(parseInt(req.query.days) || 30, 1), 90);
    fromMs = Date.now() - days * 86400_000;
  }
  if (!fromMs && !toMs) fromMs = Date.now() - 30 * 86400_000;
  fromMs = fromMs || 0;
  toMs   = toMs   || Date.now();
  const devMac = req.query.device_mac ? String(req.query.device_mac).toLowerCase() : null;
  const cap = Math.min(parseInt(req.query.limit) || 50_000, 200_000);
  const out = [];
  for (const f of arr) {
    if (f.ts < fromMs || f.ts > toMs) continue;
    if (devMac && (f.src_mac || '').toLowerCase() !== devMac) continue;
    out.push(f);
    if (out.length >= cap) break;
  }
  const format = String(req.query.format || 'json').toLowerCase();
  if (format === 'csv') {
    const esc = v => {
      if (v === null || v === undefined) return '';
      const s = String(v);
      return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
    };
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="flows-${new Date(fromMs).toISOString().slice(0,10)}-to-${new Date(toMs).toISOString().slice(0,10)}.csv"`);
    res.write('ts_iso,src_mac,dst_domain,dst_ip,dst_port,proto,category,country,bytes_up,bytes_down,blocked\n');
    for (const f of out) {
      res.write([
        new Date(f.ts).toISOString(), esc(f.src_mac), esc(f.dst_domain), esc(f.dst_ip),
        f.dst_port, esc(f.proto), esc(f.category), esc(f.country), f.bytes_up, f.bytes_down, f.blocked,
      ].join(',') + '\n');
    }
    return res.end();
  }
  res.json({
    from: new Date(fromMs).toISOString(),
    to:   new Date(toMs).toISOString(),
    device_mac: devMac,
    total: out.length,
    truncated: out.length >= cap,
    archive_total: arr.length,
    retention_days: 90,
    flows: out,
  });
});

// Stats over last N days
app.get('/api/customer/flows/archive/stats', customerAuth, (req, res) => {
  const cid = req.customer.id;
  const arr = state.flow_archive[cid] || [];
  const days = Math.min(Math.max(parseInt(req.query.days) || 30, 1), 90);
  const fromMs = Date.now() - days * 86400_000;
  let total_flows = 0, total_bytes = 0;
  const devBytes = {}, domainBytes = {};
  for (const f of arr) {
    if (f.ts < fromMs) continue;
    total_flows++;
    const bytes = (f.bytes_up || 0) + (f.bytes_down || 0);
    total_bytes += bytes;
    const k = f.src_mac || 'unknown';
    devBytes[k] = (devBytes[k] || 0) + bytes;
    const d = f.dst_domain || '(direct IP)';
    domainBytes[d] = (domainBytes[d] || 0) + bytes;
  }
  const top_devices = Object.entries(devBytes).map(([mac, bytes]) => ({ mac, bytes }))
    .sort((a, b) => b.bytes - a.bytes).slice(0, 10);
  const top_domains = Object.entries(domainBytes).map(([domain, bytes]) => ({ domain, bytes }))
    .sort((a, b) => b.bytes - a.bytes).slice(0, 10);
  res.json({ days, from: new Date(fromMs).toISOString(), total_flows, total_bytes, top_devices, top_domains, archive_size: arr.length });
});

// /api/customer/vpn — kept as a redirect to WireGuard for old links
app.get('/api/customer/vpn', customerAuth, (req, res) => {
  res.status(410).json({ error: 'gone', message: 'OpenVPN is no longer offered. Use WireGuard via /api/customer/wg/peers.' });
});

// GET /api/customer/report?month=YYYY-MM — printable HTML report
app.get('/api/customer/report', customerAuth, (req, res) => {
  const c = req.customer;
  const month = req.query.month || new Date().toISOString().slice(0, 7);  // YYYY-MM
  state.events.push({ ts: Date.now(), method: 'CUSTOMER', path: `[REPORT] ${c.name} downloaded ${month}`, ip: req.ip });

  // Build per-device totals (deterministic, based on weight ranges)
  const devices = [
    { name: c.name + "'s iPhone",     icon: '📱', mac: 'aa:bb:cc:11:11:11', weight: 1.4, gb_month: 18 },
    { name: 'Samsung TV (Living Rm)', icon: '📺', mac: 'aa:bb:cc:22:22:22', weight: 3.2, gb_month: 96 },
    { name: "Kid's iPad",             icon: '📱', mac: 'aa:bb:cc:33:33:33', weight: 1.0, gb_month: 12 },
    { name: 'PlayStation 5',          icon: '🎮', mac: 'aa:bb:cc:44:44:44', weight: 4.5, gb_month: 145 },
    { name: 'Smart bulb (Kitchen)',   icon: '💡', mac: 'aa:bb:cc:55:55:55', weight: 0.05, gb_month: 0.4 },
    { name: 'Mikrotik Router',        icon: '📡', mac: 'aa:bb:cc:66:66:66', weight: 0.5, gb_month: 6 },
  ];
  const totalGB = devices.reduce((a, d) => a + d.gb_month, 0);
  const fam = state.family_members[c.id] || [];
  const schedules = state.schedules[c.id] || [];

  const html = `<!DOCTYPE html>
<html><head>
<meta charset="UTF-8"><title>mes Network — Monthly Report — ${c.name}</title>
<style>
@page { margin: 16mm; size: A4; }
body { font-family: -apple-system, system-ui, sans-serif; max-width: 720px; margin: 0 auto; padding: 24px; color: #222; }
header { border-bottom: 3px solid #ff8c42; padding-bottom: 14px; margin-bottom: 22px; }
header h1 { color: #0f1419; font-size: 26px; margin: 0; }
header .sub { color: #6c7686; font-size: 14px; }
.box { background:#f6f8fb; border-left:3px solid #3ad29f; padding: 14px 18px; margin:14px 0; border-radius:4px; font-size:14px; }
table { width: 100%; border-collapse: collapse; margin: 14px 0; font-size: 13px; }
th { text-align: left; background: #0f1419; color: #ff8c42; padding: 8px 10px; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }
td { padding: 8px 10px; border-bottom: 1px solid #e6e8ec; }
td.num { text-align: right; font-variant-numeric: tabular-nums; }
.grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px; margin: 16px 0; }
.stat { background: #fff; border: 1px solid #e6e8ec; border-radius: 8px; padding: 14px; text-align: center; }
.stat .num { font-size: 22px; font-weight: 700; color: #ff8c42; }
.stat .lbl { font-size: 11px; color: #6c7686; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }
footer { margin-top: 30px; border-top: 1px solid #e6e8ec; padding-top: 14px; color: #6c7686; font-size: 11px; }
.print-note { background: #fff3cd; border: 1px solid #ffc107; padding: 8px 12px; border-radius: 4px; font-size: 12px; margin-bottom: 18px; }
@media print { .print-note { display: none; } }
</style>
</head><body>

<div class="print-note">
  📥 To save as PDF: press Ctrl+P (Cmd+P on Mac) → choose "Save as PDF"
</div>

<header>
  <h1>📦 mes Network — Monthly Report</h1>
  <div class="sub">${c.name} · ${c.phone || ''} · Plan: <strong>${c.plan}</strong></div>
  <div class="sub">Period: <strong>${month}</strong> · Generated ${new Date().toLocaleString()}</div>
</header>

<div class="grid">
  <div class="stat"><div class="num">${totalGB.toFixed(0)} GB</div><div class="lbl">Total this month</div></div>
  <div class="stat"><div class="num">${devices.filter(d => d.gb_month >= 1).length}</div><div class="lbl">Active devices</div></div>
  <div class="stat"><div class="num">${fam.length}</div><div class="lbl">Family members</div></div>
</div>

<h2>Bandwidth by device</h2>
<table>
  <thead><tr><th>Device</th><th>MAC</th><th>Owner</th><th class="num">GB this month</th></tr></thead>
  <tbody>
    ${devices.map(d => {
      const owner = fam.find(f => (f.device_macs || []).includes(d.mac));
      return `<tr>
        <td>${d.icon} ${d.name}</td>
        <td style="font-family:monospace;font-size:12px;">${d.mac}</td>
        <td>${owner ? owner.name + ' (' + owner.role + ')' : '—'}</td>
        <td class="num">${d.gb_month.toFixed(1)}</td>
      </tr>`;
    }).join('')}
  </tbody>
</table>

<h2>Active schedule blocks</h2>
${schedules.length ? `
<table>
  <thead><tr><th>Name</th><th>Time</th><th>Days</th><th>Devices</th></tr></thead>
  <tbody>
    ${schedules.map(s => `<tr>
      <td>${s.name}</td>
      <td>${s.start_hhmm} → ${s.end_hhmm}</td>
      <td>${(s.days || []).map(d => 'SMTWTFS'[d]).join('')}</td>
      <td>${(s.device_macs || []).length}</td>
    </tr>`).join('')}
  </tbody>
</table>` : '<div class="box">No schedule blocks configured.</div>'}

<h2>Family members</h2>
${fam.length ? `
<table>
  <thead><tr><th>Name</th><th>Role</th><th>Devices</th></tr></thead>
  <tbody>
    ${fam.map(f => `<tr><td>${f.icon || '👤'} ${f.name}</td><td>${f.role}</td><td>${(f.device_macs || []).length}</td></tr>`).join('')}
  </tbody>
</table>` : '<div class="box">No family profiles yet.</div>'}

<footer>
  <strong>mes Network</strong> · cloud.mes.net.lb · This report is for the customer's records.
  Bandwidth figures are aggregated from your box's flow accounting.
</footer>

</body></html>`;

  res.set('Content-Type', 'text/html; charset=utf-8');
  res.send(html);
});

// POST /api/customer/block-device { mac, name?, unblock? }
// Flips state.box_devices[box_mac][device_mac].blocked. The policy bundle
// (see /api/box/policy/:mac) picks blocked devices up into quota_blocked,
// which the box agent enforces via the nft quota_blocked_macs set.
app.post('/api/customer/block-device', customerAuth, (req, res) => {
  const c = req.customer;
  const dmac = normalizeMac(String(req.body.mac || ''));
  if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(dmac)) {
    return res.status(400).json({ error: 'mac required' });
  }
  const unblock = !!req.body.unblock;
  const myBoxes = Object.values(state.authorized_macs).filter(m => m.customer_id === c.id);
  let found = false;
  for (const b of myBoxes) {
    const bucket = state.box_devices[b.mac];
    if (bucket && bucket[dmac]) {
      bucket[dmac].blocked = !unblock;
      found = true;
    }
  }
  // Keep BOTH block signals in sync: the box_devices flag AND any MAC-type
  // rules. Without this, a "Block" via /customer/rules/add (the older PWA
  // path) leaves a stale rule after Unblock — policy bundle keeps shipping
  // the MAC in quota_blocked → device stays dropped at kernel level.
  if (!state.rules[c.id]) state.rules[c.id] = [];
  if (unblock) {
    state.rules[c.id] = state.rules[c.id].filter(r =>
      !(r.type === 'mac' && r.action === 'block' && (r.value || '').toLowerCase() === dmac)
    );
  } else {
    // Add a block rule if one doesn't already exist for this MAC
    const hasBlock = state.rules[c.id].some(r =>
      r.type === 'mac' && r.action === 'block' && (r.value || '').toLowerCase() === dmac && r.enabled !== false
    );
    if (!hasBlock) {
      state.rules[c.id].push({
        id: shortId(12), type: 'mac', value: dmac, action: 'block',
        scope: 'device', target: dmac, enabled: true, note: 'device-block',
        created_at: Date.now(),
      });
    }
    // Also drop any opposing allow rule for the same MAC
    state.rules[c.id] = state.rules[c.id].filter(r =>
      !(r.type === 'mac' && r.action === 'allow' && (r.value || '').toLowerCase() === dmac)
    );
  }
  if (c.id && typeof bumpPolicyEtag === 'function') bumpPolicyEtag(c.id, 'device-block');
  state.events.push({
    ts: Date.now(),
    method: 'CUSTOMER',
    path: `[${unblock ? 'UNBLOCK' : 'BLOCK'}] ${c.name} ${unblock ? 'unblocked' : 'blocked'} ${req.body.name || dmac}`,
    ip: req.ip,
  });
  console.log(`         ${unblock ? '✅' : '🛑'} CUSTOMER ${unblock ? 'UNBLOCK' : 'BLOCK'} → ${c.name}  device=${dmac}${found ? '' : ' (not on any box yet)'}`);
  saveState();
  res.json({ ok: true, mac: dmac, blocked: !unblock, found });
});

// ─── Support chat ───
app.get('/api/customer/support', customerAuth, (req, res) => {
  const arr = state.support_threads[req.customer.id] || [];
  // Mark all admin messages as read by customer
  arr.forEach(m => { if (m.from === 'admin') m.read_by_customer = true; });
  res.json({ messages: arr });
});

// Bug report — bundles the message + browser/agent context
app.post('/api/customer/bug-report', customerAuth, (req, res) => {
  const c = req.customer;
  const description = String(req.body.description || '').slice(0, 5000).trim();
  if (!description) return res.status(400).json({ error: 'description required' });
  const ctx = {
    user_agent: req.headers['user-agent'] || '',
    url: String(req.body.url || '').slice(0, 200),
    customer_meta: { plan: c.plan, status: c.status, tenant_id: c.tenant_id || null },
    recent_events: (req.body.recent_events || []).slice(0, 50),
  };
  if (!state.support_threads[c.id]) state.support_threads[c.id] = [];
  const msg = {
    id: 'bug-' + shortId(8),
    from: 'customer',
    body: '🐛 BUG REPORT:\n\n' + description + '\n\n--- context ---\n' + JSON.stringify(ctx, null, 2),
    ts: Date.now(),
    bug_report: true,
    read_by_admin: false,
    read_by_customer: true,
  };
  state.support_threads[c.id].push(msg);
  saveState();
  state.events.push({ ts: Date.now(), method: 'CUSTOMER', path: `[BUG-REPORT] ${c.name}`, ip: req.ip });
  console.log(`         🐛 BUG REPORT → ${c.name}: "${description.slice(0, 80)}"`);
  if (typeof broadcastSSE === 'function') broadcastSSE('support_msg', { customer_id: c.id, customer_name: c.name, ...msg });
  if (state.config.admin_email) {
    sendEmail(state.config.admin_email, '[mes Network] 🐛 Bug report from ' + c.name,
      `Customer: ${c.name} (${c.phone})\n\nDescription:\n${description}\n\nContext:\n${JSON.stringify(ctx, null, 2)}`);
  }
  res.json({ ok: true });
});

app.post('/api/customer/support', customerAuth, (req, res) => {
  const c = req.customer;
  if (!state.support_threads[c.id]) state.support_threads[c.id] = [];
  const body = String(req.body.body || '').slice(0, 1000).trim();
  if (!body) return res.status(400).json({ error: 'empty message' });
  const msg = {
    id: 'msg-' + shortId(8),
    from: 'customer',
    body,
    ts: Date.now(),
    read_by_admin: false,
    read_by_customer: true,
  };
  state.support_threads[c.id].push(msg);
  saveState();
  state.events.push({ ts: Date.now(), method: 'CUSTOMER', path: `[SUPPORT] ${c.name}: "${body.slice(0, 60)}${body.length > 60 ? '…' : ''}"`, ip: req.ip });
  console.log(`         💬 SUPPORT MSG → ${c.name}: "${body.slice(0, 60)}"`);
  // Push to admin SSE so they see it instantly
  if (typeof broadcastSSE === 'function') broadcastSSE('support_msg', { customer_id: c.id, customer_name: c.name, ...msg });
  // Email admin (legacy fallback)
  sendEmail(state.config.admin_email, '[mes Network] Support message from ' + c.name,
    `Customer: ${c.name} (${c.phone})\n\nMessage:\n${body}\n\nReply via /admin → Customers → Support.`);
  res.json({ ok: true, message: msg });
});

// ─── Invoices ───
function genMonthlyInvoice(customer_id, periodYYYYMM) {
  const c = state.customers[customer_id];
  if (!c) return null;
  const currency = c.currency || 'USD';
  const price = planPrice(c.plan, currency);
  const existing = Object.values(state.invoices).find(i => i.customer_id === customer_id && i.period === periodYYYYMM);
  if (existing) return existing;

  const lines = [{ desc: price.label, qty: 1, unit: price.monthly, total: price.monthly }];
  let amount = price.monthly;
  let discount = 0;
  let promo_code = null;

  if (c.promo_code) {
    const result = applyPromoCode(c.promo_code, amount, currency, c.plan);
    if (result.discount > 0) {
      lines.push({ desc: 'Discount: ' + result.description, qty: 1, unit: -result.discount, total: -result.discount });
      amount = result.amount;
      discount = result.discount;
      promo_code = result.code;
      // Increment usage
      if (state.promo_codes[c.promo_code]) state.promo_codes[c.promo_code].uses++;
    }
  }

  const id = 'inv-' + shortId(10);
  const now = new Date();
  const due = new Date(now.getTime() + 15 * 86400_000);
  const inv = {
    id, customer_id, customer_name: c.name, period: periodYYYYMM,
    amount, currency, status: 'unpaid', plan: c.plan, lines,
    discount, promo_code,
    created_at: now.toISOString(),
    due_at: due.toISOString(),
    paid_at: null,
    reminders_sent: [],   // ['7d', '3d', '1d', 'overdue']
  };
  state.invoices[id] = inv;
  return inv;
}

// ─── Billing reminder cron ──────────────────────────────────────────────
// Every hour, check unpaid invoices and notify customer at 7d / 3d / 1d before due, and on overdue.
function sendBillingReminders() {
  const now = Date.now();
  for (const inv of Object.values(state.invoices || {})) {
    if (inv.status === 'paid') continue;
    if (!inv.due_at) continue;
    const due = new Date(inv.due_at).getTime();
    const daysToDue = (due - now) / 86400_000;
    if (!Array.isArray(inv.reminders_sent)) inv.reminders_sent = [];
    const sendIf = (key, label, body) => {
      if (inv.reminders_sent.includes(key)) return;
      if (typeof pushNotification === 'function') {
        pushNotification(inv.customer_id, 'billing', label, body);
      }
      inv.reminders_sent.push(key);
    };
    const amountStr = `${inv.amount} ${inv.currency}`;
    if (daysToDue > 0 && daysToDue <= 1) {
      sendIf('1d', '⚠️ Payment due tomorrow', `Invoice ${inv.id} (${amountStr}) is due in 24h. Please pay to avoid service interruption.`);
    } else if (daysToDue > 1 && daysToDue <= 3) {
      sendIf('3d', '⏳ Payment due in 3 days', `Invoice ${inv.id} (${amountStr}) is due ${inv.due_at.slice(0,10)}.`);
    } else if (daysToDue > 3 && daysToDue <= 7) {
      sendIf('7d', '📅 Payment reminder', `Invoice ${inv.id} (${amountStr}) is due in 7 days.`);
    } else if (daysToDue < 0 && !inv.reminders_sent.includes('overdue')) {
      sendIf('overdue', '🚨 Payment overdue', `Invoice ${inv.id} (${amountStr}) was due ${inv.due_at.slice(0,10)}. Please pay now.`);
    }
  }
  saveState();
}
setInterval(sendBillingReminders, 3600_000);
setTimeout(sendBillingReminders, 10 * 60_000);

// Customer: list own invoices
// Billing breakdown — show the math behind a customer's pricing
app.get('/api/customer/billing-breakdown', customerAuth, (req, res) => {
  const c = req.customer;
  const currency = c.currency || 'LBP';
  const planUsd = ({basic:5, family:10, pro:20, business:50})[c.plan] || 0;
  const lbpRate = lbpPerUsd();
  const baseUsd = planUsd;
  const baseLbp = planUsd * lbpRate;

  const promo = applyPromoCode(c.promo_code, currency === 'USD' ? baseUsd : baseLbp, currency, c.plan, c.tenant_id);
  const trialActive = c.trial_status === 'active' && c.trial_until && Date.now() < c.trial_until;
  const referralCredits = c.referral_credits || 0;
  const inPause = c.subscription_paused;

  res.json({
    plan: c.plan,
    base_usd: baseUsd,
    lbp_rate: lbpRate,
    base_lbp: baseLbp,
    currency,
    promo_code: c.promo_code || null,
    promo_discount_currency: promo.discount,
    promo_description: promo.description || null,
    referral_credits_remaining: referralCredits,
    referral_free_months_to_apply: referralCredits,
    trial_active: trialActive,
    trial_until: c.trial_until || null,
    subscription_paused: !!inPause,
    paused_until: c.subscription_resumes_at || null,
    next_invoice: {
      amount_usd: trialActive ? 0 : (referralCredits > 0 ? 0 : baseUsd - (currency === 'USD' ? promo.discount : 0)),
      amount_lbp: trialActive ? 0 : (referralCredits > 0 ? 0 : baseLbp - (currency === 'LBP' ? promo.discount : 0)),
      will_charge: !trialActive && referralCredits === 0 && !inPause,
      reason_no_charge: trialActive ? 'in trial' : (referralCredits > 0 ? 'referral credit applied' : (inPause ? 'paused' : null)),
    },
    explanation: trialActive
      ? `You're in your free trial until ${new Date(c.trial_until).toUTCString()}. No charges yet.`
      : (referralCredits > 0 ? `One free month from a referral applies to your next invoice.`
      : (inPause ? `Subscription paused — no charges until you resume.`
      : `Your next invoice will be ${currency === 'USD' ? '$' + (baseUsd - promo.discount) : Math.round(baseLbp - promo.discount).toLocaleString() + ' LBP'}${promo.code ? ' (with ' + promo.code + ' applied)' : ''}.`)),
  });
});

app.get('/api/customer/invoices', customerAuth, (req, res) => {
  const list = Object.values(state.invoices).filter(i => i.customer_id === req.customer.id)
    .sort((a, b) => b.period.localeCompare(a.period));
  res.json({
    invoices: list,
    next_due: list.find(i => i.status === 'unpaid') || null,
  });
});

// Customer: get one invoice (HTML, printable)
app.get('/api/customer/invoices/:id.html', customerAuth, (req, res) => {
  const inv = state.invoices[req.params.id];
  if (!inv || inv.customer_id !== req.customer.id) return res.status(404).send('not found');
  const c = req.customer;
  const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Invoice ${inv.id}</title>
<style>
body { font-family: -apple-system, system-ui, sans-serif; max-width: 720px; margin: 0 auto; padding: 30px; color: #222; }
header { border-bottom: 3px solid #ff8c42; padding-bottom: 14px; margin-bottom: 22px; }
header h1 { color: #0f1419; margin: 0; }
.row { display: flex; justify-content: space-between; margin: 14px 0; }
table { width: 100%; border-collapse: collapse; margin: 18px 0; }
th { background: #0f1419; color: #ff8c42; text-align: left; padding: 10px; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }
td { padding: 10px; border-bottom: 1px solid #eee; }
td.r { text-align: right; }
.total { font-size: 1.4em; font-weight: 700; color: #0f1419; }
.status-paid { color: #3ad29f; }
.status-unpaid { color: #ff5c5c; }
.print-note { background: #fff3cd; border: 1px solid #ffc107; padding: 8px 12px; border-radius: 4px; font-size: 12px; margin-bottom: 18px; }
@media print { .print-note { display: none; } }
</style></head><body>
<div class="print-note">📥 To save as PDF: press Ctrl+P (Cmd+P on Mac) → "Save as PDF"</div>
<header>
  <h1>📦 mes Network — Invoice</h1>
  <div style="color:#6c7686;font-size:14px;">Invoice #${inv.id} · Period ${inv.period}</div>
</header>
<div class="row">
  <div><strong>Bill to:</strong><br>${c.name}<br>${c.phone}<br>${c.email || ''}<br>${c.address || ''}</div>
  <div style="text-align:right;"><strong>Status:</strong> <span class="status-${inv.status}">${inv.status.toUpperCase()}</span><br>
  Issued: ${inv.created_at.slice(0,10)}<br>
  ${inv.paid_at ? 'Paid: ' + inv.paid_at.slice(0,10) : 'Due on receipt'}</div>
</div>
<table>
  <thead><tr><th>Description</th><th class="r">Qty</th><th class="r">Unit</th><th class="r">Total</th></tr></thead>
  <tbody>
    ${inv.lines.map(l => `<tr><td>${l.desc}</td><td class="r">${l.qty}</td><td class="r">${inv.currency} ${l.unit.toFixed(2)}</td><td class="r">${inv.currency} ${l.total.toFixed(2)}</td></tr>`).join('')}
  </tbody>
</table>
<div class="row" style="margin-top:24px;"><div></div><div class="total">Total: ${inv.currency} ${inv.amount.toFixed(2)}</div></div>
</body></html>`;
  res.type('html').send(html);
});

// Promo code management
app.get('/admin/api/promo-codes', adminAuth, (req, res) => {
  const tenant = req.query.tenant_id || null;
  const all = Object.values(state.promo_codes);
  const filtered = tenant ? all.filter(c => c.tenant_id === tenant) : all;
  res.json({ codes: filtered });
});

app.post('/admin/api/promo-codes/create', adminAuth, (req, res) => {
  const code = String(req.body.code || '').toUpperCase().trim().slice(0, 20);
  if (!/^[A-Z0-9_-]+$/.test(code)) return res.status(400).json({ error: 'code must be A-Z 0-9 _ - only' });
  if (state.promo_codes[code]) return res.status(409).json({ error: 'code exists' });
  const promo = {
    code,
    type: req.body.type === 'fixed' ? 'fixed' : 'percent',  // default: percent
    value: Number(req.body.value) || 10,
    currency: req.body.currency || null,  // for fixed-type
    description: req.body.description || '',
    expires_at: req.body.expires_at || null,
    max_uses: Number(req.body.max_uses) || null,
    uses: 0,
    applies_to_plans: Array.isArray(req.body.applies_to_plans) ? req.body.applies_to_plans : [],
    tenant_id: req.body.tenant_id || null,  // null = global, otherwise scoped to tenant
    created_at: new Date().toISOString(),
    created_by: req.adminUser,
  };
  state.promo_codes[code] = promo;
  saveState();
  logAdminAction(req, 'promo.create', code);
  res.json({ ok: true, promo });
});

app.post('/admin/api/promo-codes/delete', adminAuth, (req, res) => {
  delete state.promo_codes[req.body.code];
  saveState();
  logAdminAction(req, 'promo.delete', req.body.code);
  res.json({ ok: true });
});

// Customer applies promo code (saved, applied at next invoice)
app.post('/api/customer/promo-apply', customerAuth, (req, res) => {
  const code = String(req.body.code || '').toUpperCase().trim();
  const c = req.customer;
  const test = applyPromoCode(code, planPrice(c.plan, c.currency || 'USD').monthly, c.currency || 'USD', c.plan);
  if (test.error) return res.status(400).json({ error: test.error });
  c.promo_code = code;
  saveState();
  res.json({ ok: true, code, discount_preview: test.discount });
});

// Admin: list all invoices
app.get('/admin/api/invoices', adminAuth, (req, res) => {
  res.json({ invoices: Object.values(state.invoices).sort((a, b) => b.period.localeCompare(a.period)) });
});

// Admin: mark invoice paid/unpaid
app.post('/admin/api/invoices/mark', adminAuth, (req, res) => {
  const inv = state.invoices[req.body.id];
  if (!inv) return res.status(404).json({ error: 'not found' });
  if (req.body.status === 'paid') {
    inv.status = 'paid';
    inv.paid_at = new Date().toISOString();
    pushNotification(inv.customer_id, 'success', '✅ Payment received',
      `Thank you! Invoice ${inv.id} for ${inv.period} (${inv.currency} ${inv.amount}) is paid.`);
  } else {
    inv.status = 'unpaid';
    inv.paid_at = null;
  }
  saveState();
  logAdminAction(req, 'invoice.mark_' + req.body.status, inv.id, '');
  fireWebhooks('invoice.' + req.body.status, { invoice: inv });
  res.json({ ok: true, invoice: inv });
});

// Admin: trigger this-month invoice generation for all active customers
app.post('/admin/api/invoices/generate-month', adminAuth, (req, res) => {
  const period = req.body.period || new Date().toISOString().slice(0, 7);
  let created = 0, existed = 0;
  for (const c of Object.values(state.customers)) {
    // Treat customers without a status field (legacy) as active
    if (c.status && c.status !== 'active') continue;
    const before = Object.keys(state.invoices).length;
    genMonthlyInvoice(c.id, period);
    if (Object.keys(state.invoices).length > before) {
      created++;
      // Email customer (if email_enabled and they have email)
      if (c.email) {
        const inv = Object.values(state.invoices).find(i => i.customer_id === c.id && i.period === period);
        sendEmail(c.email, `[mes Network] Invoice for ${period}`,
          `Hi ${c.name},\n\nYour invoice for ${period} is ready: ${inv.currency} ${inv.amount}.\n\nView at: ${state.config.brand_domain ? 'https://' + state.config.brand_domain : ''}/pwa/ → Settings → Invoices.\n\nmes Network team`);
      }
    } else {
      existed++;
    }
  }
  saveState();
  logAdminAction(req, 'invoices.generate', period, `created=${created} existed=${existed}`);
  fireWebhooks('invoices.generated', { period, created, existed });
  res.json({ ok: true, period, created, existed });
});

// Customer profile edit
app.post('/api/customer/me/update', customerAuth, (req, res) => {
  const c = req.customer;
  // Customer can edit name, address — phone (identity) and plan (admin) excluded.
  // Email goes through verification flow below; ignore email here.
  if (req.body.name !== undefined) c.name = String(req.body.name).slice(0, 80).trim() || c.name;
  if (req.body.address !== undefined) c.address = String(req.body.address).slice(0, 200).trim();
  saveState();
  state.events.push({ ts: Date.now(), method: 'CUSTOMER', path: `[PROFILE-EDIT] ${c.name}`, ip: req.ip });
  console.log(`         📝 PROFILE EDIT → ${c.name}`);
  const { staff_notes, ...safe } = c;
  res.json({ ok: true, customer: safe });
});

// ─── Family member dashboard access (read-only share) ────────────────────
// Account holder issues a signed link that gives a family member read-only access.
// Implemented as a special "share token" that yields a JWT with `read_only: true`.
if (!state.family_share_tokens) state.family_share_tokens = {};   // token → {cid, label, created_at, last_used_at, expires_at, revoked}
app.get('/api/customer/family-share', customerAuth, (req, res) => {
  const cid = req.customer.id;
  const mine = Object.entries(state.family_share_tokens)
    .filter(([_, s]) => s.cid === cid && !s.revoked)
    .map(([token, s]) => ({ token: token.slice(0, 8) + '...', label: s.label,
      created_at: s.created_at, last_used_at: s.last_used_at, expires_at: s.expires_at }));
  res.json({ shares: mine });
});
app.post('/api/customer/family-share/create', customerAuth, (req, res) => {
  const cid = req.customer.id;
  const label = String(req.body.label || 'Family member').slice(0, 60);
  const days = Math.min(Math.max(parseInt(req.body.days) || 30, 1), 365);
  // Limit: 5 active shares per customer
  const active = Object.values(state.family_share_tokens).filter(s => s.cid === cid && !s.revoked).length;
  if (active >= 5) return res.status(429).json({ error: 'max 5 active shares' });
  const token = crypto.randomBytes(24).toString('base64url');
  state.family_share_tokens[token] = {
    cid, label,
    created_at: Date.now(),
    last_used_at: 0,
    expires_at: Date.now() + days * 86400_000,
    revoked: false,
  };
  saveState();
  res.json({ ok: true, token, share_url: `https://cloud.mes.net.lb/pwa/?share_token=${token}`, expires_in_days: days });
});
app.post('/api/customer/family-share/revoke', customerAuth, (req, res) => {
  const cid = req.customer.id;
  const tokenPrefix = String(req.body.token_prefix || '');
  // Find by prefix (we never returned the full token after creation)
  const found = Object.entries(state.family_share_tokens)
    .find(([t, s]) => s.cid === cid && t.startsWith(tokenPrefix.replace(/\.\.\.$/, '')));
  if (!found) return res.status(404).json({ error: 'not found' });
  state.family_share_tokens[found[0]].revoked = true;
  saveState();
  res.json({ ok: true });
});
// Exchange share token for a short-lived read-only customer JWT
app.post('/api/customer/family-share/exchange', (req, res) => {
  const token = String(req.body.token || '');
  const s = state.family_share_tokens[token];
  if (!s || s.revoked) return res.status(404).json({ error: 'invalid_or_revoked' });
  if (Date.now() > s.expires_at) return res.status(410).json({ error: 'expired' });
  const c = state.customers[s.cid];
  if (!c) return res.status(404).json({ error: 'customer_gone' });
  s.last_used_at = Date.now();
  // 6-hour read-only JWT with `family_share: true` claim. customerAuth is unmodified;
  // we encode a marker the PWA can read to gray out write actions client-side.
  const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    sub: c.id, name: c.name, plan: c.plan,
    family_share: true, share_label: s.label,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 6 * 3600,
  })).toString('base64url');
  const sig = crypto.sign(null, Buffer.from(header + '.' + payload), licenseKeys.privateKey).toString('base64url');
  const jwt = `${header}.${payload}.${sig}`;
  saveState();
  res.json({ ok: true, token: jwt, label: s.label, expires_in_sec: 6 * 3600, read_only: true });
});

// ─── Email change with verification ───────────────────────────────────────
// Two-step: customer requests new email → cloud stores pending + token. Customer
// confirms via /verify-email-change?token=… (clickable link in confirmation email).
if (!state.email_change_requests) state.email_change_requests = {};   // token → {cid, new_email, created_at}
app.post('/api/customer/me/email-change', customerAuth, (req, res) => {
  const c = state.customers[req.customer.id];
  const newEmail = String(req.body.email || '').trim().toLowerCase();
  if (!/^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i.test(newEmail)) return res.status(400).json({ error: 'invalid email' });
  if (newEmail === (c.email || '').toLowerCase()) return res.status(400).json({ error: 'same as current email' });
  // Single active request per customer — replace any old token
  for (const [tok, r] of Object.entries(state.email_change_requests)) {
    if (r.cid === c.id) delete state.email_change_requests[tok];
  }
  const token = crypto.randomBytes(24).toString('base64url');
  state.email_change_requests[token] = { cid: c.id, new_email: newEmail, created_at: Date.now() };
  saveState();
  const link = `https://cloud.mes.net.lb/api/customer/verify-email-change?token=${token}`;
  // Pretend email send (no SMTP infra): log + push notification with the link
  console.log(`         ✉️  EMAIL-CHANGE → ${c.name} new=${newEmail} link=${link}`);
  if (typeof pushNotification === 'function') {
    pushNotification(c.id, 'system', '✉️ Confirm email change',
      `Click the link to confirm your new email (${newEmail}). Link expires in 24h.\n${link}`);
  }
  res.json({ ok: true, message: 'Confirmation sent — click the link in your notifications/email.', expires_in_hours: 24 });
});

// Public confirmation endpoint — anyone with the token can confirm (it was emailed to the new address).
app.get('/api/customer/verify-email-change', (req, res) => {
  const token = String(req.query.token || '');
  const r = state.email_change_requests[token];
  if (!r) return res.status(404).type('html').send('<h1>Invalid or used link</h1>');
  if (Date.now() - r.created_at > 24 * 3600_000) {
    delete state.email_change_requests[token];
    return res.status(410).type('html').send('<h1>Link expired</h1>Request a new email change.');
  }
  const c = state.customers[r.cid];
  if (!c) { delete state.email_change_requests[token]; return res.status(404).type('html').send('<h1>Account no longer exists</h1>'); }
  const oldEmail = c.email;
  c.email = r.new_email;
  c.email_verified_at = Date.now();
  delete state.email_change_requests[token];
  saveState();
  if (typeof pushNotification === 'function') {
    pushNotification(c.id, 'security', '✓ Email updated', `Your email was changed from ${oldEmail || '(empty)'} to ${r.new_email}.`);
  }
  res.type('html').send(`<h1>✓ Email confirmed</h1><p>Your email is now <b>${r.new_email}</b>. You can close this page.</p>`);
});

// Customer session management. JWTs are stateless, so "active sessions" approximates
// from login history; revocation works by bumping c._jwt_min_iat (rejects older tokens).
app.get('/api/customer/sessions', customerAuth, (req, res) => {
  const c = req.customer;
  const logins = (state.customer_logins[c.id] || []).filter(l => l.success !== false);
  // Recent successful logins (likely-active sessions, JWT lifetime is 30d)
  const cutoff = Date.now() - 30 * 86400_000;
  const sessions = logins.filter(l => l.ts >= cutoff).slice(-30).reverse().map(l => ({
    ts: l.ts, ip: l.ip, ua: l.ua, age_days: Math.round((Date.now() - l.ts) / 86400_000),
  }));
  res.json({
    sessions,
    revoke_before_ts: c._jwt_min_iat ? c._jwt_min_iat * 1000 : null,
    note: 'JWTs are stateless. Use revoke-all to invalidate every active session at once.',
  });
});
app.post('/api/customer/sessions/revoke-all', customerAuth, (req, res) => {
  const c = state.customers[req.customer.id];
  c._jwt_min_iat = Math.floor(Date.now() / 1000);
  saveState();
  if (typeof pushNotification === 'function') {
    pushNotification(c.id, 'security', '🔐 All sessions revoked',
      'You revoked all login sessions. Other browsers/devices will be signed out.');
  }
  res.json({ ok: true, revoked_before_ts: c._jwt_min_iat * 1000 });
});

// Customer onboarding checklist — derives current completion state from data.
app.get('/api/customer/onboarding', customerAuth, (req, res) => {
  const c = req.customer;
  const myMacs = Object.values(state.authorized_macs).filter(m => m.customer_id === c.id);
  const onlineNow = myMacs.some(m => {
    const s = state.box_state[m.mac];
    return s && s.last_heartbeat && (Date.now() - s.last_heartbeat) < 5 * 60_000;
  });
  const myDevices = myMacs.flatMap(m => Object.values(state.box_devices[m.mac] || {}));
  const myRules = state.rules[c.id] || [];
  const myFamily = state.family_members[c.id] || [];
  const mySchedules = state.schedules[c.id] || [];
  const myPushSubs = (state.push_subscriptions[c.id] || []).length;
  const myWg = Object.values(state.wg_peers || {}).filter(p => p.customer_id === c.id).length;
  const myDdns = Object.values(state.ddns || {}).some(d => d.customer_id === c.id);

  const items = [
    { id: 'paired_box',       label: 'Pair your mes Box', done: myMacs.length > 0,    weight: 1 },
    { id: 'box_online',       label: 'Box online and reporting', done: onlineNow,    weight: 1 },
    { id: 'devices_seen',     label: 'Box has discovered devices', done: myDevices.length > 0, weight: 1 },
    { id: 'first_rule',       label: 'Add your first block rule', done: myRules.length > 0, weight: 1 },
    { id: 'family_member',    label: 'Add a family member',  done: myFamily.length > 0, weight: 1 },
    { id: 'schedule',         label: 'Set a screen-time schedule', done: mySchedules.length > 0, weight: 1 },
    { id: 'push_enabled',     label: 'Enable push notifications',  done: myPushSubs > 0, weight: 1 },
    { id: 'vpn_setup',        label: 'Set up WireGuard VPN', done: myWg > 0,           weight: 1 },
    { id: 'ddns_setup',       label: 'Configure DDNS hostname',    done: myDdns,        weight: 1 },
    { id: 'pwa_installed',    label: 'Install the PWA on your phone', done: !!c._pwa_installed, weight: 1 },
  ];
  const completed = items.filter(i => i.done).length;
  const total = items.length;
  res.json({ items, completed, total, percent: Math.round((completed / total) * 100) });
});
// Inline guided tour step tracking (which steps the customer has seen + completed).
app.get('/api/customer/tour-progress', customerAuth, (req, res) => {
  const c = req.customer;
  res.json({
    seen_steps: c.tour_seen_steps || [],
    dismissed: !!c.tour_dismissed,
    completed_at: c.tour_completed_at || null,
  });
});
app.post('/api/customer/tour-progress', customerAuth, (req, res) => {
  const c = state.customers[req.customer.id];
  if (Array.isArray(req.body.seen_steps)) {
    c.tour_seen_steps = req.body.seen_steps.filter(s => typeof s === 'string').slice(0, 50);
  }
  if (req.body.dismissed) c.tour_dismissed = true;
  if (req.body.completed) c.tour_completed_at = Date.now();
  saveState();
  res.json({ ok: true });
});

// PWA can mark itself installed
app.post('/api/customer/onboarding/pwa-installed', customerAuth, (req, res) => {
  const c = state.customers[req.customer.id];
  c._pwa_installed = true;
  c._pwa_installed_at = Date.now();
  saveState();
  res.json({ ok: true });
});

// Customer-facing audit log: every mutation the customer (or their API keys) performed.
app.get('/api/customer/audit', customerAuth, (req, res) => {
  const list = (state.customer_audit && state.customer_audit[req.customer.id]) || [];
  const limit = Math.min(parseInt(req.query.limit || 200), 500);
  res.json({ audit: list.slice(-limit).reverse(), total: list.length });
});

// Signed export of the customer's audit log (Ed25519 detached JWS-style).
// Recipient can verify with the cloud's pub key (already served at /pubkey or /api/customer/audit/pubkey).
app.get('/api/customer/audit/export-signed', customerAuth, (req, res) => {
  if (!licenseKeys) return res.status(500).json({ error: 'no_signing_key' });
  const c = req.customer;
  const list = (state.customer_audit && state.customer_audit[c.id]) || [];
  const payload = {
    customer_id: c.id,
    name: c.name,
    exported_at: new Date().toISOString(),
    entry_count: list.length,
    entries: list,
    issuer: state.config.brand_name || 'mes Network',
  };
  const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWS', cty: 'audit-log' })).toString('base64url');
  const body   = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig    = crypto.sign(null, Buffer.from(header + '.' + body), licenseKeys.privateKey).toString('base64url');
  const jws = `${header}.${body}.${sig}`;
  res.set('Content-Type', 'application/jose');
  res.set('Content-Disposition', `attachment; filename="audit-${c.id}-${Date.now()}.jws"`);
  res.send(jws);
});
app.get('/api/customer/audit/pubkey', (req, res) => {
  if (!licenseKeys) return res.status(500).json({ error: 'no_signing_key' });
  res.type('text/plain').send(licenseKeys.pubPem);
});

// ─── GDPR: customer downloads everything we have on them ───
app.get('/api/customer/me/export', customerAuth, (req, res) => {
  const c = req.customer;
  const { staff_notes, ...safeCustomer } = c;
  const myMacs = Object.values(state.authorized_macs).filter(m => m.customer_id === c.id);
  const myDevices = {};
  for (const m of myMacs) myDevices[m.mac] = state.box_devices[m.mac] || {};
  const data = {
    exported_at: new Date().toISOString(),
    export_format_version: 2,
    privacy_policy_version: LEGAL_VERSION,
    privacy_policy_url: '/legal/privacy',
    customer: safeCustomer,
    boxes: myMacs,
    licenses: Object.entries(state.issued_licenses).filter(([mac, l]) => state.authorized_macs[mac]?.customer_id === c.id).map(([mac, l]) => l),
    devices_seen: myDevices,
    family_members: state.family_members[c.id] || [],
    schedules: state.schedules[c.id] || [],
    rules: state.rules[c.id] || [],
    quotas: state.quotas[c.id] || [],
    qos_rules: state.qos_rules[c.id] || [],
    time_bank: state.time_bank[c.id] || [],
    custom_alarm_rules: state.custom_alarm_rules[c.id] || [],
    device_tags: state.device_tags[c.id] || {},
    dns_records: state.dns_records[c.id] || [],
    dns_upstreams: state.dns_upstreams[c.id] || [],
    port_forwards: state.port_forwards[c.id] || [],
    dhcp_leases: state.dhcp_leases[c.id] || [],
    vlans: state.vlans[c.id] || [],
    guest_wifi: state.guest_wifi[c.id] || null,
    s2s_tunnels: state.s2s_tunnels[c.id] || [],
    vpn_routed_macs: state.vpn_routed_macs[c.id] || [],
    reboot_schedules: state.reboot_schedules[c.id] || {},
    sites: Object.values(state.sites || {}).filter(s => s.customer_id === c.id),
    wg_peers: Object.values(state.wg_peers || {}).filter(p => p.customer_id === c.id).map(p => ({ id: p.id, label: p.device_label, address: p.address, pubkey: p.pubkey })),
    ddns: Object.values(state.ddns || {}).filter(d => d.customer_id === c.id),
    notifications: state.notifications[c.id] || [],
    notif_prefs: state.notif_prefs[c.id] || {},
    push_subscriptions_count: ((state.push_subscriptions || {})[c.id] || []).length,
    support_messages: state.support_threads[c.id] || [],
    invoices: Object.values(state.invoices || {}).filter(i => i.customer_id === c.id),
    subscription_history: state.subscription_history[c.id] || [],
    nps_responses: state.nps_responses[c.id] || [],
    plan_requests: Object.values(state.plan_requests || {}).filter(r => r.customer_id === c.id),
    hw_orders: Object.values(state.hw_orders || {}).filter(o => o.customer_id === c.id),
    activity: state.events.filter(e => e.method === 'CUSTOMER' && e.path.includes(c.name)),
    flows_recent: state.flows.filter(f => f.customer_id === c.id).slice(-1000),  // last 1000 flows
    alarms: state.alarms.filter(a => a.customer_id === c.id),
    speedtest_history: myMacs.flatMap(m => (state.speedtest_history && state.speedtest_history[m.mac] || []).map(s => ({ ...s, box_mac: m.mac }))),
    dns_queries_recent: state.dns_queries[c.id] || [],
    api_keys_count: Object.values(state.customer_api_keys || {}).filter(k => k.customer_id === c.id).length,
    support_tickets: Object.values(state.support_tickets || {}).filter(t => t.customer_id === c.id),
    custom_blocklists: state.customer_blocklists[c.id] || [],
    customer_webhooks: (state.customer_webhooks[c.id] || []).map(h => ({ ...h, secret: '[REDACTED]' })),
    rule_history: state.rule_history && state.rule_history[c.id] || [],
    rule_hits_summary: ((state.rules[c.id] || []).map(r => ({
      rule_id: r.id, type: r.type, value: r.value,
      total_hits: (state.rule_hits && state.rule_hits[r.id] && state.rule_hits[r.id].total) || 0,
    }))),
  };
  res.set('Content-Type', 'application/json');
  res.set('Content-Disposition', 'attachment; filename="my-data-' + c.id + '-' + new Date().toISOString().slice(0, 10) + '.json"');
  state.events.push({ ts: Date.now(), method: 'CUSTOMER', path: `[GDPR-EXPORT] ${c.name}`, ip: req.ip });
  console.log(`         📥 GDPR EXPORT → ${c.name} (${Object.keys(data).length} sections)`);
  res.send(JSON.stringify(data, null, 2));
});

// Per-section summary as CSV (lighter, easier to import to spreadsheet)
app.get('/api/customer/me/export.csv', customerAuth, (req, res) => {
  const c = req.customer;
  const sec = String(req.query.section || 'flows').toLowerCase();
  const esc = v => {
    if (v === null || v === undefined) return '';
    const s = String(v);
    return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  let rows;
  if (sec === 'flows') {
    const data = state.flows.filter(f => f.customer_id === c.id).slice(-5000);
    rows = [['ts_iso','src_mac','dst_domain','dst_ip','dst_port','proto','category','country','bytes_up','bytes_down','blocked']];
    for (const f of data) {
      rows.push([new Date(f.ts).toISOString(), f.src_mac, f.dst_domain, f.dst_ip, f.dst_port, f.proto, f.category, f.country, f.bytes_up, f.bytes_down, f.blocked]);
    }
  } else if (sec === 'alarms') {
    const data = state.alarms.filter(a => a.customer_id === c.id);
    rows = [['ts_iso','severity','kind','title','body','acked']];
    for (const a of data) rows.push([new Date(a.ts).toISOString(), a.severity, a.kind, a.title, a.body, a.acked]);
  } else if (sec === 'rules') {
    const data = state.rules[c.id] || [];
    rows = [['id','type','value','action','enabled','created_at_iso']];
    for (const r of data) rows.push([r.id, r.type, r.value, r.action, r.enabled, r.created_at ? new Date(r.created_at).toISOString() : '']);
  } else if (sec === 'invoices') {
    const data = Object.values(state.invoices || {}).filter(i => i.customer_id === c.id);
    rows = [['id','period','amount_usd','amount_lbp','status','created_at_iso','paid_at_iso']];
    for (const i of data) rows.push([i.id, i.period, i.amount_usd, i.amount_lbp, i.status, i.created_at ? new Date(i.created_at).toISOString() : '', i.paid_at ? new Date(i.paid_at).toISOString() : '']);
  } else {
    return res.status(400).json({ error: 'unknown section', allowed: ['flows', 'alarms', 'rules', 'invoices'] });
  }
  res.set('Content-Type', 'text/csv');
  res.set('Content-Disposition', `attachment; filename="${sec}-${c.id}-${new Date().toISOString().slice(0,10)}.csv"`);
  res.send(rows.map(r => r.map(esc).join(',')).join('\n'));
});

// GDPR: customer requests their account deletion
// Schedule deletion (7-day grace period — undoable)
app.post('/api/customer/me/delete', customerAuth, (req, res) => {
  const c = state.customers[req.customer.id];
  if (req.body.confirm_phone !== c.phone) {
    return res.status(400).json({ error: 'confirm_phone must match your phone number' });
  }
  if (c.delete_scheduled_at) {
    return res.status(409).json({ error: 'already scheduled for deletion', scheduled_for: c.delete_scheduled_at });
  }
  c.delete_scheduled_at = Date.now() + 7 * 24 * 3600_000;   // 7 days
  saveState();
  state.events.push({ ts: Date.now(), method: 'CUSTOMER', path: `[ACCOUNT-DELETE-SCHED] ${c.name}`, ip: req.ip });
  if (c.email) sendEmail(c.email, 'mes Network — account scheduled for deletion',
    `Hi ${c.name},\n\nYour account is scheduled to be permanently deleted on ${new Date(c.delete_scheduled_at).toUTCString()}.\n\nIf you change your mind, sign in within the next 7 days and click "Cancel deletion" in Settings — or just contact support.\n\nmes Network team`);
  console.log(`         ⏳ ACCOUNT DELETE SCHEDULED → ${c.name} for ${new Date(c.delete_scheduled_at).toISOString()}`);
  res.json({ ok: true, scheduled_for: c.delete_scheduled_at });
});

// Cancel scheduled deletion
app.post('/api/customer/me/delete/cancel', customerAuth, (req, res) => {
  const c = state.customers[req.customer.id];
  if (!c.delete_scheduled_at) return res.status(404).json({ error: 'no deletion scheduled' });
  delete c.delete_scheduled_at;
  saveState();
  if (c.email) sendEmail(c.email, 'mes Network — deletion cancelled',
    `Hi ${c.name},\n\nGood news — we've cancelled the deletion of your account. Welcome back.\n\nmes Network team`);
  console.log(`         ↩ ACCOUNT DELETE CANCELLED → ${c.name}`);
  res.json({ ok: true });
});

// Trial reminder + auto-conversion job — runs every 6 hours
function runTrialJob() {
  for (const c of Object.values(state.customers)) {
    if (c.demo || !c.trial_until || c.trial_status === 'converted' || c.trial_status === 'cancelled') continue;
    const now = Date.now();
    const daysLeft = Math.ceil((c.trial_until - now) / (24 * 3600_000));
    // 7-day reminder
    if (daysLeft === 7 && !c._trial_email_7) {
      if (c.email) sendEmail(c.email, '7 days left in your trial',
        `Hi ${c.name},\n\nYour mes Network trial ends in 7 days. Reply with any questions or visit the app to manage your plan.\n\nmes Network team`);
      c._trial_email_7 = now;
    }
    // 2-day reminder
    if (daysLeft === 2 && !c._trial_email_2) {
      if (c.email) sendEmail(c.email, 'Your trial ends in 2 days',
        `Hi ${c.name},\n\nYour mes Network trial ends in 2 days. After that, your account converts to ${c.plan} ($${(({basic:5,family:10,pro:20,business:50})[c.plan])}/mo).\n\nIf you don't want to continue, cancel via Settings → Delete my account before then.\n\nmes Network team`);
      c._trial_email_2 = now;
    }
    // Past expiry → convert
    if (now >= c.trial_until && c.trial_status === 'active') {
      c.trial_status = 'converted';
      c.trial_converted_at = now;
      pushNotification(c.id, 'billing', 'Trial converted to paid', `Your account is now on the ${c.plan} plan. First invoice will be issued at month-end.`);
      console.log(`         💳 TRIAL → PAID: ${c.name} (${c.plan})`);
      fireWebhooks('trial.converted', { customer_id: c.id, plan: c.plan });
    }
  }
  saveState();
}
setInterval(runTrialJob, 6 * 3600_000);
setTimeout(runTrialJob, 8 * 60_000);

// ─── Subscription pause (alternative to cancel) ─────
app.post('/api/customer/subscription/pause', customerAuth, (req, res) => {
  const c = state.customers[req.customer.id];
  if (c.subscription_paused) return res.status(409).json({ error: 'already paused' });
  const days = Math.min(parseInt(req.body.days) || 30, 90);   // max 90 days
  c.subscription_paused = true;
  c.subscription_paused_at = Date.now();
  c.subscription_resumes_at = Date.now() + days * 24 * 3600_000;
  c.status = 'paused';
  saveState();
  pushNotification(c.id, 'billing', 'Subscription paused', `Your account is paused until ${new Date(c.subscription_resumes_at).toLocaleDateString()}.`);
  if (c.email) sendEmail(c.email, 'mes Network — subscription paused',
    `Hi ${c.name},\n\nYour subscription is paused for ${days} days (until ${new Date(c.subscription_resumes_at).toUTCString()}).\n\nWhile paused: no billing, no policy enforcement on your boxes.\n\nResume any time from Settings, or wait — we'll auto-resume on the date above.\n\nmes Network team`);
  res.json({ ok: true, resumes_at: c.subscription_resumes_at });
});
app.post('/api/customer/subscription/resume', customerAuth, (req, res) => {
  const c = state.customers[req.customer.id];
  if (!c.subscription_paused) return res.status(409).json({ error: 'not paused' });
  delete c.subscription_paused;
  delete c.subscription_paused_at;
  delete c.subscription_resumes_at;
  c.status = 'active';
  saveState();
  pushNotification(c.id, 'billing', 'Subscription resumed', 'Welcome back! Policy enforcement re-enabled.');
  res.json({ ok: true });
});
app.get('/api/customer/subscription/status', customerAuth, (req, res) => {
  const c = req.customer;
  res.json({
    status: c.status || 'active',
    plan: c.plan,
    paused: !!c.subscription_paused,
    resumes_at: c.subscription_resumes_at || null,
    trial_status: c.trial_status || null,
    trial_until: c.trial_until || null,
  });
});

// Background job: auto-resume paused subscriptions when their date arrives
function runAutoResume() {
  for (const c of Object.values(state.customers)) {
    if (c.subscription_paused && c.subscription_resumes_at && c.subscription_resumes_at <= Date.now()) {
      delete c.subscription_paused;
      delete c.subscription_paused_at;
      delete c.subscription_resumes_at;
      c.status = 'active';
      pushNotification(c.id, 'billing', 'Subscription auto-resumed', 'Welcome back!');
      console.log(`         ▶ AUTO-RESUME: ${c.name}`);
    }
  }
  saveState();
}
setInterval(runAutoResume, 60 * 60_000);
setTimeout(runAutoResume, 4 * 60_000);

// Referral endpoints
app.get('/api/customer/referral', customerAuth, (req, res) => {
  const c = state.customers[req.customer.id];
  if (!c.referral_code) {
    c.referral_code = 'MES-' + shortId(6).toUpperCase();
    saveState();
  }
  const referred = Object.values(state.customers).filter(x => x.referred_by === c.id && !x.demo);
  const baseUrl = state.config.brand_domain ? 'https://' + state.config.brand_domain : '';
  res.json({
    referral_code: c.referral_code,
    referral_link: `${baseUrl}/pwa/?ref=${c.referral_code}`,
    referrals_count: referred.length,
    free_months_earned: c.referral_credits || 0,
    referred_customers: referred.map(r => ({ name: r.name, signed_up_at: r.created_at })),
  });
});

app.get('/admin/api/referrals', adminAuth, (req, res) => {
  const all = Object.values(state.customers).filter(c => c.referred_by && !c.demo);
  const byReferrer = {};
  for (const c of all) {
    if (!byReferrer[c.referred_by]) byReferrer[c.referred_by] = [];
    byReferrer[c.referred_by].push({ id: c.id, name: c.name, plan: c.plan, signed_up_at: c.created_at });
  }
  const summary = Object.entries(byReferrer).map(([refId, refs]) => {
    const r = state.customers[refId];
    return { referrer_id: refId, referrer_name: r ? r.name : 'unknown', count: refs.length, credits_used: r ? (r.referral_credits || 0) : 0, referrals: refs };
  });
  summary.sort((a, b) => b.count - a.count);
  res.json({ referrers: summary, total_referrals: all.length });
});

app.get('/api/customer/trial', customerAuth, (req, res) => {
  const c = req.customer;
  if (!c.trial_until) return res.json({ in_trial: false });
  res.json({
    in_trial: c.trial_status === 'active' && Date.now() < c.trial_until,
    trial_until: c.trial_until,
    days_left: Math.max(0, Math.ceil((c.trial_until - Date.now()) / (24 * 3600_000))),
    status: c.trial_status,
    converted_at: c.trial_converted_at || null,
  });
});

// Background job: every hour, finalize deletions whose grace period elapsed
function runScheduledDeletions() {
  for (const c of Object.values(state.customers)) {
    if (!c.delete_scheduled_at || c.delete_scheduled_at > Date.now()) continue;
    finalizeAccountDeletion(c);
  }
}
setInterval(runScheduledDeletions, 60 * 60_000);
setTimeout(runScheduledDeletions, 5 * 60_000);

function finalizeAccountDeletion(c) {
  console.log(`         ❌ FINALIZING DELETION → ${c.name} (${c.id})`);
  delete state.customers[c.id];
  delete state.family_members[c.id];
  delete state.schedules[c.id];
  delete state.notifications[c.id];
  delete state.support_threads[c.id];
  delete state.rules[c.id];
  delete state.quotas[c.id];
  delete state.qos_rules[c.id];
  delete state.dns_records[c.id];
  delete state.dns_upstreams[c.id];
  delete state.port_forwards[c.id];
  delete state.dhcp_leases[c.id];
  delete state.device_tags[c.id];
  delete state.time_bank[c.id];
  delete state.usage_monthly[c.id];
  delete state.usage_daily[c.id];
  delete state.subscription_history[c.id];
  delete state.nps_responses[c.id];
  delete state.dns_queries[c.id];
  for (const m of Object.values(state.authorized_macs)) {
    if (m.customer_id === c.id) { delete m.customer_id; m.customer_name = '(deleted)'; }
  }
  state.flows = state.flows.filter(f => f.customer_id !== c.id);
  state.alarms = state.alarms.filter(a => a.customer_id !== c.id);
  saveState();
  fireWebhooks('customer.deleted', { customer_id: c.id, name: c.name, finalized_at: Date.now() });
  if (c.email) sendEmail(c.email, 'mes Network — account permanently deleted',
    `Hi ${c.name},\n\nYour account and all associated data have been permanently deleted as requested.\n\nThank you for using mes Network.`);
}

// Legacy immediate-delete endpoint (admin-triggered — bypasses grace period)
app.post('/api/customer/me/delete-now', customerAuth, (req, res) => {
  const c = req.customer;
  if (req.body.confirm_phone !== c.phone) {
    return res.status(400).json({ error: 'confirm_phone must match your phone number' });
  }
  finalizeAccountDeletion(c);
  state.events.push({ ts: Date.now(), method: 'CUSTOMER', path: `[ACCOUNT-DELETE-NOW] ${c.name}`, ip: req.ip });
  res.json({ ok: true });
});

// GET /api/customer/activity — own action history (filtered from event stream)
app.get('/api/customer/activity', customerAuth, (req, res) => {
  const c = req.customer;
  const mine = state.events.filter(e => e.method === 'CUSTOMER' && e.path.includes(c.name));
  res.json({
    activity: mine.slice(-50).reverse().map(e => ({
      ts: e.ts,
      action: e.path,
      ip: e.ip,
    })),
  });
});

// ─── Notifications ───
app.get('/api/customer/notifications', customerAuth, (req, res) => {
  res.json({ notifications: state.notifications[req.customer.id] || [] });
});

// Notification preferences
app.get('/api/customer/notif-prefs', customerAuth, (req, res) => {
  const defaults = {
    security: true, family: true, billing: true, system: true,
    channels: { push: true, email: true, sms: false },
    channels_per_category: {},
  };
  const prefs = { ...defaults, ...(state.notif_prefs[req.customer.id] || {}) };
  if (!prefs.channels) prefs.channels = defaults.channels;
  if (!prefs.channels_per_category) prefs.channels_per_category = {};
  res.json({ prefs });
});

app.post('/api/customer/notif-prefs', customerAuth, (req, res) => {
  const c = req.customer;
  if (!state.notif_prefs[c.id]) state.notif_prefs[c.id] = {};
  const np = state.notif_prefs[c.id];
  for (const k of ['security', 'family', 'billing', 'system']) {
    if (req.body[k] !== undefined) np[k] = !!req.body[k];
  }
  // Quiet hours: HH:MM strings
  for (const k of ['quiet_start', 'quiet_end']) {
    if (req.body[k] !== undefined) {
      const v = String(req.body[k]).trim();
      if (v === '' || /^([01]\d|2[0-3]):[0-5]\d$/.test(v)) np[k] = v || null;
    }
  }
  // Per-channel global toggles (push/email/sms)
  if (req.body.channels && typeof req.body.channels === 'object') {
    if (!np.channels) np.channels = { push: true, email: true, sms: false };
    for (const ch of ['push', 'email', 'sms']) {
      if (req.body.channels[ch] !== undefined) np.channels[ch] = !!req.body.channels[ch];
    }
  }
  // Per-category × per-channel overrides
  if (req.body.channels_per_category && typeof req.body.channels_per_category === 'object') {
    if (!np.channels_per_category) np.channels_per_category = {};
    for (const cat of ['security', 'family', 'billing', 'system']) {
      const v = req.body.channels_per_category[cat];
      if (v && typeof v === 'object') {
        np.channels_per_category[cat] = np.channels_per_category[cat] || {};
        for (const ch of ['push', 'email', 'sms']) {
          if (v[ch] !== undefined) np.channels_per_category[cat][ch] = !!v[ch];
        }
      }
    }
  }
  saveState();
  res.json({ ok: true, prefs: np });
});

// Helper used by senders to check whether a (category, channel) is enabled.
function notifChannelEnabled(customer_id, category, channel) {
  const np = state.notif_prefs[customer_id] || {};
  // Per-category override wins
  const perCat = np.channels_per_category && np.channels_per_category[category];
  if (perCat && perCat[channel] !== undefined) return !!perCat[channel];
  // Global channel default
  const globalCh = np.channels || { push: true, email: true, sms: false };
  return globalCh[channel] !== false;
}

app.post('/api/customer/notifications/read', customerAuth, (req, res) => {
  const arr = state.notifications[req.customer.id] || [];
  const ids = req.body.ids || arr.map(n => n.id);  // mark all if no ids given
  arr.forEach(n => { if (ids.includes(n.id)) n.read = true; });
  saveState();
  res.json({ ok: true });
});

// ─── Family members ───
app.get('/api/customer/family', customerAuth, (req, res) => {
  res.json({ family: state.family_members[req.customer.id] || [] });
});

app.post('/api/customer/family/add', customerAuth, (req, res) => {
  const c = req.customer;
  if (!state.family_members[c.id]) state.family_members[c.id] = [];
  const limits = planLimits(c.plan);
  if (state.family_members[c.id].length >= limits.max_family_members) {
    return res.status(402).json({
      error: 'plan_limit',
      message: `Your '${c.plan}' plan supports up to ${limits.max_family_members} family member(s). Upgrade to add more.`,
      plan: c.plan, limit: limits.max_family_members, current: state.family_members[c.id].length,
    });
  }
  const member = {
    id: 'fam-' + shortId(8),
    name: (req.body.name || '').trim().slice(0, 40),
    role: req.body.role || 'Member',  // Admin / Adult / Teen / Kid / Member
    icon: req.body.icon || (req.body.role === 'Kid' ? '👧' : req.body.role === 'Teen' ? '👦' : '👤'),
    device_macs: Array.isArray(req.body.device_macs) ? req.body.device_macs : [],
    created_at: new Date().toISOString(),
  };
  if (!member.name) return res.status(400).json({ error: 'name required' });
  state.family_members[c.id].push(member);
  saveState();
  state.events.push({ ts: Date.now(), method: 'CUSTOMER', path: `[FAMILY+] ${c.name} added ${member.name} (${member.role})`, ip: req.ip });
  console.log(`         👨‍👩 family ADD → ${c.name}  member=${member.name}`);
  res.json({ ok: true, member });
});

app.post('/api/customer/family/update', customerAuth, (req, res) => {
  const c = req.customer;
  const fam = state.family_members[c.id] || [];
  const m = fam.find(x => x.id === req.body.id);
  if (!m) return res.status(404).json({ error: 'family member not found' });
  if (req.body.name) m.name = req.body.name.slice(0, 40);
  if (req.body.role) m.role = req.body.role;
  if (req.body.icon) m.icon = req.body.icon;
  if (Array.isArray(req.body.device_macs)) m.device_macs = req.body.device_macs.map(normalizeMac).filter(Boolean);
  saveState();
  res.json({ ok: true, member: m });
});

// Single-device assignment (drag-drop friendly): claim a device for / unclaim it from a member
app.post('/api/customer/family/assign-device', customerAuth, (req, res) => {
  const c = req.customer;
  const fam = state.family_members[c.id] || [];
  const target_id = req.body.member_id;  // null/empty to unassign from all
  const mac = normalizeMac(req.body.mac || '');
  if (!mac) return res.status(400).json({ error: 'mac required' });
  // Remove from every member first (a device belongs to one member)
  for (const m of fam) {
    const i = m.device_macs.indexOf(mac);
    if (i >= 0) m.device_macs.splice(i, 1);
  }
  // Add to target if specified
  if (target_id) {
    const target = fam.find(x => x.id === target_id);
    if (!target) return res.status(404).json({ error: 'member not found' });
    target.device_macs.push(mac);
  }
  saveState();
  res.json({ ok: true });
});

app.post('/api/customer/family/delete', customerAuth, (req, res) => {
  const c = req.customer;
  state.family_members[c.id] = (state.family_members[c.id] || []).filter(x => x.id !== req.body.id);
  saveState();
  res.json({ ok: true });
});

// ─── Tier-1: Per-member DNS upstream + SafeSearch toggle ───
// Preset upstream nameservers (resolver IP delivered via DHCP option 6).
const DNS_UPSTREAM_PRESETS = {
  'cloudflare':            '1.1.1.1',
  'cloudflare-family':     '1.1.1.3',
  'nextdns-family':        '45.90.28.0',
  'opendns-familyshield':  '208.67.222.123',
  'quad9':                 '9.9.9.9',
};
function resolveDnsUpstream(spec) {
  if (!spec) return null;
  if (DNS_UPSTREAM_PRESETS[spec]) return DNS_UPSTREAM_PRESETS[spec];
  if (typeof spec === 'string' && spec.startsWith('custom:')) {
    const ip = spec.slice(7).trim();
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) return ip;
  }
  return null;
}
app.get('/api/customer/family/dns-presets', customerAuth, (req, res) => {
  res.json({ presets: DNS_UPSTREAM_PRESETS });
});
app.post('/api/customer/family/:id/dns-upstream', customerAuth, (req, res) => {
  const c = req.customer;
  const fam = state.family_members[c.id] || [];
  const m = fam.find(x => x.id === req.params.id);
  if (!m) return res.status(404).json({ error: 'family member not found' });
  const spec = req.body.dns_upstream;  // null/'' to clear
  if (spec === null || spec === '' || spec === undefined) {
    delete m.dns_upstream;
  } else {
    if (typeof spec !== 'string' || spec.length > 80) return res.status(400).json({ error: 'invalid dns_upstream' });
    const isPreset = !!DNS_UPSTREAM_PRESETS[spec];
    const isCustom = spec.startsWith('custom:') && resolveDnsUpstream(spec);
    if (!isPreset && !isCustom) return res.status(400).json({ error: 'unknown preset and not a valid custom:<ipv4>' });
    m.dns_upstream = spec;
  }
  saveState();
  res.json({ ok: true, member: m });
});
app.post('/api/customer/family/:id/safe-search', customerAuth, (req, res) => {
  const c = req.customer;
  const fam = state.family_members[c.id] || [];
  const m = fam.find(x => x.id === req.params.id);
  if (!m) return res.status(404).json({ error: 'family member not found' });
  m.safe_search = !!req.body.enabled;
  saveState();
  res.json({ ok: true, member: m });
});

// ─── Schedule blocks ───
// Predefined schedule templates
const SCHEDULE_PRESETS = [
  { id: 'bedtime',     name: 'Bedtime',          icon: '🌙', days: ['mon','tue','wed','thu','fri','sat','sun'], start_hhmm: '21:00', end_hhmm: '07:00', default_target: 'kids' },
  { id: 'school',      name: 'School hours',     icon: '🏫', days: ['mon','tue','wed','thu','fri'],            start_hhmm: '08:00', end_hhmm: '15:00', default_target: 'kids' },
  { id: 'homework',    name: 'Homework time',    icon: '📚', days: ['mon','tue','wed','thu','fri'],            start_hhmm: '16:00', end_hhmm: '18:00', default_target: 'kids' },
  { id: 'work-focus',  name: 'Work focus',       icon: '🎯', days: ['mon','tue','wed','thu','fri'],            start_hhmm: '09:00', end_hhmm: '12:00', default_target: 'self' },
  { id: 'dinner',      name: 'Dinner time',      icon: '🍽️', days: ['mon','tue','wed','thu','fri','sat','sun'], start_hhmm: '19:00', end_hhmm: '20:00', default_target: 'all' },
  { id: 'weekend-am',  name: 'Weekend mornings', icon: '☀️', days: ['sat','sun'],                              start_hhmm: '07:00', end_hhmm: '11:00', default_target: 'kids' },
];
app.get('/api/customer/schedules/presets', customerAuth, (req, res) => {
  res.json({ presets: SCHEDULE_PRESETS });
});
app.post('/api/customer/schedules/from-preset', customerAuth, (req, res) => {
  const c = req.customer;
  const p = SCHEDULE_PRESETS.find(x => x.id === req.body.preset_id);
  if (!p) return res.status(404).json({ error: 'preset not found' });
  if (!state.schedules[c.id]) state.schedules[c.id] = [];
  const limits = planLimits(c.plan);
  if (state.schedules[c.id].length >= limits.max_schedules) {
    return res.status(402).json({ error: 'plan_limit', message: `Plan supports ${limits.max_schedules} schedules.` });
  }
  const sched = {
    id: 'sched-' + shortId(8),
    name: p.name,
    icon: p.icon,
    device_macs: Array.isArray(req.body.device_macs) ? req.body.device_macs.map(normalizeMac).filter(Boolean) : [],
    family_ids: Array.isArray(req.body.family_ids) ? req.body.family_ids : [],
    days: p.days,
    start_hhmm: p.start_hhmm,
    end_hhmm: p.end_hhmm,
    enabled: true,
    preset_id: p.id,
    created_at: new Date().toISOString(),
  };
  state.schedules[c.id].push(sched);
  saveState();
  res.json({ ok: true, schedule: sched });
});

app.get('/api/customer/schedules', customerAuth, (req, res) => {
  res.json({ schedules: state.schedules[req.customer.id] || [] });
});

app.post('/api/customer/schedules/add', customerAuth, (req, res) => {
  const c = req.customer;
  if (!state.schedules[c.id]) state.schedules[c.id] = [];
  const limits = planLimits(c.plan);
  if (state.schedules[c.id].length >= limits.max_schedules) {
    return res.status(402).json({
      error: 'plan_limit',
      message: `Your '${c.plan}' plan supports up to ${limits.max_schedules} schedule(s). Upgrade to add more.`,
      plan: c.plan, limit: limits.max_schedules, current: state.schedules[c.id].length,
    });
  }
  const sched = {
    id: 'sch-' + shortId(8),
    name: (req.body.name || 'Schedule').slice(0, 40),
    device_macs: Array.isArray(req.body.device_macs) ? req.body.device_macs : [],
    family_ids: Array.isArray(req.body.family_ids) ? req.body.family_ids : [],
    days: Array.isArray(req.body.days) ? req.body.days : [0,1,2,3,4,5,6],  // 0=Sun..6=Sat
    start_hhmm: req.body.start_hhmm || '22:00',
    end_hhmm: req.body.end_hhmm || '06:00',
    enabled: req.body.enabled !== false,
    created_at: new Date().toISOString(),
  };
  state.schedules[c.id].push(sched);
  saveState();
  state.events.push({ ts: Date.now(), method: 'CUSTOMER', path: `[SCHEDULE+] ${c.name} added "${sched.name}" ${sched.start_hhmm}–${sched.end_hhmm}`, ip: req.ip });
  console.log(`         🕐 schedule ADD → ${c.name}  "${sched.name}"  ${sched.start_hhmm}-${sched.end_hhmm}`);
  res.json({ ok: true, schedule: sched });
});

app.post('/api/customer/schedules/update', customerAuth, (req, res) => {
  const c = req.customer;
  const arr = state.schedules[c.id] || [];
  const s = arr.find(x => x.id === req.body.id);
  if (!s) return res.status(404).json({ error: 'schedule not found' });
  if (req.body.name) s.name = req.body.name.slice(0, 40);
  if (Array.isArray(req.body.device_macs)) s.device_macs = req.body.device_macs;
  if (Array.isArray(req.body.family_ids)) s.family_ids = req.body.family_ids;
  if (Array.isArray(req.body.days)) s.days = req.body.days;
  if (req.body.start_hhmm) s.start_hhmm = req.body.start_hhmm;
  if (req.body.end_hhmm) s.end_hhmm = req.body.end_hhmm;
  if (typeof req.body.enabled === 'boolean') s.enabled = req.body.enabled;
  saveState();
  res.json({ ok: true, schedule: s });
});

app.post('/api/customer/schedules/delete', customerAuth, (req, res) => {
  const c = req.customer;
  state.schedules[c.id] = (state.schedules[c.id] || []).filter(x => x.id !== req.body.id);
  saveState();
  res.json({ ok: true });
});

// ─── Admin user management ───
app.get('/admin/api/admins', adminAuth, (req, res) => {
  res.json({
    admins: Object.values(state.admins).map(a => ({
      username: a.username, name: a.name, role: a.role,
      active: a.active !== false, created_at: a.created_at,
    })),
    me: { user: req.adminUser, name: req.adminName, role: req.adminRole },
  });
});

app.post('/admin/api/admins/create', adminAuth, (req, res) => {
  if (req.adminRole !== 'super') return res.status(403).json({ error: 'super-admin only' });
  const { username, name, password, role } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username + password required' });
  if (state.admins[username]) return res.status(409).json({ error: 'username exists' });
  state.admins[username] = {
    username, name: name || username, role: role || 'admin',
    password_hash: hashPassword(password),
    active: true,
    created_at: new Date().toISOString(),
  };
  saveState();
  logAdminAction(req, 'admin.create', username, role || 'admin');
  console.log(`         ★ ADMIN CREATED → ${username} (${role || 'admin'})`);
  res.json({ ok: true });
});

app.post('/admin/api/admins/update', adminAuth, (req, res) => {
  if (req.adminRole !== 'super') return res.status(403).json({ error: 'super-admin only' });
  const a = state.admins[req.body.username];
  if (!a) return res.status(404).json({ error: 'not found' });
  if (req.body.name) a.name = req.body.name;
  if (req.body.role) a.role = req.body.role;
  if (typeof req.body.active === 'boolean') a.active = req.body.active;
  if (req.body.password) a.password_hash = hashPassword(req.body.password);
  saveState();
  logAdminAction(req, 'admin.update', req.body.username);
  res.json({ ok: true });
});

app.post('/admin/api/admins/delete', adminAuth, (req, res) => {
  if (req.adminRole !== 'super') return res.status(403).json({ error: 'super-admin only' });
  delete state.admins[req.body.username];
  saveState();
  logAdminAction(req, 'admin.delete', req.body.username);
  res.json({ ok: true });
});

// Assign customer(s) to a reseller admin
app.post('/admin/api/admins/assign-customers', adminAuth, (req, res) => {
  if (req.adminRole !== 'super') return res.status(403).json({ error: 'super-admin only' });
  const a = state.admins[req.body.username];
  if (!a) return res.status(404).json({ error: 'admin not found' });
  a.assigned_customer_ids = Array.isArray(req.body.customer_ids) ? req.body.customer_ids : [];
  saveState();
  logAdminAction(req, 'admin.assign_customers', req.body.username, `count=${a.assigned_customer_ids.length}`);
  res.json({ ok: true, assigned: a.assigned_customer_ids });
});

// 2FA setup: generate a fresh secret + otpauth URL for the calling admin
app.post('/admin/api/admins/2fa/setup', adminAuth, (req, res) => {
  const a = state.admins[req.adminUser];
  if (!a) return res.status(400).json({ error: 'bootstrap admin can\'t set 2FA — create a sub-admin first' });
  const secret = crypto.randomBytes(20);  // 160-bit
  const b32 = base32Encode(secret);
  // Don't activate yet — return for verification first
  a._pending_totp = b32;
  saveState();
  const issuer = encodeURIComponent('mes Cloud');
  const account = encodeURIComponent(req.adminUser + '@' + (state.config.brand_domain || 'cloud'));
  const otpauth = `otpauth://totp/${issuer}:${account}?secret=${b32}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
  res.json({ secret: b32, otpauth_url: otpauth, instructions: 'Add to your authenticator app, then POST /admin/api/admins/2fa/verify with the 6-digit code to activate.' });
});

app.post('/admin/api/admins/2fa/verify', adminAuth, (req, res) => {
  const a = state.admins[req.adminUser];
  if (!a || !a._pending_totp) return res.status(400).json({ error: 'no pending 2FA setup — run /setup first' });
  if (!totpVerify(a._pending_totp, String(req.body.code || ''), 1)) {
    return res.status(401).json({ error: 'wrong code' });
  }
  a.totp_secret = a._pending_totp;
  delete a._pending_totp;
  saveState();
  logAdminAction(req, 'admin.2fa.enable', req.adminUser);
  res.json({ ok: true, message: '2FA enabled. From now on, send X-Admin-OTP header on every request.' });
});

app.post('/admin/api/admins/2fa/disable', adminAuth, (req, res) => {
  const target = req.body.username || req.adminUser;
  if (target !== req.adminUser && req.adminRole !== 'super') {
    return res.status(403).json({ error: 'super-admin only to disable for others' });
  }
  if (state.admins[target]) {
    delete state.admins[target].totp_secret;
    delete state.admins[target]._pending_totp;
    saveState();
    logAdminAction(req, 'admin.2fa.disable', target);
  }
  res.json({ ok: true });
});

// Global search across customers / MACs / notes / events
app.get('/admin/api/search', adminAuth, (req, res) => {
  const q = (req.query.q || '').trim().toLowerCase();
  if (!q || q.length < 2) return res.json({ results: [], hint: 'enter at least 2 chars' });

  const results = [];
  // Customers
  for (const c of visibleCustomers(req)) {
    const fields = [c.name, c.phone, c.email, c.address, c.notes].filter(Boolean).join(' ').toLowerCase();
    if (fields.includes(q)) {
      results.push({ kind: 'customer', id: c.id, label: c.name, sub: `${c.phone} · ${c.plan}`, status: c.status });
    }
    // Match staff notes
    for (const n of (c.staff_notes || [])) {
      if ((n.body || '').toLowerCase().includes(q)) {
        results.push({ kind: 'note', id: n.id, label: `Note on ${c.name}`, sub: n.body.slice(0, 80) });
      }
    }
  }
  // MACs (only those owned by visible customers if reseller)
  const visibleIds = new Set(visibleCustomers(req).map(c => c.id));
  for (const m of Object.values(state.authorized_macs)) {
    if (req.adminRole === 'reseller' && m.customer_id && !visibleIds.has(m.customer_id)) continue;
    if ((m.mac || '').toLowerCase().includes(q) || (m.customer_name || '').toLowerCase().includes(q)) {
      results.push({ kind: 'mac', id: m.mac, label: m.mac, sub: m.customer_name || '(unassigned)' });
    }
  }
  // Recent events
  const recent = state.events.slice(-300);
  for (const e of recent) {
    if ((e.path || '').toLowerCase().includes(q)) {
      results.push({ kind: 'event', label: `${e.method} ${e.path}`, sub: new Date(e.ts).toLocaleString() });
      if (results.filter(r => r.kind === 'event').length >= 5) break;
    }
  }

  res.json({ q, results: results.slice(0, 30), total: results.length });
});

// API key management
app.get('/admin/api/keys', adminAuth, (req, res) => {
  res.json({
    keys: Object.values(state.api_keys).map(k => ({
      id: k.id, name: k.name, scopes: k.scopes, role: k.role,
      active: k.active !== false,
      created_by: k.created_by, created_at: k.created_at,
      last_used_at: k.last_used_at, last_used_ip: k.last_used_ip,
    })),
  });
});

app.post('/admin/api/keys/create', adminAuth, (req, res) => {
  if (req.adminRole !== 'super' && req.adminRole !== 'admin') {
    return res.status(403).json({ error: 'admin or super only' });
  }
  const name = (req.body.name || 'unnamed').slice(0, 60);
  const scopes = Array.isArray(req.body.scopes) ? req.body.scopes : ['*'];
  const role = req.body.role || 'admin';
  // Generate a new API key
  const id = 'key-' + shortId(8);
  const rawKey = 'mes_' + crypto.randomBytes(24).toString('base64').replace(/[+/=]/g, '').slice(0, 32);
  const hashed = crypto.createHash('sha256').update(rawKey).digest('hex');
  state.api_keys[id] = {
    id, name, hashed, scopes, role,
    active: true,
    created_by: req.adminUser,
    created_at: new Date().toISOString(),
  };
  saveState();
  logAdminAction(req, 'apikey.create', name);
  console.log(`         🔑 API KEY CREATED → ${name} (${role})`);
  res.json({ ok: true, id, key: rawKey, message: 'Save this key now — you will not see it again.' });
});

app.post('/admin/api/keys/delete', adminAuth, (req, res) => {
  if (req.adminRole !== 'super' && req.adminRole !== 'admin') {
    return res.status(403).json({ error: 'admin or super only' });
  }
  delete state.api_keys[req.body.id];
  saveState();
  logAdminAction(req, 'apikey.delete', req.body.id);
  res.json({ ok: true });
});

app.post('/admin/api/keys/toggle', adminAuth, (req, res) => {
  const k = state.api_keys[req.body.id];
  if (!k) return res.status(404).json({ error: 'not found' });
  k.active = !k.active;
  saveState();
  logAdminAction(req, k.active ? 'apikey.enable' : 'apikey.disable', k.id);
  res.json({ ok: true, active: k.active });
});

// SSE: real-time stream of events (admin only)
const sseClients = new Set();
app.get('/admin/api/events/stream', adminAuth, (req, res) => {
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.flushHeaders();
  res.write(`event: hello\ndata: {"connected_at":"${new Date().toISOString()}"}\n\n`);

  const client = { res, role: req.adminRole, user: req.adminUser };
  sseClients.add(client);

  // Heartbeat every 25s to keep connection alive
  const heartbeat = setInterval(() => {
    try { res.write(`: ping\n\n`); } catch { /* ignored */ }
  }, 25000);

  req.on('close', () => {
    clearInterval(heartbeat);
    sseClients.delete(client);
  });
});

function broadcastSSE(eventType, payload) {
  const msg = `event: ${eventType}\ndata: ${JSON.stringify(payload)}\n\n`;
  for (const client of sseClients) {
    try { client.res.write(msg); } catch { sseClients.delete(client); }
  }
}

// Hook broadcastSSE into the existing event push (so every recorded event also streams)
const _origEventsPush = state.events.push.bind(state.events);
state.events.push = function(item) {
  const r = _origEventsPush(item);
  // Broadcast to SSE clients (only meaningful events)
  if (item && (item.method === 'CUSTOMER' || item.method === 'ADMIN')) {
    broadcastSSE('event', { ts: item.ts, method: item.method, path: item.path, ip: item.ip });
  }
  return r;
};

// Admin actions log
app.get('/admin/api/audit', adminAuth, (req, res) => {
  res.json({ actions: state.admin_actions.slice(0, 100) });
});

// ─── Webhooks ───
app.get('/admin/api/webhooks', adminAuth, (req, res) => {
  res.json({ webhooks: state.webhooks });
});

app.post('/admin/api/webhooks', adminAuth, (req, res) => {
  const w = {
    id: 'hook-' + shortId(8),
    name: (req.body.name || 'webhook').slice(0, 40),
    url: req.body.url,
    events: Array.isArray(req.body.events) && req.body.events.length ? req.body.events : ['*'],
    enabled: req.body.enabled !== false,
    secret: req.body.secret || crypto.randomBytes(16).toString('hex'),
    created_at: new Date().toISOString(),
  };
  if (!w.url) return res.status(400).json({ error: 'url required' });
  state.webhooks.push(w);
  saveState();
  logAdminAction(req, 'webhook.create', w.id, w.url);
  res.json({ ok: true, webhook: w });
});

app.post('/admin/api/webhooks/update', adminAuth, (req, res) => {
  const w = state.webhooks.find(h => h.id === req.body.id);
  if (!w) return res.status(404).json({ error: 'not found' });
  if (req.body.url) w.url = String(req.body.url).slice(0, 500);
  if (req.body.name) w.name = String(req.body.name).slice(0, 40);
  if (Array.isArray(req.body.events)) w.events = req.body.events;
  if (typeof req.body.enabled === 'boolean') w.enabled = req.body.enabled;
  if (req.body.secret) w.secret = req.body.secret;
  saveState();
  logAdminAction(req, 'webhook.update', w.id);
  res.json({ ok: true, webhook: w });
});

// Catalog of all webhook event names this cloud emits — UI uses this for checkbox-list
app.get('/admin/api/webhook-events', adminAuth, (req, res) => {
  res.json({ events: [
    'customer.signup', 'customer.deleted',
    'license.issued',
    'mac.authorized',
    'box.claimed',
    'invoice.paid', 'invoice.unpaid', 'invoice.overdue', 'invoices.generated',
    'alarm.created',
    'firmware.uploaded',
    'plan.requested',
    'hw_order',
    'support_msg',
    '*',  // wildcard — receive everything
  ]});
});

app.post('/admin/api/webhooks/delete', adminAuth, (req, res) => {
  state.webhooks = state.webhooks.filter(h => h.id !== req.body.id);
  saveState();
  logAdminAction(req, 'webhook.delete', req.body.id);
  res.json({ ok: true });
});

// Webhook event replay — re-fire any past event from the event log
if (!state.webhook_events_log) state.webhook_events_log = [];   // [ {id, ts, event_name, payload} ]

// Wrap fireWebhooks to also persist the event (with a cap)
const _origFireWebhooks = fireWebhooks;
fireWebhooks = function(eventName, payload) {
  state.webhook_events_log.push({
    id: 'evt-' + shortId(10),
    ts: Date.now(),
    event_name: eventName,
    payload,
  });
  if (state.webhook_events_log.length > 5000) state.webhook_events_log.shift();
  return _origFireWebhooks(eventName, payload);
};

app.get('/admin/api/webhook-events-log', adminAuth, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 200, 5000);
  const filterEvent = req.query.event;
  let out = state.webhook_events_log.slice().reverse();
  if (filterEvent) out = out.filter(e => e.event_name === filterEvent);
  res.json({ events: out.slice(0, limit), total: state.webhook_events_log.length });
});

app.post('/admin/api/webhook-events/replay', adminAuth, (req, res) => {
  const id = req.body.id;
  const e = state.webhook_events_log.find(x => x.id === id);
  if (!e) return res.status(404).json({ error: 'event not found in log' });
  // Fire to all currently configured webhooks (replay flag in payload)
  _origFireWebhooks(e.event_name, { ...e.payload, _replayed_at: Date.now(), _original_ts: e.ts });
  logAdminAction(req, 'webhook.replay', e.id, e.event_name);
  res.json({ ok: true, replayed: e.event_name, ts: e.ts });
});

app.post('/admin/api/webhooks/test', adminAuth, (req, res) => {
  const h = state.webhooks.find(x => x.id === req.body.id);
  if (!h) return res.status(404).json({ error: 'not found' });
  fireWebhooks('test.ping', { from: req.adminUser, msg: 'Test ping from mes Cloud admin' });
  res.json({ ok: true, url: h.url });
});

// ─── Customer invitations ───
// Admin pre-creates a customer with an opaque invite token; sends them the URL.
// Customer clicks the URL → PWA picks it up → uses the token to claim the account.

if (!state.invitations) state.invitations = {};  // { token: {customer_id, expires_at, used} }
if (!state.invoices) state.invoices = {};         // { invoice_id: {id, customer_id, period, amount, currency, status, created_at, paid_at, lines[]} }
if (!state.firmwares) state.firmwares = {};       // { version: {file_path, sha256, size, signed_at, signature, model, notes} }
if (!state.api_keys) state.api_keys = {};         // { key_id: {id, name, hashed, scopes:[], created_by, created_at, last_used_at, last_used_ip} }
if (!state.device_renames) state.device_renames = {}; // { customer_id: { mac: custom_name } }
if (!state.webhook_queue) state.webhook_queue = []; // [ { id, hook_id, url, event, payload, attempts, next_at, created_at, last_error } ]
if (!state.push_subscriptions) state.push_subscriptions = {}; // { customer_id: [ { id, endpoint, keys: {p256dh, auth}, created_at, ua } ] }
if (!state.dns_lists) state.dns_lists = {};      // { id: {name, description, domain_count, applied_to:[customer_ids], created_at} }
if (!state.dns_list_files) state.dns_list_files = {};  // { id: '...domains separated by newlines...' } — separate from main state for size
if (!state.notif_prefs) state.notif_prefs = {};  // { customer_id: { security: bool, family: bool, billing: bool, system: bool, marketing: bool } }
if (!state.promo_codes) state.promo_codes = {};  // { code: {code, type: 'percent'|'fixed', value, currency, expires_at, max_uses, uses, applies_to_plans:[]} }
if (!state.customer_logins) state.customer_logins = {};  // { customer_id: [ {ts, ip, ua, success} ] }
if (!state.digest_state) state.digest_state = { last_sent: 0 };  // for daily digest tracking

app.post('/admin/api/customers/invite', adminAuth, (req, res) => {
  const { name, phone, email, plan, address } = req.body;
  if (!name || !phone) return res.status(400).json({ error: 'name and phone required' });
  if (findCustomerByPhone(phone)) return res.status(409).json({ error: 'phone already registered' });

  const id = 'cust-' + shortId(8);
  state.customers[id] = {
    id, name, phone, email: email || '', plan: plan || 'basic', address: address || '',
    status: 'active',
    self_signup: false,
    invited: true,
    created_at: new Date().toISOString(),
  };

  const token = crypto.randomBytes(16).toString('hex');
  state.invitations[token] = {
    customer_id: id,
    created_at: Date.now(),
    expires_at: Date.now() + 30 * 86400 * 1000,  // 30 days
    used: false,
  };
  saveState();
  logAdminAction(req, 'customer.invite', phone, name);

  const base = state.config.brand_domain ? 'https://' + state.config.brand_domain : 'http://' + req.headers.host;
  const inviteUrl = `${base}/pwa/?invite=${token}`;

  // WhatsApp deep-link — wa.me wants the phone in international format without +
  const waPhone = phone.replace(/[^\d]/g, '');
  const brand = state.config.brand_name || 'mes Network';
  const waText = encodeURIComponent(`أهلًا ${name}! 👋\n\n${brand} ready to set up. Tap below to claim your account:\n\n${inviteUrl}\n\n— ${brand}`);
  const waUrl  = `https://wa.me/${waPhone}?text=${waText}`;

  // Email customer
  if (email) sendEmail(email, 'mes Network — your account is ready',
    `Hi ${name},\n\nYour mes Network account has been pre-registered. Click below to set up your phone:\n\n${inviteUrl}\n\nThis link is valid for 30 days.\n\nmes Network team`);

  res.json({
    ok: true,
    customer_id: id,
    invite_url: inviteUrl,
    whatsapp_url: waUrl,
    expires_in_days: 30,
  });
});

app.get('/admin/api/customers/invitations', adminAuth, (req, res) => {
  const list = Object.entries(state.invitations).map(([token, inv]) => ({
    token: token.slice(0, 12) + '…',
    customer: state.customers[inv.customer_id],
    created_at: new Date(inv.created_at).toISOString(),
    expires_at: new Date(inv.expires_at).toISOString(),
    used: inv.used,
    expired: Date.now() > inv.expires_at,
  }));
  res.json({ invitations: list });
});

// Customer claims an invitation — public endpoint
app.post('/api/customer/invite/claim', (req, res) => {
  const { token } = req.body;
  const inv = state.invitations[token];
  if (!inv) return res.status(404).json({ error: 'invitation not found' });
  if (inv.used) return res.status(410).json({ error: 'invitation already used' });
  if (Date.now() > inv.expires_at) return res.status(410).json({ error: 'invitation expired' });
  const customer = state.customers[inv.customer_id];
  if (!customer) return res.status(404).json({ error: 'customer no longer exists' });

  inv.used = true;
  saveState();
  state.events.push({ ts: Date.now(), method: 'CUSTOMER', path: `[INVITE-CLAIM] ${customer.name}`, ip: req.ip });
  console.log(`         🎫 INVITE CLAIM → ${customer.name}`);

  // Issue a JWT immediately — they're logged in
  const jwt = customerJwt(customer);
  res.json({ ok: true, token: jwt, customer: { id: customer.id, name: customer.name, plan: customer.plan, phone: customer.phone } });
});

// ─── Health alerts (background watcher) ───
state.health_seen = state.health_seen || {};  // { mac: last_alerted_ts }
const OFFLINE_ALERT_AFTER_MS = 60 * 60 * 1000;  // 1 hour
const OFFLINE_ALERT_REPEAT_MS = 12 * 60 * 60 * 1000;  // re-alert every 12h max

function checkBoxHealth() {
  const now = Date.now();
  for (const m of Object.values(state.authorized_macs || {})) {
    if (!m.last_seen) continue;  // never seen — skip
    const offlineFor = now - m.last_seen;
    if (offlineFor < OFFLINE_ALERT_AFTER_MS) {
      // Box is online → clear any tracked alert
      delete state.health_seen[m.mac];
      continue;
    }
    const lastAlerted = state.health_seen[m.mac] || 0;
    if (now - lastAlerted < OFFLINE_ALERT_REPEAT_MS) continue;  // already alerted recently

    // Fire alert
    state.health_seen[m.mac] = now;
    const offlineMin = Math.round(offlineFor / 60000);
    const customer = state.customers[m.customer_id];
    console.log(`         🚨 BOX OFFLINE ALERT → ${m.mac}  customer=${customer?.name || 'unassigned'}  offline=${offlineMin}m`);
    fireWebhooks('box.offline', { mac: m.mac, customer_name: customer?.name, offline_min: offlineMin });
    sendEmail(state.config.admin_email, '[mes Cloud] Box offline alert',
      `MAC: ${m.mac}\nCustomer: ${customer?.name || '(unassigned)'} ${customer?.phone || ''}\nOffline for: ${offlineMin} minutes\nLast seen: ${new Date(m.last_seen).toISOString()}\n`);
    if (customer?.id) {
      pushNotification(customer.id, 'warn', '⚠ Your box may be offline',
        `We haven't heard from your box in ${offlineMin} minutes. Please check that it's powered on and connected.`);
    }
  }
}
setInterval(checkBoxHealth, 5 * 60 * 1000);  // every 5 min
setTimeout(checkBoxHealth, 30 * 1000);  // first run 30s after boot

// ─── Bulk customer import ───
function parseCSVRow(line) {
  const out = []; let cur = ''; let inQ = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"' && line[i+1] === '"') { cur += '"'; i++; continue; }
    if (ch === '"') { inQ = !inQ; continue; }
    if (ch === ',' && !inQ) { out.push(cur); cur = ''; continue; }
    cur += ch;
  }
  out.push(cur);
  return out;
}

app.post('/admin/api/customers/bulk-import', adminAuth, express.text({ limit: '10mb', type: 'text/csv' }), (req, res) => {
  const text = typeof req.body === 'string' ? req.body : (req.body.csv || '');
  if (!text) return res.status(400).json({ error: 'CSV body required (Content-Type: text/csv)' });

  const lines = text.split(/\r?\n/).filter(l => l.trim());
  if (lines.length < 2) return res.status(400).json({ error: 'need header + at least 1 row' });

  const headers = parseCSVRow(lines[0]).map(h => h.trim().toLowerCase());
  const idxName = headers.indexOf('name');
  const idxPhone = headers.indexOf('phone');
  const idxEmail = headers.indexOf('email');
  const idxPlan = headers.indexOf('plan');
  const idxAddress = headers.indexOf('address');
  const idxStatus = headers.indexOf('status');
  if (idxName < 0 || idxPhone < 0) return res.status(400).json({ error: 'CSV must have "name" and "phone" columns' });

  const created = [], skipped = [];
  for (let i = 1; i < lines.length; i++) {
    const cols = parseCSVRow(lines[i]);
    const name = (cols[idxName] || '').trim();
    const phone = (cols[idxPhone] || '').trim();
    if (!name || !phone) { skipped.push({ line: i+1, reason: 'missing name or phone' }); continue; }
    if (findCustomerByPhone(phone)) { skipped.push({ line: i+1, name, phone, reason: 'phone already exists' }); continue; }

    const id = 'cust-' + shortId(8);
    state.customers[id] = {
      id, name, phone,
      email: idxEmail >= 0 ? (cols[idxEmail] || '').trim() : '',
      plan: idxPlan >= 0 ? (cols[idxPlan] || 'basic').trim() : 'basic',
      address: idxAddress >= 0 ? (cols[idxAddress] || '').trim() : '',
      status: idxStatus >= 0 ? (cols[idxStatus] || 'active').trim() : 'active',
      self_signup: false,
      created_at: new Date().toISOString(),
    };
    created.push({ id, name, phone });
  }
  saveState();
  logAdminAction(req, 'customers.bulk_import', '', `created=${created.length} skipped=${skipped.length}`);
  console.log(`         ★ BULK IMPORT → created=${created.length} skipped=${skipped.length}`);
  fireWebhooks('customers.bulk_import', { created: created.length, skipped: skipped.length });
  res.json({ ok: true, created: created.length, skipped: skipped.length, created_list: created, skipped_list: skipped });
});

// ─── Admin support chat ───
app.get('/admin/api/support', adminAuth, (req, res) => {
  // Return all threads with unread counts
  const threads = Object.entries(state.support_threads || {}).map(([cid, arr]) => {
    const c = state.customers[cid];
    const unread = arr.filter(m => m.from === 'customer' && !m.read_by_admin).length;
    const last = arr[arr.length - 1] || null;
    return {
      customer_id: cid,
      customer_name: c ? c.name : '(unknown)',
      customer_phone: c ? c.phone : '',
      message_count: arr.length,
      unread,
      last_ts: last ? last.ts : 0,
      last_body: last ? last.body.slice(0, 80) : '',
      last_from: last ? last.from : '',
    };
  }).sort((a, b) => b.last_ts - a.last_ts);
  res.json({ threads });
});

app.get('/admin/api/support/:cid', adminAuth, (req, res) => {
  const arr = state.support_threads[req.params.cid] || [];
  // Mark all customer messages as read by admin on view
  arr.forEach(m => { if (m.from === 'customer') m.read_by_admin = true; });
  res.json({
    customer: state.customers[req.params.cid],
    messages: arr,
  });
});

app.post('/admin/api/support/:cid/reply', adminAuth, (req, res) => {
  const c = state.customers[req.params.cid];
  if (!c) return res.status(404).json({ error: 'customer not found' });
  if (!state.support_threads[c.id]) state.support_threads[c.id] = [];
  const body = String(req.body.body || '').slice(0, 1000).trim();
  if (!body) return res.status(400).json({ error: 'empty message' });
  const msg = {
    id: 'msg-' + shortId(8),
    from: 'admin',
    body,
    ts: Date.now(),
    read_by_admin: true,
    read_by_customer: false,
  };
  state.support_threads[c.id].push(msg);
  // Also push as a notification so it shows up on home banner
  pushNotification(c.id, 'info', '💬 mes Cloud support', body);
  // Real-time push to customer's SSE stream
  if (typeof customerSseEmit === 'function') customerSseEmit(c.id, 'support_msg', msg);
  saveState();
  state.events.push({ ts: Date.now(), method: 'ADMIN', path: `[SUPPORT-REPLY] → ${c.name}: "${body.slice(0, 60)}…"` });
  // Email customer if they have one
  if (c.email) sendEmail(c.email, '[mes Network] Support reply',
    `Hi ${c.name},\n\nA support agent replied:\n\n${body}\n\nView and reply in the app.\n\nmes Network team`);
  res.json({ ok: true });
});

// ─── DNS blocklists (admin uploads, applies to selected customers) ───
app.post('/admin/api/dnslists/upload', adminAuth, express.text({ type: 'text/plain', limit: '20mb' }), (req, res) => {
  const text = String(req.body || '');
  if (!text.trim()) return res.status(400).json({ error: 'empty body — POST text/plain with one domain per line' });
  // Parse: hosts-file format ("0.0.0.0 domain.com" / "127.0.0.1 domain.com") OR plain "domain.com"
  const domains = new Set();
  for (const raw of text.split(/\r?\n/)) {
    let line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith('!')) continue;
    // Strip leading IP if present
    const parts = line.split(/\s+/);
    const candidate = parts.length > 1 ? parts[1] : parts[0];
    if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(candidate)) domains.add(candidate.toLowerCase());
  }
  if (!domains.size) return res.status(400).json({ error: 'no valid domains parsed' });

  const id = 'dnslist-' + shortId(8);
  const list = {
    id,
    name: req.query.name || ('list-' + new Date().toISOString().slice(0, 10)),
    description: req.query.description || '',
    domain_count: domains.size,
    applied_to: [],
    created_at: new Date().toISOString(),
    created_by: req.adminUser,
  };
  state.dns_lists[id] = list;
  state.dns_list_files[id] = Array.from(domains).join('\n');
  saveState();
  logAdminAction(req, 'dnslist.create', id, `domains=${domains.size}`);
  console.log(`         📝 DNS LIST CREATED → ${id} (${domains.size} domains)`);
  res.json({ ok: true, list });
});

app.get('/admin/api/dnslists', adminAuth, (req, res) => {
  res.json({ lists: Object.values(state.dns_lists) });
});

app.get('/admin/api/dnslists/:id/download', adminAuth, (req, res) => {
  const list = state.dns_lists[req.params.id];
  if (!list) return res.status(404).json({ error: 'not found' });
  const txt = state.dns_list_files[req.params.id] || '';
  res.set('Content-Type', 'text/plain');
  res.set('Content-Disposition', `attachment; filename="${list.name}.txt"`);
  res.send(txt);
});

app.post('/admin/api/dnslists/:id/apply', adminAuth, (req, res) => {
  const list = state.dns_lists[req.params.id];
  if (!list) return res.status(404).json({ error: 'not found' });
  const customer_ids = Array.isArray(req.body.customer_ids) ? req.body.customer_ids : [];
  list.applied_to = customer_ids.filter(id => state.customers[id]);
  saveState();
  logAdminAction(req, 'dnslist.apply', req.params.id, `customers=${list.applied_to.length}`);
  // Notify each affected customer
  for (const cid of list.applied_to) {
    pushNotification(cid, 'system', '🛡 New protection list applied',
      `Your provider applied "${list.name}" (${list.domain_count} domains) to your network.`);
  }
  fireWebhooks('dnslist.applied', { list_id: req.params.id, name: list.name, customer_count: list.applied_to.length });
  res.json({ ok: true, applied_to_count: list.applied_to.length });
});

app.post('/admin/api/dnslists/:id/delete', adminAuth, (req, res) => {
  if (req.adminRole !== 'super' && req.adminRole !== 'admin') return res.status(403).json({ error: 'admin or super only' });
  delete state.dns_lists[req.params.id];
  delete state.dns_list_files[req.params.id];
  saveState();
  logAdminAction(req, 'dnslist.delete', req.params.id);
  res.json({ ok: true });
});

// PUBLIC: a paired box can fetch its assigned DNS lists by MAC (no auth — protected by MAC obscurity / would be Bearer in production)
app.get('/api/box/dnslists/:mac', (req, res) => {
  const mac = normalizeMac(req.params.mac);
  const m = state.authorized_macs[mac];
  if (!m || !m.customer_id) return res.status(404).json({ error: 'unknown or unassigned' });
  const lists = Object.values(state.dns_lists)
    .filter(l => l.applied_to.includes(m.customer_id))
    .map(l => ({ id: l.id, name: l.name, domain_count: l.domain_count, etag: crypto.createHash('sha256').update(state.dns_list_files[l.id] || '').digest('hex').slice(0, 16) }));
  res.json({ mac, customer_id: m.customer_id, lists });
});

app.get('/api/box/dnslists/:mac/:listId', (req, res) => {
  const mac = normalizeMac(req.params.mac);
  const m = state.authorized_macs[mac];
  if (!m || !m.customer_id) return res.status(404).json({ error: 'unknown' });
  const list = state.dns_lists[req.params.listId];
  if (!list || !list.applied_to.includes(m.customer_id)) return res.status(404).json({ error: 'not assigned to this box' });
  res.set('Content-Type', 'text/plain');
  res.send(state.dns_list_files[req.params.listId] || '');
});

// ═══════════════════════════════════════════════════════════════════════════
//  BOX AGENT API — endpoints the on-premise box daemon calls
// ═══════════════════════════════════════════════════════════════════════════

// Default app-category domain lists (Firewalla-style: block whole categories)
const APP_CATEGORIES_DEFAULT = {
  social:   { name: 'Social Media',  icon: '👥', domains: ['facebook.com','instagram.com','twitter.com','x.com','tiktok.com','snapchat.com','reddit.com','linkedin.com','pinterest.com','threads.net'] },
  video:    { name: 'Video / Streaming', icon: '📺', domains: ['youtube.com','netflix.com','hulu.com','disneyplus.com','twitch.tv','primevideo.com','shahid.net','mbc.net','vimeo.com','dailymotion.com'] },
  gaming:   { name: 'Gaming',        icon: '🎮', domains: ['steampowered.com','steamcommunity.com','epicgames.com','playstation.com','xbox.com','nintendo.com','roblox.com','minecraft.net','battle.net','ea.com'] },
  adult:    { name: 'Adult Content', icon: '🔞', domains: ['pornhub.com','xvideos.com','xnxx.com','xhamster.com','redtube.com','onlyfans.com','chaturbate.com','youporn.com','tnaflix.com'] },
  news:     { name: 'News',          icon: '📰', domains: ['cnn.com','bbc.com','aljazeera.com','reuters.com','nytimes.com','washingtonpost.com','foxnews.com','bbc.co.uk','dw.com','france24.com'] },
  shopping: { name: 'Shopping',      icon: '🛒', domains: ['amazon.com','ebay.com','aliexpress.com','shein.com','noon.com','souq.com','walmart.com','target.com','etsy.com'] },
  ads:      { name: 'Ads & Trackers', icon: '🚫', domains: ['doubleclick.net','googleadservices.com','googlesyndication.com','google-analytics.com','facebook.net','adroll.com','taboola.com','outbrain.com','criteo.com','scorecardresearch.com'] },
  malware:  { name: 'Malware (always-block)', icon: '☣️', domains: [], builtin: true, locked: true },
};
if (!state.app_categories) state.app_categories = JSON.parse(JSON.stringify(APP_CATEGORIES_DEFAULT));

// HMAC-based box auth: each authorized MAC has a derived shared secret
function boxSecret(mac) {
  const root = state.config.box_secret_root || (state.config.box_secret_root = crypto.randomBytes(32).toString('hex'));
  return crypto.createHmac('sha256', root).update(mac.toLowerCase()).digest('hex');
}

function boxAuth(req, res, next) {
  // Box presents either a session token (Authorization: Bearer <token>) or HMAC sig
  const auth = req.headers.authorization || '';
  if (auth.startsWith('Bearer ')) {
    const token = auth.slice(7);
    const sess = state.box_sessions[token];
    if (sess && (Date.now() - sess.issued_at) < 7 * 24 * 3600_000) {
      sess.last_seen = Date.now();
      req.boxMac = sess.mac;
      // Derive customer_id LIVE from authorized_macs — the session was minted at
      // /api/box/auth time and may have been before the customer claimed the box,
      // so the cached sess.customer_id can be stale (null). Trust the live value.
      const authM = state.authorized_macs[sess.mac];
      const liveCid = authM ? (authM.customer_id || null) : null;
      if (liveCid && liveCid !== sess.customer_id) sess.customer_id = liveCid;
      req.boxCustomerId = liveCid;
      return next();
    }
  }
  return res.status(401).json({ error: 'box_auth_required', hint: 'POST /api/box/auth with mac+sig first' });
}

// POST /api/box/auth — box logs in with HMAC of mac+timestamp
app.post('/api/box/auth', (req, res) => {
  const mac = normalizeMac(req.body.mac || '');
  const ts  = parseInt(req.body.ts || 0);
  const sig = String(req.body.sig || '');
  if (!mac || !ts || !sig) return res.status(400).json({ error: 'mac, ts, sig required' });
  if (Math.abs(Date.now() - ts) > 5 * 60_000) return res.status(401).json({ error: 'timestamp_skew' });
  const m = state.authorized_macs[mac];
  if (!m) return res.status(401).json({ error: 'mac_not_authorized' });
  const expected = crypto.createHmac('sha256', boxSecret(mac)).update(`${mac}:${ts}`).digest('hex');
  if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig))) {
    return res.status(401).json({ error: 'bad_signature' });
  }
  const token = shortId(40);
  state.box_sessions[token] = { mac, customer_id: m.customer_id || null, issued_at: Date.now(), last_seen: Date.now() };
  saveState();
  console.log(`         🔐 BOX AUTH OK → ${mac} cust=${m.customer_id || '-'}`);
  res.json({ ok: true, token, customer_id: m.customer_id, expires_in: 7 * 24 * 3600 });
});

// ═══════════════════════════════════════════════════════════════════════════
//  SELF-REGISTRATION — flashable-image flow (Firewalla-style "plug and pair")
// ═══════════════════════════════════════════════════════════════════════════
// On first boot the agent calls /api/box/self-register with its MAC.
// Cloud generates a 6-char pairing code, stores it, returns it to the box.
// Customer enters that code in the PWA → /api/customer/box/claim links the MAC
// to their account. Box's next /api/box/pairing-status poll picks up the claim.

if (!state.pending_boxes) state.pending_boxes = {};  // { mac: { mac, code, model, hostname, registered_at, expires_at, customer_id } }

function genPairingCode() {
  // 6 chars, no I/O/0/1 to avoid confusion when read aloud
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let s = '';
  for (let i = 0; i < 6; i++) s += alphabet[crypto.randomBytes(1)[0] % alphabet.length];
  return s;
}

// Box self-registers on first boot. Idempotent — re-registers if expired.
app.post('/api/box/self-register', (req, res) => {
  const mac = normalizeMac(req.body.mac || '');
  if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(mac)) {
    return res.status(400).json({ error: 'invalid mac' });
  }
  const model = String(req.body.model || 'pi4').slice(0, 20);
  const hostname = String(req.body.hostname || '').slice(0, 60);

  // If already authorized to a customer, return claimed status
  if (state.authorized_macs[mac] && state.authorized_macs[mac].customer_id) {
    return res.json({
      status: 'claimed',
      customer_id: state.authorized_macs[mac].customer_id,
      hint: 'This box is already owned. Run /api/box/auth to get a session token.',
    });
  }

  // Fresh code if no entry or expired
  let p = state.pending_boxes[mac];
  if (!p || p.expires_at < Date.now() || p.customer_id) {
    p = state.pending_boxes[mac] = {
      mac,
      code: genPairingCode(),
      model,
      hostname,
      registered_at: Date.now(),
      expires_at: Date.now() + 7 * 24 * 3600_000,  // 7-day window to claim
      customer_id: null,
    };
    saveState();
    console.log(`         📦 BOX SELF-REGISTERED → ${mac} model=${model} code=${p.code}`);
  }

  // Auto-authorize the MAC so the box can use HMAC auth even before being claimed.
  // The customer_id stays null until claim happens.
  if (!state.authorized_macs[mac]) {
    state.authorized_macs[mac] = {
      mac,
      customer_id: null,
      customer_name: '',
      type: model,
      authorized_at: new Date().toISOString(),
      notes: 'self-registered, awaiting customer claim',
      self_registered: true,
    };
    saveState();
  }

  res.json({
    status: 'pending',
    code: p.code,
    secret: boxSecret(mac),
    expires_at: p.expires_at,
    hint: 'Display this code to the customer. They enter it in the PWA at "Add a box".',
  });
});

// Box polls this to know when it's been claimed
app.get('/api/box/pairing-status/:mac', (req, res) => {
  const mac = normalizeMac(req.params.mac);
  const m = state.authorized_macs[mac];
  if (m && m.customer_id) {
    return res.json({ status: 'claimed', customer_id: m.customer_id, customer_name: m.customer_name });
  }
  const p = state.pending_boxes[mac];
  if (!p) return res.status(404).json({ status: 'unknown' });
  if (p.expires_at < Date.now()) return res.json({ status: 'expired' });
  res.json({ status: 'pending', code: p.code });
});

// Pre-pairing QR data: customer generates a QR before installing the box.
// Encodes: cloud URL, customer claim token. Installer scans on first-boot wizard.
// Token is single-use, expires in 24h. Box uses it to auto-claim itself.
if (!state.pre_pair_tokens) state.pre_pair_tokens = {};   // token → {cid, created_at, expires_at, used_at}
app.post('/api/customer/box/prepair', customerAuth, (req, res) => {
  const cid = req.customer.id;
  const token = crypto.randomBytes(20).toString('base64url');
  state.pre_pair_tokens[token] = {
    cid, created_at: Date.now(), expires_at: Date.now() + 24 * 3600_000, used_at: null,
  };
  saveState();
  // Payload for QR: tiny JSON (must fit comfortably in alphanumeric QR)
  const qrPayload = { cloud: 'cloud.mes.net.lb', t: token, c: cid };
  const qrText = 'MESBOX:' + Buffer.from(JSON.stringify(qrPayload)).toString('base64url');
  res.json({
    ok: true,
    token,
    qr_text: qrText,
    qr_url_for_render: `https://cloud.mes.net.lb/api/qr/render?text=${encodeURIComponent(qrText)}`,
    expires_in_hours: 24,
    instructions: 'Show this QR to the box during first-boot setup, or paste the text in the wizard.',
  });
});
// Box uses this on first boot if a prepair token was provided.
app.post('/api/box/prepair-claim', (req, res) => {
  const token = String(req.body.token || '');
  const mac = normalizeMac(req.body.mac || '');
  if (!mac) return res.status(400).json({ error: 'mac required' });
  const t = state.pre_pair_tokens[token];
  if (!t) return res.status(404).json({ error: 'invalid_token' });
  if (Date.now() > t.expires_at) { delete state.pre_pair_tokens[token]; return res.status(410).json({ error: 'expired' }); }
  if (t.used_at) return res.status(409).json({ error: 'already_used' });
  const c = state.customers[t.cid];
  if (!c) return res.status(404).json({ error: 'customer_gone' });
  // Bind
  if (!state.authorized_macs[mac]) {
    state.authorized_macs[mac] = { mac, customer_id: c.id, customer_name: c.name, claimed_at: Date.now(), source: 'prepair_qr' };
  } else {
    state.authorized_macs[mac].customer_id = c.id;
    state.authorized_macs[mac].customer_name = c.name;
  }
  t.used_at = Date.now();
  saveState();
  console.log(`         📷 PREPAIR-QR claim: ${mac} → ${c.name}`);
  if (typeof pushNotification === 'function') pushNotification(c.id, 'system', '✓ Box auto-paired', `Your box (${mac}) was claimed via QR.`);
  res.json({ ok: true, customer_id: c.id, customer_name: c.name });
});
// Lightweight QR renderer using qrcode.min.js inline. Returns SVG.
app.get('/api/qr/render', (req, res) => {
  const text = String(req.query.text || '').slice(0, 1000);
  if (!text) return res.status(400).send('text param required');
  // Minimal SVG QR using a built-in encoder is heavy; instead serve an HTML page that uses the lib.
  res.type('html').send(`<!doctype html>
<html><head><meta charset="utf-8"><title>mes Box pairing QR</title>
<style>body{font-family:sans-serif;text-align:center;background:#0f1419;color:#fff;padding:20px}
canvas{background:#fff;padding:12px;border-radius:8px}.code{font-family:monospace;font-size:.8em;word-break:break-all;color:#888;margin-top:12px;max-width:400px;margin-left:auto;margin-right:auto}</style>
</head><body>
<h2>mes Box pairing</h2>
<canvas id="qr"></canvas>
<div class="code">${text.replace(/[<>"&]/g, c => ({ '<':'&lt;', '>':'&gt;', '"':'&quot;', '&':'&amp;' })[c])}</div>
<script src="/api/qrcode.min.js"></script>
<script>QRCode.toCanvas(document.getElementById('qr'), ${JSON.stringify(text)}, { width: 320, margin: 2 });</script>
</body></html>`);
});

// Customer claims a pending box by entering the pairing code
app.post('/api/customer/box/claim', customerAuth, (req, res) => {
  const code = String(req.body.code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
  if (code.length !== 6) return res.status(400).json({ error: 'code must be 6 alphanumeric characters' });

  const pending = Object.values(state.pending_boxes || {}).find(p => p.code === code && !p.customer_id && p.expires_at > Date.now());
  if (!pending) return res.status(404).json({ error: 'code_not_found_or_expired' });

  // Bind to customer
  pending.customer_id = req.customer.id;
  pending.claimed_at = Date.now();
  if (state.authorized_macs[pending.mac]) {
    state.authorized_macs[pending.mac].customer_id = req.customer.id;
    state.authorized_macs[pending.mac].customer_name = req.customer.name;
  }
  saveState();
  state.events.push({ ts: Date.now(), method: 'CUSTOMER', path: `[BOX:CLAIM] ${req.customer.name} claimed ${pending.mac}`, ip: req.ip });
  pushNotification(req.customer.id, 'system', 'New box added', `Your ${pending.model || 'box'} is now linked to your account`);
  fireWebhooks('box.claimed', { mac: pending.mac, customer_id: req.customer.id });
  console.log(`         ✓ BOX CLAIMED → ${pending.mac} by ${req.customer.name} (${req.customer.id})`);
  res.json({ ok: true, mac: pending.mac, model: pending.model });
});

// Auto-discover unclaimed boxes that share the requesting client's public IP.
// Used by the PWA: customer on same home network as their freshly-flashed Pi
// → cloud surfaces the box for one-tap claim without needing the pairing code.
app.get('/api/customer/box/discover', customerAuth, (req, res) => {
  const reqIp = (req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim().replace(/^::ffff:/, '');
  if (!reqIp) return res.json({ candidates: [] });
  const candidates = [];
  for (const [mac, b] of Object.entries(state.box_state || {})) {
    if (state.authorized_macs[mac] && state.authorized_macs[mac].customer_id) continue; // claimed
    const boxPubIp = (b.public_ip || '').split(',')[0].trim();
    if (!boxPubIp) continue;
    if (boxPubIp !== reqIp) continue;
    if (!b.last_heartbeat || (Date.now() - b.last_heartbeat) > 10 * 60_000) continue; // stale
    candidates.push({
      mac,
      version: b.version || '?',
      hw: b.hw || null,
      last_heartbeat: b.last_heartbeat,
      uptime_s: b.uptime_s || 0,
      device_count: b.device_count || 0,
      pending_code: (Object.values(state.pending_boxes || {}).find(p => p.mac === mac && !p.customer_id) || {}).code || null,
    });
  }
  res.json({ candidates, your_ip: reqIp });
});

// One-tap claim — works only when the box is on the same network as the requester
// (verified by matching public IP). Skips the 6-char code entirely.
app.post('/api/customer/box/auto-claim', customerAuth, (req, res) => {
  const reqIp = (req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim().replace(/^::ffff:/, '');
  const mac = normalizeMac(req.body.mac || '');
  if (!mac) return res.status(400).json({ error: 'mac required' });
  const b = state.box_state[mac];
  if (!b) return res.status(404).json({ error: 'unknown_box' });
  const boxPubIp = (b.public_ip || '').split(',')[0].trim();
  if (boxPubIp !== reqIp) return res.status(403).json({ error: 'ip_mismatch', your_ip: reqIp, box_ip: boxPubIp, message: 'Auto-claim only works when you are on the same network as the box. Use the 6-char pairing code instead.' });
  const auth = state.authorized_macs[mac];
  if (auth && auth.customer_id) return res.status(409).json({ error: 'already_claimed' });
  // Bind
  if (!state.authorized_macs[mac]) {
    state.authorized_macs[mac] = { mac, type: (b.hw && b.hw.hw_model) ? 'pi4' : 'unknown', authorized_at: new Date().toISOString(), source: 'auto-claim' };
  }
  state.authorized_macs[mac].customer_id = req.customer.id;
  state.authorized_macs[mac].customer_name = req.customer.name;
  // Also clear any pending pairing record
  for (const p of Object.values(state.pending_boxes || {})) {
    if (p.mac === mac) { p.customer_id = req.customer.id; p.claimed_at = Date.now(); }
  }
  saveState();
  if (typeof pushNotification === 'function') pushNotification(req.customer.id, 'system', 'Box auto-paired', `Your ${state.authorized_macs[mac].type || 'box'} (${mac}) is now linked.`);
  if (typeof fireWebhooks === 'function') fireWebhooks('box.claimed', { mac, customer_id: req.customer.id, method: 'auto-claim' });
  console.log(`         ✓ BOX AUTO-CLAIMED → ${mac} by ${req.customer.name} (same network: ${reqIp})`);
  res.json({ ok: true, mac, source: 'auto-claim' });
});

// Customer health score (0-100, churn-risk indicator)
// Composite: box uptime + recent activity + payment status + alarms count + age
function computeHealthScore(c) {
  if (!c) return 0;
  let score = 100;
  const reasons = [];
  // Account status
  if (c.status === 'pending') { score -= 30; reasons.push('account pending approval'); }
  if (c.status === 'archived') { score -= 50; reasons.push('account archived'); }
  if (c.delete_scheduled_at) { score -= 40; reasons.push('account scheduled for deletion'); }

  // Boxes — none assigned is bad
  const myMacs = Object.values(state.authorized_macs).filter(m => m.customer_id === c.id);
  if (myMacs.length === 0) { score -= 25; reasons.push('no box claimed'); }
  else {
    const onlineBoxes = myMacs.filter(m => {
      const s = state.box_state[m.mac];
      return s && s.last_heartbeat && (Date.now() - s.last_heartbeat) < 5*60_000;
    });
    if (onlineBoxes.length === 0) { score -= 30; reasons.push('all boxes offline'); }
  }

  // Recent activity
  const recentEvents = state.events.filter(e => e.path && e.path.includes(c.name) && (Date.now() - e.ts) < 7*24*3600_000);
  if (recentEvents.length === 0 && (Date.now() - new Date(c.created_at).getTime()) > 7*24*3600_000) {
    score -= 15; reasons.push('no activity in 7 days');
  }

  // Unpaid invoices
  const unpaid = Object.values(state.invoices || {}).filter(i => i.customer_id === c.id && i.status !== 'paid');
  if (unpaid.length > 1) { score -= 20; reasons.push(unpaid.length + ' unpaid invoices'); }

  // High alarm load (red flag)
  const recentCriticalAlarms = state.alarms.filter(a => a.customer_id === c.id && a.severity === 'critical' && (Date.now() - a.ts) < 7*24*3600_000).length;
  if (recentCriticalAlarms > 3) { score -= 10; reasons.push(recentCriticalAlarms + ' critical alarms this week'); }

  // NPS detractor?
  const recentNps = (state.nps_responses[c.id] || []).slice(-3);
  if (recentNps.length && recentNps.every(r => r.score <= 6)) { score -= 15; reasons.push('detractor NPS scores'); }

  return { score: Math.max(0, Math.min(100, score)), reasons };
}

app.get('/admin/api/customer/:cid/health', adminAuth, (req, res) => {
  const c = state.customers[req.params.cid];
  if (!c) return res.status(404).json({ error: 'not found' });
  res.json({ customer_id: c.id, name: c.name, ...computeHealthScore(c) });
});

app.get('/admin/api/customers/health-summary', adminAuth, (req, res) => {
  const out = Object.values(state.customers)
    .filter(c => !c.demo)
    .map(c => ({ id: c.id, name: c.name, plan: c.plan, ...computeHealthScore(c) }));
  out.sort((a, b) => a.score - b.score);   // worst first
  // Aggregate buckets
  const at_risk = out.filter(o => o.score < 50).length;
  const warning = out.filter(o => o.score >= 50 && o.score < 75).length;
  const healthy = out.filter(o => o.score >= 75).length;
  res.json({ customers: out, buckets: { at_risk, warning, healthy } });
});

// Admin: cohort retention — customers grouped by signup-month, % active at 30/60/90/180 days
app.get('/admin/api/cohort-retention', adminAuth, (req, res) => {
  const cohorts = {};   // 'YYYY-MM' → [customers signed up that month]
  for (const c of Object.values(state.customers)) {
    if (c.demo) continue;
    const m = String(c.created_at || '').slice(0, 7);
    if (!m) continue;
    if (!cohorts[m]) cohorts[m] = [];
    cohorts[m].push(c);
  }
  // For each cohort, compute retention at 30/60/90/180 days
  // We can only know "active" by their box being seen recently OR signed in within the window
  function isStillActive(cust, atTime) {
    const myMacs = Object.values(state.authorized_macs).filter(m => m.customer_id === cust.id);
    for (const m of myMacs) {
      const s = state.box_state[m.mac];
      if (s && s.last_heartbeat && s.last_heartbeat <= atTime && (atTime - s.last_heartbeat) < 30 * 24 * 3600_000) return true;
    }
    // If they've ever signed in within 30 days of `atTime`
    return false;
  }
  const out = [];
  const months = Object.keys(cohorts).sort();
  for (const m of months) {
    const cohort = cohorts[m];
    const monthDate = new Date(m + '-01').getTime();
    const stages = [30, 60, 90, 180];
    const retention = {};
    for (const days of stages) {
      const t = monthDate + days * 24 * 3600_000;
      if (t > Date.now()) {
        retention['day_' + days] = null;
        continue;
      }
      const stillActive = cohort.filter(c => isStillActive(c, t)).length;
      retention['day_' + days] = cohort.length > 0 ? Math.round((stillActive / cohort.length) * 100) : 0;
    }
    out.push({ cohort: m, signups: cohort.length, retention });
  }
  res.json({ cohorts: out });
});

// Admin: acquisition source breakdown
app.get('/admin/api/acquisition', adminAuth, (req, res) => {
  const bySource = {}, byMedium = {}, byCampaign = {};
  for (const c of Object.values(state.customers)) {
    if (c.demo) continue;
    const u = c.utm || {};
    const src = u.source || '(direct)';
    const med = u.medium || '(none)';
    const camp = u.campaign || '(none)';
    bySource[src]   = (bySource[src]   || 0) + 1;
    byMedium[med]   = (byMedium[med]   || 0) + 1;
    byCampaign[camp]= (byCampaign[camp]|| 0) + 1;
  }
  res.json({ by_source: bySource, by_medium: byMedium, by_campaign: byCampaign });
});

// Admin: queue health snapshot (single endpoint with all the queue depths)
app.get('/admin/api/queue-health', adminAuth, (req, res) => {
  const now = Date.now();
  // Webhook delivery queue
  const webhookPending = (state.webhook_queue || []).filter(q => q.status === 'pending').length;
  const webhookFailed  = (state.webhook_queue || []).filter(q => q.status === 'failed').length;
  // Box command queue
  let cmdPending = 0, cmdInProgress = 0, cmdFailed = 0;
  for (const queue of Object.values(state.box_commands || {})) {
    for (const c of queue) {
      if (c.status === 'pending') cmdPending++;
      else if (c.status === 'in_progress') cmdInProgress++;
      else if (c.status === 'failed') cmdFailed++;
    }
  }
  // Pending registrations (boxes self-registered, not yet claimed)
  const pendingBoxes = Object.values(state.pending_boxes || {})
    .filter(p => !p.customer_id && p.expires_at > now).length;
  // Support thread backlog (unread by admin)
  let supportBacklog = 0;
  for (const thread of Object.values(state.support_threads || {})) {
    supportBacklog += thread.filter(m => m.from === 'customer' && !m.read_by_admin).length;
  }
  // Plan requests pending
  const planRequestsPending = Object.values(state.plan_requests || {}).filter(r => r.status === 'pending').length;
  // Hardware orders needing action
  const hwOrdersPending = Object.values(state.hw_orders || {}).filter(o => o.status === 'received' || o.status === 'prepping').length;
  // Bug reports unread
  let bugReportsUnread = 0;
  for (const thread of Object.values(state.support_threads || {})) {
    bugReportsUnread += thread.filter(m => m.bug_report && !m.read_by_admin).length;
  }
  // Open outages
  const openOutages = (state.outage_log || []).filter(o => o.ended_at === null).length;
  // Failed in last 24h
  const cutoff = now - 24 * 3600_000;
  const recentFailedAlarms = (state.alarms || []).filter(a => a.severity === 'critical' && a.ts >= cutoff).length;

  res.json({
    snapshot_at: now,
    queues: {
      webhook_pending: webhookPending,
      webhook_failed: webhookFailed,
      box_commands_pending: cmdPending,
      box_commands_in_progress: cmdInProgress,
      box_commands_failed: cmdFailed,
      pending_box_registrations: pendingBoxes,
      support_unread: supportBacklog,
      bug_reports_unread: bugReportsUnread,
      plan_requests_pending: planRequestsPending,
      hw_orders_pending: hwOrdersPending,
      open_outages: openOutages,
      critical_alarms_24h: recentFailedAlarms,
    },
    health: {
      // simple traffic-light
      status: (webhookFailed > 10 || openOutages > 5 || recentFailedAlarms > 0) ? 'red'
            : (webhookPending > 50 || cmdPending > 50 || supportBacklog > 20 || hwOrdersPending > 5) ? 'yellow'
            : 'green',
    },
  });
});

// Admin: revenue forecast
app.get('/admin/api/revenue-forecast', adminAuth, (req, res) => {
  const now = Date.now();
  const day = 24 * 3600_000;
  const planUsd = { basic: 5, family: 10, pro: 20, business: 50 };
  const real = Object.values(state.customers || {}).filter(c => !c.demo);
  // Current MRR (excluding paused + trial)
  let currentMrr = 0;
  for (const c of real) {
    if (c.status === 'archived' || c.subscription_paused) continue;
    if (c.trial_status === 'active' && c.trial_until > now) continue;   // trials don't pay yet
    if ((c.referral_credits || 0) > 0) continue;   // current month is free
    currentMrr += planUsd[c.plan] || 0;
  }
  // Growth rate — signups in last 30 days / signups in prior 30 days
  const sig30 = real.filter(c => (now - new Date(c.created_at).getTime()) < 30 * day).length;
  const sig60 = real.filter(c => {
    const age = now - new Date(c.created_at).getTime();
    return age >= 30 * day && age < 60 * day;
  }).length;
  const growthRate = sig60 > 0 ? (sig30 / sig60) - 1 : (sig30 > 0 ? 1.0 : 0);
  // Trial conversion rate (estimated — assume 60% if no data)
  const trialEnded = real.filter(c => c.trial_status === 'converted' || c.trial_status === 'cancelled').length;
  const converted = real.filter(c => c.trial_status === 'converted').length;
  const conversionRate = trialEnded > 0 ? (converted / trialEnded) : 0.6;
  // Active trials ending soon
  const trialsEndingIn30Days = real.filter(c => c.trial_status === 'active' && c.trial_until && (c.trial_until - now) < 30 * day).length;
  // Project
  const next30 = currentMrr + (trialsEndingIn30Days * conversionRate * 10);   // assume avg $10/customer
  const next60 = next30 * (1 + Math.min(0.3, Math.max(-0.2, growthRate)));
  const next90 = next60 * (1 + Math.min(0.3, Math.max(-0.2, growthRate)));
  res.json({
    current_mrr_usd: currentMrr,
    current_mrr_lbp: currentMrr * lbpPerUsd(),
    signups_last_30d: sig30,
    signups_30_to_60d_ago: sig60,
    growth_rate: Math.round(growthRate * 100) / 100,
    trial_conversion_rate: Math.round(conversionRate * 100) / 100,
    active_trials_ending_in_30d: trialsEndingIn30Days,
    forecast_30d_usd: Math.round(next30),
    forecast_60d_usd: Math.round(next60),
    forecast_90d_usd: Math.round(next90),
  });
});

// Admin: business-intel summary
app.get('/admin/api/biz-intel', adminAuth, (req, res) => {
  const now = Date.now();
  const day_ms = 24 * 3600_000;
  const customers = Object.values(state.customers || {});
  const real = customers.filter(c => !c.demo);

  // MRR — sum of all active customers' monthly USD price
  const planUsd = { basic: 5, family: 10, pro: 20, business: 50 };
  let mrr_usd = 0;
  const planDist = { basic: 0, family: 0, pro: 0, business: 0 };
  for (const c of real) {
    if (c.status === 'active' || !c.status) {
      mrr_usd += planUsd[c.plan] || 0;
      planDist[c.plan] = (planDist[c.plan] || 0) + 1;
    }
  }

  // Growth: signups by week for last 12 weeks
  const weekly = [];
  for (let w = 11; w >= 0; w--) {
    const start = now - (w + 1) * 7 * day_ms;
    const end   = now - w * 7 * day_ms;
    weekly.push({
      week_start: new Date(start).toISOString().slice(0, 10),
      signups: real.filter(c => {
        const ts = new Date(c.created_at).getTime();
        return ts >= start && ts < end;
      }).length,
    });
  }

  // Tenant breakdown
  const tenants = state.tenants || {};
  const byTenant = {};
  for (const c of real) {
    const tid = c.tenant_id || 'default';
    if (!byTenant[tid]) byTenant[tid] = { customers: 0, mrr_usd: 0, name: tenants[tid] ? tenants[tid].name : 'Default' };
    byTenant[tid].customers++;
    byTenant[tid].mrr_usd += planUsd[c.plan] || 0;
  }

  // Conversion funnel (rough — based on seeded data)
  const total_signups = real.length;
  const claimed_box   = real.filter(c => Object.values(state.authorized_macs).some(m => m.customer_id === c.id)).length;
  const active_box    = real.filter(c =>
    Object.values(state.authorized_macs).filter(m => m.customer_id === c.id).some(m => {
      const s = state.box_state[m.mac];
      return s && (now - s.last_heartbeat) < 5*60_000;
    })
  ).length;

  res.json({
    mrr_usd,
    mrr_lbp: mrr_usd * lbpPerUsd(),
    customer_count: real.length,
    plan_distribution: planDist,
    weekly_signups: weekly,
    tenant_breakdown: byTenant,
    funnel: {
      signed_up: total_signups,
      claimed_box,
      active_box,
    },
  });
});

// Admin: list pending boxes (boxes that have called home but no customer yet)
app.get('/admin/api/pending-boxes', adminAuth, (req, res) => {
  const out = Object.values(state.pending_boxes || {})
    .filter(p => !p.customer_id && p.expires_at > Date.now())
    .map(p => ({ mac: p.mac, code: p.code, model: p.model, hostname: p.hostname, registered_at: p.registered_at, expires_at: p.expires_at }));
  res.json({ pending: out });
});

// GET /api/box/secret/:mac — admin retrieves the box-side shared secret to provision boxes
app.get('/admin/api/box/secret/:mac', adminAuth, (req, res) => {
  const mac = normalizeMac(req.params.mac);
  if (!state.authorized_macs[mac]) return res.status(404).json({ error: 'mac not authorized' });
  res.json({ mac, secret: boxSecret(mac), hint: 'Provision this on the box. Used to sign HMAC for /api/box/auth.' });
});

// POST /api/box/crash — box uploads its last crash log on boot recovery
if (!state.box_crashes) state.box_crashes = [];
app.post('/api/box/crash', boxAuth, (req, res) => {
  const entry = {
    id: 'crash-' + shortId(10),
    ts: Date.now(),
    box_mac: req.boxMac,
    customer_id: req.boxCustomerId || null,
    version: req.body.version,
    uname: req.body.uname,
    uptime: req.body.uptime,
    crash_log: String(req.body.crash_log || '').slice(0, 50_000),
  };
  state.box_crashes.unshift(entry);
  if (state.box_crashes.length > 500) state.box_crashes.length = 500;
  saveState();
  console.log(`         💥 BOX CRASH REPORT ← ${req.boxMac} v${req.body.version}`);
  // Notify admin
  if (state.config.admin_email) {
    sendEmail(state.config.admin_email,
      `[mes Network] 💥 Box crash report from ${req.boxMac}`,
      `Box: ${req.boxMac}\nCustomer: ${req.boxCustomerId || '(unassigned)'}\nVersion: ${req.body.version}\nUname: ${req.body.uname}\nUptime: ${req.body.uptime}s\n\n--- crash log ---\n${(req.body.crash_log || '').slice(0, 5000)}`);
  }
  fireWebhooks('box.crashed', { box_mac: req.boxMac, customer_id: req.boxCustomerId, version: req.body.version });
  res.json({ ok: true });
});

app.get('/admin/api/box-crashes', adminAuth, (req, res) => {
  res.json({ crashes: state.box_crashes.slice(0, 100) });
});

// POST /api/box/throughput — 5s real-time bandwidth samples for live speedometer.
if (!state.box_throughput) state.box_throughput = {};   // mac → { rx_bps, tx_bps, ts, hist60: [...] }
app.post('/api/box/throughput', boxAuth, (req, res) => {
  const mac = req.boxMac;
  const rx_bps = Math.max(0, parseInt(req.body.rx_bps) || 0);
  const tx_bps = Math.max(0, parseInt(req.body.tx_bps) || 0);
  const ts     = parseInt(req.body.ts) || Date.now();
  if (!state.box_throughput[mac]) state.box_throughput[mac] = { hist60: [] };
  const t = state.box_throughput[mac];
  t.rx_bps = rx_bps; t.tx_bps = tx_bps; t.ts = ts;
  t.hist60.push({ ts, rx: rx_bps, tx: tx_bps });
  if (t.hist60.length > 60) t.hist60.shift();   // last 5 min @ 5s = 60 samples
  // Stream to customer SSE
  if (req.boxCustomerId && typeof customerSseEmit === 'function') {
    customerSseEmit(req.boxCustomerId, 'throughput', { mac, rx_bps, tx_bps, ts });
  }
  res.json({ ok: true });
});
// Customer reads current throughput + 5-min history (poll fallback if no SSE)
app.get('/api/customer/throughput', customerAuth, (req, res) => {
  const myMacs = Object.values(state.authorized_macs).filter(m => m.customer_id === req.customer.id).map(m => m.mac);
  const out = {};
  for (const mac of myMacs) out[mac] = state.box_throughput[mac] || null;
  res.json({ throughput: out });
});

// Per-device live throughput (5s cadence from box). Keeps a 12-sample (60s)
// ring per device for the PWA's "tap device → see live graph" view.
if (!state.device_throughput) state.device_throughput = {};   // box_mac → { device_mac: {rx_bps,tx_bps,ts,hist:[...]} }
app.post('/api/box/device-throughput', boxAuth, (req, res) => {
  const list = Array.isArray(req.body.devices) ? req.body.devices : [];
  const ts = parseInt(req.body.ts) || Date.now();
  const bucket = state.device_throughput[req.boxMac] = state.device_throughput[req.boxMac] || {};
  const cid = req.boxCustomerId;
  const period = (typeof currentPeriod === 'function') ? currentPeriod() : null;
  const day    = (typeof currentDay    === 'function') ? currentDay()    : null;
  // Tally per-device byte deltas into the monthly/daily usage maps. The agent
  // sends bytes_{rx,tx}_delta — the exact bytes counted by iptables since the
  // previous 5s sample, which is the ground truth for "this month" usage.
  // (Previously, only flow-based tallyFlow() incremented usage_monthly, but
  // the agent's flow capture had bytes_down hardcoded to 0, so usage never
  // grew. This path is the accurate one.)
  if (cid && period && !state.usage_monthly) state.usage_monthly = {};
  if (cid && day    && !state.usage_daily)   state.usage_daily   = {};
  if (cid && period) state.usage_monthly[cid] = state.usage_monthly[cid] || {};
  if (cid && day)    state.usage_daily[cid]   = state.usage_daily[cid]   || {};
  const monthMap = (cid && period) ? (state.usage_monthly[cid][period] = state.usage_monthly[cid][period] || {}) : null;
  const dayMap   = (cid && day)    ? (state.usage_daily[cid][day]      = state.usage_daily[cid][day]      || {}) : null;
  for (const d of list.slice(0, 500)) {
    const mac = (d.mac || '').toLowerCase();
    if (!/^[0-9a-f:]{17}$/.test(mac)) continue;
    const e = bucket[mac] = bucket[mac] || { hist: [] };
    e.rx_bps = Math.max(0, parseInt(d.rx_bps) || 0);
    e.tx_bps = Math.max(0, parseInt(d.tx_bps) || 0);
    e.ts = ts;
    e.ip = d.ip || e.ip;
    e.hist.push({ ts, rx: e.rx_bps, tx: e.tx_bps });
    if (e.hist.length > 12) e.hist.shift();
    const dnDelta = Math.max(0, parseInt(d.bytes_rx_delta) || 0);
    const upDelta = Math.max(0, parseInt(d.bytes_tx_delta) || 0);
    if (monthMap) {
      const u = monthMap[mac] = monthMap[mac] || { bytes_up: 0, bytes_down: 0 };
      u.bytes_up   += upDelta;
      u.bytes_down += dnDelta;
    }
    if (dayMap) {
      const u = dayMap[mac] = dayMap[mac] || { bytes_up: 0, bytes_down: 0 };
      u.bytes_up   += upDelta;
      u.bytes_down += dnDelta;
    }
  }
  if (cid && typeof customerSseEmit === 'function') {
    customerSseEmit(cid, 'device-throughput', { box_mac: req.boxMac, devices: list, ts });
  }
  res.json({ ok: true, accepted: list.length });
});
app.get('/api/customer/device-throughput/:mac', customerAuth, (req, res) => {
  const devMac = normalizeMac(req.params.mac);
  const myBoxes = Object.values(state.authorized_macs).filter(m => m.customer_id === req.customer.id).map(m => m.mac);
  for (const bmac of myBoxes) {
    const e = (state.device_throughput[bmac] || {})[devMac];
    if (e) return res.json({ mac: devMac, ...e });
  }
  res.json({ mac: devMac, rx_bps: 0, tx_bps: 0, hist: [] });
});

// Bulk variant — returns current rx/tx for ALL devices across the customer's
// boxes. PWA hits this on Devices tab open + every 5s as poll fallback for SSE.
app.get('/api/customer/device-throughput-all', customerAuth, (req, res) => {
  const myBoxes = Object.values(state.authorized_macs).filter(m => m.customer_id === req.customer.id).map(m => m.mac);
  const out = {};
  for (const bmac of myBoxes) {
    const bucket = state.device_throughput[bmac] || {};
    for (const [dmac, e] of Object.entries(bucket)) {
      // Most-recent box wins on duplicates (multi-box customers)
      if (!out[dmac] || (e.ts || 0) > (out[dmac].ts || 0)) {
        out[dmac] = { rx_bps: e.rx_bps || 0, tx_bps: e.tx_bps || 0, ts: e.ts || 0 };
      }
    }
  }
  res.json({ devices: out });
});

// POST /api/box/heartbeat — box reports vitals every 60s
app.post('/api/box/heartbeat', boxAuth, (req, res) => {
  const b = state.box_state[req.boxMac] = state.box_state[req.boxMac] || {};
  b.last_heartbeat = Date.now();
  b.public_ip      = req.headers['x-forwarded-for'] || req.ip;
  b.internal_ip    = req.body.internal_ip || b.internal_ip || null;
  b.version        = req.body.version || b.version || 'unknown';
  // Detect reboot — uptime_s decreased substantially since last heartbeat
  if (req.body.uptime_s !== undefined && b.uptime_s > 60 && req.body.uptime_s < b.uptime_s - 60) {
    if (!state.reboot_events) state.reboot_events = {};
    if (!state.reboot_events[req.boxMac]) state.reboot_events[req.boxMac] = [];
    state.reboot_events[req.boxMac].push({
      ts: Date.now(),
      planned: !!(state.box_commands && (state.box_commands[req.boxMac] || []).find(c => c.action === 'reboot' && c.completed_at && (Date.now() - c.completed_at) < 5 * 60_000)),
      previous_uptime_s: b.uptime_s,
    });
    if (state.reboot_events[req.boxMac].length > 200) state.reboot_events[req.boxMac].shift();
  }
  b.uptime_s       = req.body.uptime_s || 0;
  b.cpu_pct        = req.body.cpu_pct || 0;
  b.ram_pct        = req.body.ram_pct || 0;
  b.temp_c         = req.body.temp_c || null;
  b.device_count   = req.body.device_count || 0;
  if (req.body.hw && typeof req.body.hw === 'object') b.hw = req.body.hw;
  // Geofence: detect public-IP country change AND check against customer's allowlist.
  const newPublicIp = (req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim();
  if (newPublicIp && typeof geoCountryFor === 'function') {
    const newCountry = geoCountryFor(newPublicIp);
    if (b._last_country && newCountry && newCountry !== 'XX' && b._last_country !== newCountry && req.boxCustomerId) {
      fireSyntheticAlarm(req.boxCustomerId, req.boxMac, 'high', 'box_geofence',
        'Box moved to a new country',
        `Box ${req.boxMac} appears to have moved from ${b._last_country} to ${newCountry}. ` +
        `If this isn't expected, your box may have been stolen, relocated, or someone is spoofing its MAC.`);
    }
    b._last_country = newCountry;
    // Allowlist check: if customer set allowed_countries[] and current isn't in it → alarm.
    if (req.boxCustomerId && newCountry && newCountry !== 'XX') {
      const c = state.customers[req.boxCustomerId];
      const allowed = c && c.allowed_countries;
      if (Array.isArray(allowed) && allowed.length && !allowed.includes(newCountry)) {
        const dedup = `geofence_violation_${req.boxMac}_${newCountry}`;
        if (!state.anomaly_dedup[dedup] || (Date.now() - state.anomaly_dedup[dedup]) > 6 * 3600_000) {
          state.anomaly_dedup[dedup] = Date.now();
          fireSyntheticAlarm(req.boxCustomerId, req.boxMac, 'high', 'geofence_violation',
            `Box outside allowed countries (${newCountry})`,
            `Box ${req.boxMac} is reporting from ${newCountry}, which is not in your allowlist [${allowed.join(', ')}]. ` +
            `Possible theft/relocation. Review and reset allowlist if intentional.`);
        }
      }
    }
  }

  // Capture heartbeat timestamp for uptime calc — keep only last 30 days
  if (!state.heartbeat_history) state.heartbeat_history = {};
  if (!state.heartbeat_history[req.boxMac]) state.heartbeat_history[req.boxMac] = [];
  state.heartbeat_history[req.boxMac].push(Date.now());
  // Sample only every 5 minutes worth of heartbeats (keep ~30 days of 5-min samples = 8640 entries)
  if (state.heartbeat_history[req.boxMac].length > 9000) {
    const cutoff = Date.now() - 30 * 24 * 3600_000;
    state.heartbeat_history[req.boxMac] = state.heartbeat_history[req.boxMac].filter(t => t >= cutoff);
  }
  // Update DDNS for the customer (if a slug is configured)
  if (req.boxCustomerId) {
    for (const d of Object.values(state.ddns)) {
      if (d.customer_id === req.boxCustomerId) {
        d.current_ip = b.public_ip;
        d.last_update = Date.now();
      }
    }
  }
  // Log only every 10th heartbeat to avoid spam
  if (Math.random() < 0.1) console.log(`         💓 HEARTBEAT ${req.boxMac} v${b.version} dev=${b.device_count}`);
  res.json({ ok: true, ts: Date.now() });
});

// POST /api/box/flows — box uploads a batch of flow records (capped ring buffer)
app.post('/api/box/flows', boxAuth, (req, res) => {
  const flows = Array.isArray(req.body.flows) ? req.body.flows : [];
  const now = Date.now();
  const c = req.boxCustomerId ? state.customers[req.boxCustomerId] : null;
  // Privacy mode: customer opted out of cloud-side flow logging entirely.
  // We still tally rule hits + quotas (aggregates only) so policy + billing keep working,
  // but raw flow records and live SSE streams are skipped.
  const privacy = !!(c && c.privacy_mode);
  for (const f of flows.slice(0, 1000)) {
    const enriched = {
      ts: f.ts || now,
      box_mac: req.boxMac,
      customer_id: req.boxCustomerId,
      src_mac: normalizeMac(f.src_mac || ''),
      src_ip:  f.src_ip  || '',
      dst_ip:  f.dst_ip  || '',
      dst_port: f.dst_port || 0,
      dst_domain: f.dst_domain || '',
      proto: f.proto || 'tcp',
      bytes_up: f.bytes_up || 0,
      bytes_down: f.bytes_down || 0,
      blocked: !!f.blocked,
      category: f.category || categoryForDomain(f.dst_domain),
      country: f.country || (typeof geoCountryFor === 'function' ? geoCountryFor(f.dst_ip) : null),
    };
    if (!privacy) state.flows.push(enriched);
    // Tier-1 long-term archive (90d retention). Skip when privacy mode is on.
    if (!privacy && req.boxCustomerId && typeof appendFlowToArchive === 'function') {
      appendFlowToArchive(req.boxCustomerId, enriched);
    }
    if (typeof tallyFlow === 'function') tallyFlow(enriched);
    if (typeof tallyTimeBank === 'function') tallyTimeBank(enriched);
    if (enriched.blocked && req.boxCustomerId) tallyRuleHits(req.boxCustomerId, enriched);
    // Behavior baselining + Active Protect + app-DPI identification
    if (cloudBehaviorBaseline && cloudBehaviorBaseline.ingest) {
      try { cloudBehaviorBaseline.ingest(enriched); } catch {}
    }
    if (cloudActiveProtect && cloudActiveProtect.ingestFlow && req.boxCustomerId) {
      try {
        const r = cloudActiveProtect.ingestFlow(enriched);
        if (r && r.action === 'deny') {
          // Mark this flow as blocked-by-active-protect (after the fact for visibility)
          enriched.blocked = true;
          enriched.matched_by = 'active-protect:' + (r.matched || 'unknown');
        }
      } catch {}
    }
    if (!privacy) {
      if (typeof broadcastSSE === 'function') broadcastSSE('flow', enriched);
      if (req.boxCustomerId && typeof customerSseEmit === 'function') customerSseEmit(req.boxCustomerId, 'flow', enriched);
    }
    // Tier-3 Feature B: optionally forward each enriched flow to the
    // customer's SIEM. Default OFF — volume is huge — only fires when the
    // customer flipped forward_flows: true in the SIEM config.
    try {
      if (!privacy && req.boxCustomerId && typeof cloudSiemForwarder !== 'undefined' && cloudSiemForwarder) {
        cloudSiemForwarder.forward(req.boxCustomerId, { type: 'flow', ...enriched }).catch(()=>{});
      }
    } catch {}
  }
  if (state.flows.length > FLOWS_MAX) {
    state.flows.splice(0, state.flows.length - FLOWS_MAX);
  }
  res.json({ ok: true, accepted: flows.length, privacy_mode: privacy });
});

function categoryForDomain(domain) {
  if (!domain) return null;
  const d = domain.toLowerCase();
  // Admin overrides win over the auto-categorizer.
  if (state.category_overrides && state.category_overrides[d]) {
    return state.category_overrides[d];
  }
  for (const [catKey, cat] of Object.entries(state.app_categories || {})) {
    for (const dom of (cat.domains || [])) {
      if (d === dom || d.endsWith('.' + dom)) return catKey;
    }
  }
  return null;
}

// Admin: domain → category overrides
if (!state.category_overrides) state.category_overrides = {};   // { 'foo.com': 'social' }
app.get('/admin/api/category-overrides', adminAuth, (req, res) => {
  res.json({ overrides: state.category_overrides });
});
app.post('/admin/api/category-overrides/set', adminAuth, (req, res) => {
  const dom = String(req.body.domain || '').toLowerCase().trim();
  const cat = String(req.body.category || '').toLowerCase().trim();
  if (!/^[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}$/.test(dom)) return res.status(400).json({ error: 'invalid domain' });
  if (!state.app_categories[cat]) return res.status(400).json({ error: 'unknown category', allowed: Object.keys(state.app_categories) });
  state.category_overrides[dom] = cat;
  saveState();
  if (typeof logAdminAction === 'function') logAdminAction(req, 'category_override.set', dom, cat);
  res.json({ ok: true, domain: dom, category: cat });
});
app.post('/admin/api/category-overrides/delete', adminAuth, (req, res) => {
  const dom = String(req.body.domain || '').toLowerCase().trim();
  if (!state.category_overrides[dom]) return res.status(404).json({ error: 'not found' });
  delete state.category_overrides[dom];
  saveState();
  if (typeof logAdminAction === 'function') logAdminAction(req, 'category_override.delete', dom);
  res.json({ ok: true });
});

// POST /api/box/devices — box reports the devices it sees on the LAN
app.post('/api/box/devices', boxAuth, (req, res) => {
  const devices = Array.isArray(req.body.devices) ? req.body.devices : [];
  const bucket = state.box_devices[req.boxMac] = state.box_devices[req.boxMac] || {};
  const now = Date.now();
  const cid = req.boxCustomerId;
  const c = cid ? state.customers[cid] : null;
  const cap = c ? planDeviceCap(c) : -1;
  for (const d of devices.slice(0, 500)) {
    const mac = normalizeMac(d.mac || '');
    if (!mac) continue;
    const existing = bucket[mac];
    const vendor = d.vendor || (existing && existing.vendor) || ouiVendor(mac);
    const hostname = d.hostname || (existing && existing.hostname) || '';
    const dhcpFp = d.dhcp_fp || (existing && existing.dhcp_fp) || '';
    const cls = classifyDevice(mac, hostname, vendor, dhcpFp);
    bucket[mac] = {
      mac,
      ip: d.ip || (existing && existing.ip) || '',
      hostname,
      vendor,
      dhcp_fp: dhcpFp,
      device_type: cls.type,
      device_icon: cls.icon,
      device_label: cls.label || (existing && existing.device_label) || null,
      first_seen: (existing && existing.first_seen) || now,
      last_seen: now,
      blocked: !!d.blocked,
      online: d.online !== false,
    };
  }
  // Plan device-cap enforcement: alarm if over.
  if (cap > 0) {
    const total = Object.keys(bucket).length;
    if (total > cap) {
      const dedup = `device_cap_${cid}_${cap}`;
      if (!state.anomaly_dedup[dedup] || (now - state.anomaly_dedup[dedup]) > 24 * 3600_000) {
        state.anomaly_dedup[dedup] = now;
        if (typeof fireSyntheticAlarm === 'function') {
          fireSyntheticAlarm(cid, req.boxMac, 'medium', 'plan_device_cap',
            `${total} devices exceed your plan limit (${cap})`,
            `Your "${c.plan}" plan covers ${cap} devices. The box is currently seeing ${total}. ` +
            `Upgrade plan or remove unused devices to avoid service degradation.`);
        }
      }
    }
  }
  res.json({ ok: true, accepted: devices.length, plan_cap: cap, total_devices: Object.keys(bucket).length });
});

// Plan device caps. -1 = unlimited.
function planDeviceCapRaw(plan) {
  return ({ basic: 5, family: 20, pro: 50, business: -1 })[plan] ?? 20;
}
// Honors 30-day downgrade grace: returns the higher (previous) cap during grace.
function planDeviceCap(planOrCustomer) {
  if (typeof planOrCustomer === 'string') return planDeviceCapRaw(planOrCustomer);
  const c = planOrCustomer;
  if (!c) return 20;
  const current = planDeviceCapRaw(c.plan);
  if (c.downgrade_grace_until && c.downgrade_grace_until > Date.now() && c.downgrade_from_plan) {
    const previous = planDeviceCapRaw(c.downgrade_from_plan);
    if (previous === -1) return -1;
    if (previous > current) return previous;
  }
  return current;
}

// POST /api/box/alarms — box reports detected alarm (intrusion, new device, etc.)
app.post('/api/box/alarms', boxAuth, (req, res) => {
  const a = {
    id: shortId(16),
    ts: Date.now(),
    customer_id: req.boxCustomerId,
    box_mac: req.boxMac,
    severity: ['low','medium','high','critical'].includes(req.body.severity) ? req.body.severity : 'medium',
    kind: String(req.body.kind || 'unknown').slice(0, 40),
    title: String(req.body.title || '').slice(0, 200),
    body: String(req.body.body || '').slice(0, 1000),
    device_mac: normalizeMac(req.body.device_mac || ''),
    acked: false,
  };
  state.alarms.unshift(a);
  if (state.alarms.length > 5000) state.alarms.length = 5000;
  // Notify the customer
  if (req.boxCustomerId) {
    pushNotification(req.boxCustomerId, 'security', a.title || 'Security alert', a.body);
    if (typeof customerSseEmit === 'function') customerSseEmit(req.boxCustomerId, 'alarm', a);
  }
  if (typeof broadcastSSE === 'function') broadcastSSE('alarm', a);
  fireWebhooks('alarm.created', { id: a.id, customer_id: a.customer_id, severity: a.severity, kind: a.kind, title: a.title });
  console.log(`         🚨 ALARM ${a.severity.toUpperCase()} ${req.boxMac} ${a.kind}: ${a.title}`);
  saveState();
  res.json({ ok: true, id: a.id });
});

// GET /api/box/policy/:mac — box pulls effective policy bundle
app.get('/api/box/policy/:mac', (req, res) => {
  const mac = normalizeMac(req.params.mac);
  const m = state.authorized_macs[mac];
  if (!m) return res.status(404).json({ error: 'unknown_box' });
  const cust_id = m.customer_id;
  const c = cust_id ? state.customers[cust_id] : null;

  // Build effective rules (customer-scoped + device-scoped)
  const rules = (cust_id && state.rules[cust_id]) || [];
  const enabled = rules.filter(r => r.enabled !== false && !(r.expires_at && r.expires_at < Date.now()));

  // Resolve category rules → expand domains
  // Tier-1 Smart Block: domain rules may carry pattern_type:
  //   'exact' (default)  → exact match (blocked_domains)
  //   'suffix'           → match domain + subdomains (blocked_domain_patterns + '*.value')
  //   'prefix'           → match labels starting with value
  //   'contains'         → match anything containing value
  //   'sni-prefix'       → match by TLS SNI; rendered into blocked_sni_patterns for the box
  const blocked_domains = new Set();
  const blocked_domain_patterns = [];   // each {pattern_type, value} -> rendered by agent
  const blocked_sni_patterns = [];      // {pattern_type, value, action:'block'} -> sni-parser
  const blocked_categories = new Set();
  for (const r of enabled) {
    if (r.action !== 'block') continue;
    if (r.type === 'domain') {
      const pt = r.pattern_type || 'exact';
      if (pt === 'exact') {
        blocked_domains.add(r.value);
      } else if (pt === 'sni-prefix') {
        blocked_sni_patterns.push({ pattern_type: pt, value: r.value, action: 'block' });
      } else if (['suffix','prefix','contains'].includes(pt)) {
        blocked_domain_patterns.push({ pattern_type: pt, value: r.value });
      } else {
        blocked_domains.add(r.value);
      }
    }
    if (r.type === 'category') {
      blocked_categories.add(r.value);
      const cat = state.app_categories[r.value];
      if (cat) for (const d of (cat.domains || [])) blocked_domains.add(d);
    }
  }
  // Merge per-customer custom blocklist domains
  if (cust_id && state.customer_blocklist_domains && state.customer_blocklist_domains[cust_id]) {
    for (const d of state.customer_blocklist_domains[cust_id]) blocked_domains.add(d);
  }

  // Safe Search overrides (CNAMEs the box should rewrite).
  // Tier-1: activated either by the legacy 'adult' category block OR by any
  // family member with safe_search:true. dnsmasq can only do this globally,
  // so we light it up box-wide when ANY kid needs it (documented in PWA).
  const _famForSafe = (cust_id && state.family_members[cust_id]) || [];
  const _anyMemberSafe = _famForSafe.some(m => m.safe_search === true);
  const safe_search = (enabled.some(r => r.type === 'category' && r.value === 'adult' && r.action === 'block') || _anyMemberSafe)
    ? SAFE_SEARCH_OVERRIDES : {};

  // Active schedules
  const schedules = (cust_id && state.schedules[cust_id]) || [];

  // Pause state (whole-network or per-device)
  const pause = (c && c.pause_until && c.pause_until > Date.now()) ? { until: c.pause_until } : null;

  // Quotas — devices that have hit their cap → block
  const period = currentPeriod();
  const quotas = (cust_id && state.quotas[cust_id]) || [];
  const usage  = ((cust_id && state.usage_monthly[cust_id]) || {})[period] || {};
  const quota_blocked = [];
  for (const q of quotas) {
    const u = usage[q.device_mac] || { bytes_up: 0, bytes_down: 0 };
    const used_gb = (u.bytes_up + u.bytes_down) / (1024 ** 3);
    if (used_gb >= q.monthly_gb) quota_blocked.push(q.device_mac);
  }
  // Time bank — devices over today's minute budget (incl. parent-granted bonus
  // and Tier-2 Feature D rolled-over minutes) → block
  if (cust_id) {
    timeBankResetIfNew(cust_id);
    for (const e of (state.time_bank[cust_id] || [])) {
      const bonus  = e.bonus_minutes_today || 0;
      const rolled = e.rolled_minutes_today || 0;
      if (e.used_minutes >= (e.daily_minutes + bonus + rolled)) quota_blocked.push(e.device_mac);
    }
  }
  // MAC-type block rules (created when customer taps "Block device" in PWA).
  // The same nftables quota_blocked_macs set handles all device-MAC drops.
  for (const r of enabled) {
    if (r.action === 'block' && r.type === 'mac' && r.value) {
      const mac_norm = normalizeMac(r.value);
      if (mac_norm) quota_blocked.push(mac_norm);
    }
  }
  // Per-device blocked flag (set by /api/customer/block-device). Each customer
  // device with .blocked === true goes into quota_blocked too.
  for (const dmac of Object.keys(state.box_devices[mac] || {})) {
    const d = state.box_devices[mac][dmac];
    if (d && d.blocked === true) quota_blocked.push(dmac);
  }
  // Pause Internet: force every device on this box into quota_blocked until
  // pause_until elapses. The agent's NFT quota_blocked_macs set then drops
  // all forwarded traffic from those MACs.
  if (pause) {
    for (const dmac of Object.keys(state.box_devices[mac] || {})) {
      quota_blocked.push(dmac);
    }
  }
  // Tier-2 Feature C — Selective family pause. When active, push every device
  // on the box into quota_blocked EXCEPT those whose MAC is exempted or whose
  // owner family member is in exclude_member_ids. Cancels itself once `until`
  // elapses (next policy fetch).
  let selective_pause = null;
  if (cust_id && c && selectivePauseActive(c)) {
    const exempted = selectivePauseExpandExcluded(cust_id);
    for (const dmac of Object.keys(state.box_devices[mac] || {})) {
      if (!exempted.has(dmac.toLowerCase())) quota_blocked.push(dmac);
    }
    selective_pause = {
      active: true,
      until: c.selective_pause.until,
      exempted_count: exempted.size,
      reason: c.selective_pause.reason || '',
    };
  }

  // Geo-blocking (collect from rules)
  const geo_block = enabled.filter(r => r.type === 'geo' && r.action === 'block').map(r => String(r.value || '').toUpperCase());

  // Custom IP-block rules → blocked_ips (Fix 5). Only IPv4 dotted-quad accepted.
  const custom_blocked_ips = [];
  for (const r of enabled) {
    if (r.action !== 'block' || r.type !== 'ip') continue;
    if (/^\d+\.\d+\.\d+\.\d+$/.test(r.value)) custom_blocked_ips.push(r.value);
  }

  // Geo-block expansion (Fix 6). The box has no GeoIP DB, so the cloud expands
  // each country code to its CIDR list using the dbip-country DB already loaded
  // for telemetry. Capped to GEO_BLOCK_CIDR_CAP CIDRs per bundle to keep the
  // policy payload small and the nft set update fast.
  const geo_cidrs = [];
  if (geo_block.length && typeof rangesForCountry === 'function') {
    for (const cc of geo_block) {
      for (const cidr of rangesForCountry(cc)) {
        geo_cidrs.push(cidr);
        if (geo_cidrs.length >= GEO_BLOCK_CIDR_CAP) break;
      }
      if (geo_cidrs.length >= GEO_BLOCK_CIDR_CAP) break;
    }
  }

  // Expand schedule family_ids → current device MACs for that family member
  const fam = (cust_id && state.family_members[cust_id]) || [];
  const enabledSchedules = schedules.filter(s => s.enabled !== false).map(s => {
    const expanded_macs = new Set((s.device_macs || []).map(normalizeMac).filter(Boolean));
    for (const fid of (s.family_ids || [])) {
      const m = fam.find(x => x.id === fid);
      if (m) for (const mac of (m.device_macs || [])) expanded_macs.add(normalizeMac(mac));
    }
    return { ...s, effective_macs: Array.from(expanded_macs) };
  });

  // Tier-1 Feature A: per-device DNS upstream map (mac → resolver IP).
  // Walk every family member and, if they have a dns_upstream preset/custom,
  // emit (mac → resolved IP) for each of their devices.
  const per_device_dns_upstream = {};
  const per_device_safe_search  = {};
  for (const m of fam) {
    const ip = resolveDnsUpstream(m.dns_upstream);
    const wantsSafe = m.safe_search === true;
    if (!ip && !wantsSafe) continue;
    for (const dmacRaw of (m.device_macs || [])) {
      const dmac = normalizeMac(dmacRaw);
      if (!dmac) continue;
      if (ip) per_device_dns_upstream[dmac] = ip;
      if (wantsSafe) per_device_safe_search[dmac] = true;
    }
  }

  // Etag for change detection
  const bundle = { mac, customer_id: cust_id, plan: c ? c.plan : null,
    plan_device_cap: c ? planDeviceCap(c) : -1,
    latency_probes: (cust_id && state.latency_probes && state.latency_probes[cust_id] && state.latency_probes[cust_id].targets) || [],
    device_groups: (cust_id && state.device_groups[cust_id]) || [],
    blocked_domains: Array.from(blocked_domains),
    blocked_domain_patterns,             // Tier-1 Smart Block: {pattern_type, value}
    blocked_sni_patterns,                // Tier-1 Smart Block: SNI-based blocking
    blocked_categories: Array.from(blocked_categories),
    blocked_ips: [
      ...(blocked_categories.has('malware') ? (state.threat_feeds.ips || []) : []),
      ...(state.global_ip_bans || []),   // admin-maintained global ban list
      ...custom_blocked_ips,             // Fix 5: per-customer `type:"ip"` rules
      ...geo_cidrs,                      // Fix 6: country → CIDRs from dbip DB
      // Tier-3 Feature A: community threat intel (CrowdSec-style, pull-only).
      // Opt-in (default true for new customers). Domains are merged separately
      // below (cap-aware) so the bundle doesn't ship 1M entries.
      ...((c && c.community_intel_enabled !== false && cloudCommunityIntel)
            ? cloudCommunityIntel.getIpsArray() : []),
    ],
    rules: enabled,
    schedules: enabledSchedules,
    pause,
    safe_search,
    per_device_dns_upstream,             // Tier-1 Feature A: mac → upstream IP
    per_device_safe_search,               // Tier-1 Feature B: mac → true (informational)
    quota_blocked,
    geo_block,
    port_forwards: (cust_id && state.port_forwards[cust_id]) || [],
    dhcp_leases:   (cust_id && state.dhcp_leases[cust_id])   || [],
    dns_upstreams: (cust_id && state.dns_upstreams[cust_id]) || [],
    dns_records:   (cust_id && state.dns_records[cust_id])   || [],
    qos_rules:     (cust_id && state.qos_rules[cust_id])     || [],
    vlans:         (cust_id && state.vlans[cust_id])         || [],
    guest_wifi:    (cust_id && state.guest_wifi[cust_id])    || { enabled: false },
    vpn_routed_macs: (cust_id && state.vpn_routed_macs[cust_id]) || [],
    s2s_tunnels:   ((cust_id && state.s2s_tunnels[cust_id]) || []).filter(t =>
      t.box_a_mac === mac || t.box_b_mac === mac
    ).map(t => {
      // Box only sees its own keys + the peer's pubkey + endpoint
      const isA = t.box_a_mac === mac;
      const peerMac = isA ? t.box_b_mac : t.box_a_mac;
      const peerState = state.box_state[peerMac] || {};
      return {
        id: t.id, name: t.name,
        my_priv: isA ? t.key_a_priv : t.key_b_priv,
        my_addr: isA ? t.tunnel_ip_a : t.tunnel_ip_b,
        peer_pub: isA ? t.key_b_pub : t.key_a_pub,
        peer_endpoint: peerState.public_ip ? peerState.public_ip + ':' + t.listen_port : null,
        peer_subnet: isA ? t.subnet_b : t.subnet_a,
        listen_port: t.listen_port,
      };
    }),
    vacation_mode: (c && c.vacation_active && c.vacation_until > Date.now())
      ? { active: true, until: c.vacation_until,
          // While on vacation, force-block social, video, and adult categories
          extra_blocked_categories: ['social', 'video', 'adult'] }
      : { active: false },
    auto_quarantine: !!(c && c.auto_quarantine),
    selective_pause,
  };
  // Apply vacation extras to blocked sets
  if (bundle.vacation_mode.active) {
    for (const catKey of bundle.vacation_mode.extra_blocked_categories) {
      bundle.blocked_categories.push(catKey);
      const cat = state.app_categories[catKey];
      if (cat) for (const d of (cat.domains || [])) bundle.blocked_domains.push(d);
    }
    // Dedupe
    bundle.blocked_categories = Array.from(new Set(bundle.blocked_categories));
    bundle.blocked_domains = Array.from(new Set(bundle.blocked_domains));
  }
  // Tier-3 Feature A: append community-intel domains (cap 50k by recency).
  // We dedupe by Set + cap; the IP list is already injected up in `blocked_ips`.
  if (c && c.community_intel_enabled !== false && cloudCommunityIntel) {
    const ciDomains = cloudCommunityIntel.getDomainsArray(50000);
    if (ciDomains.length) {
      const merged = new Set(bundle.blocked_domains);
      for (const d of ciDomains) merged.add(d);
      bundle.blocked_domains = Array.from(merged);
    }
  }
  // Include global policy version in the etag so a fleet-wide bump forces re-sync everywhere
  const etag = crypto.createHash('sha256')
    .update(JSON.stringify(bundle) + ':' + (state._policy_global_version || 0))
    .digest('hex').slice(0, 16);
  res.set('ETag', etag);
  if (req.headers['if-none-match'] === etag) return res.status(304).end();
  res.json({ ...bundle, etag, generated_at: Date.now() });
});

// ───── App categories (admin can edit defaults; customers can list)
app.get('/admin/api/categories', adminAuth, (req, res) => {
  res.json({ categories: state.app_categories });
});
app.post('/admin/api/categories/:key', adminAuth, (req, res) => {
  const key = req.params.key;
  const cat = state.app_categories[key];
  if (!cat) return res.status(404).json({ error: 'unknown_category' });
  if (cat.locked) return res.status(403).json({ error: 'category_is_locked' });
  if (Array.isArray(req.body.domains)) {
    cat.domains = req.body.domains.map(d => String(d).toLowerCase().trim()).filter(Boolean);
  }
  if (req.body.name) cat.name = String(req.body.name).slice(0, 80);
  if (req.body.icon) cat.icon = String(req.body.icon).slice(0, 4);
  saveState();
  logAdminAction(req, 'category.update', key, `domains=${cat.domains.length}`);
  res.json({ ok: true, category: cat });
});
app.get('/api/customer/categories', customerAuth, (req, res) => {
  // Customer just sees the category catalog (without locked categories' domain lists for security)
  const out = {};
  for (const [k, v] of Object.entries(state.app_categories)) {
    out[k] = { name: v.name, icon: v.icon, domain_count: (v.domains || []).length, locked: !!v.locked };
  }
  res.json({ categories: out });
});

// ───── Rule engine (customer-facing)
app.get('/api/customer/rules', customerAuth, (req, res) => {
  res.json({ rules: state.rules[req.customer.id] || [] });
});
// Rule revision history
if (!state.rule_history) state.rule_history = {};   // { customer_id: [ {ts, op, rule_id, before, after, actor} ] }
function recordRuleHistory(customer_id, op, rule_id, before, after, actor) {
  if (!state.rule_history[customer_id]) state.rule_history[customer_id] = [];
  state.rule_history[customer_id].push({ ts: Date.now(), op, rule_id, before, after, actor: actor || 'customer' });
  if (state.rule_history[customer_id].length > 500) state.rule_history[customer_id].shift();
}

// What's-new changelog — admin curates entries; customer sees unread badge.
if (!state.changelog) state.changelog = [];   // [{id, version, title, body, type, created_at}]
app.get('/api/customer/changelog', customerAuth, (req, res) => {
  const c = req.customer;
  const lastSeen = c.changelog_last_seen_id || null;
  const items = state.changelog.slice(0, 50);
  let unread = 0;
  for (const e of items) {
    if (e.id === lastSeen) break;
    unread++;
  }
  res.json({ items, unread, last_seen_id: lastSeen });
});
app.post('/api/customer/changelog/mark-seen', customerAuth, (req, res) => {
  const c = state.customers[req.customer.id];
  c.changelog_last_seen_id = (state.changelog[0] && state.changelog[0].id) || null;
  saveState();
  res.json({ ok: true });
});
app.get('/admin/api/changelog', adminAuth, (req, res) => {
  res.json({ items: state.changelog });
});
app.post('/admin/api/changelog/add', adminAuth, (req, res) => {
  const title = String(req.body.title || '').trim().slice(0, 120);
  const body  = String(req.body.body || '').trim().slice(0, 5000);
  const type  = ['feature','fix','breaking','notice'].includes(req.body.type) ? req.body.type : 'feature';
  const version = String(req.body.version || '').slice(0, 20);
  if (!title) return res.status(400).json({ error: 'title required' });
  const entry = {
    id: 'cl-' + shortId(10),
    version, title, body, type,
    created_at: Date.now(),
    created_by: req.adminUser || 'admin',
  };
  state.changelog.unshift(entry);
  if (state.changelog.length > 200) state.changelog.length = 200;
  saveState();
  if (typeof logAdminAction === 'function') logAdminAction(req, 'changelog.add', entry.id, title);
  res.json({ ok: true, entry });
});
app.post('/admin/api/changelog/delete', adminAuth, (req, res) => {
  const i = state.changelog.findIndex(e => e.id === req.body.id);
  if (i < 0) return res.status(404).json({ error: 'not found' });
  state.changelog.splice(i, 1);
  saveState();
  res.json({ ok: true });
});

// Detect contradicting rules: same (type, value, scope, target) with opposite action.
function detectRuleConflicts(rules) {
  const conflicts = [];
  const byKey = {};
  for (const r of rules) {
    if (r.enabled === false) continue;
    const key = `${r.type}|${r.value}|${r.scope || 'all'}|${r.target || ''}`;
    if (!byKey[key]) byKey[key] = [];
    byKey[key].push(r);
  }
  for (const [key, list] of Object.entries(byKey)) {
    if (list.length < 2) continue;
    const actions = new Set(list.map(r => r.action));
    if (actions.has('block') && actions.has('allow')) {
      conflicts.push({
        key,
        type: list[0].type,
        value: list[0].value,
        scope: list[0].scope,
        target: list[0].target,
        rule_ids: list.map(r => r.id),
        actions: list.map(r => ({ id: r.id, action: r.action })),
      });
    }
  }
  return conflicts;
}
app.get('/api/customer/rules/conflicts', customerAuth, (req, res) => {
  const rules = state.rules[req.customer.id] || [];
  res.json({ conflicts: detectRuleConflicts(rules) });
});

// Preview: simulate a candidate rule against the customer's last 100 flows.
app.post('/api/customer/rules/preview', customerAuth, (req, res) => {
  const cid = req.customer.id;
  const type = String(req.body.type || '').toLowerCase();
  const value = String(req.body.value || '').toLowerCase();
  if (!['domain','category','ip','geo'].includes(type)) return res.status(400).json({ error: 'invalid type' });
  if (!value) return res.status(400).json({ error: 'value required' });
  const recent = state.flows.filter(f => f.customer_id === cid).slice(-1000);
  const matches = [];
  for (const f of recent) {
    let hit = false;
    if (type === 'domain') {
      const d = (f.dst_domain || '').toLowerCase();
      if (d && (d === value || d.endsWith('.' + value))) hit = true;
    } else if (type === 'category') {
      if ((f.category || '').toLowerCase() === value) hit = true;
    } else if (type === 'ip') {
      if (f.dst_ip === value) hit = true;
    } else if (type === 'geo') {
      if ((f.country || '').toUpperCase() === value.toUpperCase()) hit = true;
    }
    if (hit) matches.push({ ts: f.ts, src_mac: f.src_mac, dst_domain: f.dst_domain, dst_ip: f.dst_ip, category: f.category, country: f.country, bytes: (f.bytes_up || 0) + (f.bytes_down || 0) });
  }
  res.json({
    flows_examined: recent.length,
    would_match: matches.length,
    sample: matches.slice(-25).reverse(),
    distinct_devices: new Set(matches.map(m => m.src_mac)).size,
  });
});

// Pre-made rule bundles. Customer applies one with /api/customer/rules/apply-preset.
const RULE_PRESETS = {
  kids: {
    label: 'Kids mode',
    description: 'Block adult content + social media + gambling.',
    rules: [
      { type: 'category', value: 'adult', action: 'block' },
      { type: 'category', value: 'social', action: 'block' },
      { type: 'category', value: 'gambling', action: 'block' },
    ],
  },
  privacy: {
    label: 'Privacy Pro',
    description: 'Block ads, trackers, telemetry.',
    rules: [
      { type: 'category', value: 'ads', action: 'block' },
      { type: 'category', value: 'trackers', action: 'block' },
      { type: 'category', value: 'telemetry', action: 'block' },
    ],
  },
  work_focus: {
    label: 'Work focus',
    description: 'Block social, video, and games during work hours.',
    rules: [
      { type: 'category', value: 'social', action: 'block' },
      { type: 'category', value: 'video', action: 'block' },
      { type: 'category', value: 'gaming', action: 'block' },
    ],
  },
  security_max: {
    label: 'Security max',
    description: 'Block malware, phishing, crypto-mining sources.',
    rules: [
      { type: 'category', value: 'malware', action: 'block' },
      { type: 'category', value: 'phishing', action: 'block' },
      { type: 'category', value: 'crypto', action: 'block' },
    ],
  },
};
app.get('/api/customer/rule-presets', customerAuth, (req, res) => {
  // Filter to only presets whose categories actually exist.
  const out = {};
  for (const [key, p] of Object.entries(RULE_PRESETS)) {
    out[key] = {
      ...p,
      rules: p.rules.filter(r => r.type !== 'category' || (state.app_categories && state.app_categories[r.value])),
    };
  }
  res.json({ presets: out });
});
app.post('/api/customer/rules/apply-preset', customerAuth, (req, res) => {
  const c = req.customer;
  const key = String(req.body.preset || '').toLowerCase();
  const preset = RULE_PRESETS[key];
  if (!preset) return res.status(400).json({ error: 'unknown preset', allowed: Object.keys(RULE_PRESETS) });
  if (!state.rules[c.id]) state.rules[c.id] = [];
  const added = [];
  for (const tpl of preset.rules) {
    if (tpl.type === 'category' && !(state.app_categories && state.app_categories[tpl.value])) continue;
    // Skip if same rule already exists
    if ((state.rules[c.id] || []).some(r => r.type === tpl.type && r.value === tpl.value && r.action === tpl.action)) continue;
    const r = {
      id: shortId(12),
      scope: 'all',
      target: '',
      type: tpl.type,
      value: tpl.value,
      action: tpl.action,
      enabled: true,
      note: `from preset: ${preset.label}`,
      preset_key: key,
      created_at: Date.now(),
    };
    state.rules[c.id].push(r);
    if (typeof recordRuleHistory === 'function') recordRuleHistory(c.id, 'add', r.id, null, r);
    added.push(r);
  }
  saveState();
  if (typeof pushNotification === 'function') {
    pushNotification(c.id, 'system', `🎯 Preset applied: ${preset.label}`,
      `Added ${added.length} rule(s). Review and tweak in the Rules tab.`);
  }
  res.json({ ok: true, preset: key, added });
});

app.post('/api/customer/rules/add', customerAuth, (req, res) => {
  const c = req.customer;
  const VALID_PATTERN_TYPES = ['exact','suffix','prefix','contains','sni-prefix'];
  const r = {
    id: shortId(12),
    scope: ['all','device','family','tag'].includes(req.body.scope) ? req.body.scope : 'all',
    target: String(req.body.target || '').slice(0, 80),  // mac/family_id/tag depending on scope
    type: ['category','domain','ip','geo','mac'].includes(req.body.type) ? req.body.type : 'domain',
    value: String(req.body.value || '').toLowerCase().slice(0, 200),
    action: ['block','allow'].includes(req.body.action) ? req.body.action : 'block',
    enabled: req.body.enabled !== false,
    note: String(req.body.note || '').slice(0, 200),
    expires_at: req.body.expires_at ? Number(req.body.expires_at) : null,
    // Tier-1 Smart Block: only meaningful for type=domain (others get default 'exact').
    pattern_type: VALID_PATTERN_TYPES.includes(req.body.pattern_type) ? req.body.pattern_type : 'exact',
    created_at: Date.now(),
  };
  if (!r.value) return res.status(400).json({ error: 'value required' });
  if (r.expires_at && (isNaN(r.expires_at) || r.expires_at < Date.now())) return res.status(400).json({ error: 'expires_at must be a future timestamp (ms)' });
  if (!state.rules[c.id]) state.rules[c.id] = [];
  state.rules[c.id].push(r);
  recordRuleHistory(c.id, 'add', r.id, null, r);
  saveState();
  pushNotification(c.id, 'system', 'Rule added', `${r.action} ${r.type}:${r.value}`);
  // Surface any new conflict the addition introduces.
  const conflicts = detectRuleConflicts(state.rules[c.id]).filter(cf => cf.rule_ids.includes(r.id));
  res.json({ ok: true, rule: r, conflicts: conflicts.length ? conflicts : undefined });
});
app.post('/api/customer/rules/update', customerAuth, (req, res) => {
  const list = state.rules[req.customer.id] || [];
  const r = list.find(x => x.id === req.body.id);
  if (!r) return res.status(404).json({ error: 'not found' });
  const before = { ...r };
  if (typeof req.body.enabled === 'boolean') r.enabled = req.body.enabled;
  if (req.body.value) r.value = String(req.body.value).toLowerCase().slice(0, 200);
  if (req.body.action && ['block','allow'].includes(req.body.action)) r.action = req.body.action;
  if (req.body.note !== undefined) r.note = String(req.body.note).slice(0, 200);
  if (req.body.expires_at !== undefined) {
    if (req.body.expires_at === null) r.expires_at = null;
    else {
      const v = Number(req.body.expires_at);
      if (isNaN(v)) return res.status(400).json({ error: 'expires_at must be number or null' });
      r.expires_at = v;
    }
  }
  recordRuleHistory(req.customer.id, 'update', r.id, before, { ...r });
  saveState();
  res.json({ ok: true, rule: r });
});
app.post('/api/customer/rules/delete', customerAuth, (req, res) => {
  const list = state.rules[req.customer.id] || [];
  const i = list.findIndex(x => x.id === req.body.id);
  if (i < 0) return res.status(404).json({ error: 'not found' });
  const removed = list[i];
  list.splice(i, 1);
  recordRuleHistory(req.customer.id, 'delete', removed.id, removed, null);
  saveState();
  res.json({ ok: true });
});

app.get('/api/customer/rules/history', customerAuth, (req, res) => {
  res.json({ history: (state.rule_history[req.customer.id] || []).slice().reverse() });
});

// ═══════════════════════════════════════════════════════════════════════════
//  Port forwarding, custom DNS upstream, static DHCP leases (per customer)
// ═══════════════════════════════════════════════════════════════════════════
if (!state.port_forwards) state.port_forwards = {};   // { customer_id: [ {id, ext_port, int_ip, int_port, proto, label} ] }
if (!state.dhcp_leases) state.dhcp_leases = {};       // { customer_id: [ {id, mac, ip, hostname} ] }
if (!state.dns_upstreams) state.dns_upstreams = {};   // { customer_id: ['1.1.1.1','1.0.0.1'] }

// ─── port forwards ─────
app.get('/api/customer/portfwd', customerAuth, (req, res) => {
  res.json({ forwards: state.port_forwards[req.customer.id] || [] });
});
app.post('/api/customer/portfwd/add', customerAuth, (req, res) => {
  const c = req.customer;
  const fwd = {
    id: shortId(10),
    ext_port: parseInt(req.body.ext_port),
    int_ip: String(req.body.int_ip || ''),
    int_port: parseInt(req.body.int_port),
    proto: ['tcp','udp','both'].includes(req.body.proto) ? req.body.proto : 'tcp',
    label: String(req.body.label || '').slice(0, 60),
    created_at: Date.now(),
  };
  if (!fwd.ext_port || !fwd.int_port || !fwd.int_ip) return res.status(400).json({ error: 'ext_port, int_ip, int_port required' });
  if (fwd.ext_port < 1 || fwd.ext_port > 65535) return res.status(400).json({ error: 'ext_port out of range' });
  // Block reserved ports
  if ([22, 53, 80, 443, 51820].includes(fwd.ext_port)) return res.status(400).json({ error: 'reserved_port' });
  if (!state.port_forwards[c.id]) state.port_forwards[c.id] = [];
  state.port_forwards[c.id].push(fwd);
  saveState();
  res.json({ ok: true, forward: fwd });
});
app.post('/api/customer/portfwd/delete', customerAuth, (req, res) => {
  const list = state.port_forwards[req.customer.id] || [];
  const i = list.findIndex(x => x.id === req.body.id);
  if (i < 0) return res.status(404).json({ error: 'not found' });
  list.splice(i, 1);
  saveState();
  res.json({ ok: true });
});

// ─── static DHCP leases ─────
app.get('/api/customer/dhcp-leases', customerAuth, (req, res) => {
  res.json({ leases: state.dhcp_leases[req.customer.id] || [] });
});
app.post('/api/customer/dhcp-leases/set', customerAuth, (req, res) => {
  const c = req.customer;
  const mac = normalizeMac(req.body.mac || '');
  const ip = String(req.body.ip || '');
  const hostname = String(req.body.hostname || '').slice(0, 63);
  if (!mac || !ip) return res.status(400).json({ error: 'mac and ip required' });
  if (!state.dhcp_leases[c.id]) state.dhcp_leases[c.id] = [];
  const list = state.dhcp_leases[c.id];
  const existing = list.find(l => l.mac === mac);
  if (existing) {
    existing.ip = ip; existing.hostname = hostname;
  } else {
    list.push({ id: shortId(10), mac, ip, hostname, created_at: Date.now() });
  }
  saveState();
  res.json({ ok: true });
});
app.post('/api/customer/dhcp-leases/delete', customerAuth, (req, res) => {
  const list = state.dhcp_leases[req.customer.id] || [];
  const i = list.findIndex(x => x.id === req.body.id);
  if (i < 0) return res.status(404).json({ error: 'not found' });
  list.splice(i, 1);
  saveState();
  res.json({ ok: true });
});

// ─── Customer share-links (read-only view of stats) ─────
// state.share_links = { token: { customer_id, scope: 'overview'|'usage'|'devices', expires_at, created_at } }
if (!state.share_links) state.share_links = {};

app.post('/api/customer/share-links/create', customerAuth, (req, res) => {
  const c = req.customer;
  const scope = ['overview','usage','devices'].includes(req.body.scope) ? req.body.scope : 'overview';
  const ttl_hours = Math.min(parseInt(req.body.ttl_hours) || 168, 24 * 30);
  const token = crypto.randomBytes(20).toString('base64url');
  state.share_links[token] = {
    customer_id: c.id,
    scope,
    expires_at: Date.now() + ttl_hours * 3600_000,
    created_at: Date.now(),
  };
  saveState();
  const url = `${state.config.brand_domain ? 'https://' + state.config.brand_domain : ''}/share/${token}`;
  res.json({ ok: true, token, url, expires_at: state.share_links[token].expires_at });
});
app.get('/api/customer/share-links', customerAuth, (req, res) => {
  const mine = Object.entries(state.share_links)
    .filter(([_, s]) => s.customer_id === req.customer.id && s.expires_at > Date.now())
    .map(([token, s]) => ({ token, scope: s.scope, expires_at: s.expires_at, created_at: s.created_at }));
  res.json({ links: mine });
});
app.post('/api/customer/share-links/revoke', customerAuth, (req, res) => {
  const t = req.body.token;
  if (state.share_links[t] && state.share_links[t].customer_id === req.customer.id) {
    delete state.share_links[t];
    saveState();
  }
  res.json({ ok: true });
});

// Public viewer — no auth, just a valid share token
app.get('/share/:token', (req, res) => {
  const s = state.share_links[req.params.token];
  if (!s || s.expires_at < Date.now()) {
    return res.status(404).type('html').send('<h1>This share link has expired or is invalid.</h1>');
  }
  const c = state.customers[s.customer_id];
  if (!c) return res.status(404).type('html').send('<h1>Customer not found.</h1>');
  const branding = effectiveBranding(state.tenants && state.tenants[c.tenant_id]);

  const myMacs = Object.values(state.authorized_macs).filter(m => m.customer_id === c.id).map(m => m.mac);
  const onlineBoxes = myMacs.filter(mac => {
    const st = state.box_state[mac];
    return st && st.last_heartbeat && (Date.now() - st.last_heartbeat) < 5*60_000;
  }).length;

  const period = currentPeriod();
  const usage = (state.usage_monthly[c.id] || {})[period] || {};
  const totalGB = (Object.values(usage).reduce((s, v) => s + (v.bytes_up||0) + (v.bytes_down||0), 0) / 1024**3).toFixed(2);

  const recentAlarms = state.alarms.filter(a => a.customer_id === c.id).slice(0, 5);

  res.type('html').send(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${c.name} — ${branding.brand_name}</title>
<style>
body{font-family:system-ui;background:#0f1419;color:#e3e9f0;margin:0;padding:30px 20px;}
.wrap{max-width:600px;margin:0 auto;}
h1{color:${branding.brand_color};font-size:1.4em;}
.card{background:#1a2028;padding:20px;border-radius:12px;margin:14px 0;}
.stat{display:flex;justify-content:space-between;align-items:baseline;}
.stat .v{font-size:1.8em;color:#3ad29f;font-weight:700;}
.stat .l{color:#8aa0c0;font-size:.85em;}
.alarm{padding:10px;background:#0f1419;border-left:3px solid #ff8c42;border-radius:4px;margin-bottom:6px;}
.alarm .t{color:#fff;}
.alarm .ts{color:#6c7686;font-size:.75em;}
footer{text-align:center;color:#6c7686;font-size:.8em;margin-top:30px;}
</style></head><body><div class="wrap">
<h1>📊 ${c.name}'s network</h1>
<p style="color:#6c7686;font-size:.85em;">Read-only share — link expires ${new Date(s.expires_at).toLocaleDateString()}</p>

<div class="card">
  <div class="stat"><span class="l">Boxes online</span><span class="v">${onlineBoxes}/${myMacs.length}</span></div>
</div>
<div class="card">
  <div class="stat"><span class="l">Bandwidth this month</span><span class="v">${totalGB} GB</span></div>
</div>
<div class="card">
  <h3 style="color:#8aa0c0;font-size:.9em;margin-bottom:10px;">Recent alarms</h3>
  ${recentAlarms.length === 0
    ? '<p style="color:#6c7686;padding:8px;">All quiet.</p>'
    : recentAlarms.map(a => '<div class="alarm"><div class="t">' + (a.title || a.kind) + '</div><div class="ts">' + new Date(a.ts).toLocaleString() + '</div></div>').join('')}
</div>

<footer>${branding.brand_name} · Read-only share view</footer>
</div></body></html>`);
});

// ─── Custom alarm rules ─────
// state.custom_alarm_rules = { customer_id: [ {id, label, mac (or '*'), metric, threshold_mb, window_min, severity, enabled} ] }
if (!state.custom_alarm_rules) state.custom_alarm_rules = {};

app.get('/api/customer/custom-alarms', customerAuth, (req, res) => {
  res.json({ rules: state.custom_alarm_rules[req.customer.id] || [] });
});
app.post('/api/customer/custom-alarms/add', customerAuth, (req, res) => {
  const c = req.customer;
  const r = {
    id: shortId(10),
    label: String(req.body.label || 'Custom alarm').slice(0, 60),
    mac: req.body.mac ? normalizeMac(req.body.mac) : '*',
    metric: ['bytes_total','bytes_up','bytes_down','flow_count'].includes(req.body.metric) ? req.body.metric : 'bytes_total',
    threshold_mb: parseFloat(req.body.threshold_mb) || 100,
    window_min: Math.min(parseInt(req.body.window_min) || 60, 60 * 24),
    severity: ['low','medium','high','critical'].includes(req.body.severity) ? req.body.severity : 'medium',
    enabled: req.body.enabled !== false,
    created_at: Date.now(),
  };
  if (!state.custom_alarm_rules[c.id]) state.custom_alarm_rules[c.id] = [];
  state.custom_alarm_rules[c.id].push(r);
  saveState();
  res.json({ ok: true, rule: r });
});
app.post('/api/customer/custom-alarms/delete', customerAuth, (req, res) => {
  const list = state.custom_alarm_rules[req.customer.id] || [];
  const i = list.findIndex(r => r.id === req.body.id);
  if (i < 0) return res.status(404).json({ error: 'not found' });
  list.splice(i, 1);
  saveState();
  res.json({ ok: true });
});

// Custom alarm scanner — runs every 5 min
function runCustomAlarmScan() {
  for (const [cid, rules] of Object.entries(state.custom_alarm_rules || {})) {
    for (const r of rules) {
      if (!r.enabled) continue;
      const cutoff = Date.now() - r.window_min * 60_000;
      const flows = state.flows.filter(f => f.customer_id === cid && f.ts >= cutoff
        && (r.mac === '*' || f.src_mac === r.mac));
      let v = 0;
      if (r.metric === 'bytes_total') v = flows.reduce((s, f) => s + (f.bytes_up||0) + (f.bytes_down||0), 0);
      else if (r.metric === 'bytes_up') v = flows.reduce((s, f) => s + (f.bytes_up||0), 0);
      else if (r.metric === 'bytes_down') v = flows.reduce((s, f) => s + (f.bytes_down||0), 0);
      else if (r.metric === 'flow_count') v = flows.length;
      const valueMB = r.metric === 'flow_count' ? v : v / (1024 * 1024);
      if (valueMB >= r.threshold_mb) {
        fireSyntheticAlarm(cid, null, r.severity, 'custom_rule_' + r.id,
          r.label,
          `Threshold reached: ${r.metric} for ${r.mac} = ${valueMB.toFixed(1)} ${r.metric === 'flow_count' ? 'flows' : 'MB'} in last ${r.window_min} min (limit ${r.threshold_mb}).`);
      }
    }
  }
}
setInterval(runCustomAlarmScan, 5 * 60_000);
setTimeout(runCustomAlarmScan, 90_000);

// ─── Time bank (per-device daily-minutes budget) ─────
// state.time_bank = { customer_id: [ { id, device_mac, daily_minutes, period_yyyy_mm_dd, used_minutes } ] }
if (!state.time_bank) state.time_bank = {};

function timeBankResetIfNew(c_id) {
  const today = currentDay();
  const list = state.time_bank[c_id] || [];
  for (const e of list) {
    if (e.period_yyyy_mm_dd !== today) {
      // Tier-2 Feature D: compute rollover from yesterday's leftover BEFORE reset.
      // Unused minutes carry over up to max_rollover_minutes (default = daily_minutes).
      const yesterdayBudget = (e.daily_minutes || 0) + (e.bonus_minutes_today || 0) + (e.rolled_minutes_today || 0);
      const yesterdayLeftover = Math.max(0, yesterdayBudget - (e.used_minutes || 0));
      const cap = (typeof e.max_rollover_minutes === 'number')
        ? e.max_rollover_minutes
        : (e.daily_minutes || 0);
      e.rolled_minutes_today = e.rollover_enabled ? Math.min(cap, yesterdayLeftover) : 0;
      e.period_yyyy_mm_dd = today;
      e.used_minutes = 0;
      // Tier-1 Feature D: bonus minutes are per-day and reset alongside used_minutes.
      e.bonus_minutes_today = 0;
    }
    if (typeof e.bonus_minutes_today !== 'number') e.bonus_minutes_today = 0;
    if (typeof e.rolled_minutes_today !== 'number') e.rolled_minutes_today = 0;
    if (typeof e.rollover_enabled !== 'boolean')   e.rollover_enabled = false;
    if (typeof e.max_rollover_minutes !== 'number') e.max_rollover_minutes = e.daily_minutes || 0;
  }
}

app.get('/api/customer/time-bank', customerAuth, (req, res) => {
  timeBankResetIfNew(req.customer.id);
  res.json({ entries: state.time_bank[req.customer.id] || [], today: currentDay() });
});
app.post('/api/customer/time-bank/set', customerAuth, (req, res) => {
  const c = req.customer;
  const mac = normalizeMac(req.body.device_mac || '');
  const minutes = parseInt(req.body.daily_minutes) || 0;
  if (!mac || minutes <= 0) return res.status(400).json({ error: 'device_mac and daily_minutes>0 required' });
  if (!state.time_bank[c.id]) state.time_bank[c.id] = [];
  const list = state.time_bank[c.id];
  let e = list.find(x => x.device_mac === mac);
  if (!e) {
    e = { id: shortId(10), device_mac: mac, daily_minutes: minutes, period_yyyy_mm_dd: currentDay(), used_minutes: 0, created_at: Date.now() };
    list.push(e);
  } else {
    e.daily_minutes = minutes;
  }
  saveState();
  res.json({ ok: true, entry: e });
});
app.post('/api/customer/time-bank/delete', customerAuth, (req, res) => {
  const list = state.time_bank[req.customer.id] || [];
  const i = list.findIndex(x => x.id === req.body.id);
  if (i < 0) return res.status(404).json({ error: 'not found' });
  list.splice(i, 1);
  saveState();
  res.json({ ok: true });
});

// Tier-1 Feature D: parent grants bonus minutes (e.g. "+30 min" from a notification)
// Adds to bonus_minutes_today, which resets at midnight along with used_minutes.
app.post('/api/customer/time-bank/grant-bonus', customerAuth, (req, res) => {
  const cid = req.customer.id;
  const mac = normalizeMac(req.body.device_mac || '');
  const minutes = parseInt(req.body.minutes, 10);
  if (!mac) return res.status(400).json({ error: 'device_mac required' });
  if (!Number.isFinite(minutes) || minutes <= 0 || minutes > 1440) {
    return res.status(400).json({ error: 'minutes must be 1..1440' });
  }
  timeBankResetIfNew(cid);
  const list = state.time_bank[cid] || [];
  const e = list.find(x => (x.device_mac || '').toLowerCase() === mac);
  if (!e) return res.status(404).json({ error: 'no time-bank entry for that device' });
  e.bonus_minutes_today = (e.bonus_minutes_today || 0) + minutes;
  saveState();
  state.events.push({ ts: Date.now(), method: 'CUSTOMER', path: `[TIME-BANK+] ${req.customer.name||cid} +${minutes}m bonus for ${mac}`, ip: req.ip });
  res.json({ ok: true, entry: e });
});

// Time-bank usage tally — driven by flow ingest (a device with traffic in last minute counts as 1 minute used)
function tallyTimeBank(f) {
  const cid = f.customer_id;
  if (!cid) return;
  const list = state.time_bank[cid];
  if (!list || !list.length) return;
  const mac = f.src_mac;
  if (!mac) return;
  const e = list.find(x => x.device_mac === mac);
  if (!e) return;
  // Only count one minute per minute (use a per-device timestamp)
  if (!e._last_count_min) e._last_count_min = 0;
  const minBucket = Math.floor((f.ts || Date.now()) / 60_000);
  if (minBucket !== e._last_count_min) {
    e._last_count_min = minBucket;
    timeBankResetIfNew(cid);
    e.used_minutes = (e.used_minutes || 0) + 1;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// TIER-2 Feature A — Per-device risk score (0..100)
// TIER-2 Feature B — Behavioural baselines + deviation alerts
// TIER-2 Feature C — Selective family pause
// TIER-2 Feature D — Time-bank rollover
// ═══════════════════════════════════════════════════════════════════════════
if (!state.device_risk)      state.device_risk      = {};   // { cid: { mac: { score, factors, severity, computed_at } } }
if (!state.device_baselines) state.device_baselines = {};   // { cid: { mac: { avg_bytes, std_bytes, avg_dests, std_dests, avg_countries, std_countries, avg_ports, std_ports, samples, computed_at } } }
if (!state.device_cves)      state.device_cves      = {};   // sibling agent populates — we only read

const RISK_SEVERITY_BAND = (s) => s >= 76 ? 'critical' : s >= 51 ? 'high' : s >= 26 ? 'medium' : 'low';

// IoT classifier hint — used for the baseline +10 in the risk score. We look at
// device_type AND vendor strings since some boxes report 'iot' explicitly and
// some leave the type generic but the vendor is a known IoT maker.
const IOT_VENDOR_HINTS = /hikvision|dahua|reolink|tp-?link|ezviz|amcrest|nest|ring|amazon|google home|sonoff|tuya|xiaomi|wyze|eufy|tplink|broadlink|shelly|philips|lifx|sonos|ecobee|honeywell|smartthings/i;
function isIoTDevice(dev) {
  if (!dev) return false;
  if (dev.device_type === 'iot') return true;
  if (dev.vendor && IOT_VENDOR_HINTS.test(dev.vendor)) return true;
  const fp = (dev.dhcp_fp || '').toLowerCase();
  if (fp && /(hikvision|nest|ring|amazon|google|sonos)/.test(fp)) return true;
  return false;
}

// Resolve the customer's devices across all their boxes (deduped by MAC, latest wins).
function devicesForCustomer(cid) {
  const myBoxes = Object.values(state.authorized_macs).filter(m => m.customer_id === cid);
  const out = {};
  for (const b of myBoxes) {
    const bucket = state.box_devices[b.mac] || {};
    for (const d of Object.values(bucket)) {
      const prev = out[d.mac];
      if (!prev || (d.last_seen || 0) > (prev.last_seen || 0)) out[d.mac] = d;
    }
  }
  return out;
}

// ─── Feature A — risk score
function computeDeviceRiskScore(cid, mac) {
  const macL = (mac || '').toLowerCase();
  const factors = [];
  let score = 0;

  // CVE hits — sibling Feature
  const cves = (state.device_cves && state.device_cves[cid] && state.device_cves[cid][macL]) || null;
  if (cves && Array.isArray(cves.matches || cves)) {
    const list = Array.isArray(cves.matches) ? cves.matches : cves;
    let cveWeight = 0;
    for (const c of list) {
      const sev = String(c.severity || c.cvss_severity || '').toLowerCase();
      if (sev === 'critical') cveWeight += 25;
      else if (sev === 'high') cveWeight += 10;
      else if (sev === 'medium' || sev === 'moderate') cveWeight += 5;
    }
    cveWeight = Math.min(40, cveWeight);
    if (cveWeight > 0) { score += cveWeight; factors.push({ name: 'cve_hits', weight: cveWeight, count: list.length }); }
  }

  // Behavior deviation (if baseline shows >3σ today on any metric → +20)
  const baseline = (state.device_baselines[cid] || {})[macL] || null;
  if (baseline && baseline.samples >= 3) {
    const today = currentDay();
    const todayBucket = ((state.usage_daily || {})[cid] || {})[today] || {};
    const u = todayBucket[macL] || { bytes_up: 0, bytes_down: 0 };
    const todayBytes = (u.bytes_up || 0) + (u.bytes_down || 0);
    const todayMetrics = computeTodayMetrics(cid, macL);
    let deviated = false;
    if (baseline.std_bytes > 0 && todayBytes > baseline.avg_bytes + 3 * baseline.std_bytes) deviated = true;
    if (baseline.std_dests > 0 && todayMetrics.dests > baseline.avg_dests + 3 * baseline.std_dests) deviated = true;
    if (baseline.std_countries > 0 && todayMetrics.countries > baseline.avg_countries + 3 * baseline.std_countries) deviated = true;
    if (baseline.std_ports > 0 && todayMetrics.ports > baseline.avg_ports + 3 * baseline.std_ports) deviated = true;
    if (deviated) { score += 20; factors.push({ name: 'behaviour_deviation', weight: 20 }); }
  }

  // Threat-intel hits — alarms last 7 days for this device, certain kinds
  const intelKinds = new Set(['sig_match','signature_match','ja3_malware_signature','bypass_attempt','dga_suspected','c2_beacon_suspected','ids_match']);
  const cutoff = Date.now() - 7 * 86400_000;
  let intelHits = 0;
  for (const a of (state.alarms || [])) {
    if (a.customer_id !== cid) continue;
    if (!a.ts || a.ts < cutoff) continue;
    if ((a.device_mac || '').toLowerCase() !== macL) continue;
    if (intelKinds.has(a.kind)) intelHits++;
  }
  if (intelHits > 0) {
    const w = Math.min(30, intelHits * 5);
    score += w;
    factors.push({ name: 'threat_intel_hits', weight: w, count: intelHits });
  }

  // IoT classification
  const devs = devicesForCustomer(cid);
  const dev = devs[macL] || null;
  if (dev && isIoTDevice(dev)) {
    score += 10;
    factors.push({ name: 'iot_baseline', weight: 10 });
  }

  score = Math.max(0, Math.min(100, Math.round(score)));
  const severity = RISK_SEVERITY_BAND(score);
  const cached = { score, factors, severity, computed_at: Date.now() };
  if (!state.device_risk[cid]) state.device_risk[cid] = {};
  state.device_risk[cid][macL] = cached;
  return cached;
}

function recomputeAllRiskForCustomer(cid) {
  const devs = devicesForCustomer(cid);
  for (const mac of Object.keys(devs)) computeDeviceRiskScore(cid, mac);
}
function recomputeAllRiskFleet() {
  for (const cid of Object.keys(state.customers || {})) {
    try { recomputeAllRiskForCustomer(cid); } catch(e) {}
  }
  saveState();
}
// Hourly fleet-wide refresh
setTimeout(recomputeAllRiskFleet, 4 * 60_000);
setInterval(recomputeAllRiskFleet, 3600_000);

app.get('/api/customer/devices/:mac/risk', customerAuth, (req, res) => {
  const macL = (req.params.mac || '').toLowerCase();
  const cid = req.customer.id;
  let cached = (state.device_risk[cid] || {})[macL];
  // Recompute on demand if missing or stale (>1h)
  if (!cached || (Date.now() - cached.computed_at) > 3600_000) {
    cached = computeDeviceRiskScore(cid, macL);
  }
  res.json(cached);
});

app.get('/api/customer/risk-overview', customerAuth, (req, res) => {
  const cid = req.customer.id;
  const devs = devicesForCustomer(cid);
  const out = [];
  for (const [mac, d] of Object.entries(devs)) {
    let cached = (state.device_risk[cid] || {})[mac];
    if (!cached || (Date.now() - cached.computed_at) > 3600_000) {
      cached = computeDeviceRiskScore(cid, mac);
    }
    out.push({
      mac,
      name: d.hostname || d.device_label || d.vendor || mac,
      vendor: d.vendor || '',
      device_type: d.device_type || '',
      ip: d.ip || '',
      online: d.last_seen ? (Date.now() - d.last_seen) < 10 * 60_000 : false,
      ...cached,
    });
  }
  out.sort((a, b) => b.score - a.score);
  res.json({ devices: out, generated_at: Date.now() });
});

// ─── Feature B — baselines
// Compute today's actual destinations / countries / ports from flow_archive
function computeTodayMetrics(cid, macL) {
  const startOfDay = new Date(); startOfDay.setHours(0,0,0,0);
  const startMs = startOfDay.getTime();
  const dests = new Set(), countries = new Set(), ports = new Set();
  const arr = state.flow_archive[cid] || [];
  for (const f of arr) {
    if (f.ts < startMs) continue;
    if ((f.src_mac || '').toLowerCase() !== macL) continue;
    if (f.dst_domain) dests.add(f.dst_domain);
    else if (f.dst_ip) dests.add(f.dst_ip);
    if (f.country) countries.add(f.country);
    if (f.dst_port) ports.add(f.dst_port);
  }
  return { dests: dests.size, countries: countries.size, ports: ports.size };
}
function metricsForDay(cid, macL, dayStr) {
  // returns {bytes, dests, countries, ports} for a single yyyy-mm-dd
  const dayStartMs = new Date(dayStr + 'T00:00:00Z').getTime();
  const dayEndMs   = dayStartMs + 86400_000;
  const u = ((state.usage_daily[cid] || {})[dayStr] || {})[macL] || { bytes_up: 0, bytes_down: 0 };
  const bytes = (u.bytes_up || 0) + (u.bytes_down || 0);
  const dests = new Set(), countries = new Set(), ports = new Set();
  for (const f of (state.flow_archive[cid] || [])) {
    if (f.ts < dayStartMs || f.ts >= dayEndMs) continue;
    if ((f.src_mac || '').toLowerCase() !== macL) continue;
    if (f.dst_domain) dests.add(f.dst_domain);
    else if (f.dst_ip) dests.add(f.dst_ip);
    if (f.country) countries.add(f.country);
    if (f.dst_port) ports.add(f.dst_port);
  }
  return { bytes, dests: dests.size, countries: countries.size, ports: ports.size };
}
function recomputeBaseline(cid, macL) {
  // Look at the last 7 days (excluding today)
  const samples = [];
  for (let i = 1; i <= 7; i++) {
    const day = new Date(Date.now() - i * 86400_000).toISOString().slice(0, 10);
    const m = metricsForDay(cid, macL, day);
    samples.push(m);
  }
  // Only retain non-zero days so brand-new devices don't have artificially low std
  const valid = samples.filter(s => (s.bytes + s.dests + s.countries + s.ports) > 0);
  if (!valid.length) return null;
  const meanStd = arr => {
    const n = arr.length;
    const mean = arr.reduce((a,b)=>a+b,0) / n;
    const variance = arr.reduce((a,b)=>a + (b-mean)*(b-mean), 0) / n;
    return { mean, std: Math.sqrt(variance) };
  };
  const b = meanStd(valid.map(s => s.bytes));
  const d = meanStd(valid.map(s => s.dests));
  const c = meanStd(valid.map(s => s.countries));
  const p = meanStd(valid.map(s => s.ports));
  const out = {
    avg_bytes: b.mean, std_bytes: b.std,
    avg_dests: d.mean, std_dests: d.std,
    avg_countries: c.mean, std_countries: c.std,
    avg_ports: p.mean, std_ports: p.std,
    samples: valid.length,
    computed_at: Date.now(),
  };
  if (!state.device_baselines[cid]) state.device_baselines[cid] = {};
  state.device_baselines[cid][macL] = out;
  return out;
}
function recomputeAllBaselines() {
  for (const cid of Object.keys(state.customers || {})) {
    const devs = devicesForCustomer(cid);
    for (const mac of Object.keys(devs)) {
      try { recomputeBaseline(cid, mac); } catch(e) {}
    }
  }
  saveState();
}
// Daily baseline rebuild — once after startup (5 min), then every 24h
setTimeout(recomputeAllBaselines, 5 * 60_000);
setInterval(recomputeAllBaselines, 24 * 3600_000);

// Hourly deviation check — fires `behavior_deviation` alarm at >3σ
function detectBehaviorDeviations() {
  for (const cid of Object.keys(state.customers || {})) {
    const devs = devicesForCustomer(cid);
    for (const [mac, dev] of Object.entries(devs)) {
      const macL = mac.toLowerCase();
      const baseline = (state.device_baselines[cid] || {})[macL];
      if (!baseline || baseline.samples < 3) continue;
      const today = currentDay();
      const u = ((state.usage_daily[cid] || {})[today] || {})[macL] || { bytes_up: 0, bytes_down: 0 };
      const todayBytes = (u.bytes_up || 0) + (u.bytes_down || 0);
      const tm = computeTodayMetrics(cid, macL);
      const fmtMB = b => (b/1024/1024).toFixed(0) + ' MB';
      const fmtGB = b => (b/1024/1024/1024).toFixed(1) + ' GB';
      const fmtBytes = b => b >= 1024*1024*1024 ? fmtGB(b) : fmtMB(b);
      let breach = null;
      if (baseline.std_bytes > 0 && todayBytes > baseline.avg_bytes + 3 * baseline.std_bytes) {
        breach = { metric: 'bytes', actual: todayBytes, expected: baseline.avg_bytes,
                   body: `Device ${dev.hostname || mac} transferred ${fmtBytes(todayBytes)} today (typical: ${fmtBytes(baseline.avg_bytes)}).` };
      } else if (baseline.std_dests > 0 && tm.dests > baseline.avg_dests + 3 * baseline.std_dests) {
        breach = { metric: 'destinations', actual: tm.dests, expected: baseline.avg_dests,
                   body: `Device ${dev.hostname || mac} contacted ${tm.dests} destinations today (typical: ${Math.round(baseline.avg_dests)}).` };
      } else if (baseline.std_countries > 0 && tm.countries > baseline.avg_countries + 3 * baseline.std_countries) {
        breach = { metric: 'countries', actual: tm.countries, expected: baseline.avg_countries,
                   body: `Device ${dev.hostname || mac} reached ${tm.countries} countries today (typical: ${Math.round(baseline.avg_countries)}).` };
      } else if (baseline.std_ports > 0 && tm.ports > baseline.avg_ports + 3 * baseline.std_ports) {
        breach = { metric: 'ports', actual: tm.ports, expected: baseline.avg_ports,
                   body: `Device ${dev.hostname || mac} hit ${tm.ports} distinct ports today (typical: ${Math.round(baseline.avg_ports)}).` };
      }
      if (breach && typeof fireSyntheticAlarm === 'function') {
        // Pick the first customer's box mac if any
        const boxMac = (Object.values(state.authorized_macs).find(m => m.customer_id === cid) || {}).mac || null;
        fireSyntheticAlarm(cid, boxMac, 'medium', 'behavior_deviation',
          `Unusual activity: ${dev.hostname || mac}`,
          breach.body,
          { device_mac: mac, metric_name: breach.metric, actual: breach.actual, expected: Math.round(breach.expected) });
      }
    }
  }
}
setTimeout(detectBehaviorDeviations, 7 * 60_000);
setInterval(detectBehaviorDeviations, 3600_000);

// Register the new MITRE tag for behavior_deviation. We attach it after the
// MITRE_TAGS const is defined (later in this file) — see additional block below.

app.get('/api/customer/devices/:mac/baseline', customerAuth, (req, res) => {
  const cid = req.customer.id;
  const macL = (req.params.mac || '').toLowerCase();
  let baseline = (state.device_baselines[cid] || {})[macL];
  if (!baseline) baseline = recomputeBaseline(cid, macL);
  const today = currentDay();
  const u = ((state.usage_daily[cid] || {})[today] || {})[macL] || { bytes_up: 0, bytes_down: 0 };
  const todayBytes = (u.bytes_up || 0) + (u.bytes_down || 0);
  const tm = computeTodayMetrics(cid, macL);
  const dev_pct = (actual, expected) => (expected > 0) ? Math.round(((actual - expected) / expected) * 100) : (actual > 0 ? 999 : 0);
  res.json({
    mac: macL,
    baseline: baseline || null,
    today: { bytes: todayBytes, dests: tm.dests, countries: tm.countries, ports: tm.ports },
    deviation_pct: baseline ? {
      bytes:     dev_pct(todayBytes, baseline.avg_bytes),
      dests:     dev_pct(tm.dests,    baseline.avg_dests),
      countries: dev_pct(tm.countries, baseline.avg_countries),
      ports:     dev_pct(tm.ports,    baseline.avg_ports),
    } : null,
  });
});

// ─── Feature C — Selective family pause
//   state.customers[cid].selective_pause = { active, until, exclude_member_ids[], exclude_device_macs[], reason }
function selectivePauseActive(c) {
  return !!(c && c.selective_pause && c.selective_pause.active && c.selective_pause.until > Date.now());
}
function selectivePauseExpandExcluded(cid) {
  const c = state.customers[cid];
  if (!c || !selectivePauseActive(c)) return new Set();
  const sp = c.selective_pause;
  const out = new Set((sp.exclude_device_macs || []).map(m => (m||'').toLowerCase()).filter(Boolean));
  const fam = state.family_members[cid] || [];
  for (const fid of (sp.exclude_member_ids || [])) {
    const m = fam.find(x => x.id === fid);
    if (m) for (const dmac of (m.device_macs || [])) out.add((dmac||'').toLowerCase());
  }
  return out;
}
app.post('/api/customer/selective-pause', customerAuth, (req, res) => {
  const c = req.customer;
  const minutes = Math.max(1, Math.min(parseInt(req.body.minutes) || 60, 1440));
  const exclude_member_ids = Array.isArray(req.body.exclude_member_ids) ? req.body.exclude_member_ids.slice(0, 50) : [];
  const exclude_device_macs = Array.isArray(req.body.exclude_device_macs)
    ? req.body.exclude_device_macs.map(m => (m||'').toLowerCase()).filter(Boolean).slice(0, 200)
    : [];
  const reason = String(req.body.reason || '').slice(0, 120);
  c.selective_pause = {
    active: true,
    until: Date.now() + minutes * 60_000,
    exclude_member_ids,
    exclude_device_macs,
    reason,
    started_at: Date.now(),
  };
  state.events.push({ ts: Date.now(), method: 'CUSTOMER',
    path: `[SELECTIVE-PAUSE] ${c.name} → ${minutes}m, exempt ${exclude_member_ids.length} members + ${exclude_device_macs.length} devices`, ip: req.ip });
  saveState();
  if (typeof bumpPolicyEtagGlobal === 'function') bumpPolicyEtagGlobal(`selective_pause:${c.id}`);
  res.json({ ok: true, selective_pause: c.selective_pause });
});
app.post('/api/customer/selective-pause/cancel', customerAuth, (req, res) => {
  const c = req.customer;
  if (c.selective_pause) c.selective_pause.active = false;
  saveState();
  if (typeof bumpPolicyEtagGlobal === 'function') bumpPolicyEtagGlobal(`selective_pause_cancel:${c.id}`);
  state.events.push({ ts: Date.now(), method: 'CUSTOMER',
    path: `[SELECTIVE-PAUSE-CANCEL] ${c.name}`, ip: req.ip });
  res.json({ ok: true });
});
app.get('/api/customer/selective-pause', customerAuth, (req, res) => {
  const c = req.customer;
  const sp = c.selective_pause || null;
  let exempted = [];
  if (sp && selectivePauseActive(c)) {
    exempted = Array.from(selectivePauseExpandExcluded(c.id));
  }
  res.json({ selective_pause: sp, exempted_macs: exempted, active: selectivePauseActive(c) });
});

// ─── Feature D — Time-bank rollover (extends Tier-1 time-bank)
// New per-entry fields:
//   rollover_enabled, max_rollover_minutes, rolled_minutes_today, _last_rolled_day
app.post('/api/customer/time-bank/rollover-prefs', customerAuth, (req, res) => {
  const cid = req.customer.id;
  const mac = normalizeMac(req.body.device_mac || '');
  if (!mac) return res.status(400).json({ error: 'device_mac required' });
  const enabled = req.body.enabled !== false && req.body.enabled !== 'false';
  const list = state.time_bank[cid] || [];
  const e = list.find(x => (x.device_mac || '').toLowerCase() === mac);
  if (!e) return res.status(404).json({ error: 'no time-bank entry for that device' });
  e.rollover_enabled = !!enabled;
  if (req.body.max_rollover_minutes != null) {
    const v = parseInt(req.body.max_rollover_minutes, 10);
    if (Number.isFinite(v) && v >= 0 && v <= 1440) e.max_rollover_minutes = v;
  }
  if (e.max_rollover_minutes == null) e.max_rollover_minutes = e.daily_minutes;
  saveState();
  res.json({ ok: true, entry: e });
});

// ─── Device tags (per customer) ─────
// state.device_tags = { customer_id: { mac: [tag, tag, ...] } }
if (!state.device_tags) state.device_tags = {};
app.get('/api/customer/device-tags', customerAuth, (req, res) => {
  res.json({ tags: state.device_tags[req.customer.id] || {} });
});
app.post('/api/customer/device-tags/set', customerAuth, (req, res) => {
  const c = req.customer;
  const mac = normalizeMac(req.body.mac || '');
  const tags = Array.isArray(req.body.tags) ? req.body.tags.map(t => String(t).toLowerCase().slice(0, 30)).filter(Boolean) : [];
  if (!mac) return res.status(400).json({ error: 'mac required' });
  if (!state.device_tags[c.id]) state.device_tags[c.id] = {};
  if (tags.length) state.device_tags[c.id][mac] = tags;
  else delete state.device_tags[c.id][mac];
  saveState();
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════════════════════════
//  FIREWALLA-PARITY: VLAN + Guest WiFi + Site-to-site VPN + Per-device VPN routing
// ═══════════════════════════════════════════════════════════════════════════

// ─── VLANs (per customer) ─────
// state.vlans = { customer_id: [ {id, vlan_id (1-4094), name, subnet, gateway, dhcp_start, dhcp_end} ] }
if (!state.vlans) state.vlans = {};
app.get('/api/customer/vlans', customerAuth, (req, res) => {
  res.json({ vlans: state.vlans[req.customer.id] || [] });
});
app.post('/api/customer/vlans/add', customerAuth, (req, res) => {
  const c = req.customer;
  const vlan_id = parseInt(req.body.vlan_id);
  if (vlan_id < 2 || vlan_id > 4094) return res.status(400).json({ error: 'vlan_id must be 2-4094' });
  if (!state.vlans[c.id]) state.vlans[c.id] = [];
  if (state.vlans[c.id].some(v => v.vlan_id === vlan_id)) return res.status(409).json({ error: 'vlan_id already used' });
  const v = {
    id: shortId(10), vlan_id,
    name: String(req.body.name || 'VLAN ' + vlan_id).slice(0, 30),
    subnet: req.body.subnet || `192.168.${vlan_id}.0/24`,
    gateway: req.body.gateway || `192.168.${vlan_id}.1`,
    dhcp_start: req.body.dhcp_start || `192.168.${vlan_id}.50`,
    dhcp_end:   req.body.dhcp_end   || `192.168.${vlan_id}.250`,
    isolated_from_main: req.body.isolated_from_main !== false,
    created_at: Date.now(),
  };
  state.vlans[c.id].push(v);
  saveState();
  res.json({ ok: true, vlan: v });
});
app.post('/api/customer/vlans/delete', customerAuth, (req, res) => {
  const list = state.vlans[req.customer.id] || [];
  const i = list.findIndex(v => v.id === req.body.id);
  if (i < 0) return res.status(404).json({ error: 'not found' });
  list.splice(i, 1);
  saveState();
  res.json({ ok: true });
});

// ─── Guest WiFi ─────
// state.guest_wifi = { customer_id: { enabled, ssid, password, band, vlan_id, captive_portal_msg } }
if (!state.guest_wifi) state.guest_wifi = {};
app.get('/api/customer/guest-wifi', customerAuth, (req, res) => {
  res.json({ config: state.guest_wifi[req.customer.id] || { enabled: false } });
});
app.post('/api/customer/guest-wifi/set', customerAuth, (req, res) => {
  const c = req.customer;
  const enabled = !!req.body.enabled;
  if (!enabled) {
    state.guest_wifi[c.id] = { enabled: false };
    saveState();
    return res.json({ ok: true, config: state.guest_wifi[c.id] });
  }
  const ssid = String(req.body.ssid || '').slice(0, 32);
  const password = String(req.body.password || '').slice(0, 63);
  if (ssid.length < 1 || password.length < 8) return res.status(400).json({ error: 'ssid required, password ≥ 8 chars' });
  state.guest_wifi[c.id] = {
    enabled: true,
    ssid,
    password,
    band: ['2.4','5','both'].includes(req.body.band) ? req.body.band : 'both',
    vlan_id: parseInt(req.body.vlan_id) || 99,
    captive_portal_msg: String(req.body.captive_portal_msg || 'Welcome to guest WiFi').slice(0, 200),
    isolate_from_lan: req.body.isolate_from_lan !== false,
    block_categories: Array.isArray(req.body.block_categories) ? req.body.block_categories : ['adult','malware'],
    created_at: state.guest_wifi[c.id]?.created_at || Date.now(),
    updated_at: Date.now(),
  };
  saveState();
  res.json({ ok: true, config: state.guest_wifi[c.id] });
});

// ─── Site-to-site VPN (between two of a customer's boxes) ─────
// state.s2s_tunnels = { customer_id: [ {id, name, box_a_mac, box_b_mac, subnet_a, subnet_b, key_a_priv, key_a_pub, key_b_priv, key_b_pub, listen_port_a, listen_port_b} ] }
if (!state.s2s_tunnels) state.s2s_tunnels = {};
app.get('/api/customer/s2s-tunnels', customerAuth, (req, res) => {
  res.json({ tunnels: state.s2s_tunnels[req.customer.id] || [] });
});
app.post('/api/customer/s2s-tunnels/create', customerAuth, (req, res) => {
  const c = req.customer;
  const macA = normalizeMac(req.body.box_a_mac || '');
  const macB = normalizeMac(req.body.box_b_mac || '');
  if (!macA || !macB || macA === macB) return res.status(400).json({ error: 'two distinct boxes required' });
  for (const mac of [macA, macB]) {
    const m = state.authorized_macs[mac];
    if (!m || m.customer_id !== c.id) return res.status(400).json({ error: `box ${mac} not yours` });
  }
  // Generate WG keypairs for both endpoints
  const a = wgGenKeypair(), b = wgGenKeypair();
  const t = {
    id: shortId(10),
    name: String(req.body.name || `Site-to-site`).slice(0, 60),
    box_a_mac: macA,
    box_b_mac: macB,
    subnet_a: req.body.subnet_a || '10.50.10.0/24',
    subnet_b: req.body.subnet_b || '10.50.20.0/24',
    key_a_priv: a.privkey, key_a_pub: a.pubkey,
    key_b_priv: b.privkey, key_b_pub: b.pubkey,
    tunnel_ip_a: '10.50.0.1/30',
    tunnel_ip_b: '10.50.0.2/30',
    listen_port: 51821,
    created_at: Date.now(),
  };
  if (!state.s2s_tunnels[c.id]) state.s2s_tunnels[c.id] = [];
  state.s2s_tunnels[c.id].push(t);
  saveState();
  res.json({ ok: true, tunnel: t });
});
app.post('/api/customer/s2s-tunnels/delete', customerAuth, (req, res) => {
  const list = state.s2s_tunnels[req.customer.id] || [];
  const i = list.findIndex(t => t.id === req.body.id);
  if (i < 0) return res.status(404).json({ error: 'not found' });
  list.splice(i, 1);
  saveState();
  res.json({ ok: true });
});

// ─── Per-device VPN routing — force specific devices through WireGuard ─────
if (!state.vpn_routed_macs) state.vpn_routed_macs = {};   // { customer_id: [mac, mac, ...] }
app.get('/api/customer/vpn-routing', customerAuth, (req, res) => {
  res.json({ macs: state.vpn_routed_macs[req.customer.id] || [] });
});
app.post('/api/customer/vpn-routing/set', customerAuth, (req, res) => {
  const macs = Array.isArray(req.body.macs) ? req.body.macs.map(normalizeMac).filter(Boolean) : [];
  state.vpn_routed_macs[req.customer.id] = macs;
  saveState();
  res.json({ ok: true });
});

// ─── Box reboot scheduler ─────
// state.reboot_schedules = { customer_id: { mac: { day_of_week (0-6), hour (0-23), enabled } } }
if (!state.reboot_schedules) state.reboot_schedules = {};
app.get('/api/customer/reboot-schedule', customerAuth, (req, res) => {
  res.json({ schedules: state.reboot_schedules[req.customer.id] || {} });
});
app.post('/api/customer/reboot-schedule/set', customerAuth, (req, res) => {
  const c = req.customer;
  const mac = normalizeMac(req.body.mac || '');
  if (!mac) return res.status(400).json({ error: 'mac required' });
  if (!state.reboot_schedules[c.id]) state.reboot_schedules[c.id] = {};
  if (req.body.enabled === false) {
    delete state.reboot_schedules[c.id][mac];
  } else {
    state.reboot_schedules[c.id][mac] = {
      day_of_week: Math.min(6, Math.max(0, parseInt(req.body.day_of_week) || 0)),
      hour: Math.min(23, Math.max(0, parseInt(req.body.hour) || 4)),
      enabled: true,
    };
  }
  saveState();
  res.json({ ok: true });
});

// Reboot scheduler runs every 30 min, queues reboot commands when window matches
function runRebootScheduler() {
  const now = new Date();
  const dow = now.getDay();
  const hour = now.getHours();
  for (const [cid, schedules] of Object.entries(state.reboot_schedules || {})) {
    for (const [mac, s] of Object.entries(schedules)) {
      if (!s.enabled) continue;
      if (s.day_of_week !== dow) continue;
      if (s.hour !== hour) continue;
      // Dedup: only fire once per hour per box
      const dedupeKey = `${mac}|${dow}|${hour}|${now.getDate()}`;
      if (s._last_fired === dedupeKey) continue;
      s._last_fired = dedupeKey;
      // Queue the reboot command
      if (!state.box_commands) state.box_commands = {};
      if (!state.box_commands[mac]) state.box_commands[mac] = [];
      state.box_commands[mac].push({
        id: shortId(16), action: 'reboot', args: { scheduled: true },
        status: 'pending', created_at: Date.now(), result: null, completed_at: null,
      });
      console.log(`         🔄 SCHEDULED REBOOT queued for ${mac}`);
    }
  }
  saveState();
}
setInterval(runRebootScheduler, 30 * 60_000);

// Add all of these to the policy bundle so the box can apply them
app._origPolicyBundle = null;  // marker for later if we hot-patch

// ─── Customer API keys (scoped) ─────
// state.customer_api_keys = { key: { customer_id, label, scope: 'read'|'full', created_at, last_used_at } }
if (!state.customer_api_keys) state.customer_api_keys = {};

app.get('/api/customer/api-keys', customerAuth, (req, res) => {
  const mine = Object.entries(state.customer_api_keys)
    .filter(([_, k]) => k.customer_id === req.customer.id)
    .map(([key, k]) => ({
      key: key.slice(0, 8) + '...' + key.slice(-4),  // never expose the full key after creation
      label: k.label, scope: k.scope, created_at: k.created_at, last_used_at: k.last_used_at,
    }));
  res.json({ keys: mine });
});
app.post('/api/customer/api-keys/create', customerAuth, (req, res) => {
  const c = req.customer;
  const scope = ['read','full'].includes(req.body.scope) ? req.body.scope : 'read';
  const label = String(req.body.label || 'API key').slice(0, 60);
  const key = 'mes_' + crypto.randomBytes(24).toString('base64url');
  state.customer_api_keys[key] = {
    customer_id: c.id, label, scope,
    created_at: Date.now(), last_used_at: null,
  };
  saveState();
  // Show the full key ONCE
  res.json({ ok: true, key, scope, hint: 'Save this key now. It will not be shown again.' });
});
app.post('/api/customer/api-keys/revoke', customerAuth, (req, res) => {
  const prefix = String(req.body.prefix || '');
  const found = Object.entries(state.customer_api_keys)
    .find(([key, k]) => k.customer_id === req.customer.id && key.startsWith(prefix));
  if (!found) return res.status(404).json({ error: 'not found' });
  delete state.customer_api_keys[found[0]];
  saveState();
  res.json({ ok: true });
});

// Initialize rate limit table now (variables hoisted above)
PLAN_RATE_LIMITS = { basic: 300, family: 600, pro: 1500, business: 3000 };

// ─── State integrity self-check ─────
// Validates the shape of state.json on a schedule + alarms super-admin if corruption found
function runStateIntegrityCheck() {
  const issues = [];

  // 1. Customer→box reference integrity
  for (const m of Object.values(state.authorized_macs || {})) {
    if (m.customer_id && !state.customers[m.customer_id]) {
      issues.push(`Orphan box ${m.mac}: refs missing customer_id ${m.customer_id}`);
    }
  }
  // 2. Family member references
  for (const cid of Object.keys(state.family_members || {})) {
    if (!state.customers[cid]) issues.push(`Family entries for missing customer ${cid}`);
  }
  // 3. Schedule references
  for (const cid of Object.keys(state.schedules || {})) {
    if (!state.customers[cid]) issues.push(`Schedules for missing customer ${cid}`);
    for (const s of (state.schedules[cid] || [])) {
      for (const fid of (s.family_ids || [])) {
        const fam = (state.family_members[cid] || []).find(f => f.id === fid);
        if (!fam) issues.push(`Schedule ${s.id} references missing family member ${fid}`);
      }
    }
  }
  // 4. Customer must have a plan in the price table
  for (const c of Object.values(state.customers || {})) {
    if (c.plan && !PLAN_PRICES[c.plan]) issues.push(`Customer ${c.id} has unknown plan: ${c.plan}`);
  }
  // 5. Sites references
  for (const s of Object.values(state.sites || {})) {
    if (!state.customers[s.customer_id]) issues.push(`Site ${s.id} refs missing customer ${s.customer_id}`);
  }
  // 6. WG peers references
  for (const p of Object.values(state.wg_peers || {})) {
    if (!state.customers[p.customer_id]) issues.push(`WG peer ${p.id} refs missing customer ${p.customer_id}`);
  }
  // 7. Notifications/usage with no customer
  for (const cid of Object.keys(state.notifications || {})) {
    if (!state.customers[cid]) issues.push(`Notifications for missing customer ${cid}`);
  }
  // 8. Threat feed shape
  if (state.threat_feeds && !Array.isArray(state.threat_feeds.domains)) {
    issues.push('threat_feeds.domains is not an array');
  }
  // 9. Required top-level keys
  for (const k of ['customers','authorized_macs','events','admin_actions','box_state']) {
    if (!state[k]) issues.push(`Missing required state key: ${k}`);
  }

  state._integrity = { last_run: Date.now(), issue_count: issues.length, issues: issues.slice(0, 50) };
  if (issues.length > 0) {
    console.error(`         🚨 STATE INTEGRITY: ${issues.length} issues found:`);
    issues.slice(0, 5).forEach(i => console.error(`            - ${i}`));
    // Alarm super-admin (only if more than threshold or critical)
    if (issues.length >= 5) {
      sendEmail(state.config.admin_email,
        `[mes Network] 🚨 State integrity check found ${issues.length} issues`,
        'Issues:\n\n' + issues.slice(0, 30).join('\n') + (issues.length > 30 ? `\n\n…and ${issues.length - 30} more` : ''));
    }
  } else {
    console.log('         ✓ state integrity OK');
  }
}
setInterval(runStateIntegrityCheck, 6 * 3600_000);  // every 6 hours
setTimeout(runStateIntegrityCheck, 5 * 60_000);     // first run 5 min after boot

// Backup restore verification — periodically validate that the most recent backup file
// in /var/backups parses correctly + has all required keys.
function verifyBackups() {
  const dir = '/var/backups';
  let result = { last_check: Date.now(), backup_count: 0, latest: null, valid: false, error: null };
  try {
    if (!fs.existsSync(dir)) {
      result.error = 'backup dir missing';
      state._backup_check = result;
      return;
    }
    const files = fs.readdirSync(dir).filter(f => f.startsWith('mes-cloud-') && f.endsWith('.json'));
    result.backup_count = files.length;
    if (files.length === 0) {
      result.error = 'no backups found';
      state._backup_check = result;
      return;
    }
    // Check most recent (sort by name — daily filenames are date-keyed)
    files.sort();
    const latest = files[files.length - 1];
    result.latest = { name: latest, size: 0, mtime: null };
    const fullPath = path.join(dir, latest);
    const stat = fs.statSync(fullPath);
    result.latest.size = stat.size;
    result.latest.mtime = stat.mtime;
    // Try to parse it
    const raw = fs.readFileSync(fullPath, 'utf8');
    const parsed = JSON.parse(raw);
    // Check required top-level keys
    const required = ['customers','authorized_macs'];
    const missing = required.filter(k => !parsed[k] && !(parsed.state && parsed.state[k]));
    if (missing.length > 0) {
      result.error = 'missing keys: ' + missing.join(', ');
    } else {
      result.valid = true;
      result.customer_count_in_backup = Object.keys((parsed.state && parsed.state.customers) || parsed.customers || {}).length;
    }
  } catch (e) {
    result.error = e.message;
  }
  state._backup_check = result;
  if (!result.valid) {
    console.error(`         🚨 BACKUP CHECK FAILED: ${result.error}`);
    if (state.config.admin_email) {
      sendEmail(state.config.admin_email,
        '[mes Network] 🚨 Backup verification failed',
        `Backup check failed at ${new Date().toISOString()}\n\nLatest: ${result.latest && result.latest.name}\nError: ${result.error}\n\nCheck /var/backups on the host.`);
    }
  } else {
    console.log(`         ✓ backup verified: ${result.latest.name} (${result.customer_count_in_backup} customers, ${(result.latest.size/1024/1024).toFixed(1)} MB)`);
  }
}
setInterval(verifyBackups, 6 * 3600_000);
setTimeout(verifyBackups, 10 * 60_000);  // 10 min after boot

app.get('/admin/api/backup-check', adminAuth, (req, res) => {
  res.json(state._backup_check || { error: 'not yet run' });
});
app.post('/admin/api/backup-check/run', adminAuth, (req, res) => {
  verifyBackups();
  res.json(state._backup_check);
});

app.get('/admin/api/integrity', adminAuth, (req, res) => {
  res.json(state._integrity || { last_run: null, issue_count: null });
});
app.post('/admin/api/integrity/run', adminAuth, (req, res) => {
  runStateIntegrityCheck();
  res.json(state._integrity);
});
app.post('/admin/api/integrity/autofix', adminAuth, (req, res) => {
  if (req.adminRole && req.adminRole !== 'super') return res.status(403).json({ error: 'super-admin only' });
  const fixes = [];

  // 1. Drop orphan-customer keyed maps
  for (const k of ['family_members','schedules','rules','quotas','qos_rules','notifications','support_threads',
                   'dns_records','dns_upstreams','port_forwards','dhcp_leases','device_tags','time_bank',
                   'usage_monthly','usage_daily','subscription_history','nps_responses','dns_queries',
                   'vlans','guest_wifi','vpn_routed_macs','s2s_tunnels','reboot_schedules']) {
    if (!state[k]) continue;
    for (const cid of Object.keys(state[k])) {
      if (!state.customers[cid]) {
        delete state[k][cid];
        fixes.push(`Removed orphan ${k}[${cid}]`);
      }
    }
  }
  // 2. Schedule references to missing family members
  for (const cid of Object.keys(state.schedules || {})) {
    for (const s of (state.schedules[cid] || [])) {
      const validFids = (state.family_members[cid] || []).map(f => f.id);
      const before = (s.family_ids || []).length;
      s.family_ids = (s.family_ids || []).filter(fid => validFids.includes(fid));
      if (s.family_ids.length < before) fixes.push(`Pruned ${before - s.family_ids.length} bad family_id from schedule ${s.id}`);
    }
  }
  // 3. Drop sites/wg_peers belonging to deleted customers
  for (const map of ['sites','wg_peers']) {
    for (const k of Object.keys(state[map] || {})) {
      if (!state.customers[state[map][k].customer_id]) {
        delete state[map][k];
        fixes.push(`Removed orphan ${map}[${k}]`);
      }
    }
  }
  // 4. Customer-API keys for deleted customers
  if (state.customer_api_keys) {
    for (const k of Object.keys(state.customer_api_keys)) {
      if (!state.customers[state.customer_api_keys[k].customer_id]) {
        delete state.customer_api_keys[k];
        fixes.push(`Removed orphan api_key ${k.slice(0, 8)}...`);
      }
    }
  }
  // 5. Drop demo customers' lingering data — done by unseed-demo, but be defensive
  // 6. Re-run integrity to confirm clean
  runStateIntegrityCheck();
  saveState();
  logAdminAction(req, 'integrity.autofix', '', `fixes=${fixes.length}`);
  console.log(`         🧹 INTEGRITY AUTO-FIX → applied ${fixes.length} fixes`);
  res.json({ ok: true, fixes_applied: fixes.length, fixes: fixes.slice(0, 50), remaining_issues: state._integrity.issue_count });
});

// ─── Hardware-shipping requests ─────
// state.hw_orders = { id: { customer_id, address, phone, model, notes, status, created_at, status_history: [] } }
if (!state.hw_orders) state.hw_orders = {};

const HW_STATUSES = ['received','prepping','shipping','delivered','cancelled'];

app.post('/api/customer/hw-order', customerAuth, (req, res) => {
  const c = req.customer;
  const id = 'hwo-' + shortId(10);
  const o = {
    id, customer_id: c.id,
    customer_name: c.name,
    customer_phone: c.phone,
    address: String(req.body.address || c.address || '').slice(0, 300),
    contact_phone: String(req.body.contact_phone || c.phone || '').slice(0, 30),
    model: String(req.body.model || 'pi4-pre-flashed').slice(0, 30),
    notes: String(req.body.notes || '').slice(0, 500),
    status: 'received',
    created_at: Date.now(),
    status_history: [{ status: 'received', ts: Date.now(), actor: 'customer' }],
  };
  if (!o.address) return res.status(400).json({ error: 'shipping address required' });
  state.hw_orders[id] = o;
  saveState();
  state.events.push({ ts: Date.now(), method: 'CUSTOMER', path: `[HW-ORDER] ${c.name} → ${o.model}`, ip: req.ip });
  if (typeof broadcastSSE === 'function') broadcastSSE('hw_order', o);
  if (state.config.admin_email) {
    sendEmail(state.config.admin_email, `[mes Network] 📦 Hardware order from ${c.name}`,
      `New box order:\n\nCustomer: ${c.name} (${c.phone})\nAddress: ${o.address}\nContact: ${o.contact_phone}\nModel: ${o.model}\nNotes: ${o.notes || '(none)'}\n\nView all orders at /admin → Hardware orders.`);
  }
  res.json({ ok: true, order_id: id });
});

app.get('/api/customer/hw-orders', customerAuth, (req, res) => {
  const mine = Object.values(state.hw_orders).filter(o => o.customer_id === req.customer.id);
  res.json({ orders: mine });
});

app.get('/admin/api/hw-orders', adminAuth, (req, res) => {
  res.json({ orders: Object.values(state.hw_orders).sort((a, b) => b.created_at - a.created_at) });
});
app.post('/admin/api/hw-orders/update-status', adminAuth, (req, res) => {
  const o = state.hw_orders[req.body.id];
  if (!o) return res.status(404).json({ error: 'not found' });
  if (!HW_STATUSES.includes(req.body.status)) return res.status(400).json({ error: 'bad status', allowed: HW_STATUSES });
  o.status = req.body.status;
  o.status_history.push({ status: req.body.status, ts: Date.now(), actor: req.adminUser || 'admin', note: req.body.note || '' });
  saveState();
  pushNotification(o.customer_id, 'system', '📦 Box order update', `Status: ${o.status}` + (req.body.note ? ` — ${req.body.note}` : ''));
  logAdminAction(req, 'hw-order.status', o.id, req.body.status);
  res.json({ ok: true });
});

// ─── Plan-upgrade requests ─────
// state.plan_requests = { id: { customer_id, current_plan, requested_plan, note, status, created_at, decided_at, decided_by } }
if (!state.plan_requests) state.plan_requests = {};

app.get('/api/customer/plan-request', customerAuth, (req, res) => {
  const mine = Object.values(state.plan_requests).filter(r => r.customer_id === req.customer.id);
  res.json({ requests: mine, current_plan: req.customer.plan, available_plans: Object.keys(PLAN_PRICES) });
});
app.post('/api/customer/plan-request', customerAuth, (req, res) => {
  const c = req.customer;
  const requested = req.body.requested_plan;
  if (!PLAN_PRICES[requested]) return res.status(400).json({ error: 'invalid plan' });
  if (requested === c.plan) return res.status(400).json({ error: 'same plan' });
  // Cancel any pending earlier requests
  for (const r of Object.values(state.plan_requests)) {
    if (r.customer_id === c.id && r.status === 'pending') r.status = 'superseded';
  }
  const id = 'plan-' + shortId(10);
  state.plan_requests[id] = {
    id, customer_id: c.id, current_plan: c.plan,
    requested_plan: requested,
    note: String(req.body.note || '').slice(0, 200),
    status: 'pending',
    created_at: Date.now(),
  };
  saveState();
  // Notify admins
  state.events.push({ ts: Date.now(), method: 'CUSTOMER', path: `[PLAN-REQ] ${c.name}: ${c.plan} → ${requested}`, ip: req.ip });
  fireWebhooks('plan.requested', { id, customer_id: c.id, customer_name: c.name, current_plan: c.plan, requested_plan: requested });
  res.json({ ok: true, id });
});

app.get('/admin/api/plan-requests', adminAuth, (req, res) => {
  const out = Object.values(state.plan_requests).map(r => {
    const c = state.customers[r.customer_id] || {};
    return { ...r, customer_name: c.name || '', customer_phone: c.phone || '' };
  }).sort((a, b) => b.created_at - a.created_at);
  res.json({ requests: out });
});
app.post('/admin/api/plan-requests/decide', adminAuth, (req, res) => {
  const r = state.plan_requests[req.body.id];
  if (!r) return res.status(404).json({ error: 'not found' });
  const decision = req.body.decision === 'approve' ? 'approved' : 'declined';
  r.status = decision;
  r.decided_at = Date.now();
  r.decided_by = req.adminUser || 'admin';
  r.decision_note = String(req.body.note || '').slice(0, 200);
  if (decision === 'approved') {
    const c = state.customers[r.customer_id];
    if (c) {
      recordPlanChange(c, r.requested_plan, 'plan_request_approved', r.decided_by);
      c.plan = r.requested_plan;
    }
    pushNotification(r.customer_id, 'billing', 'Plan upgraded', `Your account is now on the ${r.requested_plan} plan.`);
  } else {
    pushNotification(r.customer_id, 'billing', 'Plan request declined', r.decision_note || 'Contact support for details.');
  }
  saveState();
  logAdminAction(req, 'plan.' + decision, r.customer_id, r.current_plan + '→' + r.requested_plan);
  res.json({ ok: true });
});

// ─── Subscription history (per customer plan-change log) ─────
// state.subscription_history = { customer_id: [ {ts, from_plan, to_plan, reason, actor} ] }
if (!state.subscription_history) state.subscription_history = {};

function recordPlanChange(customer, newPlan, reason, actor) {
  if (!customer || customer.plan === newPlan) return;
  if (!state.subscription_history[customer.id]) state.subscription_history[customer.id] = [];
  const planTier = (p) => ({ basic: 1, family: 2, pro: 3, business: 4 })[p] || 0;
  const isDowngrade = planTier(newPlan) < planTier(customer.plan);
  state.subscription_history[customer.id].push({
    ts: Date.now(),
    from_plan: customer.plan,
    to_plan: newPlan,
    reason: reason || 'admin_update',
    actor: actor || 'system',
    downgrade: isDowngrade,
  });
  // 30-day grace: lower limits don't enforce immediately. We attach a record
  // that planDeviceCap() / quota checks consult.
  if (isDowngrade) {
    customer.downgrade_grace_until = Date.now() + 30 * 86400_000;
    customer.downgrade_from_plan = customer.plan;
    customer.downgrade_to_plan   = newPlan;
    if (typeof pushNotification === 'function') {
      pushNotification(customer.id, 'billing',
        `📉 Plan downgrade: ${customer.plan} → ${newPlan}`,
        `Your previous plan's limits remain active for 30 days. Adjust devices, rules, etc. before grace ends to avoid service degradation.`);
    }
  } else {
    // Upgrade clears any pending grace
    delete customer.downgrade_grace_until;
    delete customer.downgrade_from_plan;
    delete customer.downgrade_to_plan;
  }
}

app.get('/api/customer/subscription-history', customerAuth, (req, res) => {
  res.json({ history: state.subscription_history[req.customer.id] || [] });
});

app.get('/admin/api/customer/:cid/subscription-history', adminAuth, (req, res) => {
  res.json({ history: state.subscription_history[req.params.cid] || [] });
});

// ─── QoS / bandwidth throttling per device ─────
// state.qos_rules = { customer_id: [ { id, device_mac, down_kbps, up_kbps, label } ] }
if (!state.qos_rules) state.qos_rules = {};
app.get('/api/customer/qos', customerAuth, (req, res) => {
  res.json({ rules: state.qos_rules[req.customer.id] || [] });
});
app.post('/api/customer/qos/set', customerAuth, (req, res) => {
  const c = req.customer;
  const mac = normalizeMac(req.body.device_mac || '');
  const down_kbps = parseInt(req.body.down_kbps) || 0;
  const up_kbps   = parseInt(req.body.up_kbps)   || 0;
  if (!mac) return res.status(400).json({ error: 'device_mac required' });
  if (down_kbps < 0 || up_kbps < 0 || down_kbps > 10_000_000 || up_kbps > 10_000_000) {
    return res.status(400).json({ error: 'kbps out of range' });
  }
  if (!state.qos_rules[c.id]) state.qos_rules[c.id] = [];
  const list = state.qos_rules[c.id];
  const existing = list.find(r => r.device_mac === mac);
  const rule = existing || { id: shortId(10), device_mac: mac, created_at: Date.now() };
  rule.down_kbps = down_kbps;
  rule.up_kbps = up_kbps;
  rule.label = String(req.body.label || '').slice(0, 60);
  if (!existing) list.push(rule);
  saveState();
  res.json({ ok: true, rule });
});
app.post('/api/customer/qos/delete', customerAuth, (req, res) => {
  const list = state.qos_rules[req.customer.id] || [];
  const i = list.findIndex(r => r.id === req.body.id);
  if (i < 0) return res.status(404).json({ error: 'not found' });
  list.splice(i, 1);
  saveState();
  res.json({ ok: true });
});

// ─── Vacation mode (per customer) ─────
// Single toggle that applies stricter rules and (optionally) emails a weekly digest.
app.get('/api/customer/vacation', customerAuth, (req, res) => {
  const c = req.customer;
  res.json({
    active: !!c.vacation_active,
    started_at: c.vacation_started_at || null,
    until:      c.vacation_until || null,
  });
});
app.post('/api/customer/vacation/toggle', customerAuth, (req, res) => {
  const c = state.customers[req.customer.id];
  if (!c) return res.status(404).json({ error: 'not found' });
  if (c.vacation_active) {
    c.vacation_active = false;
    c.vacation_started_at = null;
    c.vacation_until = null;
    pushNotification(c.id, 'system', 'Vacation mode off', 'Welcome back. Normal rules resumed.');
  } else {
    c.vacation_active = true;
    c.vacation_started_at = Date.now();
    c.vacation_until = req.body.until || (Date.now() + 14 * 24 * 3600_000);
    pushNotification(c.id, 'system', 'Vacation mode on',
      'Stricter blocking active. We\'ll email you a weekly summary while you\'re away.');
  }
  saveState();
  res.json({ ok: true, active: c.vacation_active, until: c.vacation_until });
});

// ─── Custom DNS records (per customer) ─────
// Like a personal /etc/hosts: hostname → IP for things like home.lan, nas.local.
if (!state.dns_records) state.dns_records = {};   // { customer_id: [ {id, hostname, ip, ttl, created_at} ] }
app.get('/api/customer/dns-records', customerAuth, (req, res) => {
  res.json({ records: state.dns_records[req.customer.id] || [] });
});
app.post('/api/customer/dns-records/add', customerAuth, (req, res) => {
  const c = req.customer;
  const hostname = String(req.body.hostname || '').toLowerCase().trim().slice(0, 200);
  const ip = String(req.body.ip || '').trim();
  if (!/^[a-z0-9][a-z0-9.\-]*[a-z0-9]$/.test(hostname)) return res.status(400).json({ error: 'invalid hostname' });
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return res.status(400).json({ error: 'invalid ip' });
  if (!state.dns_records[c.id]) state.dns_records[c.id] = [];
  // Replace if hostname already exists
  const existing = state.dns_records[c.id].find(r => r.hostname === hostname);
  if (existing) {
    existing.ip = ip;
  } else {
    state.dns_records[c.id].push({
      id: shortId(10), hostname, ip, ttl: parseInt(req.body.ttl) || 300, created_at: Date.now(),
    });
  }
  saveState();
  res.json({ ok: true });
});
app.post('/api/customer/dns-records/delete', customerAuth, (req, res) => {
  const list = state.dns_records[req.customer.id] || [];
  const i = list.findIndex(r => r.id === req.body.id);
  if (i < 0) return res.status(404).json({ error: 'not found' });
  list.splice(i, 1);
  saveState();
  res.json({ ok: true });
});

// ─── custom DNS upstream per customer ─────
app.get('/api/customer/dns-upstreams', customerAuth, (req, res) => {
  res.json({ upstreams: state.dns_upstreams[req.customer.id] || [] });
});
app.post('/api/customer/dns-upstreams/set', customerAuth, (req, res) => {
  const list = Array.isArray(req.body.upstreams) ? req.body.upstreams : [];
  const cleaned = list.map(s => String(s).trim()).filter(s => /^[\d.]+$/.test(s)).slice(0, 4);
  state.dns_upstreams[req.customer.id] = cleaned;
  saveState();
  res.json({ ok: true, upstreams: cleaned });
});

// Bump global policy etag — forces all box agents to fetch fresh policy on next sync
function bumpPolicyEtagGlobal(reason) {
  state._policy_global_version = (state._policy_global_version || 0) + 1;
  state._policy_last_bump = Date.now();
  state._policy_last_bump_reason = reason || '';
  if (typeof broadcastSSE === 'function') broadcastSSE('policy_changed', { reason, ts: Date.now() });
}

// Cloud resolves blocked domains → IPs hourly so the agent can do IP-level enforcement
async function resolveBlockedDomainIps() {
  // Limit to 200 most-popular domains to keep DNS load manageable
  const sample = (state.threat_feeds.domains || []).slice(0, 200);
  const out = new Set();
  await Promise.all(sample.map(d => new Promise(r => {
    require('dns').resolve4(d, { ttl: false }, (err, addrs) => {
      if (!err && Array.isArray(addrs)) for (const ip of addrs) out.add(ip);
      r();
    });
  })));
  state.threat_feeds.ips = Array.from(out);
  saveState();
  console.log(`         🛡️  Resolved ${out.size} threat IPs from top 200 domains`);
}
setTimeout(resolveBlockedDomainIps, 5 * 60_000);
setInterval(resolveBlockedDomainIps, 60 * 60_000);

// ───── Admin can list/manage flows + alarms
app.get('/admin/api/flows', adminAuth, (req, res) => {
  const cust = req.query.customer_id;
  const limit = Math.min(parseInt(req.query.limit || 200), 5000);
  let out = state.flows;
  if (cust) out = out.filter(f => f.customer_id === cust);
  res.json({ flows: out.slice(-limit).reverse(), total: out.length });
});
app.get('/api/customer/flows', customerAuth, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || 100), 1000);
  const ruleFilter = req.query.rule_id || null;
  let out = state.flows.filter(f => f.customer_id === req.customer.id);
  if (ruleFilter) out = out.filter(f => f.matched_rule_id === ruleFilter);
  // Decorate each flow with `matched_by` (the human-readable rule label)
  const myRules = state.rules[req.customer.id] || [];
  const ruleById = Object.fromEntries(myRules.map(r => [r.id, r]));
  const decorated = out.slice(-limit).reverse().map(f => {
    const r = f.matched_rule_id ? ruleById[f.matched_rule_id] : null;
    return { ...f, matched_by: r ? `${r.action} ${r.type}:${r.value}` : null };
  });
  res.json({ flows: decorated, total: out.length });
});

// Per-rule details + recent flows that matched it
app.get('/api/customer/rule/:id/details', customerAuth, (req, res) => {
  const cid = req.customer.id;
  const rule = (state.rules[cid] || []).find(r => r.id === req.params.id);
  if (!rule) return res.status(404).json({ error: 'rule_not_found' });
  const hits = (state.rule_hits && state.rule_hits[rule.id]) || { total: 0, last_hit_ts: 0, daily: {} };
  // Last 50 flows that matched this rule
  const matched = state.flows.filter(f => f.customer_id === cid && f.matched_rule_id === rule.id).slice(-50).reverse();
  res.json({ rule, hits, recent_flows: matched });
});
// Hour-of-day × day-of-week traffic heatmap (last 7 days). Optional ?mac=
app.get('/api/customer/flow-heatmap', customerAuth, (req, res) => {
  const cutoff = Date.now() - 7 * 86400_000;
  const macFilter = (req.query.mac || '').toLowerCase();
  // grid[dow][hour] = bytes
  const grid = Array.from({ length: 7 }, () => new Array(24).fill(0));
  let total = 0;
  for (const f of state.flows) {
    if (f.customer_id !== req.customer.id) continue;
    if (f.ts < cutoff) continue;
    if (macFilter && (f.src_mac || '').toLowerCase() !== macFilter) continue;
    const d = new Date(f.ts);
    const dow = d.getDay(); // 0=Sun
    const hr = d.getHours();
    const bytes = (f.bytes_up || 0) + (f.bytes_down || 0);
    grid[dow][hr] += bytes;
    total += bytes;
  }
  res.json({ grid, total_bytes: total, window_days: 7, mac_filter: macFilter || null });
});
app.get('/admin/api/alarms', adminAuth, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || 200), 5000);
  res.json({ alarms: state.alarms.slice(0, limit) });
});
app.get('/api/customer/alarms', customerAuth, (req, res) => {
  // By default exclude archived (Firewalla "Archive" = soft delete from default
  // view but kept queryable). Pass ?include_archived=1 to see them.
  const incArch = req.query.include_archived === '1';
  const out = state.alarms.filter(a => a.customer_id === req.customer.id && (incArch || !a.archived)).slice(0, 500);
  res.json({ alarms: out });
});
// Clustered (de-noised) alarm view — groups by `dedup_key` (kind|device|target|hour-bucket).
// Returned shape: [{ cluster_key, latest, count, first_ts, last_ts, alarm_ids: [...] }]
// The raw `/api/customer/alarms` endpoint stays granular for forensic export.
app.get('/api/customer/alarms-clustered', customerAuth, (req, res) => {
  const incArch = req.query.include_archived === '1';
  const mine = state.alarms.filter(a => a.customer_id === req.customer.id && (incArch || !a.archived)).slice(0, 2000);
  const clusters = new Map();
  for (const a of mine) {
    // Back-fill dedup_key for legacy alarms that pre-date this feature.
    const key = a.dedup_key || `${a.kind}|${(a.device_mac||'').toLowerCase()}|${(a.dst_domain||a.dst_ip||'any').toLowerCase()}|${Math.floor((a.ts||0)/3600000)}`;
    let c = clusters.get(key);
    if (!c) {
      c = { cluster_key: key, latest: a, count: 0, first_ts: a.ts, last_ts: a.ts, alarm_ids: [] };
      clusters.set(key, c);
    }
    c.count++;
    c.alarm_ids.push(a.id);
    if ((a.ts || 0) > (c.last_ts || 0)) { c.last_ts = a.ts; c.latest = a; }
    if ((a.ts || 0) < (c.first_ts || 0)) c.first_ts = a.ts;
  }
  const out = Array.from(clusters.values()).sort((x, y) => (y.last_ts || 0) - (x.last_ts || 0)).slice(0, 500);
  res.json({ clusters: out });
});
app.post('/api/customer/alarms/ack', customerAuth, (req, res) => {
  const a = state.alarms.find(x => x.id === req.body.id && x.customer_id === req.customer.id);
  if (!a) return res.status(404).json({ error: 'not found' });
  a.acked = true;
  saveState();
  res.json({ ok: true });
});
// Firewalla parity: Archive (soft-delete from view but keep history)
app.post('/api/customer/alarms/archive', customerAuth, (req, res) => {
  const a = state.alarms.find(x => x.id === req.body.id && x.customer_id === req.customer.id);
  if (!a) return res.status(404).json({ error: 'not found' });
  a.archived = true; a.acked = true;
  saveState();
  res.json({ ok: true });
});
// One-tap "Block this source" — creates a rule from an alarm. Best-effort
// inference: prefer dst_domain (DNS block) over dst_ip (IP block) over
// device_mac (block the device itself).
app.post('/api/customer/alarms/block-source', customerAuth, (req, res) => {
  const a = state.alarms.find(x => x.id === req.body.id && x.customer_id === req.customer.id);
  if (!a) return res.status(404).json({ error: 'not found' });
  const c = req.customer;
  if (!state.rules[c.id]) state.rules[c.id] = [];
  let type, value;
  if (a.dst_domain) { type = 'domain'; value = a.dst_domain; }
  else if (a.dst_ip) { type = 'ip'; value = a.dst_ip; }
  else if (a.device_mac) { type = 'mac'; value = a.device_mac.toLowerCase(); }
  else return res.status(400).json({ error: 'alarm has no blockable target' });
  // Avoid duplicate rule
  const exists = state.rules[c.id].some(r => r.type === type && (r.value || '').toLowerCase() === value.toLowerCase() && r.action === 'block' && r.enabled !== false);
  let rule = null;
  if (!exists) {
    rule = {
      id: shortId(12), type, value, action: 'block',
      scope: 'all', target: '', enabled: true,
      note: `from-alarm:${a.kind}`, created_at: Date.now(),
    };
    state.rules[c.id].push(rule);
  }
  a.archived = true; a.acked = true;
  a.action_taken = `block-${type}:${value}`;
  if (typeof bumpPolicyEtag === 'function') bumpPolicyEtag(c.id, 'alarm-block-source');
  saveState();
  res.json({ ok: true, rule, blocked: { type, value }, already_existed: exists });
});

// ───── Box fleet (admin view)
app.get('/admin/api/boxes', adminAuth, (req, res) => {
  const out = Object.entries(state.box_state).map(([mac, s]) => {
    const m = state.authorized_macs[mac] || {};
    const c = m.customer_id ? state.customers[m.customer_id] : null;
    return {
      mac,
      customer_id: m.customer_id,
      customer_name: c ? c.name : null,
      online: s.last_heartbeat && (Date.now() - s.last_heartbeat) < 5 * 60_000,
      last_heartbeat: s.last_heartbeat,
      public_ip: s.public_ip,
      version: s.version,
      device_count: s.device_count,
      cpu_pct: s.cpu_pct,
      ram_pct: s.ram_pct,
      temp_c: s.temp_c,
      uptime_s: s.uptime_s,
    };
  });
  res.json({ boxes: out });
});

// Customer-facing variant — only their own boxes
app.get('/api/customer/boxes', customerAuth, (req, res) => {
  const cid = req.customer.id;
  const myMacs = Object.values(state.authorized_macs).filter(m => m.customer_id === cid);
  const out = myMacs.map(m => {
    const s = state.box_state[m.mac] || {};
    return {
      mac: m.mac,
      type: m.type,
      friendly_name: m.friendly_name || '',
      authorized_at: m.authorized_at,
      online: s.last_heartbeat && (Date.now() - s.last_heartbeat) < 5 * 60_000,
      last_heartbeat: s.last_heartbeat || null,
      public_ip: s.public_ip || null,
      version: s.version || null,
      device_count: s.device_count || 0,
      cpu_pct: s.cpu_pct || 0,
      ram_pct: s.ram_pct || 0,
      temp_c: s.temp_c || null,
      uptime_s: s.uptime_s || 0,
    };
  });
  res.json({ boxes: out });
});

// Customer can rename their box
app.post('/api/customer/box/rename', customerAuth, (req, res) => {
  const mac = normalizeMac(req.body.mac || '');
  const m = state.authorized_macs[mac];
  if (!m || m.customer_id !== req.customer.id) return res.status(404).json({ error: 'not your box' });
  m.friendly_name = String(req.body.friendly_name || '').slice(0, 60).trim();
  saveState();
  res.json({ ok: true, mac, friendly_name: m.friendly_name });
});

// ═══════════════════════════════════════════════════════════════════════════
//  WIREGUARD VPN — server config + per-device peer generation
// ═══════════════════════════════════════════════════════════════════════════
function wgGenKeypair() {
  // Use Node's crypto to generate an X25519 keypair (WG-compatible)
  const kp = crypto.generateKeyPairSync('x25519');
  const priv = kp.privateKey.export({ type: 'pkcs8', format: 'der' });
  const pub  = kp.publicKey.export({ type: 'spki',  format: 'der' });
  // The last 32 bytes of the DER are the raw X25519 key
  return {
    privkey: priv.slice(-32).toString('base64'),
    pubkey:  pub.slice(-32).toString('base64'),
  };
}
function ensureWgServer() {
  if (state.wg_server && state.wg_server.privkey) return state.wg_server;
  const kp = wgGenKeypair();
  state.wg_server = {
    ...kp,
    listen_port: 51820,
    network_cidr: '10.99.0.0/24',
    server_addr: '10.99.0.1',
    dns: '10.99.0.1, 1.1.1.1',
    next_peer_octet: 2,
  };
  saveState();
  return state.wg_server;
}

app.get('/api/customer/wg/peers', customerAuth, (req, res) => {
  const peers = Object.values(state.wg_peers).filter(p => p.customer_id === req.customer.id);
  res.json({ peers: peers.map(p => ({ id: p.id, label: p.device_label, address: p.address, created_at: p.created_at, pubkey: p.pubkey })) });
});

app.post('/api/customer/wg/peers/create', customerAuth, (req, res) => {
  const c = req.customer;
  if (!planLimits(c.plan).vpn) {
    return res.status(402).json({ error: 'plan_limit', message: 'WireGuard VPN is on Pro and Business plans.' });
  }
  const srv = ensureWgServer();
  const kp = wgGenKeypair();
  const id = shortId(12);
  const peer = {
    id,
    customer_id: c.id,
    device_label: String(req.body.label || 'My Device').slice(0, 60),
    pubkey: kp.pubkey,
    privkey: kp.privkey,  // in real product, generate on client; we generate here for convenience
    address: `10.99.0.${srv.next_peer_octet++}/32`,
    created_at: Date.now(),
  };
  state.wg_peers[id] = peer;
  saveState();
  pushNotification(c.id, 'system', 'WireGuard peer created', peer.device_label);
  res.json({ ok: true, peer: { id, label: peer.device_label, address: peer.address, pubkey: peer.pubkey } });
});

app.post('/api/customer/wg/peers/delete', customerAuth, (req, res) => {
  const p = state.wg_peers[req.body.id];
  if (!p || p.customer_id !== req.customer.id) return res.status(404).json({ error: 'not found' });
  delete state.wg_peers[req.body.id];
  saveState();
  res.json({ ok: true });
});

app.get('/api/customer/wg/peers/:id.conf', customerAuth, (req, res) => {
  const p = state.wg_peers[req.params.id];
  if (!p || p.customer_id !== req.customer.id) return res.status(404).json({ error: 'not found' });
  const srv = ensureWgServer();
  const endpoint = (state.config.brand_domain || 'cloud.mes.net.lb');
  const conf = `# mes Network — WireGuard config for ${p.device_label}
# Customer: ${req.customer.name}
# Generated: ${new Date().toISOString()}
[Interface]
PrivateKey = ${p.privkey}
Address = ${p.address}
DNS = ${srv.dns}

[Peer]
PublicKey = ${srv.pubkey}
AllowedIPs = 0.0.0.0/0
Endpoint = ${endpoint}:${srv.listen_port}
PersistentKeepalive = 25
`;
  res.set('Content-Type', 'text/plain');
  res.set('Content-Disposition', `attachment; filename="${p.device_label.replace(/[^a-z0-9]+/gi,'-')}.conf"`);
  res.send(conf);
});

// QR code as SVG (for scanning into the WireGuard mobile app)
app.get('/api/customer/wg/peers/:id.qr.svg', customerAuth, (req, res) => {
  const p = state.wg_peers[req.params.id];
  if (!p || p.customer_id !== req.customer.id) return res.status(404).json({ error: 'not found' });
  const srv = ensureWgServer();
  const endpoint = (state.config.brand_domain || 'cloud.mes.net.lb');
  const conf = `[Interface]
PrivateKey = ${p.privkey}
Address = ${p.address}
DNS = ${srv.dns}

[Peer]
PublicKey = ${srv.pubkey}
AllowedIPs = 0.0.0.0/0
Endpoint = ${endpoint}:${srv.listen_port}
PersistentKeepalive = 25
`;
  // Tiny QR encoder in pure JS would be heavy; emit a placeholder SVG that the PWA can replace via JS QR lib
  res.set('Content-Type', 'image/svg+xml');
  res.send(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256"><rect width="256" height="256" fill="#fff"/><text x="50%" y="50%" font-size="11" text-anchor="middle" font-family="monospace" fill="#000">WG config — render via JS</text><desc>${conf.replace(/[<>&]/g, c => ({ '<':'&lt;','>':'&gt;','&':'&amp;'}[c]))}</desc></svg>`);
});

// Admin: trigger WG server init + read public config
app.get('/admin/api/wg/server', adminAuth, (req, res) => {
  const srv = ensureWgServer();
  res.json({
    pubkey: srv.pubkey,
    listen_port: srv.listen_port,
    network_cidr: srv.network_cidr,
    server_addr: srv.server_addr,
    peer_count: Object.keys(state.wg_peers).length,
  });
});

// Box pulls the WG server config to set up its own peers (if customer's box runs as WG server)
app.get('/api/box/wg/server', boxAuth, (req, res) => {
  const srv = ensureWgServer();
  const peers = Object.values(state.wg_peers).filter(p => p.customer_id === req.boxCustomerId);
  res.json({
    server: { pubkey: srv.pubkey, listen_port: srv.listen_port, network_cidr: srv.network_cidr, server_addr: srv.server_addr },
    peers: peers.map(p => ({ pubkey: p.pubkey, allowed_ips: p.address, label: p.device_label })),
  });
});

// ═══════════════════════════════════════════════════════════════════════════
//  WG CLIENT — route home network OUT through a commercial VPN (Mullvad/Proton/etc)
//  conf_text lives only on the box; cloud holds metadata + queues actions.
// ═══════════════════════════════════════════════════════════════════════════
function _vpnClientPickBox(c) {
  const myBoxes = Object.values(state.authorized_macs).filter(m => m.customer_id === c.id);
  if (!myBoxes.length) return null;
  return myBoxes[0].mac;
}
function _vpnClientList(cid) {
  if (!state.vpn_clients[cid]) state.vpn_clients[cid] = [];
  return state.vpn_clients[cid];
}
function _vpnClientParseEndpoint(conf_text) {
  const m = String(conf_text || '').match(/^\s*Endpoint\s*=\s*(.+)$/mi);
  return m ? m[1].trim() : '';
}

app.get('/api/customer/vpn-clients', customerAuth, (req, res) => {
  res.json({ profiles: _vpnClientList(req.customer.id) });
});

app.post('/api/customer/vpn-client/add', customerAuth, async (req, res) => {
  const c = req.customer;
  const label = String(req.body.label || '').trim().slice(0, 60);
  const conf_text = String(req.body.conf_text || '');
  const provider = String(req.body.provider || '').slice(0, 30);
  const country  = String(req.body.country  || '').slice(0, 30);
  if (!label) return res.status(400).json({ error: 'label_required' });
  for (const tok of ['[Interface]', 'PrivateKey', '[Peer]', 'Endpoint']) {
    if (conf_text.indexOf(tok) === -1) return res.status(400).json({ error: 'conf_invalid', missing: tok });
  }
  const mac = _vpnClientPickBox(c);
  if (!mac) return res.status(404).json({ error: 'no_box_assigned' });

  // Profile id is generated from the label on the box (must match wg-client.js logic)
  const slug = label.toLowerCase().replace(/[^a-z0-9]+/g, '').slice(0, 4) || 'vpn';
  const profile_id = 'mes-client-' + slug;

  const list = _vpnClientList(c.id);
  if (list.find(p => p.id === profile_id)) {
    return res.status(409).json({ error: 'profile_exists', profile_id });
  }
  const entry = {
    id: profile_id,
    label,
    provider: provider || null,
    endpoint: _vpnClientParseEndpoint(conf_text),
    country: country || null,
    active: false,
    created_at: Date.now(),
  };
  list.push(entry);
  state.vpn_clients[c.id] = list;

  if (!state.box_commands[mac]) state.box_commands[mac] = [];
  state.box_commands[mac].push({
    id: shortId(16),
    action: 'wg-client-add',
    args: { label, conf_text },
    status: 'pending', created_at: Date.now(), result: null, completed_at: null,
  });
  saveState();
  pushNotification(c.id, 'system', 'VPN client profile added', label);
  res.json({ ok: true, profile: entry });
});

app.post('/api/customer/vpn-client/start', customerAuth, (req, res) => {
  const c = req.customer;
  const id = String(req.body.id || '');
  const list = _vpnClientList(c.id);
  const entry = list.find(p => p.id === id);
  if (!entry) return res.status(404).json({ error: 'not_found' });
  const mac = _vpnClientPickBox(c);
  if (!mac) return res.status(404).json({ error: 'no_box_assigned' });
  // Mark this active, all others inactive (only one client active at a time)
  for (const p of list) p.active = (p.id === id);
  if (!state.box_commands[mac]) state.box_commands[mac] = [];
  state.box_commands[mac].push({
    id: shortId(16),
    action: 'wg-client-start',
    args: { profile_id: id },
    status: 'pending', created_at: Date.now(), result: null, completed_at: null,
  });
  saveState();
  res.json({ ok: true });
});

app.post('/api/customer/vpn-client/stop', customerAuth, (req, res) => {
  const c = req.customer;
  const id = String(req.body.id || '');
  const list = _vpnClientList(c.id);
  const entry = list.find(p => p.id === id);
  if (!entry) return res.status(404).json({ error: 'not_found' });
  const mac = _vpnClientPickBox(c);
  if (!mac) return res.status(404).json({ error: 'no_box_assigned' });
  entry.active = false;
  if (!state.box_commands[mac]) state.box_commands[mac] = [];
  state.box_commands[mac].push({
    id: shortId(16),
    action: 'wg-client-stop',
    args: { profile_id: id },
    status: 'pending', created_at: Date.now(), result: null, completed_at: null,
  });
  saveState();
  res.json({ ok: true });
});

app.delete('/api/customer/vpn-client/:id', customerAuth, (req, res) => {
  const c = req.customer;
  const id = String(req.params.id || '');
  const list = _vpnClientList(c.id);
  const idx = list.findIndex(p => p.id === id);
  if (idx === -1) return res.status(404).json({ error: 'not_found' });
  list.splice(idx, 1);
  const mac = _vpnClientPickBox(c);
  if (mac) {
    if (!state.box_commands[mac]) state.box_commands[mac] = [];
    state.box_commands[mac].push({
      id: shortId(16),
      action: 'wg-client-remove',
      args: { profile_id: id },
      status: 'pending', created_at: Date.now(), result: null, completed_at: null,
    });
  }
  saveState();
  res.json({ ok: true });
});

app.post('/api/customer/vpn-client/route-device', customerAuth, (req, res) => {
  const c = req.customer;
  const mac_raw = String(req.body.mac || '');
  if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(mac_raw)) return res.status(400).json({ error: 'bad_mac' });
  const mac = mac_raw.toLowerCase();
  // profile_id may be explicit null (un-route) or a real id
  const pid = (req.body.profile_id === null || req.body.profile_id === undefined) ? null : String(req.body.profile_id);
  if (pid !== null) {
    const entry = _vpnClientList(c.id).find(p => p.id === pid);
    if (!entry) return res.status(404).json({ error: 'profile_not_found' });
  }
  const boxMac = _vpnClientPickBox(c);
  if (!boxMac) return res.status(404).json({ error: 'no_box_assigned' });
  if (!state.box_commands[boxMac]) state.box_commands[boxMac] = [];
  state.box_commands[boxMac].push({
    id: shortId(16),
    action: 'wg-client-route-device',
    args: { mac, profile_id: pid },
    status: 'pending', created_at: Date.now(), result: null, completed_at: null,
  });
  saveState();
  res.json({ ok: true, mac, profile_id: pid });
});

// ═══════════════════════════════════════════════════════════════════════════
//  Firewalla parity: QoS, IoT lockdown, Quarantine, Security scans, OpenVPN client
// ═══════════════════════════════════════════════════════════════════════════
if (!state.security_scans) state.security_scans = {};        // mac → [{ ts, type, result }]
if (!state.box_internal_scans) state.box_internal_scans = {}; // mac → { ts, hosts: [...] }
if (!state.box_iot_learn) state.box_iot_learn = {};          // mac → [{ device_mac, endpoints, ts }]
if (!state.openvpn_clients) state.openvpn_clients = {};      // customer_id → [ { id, label, endpoint, active, created_at } ]

function _pickBoxForCust(c) {
  const myBoxes = Object.values(state.authorized_macs).filter(m => m.customer_id === c.id);
  return myBoxes.length ? myBoxes[0].mac : null;
}
function _queueBoxCmd(mac, action, args) {
  if (!state.box_commands[mac]) state.box_commands[mac] = [];
  const cmd = { id: shortId(16), action, args: args || {}, status: 'pending',
                created_at: Date.now(), result: null, completed_at: null };
  state.box_commands[mac].push(cmd);
  return cmd;
}

// ─── QoS / Smart Queue ──────────────────────────────────────────────────────
app.get('/api/customer/qos/status', customerAuth, (req, res) => {
  const mac = _pickBoxForCust(req.customer);
  if (!mac) return res.status(404).json({ error: 'no_box_assigned' });
  res.json({ ok: true, queued: _queueBoxCmd(mac, 'qos-status') });
});
app.post('/api/customer/qos/apply', customerAuth, (req, res) => {
  const mac = _pickBoxForCust(req.customer);
  if (!mac) return res.status(404).json({ error: 'no_box_assigned' });
  const down = parseInt(req.body.down_mbps) || 100;
  const up   = parseInt(req.body.up_mbps)   || 20;
  const wan  = String(req.body.wan_iface || '');
  res.json({ ok: true, queued: _queueBoxCmd(mac, 'qos-apply-cake', { down_mbps: down, up_mbps: up, wan_iface: wan || undefined }) });
});
app.post('/api/customer/qos/device-priority', customerAuth, (req, res) => {
  const mac = _pickBoxForCust(req.customer);
  if (!mac) return res.status(404).json({ error: 'no_box_assigned' });
  const dmac = String(req.body.mac || '').toLowerCase();
  const cls  = String(req.body.class || 'normal');
  if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(dmac)) return res.status(400).json({ error: 'bad_mac' });
  if (!['high', 'normal', 'low', 'throttle'].includes(cls)) return res.status(400).json({ error: 'bad_class' });
  res.json({ ok: true, queued: _queueBoxCmd(mac, 'qos-set-priority', { mac: dmac, class: cls }) });
});
if (!state.device_bw_caps) state.device_bw_caps = {};   // customer_id → [{mac, down_kbps, up_kbps, set_at}]
app.post('/api/customer/qos/device-cap', customerAuth, (req, res) => {
  const mac = _pickBoxForCust(req.customer);
  if (!mac) return res.status(404).json({ error: 'no_box_assigned' });
  const dmac = String(req.body.mac || '').toLowerCase();
  if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(dmac)) return res.status(400).json({ error: 'bad_mac' });
  const down_kbps = parseInt(req.body.down_kbps) || 0;
  const up_kbps   = parseInt(req.body.up_kbps)   || 0;
  const cid = req.customer.id;
  if (!state.device_bw_caps[cid]) state.device_bw_caps[cid] = [];
  state.device_bw_caps[cid] = state.device_bw_caps[cid].filter(c => c.mac !== dmac);
  if (down_kbps > 0 || up_kbps > 0) {
    state.device_bw_caps[cid].push({ mac: dmac, down_kbps, up_kbps, set_at: Date.now() });
  }
  saveState();
  res.json({ ok: true, queued: _queueBoxCmd(mac, 'qos-set-cap', { mac: dmac, down_kbps, up_kbps }) });
});
app.get('/api/customer/qos/caps', customerAuth, (req, res) => {
  res.json({ caps: state.device_bw_caps[req.customer.id] || [] });
});
app.post('/api/customer/qos/clear', customerAuth, (req, res) => {
  const mac = _pickBoxForCust(req.customer);
  if (!mac) return res.status(404).json({ error: 'no_box_assigned' });
  res.json({ ok: true, queued: _queueBoxCmd(mac, 'qos-clear') });
});

// ─── IoT lockdown ──────────────────────────────────────────────────────────
app.post('/api/customer/iot/learn', customerAuth, (req, res) => {
  const mac = _pickBoxForCust(req.customer);
  if (!mac) return res.status(404).json({ error: 'no_box_assigned' });
  const dmac = String(req.body.mac || '').toLowerCase();
  if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(dmac)) return res.status(400).json({ error: 'bad_mac' });
  const dur = parseInt(req.body.duration_s) || 600;
  res.json({ ok: true, queued: _queueBoxCmd(mac, 'iot-learn-start', { mac: dmac, duration_s: dur }) });
});
app.post('/api/customer/iot/enforce', customerAuth, (req, res) => {
  const mac = _pickBoxForCust(req.customer);
  if (!mac) return res.status(404).json({ error: 'no_box_assigned' });
  const dmac = String(req.body.mac || '').toLowerCase();
  if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(dmac)) return res.status(400).json({ error: 'bad_mac' });
  res.json({ ok: true, queued: _queueBoxCmd(mac, 'iot-enforce', { mac: dmac }) });
});
app.post('/api/customer/iot/disable', customerAuth, (req, res) => {
  const mac = _pickBoxForCust(req.customer);
  if (!mac) return res.status(404).json({ error: 'no_box_assigned' });
  const dmac = String(req.body.mac || '').toLowerCase();
  if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(dmac)) return res.status(400).json({ error: 'bad_mac' });
  res.json({ ok: true, queued: _queueBoxCmd(mac, 'iot-disable', { mac: dmac }) });
});
app.get('/api/customer/iot/locked', customerAuth, (req, res) => {
  const mac = _pickBoxForCust(req.customer);
  if (!mac) return res.status(404).json({ error: 'no_box_assigned' });
  res.json({ ok: true, queued: _queueBoxCmd(mac, 'iot-list-locked'), recent: state.box_iot_learn[mac] || [] });
});
// Box pushes its captured endpoints during learning
app.post('/api/box/iot-learn', boxAuth, (req, res) => {
  const boxMac = req.boxMac;
  const dmac = String(req.body.mac || '').toLowerCase();
  const endpoints = Array.isArray(req.body.endpoints) ? req.body.endpoints.slice(0, 1000) : [];
  if (!state.box_iot_learn[boxMac]) state.box_iot_learn[boxMac] = [];
  state.box_iot_learn[boxMac].unshift({
    device_mac: dmac, endpoints, ts: Date.now(),
  });
  if (state.box_iot_learn[boxMac].length > 50) state.box_iot_learn[boxMac].length = 50;
  saveState();
  res.json({ ok: true, stored: endpoints.length });
});

// ─── Quarantine ────────────────────────────────────────────────────────────
app.post('/api/customer/auto-quarantine', customerAuth, (req, res) => {
  const c = state.customers[req.customer.id];
  if (!c) return res.status(404).json({ error: 'no_customer' });
  c.auto_quarantine = !!req.body.enabled;
  // Bump policy etag so the box pulls the new flag soon
  if (typeof bumpPolicyEtag === 'function') bumpPolicyEtag(c.id, 'auto_quarantine');
  saveState();
  res.json({ ok: true, auto_quarantine: c.auto_quarantine });
});
app.get('/api/customer/auto-quarantine', customerAuth, (req, res) => {
  const c = state.customers[req.customer.id];
  res.json({ ok: true, auto_quarantine: !!(c && c.auto_quarantine) });
});
app.post('/api/customer/quarantine/add', customerAuth, (req, res) => {
  const mac = _pickBoxForCust(req.customer);
  if (!mac) return res.status(404).json({ error: 'no_box_assigned' });
  const dmac = String(req.body.mac || '').toLowerCase();
  if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(dmac)) return res.status(400).json({ error: 'bad_mac' });
  res.json({ ok: true, queued: _queueBoxCmd(mac, 'quarantine-add', { mac: dmac }) });
});
app.post('/api/customer/quarantine/approve', customerAuth, (req, res) => {
  const mac = _pickBoxForCust(req.customer);
  if (!mac) return res.status(404).json({ error: 'no_box_assigned' });
  const dmac = String(req.body.mac || '').toLowerCase();
  if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(dmac)) return res.status(400).json({ error: 'bad_mac' });
  res.json({ ok: true, queued: _queueBoxCmd(mac, 'quarantine-approve', { mac: dmac }) });
});
app.get('/api/customer/quarantine/list', customerAuth, (req, res) => {
  const mac = _pickBoxForCust(req.customer);
  if (!mac) return res.status(404).json({ error: 'no_box_assigned' });
  res.json({ ok: true, queued: _queueBoxCmd(mac, 'quarantine-list') });
});

// ─── External port scan (run on cloud, scan customer's public IP) ──────────
app.post('/api/customer/security/external-scan', customerAuth, (req, res) => {
  const mac = _pickBoxForCust(req.customer);
  if (!mac) return res.status(404).json({ error: 'no_box_assigned' });
  // Determine public IP from box state
  const bx = state.box_state[mac];
  const pubIp = (bx && bx.public_ip) || null;
  if (!pubIp) return res.status(400).json({ error: 'public_ip_unknown', hint: 'Wait for box to heartbeat first' });
  // Check for nmap on the cloud
  const { spawnSync } = require('child_process');
  const which = spawnSync('which', ['nmap']);
  if (which.status !== 0) {
    return res.status(503).json({ ok: false, error: 'nmap_not_installed', hint: 'Install nmap in the cloud container or contact support.' });
  }
  // Fire async
  if (!state.security_scans[mac]) state.security_scans[mac] = [];
  const entry = { id: shortId(10), ts: Date.now(), type: 'external', target: pubIp, status: 'running', result: null };
  state.security_scans[mac].unshift(entry);
  if (state.security_scans[mac].length > 20) state.security_scans[mac].length = 20;
  saveState();
  // Run nmap async; do not block the request
  setImmediate(() => {
    const r = spawnSync('nmap', ['-F', '-Pn', '--max-retries', '1', '--host-timeout', '90s', pubIp],
                        { encoding: 'utf8', timeout: 120_000 });
    const out = r.stdout || '';
    const ports = [];
    const reSvc = /^(\d+)\/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)/gm;
    let m;
    while ((m = reSvc.exec(out)) !== null && ports.length < 20) {
      ports.push({ port: parseInt(m[1], 10), proto: m[2], state: m[3], service: m[4] });
    }
    entry.status = r.status === 0 ? 'done' : 'error';
    entry.result = { ports, raw_tail: out.slice(-2000) };
    entry.completed_at = Date.now();
    saveState();
  });
  res.json({ ok: true, scan_id: entry.id, target: pubIp });
});
app.get('/api/customer/security/scans', customerAuth, (req, res) => {
  const mac = _pickBoxForCust(req.customer);
  if (!mac) return res.status(404).json({ error: 'no_box_assigned' });
  res.json({ ok: true, scans: state.security_scans[mac] || [], internal: state.box_internal_scans[mac] || null });
});

// ─── Internal vuln scan (queues on box) ────────────────────────────────────
app.post('/api/customer/security/internal-scan', customerAuth, (req, res) => {
  const mac = _pickBoxForCust(req.customer);
  if (!mac) return res.status(404).json({ error: 'no_box_assigned' });
  const cmd = _queueBoxCmd(mac, 'vuln-scan', req.body || {});
  res.json({ ok: true, queued: cmd });
});
app.get('/api/customer/security/internal-scan/:mac', customerAuth, (req, res) => {
  const m = req.params.mac.toLowerCase();
  if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(m)) return res.status(400).json({ error: 'bad_mac' });
  const auth = state.authorized_macs[m];
  if (!auth || auth.customer_id !== req.customer.id) return res.status(403).json({ error: 'not_your_box' });
  res.json({ ok: true, scan: state.box_internal_scans[m] || null });
});

// ─── OpenVPN client (mirrors WG client) ────────────────────────────────────
function _ovpnList(cid) { if (!state.openvpn_clients[cid]) state.openvpn_clients[cid] = []; return state.openvpn_clients[cid]; }
app.get('/api/customer/openvpn-clients', customerAuth, (req, res) => {
  res.json({ profiles: _ovpnList(req.customer.id) });
});
app.post('/api/customer/openvpn-client/add', customerAuth, (req, res) => {
  const c = req.customer;
  const label = String(req.body.label || '').trim().slice(0, 60);
  const ovpn_text = String(req.body.ovpn_text || '');
  if (!label) return res.status(400).json({ error: 'label_required' });
  if (ovpn_text.indexOf('remote ') === -1) return res.status(400).json({ error: 'ovpn_invalid', missing: 'remote' });
  const mac = _pickBoxForCust(c);
  if (!mac) return res.status(404).json({ error: 'no_box_assigned' });
  const slug = label.toLowerCase().replace(/[^a-z0-9]+/g, '').slice(0, 12) || 'vpn';
  const profile_id = 'mes-' + slug;
  const list = _ovpnList(c.id);
  if (list.find(p => p.id === profile_id)) return res.status(409).json({ error: 'profile_exists', profile_id });
  // Parse endpoint
  let endpoint = '';
  const em = ovpn_text.match(/^\s*remote\s+(\S+)\s+(\d+)/m);
  if (em) endpoint = `${em[1]}:${em[2]}`;
  const entry = { id: profile_id, label, endpoint, active: false, created_at: Date.now() };
  list.push(entry);
  state.openvpn_clients[c.id] = list;
  _queueBoxCmd(mac, 'ovpn-client-add', { label, ovpn_text });
  saveState();
  res.json({ ok: true, profile: entry });
});
app.post('/api/customer/openvpn-client/start', customerAuth, (req, res) => {
  const c = req.customer;
  const id = String(req.body.id || '');
  const list = _ovpnList(c.id);
  const entry = list.find(p => p.id === id);
  if (!entry) return res.status(404).json({ error: 'not_found' });
  const mac = _pickBoxForCust(c);
  if (!mac) return res.status(404).json({ error: 'no_box_assigned' });
  for (const p of list) p.active = (p.id === id);
  _queueBoxCmd(mac, 'ovpn-client-start', { profile_id: id });
  saveState();
  res.json({ ok: true });
});
app.post('/api/customer/openvpn-client/stop', customerAuth, (req, res) => {
  const c = req.customer;
  const id = String(req.body.id || '');
  const list = _ovpnList(c.id);
  const entry = list.find(p => p.id === id);
  if (!entry) return res.status(404).json({ error: 'not_found' });
  const mac = _pickBoxForCust(c);
  if (!mac) return res.status(404).json({ error: 'no_box_assigned' });
  entry.active = false;
  _queueBoxCmd(mac, 'ovpn-client-stop', { profile_id: id });
  saveState();
  res.json({ ok: true });
});
app.delete('/api/customer/openvpn-client/:id', customerAuth, (req, res) => {
  const c = req.customer;
  const id = String(req.params.id || '');
  const list = _ovpnList(c.id);
  const idx = list.findIndex(p => p.id === id);
  if (idx === -1) return res.status(404).json({ error: 'not_found' });
  list.splice(idx, 1);
  const mac = _pickBoxForCust(c);
  if (mac) _queueBoxCmd(mac, 'ovpn-client-remove', { profile_id: id });
  saveState();
  res.json({ ok: true });
});

// Box reports back its internal-scan result via the existing command-result
// endpoint; mirror it into state.box_internal_scans for fast retrieval.
// Hooked into the existing result handler below — see "_recordCommandResult".

// ════════════════════════════════════════════════════════════════════════
//  Tier 3 — VPN expansion: Tailscale, IPsec/IKEv2, AmneziaWG
// ════════════════════════════════════════════════════════════════════════
if (!state.ipsec_users) state.ipsec_users = {};        // customer_id → [ { id, username, created_at } ]
if (!state.tailscale_state) state.tailscale_state = {};// customer_id → { connected_at, hostname, advertise_routes, exit_node }
if (!state.awg_peers) state.awg_peers = {};            // customer_id → [ { id, label, ip, pubkey, created_at } ]

// Wait up to `timeout_ms` for an enqueued command to complete; resolve with
// the command's result (or null on timeout/missing). Avoids hard-coupling
// each consumer to the same polling loop.
async function _waitForCmd(mac, cmdId, timeout_ms = 12_000) {
  const deadline = Date.now() + timeout_ms;
  while (Date.now() < deadline) {
    await new Promise(r => setTimeout(r, 250));
    const q = state.box_commands[mac] || [];
    const c = q.find(x => x.id === cmdId);
    if (c && (c.status === 'completed' || c.status === 'failed')) {
      return { status: c.status, result: c.result };
    }
  }
  return { status: 'queued', result: null };
}

// ─── Feature A: Tailscale ─────────────────────────────────────────────────
app.post('/api/customer/tailscale/connect', customerAuth, async (req, res) => {
  const c = req.customer;
  const mac = _pickBoxForCust(c);
  if (!mac) return res.status(404).json({ error: 'no_box_assigned' });
  const auth_key = String(req.body.auth_key || '').trim();
  if (!auth_key) return res.status(400).json({ error: 'auth_key_required', hint: 'Generate at https://login.tailscale.com/admin/settings/keys' });
  const hostname = String(req.body.hostname || '').trim() || ('mes-box-' + mac.slice(-5).replace(/:/g, ''));
  const advertise_routes = Array.isArray(req.body.advertise_routes) ? req.body.advertise_routes :
                           (typeof req.body.advertise_routes === 'string' ? req.body.advertise_routes.split(',').map(s => s.trim()).filter(Boolean) : []);
  const exit_node_advertise = !!req.body.advertise_exit_node;
  const accept_routes = !!req.body.accept_routes;
  const login_server = req.body.login_server ? String(req.body.login_server).trim() : undefined;
  // Auto-discover LAN /24 if "advertise_lan" was passed and no explicit routes
  if (req.body.advertise_lan && advertise_routes.length === 0) {
    const bs = state.box_state[mac] || {};
    if (bs.internal_ip && /^\d+\.\d+\.\d+\.\d+$/.test(bs.internal_ip)) {
      advertise_routes.push(bs.internal_ip.split('.').slice(0, 3).join('.') + '.0/24');
    }
  }
  _queueBoxCmd(mac, 'tailscale-install', {});
  const upArgs = { auth_key, hostname, accept_routes, login_server };
  if (advertise_routes.length) upArgs.advertise_routes = advertise_routes;
  if (exit_node_advertise) upArgs.advertise_exit_node = true;
  const cmd = _queueBoxCmd(mac, 'tailscale-up', upArgs);
  state.tailscale_state[c.id] = {
    connected_at: Date.now(),
    hostname,
    advertise_routes,
    advertise_exit_node: exit_node_advertise,
  };
  saveState();
  res.json({ ok: true, queued_cmd_id: cmd.id, hostname, advertise_routes });
});
app.post('/api/customer/tailscale/disconnect', customerAuth, (req, res) => {
  const c = req.customer;
  const mac = _pickBoxForCust(c);
  if (!mac) return res.status(404).json({ error: 'no_box_assigned' });
  const cmd = _queueBoxCmd(mac, 'tailscale-down', {});
  if (state.tailscale_state[c.id]) delete state.tailscale_state[c.id];
  saveState();
  res.json({ ok: true, queued_cmd_id: cmd.id });
});
app.get('/api/customer/tailscale/status', customerAuth, async (req, res) => {
  const c = req.customer;
  const mac = _pickBoxForCust(c);
  if (!mac) return res.status(404).json({ error: 'no_box_assigned' });
  const bs = state.box_state[mac];
  const online = bs && (Date.now() - bs.last_heartbeat) < 5 * 60_000;
  if (!online) return res.json({ ok: false, error: 'box_offline', cloud_state: state.tailscale_state[c.id] || null });
  const cmd = _queueBoxCmd(mac, 'tailscale-status', {});
  saveState();
  const r = await _waitForCmd(mac, cmd.id, 8000);
  res.json({ ok: true, status: r.status, result: r.result, cloud_state: state.tailscale_state[c.id] || null });
});
app.post('/api/customer/tailscale/set-routes', customerAuth, (req, res) => {
  const c = req.customer;
  const mac = _pickBoxForCust(c);
  if (!mac) return res.status(404).json({ error: 'no_box_assigned' });
  let cidrs = req.body.cidrs;
  if (typeof cidrs === 'string') cidrs = cidrs.split(',').map(s => s.trim()).filter(Boolean);
  if (!Array.isArray(cidrs)) cidrs = [];
  const cmd = _queueBoxCmd(mac, 'tailscale-set-routes', { cidrs });
  if (state.tailscale_state[c.id]) state.tailscale_state[c.id].advertise_routes = cidrs;
  saveState();
  res.json({ ok: true, queued_cmd_id: cmd.id, cidrs });
});
app.post('/api/customer/tailscale/logout', customerAuth, (req, res) => {
  const c = req.customer;
  const mac = _pickBoxForCust(c);
  if (!mac) return res.status(404).json({ error: 'no_box_assigned' });
  const cmd = _queueBoxCmd(mac, 'tailscale-logout', {});
  if (state.tailscale_state[c.id]) delete state.tailscale_state[c.id];
  saveState();
  res.json({ ok: true, queued_cmd_id: cmd.id });
});

// ─── Feature B: IPsec / IKEv2 (strongSwan) ────────────────────────────────
function _ipsecUsers(cid) { if (!state.ipsec_users[cid]) state.ipsec_users[cid] = []; return state.ipsec_users[cid]; }

app.post('/api/customer/ipsec/setup', customerAuth, async (req, res) => {
  const c = req.customer;
  const mac = _pickBoxForCust(c);
  if (!mac) return res.status(404).json({ error: 'no_box_assigned' });
  const domain_or_ip = String(req.body.domain_or_ip || '').trim();
  if (!domain_or_ip) return res.status(400).json({ error: 'domain_or_ip_required' });
  _queueBoxCmd(mac, 'ipsec-install', {});
  const cmd = _queueBoxCmd(mac, 'ipsec-setup', { domain_or_ip, ca_cn: req.body.ca_cn || undefined });
  saveState();
  res.json({ ok: true, queued_cmd_id: cmd.id, domain_or_ip });
});
app.get('/api/customer/ipsec/users/list', customerAuth, (req, res) => {
  res.json({ users: _ipsecUsers(req.customer.id) });
});
app.post('/api/customer/ipsec/users/add', customerAuth, (req, res) => {
  const c = req.customer;
  const mac = _pickBoxForCust(c);
  if (!mac) return res.status(404).json({ error: 'no_box_assigned' });
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  if (!/^[a-zA-Z0-9._-]{1,32}$/.test(username)) return res.status(400).json({ error: 'bad_username' });
  if (!password || password.length < 6 || password.length > 128) return res.status(400).json({ error: 'bad_password' });
  const list = _ipsecUsers(c.id);
  if (list.find(u => u.username === username)) return res.status(409).json({ error: 'user_exists' });
  const id = shortId(12);
  list.push({ id, username, created_at: Date.now() });
  // Stash password ONLY so the .mobileconfig endpoint can embed it later.
  // Never expose it on any listing endpoint.
  if (!state._ipsec_secrets) state._ipsec_secrets = {};
  if (!state._ipsec_secrets[c.id]) state._ipsec_secrets[c.id] = {};
  state._ipsec_secrets[c.id][id] = password;
  _queueBoxCmd(mac, 'ipsec-user-add', { username, password });
  saveState();
  res.json({ ok: true, user: { id, username, created_at: list[list.length - 1].created_at } });
});
app.post('/api/customer/ipsec/users/delete', customerAuth, (req, res) => {
  const c = req.customer;
  const mac = _pickBoxForCust(c);
  if (!mac) return res.status(404).json({ error: 'no_box_assigned' });
  const id = String(req.body.id || '');
  const list = _ipsecUsers(c.id);
  const idx = list.findIndex(u => u.id === id);
  if (idx === -1) return res.status(404).json({ error: 'user_not_found' });
  const username = list[idx].username;
  list.splice(idx, 1);
  if (state._ipsec_secrets && state._ipsec_secrets[c.id]) delete state._ipsec_secrets[c.id][id];
  _queueBoxCmd(mac, 'ipsec-user-remove', { username });
  saveState();
  res.json({ ok: true });
});
app.get('/api/customer/ipsec/status', customerAuth, async (req, res) => {
  const c = req.customer;
  const mac = _pickBoxForCust(c);
  if (!mac) return res.status(404).json({ error: 'no_box_assigned' });
  const bs = state.box_state[mac];
  const online = bs && (Date.now() - bs.last_heartbeat) < 5 * 60_000;
  if (!online) return res.json({ ok: false, error: 'box_offline', users: _ipsecUsers(c.id) });
  const cmd = _queueBoxCmd(mac, 'ipsec-status', {});
  saveState();
  const r = await _waitForCmd(mac, cmd.id, 6000);
  res.json({ ok: true, status: r.status, result: r.result, users: _ipsecUsers(c.id) });
});
app.get('/api/customer/ipsec/users/:id/mobileconfig.mobileconfig', customerAuth, async (req, res) => {
  const c = req.customer;
  const mac = _pickBoxForCust(c);
  if (!mac) return res.status(404).json({ error: 'no_box_assigned' });
  const id = String(req.params.id || '');
  const list = _ipsecUsers(c.id);
  const entry = list.find(u => u.id === id);
  if (!entry) return res.status(404).json({ error: 'user_not_found' });
  const password = (state._ipsec_secrets && state._ipsec_secrets[c.id] && state._ipsec_secrets[c.id][id]) || '';
  if (!password) return res.status(410).json({ error: 'password_lost', hint: 'Delete + re-add this user to regenerate.' });
  const cmd = _queueBoxCmd(mac, 'ipsec-mobileconfig', { username: entry.username, password, vpn_name: 'mes IPsec' });
  saveState();
  const r = await _waitForCmd(mac, cmd.id, 8000);
  if (r.status === 'completed' && r.result && r.result.plist) {
    res.setHeader('Content-Type', 'application/x-apple-aspen-config');
    res.setHeader('Content-Disposition', `attachment; filename="mes-ipsec-${entry.username}.mobileconfig"`);
    return res.send(r.result.plist);
  }
  res.status(503).json({ error: 'mobileconfig_unavailable', status: r.status, result: r.result });
});

// ─── Feature C: AmneziaWG (obfuscated WireGuard) ──────────────────────────
function _awgPeers(cid) { if (!state.awg_peers[cid]) state.awg_peers[cid] = []; return state.awg_peers[cid]; }

app.post('/api/customer/awg/setup', customerAuth, (req, res) => {
  const c = req.customer;
  const mac = _pickBoxForCust(c);
  if (!mac) return res.status(404).json({ error: 'no_box_assigned' });
  _queueBoxCmd(mac, 'awg-install', {});
  const cmd = _queueBoxCmd(mac, 'awg-setup', {
    listen_port: parseInt(req.body.listen_port, 10) || undefined,
    network_cidr: req.body.network_cidr || undefined,
  });
  saveState();
  res.json({ ok: true, queued_cmd_id: cmd.id });
});
app.get('/api/customer/awg/status', customerAuth, async (req, res) => {
  const c = req.customer;
  const mac = _pickBoxForCust(c);
  if (!mac) return res.status(404).json({ error: 'no_box_assigned' });
  const bs = state.box_state[mac];
  const online = bs && (Date.now() - bs.last_heartbeat) < 5 * 60_000;
  if (!online) return res.json({ ok: false, error: 'box_offline', peers: _awgPeers(c.id) });
  const cmd = _queueBoxCmd(mac, 'awg-status', {});
  saveState();
  const r = await _waitForCmd(mac, cmd.id, 6000);
  res.json({ ok: true, status: r.status, result: r.result, peers: _awgPeers(c.id) });
});
app.post('/api/customer/awg/peers/add', customerAuth, async (req, res) => {
  const c = req.customer;
  const mac = _pickBoxForCust(c);
  if (!mac) return res.status(404).json({ error: 'no_box_assigned' });
  const label = String(req.body.label || '').trim().slice(0, 40);
  if (!label) return res.status(400).json({ error: 'label_required' });
  const cmd = _queueBoxCmd(mac, 'awg-peer-add', { label });
  saveState();
  const r = await _waitForCmd(mac, cmd.id, 10_000);
  if (r.status === 'completed' && r.result && r.result.ok && r.result.peer) {
    const list = _awgPeers(c.id);
    list.push({
      id: r.result.peer.id,
      label: r.result.peer.label,
      ip: r.result.peer.ip,
      pubkey: r.result.peer.pubkey,
      created_at: r.result.peer.created_at || Date.now(),
    });
    saveState();
    return res.json({ ok: true, peer: r.result.peer, conf_text: r.result.conf_text });
  }
  res.json({ ok: false, status: r.status, result: r.result });
});
app.post('/api/customer/awg/peers/delete', customerAuth, (req, res) => {
  const c = req.customer;
  const mac = _pickBoxForCust(c);
  if (!mac) return res.status(404).json({ error: 'no_box_assigned' });
  const id = String(req.body.id || '');
  const list = _awgPeers(c.id);
  const idx = list.findIndex(p => p.id === id);
  if (idx === -1) return res.status(404).json({ error: 'peer_not_found' });
  list.splice(idx, 1);
  _queueBoxCmd(mac, 'awg-peer-remove', { peer_id: id });
  saveState();
  res.json({ ok: true });
});
app.get('/api/customer/awg/peers', customerAuth, (req, res) => {
  res.json({ peers: _awgPeers(req.customer.id) });
});

// ─── SMTP admin config ─────────────────────────────────────────────────────
app.get('/admin/api/smtp-config', adminAuth, (req, res) => {
  const s = state.config.smtp || {};
  // Don't leak password
  res.json({
    host: s.host || '', port: s.port || '', user: s.user || '',
    secure: !!s.secure, from: s.from || state.config.email_from || '',
    has_pass: !!s.pass,
    nodemailer_installed: !!_nodemailer,
  });
});
app.post('/admin/api/smtp-config', adminAuth, (req, res) => {
  if (!state.config.smtp) state.config.smtp = {};
  const s = state.config.smtp;
  if (req.body.host !== undefined) s.host = String(req.body.host || '');
  if (req.body.port !== undefined) s.port = parseInt(req.body.port, 10) || '';
  if (req.body.user !== undefined) s.user = String(req.body.user || '');
  if (req.body.pass !== undefined) s.pass = String(req.body.pass || '');
  if (req.body.from !== undefined) s.from = String(req.body.from || '');
  if (req.body.secure !== undefined) s.secure = !!req.body.secure;
  _smtpTransport = null;   // force rebuild
  saveState();
  res.json({ ok: true, nodemailer_installed: !!_nodemailer });
});
app.post('/admin/api/smtp-test', adminAuth, async (req, res) => {
  const to = String(req.body.to || '').trim();
  if (!to || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)) return res.status(400).json({ error: 'bad_to' });
  if (!_nodemailer) return res.status(503).json({ ok: false, error: 'nodemailer_not_installed', hint: 'Add nodemailer to package.json and run npm install on the cloud.' });
  const r = await sendEmailViaSmtp(to, '[mes] SMTP test', 'This is a test message from your mes Cloud SMTP config.\n');
  res.json(r);
});

// ═══════════════════════════════════════════════════════════════════════════
//  DDNS — every customer can claim a <slug>.ddns.<brand_domain> name
// ═══════════════════════════════════════════════════════════════════════════
app.post('/api/customer/ddns/claim', customerAuth, (req, res) => {
  const slug = String(req.body.slug || '').toLowerCase().replace(/[^a-z0-9-]/g, '').slice(0, 40);
  if (!slug || slug.length < 3) return res.status(400).json({ error: 'slug_3_to_40_chars_alnum_dash' });
  if (state.ddns[slug] && state.ddns[slug].customer_id !== req.customer.id) {
    return res.status(409).json({ error: 'slug_taken' });
  }
  // Drop any old slugs for this customer
  for (const [s, d] of Object.entries(state.ddns)) {
    if (d.customer_id === req.customer.id && s !== slug) delete state.ddns[s];
  }
  state.ddns[slug] = { slug, customer_id: req.customer.id, current_ip: null, last_update: 0, ttl: 60 };
  saveState();
  res.json({ ok: true, hostname: `${slug}.ddns.${state.config.brand_domain || 'mes.net.lb'}` });
});
app.get('/api/customer/ddns', customerAuth, (req, res) => {
  const mine = Object.values(state.ddns).filter(d => d.customer_id === req.customer.id);
  res.json({ records: mine.map(d => ({ slug: d.slug, hostname: `${d.slug}.ddns.${state.config.brand_domain || 'mes.net.lb'}`, current_ip: d.current_ip, last_update: d.last_update, ttl: d.ttl })) });
});
// Public zone file (consumed by NSD poller on the DNS host) — no auth.
// MUST be defined before /ddns/:slug or Express matches it as a slug.
app.get('/ddns/zonefile', (req, res) => {
  const brand = state.config.brand_domain && state.config.brand_domain.replace(/^cloud\./, '') || 'mes.net.lb';
  const ddnsDomain = `ddns.${brand}`;
  const ns1 = `ns1.${brand}`;
  const ns2 = `ns2.${brand}`;
  const serial = Math.floor(Date.now() / 1000);
  const lines = [
    `; mes Network DDNS zone — generated ${new Date().toISOString()}`,
    `$ORIGIN ${ddnsDomain}.`,
    `$TTL 60`,
    `@\tIN\tSOA\t${ns1}. hostmaster.${brand}. ( ${serial} 3600 600 604800 60 )`,
    `@\tIN\tNS\t${ns1}.`,
    `@\tIN\tNS\t${ns2}.`,
  ];
  for (const d of Object.values(state.ddns)) {
    if (d.current_ip) lines.push(`${d.slug}\tIN\tA\t${d.current_ip}`);
  }
  res.set('Content-Type', 'text/plain');
  res.send(lines.join('\n') + '\n');
});
// NoIP / DynDNS-2 compatible update endpoint — any router can use this format
//   GET /nic/update?hostname=<slug>.ddns.<brand>&myip=<ip>
//   Auth: HTTP Basic (phone:OTP) or query token=<API key from /admin/api/keys>
//
// Returns plain-text DynDNS-2 response codes:
//   "good <ip>"   updated
//   "nochg <ip>"  unchanged
//   "nohost"      hostname not found
//   "badauth"     auth failed
app.get('/nic/update', (req, res) => {
  res.set('Content-Type', 'text/plain');

  // Parse hostname → slug
  const hostname = (req.query.hostname || '').toLowerCase();
  const m = hostname.match(/^([a-z0-9][a-z0-9\-]*)\.ddns\./);
  if (!m) return res.status(400).send('notfqdn');
  const slug = m[1];
  const d = state.ddns[slug];
  if (!d) return res.status(404).send('nohost');

  // Auth: HTTP Basic with customer phone + OTP, or token=<api-key>
  let authedCustomerId = null;
  const tokenQuery = (req.query.token || '').trim();
  if (tokenQuery) {
    const k = (state.api_keys || []).find(x => x.key === tokenQuery && x.enabled !== false);
    if (k && k.customer_id === d.customer_id) authedCustomerId = k.customer_id;
  } else {
    const auth = req.headers.authorization || '';
    if (auth.startsWith('Basic ')) {
      const [user, pass] = Buffer.from(auth.slice(6), 'base64').toString('utf8').split(':');
      const cust = findCustomerByPhone(user);
      if (cust && cust.id === d.customer_id && pass === FIXED_OTP) authedCustomerId = cust.id;
    }
  }
  if (!authedCustomerId) return res.status(401).send('badauth');

  // Determine new IP
  let ip = req.query.myip || req.headers['x-forwarded-for'] || req.ip;
  if (typeof ip === 'string' && ip.includes(',')) ip = ip.split(',')[0].trim();
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return res.status(400).send('badip');

  if (d.current_ip === ip) {
    return res.send('nochg ' + ip);
  }
  d.current_ip = ip;
  d.last_update = Date.now();
  saveState();
  console.log(`         🔄 DDNS UPDATE → ${slug} = ${ip} (NoIP-style auth)`);
  res.send('good ' + ip);
});

// Public DDNS lookup — what a DNS server (or curl) hits
app.get('/ddns/:slug', (req, res) => {
  const d = state.ddns[req.params.slug.toLowerCase()];
  if (!d || !d.current_ip) return res.status(404).json({ error: 'not_found' });
  res.json({ hostname: `${d.slug}.ddns.${state.config.brand_domain || 'mes.net.lb'}`, ip: d.current_ip, last_update: d.last_update, ttl: d.ttl });
});
// Admin alias (legacy)
app.get('/admin/api/ddns/zonefile', adminAuth, (req, res) => res.redirect('/ddns/zonefile'));

// ═══════════════════════════════════════════════════════════════════════════
//  MULTI-SITE — one customer → many sites, each with their own boxes
// ═══════════════════════════════════════════════════════════════════════════
app.get('/api/customer/sites', customerAuth, (req, res) => {
  const mine = Object.values(state.sites).filter(s => s.customer_id === req.customer.id);
  res.json({ sites: mine });
});
app.post('/api/customer/sites/create', customerAuth, (req, res) => {
  const c = req.customer;
  if (!planLimits(c.plan).multi_site) {
    return res.status(402).json({ error: 'plan_limit', message: 'Multi-site requires Business plan.' });
  }
  const id = shortId(12);
  state.sites[id] = {
    id, customer_id: c.id,
    name: String(req.body.name || 'New Site').slice(0, 60),
    address: String(req.body.address || '').slice(0, 200),
    box_macs: [],
    created_at: Date.now(),
  };
  saveState();
  res.json({ ok: true, site: state.sites[id] });
});
app.post('/api/customer/sites/update', customerAuth, (req, res) => {
  const s = state.sites[req.body.id];
  if (!s || s.customer_id !== req.customer.id) return res.status(404).json({ error: 'not found' });
  if (req.body.name) s.name = String(req.body.name).slice(0, 60);
  if (req.body.address !== undefined) s.address = String(req.body.address).slice(0, 200);
  if (Array.isArray(req.body.box_macs)) s.box_macs = req.body.box_macs.map(normalizeMac).filter(Boolean);
  saveState();
  res.json({ ok: true, site: s });
});
app.post('/api/customer/sites/delete', customerAuth, (req, res) => {
  const s = state.sites[req.body.id];
  if (!s || s.customer_id !== req.customer.id) return res.status(404).json({ error: 'not found' });
  delete state.sites[req.body.id];
  saveState();
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════════════════════════
//  GEO-IP — small embedded country table, enrich flows on ingest
// ═══════════════════════════════════════════════════════════════════════════
// Real geo-IP DB: db-ip.com country-lite (CC0, ~350k rows). Loaded at boot.
// Format on disk: CSV "start_ip,end_ip,CC". We sort + parse into typed arrays for fast binary search.
let GEO_STARTS, GEO_ENDS, GEO_CCS;
function ipToLong(ip) {
  if (!ip || typeof ip !== 'string') return 0;
  const o = ip.split('.').map(n => parseInt(n));
  if (o.length !== 4 || o.some(x => isNaN(x) || x < 0 || x > 255)) return 0;
  return ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0;
}
function loadGeoDb() {
  const candidates = [
    path.join(__dirname, 'dbip-country-ipv4.csv'),
    '/data/dbip-country-ipv4.csv',
  ];
  let raw = null;
  for (const p of candidates) { try { raw = fs.readFileSync(p, 'utf8'); break; } catch {} }
  if (!raw) {
    console.warn('         ⚠️  geo-ip DB not found — country enrichment disabled');
    GEO_STARTS = new Uint32Array(0); GEO_ENDS = new Uint32Array(0); GEO_CCS = [];
    return;
  }
  const lines = raw.split('\n');
  GEO_STARTS = new Uint32Array(lines.length);
  GEO_ENDS   = new Uint32Array(lines.length);
  GEO_CCS    = new Array(lines.length);
  let n = 0;
  for (const line of lines) {
    if (!line) continue;
    const parts = line.split(',');
    if (parts.length < 3) continue;
    const s = ipToLong(parts[0]);
    const e = ipToLong(parts[1]);
    if (!s || !e) continue;
    GEO_STARTS[n] = s; GEO_ENDS[n] = e; GEO_CCS[n] = parts[2].trim();
    n++;
  }
  // The CSV is already sorted by start_ip — trust it
  GEO_STARTS = GEO_STARTS.slice(0, n);
  GEO_ENDS   = GEO_ENDS.slice(0, n);
  GEO_CCS.length = n;
  console.log(`         🌍 geo-ip DB loaded: ${n} ranges`);
}
loadGeoDb();
function geoCountryFor(ip) {
  const n = ipToLong(ip);
  if (!n || !GEO_STARTS || !GEO_STARTS.length) return null;
  // Binary search: find largest start_ip ≤ n
  let lo = 0, hi = GEO_STARTS.length - 1, mid;
  while (lo <= hi) {
    mid = (lo + hi) >>> 1;
    if (GEO_STARTS[mid] <= n) lo = mid + 1; else hi = mid - 1;
  }
  if (hi < 0) return 'XX';
  return n <= GEO_ENDS[hi] ? GEO_CCS[hi] : 'XX';
}

// ─── Geo-block expansion (Fix 6) ───────────────────────────────────────────
// Cloud-side: turn a country code into a flat list of CIDRs that the box
// can drop into its nft `blocked_ips` interval set. We use the same dbip DB
// already loaded for telemetry. Country → CIDR list is memoised because the
// expansion is identical for every box pulling the same country.
const GEO_BLOCK_CIDR_CAP = 4000;          // per-bundle hard cap, keeps payload reasonable
const _countryCidrCache = new Map();      // cc → string[] of CIDRs

// Convert a single [start,end] IPv4 range to a minimum set of CIDR strings.
// Greedy: at each step emit the largest aligned power-of-2 block that fits.
function rangeToCidrs(start, end) {
  const out = [];
  let s = start >>> 0;
  const e = end >>> 0;
  while (s <= e) {
    // Largest prefix length n such that (a) s is aligned to 2^(32-n)
    // and (b) the block [s, s + 2^(32-n) - 1] stays inside [s, e].
    let n = 32;
    while (n > 0) {
      const tryN = n - 1;
      const blockSize = Math.pow(2, 32 - tryN);
      // Alignment check: s must be a multiple of blockSize.
      if ((s % blockSize) !== 0) break;
      // Fit check: block must not overshoot e.
      if (s + blockSize - 1 > e) break;
      n = tryN;
    }
    const blockSize = Math.pow(2, 32 - n);
    const o1 = (s >>> 24) & 0xFF, o2 = (s >>> 16) & 0xFF, o3 = (s >>> 8) & 0xFF, o4 = s & 0xFF;
    out.push(`${o1}.${o2}.${o3}.${o4}/${n}`);
    s = s + blockSize;
    if (s > 0xFFFFFFFF) break;
  }
  return out;
}

function rangesForCountry(cc) {
  cc = String(cc || '').toUpperCase();
  if (!cc || cc.length !== 2) return [];
  if (_countryCidrCache.has(cc)) return _countryCidrCache.get(cc);
  const cidrs = [];
  if (GEO_STARTS && GEO_CCS) {
    for (let i = 0; i < GEO_STARTS.length; i++) {
      if (GEO_CCS[i] !== cc) continue;
      const sub = rangeToCidrs(GEO_STARTS[i], GEO_ENDS[i]);
      for (const c of sub) {
        cidrs.push(c);
        if (cidrs.length >= GEO_BLOCK_CIDR_CAP) break;
      }
      if (cidrs.length >= GEO_BLOCK_CIDR_CAP) break;
    }
  }
  _countryCidrCache.set(cc, cidrs);
  return cidrs;
}

// ═══════════════════════════════════════════════════════════════════════════
//  THREAT INTEL — auto-pulled URLhaus + abuse.ch feeds (or empty if offline)
// ═══════════════════════════════════════════════════════════════════════════
if (!state.threat_feeds) state.threat_feeds = { domains: [], ips: [], last_update: 0, sources: [], per_source: {} };

function httpsGetText(url, timeout_ms = 20000) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { timeout: timeout_ms }, res => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        return httpsGetText(res.headers.location, timeout_ms).then(resolve, reject);
      }
      if (res.statusCode >= 400) { res.resume(); return reject(new Error(`HTTP ${res.statusCode}`)); }
      let chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    });
    req.on('timeout', () => { req.destroy(new Error('timeout')); });
    req.on('error', reject);
  });
}

const THREAT_SOURCES = [
  {
    name: 'urlhaus.abuse.ch',
    url:  'https://urlhaus.abuse.ch/downloads/text_recent/',
    parse: txt => {
      const out = new Set();
      for (const line of txt.split('\n').slice(0, 20000)) {
        if (!line || line.startsWith('#')) continue;
        try {
          const u = new URL(line.trim());
          if (u.hostname && !/^[\d.]+$/.test(u.hostname)) out.add(u.hostname.toLowerCase());
        } catch {}
      }
      return out;
    },
  },
  {
    name: 'stevenblack-hosts',
    url:  'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
    parse: txt => {
      const out = new Set();
      for (const line of txt.split('\n')) {
        if (!line || line.startsWith('#')) continue;
        const m = line.match(/^0\.0\.0\.0\s+(\S+)/);
        if (m && m[1] !== '0.0.0.0' && !/^[\d.]+$/.test(m[1])) out.add(m[1].toLowerCase());
      }
      return out;
    },
  },
  {
    name: 'oisd-basic',
    url:  'https://small.oisd.nl/',
    parse: txt => {
      const out = new Set();
      for (const line of txt.split('\n')) {
        if (!line || line.startsWith('#') || line.startsWith('!')) continue;
        // Adblock-style: "||example.com^"
        const m = line.match(/^\|\|([a-z0-9.\-]+)\^/i);
        if (m) out.add(m[1].toLowerCase());
      }
      return out;
    },
  },
  {
    name: 'nocoin',
    url:  'https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt',
    parse: txt => {
      const out = new Set();
      for (const line of txt.split('\n')) {
        if (!line || line.startsWith('#')) continue;
        const m = line.match(/^0\.0\.0\.0\s+(\S+)/);
        if (m && !/^[\d.]+$/.test(m[1])) out.add(m[1].toLowerCase());
      }
      return out;
    },
  },
];

async function fetchOneSource(s) {
  try {
    const txt = await httpsGetText(s.url);
    const set = s.parse(txt);
    return { name: s.name, count: set.size, domains: set };
  } catch (e) {
    console.error(`  threat feed ${s.name} failed: ${e.message}`);
    return { name: s.name, count: 0, domains: new Set(), error: e.message };
  }
}

// Generic parser for hosts/adblock-style lists — covers most user-supplied feeds
function parseGenericFeed(txt) {
  const out = new Set();
  for (const line of txt.split('\n')) {
    const l = line.trim();
    if (!l || l.startsWith('#') || l.startsWith('!')) continue;
    // hosts format: "0.0.0.0 example.com"
    let m = l.match(/^(?:0\.0\.0\.0|127\.0\.0\.1)\s+(\S+)/);
    if (m) { if (!/^[\d.]+$/.test(m[1])) out.add(m[1].toLowerCase()); continue; }
    // adblock format: "||example.com^"
    m = l.match(/^\|\|([a-z0-9.\-]+)\^/i);
    if (m) { out.add(m[1].toLowerCase()); continue; }
    // bare domain
    if (/^[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}$/i.test(l)) out.add(l.toLowerCase());
  }
  return out;
}

async function fetchThreatFeed() {
  const builtin = await Promise.all(THREAT_SOURCES.map(fetchOneSource));
  const customSources = (state.threat_feeds.custom_urls || []).map(c => ({
    name: c.name || c.url,
    url:  c.url,
    parse: parseGenericFeed,
  }));
  const custom = await Promise.all(customSources.map(fetchOneSource));
  const all = builtin.concat(custom);

  const merged = new Set();
  const per_source = {};
  for (const r of all) {
    per_source[r.name] = { count: r.count, error: r.error || null };
    for (const d of r.domains) merged.add(d);
  }
  const total = Array.from(merged).slice(0, 200000);
  const prevCount = (state.threat_feeds.domains || []).length;
  state.threat_feeds.domains = total;
  state.threat_feeds.last_update = Date.now();
  state.threat_feeds.sources = all.filter(r => r.count > 0).map(r => r.name);
  state.threat_feeds.per_source = per_source;
  if (state.app_categories.malware) {
    state.app_categories.malware.domains = total;
  }
  saveState();
  console.log(`         🛡️  THREAT FEED → ${total.length} malware domains from ${state.threat_feeds.sources.length} source(s)`);
  // If significantly different, bump the global policy etag so boxes pull fresh
  if (Math.abs(total.length - prevCount) > 100) {
    if (typeof bumpPolicyEtagGlobal === 'function') bumpPolicyEtagGlobal(`threat_feed_changed:${total.length - prevCount}`);
  }
  return total.length;
}

// Admin: manage custom threat feed URLs
app.get('/admin/api/threat-feed/custom', adminAuth, (req, res) => {
  res.json({ custom: state.threat_feeds.custom_urls || [] });
});
app.post('/admin/api/threat-feed/custom/add', adminAuth, (req, res) => {
  if (!state.threat_feeds.custom_urls) state.threat_feeds.custom_urls = [];
  const url = String(req.body.url || '').trim();
  const name = String(req.body.name || '').trim() || url;
  if (!/^https?:\/\//.test(url)) return res.status(400).json({ error: 'url must be http(s)://...' });
  if (state.threat_feeds.custom_urls.some(c => c.url === url)) return res.status(409).json({ error: 'already added' });
  state.threat_feeds.custom_urls.push({ id: shortId(10), name, url, added_at: Date.now() });
  saveState();
  logAdminAction(req, 'threat-feed.custom.add', name, url);
  res.json({ ok: true });
});
app.post('/admin/api/threat-feed/custom/delete', adminAuth, (req, res) => {
  const list = state.threat_feeds.custom_urls || [];
  const i = list.findIndex(c => c.id === req.body.id);
  if (i < 0) return res.status(404).json({ error: 'not found' });
  list.splice(i, 1);
  saveState();
  res.json({ ok: true });
});
// Refresh once a day after first boot (heavy fetch ~150k domains; saves bandwidth)
setTimeout(fetchThreatFeed, 30_000);
setInterval(fetchThreatFeed, 24 * 3600_000);

// ─── Target Lists (Firewalla-style) ──────────────────────────────────────
// Unified list view across:
//   - built-in lists curated by us (firewalla-style)
//   - admin-imported GitHub / URL lists
//   - manual lists with explicit targets
// state.target_lists = { id: { id, name, category, source, source_url, targets:[], targets_count, updated_at, managed_by, notes, locked } }
if (!state.target_lists) {
  state.target_lists = {};
  // Pre-seed with the same set Firewalla MSP ships with
  const seed = [
    { name: 'DoH Services', category: 'privacy', source: 'github', source_url: 'https://raw.githubusercontent.com/firewalla/fw-public-lists/main/doh-services.txt', notes: 'A list of well-known DNS-over-HTTPS servers', managed_by: 'Firewalla' },
    { name: 'Apple Private Relay', category: 'privacy', source: 'github', source_url: 'https://raw.githubusercontent.com/firewalla/fw-public-lists/main/apple-private-relay.txt', notes: 'Apple Private Relay Servers, block them to ban the relay service.', managed_by: 'Firewalla' },
    { name: 'OISD', category: 'ad_block', source: 'url', source_url: 'https://big.oisd.nl/domainswild', notes: 'Comprehensive ad/tracker blocklist (oisd.nl)', managed_by: 'Firewalla' },
    { name: 'Log4j attackers', category: 'security', source: 'github', source_url: 'https://raw.githubusercontent.com/firewalla/fw-public-lists/main/log4j-attackers.txt', notes: 'Known Log4j attackers from public lists', managed_by: 'Firewalla' },
    { name: 'DShield Block List', category: 'security', source: 'url', source_url: 'https://www.dshield.org/block.txt', notes: 'A DShield-recommended block list', managed_by: 'Firewalla' },
    { name: 'Tor Exit Nodes', category: 'security', source: 'url', source_url: 'https://check.torproject.org/torbulkexitlist', notes: 'Tor Exit Nodes', managed_by: 'Firewalla' },
    { name: 'Tor Full Nodes', category: 'security', source: 'github', source_url: 'https://raw.githubusercontent.com/firewalla/fw-public-lists/main/tor-full.txt', notes: 'Be aware that this is a list of all nodes, not just exit nodes', managed_by: 'Firewalla' },
    { name: 'Crypto List', category: 'crypto', source: 'github', source_url: 'https://raw.githubusercontent.com/firewalla/fw-public-lists/main/crypto.txt', notes: 'Cryptocurrency / mining endpoints', managed_by: 'Firewalla' },
    { name: 'Google VPN', category: 'privacy', source: 'github', source_url: 'https://raw.githubusercontent.com/firewalla/fw-public-lists/main/google-vpn.txt', notes: 'Google VPN servers', managed_by: 'Firewalla' },
    { name: 'Newly Registered Domains', category: 'security', source: 'url', source_url: 'https://nrd-list.example/list.txt', notes: 'Newly Registered Domains (last 30 days)', managed_by: 'Firewalla' },
  ];
  for (const s of seed) {
    const id = 'tlst-' + shortId(8);
    state.target_lists[id] = {
      id, name: s.name, category: s.category,
      source: s.source, source_url: s.source_url,
      targets: [], targets_count: 0,
      updated_at: 0, last_error: null,
      managed_by: s.managed_by, notes: s.notes,
      locked: s.managed_by === 'Firewalla',
      created_at: Date.now(),
    };
  }
  saveState();
}

// Refresh a single target list from its source URL
async function refreshTargetList(id) {
  const tl = state.target_lists[id];
  if (!tl) throw new Error('not_found');
  if (!tl.source_url) { tl.last_error = 'no_source_url'; return; }
  try {
    const r = await fetchOneSource({ name: tl.name, url: tl.source_url, parse: parseGenericFeed });
    const arr = Array.from(r.domains || []);
    tl.targets = arr.slice(0, 50000);   // cap to keep state.json sane
    tl.targets_count = arr.length;
    tl.updated_at = Date.now();
    tl.last_error = r.error || null;
    saveState();
  } catch (e) {
    tl.last_error = String(e.message || e);
  }
}

// Daily refresh of all lists with source URLs
async function refreshAllTargetLists() {
  for (const id of Object.keys(state.target_lists || {})) {
    if (state.target_lists[id].source_url && state.target_lists[id].source !== 'manual') {
      try { await refreshTargetList(id); } catch {}
    }
  }
}
setTimeout(refreshAllTargetLists, 5 * 60_000);
setInterval(refreshAllTargetLists, 24 * 3600_000);

// Admin endpoints
app.get('/admin/api/target-lists', adminAuth, (req, res) => {
  // Return all lists, slim down (don't ship full target arrays in list view)
  const out = Object.values(state.target_lists || {}).map(tl => ({
    id: tl.id, name: tl.name, category: tl.category,
    source: tl.source, source_url: tl.source_url,
    targets_count: tl.targets_count, updated_at: tl.updated_at,
    managed_by: tl.managed_by, notes: tl.notes, locked: tl.locked,
    last_error: tl.last_error,
  }));
  out.sort((a, b) => (b.targets_count || 0) - (a.targets_count || 0));
  res.json({ lists: out });
});
app.get('/admin/api/target-lists/:id', adminAuth, (req, res) => {
  const tl = state.target_lists[req.params.id];
  if (!tl) return res.status(404).json({ error: 'not_found' });
  // Full list — include targets but cap
  res.json({ ...tl, targets: (tl.targets || []).slice(0, 1000), targets_total: tl.targets_count });
});
app.post('/admin/api/target-lists/create', adminAuth, async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 80);
  if (!name) return res.status(400).json({ error: 'name_required' });
  const category = String(req.body.category || 'custom').slice(0, 30);
  const notes    = String(req.body.notes || '').slice(0, 300);
  const source   = req.body.targets ? 'manual' : (req.body.source_url ? 'url' : 'manual');
  const source_url = String(req.body.source_url || '').trim();
  if (source !== 'manual' && !/^https?:\/\//.test(source_url)) return res.status(400).json({ error: 'source_url must be http(s)' });
  const id = 'tlst-' + shortId(8);
  const targets = Array.isArray(req.body.targets) ? req.body.targets.filter(t => /^[a-z0-9.\-_]+$/i.test(t)).slice(0, 50000) : [];
  state.target_lists[id] = {
    id, name, category, source, source_url,
    targets, targets_count: targets.length,
    updated_at: source === 'manual' ? Date.now() : 0,
    managed_by: 'Custom', notes, locked: false, created_at: Date.now(),
    last_error: null,
  };
  saveState();
  if (typeof logAdminAction === 'function') logAdminAction(req, 'target_list.create', id, name);
  // Fire async refresh if URL-based
  if (source !== 'manual') refreshTargetList(id).catch(() => {});
  res.json({ ok: true, id, list: state.target_lists[id] });
});
app.post('/admin/api/target-lists/import-github', adminAuth, async (req, res) => {
  // Convenience: paste a github URL like https://github.com/user/repo/blob/main/file.txt
  // → converted to raw.githubusercontent.com URL
  let url = String(req.body.url || '').trim();
  if (!url) return res.status(400).json({ error: 'url_required' });
  url = url.replace('github.com/', 'raw.githubusercontent.com/').replace('/blob/', '/');
  const name = String(req.body.name || url.split('/').pop().replace(/\.[^.]+$/, '') || 'GitHub list').slice(0, 80);
  const id = 'tlst-' + shortId(8);
  state.target_lists[id] = {
    id, name, category: 'imported',
    source: 'github', source_url: url,
    targets: [], targets_count: 0, updated_at: 0,
    managed_by: 'Custom', notes: 'Imported from ' + url, locked: false, created_at: Date.now(),
    last_error: null,
  };
  saveState();
  if (typeof logAdminAction === 'function') logAdminAction(req, 'target_list.import_github', id, url);
  refreshTargetList(id).catch(() => {});
  res.json({ ok: true, id, list: state.target_lists[id] });
});
app.post('/admin/api/target-lists/refresh', adminAuth, async (req, res) => {
  const tl = state.target_lists[req.body.id];
  if (!tl) return res.status(404).json({ error: 'not_found' });
  await refreshTargetList(tl.id);
  res.json({ ok: true, list: state.target_lists[tl.id] });
});
app.post('/admin/api/target-lists/delete', adminAuth, (req, res) => {
  const tl = state.target_lists[req.body.id];
  if (!tl) return res.status(404).json({ error: 'not_found' });
  if (tl.locked) return res.status(403).json({ error: 'locked', message: 'Firewalla-managed lists cannot be deleted.' });
  delete state.target_lists[tl.id];
  saveState();
  if (typeof logAdminAction === 'function') logAdminAction(req, 'target_list.delete', tl.id, tl.name);
  res.json({ ok: true });
});

// ─── Cloud modules ────────────────────────────────────────────────────────
let cloudPortscan = null, cloudNlFlowSearch = null;
let cloudBehaviorBaseline = null, cloudActiveProtect = null, cloudAppDpi = null;
try { cloudPortscan = require('./cloud-modules/portscan'); } catch (e) { console.error('portscan module not available:', e.message); }
try { cloudNlFlowSearch = require('./cloud-modules/nl-flow-search'); } catch (e) { console.error('nl-flow-search module not available:', e.message); }
try { cloudBehaviorBaseline = require('./cloud-modules/behavior-baseline'); } catch (e) { console.error('behavior-baseline module not available:', e.message); }
try { cloudActiveProtect = require('./cloud-modules/active-protect'); cloudActiveProtect.init && cloudActiveProtect.init(state); } catch (e) { console.error('active-protect module not available:', e.message); }
try { cloudAppDpi = require('./cloud-modules/app-dpi-rules'); } catch (e) { console.error('app-dpi-rules module not available:', e.message); }
let cloudQuarantine = null;
try {
  cloudQuarantine = require('./cloud-modules/quarantine');
  if (cloudQuarantine.init) cloudQuarantine.init(state);
  if (cloudQuarantine.setNotifier && typeof pushNotification === 'function') {
    cloudQuarantine.setNotifier((cid, title, body) => pushNotification(cid, 'security', title, body));
  }
} catch (e) { console.error('quarantine module not available:', e.message); }

// Tier-3 — community threat intel + SIEM forwarding
let cloudCommunityIntel = null, cloudSiemForwarder = null;
try { cloudCommunityIntel = require('./cloud-modules/community-intel'); cloudCommunityIntel.init(state); }
catch (e) { console.error('community-intel module not available:', e.message); }
try { cloudSiemForwarder = require('./cloud-modules/siem-forwarder'); cloudSiemForwarder.init(state); }
catch (e) { console.error('siem-forwarder module not available:', e.message); }
// Auto-refresh community intel every 6h (and once shortly after boot)
if (cloudCommunityIntel) {
  setTimeout(() => { cloudCommunityIntel.refresh().catch(e => console.error('community-intel refresh err:', e.message)); }, 30_000);
  setInterval(() => { cloudCommunityIntel.refresh().catch(e => console.error('community-intel refresh err:', e.message)); }, 6 * 3600_000);
}

// ── Tier-3 Feature A: community-intel admin + customer endpoints ──────────
app.post('/admin/api/community-intel/refresh', adminAuth, async (req, res) => {
  if (!cloudCommunityIntel) return res.status(500).json({ error: 'community_intel_unavailable' });
  try {
    const r = await cloudCommunityIntel.refresh();
    if (typeof logAdminAction === 'function') logAdminAction(req, 'community_intel.refresh', '', `${r.total_ips || 0} IPs, ${r.total_domains || 0} domains`);
    res.json(r);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/admin/api/community-intel/status', adminAuth, (req, res) => {
  if (!cloudCommunityIntel) return res.json({ enabled: false });
  res.json(cloudCommunityIntel.status());
});
app.get('/api/customer/community-intel/status', customerAuth, (req, res) => {
  if (!cloudCommunityIntel) return res.json({ enabled: false, available: false });
  const c = state.customers[req.customer.id];
  const enabled = c && c.community_intel_enabled !== false;  // default true (opt-out)
  res.json({ enabled, available: true, ...cloudCommunityIntel.status() });
});
app.post('/api/customer/community-intel/toggle', customerAuth, (req, res) => {
  const c = state.customers[req.customer.id];
  if (!c) return res.status(404).json({ error: 'customer_not_found' });
  c.community_intel_enabled = !!req.body.enabled;
  saveState();
  // Bump global policy version so boxes pick up the change on next pull
  state._policy_global_version = (state._policy_global_version || 0) + 1;
  res.json({ ok: true, enabled: c.community_intel_enabled });
});

// ── Tier-3 Feature B: SIEM-forwarding endpoints ───────────────────────────
app.get('/api/customer/siem-config', customerAuth, (req, res) => {
  if (!cloudSiemForwarder) return res.json({ available: false });
  const cfg = cloudSiemForwarder.getConfig(req.customer.id) || { enabled: false };
  // Don't leak internal counters' day-key — just the numbers
  res.json({
    available: true,
    enabled: !!cfg.enabled,
    transport: cfg.transport || 'tcp',
    host: cfg.host || '',
    port: cfg.port || 0,
    format: cfg.format || 'json',
    forward_alarms: cfg.forward_alarms !== false,
    forward_flows:  !!cfg.forward_flows,
    forwarded_today: cfg.forwarded_today || 0,
    dropped_today:   cfg.dropped_today || 0,
    last_error:      cfg.last_error || null,
    last_error_at:   cfg.last_error_at || 0,
    last_success_at: cfg.last_success_at || 0,
  });
});
app.post('/api/customer/siem-config', customerAuth, (req, res) => {
  if (!cloudSiemForwarder) return res.status(500).json({ error: 'siem_unavailable' });
  try {
    const cfg = cloudSiemForwarder.configure({
      customer_id: req.customer.id,
      transport:      req.body.transport,
      host:           req.body.host,
      port:           req.body.port,
      format:         req.body.format,
      enabled:        req.body.enabled,
      forward_alarms: req.body.forward_alarms,
      forward_flows:  req.body.forward_flows,
    });
    saveState();
    res.json({ ok: true, enabled: cfg.enabled, transport: cfg.transport, host: cfg.host, port: cfg.port, format: cfg.format });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.post('/api/customer/siem-test', customerAuth, async (req, res) => {
  if (!cloudSiemForwarder) return res.status(500).json({ error: 'siem_unavailable' });
  const cfg = cloudSiemForwarder.getConfig(req.customer.id);
  if (!cfg || !cfg.enabled) return res.status(400).json({ error: 'siem_not_configured', message: 'Enable and save your SIEM config first.' });
  const r = await cloudSiemForwarder.forward(req.customer.id, {
    type: 'test',
    severity: 'low',
    kind: 'siem_test',
    title: 'mes Network SIEM test',
    message: 'mes Network SIEM test',
    customer_id: req.customer.id,
    ts: Date.now(),
  });
  res.json(r);
});

// ── Tier-3 Feature C: IoT default-credential test endpoints ───────────────
// Tokens are short-lived (10 minutes), single-use, and the box echoes them
// back to prove this scan was customer-authorized. NEVER auto-issue without
// an explicit opt-in flag.
if (!state.iot_credtest_tokens) state.iot_credtest_tokens = {};  // { token: { cid, mac, issued_at, used } }
if (!state.iot_credtest_results) state.iot_credtest_results = {}; // { cid: [{ts, findings, scanned}] }

app.post('/api/customer/iot/credtest/opt-in', customerAuth, (req, res) => {
  const c = state.customers[req.customer.id];
  if (!c) return res.status(404).json({ error: 'customer_not_found' });
  c.iot_credtest_opted_in = !!req.body.opted_in;
  c.iot_credtest_opted_in_at = c.iot_credtest_opted_in ? Date.now() : 0;
  saveState();
  res.json({ ok: true, opted_in: c.iot_credtest_opted_in });
});
app.get('/api/customer/iot/credtest/status', customerAuth, (req, res) => {
  const c = state.customers[req.customer.id];
  res.json({
    opted_in: !!(c && c.iot_credtest_opted_in),
    opted_in_at: (c && c.iot_credtest_opted_in_at) || 0,
    last_results: (state.iot_credtest_results[req.customer.id] || []).slice(-5).reverse(),
  });
});
app.post('/api/customer/iot/credtest/start', customerAuth, async (req, res) => {
  const c = state.customers[req.customer.id];
  if (!c || !c.iot_credtest_opted_in) {
    return res.status(403).json({ error: 'opt_in_required', message: 'You must opt in before any scan runs.' });
  }
  // Find the customer's box
  const myBoxes = Object.values(state.authorized_macs).filter(m => m.customer_id === c.id);
  if (!myBoxes.length) return res.status(404).json({ error: 'no_box_assigned' });
  const boxMac = myBoxes[0].mac;
  // Build a target device list — ONLY LAN devices that the box has reported
  const seen = state.box_devices[boxMac] || {};
  const devices = Object.values(seen)
    .filter(d => d.ip && /^\d+\.\d+\.\d+\.\d+$/.test(d.ip))
    .map(d => ({ mac: d.mac, ip: d.ip, vendor: d.vendor || '' }));
  if (!devices.length) return res.status(400).json({ error: 'no_lan_devices_known' });
  // Issue a one-time opt-in token
  const token = shortId(32);
  state.iot_credtest_tokens[token] = { cid: c.id, mac: boxMac, issued_at: Date.now(), used: false };
  // Queue the action on the box
  if (!state.box_commands[boxMac]) state.box_commands[boxMac] = [];
  state.box_commands[boxMac].push({
    id: shortId(16),
    action: 'iot-credtest',
    args: { devices, opt_in_token: token, expected_token: token },
    status: 'pending',
    created_at: Date.now(),
    result: null,
    completed_at: null,
  });
  saveState();
  res.json({ ok: true, queued: true, devices_count: devices.length, token_issued: true });
});
// Box-side: report the credtest findings + raise an alarm per vulnerable finding
app.post('/api/box/iot/credtest/result', boxAuth, (req, res) => {
  const cid = req.boxCustomerId;
  if (!cid) return res.status(400).json({ error: 'no_customer' });
  const token = String(req.body.token || '');
  const t = state.iot_credtest_tokens[token];
  if (!t || t.cid !== cid || t.used) return res.status(403).json({ error: 'invalid_or_used_token' });
  t.used = true;
  const findings = Array.isArray(req.body.findings) ? req.body.findings : [];
  // SAFETY check: refuse the report if any finding contains a 'credentials'
  // / 'password' / 'user' field — module promises NOT to return working creds.
  for (const f of findings) {
    for (const banned of ['credentials','password','user','username','passphrase']) {
      if (banned in f) {
        console.log(`         🚨 credtest result contained banned field ${banned} — discarding`);
        return res.status(400).json({ error: 'leaked_credentials_in_response' });
      }
    }
  }
  // Record the result
  if (!state.iot_credtest_results[cid]) state.iot_credtest_results[cid] = [];
  state.iot_credtest_results[cid].push({
    ts: Date.now(),
    scanned: req.body.scanned || findings.length,
    findings,
  });
  // Keep only the last 20 runs per customer
  if (state.iot_credtest_results[cid].length > 20) {
    state.iot_credtest_results[cid] = state.iot_credtest_results[cid].slice(-20);
  }
  // Raise an alarm per vulnerable device
  for (const f of findings) {
    if (!f.vulnerable) continue;
    if (typeof fireSyntheticAlarm === 'function') {
      fireSyntheticAlarm(cid, req.boxMac, 'high', 'iot_default_creds_found',
        '🔓 Device uses default credentials',
        `Your ${f.vendor || 'device'} at ${f.ip} (${f.service.toUpperCase()}) uses default credentials — change immediately.`,
        { device_mac: f.mac, dst_ip: f.ip, attempts: f.attempts, service: f.service });
    }
  }
  saveState();
  res.json({ ok: true, recorded: findings.length });
});

// Inject the box-command queue so portscan can enqueue internal scans on boxes
if (cloudPortscan && cloudPortscan.setBoxQueue) {
  cloudPortscan.setBoxQueue({
    enqueue: (mac, cmd) => {
      if (!state.box_commands[mac]) state.box_commands[mac] = [];
      state.box_commands[mac].push({ id: shortId(16), action: 'admin-diag', args: cmd, status: 'pending', created_at: Date.now(), result: null, completed_at: null });
    },
  });
}

// External port scan against a customer's public IP
app.post('/admin/api/portscan/external', adminAuth, async (req, res) => {
  if (!cloudPortscan) return res.status(500).json({ error: 'portscan_unavailable' });
  const ip = String(req.body.ip || '').trim();
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return res.status(400).json({ error: 'invalid_ipv4' });
  try {
    const r = await cloudPortscan.scanExternal(ip, { timeout_ms: 60000 });
    cloudPortscan.recordScan(ip, r);
    if (typeof logAdminAction === 'function') logAdminAction(req, 'portscan.external', ip, `${r.open_ports.length} open`);
    res.json(r);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/admin/api/portscan/history', adminAuth, (req, res) => {
  if (!cloudPortscan) return res.json({ history: [] });
  const target = req.query.target || null;
  res.json({ history: cloudPortscan.getScanHistory(target) || [] });
});
// Internal LAN scan (queued on the box agent)
app.post('/admin/api/portscan/internal', adminAuth, (req, res) => {
  if (!cloudPortscan) return res.status(500).json({ error: 'portscan_unavailable' });
  const mac = normalizeMac(req.body.mac || '');
  const subnet = String(req.body.subnet || '192.168.1.0/24');
  if (!state.authorized_macs[mac]) return res.status(404).json({ error: 'unknown_box' });
  try {
    cloudPortscan.scanInternalSubnet(mac, subnet, {});
    res.json({ ok: true, queued: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// NL flow search (admin sees all flows)
app.post('/admin/api/flows/search', adminAuth, async (req, res) => {
  if (!cloudNlFlowSearch) return res.status(500).json({ error: 'nl_search_unavailable' });
  const q = String(req.body.q || '').trim();
  if (!q) return res.status(400).json({ error: 'query_required' });
  try {
    const parsed = await cloudNlFlowSearch.parse(q, {});
    const filtered = cloudNlFlowSearch.applyFilter(state.flows, parsed.filter);
    res.json({ query: q, ...parsed, total: filtered.length, flows: filtered.slice(0, 200) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// Customer NL flow search (their own flows)
app.post('/api/customer/flows/search', customerAuth, async (req, res) => {
  if (!cloudNlFlowSearch) return res.status(500).json({ error: 'nl_search_unavailable' });
  const q = String(req.body.q || '').trim();
  if (!q) return res.status(400).json({ error: 'query_required' });
  try {
    const parsed = await cloudNlFlowSearch.parse(q, {});
    const myFlows = state.flows.filter(f => f.customer_id === req.customer.id);
    const filtered = cloudNlFlowSearch.applyFilter(myFlows, parsed.filter);
    res.json({ query: q, ...parsed, total: filtered.length, flows: filtered.slice(0, 200) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Signature engine: customer-managed extra signatures (cloud propagates to box)
if (!state.custom_signatures) state.custom_signatures = {};   // cid → [sig...]
app.get('/api/customer/signatures', customerAuth, (req, res) => {
  res.json({ signatures: state.custom_signatures[req.customer.id] || [] });
});
app.post('/api/customer/signatures/add', customerAuth, (req, res) => {
  const cid = req.customer.id;
  const sig = req.body.signature;
  if (!sig || !sig.name || !Array.isArray(sig.matchers)) return res.status(400).json({ error: 'invalid_sig' });
  if (!state.custom_signatures[cid]) state.custom_signatures[cid] = [];
  if (state.custom_signatures[cid].length >= 50) return res.status(429).json({ error: 'max 50 sigs per customer' });
  const id = sig.id || ('SIG-' + shortId(8));
  state.custom_signatures[cid].push({ ...sig, id, enabled: true, created_at: Date.now() });
  saveState();
  if (typeof bumpPolicyEtag === 'function') bumpPolicyEtag(cid, 'sig_added');
  res.json({ ok: true, id });
});
app.post('/api/customer/signatures/delete', customerAuth, (req, res) => {
  const list = state.custom_signatures[req.customer.id] || [];
  const i = list.findIndex(s => s.id === req.body.id);
  if (i < 0) return res.status(404).json({ error: 'not_found' });
  list.splice(i, 1);
  saveState();
  if (typeof bumpPolicyEtag === 'function') bumpPolicyEtag(req.customer.id, 'sig_removed');
  res.json({ ok: true });
});
// Box agent reports a sig-engine hit
app.post('/api/box/sig-hit', boxAuth, (req, res) => {
  if (!state.sig_hits) state.sig_hits = [];
  const cid = req.boxCustomerId;
  const hit = {
    ts: req.body.ts || Date.now(),
    box_mac: req.boxMac,
    customer_id: cid,
    sig_id: req.body.sig_id,
    sig_name: req.body.sig_name,
    severity: req.body.severity,
    flow_summary: req.body.flow_summary || '',
  };
  state.sig_hits.unshift(hit);
  if (state.sig_hits.length > 1000) state.sig_hits.length = 1000;
  // Auto-fire alarm
  if (cid && typeof fireSyntheticAlarm === 'function') {
    fireSyntheticAlarm(cid, req.boxMac, hit.severity || 'medium', 'sig_match',
      `Signature match: ${hit.sig_name}`, `Flow: ${hit.flow_summary}`);
  }
  res.json({ ok: true });
});
app.get('/admin/api/sig-hits', adminAuth, (req, res) => {
  res.json({ hits: state.sig_hits || [] });
});

// SNI/JA3 reporting from box agent
app.post('/api/box/sni-handshakes', boxAuth, (req, res) => {
  if (!state.sni_handshakes) state.sni_handshakes = {};
  const cid = req.boxCustomerId;
  if (!cid) return res.json({ ok: true, accepted: 0 });
  if (!state.sni_handshakes[cid]) state.sni_handshakes[cid] = [];
  const list = Array.isArray(req.body.handshakes) ? req.body.handshakes : [];
  // Resolve box's primary device-MAC mapping once (used for alarm device_mac
  // hints — the SNI handshake records carry src_ip not src_mac, so we leave
  // device_mac blank when we can't infer it cheaply).
  for (const h of list.slice(0, 200)) {
    const sni = (h.sni || '').toLowerCase();
    const ja3 = (h.ja3_md5 || '').toLowerCase();
    state.sni_handshakes[cid].push({
      ts: h.ts || Date.now(),
      src_ip: h.src_ip, dst_ip: h.dst_ip, dst_port: h.dst_port,
      sni, ja3_md5: ja3,
      box_mac: req.boxMac,
    });
    // Feature D: bypass-attempt detection. Match SNI against known DoH /
    // VPN / Tor / iCloud Private Relay patterns; on hit, fire alarm with
    // dst_domain so the existing "Block source" button works.
    if (sni && typeof fireSyntheticAlarm === 'function') {
      for (const p of BYPASS_SNI_PATTERNS) {
        if (p.re.test(sni)) {
          fireSyntheticAlarm(cid, req.boxMac, 'medium', 'bypass_attempt',
            `Filter-bypass attempt: ${p.label}`,
            `A device on your network reached ${sni} (${p.label}). This can route around parental controls and DNS-level filtering.`,
            { dst_domain: sni, dst_ip: h.dst_ip || '' });
          break;
        }
      }
    }
    // Feature C: JA3 malware-fingerprint check. Currently the box's tshark
    // pipeline does NOT emit ja3_md5 (tshark 4.x dropped the field; see
    // sni-parser.js). This branch is therefore dormant until either the
    // tshark JA3 plugin is installed on boxes or we ship a Node-level
    // ClientHello parser. The cloud-side blocklist is in place.
    if (ja3 && JA3_INTEL.has(ja3) && typeof fireSyntheticAlarm === 'function') {
      fireSyntheticAlarm(cid, req.boxMac, 'high', 'ja3_malware_signature',
        'Known-bad TLS fingerprint detected',
        `A device on your network produced a TLS ClientHello fingerprint (JA3 ${ja3}) that matches a malware family in our threat-intel set${sni ? ` while reaching ${sni}` : ''}.`,
        { dst_domain: sni, dst_ip: h.dst_ip || '' });
    }
  }
  // 24-hour retention
  const cutoff = Date.now() - 24 * 3600_000;
  state.sni_handshakes[cid] = state.sni_handshakes[cid].filter(h => h.ts >= cutoff).slice(-5000);
  res.json({ ok: true, accepted: list.length });
});
app.get('/api/customer/sni-handshakes', customerAuth, (req, res) => {
  const list = (state.sni_handshakes && state.sni_handshakes[req.customer.id]) || [];
  res.json({ handshakes: list.slice(-200).reverse() });
});

// Behavior baseline — admin sees recent anomalies, customer sees own
app.get('/admin/api/behavior/anomalies', adminAuth, (req, res) => {
  if (!cloudBehaviorBaseline) return res.json({ anomalies: [] });
  const limit = Math.min(parseInt(req.query.limit) || 100, 500);
  res.json({ anomalies: cloudBehaviorBaseline.getRecentAnomalies(limit) });
});
app.get('/admin/api/behavior/baseline/:mac', adminAuth, (req, res) => {
  if (!cloudBehaviorBaseline) return res.status(404).json({ error: 'not_loaded' });
  const b = cloudBehaviorBaseline.getBaseline(normalizeMac(req.params.mac));
  if (!b) return res.status(404).json({ error: 'no_baseline' });
  res.json(b);
});
app.get('/api/customer/behavior/anomalies', customerAuth, (req, res) => {
  if (!cloudBehaviorBaseline) return res.json({ anomalies: [] });
  const myMacs = new Set(Object.values(state.authorized_macs).filter(m => m.customer_id === req.customer.id).map(m => m.mac));
  // Include device MACs the customer's boxes have seen
  for (const boxMac of myMacs) {
    for (const dmac of Object.keys(state.box_devices[boxMac] || {})) myMacs.add(dmac);
  }
  const all = cloudBehaviorBaseline.getRecentAnomalies(500);
  const mine = all.filter(a => myMacs.has(a.mac));
  res.json({ anomalies: mine });
});

// Active Protect (IoT lockdown)
app.post('/api/customer/active-protect/enable', customerAuth, (req, res) => {
  if (!cloudActiveProtect) return res.status(500).json({ error: 'not_loaded' });
  const mac = normalizeMac(req.body.device_mac || '');
  if (!mac) return res.status(400).json({ error: 'device_mac required' });
  const opts = { learning_days: parseInt(req.body.learning_days) || 7 };
  const r = cloudActiveProtect.enable(req.customer.id, mac, opts);
  saveState();
  res.json(r || { ok: true });
});
app.post('/api/customer/active-protect/disable', customerAuth, (req, res) => {
  if (!cloudActiveProtect) return res.status(500).json({ error: 'not_loaded' });
  const mac = normalizeMac(req.body.device_mac || '');
  cloudActiveProtect.disable(req.customer.id, mac);
  saveState();
  res.json({ ok: true });
});
app.get('/api/customer/active-protect/:mac', customerAuth, (req, res) => {
  if (!cloudActiveProtect) return res.status(500).json({ error: 'not_loaded' });
  res.json(cloudActiveProtect.getStatus(req.customer.id, normalizeMac(req.params.mac)) || {});
});
app.post('/api/customer/active-protect/finish-learning', customerAuth, (req, res) => {
  if (!cloudActiveProtect) return res.status(500).json({ error: 'not_loaded' });
  cloudActiveProtect.finishLearningEarly(req.customer.id, normalizeMac(req.body.device_mac || ''));
  saveState();
  res.json({ ok: true });
});
app.post('/api/customer/active-protect/allowlist', customerAuth, (req, res) => {
  if (!cloudActiveProtect) return res.status(500).json({ error: 'not_loaded' });
  const mac = normalizeMac(req.body.device_mac || '');
  const entry = String(req.body.entry || '').toLowerCase().trim();
  const op = String(req.body.op || 'add');
  if (op === 'add') cloudActiveProtect.addToAllowlist(req.customer.id, mac, entry);
  else if (op === 'remove') cloudActiveProtect.removeFromAllowlist(req.customer.id, mac, entry);
  saveState();
  res.json({ ok: true });
});

// App-DPI: identify recent SNI handshakes → known apps + suggest block rules
app.get('/api/customer/app-dpi/recent', customerAuth, (req, res) => {
  if (!cloudAppDpi) return res.json({ apps: [] });
  res.json({ apps: cloudAppDpi.getRecentApps(req.customer.id) || [] });
});
app.post('/api/customer/app-dpi/identify', customerAuth, (req, res) => {
  if (!cloudAppDpi) return res.status(500).json({ error: 'not_loaded' });
  const handshakes = (state.sni_handshakes && state.sni_handshakes[req.customer.id]) || [];
  const grouped = cloudAppDpi.identifyApps(handshakes);
  // Record so getRecentApps reflects this
  for (const [appName, info] of Object.entries(grouped)) {
    for (const h of (info.sample_handshakes || []).slice(0, 5)) {
      cloudAppDpi.recordIdentification(req.customer.id, h.src_ip || '', appName, Date.now());
    }
  }
  res.json({ identified: grouped });
});
app.get('/api/customer/app-dpi/known-apps', customerAuth, (req, res) => {
  if (!cloudAppDpi) return res.json({ apps: [] });
  res.json({ apps: cloudAppDpi.getKnownApps() });
});
app.post('/api/customer/app-dpi/suggest-rule', customerAuth, (req, res) => {
  if (!cloudAppDpi) return res.status(500).json({ error: 'not_loaded' });
  const app = String(req.body.app || '').trim();
  if (!app) return res.status(400).json({ error: 'app name required' });
  res.json(cloudAppDpi.suggestBlockRule(app) || { error: 'unknown_app' });
});

// Quarantine workflow
app.get('/api/customer/quarantine', customerAuth, (req, res) => {
  if (!cloudQuarantine) return res.json({ enabled: false, devices: [] });
  res.json({ enabled: cloudQuarantine.isEnabled(req.customer.id), devices: cloudQuarantine.getQuarantined(req.customer.id) });
});
app.post('/api/customer/quarantine/enable', customerAuth, (req, res) => {
  if (!cloudQuarantine) return res.status(500).json({ error: 'not_loaded' });
  cloudQuarantine.enableForCustomer(req.customer.id, req.body || {});
  saveState();
  res.json({ ok: true });
});
app.post('/api/customer/quarantine/disable', customerAuth, (req, res) => {
  if (!cloudQuarantine) return res.status(500).json({ error: 'not_loaded' });
  cloudQuarantine.disableForCustomer(req.customer.id);
  saveState();
  res.json({ ok: true });
});
app.post('/api/customer/quarantine/approve', customerAuth, (req, res) => {
  if (!cloudQuarantine) return res.status(500).json({ error: 'not_loaded' });
  cloudQuarantine.approve(req.customer.id, normalizeMac(req.body.mac || ''));
  saveState();
  res.json({ ok: true });
});
app.post('/api/customer/quarantine/block', customerAuth, (req, res) => {
  if (!cloudQuarantine) return res.status(500).json({ error: 'not_loaded' });
  cloudQuarantine.block(req.customer.id, normalizeMac(req.body.mac || ''));
  saveState();
  res.json({ ok: true });
});

// Simple Mode (Firewalla-style auto-discovery via ARP-spoof) — customer-facing one-tap
app.post('/api/customer/box/:mac/simple-mode/start', customerAuth, (req, res) => {
  const mac = normalizeMac(req.params.mac);
  const m = state.authorized_macs[mac];
  if (!m || m.customer_id !== req.customer.id) return res.status(403).json({ error: 'not_your_box' });
  if (!state.box_commands[mac]) state.box_commands[mac] = [];
  const cmd = { id: shortId(16), action: 'simple-mode-start', args: req.body || {}, status: 'pending', created_at: Date.now(), result: null, completed_at: null };
  state.box_commands[mac].push(cmd);
  state.box_network_modes[mac] = 'simple';
  saveState();
  res.json({ ok: true, queued: cmd, note: 'Pi will start ARP-spoofing the gateway in ~60s. All LAN devices will route through it transparently.' });
});
app.post('/api/customer/box/:mac/simple-mode/stop', customerAuth, (req, res) => {
  const mac = normalizeMac(req.params.mac);
  const m = state.authorized_macs[mac];
  if (!m || m.customer_id !== req.customer.id) return res.status(403).json({ error: 'not_your_box' });
  if (!state.box_commands[mac]) state.box_commands[mac] = [];
  state.box_commands[mac].push({ id: shortId(16), action: 'simple-mode-stop', args: {}, status: 'pending', created_at: Date.now(), result: null, completed_at: null });
  state.box_network_modes[mac] = 'peer';
  saveState();
  res.json({ ok: true });
});
app.post('/api/customer/box/:mac/simple-mode/rescan', customerAuth, (req, res) => {
  const mac = normalizeMac(req.params.mac);
  const m = state.authorized_macs[mac];
  if (!m || m.customer_id !== req.customer.id) return res.status(403).json({ error: 'not_your_box' });
  if (!state.box_commands[mac]) state.box_commands[mac] = [];
  state.box_commands[mac].push({ id: shortId(16), action: 'simple-mode-rescan', args: {}, status: 'pending', created_at: Date.now(), result: null, completed_at: null });
  res.json({ ok: true });
});

// NTP intercept / Disturb / Bridge / UPnP — delegate to box agent
function queueBoxAction(mac, action, args) {
  if (!state.box_commands[mac]) state.box_commands[mac] = [];
  const cmd = { id: shortId(16), action, args: args || {}, status: 'pending', created_at: Date.now(), result: null, completed_at: null };
  state.box_commands[mac].push(cmd);
  return cmd;
}
app.post('/admin/api/box/:mac/ntp/install', adminAuth, (req, res) => {
  const mac = normalizeMac(req.params.mac);
  if (!state.authorized_macs[mac]) return res.status(404).json({ error: 'unknown_box' });
  res.json({ ok: true, queued: queueBoxAction(mac, 'ntp-install', req.body) });
});
app.post('/admin/api/box/:mac/disturb/apply', adminAuth, (req, res) => {
  const mac = normalizeMac(req.params.mac);
  if (!state.authorized_macs[mac]) return res.status(404).json({ error: 'unknown_box' });
  res.json({ ok: true, queued: queueBoxAction(mac, 'disturb-apply', req.body) });
});
app.post('/admin/api/box/:mac/disturb/remove', adminAuth, (req, res) => {
  const mac = normalizeMac(req.params.mac);
  if (!state.authorized_macs[mac]) return res.status(404).json({ error: 'unknown_box' });
  res.json({ ok: true, queued: queueBoxAction(mac, 'disturb-remove', req.body) });
});
app.post('/admin/api/box/:mac/bridge/install', adminAuth, (req, res) => {
  const mac = normalizeMac(req.params.mac);
  if (!state.authorized_macs[mac]) return res.status(404).json({ error: 'unknown_box' });
  res.json({ ok: true, queued: queueBoxAction(mac, 'bridge-install', req.body) });
});
app.post('/admin/api/box/:mac/upnp/install', adminAuth, (req, res) => {
  const mac = normalizeMac(req.params.mac);
  if (!state.authorized_macs[mac]) return res.status(404).json({ error: 'unknown_box' });
  res.json({ ok: true, queued: queueBoxAction(mac, 'upnp-install', req.body) });
});

// DNS stack admin (delegates to box agent)
app.post('/admin/api/box/:mac/dns-stack/install', adminAuth, (req, res) => {
  const mac = normalizeMac(req.params.mac);
  if (!state.authorized_macs[mac]) return res.status(404).json({ error: 'unknown_box' });
  if (!state.box_commands[mac]) state.box_commands[mac] = [];
  state.box_commands[mac].push({ id: shortId(16), action: 'dns-stack-install', args: req.body || {}, status: 'pending', created_at: Date.now(), result: null, completed_at: null });
  res.json({ ok: true, queued: true });
});
app.post('/admin/api/box/:mac/dns-stack/mode', adminAuth, (req, res) => {
  const mac = normalizeMac(req.params.mac);
  if (!state.authorized_macs[mac]) return res.status(404).json({ error: 'unknown_box' });
  if (!state.box_commands[mac]) state.box_commands[mac] = [];
  state.box_commands[mac].push({ id: shortId(16), action: 'dns-stack-mode', args: { mode: req.body.mode, upstreams: req.body.upstreams }, status: 'pending', created_at: Date.now(), result: null, completed_at: null });
  res.json({ ok: true, queued: true });
});

// Multi-WAN admin
app.post('/admin/api/box/:mac/multi-wan/configure', adminAuth, (req, res) => {
  const mac = normalizeMac(req.params.mac);
  if (!state.authorized_macs[mac]) return res.status(404).json({ error: 'unknown_box' });
  if (!state.box_commands[mac]) state.box_commands[mac] = [];
  state.box_commands[mac].push({ id: shortId(16), action: 'multi-wan-configure', args: { wans: req.body.wans, mode: req.body.mode }, status: 'pending', created_at: Date.now(), result: null, completed_at: null });
  res.json({ ok: true, queued: true });
});
app.post('/admin/api/box/:mac/multi-wan/route-device', adminAuth, (req, res) => {
  const mac = normalizeMac(req.params.mac);
  if (!state.authorized_macs[mac]) return res.status(404).json({ error: 'unknown_box' });
  if (!state.box_commands[mac]) state.box_commands[mac] = [];
  state.box_commands[mac].push({ id: shortId(16), action: 'multi-wan-route-device', args: { device_mac: req.body.device_mac, wan: req.body.wan }, status: 'pending', created_at: Date.now(), result: null, completed_at: null });
  res.json({ ok: true, queued: true });
});

// OpenVPN admin (delegates real config to the box agent's openvpn.js)
app.post('/admin/api/box/:mac/openvpn/install', adminAuth, (req, res) => {
  const mac = normalizeMac(req.params.mac);
  if (!state.authorized_macs[mac]) return res.status(404).json({ error: 'unknown_box' });
  if (!state.box_commands[mac]) state.box_commands[mac] = [];
  state.box_commands[mac].push({ id: shortId(16), action: 'openvpn-install', args: req.body || {}, status: 'pending', created_at: Date.now(), result: null, completed_at: null });
  res.json({ ok: true, queued: true });
});
app.post('/admin/api/box/:mac/openvpn/add-client', adminAuth, (req, res) => {
  const mac = normalizeMac(req.params.mac);
  if (!state.authorized_macs[mac]) return res.status(404).json({ error: 'unknown_box' });
  if (!state.box_commands[mac]) state.box_commands[mac] = [];
  state.box_commands[mac].push({ id: shortId(16), action: 'openvpn-add-client', args: { name: req.body.name }, status: 'pending', created_at: Date.now(), result: null, completed_at: null });
  res.json({ ok: true, queued: true });
});

// ─── Network mode wizard (Simple / DHCP / Bridge / Router / Peer) ───────
// Stores customer's chosen deployment mode for each box. The box agent reads
// `network_mode` from the policy bundle and applies the matching config.
if (!state.box_network_modes) state.box_network_modes = {};   // mac → 'peer'|'simple'|'dhcp'|'bridge'|'router'

const NETWORK_MODES = {
  peer:   { label: 'Peer (passive)',          desc: 'Box is a regular LAN device. Watches via ARP only — no traffic interception. Safe default.' },
  dhcp:   { label: 'DHCP Mode',                desc: 'Box becomes the LAN DHCP+DNS server. Existing router still handles WAN. Recommended for most homes.' },
  bridge: { label: 'Transparent Bridge',       desc: 'Box sits inline between modem and router. No IP changes for clients. Needs 2 ethernet ports.' },
  router: { label: 'Router Mode',              desc: 'Box replaces your router entirely. Full gateway. Most invasive, most powerful.' },
  simple: { label: 'Simple Mode (ARP spoof)',  desc: 'Box impersonates the gateway via ARP. Intercepts traffic without re-cabling. Some IoT devices hate it.' },
};

app.get('/api/customer/box/:mac/network-mode', customerAuth, (req, res) => {
  const mac = normalizeMac(req.params.mac);
  const m = state.authorized_macs[mac];
  if (!m || m.customer_id !== req.customer.id) return res.status(403).json({ error: 'not_your_box' });
  const mode = state.box_network_modes[mac] || 'peer';
  res.json({
    current: mode,
    available: NETWORK_MODES,
    setup_steps: networkModeSetupSteps(mode, m),
  });
});

app.post('/api/customer/box/:mac/network-mode', customerAuth, (req, res) => {
  const mac = normalizeMac(req.params.mac);
  const m = state.authorized_macs[mac];
  if (!m || m.customer_id !== req.customer.id) return res.status(403).json({ error: 'not_your_box' });
  const newMode = String(req.body.mode || '').toLowerCase();
  if (!NETWORK_MODES[newMode]) return res.status(400).json({ error: 'invalid_mode', allowed: Object.keys(NETWORK_MODES) });
  const oldMode = state.box_network_modes[mac] || 'peer';
  if (newMode === oldMode) return res.json({ ok: true, mode: newMode, no_change: true });

  // Queue commands to:
  //   1. STOP the current inline mode (if any)
  //   2. START the new mode
  if (!state.box_commands[mac]) state.box_commands[mac] = [];
  const queue = (action, args = {}) => state.box_commands[mac].push({
    id: shortId(16), action, args, status: 'pending', created_at: Date.now(), result: null, completed_at: null,
  });

  // Step 1: stop the old mode cleanly
  if (oldMode === 'simple') queue('simple-mode-stop');
  else if (oldMode === 'bridge') queue('bridge-uninstall');
  else if (oldMode === 'dhcp') queue('dhcp-mode-stop');
  else if (oldMode === 'router') queue('router-mode-stop');
  // 'peer' has no inline activity to stop.

  // Step 2: start the new mode
  if (newMode === 'simple') queue('simple-mode-start', {});
  else if (newMode === 'bridge') queue('bridge-install', { wan_iface: req.body.wan_iface || 'eth0', lan_iface: req.body.lan_iface || 'eth1' });
  else if (newMode === 'dhcp') queue('dhcp-mode-start', { lan_iface: req.body.lan_iface || 'eth0' });
  else if (newMode === 'router') queue('router-mode-start', { wan_iface: req.body.wan_iface, lan_iface: req.body.lan_iface });
  // 'peer' = no inline activity, just stopped above.

  state.box_network_modes[mac] = newMode;
  if (typeof bumpPolicyEtag === 'function' && m.customer_id) bumpPolicyEtag(m.customer_id, `network_mode:${newMode}`);
  saveState();
  if (typeof pushNotification === 'function' && m.customer_id) {
    pushNotification(m.customer_id, 'system', `Switching to ${NETWORK_MODES[newMode].label}`,
      `Box ${mac} is changing mode (${oldMode} → ${newMode}). Activation runs in ~60 seconds.`);
  }
  if (typeof logAdminAction === 'function') logAdminAction({ adminUser: req.customer.id, ip: req.ip }, 'network_mode.switch', mac, `${oldMode}→${newMode}`);
  res.json({ ok: true, mode: newMode, previous: oldMode, queued_steps: state.box_commands[mac].slice(-2).map(c => c.action), setup_steps: networkModeSetupSteps(newMode, m) });
});

function networkModeSetupSteps(mode, boxAuth) {
  const internal_ip = (state.box_state[boxAuth.mac] && state.box_state[boxAuth.mac].internal_ip) || '<box LAN IP>';
  const subnet = internal_ip.includes('.') ? internal_ip.split('.').slice(0, 3).join('.') + '.0/24' : '192.168.1.0/24';
  if (mode === 'peer') {
    return [
      'No setup needed — box is in passive mode.',
      'It can see devices via ARP scan but does not intercept any traffic.',
      'Pick a different mode to actually block / monitor flows.',
    ];
  }
  if (mode === 'dhcp') {
    return [
      `1. SSH to the box: ssh pi@${internal_ip}`,
      '2. Confirm dnsmasq is running: sudo systemctl status dnsmasq',
      `3. Verify it serves DNS locally: dig @${internal_ip} google.com +short`,
      `4. Open your home router admin (usually http://${internal_ip.split('.').slice(0,3).join('.')}.1)`,
      `5. Find DHCP settings → set Primary DNS = ${internal_ip}`,
      '6. Save. Reboot one device to test (or wait for DHCP renewal).',
      `7. Run: dig facebook.com — if blocked categories are configured it should return 0.0.0.0.`,
    ];
  }
  if (mode === 'bridge') {
    return [
      'Requires the box to have 2 ethernet ports (Pi 4 has 1, you need a USB-Ethernet adapter).',
      `1. SSH to the box: ssh pi@${internal_ip}`,
      '2. Install bridge-utils: sudo apt install -y bridge-utils',
      '3. Power off the box.',
      '4. Cable: modem → eth0 (box) → eth1 (box) → router LAN port.',
      '5. Bring up the bridge: sudo ip link add br0 type bridge && sudo ip link set eth0 master br0 && sudo ip link set eth1 master br0',
      '6. Add ebtables FORWARD rule for inspection.',
      '7. Power on, verify clients still reach internet.',
    ];
  }
  if (mode === 'router') {
    return [
      'WARNING: this replaces your existing router. Have a recovery plan.',
      `1. SSH to the box: ssh pi@${internal_ip}`,
      '2. Connect WAN cable (from modem) to eth0 of the box.',
      '3. Connect LAN devices to a switch downstream of the box, OR use the box\'s wlan0 as AP.',
      '4. Apply: sudo sysctl -w net.ipv4.ip_forward=1',
      `5. NAT: sudo iptables -t nat -A POSTROUTING -o eth0 -s ${subnet} -j MASQUERADE`,
      '6. Configure dnsmasq for DHCP+DNS on the LAN side.',
      '7. Disable your old router\'s DHCP (or unplug it entirely).',
    ];
  }
  if (mode === 'simple') {
    return [
      'Box impersonates the gateway via gratuitous ARP. No re-cabling.',
      `1. SSH to the box: ssh pi@${internal_ip}`,
      '2. Install: sudo apt install -y dsniff',
      `3. Find your real router\'s IP (e.g. ${internal_ip.split('.').slice(0,3).join('.')}.1).`,
      `4. Start ARP spoof: sudo arpspoof -i eth0 ${internal_ip.split('.').slice(0,3).join('.')}.1 (in a screen session)`,
      '5. Box now sees all client → gateway traffic.',
      '6. Some IoT cameras / Apple devices may detect this and complain. If so, pick DHCP mode instead.',
    ];
  }
  return [];
}

// ─── Firewalla AI: pattern-based event analyzer ──────────────────────────
// Looks at recent alarms / heartbeat history / flows and produces a structured
// analysis + numbered troubleshooting steps. Mirrors the MSP 2.10 "Ask AI about
// events" feature. Falls back to canned heuristics; can pass-through to a real
// LLM if MES_LLM_API_URL + MES_LLM_API_KEY env vars are set.
function aiAnalyzeEvents(opts = {}) {
  const cutoff = Date.now() - (opts.window_h || 24) * 3600_000;
  const customerScope = opts.customer_id ? state.alarms.filter(a => a.customer_id === opts.customer_id && a.ts >= cutoff) : state.alarms.filter(a => a.ts >= cutoff);
  const boxScope = opts.box_mac ? customerScope.filter(a => a.box_mac === opts.box_mac) : customerScope;

  const findings = [];
  const steps = [];

  // Pattern 1: Ethernet flapping — port disconnect+connect within short windows
  const portEvents = boxScope.filter(a => /port|ethernet|link/i.test(a.kind || '') || /port|ethernet|link/i.test(a.title || ''));
  if (portEvents.length >= 4) {
    findings.push(`Repetitive ethernet disconnects across ${new Set(portEvents.map(p => p.box_mac)).size || 1} box(es), with ${portEvents.length} events in the last ${opts.window_h || 24} hours.`);
    steps.push('Check all ethernet cables for secure connections and physical damage');
    steps.push('Replace suspect cables (especially Cat 5/3/4 connectors)');
    steps.push('Test downstream switch ports to isolate port-specific issues');
    steps.push('Inspect power supplies for connected devices');
    steps.push('Contact ISP regarding any outages of internet service if persists');
    steps.push('Monitor connections after fixes to confirm');
  }

  // Pattern 2: Persistent high latency
  const latencyEvents = boxScope.filter(a => /latency|slow|lag/i.test(a.kind || '') || /latency|slow/i.test(a.title || ''));
  if (latencyEvents.length >= 3) {
    findings.push(`${latencyEvents.length} latency-related events in the last ${opts.window_h || 24} hours. Network responsiveness may be degraded.`);
    steps.push('Run a speedtest from the box (Internet Speed page) to confirm');
    steps.push('Check ISP modem for error lights');
    steps.push('Reboot the modem and box if speeds remain low');
    steps.push('Open a ticket with ISP if upload/download is consistently below contracted rate');
  }

  // Pattern 3: Repeated box offline
  const offlineEvents = boxScope.filter(a => a.kind === 'box_offline' || /offline/i.test(a.title || ''));
  if (offlineEvents.length >= 2) {
    findings.push(`Box went offline ${offlineEvents.length} times in the last ${opts.window_h || 24} hours.`);
    steps.push('Check power cable and outlet — try a different outlet');
    steps.push('If the box is on a UPS, verify the UPS is functioning');
    steps.push('Confirm the upstream router/modem is stable (it may be the actual issue)');
    steps.push('SSH to the box and run `dmesg | tail -50` to look for kernel errors');
  }

  // Pattern 4: Traffic anomaly (sudden spike from one device)
  const trafficAnomalies = boxScope.filter(a => a.kind === 'traffic_anomaly');
  if (trafficAnomalies.length >= 1) {
    const dev = trafficAnomalies[0].title || '';
    findings.push(`Detected unusual traffic from ${trafficAnomalies.length} device(s). ${dev ? 'First flagged: ' + dev : ''}`);
    steps.push('Identify the device by its MAC and confirm it\'s legitimate (not piggybacking)');
    steps.push('Check what categories the device is communicating with — large uploads to unknown destinations are suspicious');
    steps.push('Set a daily-bandwidth quota on this device to limit damage if compromised');
    steps.push('If the device is unknown, block it immediately and investigate');
  }

  // Pattern 5: Geofence violation
  const geofenceEvents = boxScope.filter(a => a.kind === 'box_geofence' || a.kind === 'geofence_violation');
  if (geofenceEvents.length >= 1) {
    findings.push(`Box reported from a country outside the configured allowlist. This could indicate theft, ISP routing change, or VPN misconfiguration.`);
    steps.push('Verify physically that the box is at the expected location');
    steps.push('If the box was relocated intentionally, update the geofence allowlist');
    steps.push('If unexpected, factory-reset the box via /api/customer/box/action and re-pair');
  }

  // Pattern 6: Config drift
  const driftEvents = boxScope.filter(a => a.kind === 'box_config_drift' || a.kind === 'box_integrity_drift');
  if (driftEvents.length >= 1) {
    findings.push(`Box configuration files changed unexpectedly without a matching policy update.`);
    steps.push('Review the most recent config snapshot diff under /admin/api/box-snapshots');
    steps.push('If you didn\'t run an update, this could indicate tampering or local edits');
    steps.push('Restore from a known-good snapshot and reboot the box');
  }

  // Default response when no patterns matched
  if (findings.length === 0) {
    findings.push(`No alerting patterns detected over the last ${opts.window_h || 24} hours. Network is healthy.`);
    if (boxScope.length === 0) {
      steps.push('No events recorded — your network is operating normally');
    } else {
      steps.push(`Reviewed ${boxScope.length} event(s); none matched known troubleshooting patterns`);
      steps.push('Continue monitoring; the AI will alert if patterns emerge');
    }
  }

  return {
    analysis: findings.join(' '),
    findings,
    troubleshooting: steps,
    events_analyzed: boxScope.length,
    window_hours: opts.window_h || 24,
    confidence: findings.length > 0 ? 'medium' : 'low',
    generated_at: new Date().toISOString(),
    engine: 'heuristic',
  };
}

// Optional pass-through to a real LLM if creds are set
async function aiAnalyzeViaLLM(opts) {
  const apiUrl = process.env.MES_LLM_API_URL;
  const apiKey = process.env.MES_LLM_API_KEY;
  if (!apiUrl || !apiKey) return null;
  const cutoff = Date.now() - (opts.window_h || 24) * 3600_000;
  const events = (state.alarms || []).filter(a => a.ts >= cutoff).slice(0, 100).map(a => `${new Date(a.ts).toISOString()} [${a.severity}] ${a.kind}: ${a.title}`);
  const prompt = `You are a network operations assistant. Analyze these ${events.length} events from the last ${opts.window_h || 24} hours. Reply as JSON only with keys: analysis (paragraph), troubleshooting (string[] of numbered steps).\n\nEvents:\n${events.join('\n')}`;
  try {
    const r = await fetch(apiUrl, {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: 500, messages: [{ role: 'user', content: prompt }] }),
    });
    if (!r.ok) return null;
    const j = await r.json();
    const text = (j.content && j.content[0] && j.content[0].text) || j.choices?.[0]?.message?.content;
    if (!text) return null;
    const parsed = JSON.parse(text);
    return { ...parsed, engine: 'llm', generated_at: new Date().toISOString() };
  } catch (e) {
    return null;
  }
}

// Admin endpoint
app.post('/admin/api/ai/analyze-events', adminAuth, async (req, res) => {
  const opts = {
    window_h: parseInt(req.body.window_h) || 24,
    customer_id: req.body.customer_id || null,
    box_mac: req.body.box_mac || null,
  };
  let result = await aiAnalyzeViaLLM(opts);
  if (!result) result = aiAnalyzeEvents(opts);
  if (typeof logAdminAction === 'function') logAdminAction(req, 'ai.analyze_events', opts.box_mac || opts.customer_id || 'all', `${opts.window_h}h`);
  res.json(result);
});
// Customer-facing equivalent (scoped to their own data)
app.post('/api/customer/ai/analyze-events', customerAuth, async (req, res) => {
  const opts = { window_h: parseInt(req.body.window_h) || 24, customer_id: req.customer.id };
  let result = await aiAnalyzeViaLLM(opts);
  if (!result) result = aiAnalyzeEvents(opts);
  res.json(result);
});

// ─── Admin digest settings (Firewalla MSP 2.10 "Summary Digests") ────────
// Toggles for: Alarms / Network Events × Daily / Weekly. Sent to one recipient email.
if (!state.admin_digest) {
  state.admin_digest = {
    recipient: state.config.admin_email || 'admin@firewalla.com',
    alarms_daily: false,
    alarms_weekly: true,
    events_daily: true,
    events_weekly: true,
    daily_send_at: '08:00',     // 24h HH:MM (server's TZ)
    weekly_send_day: 'mon',     // mon/tue/.../sun
    weekly_send_at: '08:00',
    last_daily_sent_at: 0,
    last_weekly_sent_at: 0,
  };
  saveState();
}
app.get('/admin/api/digest', adminAuth, (req, res) => {
  res.json({ digest: state.admin_digest });
});
app.post('/admin/api/digest', adminAuth, (req, res) => {
  const d = state.admin_digest;
  if (req.body.recipient !== undefined) {
    const e = String(req.body.recipient || '').trim();
    if (!/^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i.test(e)) return res.status(400).json({ error: 'invalid email' });
    d.recipient = e;
  }
  for (const k of ['alarms_daily', 'alarms_weekly', 'events_daily', 'events_weekly']) {
    if (req.body[k] !== undefined) d[k] = !!req.body[k];
  }
  if (req.body.daily_send_at && /^([01]\d|2[0-3]):[0-5]\d$/.test(req.body.daily_send_at)) d.daily_send_at = req.body.daily_send_at;
  if (req.body.weekly_send_at && /^([01]\d|2[0-3]):[0-5]\d$/.test(req.body.weekly_send_at)) d.weekly_send_at = req.body.weekly_send_at;
  if (req.body.weekly_send_day && ['sun','mon','tue','wed','thu','fri','sat'].includes(req.body.weekly_send_day)) d.weekly_send_day = req.body.weekly_send_day;
  saveState();
  if (typeof logAdminAction === 'function') logAdminAction(req, 'admin_digest.update', '', JSON.stringify({ alarms_d: d.alarms_daily, alarms_w: d.alarms_weekly, events_d: d.events_daily, events_w: d.events_weekly }));
  res.json({ ok: true, digest: d });
});

// Compute the digest content for the admin (cross-customer aggregate)
function computeAdminDigest(periodHours) {
  const cutoff = Date.now() - periodHours * 3600_000;
  const alarmsRecent = (state.alarms || []).filter(a => a.ts >= cutoff);
  const customers = Object.values(state.customers || {});
  const boxes = Object.values(state.authorized_macs || {});
  const onlineBoxes = boxes.filter(b => state.box_state[b.mac] && (Date.now() - state.box_state[b.mac].last_heartbeat) < 5 * 60_000).length;
  // Network events: reboot + offline + drift events
  const rebootEvents = Object.values(state.reboot_events || {}).flat().filter(r => r.ts >= cutoff);
  const flowsRecent = state.flows.filter(f => f.ts >= cutoff);
  const blockedRecent = flowsRecent.filter(f => f.blocked).length;
  return {
    period_hours: periodHours,
    customers_total: customers.length,
    boxes_total: boxes.length,
    boxes_online: onlineBoxes,
    alarms_total: alarmsRecent.length,
    alarms_high: alarmsRecent.filter(a => a.severity === 'high' || a.severity === 'critical').length,
    by_severity: {
      critical: alarmsRecent.filter(a => a.severity === 'critical').length,
      high:     alarmsRecent.filter(a => a.severity === 'high').length,
      medium:   alarmsRecent.filter(a => a.severity === 'medium').length,
      low:      alarmsRecent.filter(a => a.severity === 'low').length,
    },
    flows_total: flowsRecent.length,
    flows_blocked: blockedRecent,
    block_rate_pct: flowsRecent.length > 0 ? Math.round((blockedRecent / flowsRecent.length) * 1000) / 10 : 0,
    network_events: { reboots: rebootEvents.length, offline_alarms: alarmsRecent.filter(a => a.kind === 'box_offline').length, latency_alarms: alarmsRecent.filter(a => a.kind === 'high_latency').length },
  };
}

// Preview endpoint — returns what the digest would contain right now
app.get('/admin/api/digest/preview', adminAuth, (req, res) => {
  const period = String(req.query.period || 'daily');
  const hours = period === 'weekly' ? 168 : 24;
  res.json({ period, ...computeAdminDigest(hours) });
});
// Manual send (admin-triggered)
app.post('/admin/api/digest/send-now', adminAuth, (req, res) => {
  const period = String(req.body.period || 'daily');
  const hours = period === 'weekly' ? 168 : 24;
  const d = computeAdminDigest(hours);
  const subject = `[mes Cloud] ${period === 'weekly' ? 'Weekly' : 'Daily'} Network Events Summary Digest`;
  const body = renderAdminDigestText(period, d);
  if (typeof sendEmail === 'function') sendEmail(state.admin_digest.recipient, subject, body);
  if (period === 'weekly') state.admin_digest.last_weekly_sent_at = Date.now();
  else state.admin_digest.last_daily_sent_at = Date.now();
  saveState();
  if (typeof logAdminAction === 'function') logAdminAction(req, 'admin_digest.send_manual', period, state.admin_digest.recipient);
  res.json({ ok: true, sent_to: state.admin_digest.recipient, digest: d });
});

function renderAdminDigestText(period, d) {
  return `Hi there,\n\nHere's a summary of the network events ${period === 'weekly' ? 'this week' : 'yesterday'}.\n\n` +
    `Total Events: ${d.alarms_total}\n` +
    `  • Critical: ${d.by_severity.critical}\n` +
    `  • High:     ${d.by_severity.high}\n` +
    `  • Medium:   ${d.by_severity.medium}\n` +
    `  • Low:      ${d.by_severity.low}\n\n` +
    `Network:\n` +
    `  • Boxes online: ${d.boxes_online}/${d.boxes_total}\n` +
    `  • Box reboots:  ${d.network_events.reboots}\n` +
    `  • Offline alarms: ${d.network_events.offline_alarms}\n\n` +
    `Traffic:\n` +
    `  • Total flows: ${d.flows_total.toLocaleString()}\n` +
    `  • Blocked:     ${d.flows_blocked.toLocaleString()} (${d.block_rate_pct}%)\n\n` +
    `View the full dashboard at https://cloud.mes.net.lb/admin\n\nmes Cloud`;
}

// Cron — hourly check; sends daily/weekly per the schedule in state.admin_digest
function checkAdminDigestCron() {
  const d = state.admin_digest;
  const now = new Date();
  const hh = now.getHours().toString().padStart(2, '0') + ':' + now.getMinutes().toString().padStart(2, '0');
  // Daily
  if ((d.alarms_daily || d.events_daily) && d.daily_send_at.slice(0, 2) === hh.slice(0, 2)) {
    const ageH = (Date.now() - (d.last_daily_sent_at || 0)) / 3600_000;
    if (ageH > 23) {
      const dgst = computeAdminDigest(24);
      const subject = `[mes Cloud] Daily Summary Digest`;
      if (typeof sendEmail === 'function') sendEmail(d.recipient, subject, renderAdminDigestText('daily', dgst));
      d.last_daily_sent_at = Date.now();
      console.log(`         📧 admin daily digest → ${d.recipient}`);
    }
  }
  // Weekly
  const dayMap = ['sun','mon','tue','wed','thu','fri','sat'];
  const today = dayMap[now.getDay()];
  if ((d.alarms_weekly || d.events_weekly) && today === d.weekly_send_day && d.weekly_send_at.slice(0, 2) === hh.slice(0, 2)) {
    const ageH = (Date.now() - (d.last_weekly_sent_at || 0)) / 3600_000;
    if (ageH > 167) {
      const dgst = computeAdminDigest(168);
      const subject = `[mes Cloud] Weekly Summary Digest`;
      if (typeof sendEmail === 'function') sendEmail(d.recipient, subject, renderAdminDigestText('weekly', dgst));
      d.last_weekly_sent_at = Date.now();
      console.log(`         📧 admin weekly digest → ${d.recipient}`);
    }
  }
  saveState();
}
setInterval(checkAdminDigestCron, 30 * 60_000);
setTimeout(checkAdminDigestCron, 5 * 60_000);

// ─── Per-customer custom blocklist URLs ──────────────────────────────────
// Each customer can subscribe to their own blocklist URLs (hosts file or domain list).
// The cloud refreshes them every 6h and merges them into the customer's policy bundle.
if (!state.customer_blocklists) state.customer_blocklists = {};   // { cid: [{id, name, url, ...}] }
if (!state.customer_blocklist_domains) state.customer_blocklist_domains = {}; // { cid: [domains] }

async function refreshCustomerBlocklist(cid, entry) {
  const r = await fetchOneSource({ name: entry.name || entry.url, url: entry.url, parse: parseGenericFeed });
  entry.last_fetch_ts = Date.now();
  entry.domain_count = r.count;
  entry.last_error = r.error || null;
  return Array.from(r.domains);
}
async function refreshAllCustomerBlocklists() {
  for (const [cid, list] of Object.entries(state.customer_blocklists)) {
    if (!list || !list.length) { state.customer_blocklist_domains[cid] = []; continue; }
    const merged = new Set();
    for (const entry of list) {
      try {
        const doms = await refreshCustomerBlocklist(cid, entry);
        for (const d of doms) merged.add(d);
      } catch (e) {
        entry.last_error = String(e.message || e);
      }
    }
    state.customer_blocklist_domains[cid] = Array.from(merged).slice(0, 100000);
    if (typeof bumpPolicyEtag === 'function') bumpPolicyEtag(cid, 'customer_blocklist_refreshed');
  }
  saveState();
  console.log(`         🛡️  refreshed customer blocklists for ${Object.keys(state.customer_blocklists).length} customer(s)`);
}
setTimeout(refreshAllCustomerBlocklists, 60_000);
setInterval(refreshAllCustomerBlocklists, 6 * 3600_000);

app.get('/api/customer/blocklists', customerAuth, (req, res) => {
  const list = state.customer_blocklists[req.customer.id] || [];
  res.json({ blocklists: list, total_domains: (state.customer_blocklist_domains[req.customer.id] || []).length });
});
app.post('/api/customer/blocklists/add', customerAuth, (req, res) => {
  const cid = req.customer.id;
  const url  = String(req.body.url || '').trim();
  const name = String(req.body.name || '').trim() || url;
  if (!/^https?:\/\//.test(url)) return res.status(400).json({ error: 'url must be http(s)://...' });
  if (!state.customer_blocklists[cid]) state.customer_blocklists[cid] = [];
  if (state.customer_blocklists[cid].length >= 10) return res.status(429).json({ error: 'max 10 blocklists per customer' });
  if (state.customer_blocklists[cid].some(b => b.url === url)) return res.status(409).json({ error: 'already added' });
  const entry = { id: shortId(10), name, url, added_at: Date.now(), last_fetch_ts: 0, domain_count: 0, last_error: null };
  state.customer_blocklists[cid].push(entry);
  saveState();
  // Fire-and-forget refresh of just this entry
  refreshCustomerBlocklist(cid, entry).then(doms => {
    const merged = new Set(state.customer_blocklist_domains[cid] || []);
    for (const d of doms) merged.add(d);
    state.customer_blocklist_domains[cid] = Array.from(merged).slice(0, 100000);
    if (typeof bumpPolicyEtag === 'function') bumpPolicyEtag(cid, 'customer_blocklist_added');
    saveState();
  }).catch(e => { entry.last_error = String(e.message || e); saveState(); });
  res.json({ ok: true, blocklist: entry });
});
app.post('/api/customer/blocklists/delete', customerAuth, (req, res) => {
  const cid = req.customer.id;
  const list = state.customer_blocklists[cid] || [];
  const i = list.findIndex(b => b.id === req.body.id);
  if (i < 0) return res.status(404).json({ error: 'not found' });
  list.splice(i, 1);
  // Recompute merged domains
  const merged = new Set();
  for (const e of list) {
    // Domains from this entry are not stored separately; rebuild on next refresh.
  }
  state.customer_blocklist_domains[cid] = [];  // will repopulate on next refresh
  saveState();
  if (typeof bumpPolicyEtag === 'function') bumpPolicyEtag(cid, 'customer_blocklist_deleted');
  // Trigger immediate refresh to repopulate
  setTimeout(() => refreshAllCustomerBlocklists().catch(() => {}), 100);
  res.json({ ok: true });
});
app.post('/api/customer/blocklists/refresh', customerAuth, (req, res) => {
  const cid = req.customer.id;
  refreshAllCustomerBlocklists().catch(() => {});
  res.json({ ok: true, message: 'refresh queued' });
});

app.get('/admin/api/threat-feed', adminAuth, (req, res) => {
  res.json({
    domain_count: state.threat_feeds.domains.length,
    ip_count: state.threat_feeds.ips.length,
    last_update: state.threat_feeds.last_update,
    sources: state.threat_feeds.sources,
    per_source: state.threat_feeds.per_source || {},
  });
});
app.post('/admin/api/threat-feed/refresh', adminAuth, async (req, res) => {
  const n = await fetchThreatFeed();
  res.json({ ok: true, fetched: n });
});

// Threat-feed delta endpoint: client sends ?since=<etag>; cloud returns added + removed.
// Etag is just the snapshot count + last_update timestamp. Boxes save the last etag and
// only download deltas afterward, saving bandwidth.
function threatFeedEtag() {
  const t = state.threat_feeds || {};
  return `${(t.domains || []).length}-${t.last_update || 0}`;
}
// Track snapshots so we can compute diffs
if (!state.threat_feed_snapshots) state.threat_feed_snapshots = [];   // [{ etag, ts, domains: [...]}] keep last 5
function snapshotThreatFeed() {
  const etag = threatFeedEtag();
  if (state.threat_feed_snapshots.some(s => s.etag === etag)) return;
  state.threat_feed_snapshots.unshift({
    etag, ts: Date.now(),
    domains: (state.threat_feeds.domains || []).slice(),
  });
  if (state.threat_feed_snapshots.length > 5) state.threat_feed_snapshots.length = 5;
}
// Snapshot after each fetch
const _origFetchThreatFeed = fetchThreatFeed;
fetchThreatFeed = async function() {
  const n = await _origFetchThreatFeed();
  snapshotThreatFeed();
  return n;
};
app.get('/api/box/threat-feed/delta', boxAuth, (req, res) => {
  const since = String(req.query.since || '');
  const currentEtag = threatFeedEtag();
  if (since === currentEtag) return res.json({ etag: currentEtag, no_change: true });
  const prev = state.threat_feed_snapshots.find(s => s.etag === since);
  if (!prev) {
    // No matching snapshot → return full set
    return res.json({ etag: currentEtag, full: true, domains: state.threat_feeds.domains, ips: state.threat_feeds.ips });
  }
  const prevSet = new Set(prev.domains);
  const currSet = new Set(state.threat_feeds.domains);
  const added = [];
  const removed = [];
  for (const d of currSet) if (!prevSet.has(d)) added.push(d);
  for (const d of prevSet) if (!currSet.has(d)) removed.push(d);
  res.json({ etag: currentEtag, full: false, added, removed,
    added_count: added.length, removed_count: removed.length });
});

// ═══════════════════════════════════════════════════════════════════════════
//  SAFE SEARCH — DNS overrides for kid-safe Google/YouTube/Bing/DDG
// ═══════════════════════════════════════════════════════════════════════════
const SAFE_SEARCH_OVERRIDES = {
  // host → CNAME target (these are the official "force-safe" endpoints)
  'www.google.com':            'forcesafesearch.google.com',
  'www.google.co.uk':          'forcesafesearch.google.com',
  'www.youtube.com':           'restrict.youtube.com',
  'm.youtube.com':             'restrict.youtube.com',
  'youtube.com':               'restrict.youtube.com',
  'youtubei.googleapis.com':   'restrict.youtube.com',
  'youtube.googleapis.com':    'restrict.youtube.com',
  'www.bing.com':              'strict.bing.com',
  'duckduckgo.com':            'safe.duckduckgo.com',
};

// ═══════════════════════════════════════════════════════════════════════════
//  PER-DEVICE BANDWIDTH QUOTAS
// ═══════════════════════════════════════════════════════════════════════════
if (!state.quotas) state.quotas = {};               // { customer_id: [ { id, device_mac, monthly_gb, period_yyyy_mm, bytes_up, bytes_down } ] }
if (!state.usage_monthly) state.usage_monthly = {}; // { customer_id: { period_yyyy_mm: { device_mac: {bytes_up, bytes_down} } } }
if (!state.usage_daily) state.usage_daily = {};     // { customer_id: { yyyy_mm_dd: { device_mac: {bytes_up, bytes_down} } } }

function currentPeriod() { return new Date().toISOString().slice(0, 7); }
function currentDay() { return new Date().toISOString().slice(0, 10); }

// ─── Device traffic anomaly detection ────────────────────────────────────
// Hourly: for each device, compute today's bytes vs the previous 7-day average.
// If today >= 3x avg AND today >= 1 GB, fire a synthetic alarm (deduped per device per day).
if (!state.anomaly_dedup) state.anomaly_dedup = {};
function detectTrafficAnomalies() {
  const today = currentDay();
  for (const [cid, dailyMap] of Object.entries(state.usage_daily || {})) {
    const todayMap = dailyMap[today] || {};
    // Build per-device 7-day totals (excluding today)
    const past = {};
    for (let i = 1; i <= 7; i++) {
      const d = new Date(Date.now() - i * 86400_000).toISOString().slice(0, 10);
      const dm = dailyMap[d] || {};
      for (const [mac, bytes] of Object.entries(dm)) {
        if (!past[mac]) past[mac] = { bytes: 0, days: 0 };
        past[mac].bytes += (bytes.bytes_up || 0) + (bytes.bytes_down || 0);
        past[mac].days++;
      }
    }
    for (const [mac, b] of Object.entries(todayMap)) {
      const todayBytes = (b.bytes_up || 0) + (b.bytes_down || 0);
      if (todayBytes < 1024 ** 3) continue;  // skip <1 GB
      const p = past[mac];
      if (!p || p.days < 3) continue;  // need at least 3 days of baseline
      const avg = p.bytes / p.days;
      if (avg <= 0) continue;
      const ratio = todayBytes / avg;
      if (ratio < 3) continue;
      const dedupKey = `anomaly_traffic:${cid}:${mac}:${today}`;
      if (state.anomaly_dedup[dedupKey]) continue;
      state.anomaly_dedup[dedupKey] = Date.now();
      const todayGb = (todayBytes / (1024 ** 3)).toFixed(2);
      const avgGb = (avg / (1024 ** 3)).toFixed(2);
      if (typeof fireSyntheticAlarm === 'function') {
        fireSyntheticAlarm(cid, null, 'medium', 'traffic_anomaly',
          `Unusual traffic from ${mac}`,
          `Device ${mac} used ${todayGb} GB today — ${ratio.toFixed(1)}× its 7-day average of ${avgGb} GB/day. ` +
          `This may be normal (large download, video upload) or indicate compromised device or piggybacking.`);
      }
    }
  }
  // GC dedup map: drop entries older than 2 days
  const cutoff = Date.now() - 2 * 86400_000;
  for (const [k, ts] of Object.entries(state.anomaly_dedup)) {
    if (ts < cutoff) delete state.anomaly_dedup[k];
  }
}
setTimeout(detectTrafficAnomalies, 5 * 60_000);
setInterval(detectTrafficAnomalies, 3600_000);

// Hook into flow ingestion: add quota tracking
// (we already inserted state.flows pushes above — augment by tallying per-device usage)
function tallyFlow(f) {
  const cid = f.customer_id; if (!cid) return;
  const period = currentPeriod();
  const day = currentDay();
  const k = f.src_mac || f.src_ip || 'unknown';
  if (!state.usage_monthly[cid]) state.usage_monthly[cid] = {};
  if (!state.usage_monthly[cid][period]) state.usage_monthly[cid][period] = {};
  if (!state.usage_monthly[cid][period][k]) state.usage_monthly[cid][period][k] = { bytes_up: 0, bytes_down: 0 };
  state.usage_monthly[cid][period][k].bytes_up   += (f.bytes_up   || 0);
  state.usage_monthly[cid][period][k].bytes_down += (f.bytes_down || 0);
  // Daily roll-up (60-day retention)
  if (!state.usage_daily[cid]) state.usage_daily[cid] = {};
  if (!state.usage_daily[cid][day]) state.usage_daily[cid][day] = {};
  if (!state.usage_daily[cid][day][k]) state.usage_daily[cid][day][k] = { bytes_up: 0, bytes_down: 0 };
  state.usage_daily[cid][day][k].bytes_up   += (f.bytes_up   || 0);
  state.usage_daily[cid][day][k].bytes_down += (f.bytes_down || 0);
  // Periodic GC: drop days older than 60
  if (Math.random() < 0.001) {
    const cutoff = new Date(Date.now() - 60 * 24 * 3600_000).toISOString().slice(0, 10);
    for (const d of Object.keys(state.usage_daily[cid])) {
      if (d < cutoff) delete state.usage_daily[cid][d];
    }
  }
  // Firewalla parity: emit per-category activity alarms when a device crosses
  // a threshold on a watched category (Gaming, Video, Porn, VPN, Social, …).
  // Each (customer, device, category) tracks bytes + first_seen + last_alarm
  // within a 1-hour sliding window. Alarm fires on first crossing only — the
  // 30-min dedupe in fireSyntheticAlarm prevents spam.
  tallyCategoryActivity(cid, f);
}

// Per-category activity tracker for Firewalla-style alarms
//   gaming_activity  → device using gaming traffic
//   video_activity   → streaming video detected
//   porn_activity    → adult content (high severity)
//   vpn_activity     → device using a VPN service (cloud-bound)
//   large_upload     → >50 MB upload to one destination
//   social_activity  → social media (optional, low severity)
const _ACTIVITY_THRESHOLDS = {
  gaming:   { bytes: 5 * 1024 * 1024,  sev: 'low',    kind: 'gaming_activity',  label: 'gaming session' },
  video:    { bytes: 20 * 1024 * 1024, sev: 'low',    kind: 'video_activity',   label: 'video streaming' },
  adult:    { bytes: 256 * 1024,       sev: 'high',   kind: 'porn_activity',    label: 'adult content access' },
  vpn:      { bytes: 1 * 1024 * 1024,  sev: 'medium', kind: 'vpn_activity',     label: 'VPN connection' },
  social:   { bytes: 50 * 1024 * 1024, sev: 'low',    kind: 'social_activity',  label: 'heavy social media use' },
};
const _ACTIVITY_WINDOW_MS = 60 * 60 * 1000;   // 1h rolling window
const _LARGE_UPLOAD_THRESHOLD = 50 * 1024 * 1024;   // 50 MB
function tallyCategoryActivity(cid, f) {
  if (!cid || !f.src_mac) return;
  const cat = f.category;
  const total = (f.bytes_up || 0) + (f.bytes_down || 0);
  if (total <= 0) return;
  state.category_activity = state.category_activity || {};
  state.category_activity[cid] = state.category_activity[cid] || {};
  const bucket = state.category_activity[cid];
  const now = Date.now();

  // Per-category sliding window
  if (cat && _ACTIVITY_THRESHOLDS[cat]) {
    const cfg = _ACTIVITY_THRESHOLDS[cat];
    const key = `${f.src_mac}|${cat}`;
    const e = bucket[key] = bucket[key] || { bytes: 0, first_seen: now, last_alarm: 0 };
    if ((now - e.first_seen) > _ACTIVITY_WINDOW_MS) { e.bytes = 0; e.first_seen = now; }
    e.bytes += total;
    if (e.bytes >= cfg.bytes && (now - e.last_alarm) > _ACTIVITY_WINDOW_MS) {
      e.last_alarm = now;
      const devName = _deviceNameForMac(cid, f.src_mac) || f.src_mac;
      if (typeof fireSyntheticAlarm === 'function') {
        fireSyntheticAlarm(cid, f.box_mac, cfg.sev, cfg.kind,
          `${devName} — ${cfg.label}`,
          `${devName} crossed ${Math.round(cfg.bytes/1024/1024)} MB of ${cat} traffic in the last hour. Tap to block this category for this device.`,
          { device_mac: f.src_mac, dst_domain: f.dst_domain, dst_ip: f.dst_ip, category: cat });
      }
    }
  }
  // Large single-flow upload (Firewalla alarm type 16)
  if ((f.bytes_up || 0) >= _LARGE_UPLOAD_THRESHOLD) {
    const key = `${f.src_mac}|upload|${f.dst_ip || f.dst_domain || 'x'}`;
    const e = bucket[key] = bucket[key] || { last_alarm: 0 };
    if ((now - e.last_alarm) > _ACTIVITY_WINDOW_MS) {
      e.last_alarm = now;
      const devName = _deviceNameForMac(cid, f.src_mac) || f.src_mac;
      if (typeof fireSyntheticAlarm === 'function') {
        fireSyntheticAlarm(cid, f.box_mac, 'medium', 'large_upload',
          `${devName} large upload`,
          `${(f.bytes_up/1024/1024).toFixed(1)} MB uploaded to ${f.dst_domain || f.dst_ip || 'unknown'} in a single flow.`,
          { device_mac: f.src_mac, dst_domain: f.dst_domain, dst_ip: f.dst_ip });
      }
    }
  }
}
function _deviceNameForMac(cid, mac) {
  if (!mac) return null;
  const renames = (state.device_renames && state.device_renames[cid]) || {};
  if (renames[mac]) return renames[mac];
  const myBoxes = Object.values(state.authorized_macs).filter(m => m.customer_id === cid);
  for (const b of myBoxes) {
    const d = (state.box_devices[b.mac] || {})[mac];
    if (d) return d.hostname || d.vendor || d.device_label || null;
  }
  return null;
}

// Per-rule hit counter — when a flow is blocked, find matching rules and bump.
// Stored as state.rule_hits[rule_id] = { total, last_hit_ts, daily: {YYYY-MM-DD: n} }
function tallyRuleHits(cid, flow) {
  if (!state.rule_hits) state.rule_hits = {};
  const rules = (state.rules[cid] || []).filter(r => r.enabled !== false && r.action === 'block');
  const day = currentDay();
  const dom = (flow.dst_domain || '').toLowerCase();
  const cat = (flow.category || '').toLowerCase();
  const country = (flow.country || '').toUpperCase();
  for (const r of rules) {
    let hit = false;
    if (r.type === 'domain') {
      const v = (r.value || '').toLowerCase();
      if (v && dom && (dom === v || dom.endsWith('.' + v))) hit = true;
    } else if (r.type === 'category') {
      if ((r.value || '').toLowerCase() === cat) hit = true;
    } else if (r.type === 'geo') {
      if ((r.value || '').toUpperCase() === country) hit = true;
    }
    if (!hit) continue;
    if (!state.rule_hits[r.id]) state.rule_hits[r.id] = { total: 0, last_hit_ts: 0, daily: {} };
    const h = state.rule_hits[r.id];
    h.total++;
    h.last_hit_ts = flow.ts;
    h.daily[day] = (h.daily[day] || 0) + 1;
    // Attach the matching rule to the flow record (first match wins)
    if (!flow.matched_rule_id) flow.matched_rule_id = r.id;
    // GC: keep only last 60 days
    const cutoff = new Date(Date.now() - 60 * 24 * 3600_000).toISOString().slice(0, 10);
    for (const d of Object.keys(h.daily)) {
      if (d < cutoff) delete h.daily[d];
    }
  }
}
app.get('/api/customer/rules/hits', customerAuth, (req, res) => {
  const rules = state.rules[req.customer.id] || [];
  const out = rules.map(r => {
    const h = (state.rule_hits && state.rule_hits[r.id]) || { total: 0, last_hit_ts: 0, daily: {} };
    // Last 7 days summary
    const last7 = [];
    for (let i = 6; i >= 0; i--) {
      const d = new Date(Date.now() - i * 86400_000).toISOString().slice(0, 10);
      last7.push({ day: d, hits: h.daily[d] || 0 });
    }
    return { id: r.id, type: r.type, value: r.value, action: r.action, enabled: r.enabled !== false,
      total_hits: h.total, last_hit_ts: h.last_hit_ts, last_7_days: last7 };
  });
  out.sort((a, b) => b.total_hits - a.total_hits);
  res.json({ rules: out });
});

app.get('/api/customer/quotas', customerAuth, (req, res) => {
  const list = state.quotas[req.customer.id] || [];
  // Compute usage for each
  const period = currentPeriod();
  const usage = (state.usage_monthly[req.customer.id] || {})[period] || {};
  const out = list.map(q => {
    const u = usage[q.device_mac] || { bytes_up: 0, bytes_down: 0 };
    const used_gb = (u.bytes_up + u.bytes_down) / (1024 * 1024 * 1024);
    return { ...q, used_gb, remaining_gb: Math.max(0, q.monthly_gb - used_gb), period };
  });
  res.json({ quotas: out, period });
});
app.post('/api/customer/quotas/set', customerAuth, (req, res) => {
  const c = req.customer;
  const mac = normalizeMac(req.body.device_mac || '');
  const gb  = parseFloat(req.body.monthly_gb);
  if (!mac || !(gb > 0)) return res.status(400).json({ error: 'device_mac and monthly_gb (>0) required' });
  if (!state.quotas[c.id]) state.quotas[c.id] = [];
  const existing = state.quotas[c.id].find(q => q.device_mac === mac);
  if (existing) {
    existing.monthly_gb = gb;
  } else {
    state.quotas[c.id].push({ id: shortId(10), device_mac: mac, monthly_gb: gb, created_at: Date.now() });
  }
  saveState();
  res.json({ ok: true });
});
app.post('/api/customer/quotas/delete', customerAuth, (req, res) => {
  const list = state.quotas[req.customer.id] || [];
  const i = list.findIndex(q => q.id === req.body.id);
  if (i < 0) return res.status(404).json({ error: 'not found' });
  list.splice(i, 1);
  saveState();
  res.json({ ok: true });
});

// Customer view of all monthly usage (for charts)
app.get('/api/customer/usage', customerAuth, (req, res) => {
  const period = req.query.period || currentPeriod();
  const u = (state.usage_monthly[req.customer.id] || {})[period] || {};
  const total_up = Object.values(u).reduce((s, v) => s + v.bytes_up, 0);
  const total_down = Object.values(u).reduce((s, v) => s + v.bytes_down, 0);
  res.json({ period, total_up, total_down, per_device: u });
});

// DNS query log — box uploads recent DNS queries; cloud stores per-customer.
// Capped at last 5000 queries per customer + 24h retention.
if (!state.dns_queries) state.dns_queries = {};   // { customer_id: [ {ts, src_mac, qname, qtype, blocked} ] }

// POST /api/box/latency-probes — box reports ping results to configured targets
app.post('/api/box/latency-probes', boxAuth, (req, res) => {
  if (!state.latency_results) state.latency_results = {};
  const cid = req.boxCustomerId;
  if (!cid) return res.json({ ok: true });
  if (!state.latency_results[cid]) state.latency_results[cid] = [];
  const results = Array.isArray(req.body.results) ? req.body.results : [];
  for (const r of results.slice(0, 10)) {
    state.latency_results[cid].push({ ...r, box_mac: req.boxMac });
  }
  // 7-day retention
  const cutoff = Date.now() - 7 * 86400_000;
  state.latency_results[cid] = state.latency_results[cid].filter(r => r.ts >= cutoff).slice(-2000);
  res.json({ ok: true, accepted: results.length });
});
// Customer manages probe targets
if (!state.latency_probes) state.latency_probes = {};
app.get('/api/customer/latency-probes', customerAuth, (req, res) => {
  const cid = req.customer.id;
  res.json({
    targets: (state.latency_probes[cid] && state.latency_probes[cid].targets) || [],
    results: (state.latency_results && state.latency_results[cid]) || [],
  });
});
app.post('/api/customer/latency-probes', customerAuth, (req, res) => {
  const cid = req.customer.id;
  const targets = Array.isArray(req.body.targets) ? req.body.targets : [];
  const clean = targets.map(t => String(t).trim()).filter(t => /^[a-z0-9][a-z0-9.\-]*$/i.test(t)).slice(0, 10);
  state.latency_probes[cid] = { targets: clean };
  saveState();
  if (typeof bumpPolicyEtag === 'function') bumpPolicyEtag(cid, 'latency_probes_updated');
  res.json({ ok: true, targets: clean });
});

// POST /api/box/route-change — box reports an upstream traceroute fingerprint change
app.post('/api/box/route-change', boxAuth, (req, res) => {
  if (!state.box_route_changes) state.box_route_changes = {};
  if (!state.box_route_changes[req.boxMac]) state.box_route_changes[req.boxMac] = [];
  state.box_route_changes[req.boxMac].unshift({
    ts: req.body.ts || Date.now(),
    previous: String(req.body.previous || '').slice(0, 500),
    current: String(req.body.current || '').slice(0, 500),
  });
  if (state.box_route_changes[req.boxMac].length > 50) state.box_route_changes[req.boxMac].length = 50;
  if (req.boxCustomerId && typeof fireSyntheticAlarm === 'function') {
    fireSyntheticAlarm(req.boxCustomerId, req.boxMac, 'low', 'route_change',
      'Upstream route changed', `First 3 hops to anchor IPs changed. Could be ISP failover or BGP change.`);
  }
  res.json({ ok: true });
});

// POST /api/box/integrity-report — agent reports SHA-256 of its own files.
// Cloud compares to first-seen baseline and alarms on change.
if (!state.box_integrity_baseline) state.box_integrity_baseline = {};   // mac → {file: hash}
app.post('/api/box/integrity-report', boxAuth, (req, res) => {
  const mac = req.boxMac;
  const reported = req.body.hashes || {};
  if (!state.box_integrity_baseline[mac]) {
    state.box_integrity_baseline[mac] = { ...reported, _established_at: Date.now() };
    saveState();
    return res.json({ ok: true, baseline_established: true });
  }
  const baseline = state.box_integrity_baseline[mac];
  const drift = [];
  for (const [f, h] of Object.entries(reported)) {
    if (!baseline[f]) continue;   // new file, just record
    if (baseline[f] !== h && !h.startsWith('ERR:')) drift.push({ file: f, was: baseline[f].slice(0, 12), now: h.slice(0, 12) });
  }
  if (drift.length && req.boxCustomerId && typeof fireSyntheticAlarm === 'function') {
    fireSyntheticAlarm(req.boxCustomerId, mac, 'high', 'box_integrity_drift',
      'Box agent files changed unexpectedly',
      `${drift.length} file(s) on box ${mac} changed since baseline: ${drift.map(d => d.file).join(', ')}. ` +
      `If you didn't run an update, this could indicate tampering. Review snapshot + reboot to known good.`);
  }
  res.json({ ok: true, drift });
});
// Customer marks the most recent box snapshot as "known good". Future drift detection
// also computes diff vs known-good for quick comparison.
app.post('/admin/api/box/:mac/snapshot/mark-known-good', adminAuth, (req, res) => {
  const mac = normalizeMac(req.params.mac);
  const snaps = (state.box_snapshots && state.box_snapshots[mac]) || [];
  if (!snaps.length) return res.status(404).json({ error: 'no_snapshots' });
  snaps[0].known_good = true;
  if (!state.box_known_good) state.box_known_good = {};
  state.box_known_good[mac] = { ts: snaps[0].ts, snapshot: snaps[0] };
  saveState();
  if (typeof logAdminAction === 'function') logAdminAction(req, 'snapshot.mark_known_good', mac);
  res.json({ ok: true, ts: snaps[0].ts });
});
app.get('/admin/api/box/:mac/snapshot/diff-vs-known-good', adminAuth, (req, res) => {
  const mac = normalizeMac(req.params.mac);
  const kg = state.box_known_good && state.box_known_good[mac];
  if (!kg) return res.status(404).json({ error: 'no_known_good' });
  const cur = (state.box_snapshots && state.box_snapshots[mac] || [])[0];
  if (!cur) return res.status(404).json({ error: 'no_current_snapshot' });
  const fields = ['dnsmasq_conf', 'dnsmasq_dhcp', 'nft_ruleset', 'wg_conf', 'iptables_nat'];
  const diffs = {};
  for (const k of fields) {
    if ((kg.snapshot[k] || '') !== (cur[k] || '')) {
      diffs[k] = { changed: true, kg_len: (kg.snapshot[k] || '').length, current_len: (cur[k] || '').length };
    }
  }
  res.json({ known_good_ts: kg.ts, current_ts: cur.ts, diffs, identical: Object.keys(diffs).length === 0 });
});

// Admin-triggered baseline reset (e.g. after legit OTA)
app.post('/admin/api/box/:mac/integrity-reset', adminAuth, (req, res) => {
  const mac = normalizeMac(req.params.mac);
  if (!state.box_integrity_baseline[mac]) return res.status(404).json({ error: 'no baseline' });
  delete state.box_integrity_baseline[mac];
  saveState();
  if (typeof logAdminAction === 'function') logAdminAction(req, 'integrity_baseline_reset', mac);
  res.json({ ok: true, message: 'next report establishes new baseline' });
});

// POST /api/box/config-snapshot — daily config dump for support/audit
app.post('/api/box/config-snapshot', boxAuth, express.json({ limit: '256kb' }), (req, res) => {
  if (!state.box_snapshots) state.box_snapshots = {};
  if (!state.box_snapshots[req.boxMac]) state.box_snapshots[req.boxMac] = [];
  // Drift detection — compare to most recent snapshot before pushing the new one.
  const prev = state.box_snapshots[req.boxMac][0];
  if (prev) {
    const diffs = [];
    const ageH = (Date.now() - prev.ts) / 3600_000;
    const fields = [
      ['dnsmasq_conf', 'dnsmasq config'],
      ['dnsmasq_dhcp', 'dnsmasq DHCP config'],
      ['nft_ruleset',  'nftables ruleset'],
      ['wg_conf',      'WireGuard config'],
      ['iptables_nat', 'iptables NAT rules'],
    ];
    for (const [k, label] of fields) {
      if (prev[k] !== req.body[k] && (prev[k] || req.body[k])) diffs.push(label);
    }
    if (diffs.length > 0 && req.boxCustomerId) {
      // Heuristic: a policy etag change is the legitimate cause of dnsmasq/nft/wg drift.
      const expectedDrift = prev.last_policy_etag !== (req.body.last_policy && req.body.last_policy.etag);
      if (!expectedDrift && typeof fireSyntheticAlarm === 'function') {
        fireSyntheticAlarm(req.boxCustomerId, req.boxMac, 'medium', 'box_config_drift',
          'Box configuration changed unexpectedly',
          `Files changed since last snapshot (${ageH.toFixed(1)}h ago) without a matching policy update: ` +
          diffs.join(', ') + '. This could indicate manual edits, malware, or rollback. Review snapshot.');
      }
    }
  }
  state.box_snapshots[req.boxMac].unshift({
    ts: req.body.ts || Date.now(),
    version: req.body.version,
    hostname: req.body.hostname,
    last_policy_etag: req.body.last_policy && req.body.last_policy.etag,
    last_policy: req.body.last_policy ? { ...req.body.last_policy, blocked_domains: undefined, blocked_ips: undefined } : null,  // strip large arrays
    dnsmasq_conf: req.body.dnsmasq_conf,
    dnsmasq_dhcp: req.body.dnsmasq_dhcp,
    nft_ruleset:  req.body.nft_ruleset,
    wg_conf:      req.body.wg_conf,
    iptables_nat: req.body.iptables_nat,
    uname:        req.body.uname,
    disk_free:    req.body.disk_free,
  });
  // Keep only last 14 snapshots per box (~2 weeks of dailies)
  if (state.box_snapshots[req.boxMac].length > 14) state.box_snapshots[req.boxMac].length = 14;
  console.log(`         📸 SNAPSHOT ${req.boxMac} v${req.body.version}`);
  res.json({ ok: true });
});
app.get('/admin/api/box-snapshots', adminAuth, (req, res) => {
  const mac = req.query.mac;
  if (mac) return res.json({ mac, snapshots: (state.box_snapshots && state.box_snapshots[mac]) || [] });
  // List of boxes that have snapshots
  const list = Object.entries(state.box_snapshots || {}).map(([m, snaps]) => ({
    mac: m, count: snaps.length,
    latest_ts: snaps[0] && snaps[0].ts,
    latest_version: snaps[0] && snaps[0].version,
  }));
  list.sort((a, b) => (b.latest_ts || 0) - (a.latest_ts || 0));
  res.json({ boxes: list });
});

app.post('/api/box/dns-queries', boxAuth, (req, res) => {
  const cid = req.boxCustomerId;
  if (!cid) return res.json({ ok: true, accepted: 0 });
  const c = state.customers[cid];
  // Customer can opt out entirely (privacy) by setting retention to 0.
  const retentionH = (c && c.dns_retention_h !== undefined) ? c.dns_retention_h : 24;
  if (retentionH === 0) {
    state.dns_queries[cid] = [];
    return res.json({ ok: true, accepted: 0, retention_h: 0, reason: 'customer opted out' });
  }
  const queries = Array.isArray(req.body.queries) ? req.body.queries : [];
  if (!state.dns_queries[cid]) state.dns_queries[cid] = [];
  const now = Date.now();
  for (const q of queries.slice(0, 1000)) {
    state.dns_queries[cid].push({
      ts: q.ts || now,
      src_mac: normalizeMac(q.src_mac || ''),
      qname:   String(q.qname || '').toLowerCase().slice(0, 200),
      qtype:   String(q.qtype || 'A').slice(0, 8),
      blocked: !!q.blocked,
    });
  }
  // GC: per-customer retention, capped at 30 days
  const cutoff = now - Math.min(retentionH, 24 * 30) * 3600_000;
  state.dns_queries[cid] = state.dns_queries[cid]
    .filter(q => q.ts >= cutoff)
    .slice(-20000);
  res.json({ ok: true, accepted: queries.length, retention_h: retentionH });
});

// Customer reset-to-defaults — wipes user-created policy with a 7-day grace window.
// During the grace window, an undo button restores everything (we keep a snapshot).
if (!state.reset_pending) state.reset_pending = {};   // cid → { snapshot, scheduled_at, executes_at }
app.post('/api/customer/reset-to-defaults/schedule', customerAuth, (req, res) => {
  const cid = req.customer.id;
  if (state.reset_pending[cid]) return res.status(409).json({ error: 'reset_already_scheduled', executes_at: state.reset_pending[cid].executes_at });
  // Snapshot the slices we'll wipe
  const snap = {
    rules:           state.rules[cid],
    schedules:       state.schedules[cid],
    family_members:  state.family_members[cid],
    quotas:          state.quotas[cid],
    qos_rules:       state.qos_rules[cid],
    device_renames:  state.device_renames[cid],
    device_icons:    (state.device_icons || {})[cid],
    device_groups:   state.device_groups[cid],
    customer_blocklists: state.customer_blocklists[cid],
    custom_alarm_rules:  state.custom_alarm_rules[cid],
  };
  state.reset_pending[cid] = {
    snapshot: snap,
    scheduled_at: Date.now(),
    executes_at: Date.now() + 7 * 86400_000,
  };
  saveState();
  if (typeof pushNotification === 'function') {
    pushNotification(cid, 'security', '⚠️ Reset scheduled',
      'You scheduled a reset to defaults. It will execute in 7 days. Cancel anytime in Settings.');
  }
  res.json({ ok: true, executes_at: state.reset_pending[cid].executes_at });
});
app.post('/api/customer/reset-to-defaults/cancel', customerAuth, (req, res) => {
  const cid = req.customer.id;
  if (!state.reset_pending[cid]) return res.status(404).json({ error: 'no_reset_pending' });
  delete state.reset_pending[cid];
  saveState();
  res.json({ ok: true });
});
app.get('/api/customer/reset-to-defaults/status', customerAuth, (req, res) => {
  const r = state.reset_pending[req.customer.id];
  res.json({ pending: !!r, executes_at: r ? r.executes_at : null });
});
// Cron: execute resets whose grace expired
function processPendingResets() {
  const now = Date.now();
  for (const [cid, r] of Object.entries(state.reset_pending)) {
    if (r.executes_at > now) continue;
    state.rules[cid] = [];
    state.schedules[cid] = [];
    state.family_members[cid] = [];
    state.quotas[cid] = [];
    state.qos_rules[cid] = [];
    state.device_renames[cid] = {};
    if (state.device_icons) state.device_icons[cid] = {};
    state.device_groups[cid] = [];
    state.customer_blocklists[cid] = [];
    state.custom_alarm_rules[cid] = [];
    if (typeof bumpPolicyEtag === 'function') bumpPolicyEtag(cid, 'reset_to_defaults');
    delete state.reset_pending[cid];
    if (typeof pushNotification === 'function') pushNotification(cid, 'security', '🔄 Reset complete', 'Your account has been reset to defaults.');
    console.log(`         🔄 RESET-TO-DEFAULTS executed for ${cid}`);
  }
  saveState();
}
setInterval(processPendingResets, 3600_000);
setTimeout(processPendingResets, 5 * 60_000);

// Customer geofence allowlist — countries where their box is allowed to operate.
// Empty/null = no enforcement (just heartbeat country-change alarm still fires).
app.get('/api/customer/geofence', customerAuth, (req, res) => {
  const c = req.customer;
  res.json({
    allowed_countries: c.allowed_countries || [],
    note: 'ISO-3166 alpha-2 codes (LB, US, FR, ...). Empty = no allowlist.',
  });
});
app.post('/api/customer/geofence', customerAuth, (req, res) => {
  const c = state.customers[req.customer.id];
  const arr = Array.isArray(req.body.countries) ? req.body.countries : [];
  const clean = arr.map(s => String(s).trim().toUpperCase()).filter(s => /^[A-Z]{2}$/.test(s));
  if (clean.length > 30) return res.status(400).json({ error: 'max 30 countries' });
  c.allowed_countries = clean;
  saveState();
  res.json({ ok: true, allowed_countries: clean });
});

// Customer trusted-IP allowlist for login. If non-empty, login attempts from
// other IPs are rejected even with correct password + 2FA.
app.get('/api/customer/login-ip-allowlist', customerAuth, (req, res) => {
  res.json({ allowlist: req.customer.login_ip_allowlist || [] });
});
app.post('/api/customer/login-ip-allowlist', customerAuth, (req, res) => {
  const c = state.customers[req.customer.id];
  const list = Array.isArray(req.body.allowlist) ? req.body.allowlist : [];
  const clean = [];
  for (const e of list) {
    if (typeof e !== 'string') continue;
    if (e.includes('/')) {
      const [ip, bits] = e.split('/');
      if (_ipToNum(ip) != null && /^\d{1,2}$/.test(bits) && +bits <= 32) clean.push(e);
    } else if (_ipToNum(e) != null) clean.push(e);
  }
  if (clean.length > 50) return res.status(400).json({ error: 'max 50 entries' });
  // Self-lockout protection: requesting IP must be in new list (or list empty)
  if (clean.length > 0 && !clean.some(c => _ipInCidr((req.ip || '').replace(/^::ffff:/, ''), c))) {
    return res.status(400).json({ error: 'self_lockout', message: 'Your IP is not in the new list. Add it first.', your_ip: req.ip });
  }
  c.login_ip_allowlist = clean;
  saveState();
  res.json({ ok: true, allowlist: clean });
});

// Customer privacy mode: master toggle. When on, cloud:
//   • drops raw flow records (only aggregates kept for billing/quotas)
//   • drops DNS query records (zero retention)
//   • removes existing flow + DNS data
app.get('/api/customer/privacy-mode', customerAuth, (req, res) => {
  const c = req.customer;
  res.json({
    enabled: !!c.privacy_mode,
    enabled_at: c.privacy_mode_set_at || null,
    note: 'Privacy mode disables cloud-side flow logging and DNS query retention. Aggregates (quotas, rule hits, billing) still work.',
  });
});
app.post('/api/customer/privacy-mode', customerAuth, (req, res) => {
  const c = state.customers[req.customer.id];
  c.privacy_mode = !!req.body.enabled;
  c.privacy_mode_set_at = c.privacy_mode ? Date.now() : null;
  if (c.privacy_mode) {
    // Clear any existing flow + DNS data
    const before = state.flows.length;
    state.flows = state.flows.filter(f => f.customer_id !== c.id);
    if (state.dns_queries[c.id]) state.dns_queries[c.id] = [];
    c.dns_retention_h = 0;   // align retention with privacy on
    console.log(`         🛡️ PRIVACY MODE ON → ${c.name}, purged ${before - state.flows.length} flows`);
  }
  saveState();
  if (typeof pushNotification === 'function') {
    pushNotification(c.id, 'security',
      c.privacy_mode ? '🛡️ Privacy mode enabled' : '🔓 Privacy mode disabled',
      c.privacy_mode
        ? 'Cloud-side flow + DNS logging is now off. Existing data was purged.'
        : 'Flow + DNS logging is back on.');
  }
  res.json({ ok: true, enabled: c.privacy_mode });
});

// Customer reads / sets their DNS retention preference (privacy control).
app.get('/api/customer/dns-retention', customerAuth, (req, res) => {
  const c = req.customer;
  const v = c.dns_retention_h !== undefined ? c.dns_retention_h : 24;
  res.json({ retention_h: v, allowed: [0, 24, 168, 720], current_query_count: (state.dns_queries[c.id] || []).length });
});
app.post('/api/customer/dns-retention', customerAuth, (req, res) => {
  const c = state.customers[req.customer.id];
  const h = parseInt(req.body.retention_h);
  if (![0, 24, 168, 720].includes(h)) return res.status(400).json({ error: 'allowed values: 0 (off), 24 (1 day), 168 (7 days), 720 (30 days)' });
  c.dns_retention_h = h;
  // If lowering, prune now
  if (h === 0) {
    state.dns_queries[c.id] = [];
  } else {
    const cutoff = Date.now() - h * 3600_000;
    state.dns_queries[c.id] = (state.dns_queries[c.id] || []).filter(q => q.ts >= cutoff);
  }
  saveState();
  res.json({ ok: true, retention_h: h });
});

// Per-device weekly report — daily bytes + top sites + blocked.
app.get('/api/customer/devices/:mac/weekly-report', customerAuth, (req, res) => {
  const cid = req.customer.id;
  const mac = normalizeMac(req.params.mac);
  const myMacs = Object.values(state.authorized_macs).filter(m => m.customer_id === cid).map(m => m.mac);
  const found = myMacs.some(boxMac => state.box_devices[boxMac] && state.box_devices[boxMac][mac]);
  if (!found) return res.status(404).json({ error: 'device_not_yours_or_unknown' });
  const cutoff = Date.now() - 7 * 86400_000;
  const myFlows = state.flows.filter(f => f.customer_id === cid && f.src_mac === mac && f.ts >= cutoff);
  // Per-day buckets (LBT)
  const lbtToday = new Date(Date.now() + 3 * 3600_000).toISOString().slice(0, 10);
  const days = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date(Date.now() - i * 86400_000 + 3 * 3600_000).toISOString().slice(0, 10);
    days.push({ day: d, bytes: 0, flows: 0, blocked: 0 });
  }
  const dayIdx = {};
  days.forEach((d, i) => { dayIdx[d.day] = i; });
  const domTotals = {};
  let totalBlocked = 0;
  for (const f of myFlows) {
    const d = new Date(f.ts + 3 * 3600_000).toISOString().slice(0, 10);
    const i = dayIdx[d];
    if (i !== undefined) {
      days[i].bytes += (f.bytes_up || 0) + (f.bytes_down || 0);
      days[i].flows += 1;
      if (f.blocked) days[i].blocked += 1;
    }
    if (f.blocked) totalBlocked++;
    if (f.dst_domain) {
      const apex = f.dst_domain.split('.').slice(-2).join('.');
      if (!domTotals[apex]) domTotals[apex] = { bytes: 0, flows: 0, blocked: 0 };
      domTotals[apex].bytes += (f.bytes_up || 0) + (f.bytes_down || 0);
      domTotals[apex].flows += 1;
      if (f.blocked) domTotals[apex].blocked += 1;
    }
  }
  const top = Object.entries(domTotals)
    .map(([domain, v]) => ({ domain, ...v }))
    .sort((a, b) => b.bytes - a.bytes).slice(0, 15);
  res.json({
    mac,
    window: 'last_7_days_lbt',
    total_flows: myFlows.length,
    total_bytes: myFlows.reduce((s, f) => s + (f.bytes_up || 0) + (f.bytes_down || 0), 0),
    total_blocked: totalBlocked,
    days, top_domains: top,
  });
});

// DNS top-domains analytics: per-device most-queried domains in last 24h.
app.get('/api/customer/dns-top-domains', customerAuth, (req, res) => {
  const list = state.dns_queries[req.customer.id] || [];
  const cutoff = Date.now() - 24 * 3600_000;
  const macFilter = req.query.mac ? normalizeMac(req.query.mac) : null;
  const recent = list.filter(q => q.ts >= cutoff && (!macFilter || q.src_mac === macFilter));
  // count per (mac, domain)
  const counts = {};   // mac → domain → {count, blocked}
  for (const q of recent) {
    if (!q.qname) continue;
    const apex = q.qname.split('.').slice(-2).join('.');   // group subdomains under apex
    if (!counts[q.src_mac]) counts[q.src_mac] = {};
    if (!counts[q.src_mac][apex]) counts[q.src_mac][apex] = { count: 0, blocked: 0 };
    counts[q.src_mac][apex].count++;
    if (q.blocked) counts[q.src_mac][apex].blocked++;
  }
  // Convert to sorted lists per device
  const perDevice = {};
  for (const [mac, doms] of Object.entries(counts)) {
    const arr = Object.entries(doms)
      .map(([domain, v]) => ({ domain, count: v.count, blocked: v.blocked }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 25);
    perDevice[mac] = arr;
  }
  // Also a global top-25 across all devices
  const allCounts = {};
  for (const q of recent) {
    if (!q.qname) continue;
    const apex = q.qname.split('.').slice(-2).join('.');
    if (!allCounts[apex]) allCounts[apex] = { count: 0, blocked: 0 };
    allCounts[apex].count++;
    if (q.blocked) allCounts[apex].blocked++;
  }
  const top = Object.entries(allCounts)
    .map(([domain, v]) => ({ domain, count: v.count, blocked: v.blocked }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 25);
  res.json({ window_hours: 24, total_queries: recent.length, top, per_device: perDevice });
});

app.get('/api/customer/dns-queries', customerAuth, (req, res) => {
  const list = (state.dns_queries[req.customer.id] || []).slice().reverse();
  const mac = req.query.mac ? normalizeMac(req.query.mac) : null;
  const filtered = mac ? list.filter(q => q.src_mac === mac) : list;
  res.json({ queries: filtered.slice(0, 500), total: filtered.length });
});

// Top sites contacted by each of the customer's devices (last 24h)
app.get('/api/customer/top-sites', customerAuth, (req, res) => {
  const cutoff = Date.now() - 24 * 3600_000;
  const myFlows = state.flows.filter(f => f.customer_id === req.customer.id && f.ts >= cutoff);
  const byDevice = {};   // mac → { domain: bytes }
  for (const f of myFlows) {
    const mac = f.src_mac || f.src_ip || 'unknown';
    const dom = f.dst_domain || f.dst_ip;
    if (!dom) continue;
    if (!byDevice[mac]) byDevice[mac] = {};
    byDevice[mac][dom] = (byDevice[mac][dom] || 0) + (f.bytes_up || 0) + (f.bytes_down || 0);
  }
  // Convert each device's site map to top-N sorted list
  const out = {};
  for (const [mac, sites] of Object.entries(byDevice)) {
    out[mac] = Object.entries(sites)
      .map(([domain, bytes]) => ({ domain, bytes }))
      .sort((a, b) => b.bytes - a.bytes)
      .slice(0, 10);
  }
  res.json({ window_hours: 24, per_device: out });
});

app.get('/api/customer/reboot-events', customerAuth, (req, res) => {
  const myMacs = Object.values(state.authorized_macs).filter(m => m.customer_id === req.customer.id).map(m => m.mac);
  const out = {};
  for (const mac of myMacs) out[mac] = (state.reboot_events && state.reboot_events[mac]) || [];
  res.json({ events: out });
});

app.get('/admin/api/box/:mac/reboot-events', adminAuth, (req, res) => {
  const mac = normalizeMac(req.params.mac);
  res.json({ events: (state.reboot_events && state.reboot_events[mac]) || [] });
});

// 30-day uptime stats per box for this customer
app.get('/api/customer/uptime', customerAuth, (req, res) => {
  const myMacs = Object.values(state.authorized_macs)
    .filter(m => m.customer_id === req.customer.id)
    .map(m => m.mac);
  const cutoff = Date.now() - 30 * 24 * 3600_000;
  const out = {};
  for (const mac of myMacs) {
    const hist = (state.heartbeat_history && state.heartbeat_history[mac]) || [];
    const recent = hist.filter(h => h >= cutoff).sort((a, b) => a - b);
    if (recent.length < 2) {
      out[mac] = { uptime_pct: null, sample_count: recent.length };
      continue;
    }
    // Heartbeat is every 60s. Count "online windows" (any 5-min window with at least one heartbeat).
    const windows = new Set();
    for (const ts of recent) windows.add(Math.floor(ts / (5 * 60_000)));
    const totalWindows = Math.ceil((Date.now() - cutoff) / (5 * 60_000));
    out[mac] = {
      uptime_pct: Math.round((windows.size / totalWindows) * 1000) / 10,
      sample_count: recent.length,
      first_seen: recent[0],
      last_seen: recent[recent.length - 1],
    };
  }
  res.json({ uptime: out });
});

// NPS / feedback collection
if (!state.nps_responses) state.nps_responses = {};   // { customer_id: [ {ts, score, comment} ] }
app.post('/api/customer/nps', customerAuth, (req, res) => {
  const c = req.customer;
  const score = parseInt(req.body.score);
  if (isNaN(score) || score < 0 || score > 10) return res.status(400).json({ error: 'score must be 0-10' });
  const comment = String(req.body.comment || '').slice(0, 500);
  if (!state.nps_responses[c.id]) state.nps_responses[c.id] = [];
  state.nps_responses[c.id].push({ ts: Date.now(), score, comment });
  c._nps_last_at = Date.now();   // stops the prompt for 90 days
  saveState();
  console.log(`         📋 NPS ${score}/10 from ${c.name}: "${comment.slice(0, 40)}"`);
  res.json({ ok: true });
});
app.post('/api/customer/nps/dismiss', customerAuth, (req, res) => {
  // User declined — defer for 30 days
  const c = state.customers[req.customer.id];
  if (c) c._nps_last_at = Date.now() - (60 * 24 * 3600_000);  // pretend last asked 60 days ago, so next prompt is 30 days
  saveState();
  res.json({ ok: true });
});

// Customer endpoint to check if NPS prompt should show
app.get('/api/customer/nps-due', customerAuth, (req, res) => {
  const c = req.customer;
  const lastAt = c._nps_last_at || 0;
  const accountAgeDays = (Date.now() - new Date(c.created_at).getTime()) / (24 * 3600_000);
  // Don't ask in first 7 days. Ask every 90 days after that.
  const due = accountAgeDays >= 7 && (Date.now() - lastAt) >= 90 * 24 * 3600_000;
  res.json({ due, last_at: lastAt });
});

app.get('/admin/api/nps', adminAuth, (req, res) => {
  const all = [];
  for (const [cid, list] of Object.entries(state.nps_responses)) {
    const c = state.customers[cid];
    for (const r of list) all.push({ ...r, customer_id: cid, customer_name: c ? c.name : 'unknown' });
  }
  all.sort((a, b) => b.ts - a.ts);
  // Compute aggregate
  const recent = all.filter(r => (Date.now() - r.ts) < 90 * 24 * 3600_000);
  const promoters = recent.filter(r => r.score >= 9).length;
  const passives  = recent.filter(r => r.score >= 7 && r.score <= 8).length;
  const detractors = recent.filter(r => r.score <= 6).length;
  const total = recent.length;
  const nps = total > 0 ? Math.round(((promoters - detractors) / total) * 100) : null;
  res.json({ responses: all, aggregate: { total, promoters, passives, detractors, nps } });
});

// ─── Per-customer webhooks ───────────────────────────────────────────────
// state.customer_webhooks = { cid: [{id, name, url, secret, events, enabled, created_at}] }
if (!state.customer_webhooks) state.customer_webhooks = {};
const CUSTOMER_WEBHOOK_EVENTS = ['alarm.fired', 'box.online', 'box.offline', 'rule.triggered', 'quota.exceeded', 'invoice.issued'];

// Tiny payload-filter expression evaluator: simple `path.to.field op value` form.
// Supported ops: ==, !=, contains, gte, lte. Path uses dot-notation. Values are strings or numbers.
// Examples: "severity == high"   "payload.title contains malware"   "ts gte 1700000000"
function webhookPayloadMatches(filter, ctx) {
  if (!filter) return true;
  const m = String(filter).match(/^\s*([a-zA-Z0-9_.]+)\s+(==|!=|contains|gte|lte)\s+(.+?)\s*$/);
  if (!m) return true;   // malformed filter → allow (don't silently drop)
  const [, path, op, rawValue] = m;
  let v = ctx;
  for (const part of path.split('.')) {
    if (v == null) return false;
    v = v[part];
  }
  const target = rawValue.replace(/^["']|["']$/g, '');
  if (op === '==') return String(v) === target;
  if (op === '!=') return String(v) !== target;
  if (op === 'contains') return String(v || '').toLowerCase().includes(target.toLowerCase());
  if (op === 'gte') return Number(v) >= Number(target);
  if (op === 'lte') return Number(v) <= Number(target);
  return true;
}

function fireCustomerWebhook(cid, eventName, payload) {
  const list = state.customer_webhooks[cid] || [];
  for (const h of list) {
    if (!h.enabled) continue;
    if (!h.events.includes('*') && !h.events.includes(eventName)) continue;
    if (h.filter && !webhookPayloadMatches(h.filter, { event: eventName, payload })) continue;
    state.webhook_queue.push({
      id: 'wq-' + shortId(8),
      hook_id: h.id,
      url: h.url,
      secret: h.secret,
      template: h.template || null,
      schema: h.schema || null,
      event: eventName,
      payload: { customer_id: cid, ...payload },
      attempts: 0,
      next_at: Date.now(),
      created_at: Date.now(),
    });
  }
  if (state.webhook_queue.length > 500) state.webhook_queue = state.webhook_queue.slice(-300);
}

// Pre-built webhook payload templates the PWA picker can offer.
const WEBHOOK_TEMPLATES = {
  slack:   { label: 'Slack',   template: '{"text":"*[mes Cloud]* {{event}}: {{payload.title}}\\n{{payload.body}}"}' },
  discord: { label: 'Discord', template: '{"username":"mes Cloud","content":"**{{event}}** — {{payload.title}}\\n{{payload.body}}"}' },
  teams:   { label: 'Microsoft Teams', template: '{"@type":"MessageCard","summary":"mes Cloud event","title":"{{event}}: {{payload.title}}","text":"{{payload.body}}"}' },
  generic: { label: 'Generic JSON (default)', template: null },
};
app.get('/api/customer/webhooks/templates', customerAuth, (req, res) => {
  res.json({ templates: WEBHOOK_TEMPLATES });
});

app.get('/api/customer/webhooks', customerAuth, (req, res) => {
  res.json({ webhooks: state.customer_webhooks[req.customer.id] || [], events: CUSTOMER_WEBHOOK_EVENTS });
});
app.post('/api/customer/webhooks', customerAuth, (req, res) => {
  const cid = req.customer.id;
  if (!state.customer_webhooks[cid]) state.customer_webhooks[cid] = [];
  if (state.customer_webhooks[cid].length >= 5) return res.status(429).json({ error: 'max 5 webhooks per customer' });
  const url = String(req.body.url || '').trim();
  if (!/^https?:\/\//.test(url)) return res.status(400).json({ error: 'url must be http(s)://...' });
  const events = Array.isArray(req.body.events) ? req.body.events.filter(e => e === '*' || CUSTOMER_WEBHOOK_EVENTS.includes(e)) : ['*'];
  const secret = String(req.body.secret || '').trim() || crypto.randomBytes(16).toString('hex');
  // Resolve template: explicit `template` wins; else try `template_preset` (slack/discord/teams).
  let template = null;
  if (typeof req.body.template === 'string' && req.body.template.length) {
    template = req.body.template.slice(0, 4000);
  } else if (req.body.template_preset && WEBHOOK_TEMPLATES[req.body.template_preset]) {
    template = WEBHOOK_TEMPLATES[req.body.template_preset].template;
  }
  const h = {
    id: 'cwh-' + shortId(10),
    name: String(req.body.name || '').trim() || url,
    url, secret, events,
    template,
    template_preset: req.body.template_preset || null,
    filter: typeof req.body.filter === 'string' ? req.body.filter.slice(0, 200) : null,
    schema: typeof req.body.schema === 'string' ? req.body.schema.slice(0, 2000) : null,
    enabled: true,
    created_at: Date.now(),
  };
  state.customer_webhooks[cid].push(h);
  saveState();
  res.json({ ok: true, webhook: h });
});
app.post('/api/customer/webhooks/delete', customerAuth, (req, res) => {
  const cid = req.customer.id;
  const list = state.customer_webhooks[cid] || [];
  const i = list.findIndex(h => h.id === req.body.id);
  if (i < 0) return res.status(404).json({ error: 'not found' });
  list.splice(i, 1);
  saveState();
  res.json({ ok: true });
});
app.post('/api/customer/webhooks/test', customerAuth, (req, res) => {
  const cid = req.customer.id;
  const list = state.customer_webhooks[cid] || [];
  const h = list.find(x => x.id === req.body.id);
  if (!h) return res.status(404).json({ error: 'not found' });
  // Build a test payload and queue immediately. Return queue id so caller can poll outcome.
  const item = {
    id: 'wq-' + shortId(8),
    hook_id: h.id,
    url: h.url, secret: h.secret,
    event: 'webhook.test',
    payload: { customer_id: cid, test: true, message: 'This is a test webhook from mes Cloud.', ts: Date.now() },
    attempts: 0,
    next_at: Date.now(),
    created_at: Date.now(),
  };
  state.webhook_queue.push(item);
  res.json({ ok: true, queued_id: item.id, expected_signature_header: 'X-MES-Signature: sha256=<hex>',
    verify_with_secret: h.secret });
});

// Sweeps expired rules every hour: marks them disabled and notifies the customer.
function sweepExpiredRules() {
  const now = Date.now();
  for (const [cid, rules] of Object.entries(state.rules || {})) {
    for (const r of rules) {
      if (r.expires_at && r.expires_at < now && r.enabled !== false && !r._expired_notified) {
        r.enabled = false;
        r._expired_notified = true;
        if (typeof pushNotification === 'function') {
          pushNotification(cid, 'system', '⏰ Rule expired',
            `Your rule "${r.action} ${r.type}:${r.value}" has expired and was disabled. Re-enable from the Rules tab if you still need it.`);
        }
      }
    }
  }
  saveState();
}
setInterval(sweepExpiredRules, 3600_000);
setTimeout(sweepExpiredRules, 5 * 60_000);

// ─── Device groups (Living Room, Office, Kids' Room…) ────────────────────
// state.device_groups = { customer_id: [{id, name, icon, device_macs[]}] }
if (!state.device_groups) state.device_groups = {};

app.get('/api/customer/device-groups', customerAuth, (req, res) => {
  res.json({ groups: state.device_groups[req.customer.id] || [] });
});
app.post('/api/customer/device-groups/add', customerAuth, (req, res) => {
  const cid = req.customer.id;
  const name = String(req.body.name || '').trim().slice(0, 60);
  if (!name) return res.status(400).json({ error: 'name required' });
  if (!state.device_groups[cid]) state.device_groups[cid] = [];
  if (state.device_groups[cid].length >= 30) return res.status(429).json({ error: 'max 30 groups per customer' });
  const g = {
    id: 'grp-' + shortId(10),
    name,
    icon: String(req.body.icon || '🏠').slice(0, 4),
    device_macs: Array.isArray(req.body.device_macs) ? req.body.device_macs.map(normalizeMac).filter(Boolean) : [],
    created_at: Date.now(),
  };
  state.device_groups[cid].push(g);
  saveState();
  res.json({ ok: true, group: g });
});
app.post('/api/customer/device-groups/update', customerAuth, (req, res) => {
  const list = state.device_groups[req.customer.id] || [];
  const g = list.find(x => x.id === req.body.id);
  if (!g) return res.status(404).json({ error: 'not found' });
  if (req.body.name !== undefined) g.name = String(req.body.name).slice(0, 60);
  if (req.body.icon !== undefined) g.icon = String(req.body.icon).slice(0, 4);
  if (Array.isArray(req.body.device_macs)) g.device_macs = req.body.device_macs.map(normalizeMac).filter(Boolean);
  saveState();
  res.json({ ok: true, group: g });
});
app.post('/api/customer/device-groups/delete', customerAuth, (req, res) => {
  const list = state.device_groups[req.customer.id] || [];
  const i = list.findIndex(x => x.id === req.body.id);
  if (i < 0) return res.status(404).json({ error: 'not found' });
  list.splice(i, 1);
  saveState();
  res.json({ ok: true });
});

// ─── Customer scheduled weekly digest ────────────────────────────────────
// Customer opts into weekly digest. Cron computes summary every Monday 09:00 LBT
// and pushes a notification (which is what we have — no SMTP).
app.get('/api/customer/digest-prefs', customerAuth, (req, res) => {
  const c = req.customer;
  res.json({ enabled: !!c.digest_enabled, day: c.digest_day || 'mon', last_sent_at: c.digest_last_sent_at || null });
});
app.post('/api/customer/digest-prefs', customerAuth, (req, res) => {
  const c = state.customers[req.customer.id];
  c.digest_enabled = !!req.body.enabled;
  if (req.body.day && ['mon','tue','wed','thu','fri','sat','sun'].includes(req.body.day)) c.digest_day = req.body.day;
  saveState();
  res.json({ ok: true, enabled: c.digest_enabled, day: c.digest_day || 'mon' });
});

// Compute a digest for one customer (returns text). Used by the cron and exposed for preview.
function computeDigest(cid) {
  const c = state.customers[cid];
  if (!c) return null;
  const since = Date.now() - 7 * 86400_000;
  const myFlows = state.flows.filter(f => f.customer_id === cid && f.ts >= since);
  const blocked = myFlows.filter(f => f.blocked).length;
  const myDevices = Object.values(state.authorized_macs)
    .filter(m => m.customer_id === cid)
    .flatMap(m => Object.values(state.box_devices[m.mac] || {}));
  const newDevices = myDevices.filter(d => d.first_seen >= since).length;
  const myAlarms = state.alarms.filter(a => a.customer_id === cid && a.ts >= since);
  const myTickets = Object.values(state.support_tickets || {}).filter(t => t.customer_id === cid && t.updated_at >= since);
  const speedtests = Object.values(state.authorized_macs).filter(m => m.customer_id === cid).flatMap(m => (state.speedtest_history && state.speedtest_history[m.mac] || []).filter(s => s.ts >= since));
  const avgDown = speedtests.length ? Math.round(speedtests.reduce((s, x) => s + x.down_mbps, 0) / speedtests.length) : null;
  return {
    customer_id: cid,
    period: '7d',
    flows: myFlows.length,
    blocked,
    block_pct: myFlows.length > 0 ? Math.round((blocked / myFlows.length) * 100) : 0,
    devices_new: newDevices,
    devices_total: myDevices.length,
    alarms: myAlarms.length,
    alarms_high: myAlarms.filter(a => a.severity === 'high' || a.severity === 'critical').length,
    tickets_open: myTickets.filter(t => t.status === 'open').length,
    avg_down_mbps: avgDown,
  };
}
app.get('/api/customer/digest/preview', customerAuth, (req, res) => {
  res.json(computeDigest(req.customer.id) || { error: 'no_data' });
});

// Cron: hourly check; if it's the customer's chosen day at ~09:00 LBT and we haven't
// sent today, push the digest.
function sendDigests() {
  const lbtNow = new Date(Date.now() + 3 * 3600_000);   // UTC+3 (no DST in Lebanon since 2023)
  const dayMap = ['sun','mon','tue','wed','thu','fri','sat'];
  const today = dayMap[lbtNow.getUTCDay()];
  const hour = lbtNow.getUTCHours();
  if (hour !== 9) return;   // only run during the 09:00 LBT hour
  for (const c of Object.values(state.customers)) {
    if (!c.digest_enabled) continue;
    if ((c.digest_day || 'mon') !== today) continue;
    const ageH = c.digest_last_sent_at ? (Date.now() - c.digest_last_sent_at) / 3600_000 : 1e9;
    if (ageH < 23) continue;
    const d = computeDigest(c.id);
    if (!d) continue;
    if (typeof pushNotification === 'function') {
      pushNotification(c.id, 'system', '📊 Your weekly digest',
        `Last 7 days: ${d.flows} flows (${d.block_pct}% blocked), ${d.alarms} alarms (${d.alarms_high} high), ` +
        `${d.devices_new} new devices, avg speed: ${d.avg_down_mbps || '?'} Mbps. Open the app for details.`);
    }
    c.digest_last_sent_at = Date.now();
  }
  saveState();
}
setInterval(sendDigests, 3600_000);
setTimeout(sendDigests, 5 * 60_000);

// ─── Customer feature request board ──────────────────────────────────────
// state.feature_requests = { id: {id, customer_id, customer_name, title, body, votes:[cid], status, created_at} }
if (!state.feature_requests) state.feature_requests = {};

app.post('/api/customer/feature-requests', customerAuth, (req, res) => {
  const c = req.customer;
  const title = String(req.body.title || '').trim().slice(0, 120);
  const body  = String(req.body.body || '').trim().slice(0, 2000);
  if (!title) return res.status(400).json({ error: 'title required' });
  // Rate limit: 3 per customer per 24h
  const recent = Object.values(state.feature_requests).filter(r => r.customer_id === c.id && (Date.now() - r.created_at) < 86400_000);
  if (recent.length >= 3) return res.status(429).json({ error: 'Limit 3 feature requests per day' });
  const id = 'fr-' + shortId(10);
  const r = {
    id, customer_id: c.id, customer_name: c.name,
    title, body,
    votes: [c.id], vote_count: 1,
    status: 'open',     // open | planned | in_progress | shipped | declined
    created_at: Date.now(),
  };
  state.feature_requests[id] = r;
  saveState();
  res.json({ ok: true, request: r });
});
app.get('/api/customer/feature-requests', customerAuth, (req, res) => {
  const list = Object.values(state.feature_requests);
  // Add my_vote flag
  const out = list.map(r => ({ ...r, my_vote: r.votes.includes(req.customer.id), votes: undefined }));
  out.sort((a, b) => b.vote_count - a.vote_count);
  res.json({ requests: out });
});
app.post('/api/customer/feature-requests/vote', customerAuth, (req, res) => {
  const r = state.feature_requests[req.body.id];
  if (!r) return res.status(404).json({ error: 'not found' });
  const cid = req.customer.id;
  const i = r.votes.indexOf(cid);
  if (i >= 0) { r.votes.splice(i, 1); }   // toggle off
  else { r.votes.push(cid); }
  r.vote_count = r.votes.length;
  saveState();
  res.json({ ok: true, my_vote: r.votes.includes(cid), vote_count: r.vote_count });
});
app.get('/admin/api/feature-requests', adminAuth, (req, res) => {
  const list = Object.values(state.feature_requests).sort((a, b) => b.vote_count - a.vote_count);
  res.json({ requests: list });
});
app.post('/admin/api/feature-requests/status', adminAuth, (req, res) => {
  const r = state.feature_requests[req.body.id];
  if (!r) return res.status(404).json({ error: 'not found' });
  const status = String(req.body.status || '').toLowerCase();
  if (!['open', 'planned', 'in_progress', 'shipped', 'declined'].includes(status)) {
    return res.status(400).json({ error: 'invalid status' });
  }
  r.status = status;
  r.status_updated_at = Date.now();
  saveState();
  if (typeof logAdminAction === 'function') logAdminAction(req, 'feature_request.status', r.id, status);
  // Notify the requester
  if (typeof pushNotification === 'function') {
    pushNotification(r.customer_id, 'system',
      `💡 Your feature request: ${status.replace('_', ' ')}`,
      `"${r.title}" status changed to: ${status}`);
  }
  res.json({ ok: true });
});

// ─── Customer support tickets ────────────────────────────────────────────
// state.support_tickets = { id: {id, customer_id, subject, status, created_at, updated_at, messages: [{from, body, ts}]} }
if (!state.support_tickets) state.support_tickets = {};

app.post('/api/customer/tickets', customerAuth, (req, res) => {
  const c = req.customer;
  const subject = String(req.body.subject || '').trim().slice(0, 200);
  const body    = String(req.body.body || '').trim().slice(0, 5000);
  if (!subject || !body) return res.status(400).json({ error: 'subject and body required' });
  const id = 'tkt-' + shortId(10);
  const t = {
    id, customer_id: c.id, customer_name: c.name,
    subject, status: 'open',
    created_at: Date.now(), updated_at: Date.now(),
    messages: [{ from: 'customer', body, ts: Date.now() }],
  };
  state.support_tickets[id] = t;
  saveState();
  console.log(`         🎫 NEW TICKET ${id} from ${c.name}: "${subject}"`);
  res.json({ ok: true, ticket: t });
});
app.get('/api/customer/tickets', customerAuth, (req, res) => {
  const mine = Object.values(state.support_tickets).filter(t => t.customer_id === req.customer.id);
  mine.sort((a, b) => b.updated_at - a.updated_at);
  res.json({ tickets: mine });
});
app.post('/api/customer/tickets/reply', customerAuth, (req, res) => {
  const t = state.support_tickets[req.body.id];
  if (!t || t.customer_id !== req.customer.id) return res.status(404).json({ error: 'not found' });
  const body = String(req.body.body || '').trim().slice(0, 5000);
  if (!body) return res.status(400).json({ error: 'body required' });
  t.messages.push({ from: 'customer', body, ts: Date.now() });
  t.updated_at = Date.now();
  if (t.status === 'closed') t.status = 'open';  // reopen on reply
  saveState();
  res.json({ ok: true, ticket: t });
});
app.post('/api/customer/tickets/close', customerAuth, (req, res) => {
  const t = state.support_tickets[req.body.id];
  if (!t || t.customer_id !== req.customer.id) return res.status(404).json({ error: 'not found' });
  t.status = 'closed';
  t.updated_at = Date.now();
  t.closed_at = Date.now();
  saveState();
  res.json({ ok: true, prompt_for_rating: !t.rating });
});
// Customer rates a closed ticket (1-5 stars + optional comment)
app.post('/api/customer/tickets/rate', customerAuth, (req, res) => {
  const t = state.support_tickets[req.body.id];
  if (!t || t.customer_id !== req.customer.id) return res.status(404).json({ error: 'not found' });
  if (t.status !== 'closed') return res.status(400).json({ error: 'rate only after close' });
  const rating = parseInt(req.body.rating);
  if (!Number.isInteger(rating) || rating < 1 || rating > 5) return res.status(400).json({ error: 'rating 1-5' });
  t.rating = rating;
  t.rating_comment = String(req.body.comment || '').slice(0, 500);
  t.rated_at = Date.now();
  saveState();
  console.log(`         ⭐ TICKET RATING ${rating}/5 — ${t.id} ("${t.subject}")`);
  res.json({ ok: true, rating });
});
// Admin: ticket-rating metrics dashboard
app.get('/admin/api/tickets/ratings', adminAuth, (req, res) => {
  const rated = Object.values(state.support_tickets || {}).filter(t => t.rating);
  if (!rated.length) return res.json({ count: 0, avg: null, distribution: {1:0,2:0,3:0,4:0,5:0}, recent: [] });
  const total = rated.reduce((s, t) => s + t.rating, 0);
  const dist = {1:0,2:0,3:0,4:0,5:0};
  for (const t of rated) dist[t.rating]++;
  rated.sort((a, b) => b.rated_at - a.rated_at);
  res.json({
    count: rated.length,
    avg: Math.round((total / rated.length) * 100) / 100,
    distribution: dist,
    csat_pct: Math.round((rated.filter(t => t.rating >= 4).length / rated.length) * 100),
    recent: rated.slice(0, 50).map(t => ({
      id: t.id, customer_id: t.customer_id, subject: t.subject,
      rating: t.rating, comment: t.rating_comment, rated_at: t.rated_at,
    })),
  });
});
app.get('/admin/api/tickets', adminAuth, (req, res) => {
  const status = req.query.status;
  let list = Object.values(state.support_tickets);
  if (status) list = list.filter(t => t.status === status);
  list.sort((a, b) => b.updated_at - a.updated_at);
  res.json({ tickets: list, total: list.length });
});
app.post('/admin/api/tickets/reply', adminAuth, (req, res) => {
  const t = state.support_tickets[req.body.id];
  if (!t) return res.status(404).json({ error: 'not found' });
  const body = String(req.body.body || '').trim().slice(0, 5000);
  if (!body) return res.status(400).json({ error: 'body required' });
  t.messages.push({ from: 'support', author: req.adminUser || 'support', body, ts: Date.now() });
  t.updated_at = Date.now();
  saveState();
  if (typeof pushNotification === 'function') {
    pushNotification(t.customer_id, 'system', `🎫 Reply on "${t.subject}"`, body.slice(0, 200));
  }
  if (typeof logAdminAction === 'function') logAdminAction(req, 'ticket.reply', t.id, body.slice(0, 100));
  res.json({ ok: true, ticket: t });
});
app.post('/admin/api/tickets/status', adminAuth, (req, res) => {
  const t = state.support_tickets[req.body.id];
  if (!t) return res.status(404).json({ error: 'not found' });
  const status = String(req.body.status || '').toLowerCase();
  if (!['open', 'pending', 'closed'].includes(status)) return res.status(400).json({ error: 'invalid status' });
  t.status = status;
  t.updated_at = Date.now();
  saveState();
  if (typeof logAdminAction === 'function') logAdminAction(req, 'ticket.status', t.id, status);
  res.json({ ok: true });
});

// Self-test endpoint — returns a diagnostic of customer's setup with green/yellow/red status per check
app.get('/api/customer/self-test', customerAuth, (req, res) => {
  const c = req.customer;
  const myMacs = Object.values(state.authorized_macs).filter(m => m.customer_id === c.id);
  const onlineBoxes = myMacs.filter(m => {
    const s = state.box_state[m.mac];
    return s && s.last_heartbeat && (Date.now() - s.last_heartbeat) < 5 * 60_000;
  });
  const recentFlows = state.flows.filter(f => f.customer_id === c.id && (Date.now() - f.ts) < 3600_000);
  const recentDnsQ  = (state.dns_queries[c.id] || []).filter(q => (Date.now() - q.ts) < 3600_000);
  const familyCount = (state.family_members[c.id] || []).length;
  const rulesCount  = (state.rules[c.id] || []).length;
  const schedulesCount = (state.schedules[c.id] || []).length;
  const hasAlarmsConfig = (state.notif_prefs[c.id] && state.notif_prefs[c.id].security !== false);
  // Devices on at least one box?
  const deviceCount = myMacs.reduce((s, m) => s + Object.keys(state.box_devices[m.mac] || {}).length, 0);

  const checks = [
    {
      id: 'box_authorized',
      label: 'Box authorized',
      status: myMacs.length > 0 ? 'pass' : 'fail',
      detail: myMacs.length > 0 ? `${myMacs.length} box(es) authorized` : 'No box claimed yet — tap "+ Add" on Home tab',
    },
    {
      id: 'box_online',
      label: 'Box online',
      status: myMacs.length === 0 ? 'skip' : (onlineBoxes.length > 0 ? 'pass' : 'fail'),
      detail: myMacs.length === 0 ? 'requires authorized box' :
              (onlineBoxes.length > 0 ? `${onlineBoxes.length}/${myMacs.length} online` : 'Box has not checked in. Power-cycle it.'),
    },
    {
      id: 'devices_seen',
      label: 'Devices being detected',
      status: onlineBoxes.length === 0 ? 'skip' : (deviceCount >= 1 ? 'pass' : 'warn'),
      detail: onlineBoxes.length === 0 ? 'requires online box' :
              (deviceCount > 0 ? `${deviceCount} devices seen` : 'No devices seen yet. Connect your devices to your network.'),
    },
    {
      id: 'flows_reporting',
      label: 'Box reporting traffic flows',
      status: onlineBoxes.length === 0 ? 'skip' : (recentFlows.length > 0 ? 'pass' : 'warn'),
      detail: onlineBoxes.length === 0 ? 'requires online box' :
              (recentFlows.length > 0 ? `${recentFlows.length} flows in last hour` : 'No flows yet. Verify devices use box for DNS.'),
    },
    {
      id: 'dns_logging',
      label: 'DNS query logging',
      status: onlineBoxes.length === 0 ? 'skip' : (recentDnsQ.length > 0 ? 'pass' : 'warn'),
      detail: onlineBoxes.length === 0 ? 'requires online box' :
              (recentDnsQ.length > 0 ? `${recentDnsQ.length} queries logged in last hour` : 'No DNS queries logged. Check dnsmasq logging on box.'),
    },
    {
      id: 'family',
      label: 'Family members configured',
      status: familyCount > 0 ? 'pass' : 'warn',
      detail: familyCount > 0 ? `${familyCount} member(s)` : 'No members yet — Family tab → + Add',
    },
    {
      id: 'rules',
      label: 'Blocking rules set',
      status: rulesCount > 0 ? 'pass' : 'warn',
      detail: rulesCount > 0 ? `${rulesCount} rule(s)` : 'No rules. Try blocking malware + adult by default.',
    },
    {
      id: 'schedules',
      label: 'Schedules / screen time',
      status: schedulesCount > 0 ? 'pass' : 'warn',
      detail: schedulesCount > 0 ? `${schedulesCount} schedule(s)` : 'No schedules. Try the "Bedtime" preset.',
    },
    {
      id: 'notifications',
      label: 'Security notifications enabled',
      status: hasAlarmsConfig ? 'pass' : 'warn',
      detail: hasAlarmsConfig ? 'Security alerts ON' : 'Enable security alerts in Settings → Notification preferences',
    },
  ];
  const score = checks.filter(c => c.status === 'pass').length;
  const max = checks.filter(c => c.status !== 'skip').length;
  res.json({ checks, score, max, percent: Math.round((score / Math.max(1, max)) * 100) });
});

// Activity heatmap — bytes by (day_of_week × hour_of_day) over last 30 days
app.get('/api/customer/heatmap', customerAuth, (req, res) => {
  const cutoff = Date.now() - 30 * 24 * 3600_000;
  const grid = Array.from({length: 7}, () => Array(24).fill(0));
  for (const f of state.flows) {
    if (f.customer_id !== req.customer.id || f.ts < cutoff) continue;
    const d = new Date(f.ts);
    grid[d.getDay()][d.getHours()] += (f.bytes_up || 0) + (f.bytes_down || 0);
  }
  let max = 0;
  for (const row of grid) for (const v of row) if (v > max) max = v;
  res.json({ days: ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'], grid, max });
});

// CSV export of flows for one device (last 24h)
app.get('/api/customer/device/:mac/flows.csv', customerAuth, (req, res) => {
  const mac = normalizeMac(req.params.mac);
  const cutoff = Date.now() - 24 * 3600_000;
  const rows = state.flows.filter(f => f.customer_id === req.customer.id && f.src_mac === mac && f.ts >= cutoff);
  const csv = toCSV(rows.map(f => ({
    ts: new Date(f.ts).toISOString(),
    src_mac: f.src_mac,
    src_ip: f.src_ip,
    dst_ip: f.dst_ip,
    dst_port: f.dst_port,
    dst_domain: f.dst_domain,
    proto: f.proto,
    bytes_up: f.bytes_up,
    bytes_down: f.bytes_down,
    blocked: f.blocked,
    category: f.category,
    country: f.country,
  })), ['ts','src_mac','src_ip','dst_ip','dst_port','dst_domain','proto','bytes_up','bytes_down','blocked','category','country']);
  res.set('Content-Type', 'text/csv');
  res.set('Content-Disposition', `attachment; filename="device-${mac.replace(/:/g,'')}-flows.csv"`);
  res.send(csv);
});

// 30-day daily usage breakdown (per device, per day)
app.get('/api/customer/usage-daily', customerAuth, (req, res) => {
  const days = Math.min(parseInt(req.query.days) || 30, 60);
  const myDaily = state.usage_daily[req.customer.id] || {};
  const cutoff = new Date(Date.now() - days * 24 * 3600_000).toISOString().slice(0, 10);
  const series = {};   // { day: total_bytes }
  const perDeviceByDay = {};  // { mac: { day: bytes } }
  const totalsByDevice = {};  // { mac: total_bytes }
  for (const [day, devs] of Object.entries(myDaily)) {
    if (day < cutoff) continue;
    series[day] = 0;
    for (const [mac, bytes] of Object.entries(devs)) {
      const tot = (bytes.bytes_up || 0) + (bytes.bytes_down || 0);
      series[day] += tot;
      if (!perDeviceByDay[mac]) perDeviceByDay[mac] = {};
      perDeviceByDay[mac][day] = tot;
      totalsByDevice[mac] = (totalsByDevice[mac] || 0) + tot;
    }
  }
  res.json({ days, series, per_device_by_day: perDeviceByDay, totals_by_device: totalsByDevice });
});

// ═══════════════════════════════════════════════════════════════════════════
//  DEVICE FINGERPRINTING — bigger OUI + classification
// ═══════════════════════════════════════════════════════════════════════════
// Wireshark `manuf` table — 39k OUIs. Loaded lazily at boot.
let OUI = {};
function loadOuiTable() {
  const candidates = [
    path.join(__dirname, 'oui-table.json'),
    '/data/oui-table.json',
  ];
  for (const p of candidates) {
    try {
      OUI = JSON.parse(fs.readFileSync(p, 'utf8'));
      console.log(`         🏷️  OUI table loaded: ${Object.keys(OUI).length} entries`);
      return;
    } catch {}
  }
  console.warn('         ⚠️  OUI table not found — vendor lookup disabled');
}
loadOuiTable();
function ouiVendor(mac) {
  if (!mac) return '';
  return OUI[mac.toLowerCase().slice(0, 8)] || '';
}
// DHCP fingerprint hints (from RFC 2132 option 55 strings agent extracts).
// Maps a fingerprint string → device type/icon. Box's agent.js builds these from /var/lib/misc/dnsmasq.leases hints.
const DHCP_FINGERPRINT_HINTS = {
  // option 55 sequences observed in the wild
  '1,121,3,6,15,119,252': { type: 'phone',    icon: '📱', label: 'iOS' },
  '1,3,6,15,119,252,95,44,46': { type: 'laptop', icon: '💻', label: 'macOS' },
  '1,15,3,6,44,46,47,31,33,121,249,43': { type: 'laptop', icon: '💻', label: 'Windows' },
  '1,3,6,12,15,28,42,121': { type: 'iot', icon: '🏠', label: 'Linux/IoT' },
  '1,3,6,15,28,33,51,58,59': { type: 'iot', icon: '🤖', label: 'Embedded' },
};
function classifyDevice(mac, hostname, vendor, dhcpFp) {
  const v = (vendor || ouiVendor(mac) || '').toLowerCase();
  const h = (hostname || '').toLowerCase();
  // 1. Try DHCP fingerprint first (most accurate when present)
  if (dhcpFp && DHCP_FINGERPRINT_HINTS[dhcpFp]) {
    return DHCP_FINGERPRINT_HINTS[dhcpFp];
  }
  // 2. Hostname / vendor heuristics
  if (/iphone|ipad|airpods|apple/.test(h) || v === 'apple')        return { type: 'phone',    icon: '📱' };
  if (/android|samsung|pixel|oneplus|xiaomi/.test(h))              return { type: 'phone',    icon: '📱' };
  if (/macbook|mbp|imac|laptop|surface/.test(h))                   return { type: 'laptop',   icon: '💻' };
  if (/dell|lenovo|thinkpad|hp-/.test(h) || v === 'dell')          return { type: 'laptop',   icon: '💻' };
  if (/playstation|ps5|ps4|xbox|nintendo|switch/.test(h))          return { type: 'console',  icon: '🎮' };
  if (/sony|nintendo/.test(v))                                     return { type: 'console',  icon: '🎮' };
  if (/tv|roku|firetv|chromecast|appletv/.test(h))                 return { type: 'tv',       icon: '📺' };
  if (/roku|sonos/.test(v))                                        return { type: 'tv',       icon: '📺' };
  if (/printer|hp[-_]print|epson|brother|canon/.test(h))           return { type: 'printer',  icon: '🖨️' };
  if (/raspberry|pi|nuc|nano/.test(h) || /raspberry/.test(v))      return { type: 'iot',      icon: '🤖' };
  if (/espressif|esp32|esp8266|shelly|tasmota/.test(v))            return { type: 'iot',      icon: '💡' };
  if (/echo|alexa|nest|hue|ring|wyze|tplink/.test(h))              return { type: 'iot',      icon: '🏠' };
  if (/firewalla/.test(v))                                         return { type: 'firewall', icon: '🛡️' };
  if (/synology|nas|qnap/.test(h) || /synology/.test(v))           return { type: 'nas',      icon: '💾' };
  if (/server/.test(h))                                            return { type: 'server',   icon: '🖥️' };
  return { type: 'unknown', icon: '❓' };
}

// ═══════════════════════════════════════════════════════════════════════════
//  CUSTOMER SSE — real-time push of alarms/flows to PWA
// ═══════════════════════════════════════════════════════════════════════════
const customerSseClients = new Map();  // customer_id → Set of res
function customerSseEmit(customer_id, eventType, payload) {
  const set = customerSseClients.get(customer_id);
  if (!set) return;
  const msg = `event: ${eventType}\ndata: ${JSON.stringify(payload)}\n\n`;
  for (const res of set) { try { res.write(msg); } catch {} }
}
app.get('/api/customer/events/stream', customerAuth, (req, res) => {
  res.set({
    'Content-Type':  'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    'Connection':    'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.flushHeaders();
  res.write(`: connected\n\n`);
  const cid = req.customer.id;
  if (!customerSseClients.has(cid)) customerSseClients.set(cid, new Set());
  customerSseClients.get(cid).add(res);
  const pingTimer = setInterval(() => { try { res.write(': ping\n\n'); } catch {} }, 25_000);
  req.on('close', () => {
    clearInterval(pingTimer);
    const set = customerSseClients.get(cid);
    if (set) { set.delete(res); if (set.size === 0) customerSseClients.delete(cid); }
  });
});

// ═══════════════════════════════════════════════════════════════════════════
//  ANOMALY DETECTOR — runs every 5 minutes, scans recent flows, fires alarms
// ═══════════════════════════════════════════════════════════════════════════
function runAnomalyScan() {
  const now = Date.now();
  const window = 5 * 60_000;
  const recent = state.flows.filter(f => (now - f.ts) < window);
  // Group by customer_id + src_mac
  const buckets = {};
  for (const f of recent) {
    const k = `${f.customer_id}|${f.src_mac || f.src_ip}`;
    if (!buckets[k]) buckets[k] = { customer_id: f.customer_id, src: f.src_mac || f.src_ip, bytes: 0, ports: new Set(), countries: new Set() };
    buckets[k].bytes += (f.bytes_up || 0) + (f.bytes_down || 0);
    if (f.dst_port) buckets[k].ports.add(f.dst_port);
    if (f.country) buckets[k].countries.add(f.country);
  }
  for (const b of Object.values(buckets)) {
    if (!b.customer_id) continue;
    // High data: >1 GB in 5 min
    if (b.bytes > 1024 * 1024 * 1024) {
      fireSyntheticAlarm(b.customer_id, null, 'high', 'high_data', 'Heavy data transfer detected', `Device ${b.src} pushed ${(b.bytes/1024/1024).toFixed(0)} MB in 5 minutes.`);
    }
    // Port scanning: contacted >40 distinct ports
    if (b.ports.size > 40) {
      fireSyntheticAlarm(b.customer_id, null, 'high', 'port_scan_outgoing', 'Possible port scan from your network', `Device ${b.src} contacted ${b.ports.size} different ports in 5 min — could be malware.`);
    }
    // Talked to >2 sanctioned countries (CN/RU/IR/KP)
    const flagged = Array.from(b.countries).filter(c => ['CN','RU','IR','KP'].includes(c));
    if (flagged.length >= 2) {
      fireSyntheticAlarm(b.customer_id, null, 'medium', 'geo_anomaly', 'Traffic to multiple high-risk countries', `Device ${b.src} reached ${flagged.join(', ')} recently.`);
    }
  }
}
if (!state.anomaly_dedup) state.anomaly_dedup = {};  // { "cust|kind": last_ts }

// MITRE ATT&CK technique map for alarm `kind` → one or more technique IDs.
// Used to enrich alarms with `attack_techniques: [...]` so the PWA can link to
// https://attack.mitre.org/techniques/<id>/ for each tag. Policy-violation
// kinds (gaming/video/social/porn) intentionally have NO mapping — those are
// behavioural, not adversarial.
const MITRE_TAGS = {
  port_scan_outgoing:  ['T1046'],
  sig_match:           ['T1071.001', 'T1095'],
  traffic_anomaly:     ['T1041'],
  high_data:           ['T1041'],
  large_upload:        ['T1048'],
  geo_anomaly:         ['T1090.003'],
  route_change:        ['T1557'],
  box_integrity_drift: ['T1098'],
  box_config_drift:    ['T1098'],
  new_device:          ['T1200'],
  vpn_activity:        ['T1572'],
  bypass_attempt:      ['T1090'],
  ja3_malware_signature: ['T1071.001', 'T1573'],
  // Tier-2 Feature B — could also be benign, but the hint is appropriate
  behavior_deviation:  ['T1041'],
  // Tier-2 threat-detection-depth additions
  ids_match:           ['T1190', 'T1071'],
  dga_suspected:       ['T1568.002'],
  c2_beacon_suspected: ['T1071.001'],
  device_cve_match:    ['T1190'],
};

// SNI patterns that indicate a device is trying to bypass parental controls
// or content filters. Each entry: { re, label }. `re` is matched against the
// lowercased SNI hostname.
const BYPASS_SNI_PATTERNS = [
  { re: /^mask(-h2)?\.icloud\.com$/i,                            label: 'iCloud Private Relay' },
  { re: /^(dns|chrome|1dot1dot1dot1)\.cloudflare-dns\.com$/i,    label: 'Cloudflare DoH' },
  { re: /^cloudflare-dns\.com$/i,                                label: 'Cloudflare DoH' },
  { re: /^mozilla\.cloudflare-dns\.com$/i,                       label: 'Mozilla/Cloudflare DoH' },
  { re: /^dns\.cloudflare\.com$/i,                               label: 'Cloudflare DoH' },
  { re: /^dns\.google$/i,                                        label: 'Google DoH' },
  { re: /^dns\.nextdns\.io$/i,                                   label: 'NextDNS DoH' },
  { re: /^dns\.adguard\.com$/i,                                  label: 'AdGuard DoH' },
  { re: /(^|\.)mullvad\.net$/i,                                  label: 'Mullvad VPN' },
  { re: /(^|\.)protonvpn\.com$/i,                                label: 'Proton VPN' },
  { re: /(^|\.)expressvpn\.com$/i,                               label: 'ExpressVPN' },
  { re: /(^|\.)nordvpn\.com$/i,                                  label: 'NordVPN' },
  { re: /(^|\.)surfshark\.com$/i,                                label: 'Surfshark VPN' },
  { re: /(^|\.)azirevpn\.com$/i,                                 label: 'AzireVPN' },
  { re: /(^|\.)torproject\.org$/i,                               label: 'Tor Project' },
];

// JA3 intel — MD5 hashes of TLS ClientHello fingerprints associated with
// known malware C2 frameworks (Cobalt Strike, Sliver, Mythic, NjRAT, etc).
// Hardcoded list compiled from public abuse.ch SSL/JA3 blacklists and
// research write-ups. Re-evaluate quarterly. The box agent's tshark pipeline
// currently does NOT capture JA3 (tshark 4.x dropped the field; see
// sni-parser.js comment); however, if/when JA3 hashes arrive from the box on
// `POST /api/box/sni-handshakes`, we match against this set and fire a
// `ja3_malware_signature` alarm.
const JA3_INTEL = new Set([
  '72a589da586844d7f0818ce684948eea',  // Cobalt Strike default (very common)
  'e7d705a3286e19ea42f587b344ee6865',  // Trickbot
  '6734f37431670b3ab4292b8f60f29984',  // Dridex
  '6f0e1a8cbf2c0b1f1d5a3e3d1b5c2f87',  // Sliver default
  '51c64c77e60f3980eea90869b68c58a8',  // Emotet
  'a0e9f5d64349fb13191bc781f81f42e1',  // Cobalt Strike beacon variant
  '94c485bca29d5392be53f2b8cf7f4304',  // AsyncRAT
  '37f463bf4616ecd445d4a1937da06e19',  // Tofsee
  '46571f93338ab3a6c95f2f00b8717720',  // Pirpi/Egregor
  '64e9e75e1c602fdba0913e3eccdf6961',  // Quasar RAT
  'cd08c4cd9e554e6f0ad017f522c2c50d',  // Sality
  'b1b3e982a4af6c39ef38e1ee6741e8e7',  // Mythic default
  '7dd50e112cd23734a310b90f6f44a7cd',  // Emotet (alt)
  '9e10692f1b7f78228b2d4e424db3a98c',  // Ramnit
  '3b5074b1b5d032e5620f69f9f700ff0e',  // Dyre
  '74954a0c86284d0d6e1ef72b67c98cf7',  // NjRAT
  '0cc1e84568e471aa1d62ad4158ade6b5',  // Gozi/IcedID
  '54328bd36c14bd82ddaa0c04b25ed9ad',  // BazarLoader
  '8916410db85077a5460817142dcbc8de',  // Smoke Loader
  '6f48bc4ed4cdebf18a8de3aacecf65a8',  // Ursnif
  'd6828e30ab66774a91a96ae93be4ae4c',  // PlugX
  '76979f037d2bb59c6f6f17caec7da4ce',  // Gootkit
  '466cc3e0f1aaef41bdc7c2dd3d2b6e9b',  // Hancitor
  'ec74a5c51106f0419184d0dd08fb05bc',  // Cobalt Strike (newer)
  '88c2f4d4d4cccbd6e8e0ad36fc8f6c4f',  // Mythic C2 variant
  '4d7a28d6f2263ed61de88ca66eb011e3',  // Adwind RAT
  '00a611080d77f2dd13ab26a32cad95a1',  // Phorpiex
  '12f5b1c1c5db7d27c5b4f5f17dac6d4b',  // RedLine Stealer
  '20c41c0a44b97e0c8b9a3a7e57b8c92e',  // Vidar Stealer
  'f60de2dfdd5dffaf6c3bb3b1d2f3a9b6',  // Raccoon Stealer
]);

function fireSyntheticAlarm(customer_id, box_mac, severity, kind, title, body, extras = {}) {
  // Per-kind mute (set by /api/customer/alarm-mutes/set) suppresses the entire alarm path.
  // Caller note: critical-severity alarms still fire (we can't be silenced into missing real emergencies).
  if (severity !== 'critical' && typeof alarmKindMutedFor === 'function' && alarmKindMutedFor(customer_id, kind)) {
    console.log(`         🔕 alarm muted (kind=${kind}) → cust=${customer_id}`);
    return;
  }
  const dedupeKey = `${customer_id}|${kind}`;
  const last = state.anomaly_dedup[dedupeKey] || 0;
  if (Date.now() - last < 30 * 60_000) return;  // suppress same kind within 30 min
  state.anomaly_dedup[dedupeKey] = Date.now();
  // Periodic GC: drop entries older than 24h
  if (Math.random() < 0.05) {
    const cutoff = Date.now() - 24 * 3600_000;
    for (const k of Object.keys(state.anomaly_dedup)) {
      if (state.anomaly_dedup[k] < cutoff) delete state.anomaly_dedup[k];
    }
  }
  const ts = Date.now();
  // Stable dedup key for client-side clustering ("AI de-noising"): same kind,
  // same device, same destination, same hour-bucket collapses to one row.
  const _dk_target = (extras.dst_domain || extras.dst_ip || 'any').toLowerCase();
  const _dk_dev = (extras.device_mac || '').toLowerCase();
  const dedup_key = `${kind}|${_dk_dev}|${_dk_target}|${Math.floor(ts / 3600000)}`;
  const a = {
    id: shortId(16), ts,
    customer_id, box_mac: box_mac || null,
    severity, kind, title, body,
    device_mac: extras.device_mac || '',
    dst_domain: extras.dst_domain || '',
    dst_ip:     extras.dst_ip     || '',
    category:   extras.category   || '',
    attack_techniques: MITRE_TAGS[kind] ? MITRE_TAGS[kind].slice() : [],
    dedup_key,
    acked: false, archived: false, source: 'cloud_anomaly',
  };
  state.alarms.unshift(a);
  if (state.alarms.length > 5000) state.alarms.length = 5000;
  // Tier-2 Feature A — recompute device risk on every alarm involving a device
  if (typeof computeDeviceRiskScore === 'function' && extras.device_mac) {
    try { computeDeviceRiskScore(customer_id, extras.device_mac); } catch(e) {}
  }
  pushNotification(customer_id, 'security', title, body);
  customerSseEmit(customer_id, 'alarm', a);
  fireWebhooks('alarm.created', { id: a.id, customer_id, severity, kind, title });
  if (typeof fireCustomerWebhook === 'function') fireCustomerWebhook(customer_id, 'alarm.fired', { id: a.id, severity, kind, title, body });
  // Honor customer's per-kind alarm mute. Alarm still recorded; notification is suppressed via pushNotification's path.
  // (The pushNotification call above already fires; we *also* check mute and skip if active.
  //  Implementation: shadow pushNotification for muted kinds by checking before customerSseEmit).
  console.log(`         ⚠️  ANOMALY ${severity.toUpperCase()} cust=${customer_id} ${kind}: ${title}`);
  // Tier-2 Feature D: auto-queue pcap capture on high/critical alarms when we
  // have both src_ip and dst_ip in extras. Privacy filter is also enforced on
  // the box itself (pcap-capture.js), but we double-check here.
  try { maybeQueuePcapCapture(a); } catch (e) { console.error('pcap queue err:', e.message); }
  // Tier-3 Feature B: fire-and-forget SIEM forward (alarms). The forwarder
  // does its own enabled/rate-cap/retry handling and returns a promise we
  // don't await.
  try {
    if (typeof cloudSiemForwarder !== 'undefined' && cloudSiemForwarder) {
      cloudSiemForwarder.forward(customer_id, { type: 'alarm', ...a }).catch(()=>{});
    }
  } catch (e) { /* ignore */ }
}

// Per-kind mute: customer can silence specific alarm kinds for N hours.
// Mute affects pushNotification suppression for matching kinds via kindMutedFor().
function alarmKindMutedFor(cid, kind) {
  const c = state.customers[cid];
  if (!c || !c.alarm_mutes) return false;
  const m = c.alarm_mutes[kind];
  if (!m) return false;
  if (m.until && m.until > Date.now()) return true;
  // Expired: clean up
  delete c.alarm_mutes[kind];
  return false;
}
app.get('/api/customer/alarm-mutes', customerAuth, (req, res) => {
  const c = req.customer;
  const mutes = {};
  for (const [k, m] of Object.entries(c.alarm_mutes || {})) {
    if (m.until > Date.now()) mutes[k] = m;
  }
  res.json({ mutes });
});
app.post('/api/customer/alarm-mutes/set', customerAuth, (req, res) => {
  const c = state.customers[req.customer.id];
  const kind = String(req.body.kind || '').slice(0, 60);
  const hours = parseInt(req.body.hours);
  if (!kind) return res.status(400).json({ error: 'kind required' });
  if (!Number.isInteger(hours) || hours < 1 || hours > 720) return res.status(400).json({ error: 'hours must be 1-720' });
  if (!c.alarm_mutes) c.alarm_mutes = {};
  c.alarm_mutes[kind] = { until: Date.now() + hours * 3600_000, set_at: Date.now() };
  saveState();
  res.json({ ok: true, kind, until: c.alarm_mutes[kind].until });
});
app.post('/api/customer/alarm-mutes/clear', customerAuth, (req, res) => {
  const c = state.customers[req.customer.id];
  const kind = req.body.kind;
  if (kind && c.alarm_mutes) { delete c.alarm_mutes[kind]; }
  else if (!kind) c.alarm_mutes = {};
  saveState();
  res.json({ ok: true });
});
setInterval(runAnomalyScan, 5 * 60_000);
setTimeout(runAnomalyScan, 60_000);  // first run after 1 min

// Box hardware health watcher — fires alarms on overheating, RAM exhaustion, prolonged offline
function runBoxHealthScan() {
  const now = Date.now();
  for (const [mac, b] of Object.entries(state.box_state || {})) {
    const m = state.authorized_macs[mac] || {};
    const cid = m.customer_id;
    if (!cid) continue;

    // 1. Offline > 30 min
    if (b.last_heartbeat && (now - b.last_heartbeat) > 30 * 60_000 && (now - b.last_heartbeat) < 2 * 3600_000) {
      // Only alert in the 30m–2h window so we don't spam after long downtime
      fireSyntheticAlarm(cid, mac, 'high', 'box_offline',
        'Your mes Box is offline',
        `The box at ${mac} stopped checking in ${Math.round((now - b.last_heartbeat)/60_000)} minutes ago.`);
    }
    // 2. Overheating
    if (b.temp_c && b.temp_c > 80) {
      fireSyntheticAlarm(cid, mac, 'high', 'box_overheat',
        'Box is overheating',
        `${mac} reported ${b.temp_c}°C — ensure the box has good ventilation. Sustained > 80 °C may damage hardware.`);
    }
    // 3. RAM > 90%
    if (b.ram_pct && b.ram_pct > 90) {
      fireSyntheticAlarm(cid, mac, 'medium', 'box_ram_high',
        'Box memory pressure',
        `${mac} is using ${b.ram_pct}% RAM. Consider rebooting it.`);
    }
    // 4. CPU > 90% (sustained — looks at last value, not perfect but useful)
    if (b.cpu_pct && b.cpu_pct > 90) {
      fireSyntheticAlarm(cid, mac, 'low', 'box_cpu_high',
        'Box CPU is busy',
        `${mac} is at ${b.cpu_pct}% CPU. May affect responsiveness.`);
    }
  }
}
setInterval(runBoxHealthScan, 5 * 60_000);
setTimeout(runBoxHealthScan, 90_000);

// ISP-wide simultaneous outage detection.
// If >= 5 boxes (or >= 20% of fleet, whichever is smaller) went offline within
// the last 10 minutes AND were online before then, fire a single major incident.
if (!state.isp_incidents) state.isp_incidents = [];   // [{id, started_at, affected_macs, count, total_fleet, ended_at}]
function detectIspWideOutage() {
  const now = Date.now();
  const onlineThreshold = 5 * 60_000;   // 5 min = "online"
  const offlineNew = 10 * 60_000;       // gone in last 10 min
  const offlineMax = 30 * 60_000;       // not >30 min ago — outside our window

  let totalFleet = 0, recentlyOffline = [];
  for (const [mac, b] of Object.entries(state.box_state || {})) {
    if (!b.last_heartbeat) continue;
    totalFleet++;
    const since = now - b.last_heartbeat;
    if (since > offlineNew && since <= offlineMax) recentlyOffline.push(mac);
  }
  if (totalFleet < 3) return;   // too small a fleet to be meaningful
  const threshold = Math.min(5, Math.ceil(totalFleet * 0.2));
  // Already-open incident? If yes, just update or close.
  const open = state.isp_incidents.find(i => !i.ended_at);
  if (recentlyOffline.length >= threshold) {
    if (!open) {
      const incident = {
        id: 'isp-' + shortId(10),
        started_at: now,
        affected_macs: recentlyOffline,
        count: recentlyOffline.length,
        total_fleet: totalFleet,
        ended_at: null,
      };
      state.isp_incidents.unshift(incident);
      if (state.isp_incidents.length > 200) state.isp_incidents.length = 200;
      console.log(`         🚨 ISP-WIDE INCIDENT: ${incident.count}/${incident.total_fleet} boxes offline`);
      // Notify all affected customers (one alarm per customer)
      const cids = new Set();
      for (const mac of recentlyOffline) {
        const cid = state.authorized_macs[mac] && state.authorized_macs[mac].customer_id;
        if (cid) cids.add(cid);
      }
      for (const cid of cids) {
        if (typeof fireSyntheticAlarm === 'function') {
          fireSyntheticAlarm(cid, null, 'high', 'isp_wide_outage',
            'Network-wide outage detected',
            `${incident.count} boxes across our ISP went offline in the last 10 minutes. ` +
            `This may indicate an upstream network issue, not a problem with your box. We're investigating.`);
        }
      }
    } else {
      // Update affected list
      open.affected_macs = recentlyOffline;
      open.count = recentlyOffline.length;
      open.total_fleet = totalFleet;
    }
  } else if (open && (now - open.started_at) > 5 * 60_000) {
    // Resolved
    open.ended_at = now;
    open.duration_s = Math.round((open.ended_at - open.started_at) / 1000);
    console.log(`         ✓ ISP-WIDE INCIDENT RESOLVED after ${open.duration_s}s`);
  }
  saveState();
}
setInterval(detectIspWideOutage, 2 * 60_000);
setTimeout(detectIspWideOutage, 120_000);

app.get('/admin/api/isp-incidents', adminAuth, (req, res) => {
  res.json({ incidents: state.isp_incidents, open: state.isp_incidents.find(i => !i.ended_at) || null });
});

// Quota-threshold alerts — fire at 80% / 90% / 100% of monthly cap, once per period
function runQuotaThresholdScan() {
  const period = currentPeriod();
  for (const [cid, quotas] of Object.entries(state.quotas || {})) {
    const usage = ((state.usage_monthly[cid] || {})[period]) || {};
    for (const q of quotas) {
      const u = usage[q.device_mac] || { bytes_up: 0, bytes_down: 0 };
      const used_gb = (u.bytes_up + u.bytes_down) / (1024 ** 3);
      const pct = (used_gb / q.monthly_gb) * 100;
      const c = state.customers[cid];
      if (!c) continue;
      // Track which thresholds we've fired this period to dedupe
      if (!q.threshold_fired) q.threshold_fired = {};
      if (q.threshold_fired._period !== period) {
        q.threshold_fired = { _period: period };
      }
      const fire = (label, severity) => {
        if (q.threshold_fired[label]) return;
        q.threshold_fired[label] = Date.now();
        fireSyntheticAlarm(cid, null, severity, 'quota_' + label,
          `Bandwidth ${label}% used`,
          `Device ${q.device_mac} has used ${used_gb.toFixed(1)} of ${q.monthly_gb} GB this month (${Math.round(pct)}%).`);
      };
      if (pct >= 100) fire('100', 'high');
      else if (pct >= 90) fire('90',  'medium');
      else if (pct >= 80) fire('80',  'low');
    }
  }
  saveState();
}
setInterval(runQuotaThresholdScan, 30 * 60_000);
setTimeout(runQuotaThresholdScan, 5 * 60_000);

// Customer-level outage detector — fires when >50% of a customer's tracked devices
// stop showing flow activity for >10 min (suggests a power/internet/box outage).
if (!state.outage_log) state.outage_log = [];   // [ {id, customer_id, started_at, ended_at, duration_s, devices_affected, devices_total} ]
const _activeOutages = new Map();   // customer_id → {started_at}

function runOutageDetector() {
  const cutoff = Date.now() - 10 * 60_000;
  const longerCutoff = Date.now() - 60 * 60_000;
  for (const cid of Object.keys(state.customers || {})) {
    const myMacs = Object.values(state.authorized_macs).filter(m => m.customer_id === cid).map(m => m.mac);
    if (!myMacs.length) continue;
    const myDevices = new Set();
    for (const mac of myMacs) {
      const devs = state.box_devices[mac] || {};
      for (const d of Object.values(devs)) myDevices.add(d.mac);
    }
    if (myDevices.size < 3) continue;  // only useful with several devices

    let active = 0, recently_seen = 0;
    for (const mac of myMacs) {
      for (const d of Object.values(state.box_devices[mac] || {})) {
        if (d.last_seen >= cutoff) active++;
        if (d.last_seen >= longerCutoff) recently_seen++;
      }
    }
    if (recently_seen === 0) continue;
    const activeRatio = active / recently_seen;
    const isOutage = activeRatio < 0.5 && recently_seen >= 3;
    const wasOutage = _activeOutages.has(cid);

    if (isOutage && !wasOutage) {
      // Open new outage record
      const id = 'out-' + shortId(10);
      const start = Date.now();
      _activeOutages.set(cid, { id, started_at: start, devices_total: recently_seen, devices_affected: recently_seen - active });
      state.outage_log.unshift({
        id, customer_id: cid, started_at: start, ended_at: null, duration_s: null,
        devices_affected: recently_seen - active, devices_total: recently_seen,
      });
      if (state.outage_log.length > 1000) state.outage_log.length = 1000;
      fireSyntheticAlarm(cid, null, 'high', 'outage',
        'Possible internet outage at your home',
        `Only ${active} of your last-seen ${recently_seen} devices have any traffic in the last 10 minutes. Most of your network may be offline.`);
    } else if (!isOutage && wasOutage) {
      // Close existing outage
      const o = _activeOutages.get(cid);
      _activeOutages.delete(cid);
      const rec = state.outage_log.find(x => x.id === o.id);
      if (rec) {
        rec.ended_at = Date.now();
        rec.duration_s = Math.round((rec.ended_at - rec.started_at) / 1000);
      }
      pushNotification(cid, 'system', '✓ Network back online',
        `The outage that started ${new Date(o.started_at).toLocaleTimeString()} appears to be over.`);
      saveState();
    }
  }
}

app.get('/api/customer/outages', customerAuth, (req, res) => {
  const mine = state.outage_log.filter(o => o.customer_id === req.customer.id);
  res.json({ outages: mine });
});
app.get('/admin/api/outages', adminAuth, (req, res) => {
  // Compute MTTR
  const closed = state.outage_log.filter(o => o.duration_s != null);
  const mttr_s = closed.length ? Math.round(closed.reduce((s, o) => s + o.duration_s, 0) / closed.length) : null;
  res.json({
    outages: state.outage_log.slice(0, 200),
    total: state.outage_log.length,
    open: state.outage_log.filter(o => o.ended_at === null).length,
    mttr_seconds: mttr_s,
  });
});
setInterval(runOutageDetector, 5 * 60_000);
setTimeout(runOutageDetector, 5 * 60_000);

// ─── OTA firmware delivery ───
const FIRMWARE_DIR = process.env.FIRMWARE_DIR || '/data/firmware';

app.post('/admin/api/firmware/upload', adminAuth, express.raw({ type: 'application/octet-stream', limit: '500mb' }), (req, res) => {
  if (req.adminRole !== 'super' && req.adminRole !== 'admin') {
    return res.status(403).json({ error: 'admin or super only' });
  }
  const version = req.query.version;
  const model = req.query.model || 'navy';
  const notes = req.query.notes || '';
  if (!version || !/^[\w.\-]+$/.test(version)) {
    return res.status(400).json({ error: 'version query param required (alnum/dot/dash/underscore only)' });
  }
  if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
    return res.status(400).json({ error: 'body must be the firmware binary (Content-Type: application/octet-stream)' });
  }

  if (!fs.existsSync(FIRMWARE_DIR)) fs.mkdirSync(FIRMWARE_DIR, { recursive: true });
  const filePath = path.join(FIRMWARE_DIR, `${model}-${version}.bin`);
  fs.writeFileSync(filePath, req.body);
  const sha256 = crypto.createHash('sha256').update(req.body).digest('hex');

  // Sign the manifest with our Ed25519 key (so boxes can verify authenticity)
  const manifest = { model, version, sha256, size: req.body.length, signed_at: new Date().toISOString() };
  const sigPayload = JSON.stringify(manifest);
  const signature = licenseKeys
    ? crypto.sign(null, Buffer.from(sigPayload), licenseKeys.privateKey).toString('base64')
    : '';

  state.firmwares[`${model}-${version}`] = {
    ...manifest,
    file_path: filePath,
    notes,
    signature,
  };
  saveState();
  logAdminAction(req, 'firmware.upload', version, `model=${model} size=${req.body.length}`);
  fireWebhooks('firmware.uploaded', { model, version, sha256, size: req.body.length });
  console.log(`         📦 FIRMWARE UPLOAD → ${model}-${version}  (${req.body.length} bytes)`);
  res.json({ ok: true, manifest: state.firmwares[`${model}-${version}`] });
});

app.get('/admin/api/firmware', adminAuth, (req, res) => {
  res.json({
    firmwares: Object.values(state.firmwares).map(f => ({
      ...f,
      file_path: undefined,  // hide local path
    })),
  });
});

app.post('/admin/api/firmware/delete', adminAuth, (req, res) => {
  if (req.adminRole !== 'super') return res.status(403).json({ error: 'super-admin only' });
  const key = req.body.key;
  const f = state.firmwares[key];
  if (!f) return res.status(404).json({ error: 'not found' });
  try { fs.unlinkSync(f.file_path); } catch {}
  delete state.firmwares[key];
  saveState();
  logAdminAction(req, 'firmware.delete', key);
  res.json({ ok: true });
});

// PUBLIC: list available firmware versions for a model (boxes call this)
app.get('/firmware/list/:model', (req, res) => {
  const list = Object.values(state.firmwares)
    .filter(f => f.model === req.params.model)
    .map(f => ({
      version: f.version,
      sha256: f.sha256,
      size: f.size,
      signed_at: f.signed_at,
      notes: f.notes,
    }))
    .sort((a, b) => b.version.localeCompare(a.version));
  res.json({ model: req.params.model, firmwares: list });
});

// PUBLIC: download a specific firmware (with signed manifest in header)
app.get('/firmware/download/:model/:version', (req, res) => {
  const f = state.firmwares[`${req.params.model}-${req.params.version}`];
  if (!f) return res.status(404).json({ error: 'not found' });
  state.events.push({ ts: Date.now(), method: 'GET', path: `[FIRMWARE-DOWNLOAD] ${req.params.model}/${req.params.version}`, ip: req.ip });
  console.log(`         📦 FIRMWARE DOWNLOAD → ${req.params.model}/${req.params.version}  ip=${req.ip}`);
  res.set('X-Firmware-SHA256', f.sha256);
  res.set('X-Firmware-Signature', f.signature);
  res.set('X-Firmware-Signed-At', f.signed_at);
  res.set('Content-Type', 'application/octet-stream');
  res.set('Content-Disposition', `attachment; filename="${req.params.model}-${req.params.version}.bin"`);
  res.sendFile(path.resolve(f.file_path));
});

// PUBLIC: get the manifest only (boxes can verify before downloading)
app.get('/firmware/manifest/:model/:version', (req, res) => {
  const f = state.firmwares[`${req.params.model}-${req.params.version}`];
  if (!f) return res.status(404).json({ error: 'not found' });
  res.json({
    model: f.model,
    version: f.version,
    sha256: f.sha256,
    size: f.size,
    signed_at: f.signed_at,
    signature: f.signature,
    notes: f.notes,
  });
});

// ─── Backup / restore (with optional password encryption) ───
function encryptBackup(plaintext, password) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(password, salt, 32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    encrypted: true,
    algo: 'aes-256-gcm',
    kdf: 'scrypt(N=16384,r=8,p=1,len=32)',
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ciphertext: ct.toString('base64'),
  };
}
function decryptBackup(payload, password) {
  const salt = Buffer.from(payload.salt, 'base64');
  const key = crypto.scryptSync(password, salt, 32);
  const iv = Buffer.from(payload.iv, 'base64');
  const tag = Buffer.from(payload.tag, 'base64');
  const ct = Buffer.from(payload.ciphertext, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

app.get('/admin/api/backup', adminAuth, (req, res) => {
  const bundle = {
    backup_version: 1,
    created_at: new Date().toISOString(),
    state: JSON.parse(JSON.stringify(state, (k, v) => v instanceof Set ? Array.from(v) : v)),
    license_keypair: licenseKeys ? {
      private_pem: licenseKeys.privPem,
      public_pem: licenseKeys.pubPem,
    } : null,
  };
  const json = JSON.stringify(bundle, null, 2);
  const password = req.query.password;
  res.set('Content-Disposition', 'attachment; filename="mes-cloud-backup-' + new Date().toISOString().slice(0,10) + (password ? '.enc.json' : '.json') + '"');
  res.set('Content-Type', 'application/json');
  if (password && password.length >= 8) {
    const enc = encryptBackup(json, password);
    console.log(`         💾 BACKUP downloaded (encrypted, original=${json.length} bytes)`);
    logAdminAction(req, 'backup.download', '', 'encrypted');
    return res.send(JSON.stringify(enc, null, 2));
  }
  console.log(`         💾 BACKUP downloaded (plaintext, ${json.length} bytes)`);
  logAdminAction(req, 'backup.download', '', 'plaintext');
  res.send(json);
});

// ─── Named snapshots — admin-managed restore points ───
const SNAPSHOTS_DIR = process.env.SNAPSHOTS_DIR || '/data/snapshots';
function ensureSnapshotsDir() { if (!fs.existsSync(SNAPSHOTS_DIR)) fs.mkdirSync(SNAPSHOTS_DIR, { recursive: true }); }

app.get('/admin/api/snapshots', adminAuth, (req, res) => {
  ensureSnapshotsDir();
  const files = fs.readdirSync(SNAPSHOTS_DIR).filter(f => f.endsWith('.json'));
  const out = files.map(f => {
    const stat = fs.statSync(path.join(SNAPSHOTS_DIR, f));
    return {
      name: f.replace(/\.json$/, ''),
      size: stat.size,
      created_at: stat.mtime,
    };
  });
  out.sort((a, b) => b.created_at - a.created_at);
  res.json({ snapshots: out });
});
app.post('/admin/api/snapshots/create', adminAuth, (req, res) => {
  ensureSnapshotsDir();
  const name = String(req.body.name || 'snapshot-' + new Date().toISOString().replace(/[:.]/g, '-')).replace(/[^\w.-]/g, '_').slice(0, 60);
  const fn = path.join(SNAPSHOTS_DIR, name + '.json');
  const bundle = {
    backup_version: 1,
    created_at: new Date().toISOString(),
    snapshot_name: name,
    notes: String(req.body.notes || '').slice(0, 200),
    state: JSON.parse(JSON.stringify(state, (k, v) => v instanceof Set ? Array.from(v) : v)),
    license_keypair: licenseKeys ? { private_pem: licenseKeys.privPem, public_pem: licenseKeys.pubPem } : null,
  };
  fs.writeFileSync(fn, JSON.stringify(bundle, null, 2));
  logAdminAction(req, 'snapshot.create', name);
  console.log(`         📸 SNAPSHOT created: ${name}`);
  res.json({ ok: true, name });
});
app.post('/admin/api/snapshots/restore', adminAuth, (req, res) => {
  if (req.adminRole && req.adminRole !== 'super') return res.status(403).json({ error: 'super-admin only' });
  const name = String(req.body.name || '').replace(/[^\w.-]/g, '_');
  const fn = path.join(SNAPSHOTS_DIR, name + '.json');
  if (!fs.existsSync(fn)) return res.status(404).json({ error: 'snapshot not found' });
  // Take a safety snapshot before restoring
  const safetyName = 'pre-restore-' + Date.now();
  fs.writeFileSync(path.join(SNAPSHOTS_DIR, safetyName + '.json'),
    JSON.stringify({ backup_version: 1, created_at: new Date().toISOString(), state: JSON.parse(JSON.stringify(state, (k,v) => v instanceof Set ? Array.from(v) : v)) }));
  const bundle = JSON.parse(fs.readFileSync(fn, 'utf8'));
  if (!bundle.state) return res.status(400).json({ error: 'invalid snapshot' });
  // Apply
  state = bundle.state;
  for (const g of Object.values(state.groups || {})) g.eids = new Set(g.eids || []);
  saveState();
  logAdminAction(req, 'snapshot.restore', name, 'safety=' + safetyName);
  console.log(`         🔄 SNAPSHOT restored: ${name} (pre-restore safety: ${safetyName})`);
  res.json({ ok: true, restored: name, safety_snapshot: safetyName });
});
app.post('/admin/api/snapshots/delete', adminAuth, (req, res) => {
  if (req.adminRole && req.adminRole !== 'super') return res.status(403).json({ error: 'super-admin only' });
  const name = String(req.body.name || '').replace(/[^\w.-]/g, '_');
  const fn = path.join(SNAPSHOTS_DIR, name + '.json');
  if (!fs.existsSync(fn)) return res.status(404).json({ error: 'not found' });
  fs.unlinkSync(fn);
  logAdminAction(req, 'snapshot.delete', name);
  res.json({ ok: true });
});

app.post('/admin/api/restore', adminAuth, express.json({ limit: '50mb' }), (req, res) => {
  let bundle = req.body;
  // If the uploaded blob is encrypted, decrypt with provided password
  if (bundle && bundle.encrypted) {
    const pwd = req.headers['x-backup-password'] || req.query.password;
    if (!pwd) return res.status(400).json({ error: 'encrypted backup — supply password via X-Backup-Password header' });
    try {
      const json = decryptBackup(bundle, pwd);
      bundle = JSON.parse(json);
    } catch (e) {
      return res.status(401).json({ error: 'wrong password or corrupt backup' });
    }
  }
  if (!bundle || !bundle.state) return res.status(400).json({ error: 'invalid backup' });
  // Restore state (replace in-memory)
  state = bundle.state;
  // Re-deserialize Sets
  for (const g of Object.values(state.groups || {})) {
    g.eids = new Set(Array.isArray(g.eids) ? g.eids : []);
  }
  // Restore keypair if included (must overwrite disk)
  if (bundle.license_keypair) {
    fs.writeFileSync(path.join(ED25519_DIR, 'license.priv.pem'), bundle.license_keypair.private_pem, { mode: 0o600 });
    fs.writeFileSync(path.join(ED25519_DIR, 'license.pub.pem'), bundle.license_keypair.public_pem);
    licenseKeys = loadOrCreateLicenseKeys();
  }
  saveState();
  console.log(`         💾 RESTORE complete`);
  res.json({ ok: true });
});

// Daily auto-backup → /var/backups/mes-cloud (rotates to keep last 14)
const BACKUP_DIR = process.env.BACKUP_DIR || '/var/backups';
function dailyBackup() {
  try {
    if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });
    const date = new Date().toISOString().slice(0, 10);
    const file = path.join(BACKUP_DIR, `mes-cloud-${date}.json`);
    const bundle = {
      backup_version: 1,
      created_at: new Date().toISOString(),
      state: JSON.parse(JSON.stringify(state, (k, v) => v instanceof Set ? Array.from(v) : v)),
      license_keypair: licenseKeys ? { private_pem: licenseKeys.privPem, public_pem: licenseKeys.pubPem } : null,
    };
    fs.writeFileSync(file, JSON.stringify(bundle));
    // Rotate: keep last 14 files
    const files = fs.readdirSync(BACKUP_DIR).filter(f => f.startsWith('mes-cloud-')).sort();
    while (files.length > 14) {
      try { fs.unlinkSync(path.join(BACKUP_DIR, files.shift())); } catch {}
    }
    console.log(`         💾 daily auto-backup → ${file}`);
  } catch (e) {
    console.error('daily backup failed:', e.message);
  }
}
// Run at process start (5s after) and every 24 hours
setTimeout(dailyBackup, 5000);
setInterval(dailyBackup, 24 * 60 * 60 * 1000);

// Daily admin digest email — once per 24h, on first eligible tick
function sendDailyDigest(force) {
  const now = Date.now();
  const dayMs = 24 * 60 * 60 * 1000;
  if (!force && state.digest_state.last_sent && (now - state.digest_state.last_sent) < dayMs - 60000) return;
  if (!state.config.admin_email) return;

  const customers = Object.values(state.customers);
  const newSignups24h = customers.filter(c => new Date(c.created_at).getTime() > now - dayMs);
  const checkins24h = state.checkins.filter(c => now - c.ts < dayMs).length;
  const customerActions24h = state.events.filter(e => e.method === 'CUSTOMER' && now - e.ts < dayMs).length;
  const adminActions24h = state.events.filter(e => e.method === 'ADMIN' && now - e.ts < dayMs).length;
  const onlineBoxes = Object.values(state.authorized_macs).filter(m => m.last_seen && (now - m.last_seen < 30 * 60 * 1000)).length;
  const offlineBoxes = Object.values(state.authorized_macs).filter(m => m.last_seen && (now - m.last_seen >= 60 * 60 * 1000)).length;
  const unpaidInvoices = Object.values(state.invoices).filter(i => i.status !== 'paid').length;
  const failedWebhooks = state.webhook_queue.length;

  const body = `mes Cloud — Daily Digest (${new Date().toISOString().slice(0,10)})

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Customers (total)        : ${customers.length}
  New signups today        : ${newSignups24h.length}
  Pending approvals        : ${customers.filter(c => c.status === 'pending').length}
  Boxes online             : ${onlineBoxes}
  Boxes offline >1h        : ${offlineBoxes}
  Unpaid invoices          : ${unpaidInvoices}
  Failed webhook queue     : ${failedWebhooks}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ACTIVITY (24h)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Box check-ins            : ${checkins24h}
  Customer actions         : ${customerActions24h}
  Admin actions            : ${adminActions24h}

${newSignups24h.length ? '\nNEW SIGNUPS:\n' + newSignups24h.map(c => `  • ${c.name} (${c.phone}) — ${c.plan}`).join('\n') : ''}
${offlineBoxes ? '\n⚠ BOXES OFFLINE >1h — check support tickets' : ''}

—
mes Cloud daily digest. To stop: set state.config.daily_digest_enabled = false.
`;

  sendEmail(state.config.admin_email, '[mes Cloud] Daily digest — ' + new Date().toISOString().slice(0, 10), body);
  state.digest_state.last_sent = now;
  saveState();
  console.log(`         📧 daily digest sent → ${state.config.admin_email}`);
}
// Check every hour, send if a day has passed
setInterval(sendDailyDigest, 60 * 60 * 1000);
setTimeout(sendDailyDigest, 30000);  // first check 30s after boot

// Admin manually triggers digest (useful for testing)
app.post('/admin/api/digest/send', adminAuth, (req, res) => {
  if (req.adminRole !== 'super' && req.adminRole !== 'admin') return res.status(403).json({ error: 'admin or super only' });
  sendDailyDigest(true);
  res.json({ ok: true, sent_to: state.config.admin_email });
});

// ─── CSV exports ───
function csvEscape(v) {
  if (v == null) return '';
  const s = String(v);
  return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}
function toCSV(rows, headers) {
  if (!rows.length) return headers.join(',') + '\n';
  return [headers.join(','), ...rows.map(r => headers.map(h => csvEscape(r[h])).join(','))].join('\n') + '\n';
}

app.get('/admin/api/export/customers.csv', adminAuth, (req, res) => {
  const now = Date.now();
  const rows = Object.values(state.customers).map(c => {
    const myMacs = Object.values(state.authorized_macs).filter(m => m.customer_id === c.id);
    const lastSeen = myMacs.map(m => m.last_seen || 0).sort().pop();
    return {
      id: c.id, name: c.name, phone: c.phone, email: c.email,
      plan: c.plan, status: c.status || 'active', address: c.address,
      box_count: myMacs.length,
      box_macs: myMacs.map(m => m.mac).join(';'),
      box_last_seen: lastSeen ? new Date(lastSeen).toISOString() : '',
      family_count: (state.family_members[c.id] || []).length,
      schedule_count: (state.schedules[c.id] || []).length,
      self_signup: !!c.self_signup,
      created_at: c.created_at,
    };
  });
  const csv = toCSV(rows, ['id','name','phone','email','plan','status','address','box_count','box_macs','box_last_seen','family_count','schedule_count','self_signup','created_at']);
  res.set('Content-Type', 'text/csv');
  res.set('Content-Disposition', 'attachment; filename="customers-' + new Date().toISOString().slice(0,10) + '.csv"');
  console.log(`         📋 EXPORT customers.csv → ${rows.length} rows`);
  res.send(csv);
});

app.get('/admin/api/export/events.csv', adminAuth, (req, res) => {
  const rows = state.events.slice(-1000).map(e => ({
    timestamp: new Date(e.ts).toISOString(),
    method: e.method,
    path: e.path,
    ip: e.ip || '',
  }));
  const csv = toCSV(rows, ['timestamp','method','path','ip']);
  res.set('Content-Type', 'text/csv');
  res.set('Content-Disposition', 'attachment; filename="events-' + new Date().toISOString().slice(0,10) + '.csv"');
  res.send(csv);
});

app.get('/admin/api/export/licenses.csv', adminAuth, (req, res) => {
  const rows = Object.entries(state.issued_licenses).map(([mac, lic]) => ({
    mac,
    uuid: lic.DATA.UUID,
    customer: lic.DATA.CUSTOMER,
    eid: lic.DATA.EID,
    type: lic.DATA.TYPE,
    luid: lic.DATA.LUID,
    issued_at: lic.DATA.ISSUED_AT,
    issuer: lic.DATA.ISSUER,
  }));
  const csv = toCSV(rows, ['mac','uuid','customer','eid','type','luid','issued_at','issuer']);
  res.set('Content-Type', 'text/csv');
  res.set('Content-Disposition', 'attachment; filename="licenses-' + new Date().toISOString().slice(0,10) + '.csv"');
  res.send(csv);
});

app.get('/admin/api/export/invoices.csv', adminAuth, (req, res) => {
  const rows = Object.values(state.invoices || {}).map(inv => {
    const cust = (inv.customer_id && state.customers[inv.customer_id]) || {};
    return {
      invoice_id: inv.id,
      period: inv.period,
      customer_id: inv.customer_id,
      customer_name: cust.name || '',
      customer_phone: cust.phone || '',
      customer_email: cust.email || '',
      plan: inv.plan,
      amount: inv.amount,
      currency: inv.currency,
      status: inv.status,
      promo_code: inv.promo_code || '',
      discount: inv.discount || 0,
      created_at: inv.created_at || '',
      paid_at: inv.paid_at || '',
    };
  });
  rows.sort((a, b) => (String(b.period) + b.invoice_id).localeCompare(String(a.period) + a.invoice_id));
  const csv = toCSV(rows, ['invoice_id','period','customer_id','customer_name','customer_phone','customer_email','plan','amount','currency','status','promo_code','discount','created_at','paid_at']);
  res.set('Content-Type', 'text/csv');
  res.set('Content-Disposition', 'attachment; filename="invoices-' + new Date().toISOString().slice(0,10) + '.csv"');
  res.send(csv);
});

// Admin: comprehensive single-customer drill-down (one-shot panel data)
app.get('/admin/api/customer/:cid/full', adminAuth, (req, res) => {
  const c = state.customers[req.params.cid];
  if (!c) return res.status(404).json({ error: 'not found' });
  const myMacs = Object.values(state.authorized_macs).filter(m => m.customer_id === c.id);
  const boxes = myMacs.map(m => {
    const s = state.box_state[m.mac] || {};
    return { mac: m.mac, type: m.type, online: s.last_heartbeat && (Date.now() - s.last_heartbeat) < 5*60_000,
             last_heartbeat: s.last_heartbeat, public_ip: s.public_ip, version: s.version, vitals: s };
  });
  const period = currentPeriod();
  const usage = (state.usage_monthly[c.id] || {})[period] || {};
  const totalUp   = Object.values(usage).reduce((s, v) => s + (v.bytes_up || 0), 0);
  const totalDown = Object.values(usage).reduce((s, v) => s + (v.bytes_down || 0), 0);

  res.json({
    customer: c,
    boxes,
    devices: Object.assign({}, ...myMacs.map(m => state.box_devices[m.mac] || {})),
    rules: state.rules[c.id] || [],
    schedules: state.schedules[c.id] || [],
    family: state.family_members[c.id] || [],
    quotas: state.quotas[c.id] || [],
    qos_rules: state.qos_rules[c.id] || [],
    time_bank: state.time_bank[c.id] || [],
    invoices: Object.values(state.invoices || {}).filter(i => i.customer_id === c.id),
    alarms: state.alarms.filter(a => a.customer_id === c.id).slice(0, 30),
    flows_recent: state.flows.filter(f => f.customer_id === c.id).slice(-50).reverse(),
    support_thread: state.support_threads[c.id] || [],
    notif_prefs: state.notif_prefs[c.id] || {},
    sites: Object.values(state.sites || {}).filter(s => s.customer_id === c.id),
    wg_peers: Object.values(state.wg_peers || {}).filter(p => p.customer_id === c.id).map(p => ({ id: p.id, label: p.device_label, address: p.address, pubkey: p.pubkey })),
    ddns: Object.values(state.ddns || {}).filter(d => d.customer_id === c.id),
    dns_records: state.dns_records[c.id] || [],
    dns_upstreams: state.dns_upstreams[c.id] || [],
    port_forwards: state.port_forwards[c.id] || [],
    dhcp_leases: state.dhcp_leases[c.id] || [],
    device_tags: state.device_tags[c.id] || {},
    usage_this_month: { bytes_up: totalUp, bytes_down: totalDown, gb: ((totalUp + totalDown) / 1024**3).toFixed(2) },
    speedtest_recent: myMacs.flatMap(m => (state.speedtest_history && state.speedtest_history[m.mac]) || []).sort((a, b) => b.ts - a.ts).slice(0, 10),
  });
});

// ─── Customer management admin API ───
app.get('/admin/api/customers', adminAuth, (req, res) => {
  const customers = Object.values(state.customers).map(c => ({
    ...c,
    boxes: Object.values(state.authorized_macs).filter(m => m.customer_id === c.id).map(m => ({
      mac: m.mac,
      type: m.type,
      authorized_at: m.authorized_at,
      license_issued: !!state.issued_licenses[m.mac],
    })),
  }));
  res.json({ customers });
});

app.post('/admin/api/customers/create', adminAuth, (req, res) => {
  const id = 'cust-' + shortId(8);
  const customer = {
    id,
    name: req.body.name || 'Unnamed',
    phone: req.body.phone || '',
    email: req.body.email || '',
    plan: req.body.plan || 'basic',
    address: req.body.address || '',
    notes: req.body.notes || '',
    status: 'active',
    self_signup: false,
    created_at: new Date().toISOString(),
  };
  state.customers[id] = customer;
  saveState();
  console.log(`         ★ CUSTOMER CREATED → ${id} (${customer.name})`);
  res.json({ ok: true, ...customer });
});

app.post('/admin/api/customers/update', adminAuth, (req, res) => {
  const c = state.customers[req.body.id];
  if (!c) return res.status(404).json({ error: 'customer not found' });
  // Track plan changes
  if (req.body.plan && req.body.plan !== c.plan) {
    recordPlanChange(c, req.body.plan, 'admin_direct_update', req.adminUser || 'admin');
  }
  Object.assign(c, {
    name: req.body.name ?? c.name,
    phone: req.body.phone ?? c.phone,
    email: req.body.email ?? c.email,
    plan: req.body.plan ?? c.plan,
    address: req.body.address ?? c.address,
    notes: req.body.notes ?? c.notes,
  });
  saveState();
  res.json({ ok: true, ...c });
});

// Bulk plan migration — move N customers from one plan to another.
// Body: { from_plan, to_plan, dry_run, customer_ids?: [], filter_status? }
// If customer_ids provided, only those are migrated. Otherwise all matching from_plan.
app.post('/admin/api/customers/bulk-migrate-plan', adminAuth, (req, res) => {
  const { from_plan, to_plan, dry_run, customer_ids, filter_status } = req.body || {};
  if (!to_plan) return res.status(400).json({ error: 'to_plan is required' });
  const validPlans = ['basic', 'family', 'pro', 'business'];
  if (!validPlans.includes(to_plan)) return res.status(400).json({ error: 'invalid to_plan', allowed: validPlans });
  if (from_plan && !validPlans.includes(from_plan)) return res.status(400).json({ error: 'invalid from_plan', allowed: validPlans });

  const planUsd = { basic: 5, family: 10, pro: 20, business: 50 };
  const idSet = Array.isArray(customer_ids) && customer_ids.length ? new Set(customer_ids) : null;
  const candidates = Object.values(state.customers).filter(c => {
    if (c.status === 'archived') return false;
    if (idSet) return idSet.has(c.id);
    if (from_plan && c.plan !== from_plan) return false;
    if (filter_status && c.status !== filter_status) return false;
    return true;
  });
  const summary = {
    matched: candidates.length,
    migrated: 0,
    revenue_delta_usd: 0,
    customers: [],
  };
  for (const c of candidates) {
    const before = c.plan;
    const beforeUsd = planUsd[before] || 0;
    const afterUsd = planUsd[to_plan] || 0;
    summary.revenue_delta_usd += (afterUsd - beforeUsd);
    summary.customers.push({ id: c.id, name: c.name, before, after: to_plan, mrr_delta_usd: afterUsd - beforeUsd });
    if (!dry_run) {
      if (before !== to_plan) {
        if (typeof recordPlanChange === 'function') recordPlanChange(c, to_plan, 'bulk_migrate', req.adminUser || 'admin');
        c.plan = to_plan;
        summary.migrated++;
      }
    }
  }
  if (!dry_run) {
    if (typeof logAdminAction === 'function') {
      logAdminAction(req, 'bulk_migrate_plan',
        `${from_plan || 'any'} → ${to_plan}`,
        `migrated=${summary.migrated} delta_usd=${summary.revenue_delta_usd}`);
    }
    saveState();
  }
  res.json({ dry_run: !!dry_run, ...summary });
});

app.post('/admin/api/customers/delete', adminAuth, (req, res) => {
  delete state.customers[req.body.id];
  // Unassign their boxes (don't revoke, just orphan them)
  for (const m of Object.values(state.authorized_macs)) {
    if (m.customer_id === req.body.id) {
      delete m.customer_id;
      m.customer_name = '(unassigned)';
    }
  }
  saveState();
  res.json({ ok: true });
});

// Get / set system config (auto-approve, signup enabled, etc.)
app.get('/admin/api/config', adminAuth, (req, res) => {
  res.json({ config: state.config });
});

app.post('/admin/api/config', adminAuth, (req, res) => {
  state.config = { ...state.config, ...req.body };
  saveState();
  console.log(`         ★ CONFIG UPDATED → ${JSON.stringify(state.config)}`);
  res.json({ ok: true, config: state.config });
});

// Admin IP allowlist — separate endpoint with validation. Empty array = disabled.
app.get('/admin/api/admin-ip-allowlist', adminAuth, (req, res) => {
  res.json({ allowlist: (state.config && state.config.admin_ip_allowlist) || [], your_ip: req.ip });
});
app.post('/admin/api/admin-ip-allowlist', adminAuth, (req, res) => {
  const list = Array.isArray(req.body.allowlist) ? req.body.allowlist : [];
  // Validate: each must be IP or IP/CIDR
  for (const entry of list) {
    if (typeof entry !== 'string') return res.status(400).json({ error: 'allowlist must be array of IP strings' });
    if (entry.includes('/')) {
      const [ip, bits] = entry.split('/');
      if (_ipToNum(ip) == null || isNaN(parseInt(bits)) || parseInt(bits) < 0 || parseInt(bits) > 32) {
        return res.status(400).json({ error: `invalid CIDR: ${entry}` });
      }
    } else if (_ipToNum(entry) == null) {
      return res.status(400).json({ error: `invalid IP: ${entry}` });
    }
  }
  // Safety: don't lock yourself out — the requesting IP must be in the new list (if non-empty)
  if (list.length > 0 && !list.some(c => _ipInCidr(req.ip.replace(/^::ffff:/, ''), c))) {
    // Allow X-Forwarded-For too
    const xff = String(req.headers['x-forwarded-for'] || '').split(',').map(s => s.trim()).filter(Boolean);
    if (!xff.some(ip => list.some(c => _ipInCidr(ip, c)))) {
      return res.status(400).json({ error: 'self_lockout_risk', message: 'Your IP is not in the new allowlist. Add it first.', your_ip: req.ip, your_xff: xff });
    }
  }
  state.config.admin_ip_allowlist = list;
  saveState();
  if (typeof logAdminAction === 'function') logAdminAction(req, 'admin_ip_allowlist_set', '', JSON.stringify(list));
  res.json({ ok: true, allowlist: list });
});

// Internal staff notes (admin-only) — stored on the customer record under `staff_notes`
app.post('/admin/api/customers/note', adminAuth, (req, res) => {
  const c = state.customers[req.body.id];
  if (!c) return res.status(404).json({ error: 'customer not found' });
  if (!c.staff_notes) c.staff_notes = [];
  const note = {
    id: 'note-' + shortId(8),
    body: String(req.body.body || '').slice(0, 1000).trim(),
    by: req.adminUser,
    ts: Date.now(),
  };
  if (!note.body) return res.status(400).json({ error: 'empty note' });
  c.staff_notes.unshift(note);
  if (c.staff_notes.length > 50) c.staff_notes = c.staff_notes.slice(0, 50);
  saveState();
  logAdminAction(req, 'customer.note_add', c.id, note.body.slice(0, 60));
  res.json({ ok: true, note });
});

app.post('/admin/api/customers/note/delete', adminAuth, (req, res) => {
  const c = state.customers[req.body.id];
  if (!c || !c.staff_notes) return res.status(404).json({ error: 'not found' });
  c.staff_notes = c.staff_notes.filter(n => n.id !== req.body.note_id);
  saveState();
  res.json({ ok: true });
});

// 30-day trend data (for admin dashboard graphs)
app.get('/admin/api/trends', adminAuth, (req, res) => {
  const days = 30;
  const now = Date.now();
  const dayStart = (i) => {
    const d = new Date(now - (days - 1 - i) * 86400000);
    d.setHours(0, 0, 0, 0);
    return d.getTime();
  };

  // Signups per day (from customer.created_at)
  const signups = Array(days).fill(0);
  for (const c of Object.values(state.customers)) {
    const t = new Date(c.created_at).getTime();
    for (let i = 0; i < days; i++) {
      if (t >= dayStart(i) && t < dayStart(i) + 86400000) { signups[i]++; break; }
    }
  }

  // Customer events per day (from event stream — only CUSTOMER actions)
  const actions = Array(days).fill(0);
  for (const e of state.events) {
    if (e.method !== 'CUSTOMER') continue;
    for (let i = 0; i < days; i++) {
      if (e.ts >= dayStart(i) && e.ts < dayStart(i) + 86400000) { actions[i]++; break; }
    }
  }

  // Box check-ins per day
  const checkins = Array(days).fill(0);
  for (const c of state.checkins) {
    for (let i = 0; i < days; i++) {
      if (c.ts >= dayStart(i) && c.ts < dayStart(i) + 86400000) { checkins[i]++; break; }
    }
  }

  res.json({
    days,
    labels: Array.from({ length: days }, (_, i) => new Date(dayStart(i)).toISOString().slice(5, 10)),
    signups,
    actions,
    checkins,
    totals: {
      signups: signups.reduce((a, b) => a + b, 0),
      actions: actions.reduce((a, b) => a + b, 0),
      checkins: checkins.reduce((a, b) => a + b, 0),
    },
  });
});

// Demo data seeder (super-admin only)
app.post('/admin/api/seed-demo', adminAuth, (req, res) => {
  if (req.adminRole !== 'super') return res.status(403).json({ error: 'super-admin only' });

  // Seed ~5 demo customers with full realistic data — for sales demos
  const customers = [
    { name: 'Hassan Demo',  phone: '+961 70 999 0001', email: 'hassan@demo.lb',  plan: 'family',   address: 'Hamra, Beirut' },
    { name: 'Layla Demo',   phone: '+961 70 999 0002', email: 'layla@demo.lb',   plan: 'pro',      address: 'Verdun, Beirut' },
    { name: 'Karim Demo',   phone: '+961 70 999 0003', email: 'karim@demo.lb',   plan: 'basic',    address: 'Ain el Mreisseh' },
    { name: 'Demo Office',  phone: '+961 1 999 0004',  email: 'office@demo.lb',  plan: 'business', address: 'Achrafieh' },
    { name: 'Maya Demo',    phone: '+961 76 999 0005', email: 'maya@demo.lb',    plan: 'family',   address: 'Tripoli' },
  ];
  let createdCount = 0;
  const seededIds = [];
  for (const cd of customers) {
    if (findCustomerByPhone(cd.phone)) continue;
    const id = 'cust-' + shortId(8);
    state.customers[id] = { id, ...cd, status: 'active', self_signup: false, demo: true, created_at: new Date().toISOString() };
    seededIds.push(id);
    createdCount++;

    // Authorize 1-2 boxes per customer
    const boxCount = cd.plan === 'business' ? 2 : 1;
    for (let i = 0; i < boxCount; i++) {
      const oui = ['b8:27:eb','dc:a6:32','d8:3a:dd'][Math.floor(Math.random()*3)];
      const mac = `${oui}:${shortId(2).toLowerCase()}:${shortId(2).toLowerCase()}:${shortId(2).toLowerCase()}`;
      state.authorized_macs[mac] = {
        mac, customer_id: id, customer_name: cd.name,
        type: 'pi4', authorized_at: new Date().toISOString(),
        notes: 'demo seed', friendly_name: i > 0 ? 'Office' : 'Home', demo: true,
      };
      // Fake heartbeat history (last 30 days, 50% online)
      state.box_state[mac] = {
        last_heartbeat: Date.now() - Math.floor(Math.random() * 5 * 60_000),
        public_ip: `188.93.${110+Math.floor(Math.random()*5)}.${Math.floor(Math.random()*250)}`,
        version: '1.0.0',
        uptime_s: Math.floor(Math.random() * 30 * 86400),
        cpu_pct: Math.floor(5 + Math.random() * 25),
        ram_pct: Math.floor(35 + Math.random() * 30),
        temp_c:  Math.floor(38 + Math.random() * 12),
        device_count: Math.floor(4 + Math.random() * 12),
      };
      // Devices
      const deviceTemplates = [
        { hostname: 'iPhone-15',     vendor: 'Apple',  device_type: 'phone',   device_icon: '📱' },
        { hostname: 'MacBookPro',    vendor: 'Apple',  device_type: 'laptop',  device_icon: '💻' },
        { hostname: 'Samsung-TV',    vendor: 'Samsung',device_type: 'tv',      device_icon: '📺' },
        { hostname: 'PlayStation-5', vendor: 'Sony',   device_type: 'console', device_icon: '🎮' },
        { hostname: 'Echo-Living',   vendor: 'Amazon', device_type: 'iot',     device_icon: '🏠' },
        { hostname: 'iPad-Kids',     vendor: 'Apple',  device_type: 'phone',   device_icon: '📱' },
      ];
      state.box_devices[mac] = {};
      for (const dt of deviceTemplates.slice(0, state.box_state[mac].device_count)) {
        const dmac = `${shortId(2).toLowerCase()}:${shortId(2).toLowerCase()}:${shortId(2).toLowerCase()}:${shortId(2).toLowerCase()}:${shortId(2).toLowerCase()}:${shortId(2).toLowerCase()}`;
        state.box_devices[mac][dmac] = {
          mac: dmac, ip: `192.168.1.${20 + Math.floor(Math.random() * 200)}`,
          ...dt,
          first_seen: Date.now() - Math.floor(Math.random() * 30 * 86400_000),
          last_seen:  Date.now() - Math.floor(Math.random() * 5 * 60_000),
          blocked: false, online: true,
        };
      }
      // Speedtest history (last 7 days)
      if (!state.speedtest_history) state.speedtest_history = {};
      state.speedtest_history[mac] = [];
      for (let d = 0; d < 7; d++) {
        state.speedtest_history[mac].push({
          ts: Date.now() - d * 86400_000,
          down_mbps: 80 + Math.random() * 50,
          up_mbps: 12 + Math.random() * 8,
          latency_ms: 6 + Math.random() * 12,
          tool: 'speedtest-cli', server: 'Beirut',
        });
      }
      // Heartbeat history for uptime calc
      if (!state.heartbeat_history) state.heartbeat_history = {};
      state.heartbeat_history[mac] = [];
      for (let m = 0; m < 30 * 24 * 12; m++) {
        if (Math.random() > 0.05) state.heartbeat_history[mac].push(Date.now() - m * 5 * 60_000);
      }
    }

    // Family members
    state.family_members[id] = [
      { id: 'fam-' + shortId(8), name: 'Mom',  role: 'Adult', icon: '👩', device_macs: [], created_at: new Date().toISOString() },
      { id: 'fam-' + shortId(8), name: 'Yara', role: 'Kid',   icon: '👧', device_macs: [], created_at: new Date().toISOString() },
    ];
    // Sample schedule
    state.schedules[id] = [{
      id: 'sched-' + shortId(8), name: 'Bedtime', icon: '🌙',
      device_macs: [], family_ids: [state.family_members[id][1].id],
      days: ['mon','tue','wed','thu','fri','sat','sun'],
      start_hhmm: '21:00', end_hhmm: '07:00', enabled: true, preset_id: 'bedtime',
      created_at: new Date().toISOString(),
    }];
    // Sample rules
    state.rules[id] = [
      { id: shortId(12), scope:'all', target:'', type:'category', value:'adult', action:'block', enabled:true, created_at: Date.now() },
      { id: shortId(12), scope:'all', target:'', type:'category', value:'malware', action:'block', enabled:true, created_at: Date.now() },
    ];
    // Quotas
    state.quotas[id] = [{ id: shortId(10), device_mac: 'aa:bb:cc:dd:ee:01', monthly_gb: 10, created_at: Date.now() }];
    // Recent flows (50 entries spread over last 24h)
    const targets = [
      { domain:'youtube.com',  ip:'142.250.190.46', cat:'video', country:'US' },
      { domain:'instagram.com',ip:'157.240.7.174',  cat:'social', country:'US' },
      { domain:'whatsapp.com', ip:'31.13.65.51',    cat:null, country:'US' },
      { domain:'netflix.com',  ip:'52.6.117.190',   cat:'video', country:'US' },
      { domain:'wikipedia.org',ip:'208.80.154.224', cat:null, country:'US' },
      { domain:'google.com',   ip:'142.250.179.110',cat:null, country:'US' },
    ];
    const myMacs = Object.keys(state.box_devices[Object.keys(state.box_devices)[0]] || {});
    for (let i = 0; i < 80; i++) {
      const t = targets[Math.floor(Math.random() * targets.length)];
      const srcMac = myMacs[Math.floor(Math.random() * myMacs.length)] || 'aa:bb:cc:dd:ee:01';
      state.flows.push({
        ts: Date.now() - Math.floor(Math.random() * 24 * 3600_000),
        box_mac: Object.keys(state.box_state)[0], customer_id: id,
        src_mac: srcMac, src_ip: '192.168.1.' + (50 + Math.floor(Math.random()*100)),
        dst_ip: t.ip, dst_port: 443, dst_domain: t.domain, proto: 'tcp',
        bytes_up: Math.floor(1000 + Math.random() * 50000),
        bytes_down: Math.floor(20000 + Math.random() * 5_000_000),
        blocked: false, category: t.cat, country: t.country,
      });
    }
    // Recent alarms
    state.alarms.unshift({
      id: shortId(16), ts: Date.now() - Math.floor(Math.random() * 6 * 3600_000),
      customer_id: id, box_mac: Object.keys(state.box_state)[0],
      severity: 'medium', kind: 'new_device',
      title: 'New device on your network',
      body: 'iPhone-15 (aa:bb:cc:dd:ee:23) joined your network',
      device_mac: 'aa:bb:cc:dd:ee:23', acked: false,
    });
  }
  saveState();
  logAdminAction(req, 'seed.demo', '', `created=${createdCount}`);
  res.json({ ok: true, created: createdCount, customer_ids: seededIds });
});

// Wipe all demo customers + their data (for un-seeding before going live)
app.post('/admin/api/unseed-demo', adminAuth, (req, res) => {
  if (req.adminRole !== 'super') return res.status(403).json({ error: 'super-admin only' });
  const demoCusts = Object.values(state.customers).filter(c => c.demo);
  let removed = 0;
  for (const c of demoCusts) {
    delete state.customers[c.id];
    delete state.family_members[c.id];
    delete state.schedules[c.id];
    delete state.rules[c.id];
    delete state.quotas[c.id];
    delete state.notifications[c.id];
    state.flows = state.flows.filter(f => f.customer_id !== c.id);
    state.alarms = state.alarms.filter(a => a.customer_id !== c.id);
    removed++;
  }
  // Delete demo MACs + their telemetry
  for (const m of Object.values(state.authorized_macs)) {
    if (m.demo) {
      delete state.authorized_macs[m.mac];
      delete state.box_state[m.mac];
      delete state.box_devices[m.mac];
      if (state.speedtest_history) delete state.speedtest_history[m.mac];
      if (state.heartbeat_history) delete state.heartbeat_history[m.mac];
    }
  }
  saveState();
  logAdminAction(req, 'unseed.demo', '', `removed=${removed}`);
  res.json({ ok: true, removed });
});

// State reset (super-admin only — wipes everything except admins + license keypair)
app.post('/admin/api/reset-state', adminAuth, (req, res) => {
  if (req.adminRole !== 'super') return res.status(403).json({ error: 'super-admin only' });
  if (req.body.confirm !== 'YES_RESET_EVERYTHING') {
    return res.status(400).json({ error: 'must POST {confirm: "YES_RESET_EVERYTHING"}' });
  }
  const keepAdmins = state.admins;
  const keepConfig = state.config;
  state = {
    groups: {}, rendezvous: {}, endpoints: {}, licenses: {},
    messages: [], checkins: [], events: [],
    authorized_macs: {}, issued_licenses: {}, customers: {},
    family_members: {}, schedules: {}, notifications: {},
    support_threads: {}, invitations: {},
    admins: keepAdmins, config: keepConfig,
    webhooks: [], admin_actions: [],
  };
  saveState();
  console.log(`         ⚠ STATE RESET by ${req.adminUser}`);
  res.json({ ok: true, message: 'State reset — admins + config + Ed25519 keypair preserved.' });
});

// Admin impersonate a customer — issues a short-lived (1h) customer JWT for debugging
app.post('/admin/api/customers/impersonate', adminAuth, (req, res) => {
  if (req.adminRole === 'reseller' && !canAccessCustomer(req, req.body.id)) {
    return res.status(403).json({ error: 'not in your scope' });
  }
  const c = state.customers[req.body.id];
  if (!c) return res.status(404).json({ error: 'customer not found' });
  if (!licenseKeys) return res.status(500).json({ error: 'no signing key' });

  const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    sub: c.id, name: c.name, phone: c.phone, plan: c.plan,
    impersonated_by: req.adminUser,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,  // 1 hour
  })).toString('base64url');
  const signature = crypto.sign(null, Buffer.from(header + '.' + payload), licenseKeys.privateKey).toString('base64url');
  const token = `${header}.${payload}.${signature}`;

  logAdminAction(req, 'customer.impersonate', c.id, c.name);
  console.log(`         👁 IMPERSONATE → ${req.adminUser} as ${c.name}`);
  // Notify the customer (audit trail visible to them)
  pushNotification(c.id, 'system', 'ℹ️ Account accessed by support',
    `A support agent (${req.adminUser}) opened your account briefly to help. This is logged.`);

  const url = `https://${state.config.brand_domain || 'cloud.mes.net.lb'}/pwa/?impersonate=${token}`;
  res.json({ ok: true, token, expires_in_sec: 3600, url, customer: { id: c.id, name: c.name } });
});

// Bulk customer operations — approve/suspend/notify/delete a list of customer IDs at once
app.post('/admin/api/customers/bulk', adminAuth, (req, res) => {
  const ids = Array.isArray(req.body.ids) ? req.body.ids : [];
  const action = req.body.action;
  if (!ids.length) return res.status(400).json({ error: 'no customer ids' });
  if (!['approve', 'suspend', 'reactivate', 'delete', 'notify'].includes(action)) {
    return res.status(400).json({ error: 'invalid action', allowed: ['approve','suspend','reactivate','delete','notify'] });
  }

  // Filter to customers within scope (resellers can only act on their assigned)
  const targets = ids.filter(id => state.customers[id] && canAccessCustomer(req, id));
  let processed = 0;

  for (const id of targets) {
    const c = state.customers[id];
    if (action === 'approve' || action === 'reactivate') {
      const was = c.status;
      c.status = 'active';
      if (was === 'pending') {
        pushNotification(c.id, 'success', '✅ Account approved', 'Welcome! You can now sign in.');
      }
      processed++;
    } else if (action === 'suspend') {
      c.status = 'suspended';
      pushNotification(c.id, 'warn', '⚠ Account suspended', 'Please contact support to restore service.');
      processed++;
    } else if (action === 'delete') {
      delete state.customers[id];
      delete state.family_members[id];
      delete state.schedules[id];
      delete state.notifications[id];
      delete state.support_threads[id];
      for (const m of Object.values(state.authorized_macs)) {
        if (m.customer_id === id) { delete m.customer_id; m.customer_name = '(deleted)'; }
      }
      processed++;
    } else if (action === 'notify') {
      const title = req.body.title || 'Notice';
      const body = req.body.body || '';
      const kind = req.body.kind || 'info';
      pushNotification(c.id, kind, title, body);
      processed++;
    }
  }

  saveState();
  logAdminAction(req, 'customers.bulk_' + action, '', `targets=${targets.length} processed=${processed}`);
  fireWebhooks('customers.bulk_op', { action, processed, target_count: targets.length });
  console.log(`         ★ BULK ${action.toUpperCase()} → processed=${processed}/${targets.length}`);
  res.json({ ok: true, processed, requested: ids.length, in_scope: targets.length });
});

// Webhook signature debugger — admin pastes payload + secret, gets the expected HMAC
app.post('/admin/api/webhook-sig-test', adminAuth, (req, res) => {
  const payload = String(req.body.payload || '');
  const secret = String(req.body.secret || '');
  if (!payload || !secret) return res.status(400).json({ error: 'payload and secret required' });
  const sig = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  res.json({
    expected_signature: 'sha256=' + sig,
    note: 'Compare with the X-MES-Signature header of the incoming webhook. They must match.',
  });
});

// Send test email to a customer (admin)
app.post('/admin/api/email-test', adminAuth, (req, res) => {
  const c = state.customers[req.body.customer_id];
  if (!c) return res.status(404).json({ error: 'customer not found' });
  if (!canAccessCustomer(req, c.id)) return res.status(403).json({ error: 'not in your scope' });
  if (!c.email) return res.status(400).json({ error: 'customer has no email' });
  if (!state.config.email_enabled) {
    return res.status(400).json({ error: 'email is disabled in config (state.config.email_enabled = false)' });
  }
  sendEmail(c.email,
    '[mes Network] Test email from your provider',
    `Hi ${c.name},\n\nThis is a test email from mes Network. If you received this, your email contact is working correctly.\n\nNo action needed.\n\nmes Network team`);
  logAdminAction(req, 'email.test', c.id, c.email);
  res.json({ ok: true, sent_to: c.email });
});

// Set customer status (approve / suspend / reactivate / delete)
app.post('/admin/api/customers/set-status', adminAuth, (req, res) => {
  const c = state.customers[req.body.id];
  if (!c) return res.status(404).json({ error: 'customer not found' });
  if (!canAccessCustomer(req, c.id)) return res.status(403).json({ error: 'not in your assigned scope' });
  const status = req.body.status;
  if (!['pending', 'active', 'suspended'].includes(status)) {
    return res.status(400).json({ error: 'invalid status' });
  }
  const was = c.status;
  c.status = status;
  saveState();

  // Notify customer (in-app + email)
  if (status === 'active' && was === 'pending') {
    pushNotification(c.id, 'success', '✅ Account approved',
      'Welcome! You can now sign in. If you have a box, plug it in — we\'ll bring it online automatically.');
    if (c.email) sendEmail(c.email, 'mes Network — account approved',
      `Hi ${c.name},\n\nYour account is now active. Sign in at ${state.config.brand_domain ? 'https://' + state.config.brand_domain : 'our app'} — your phone number is your username.\n\nmes Network team`);
  } else if (status === 'suspended') {
    pushNotification(c.id, 'warn', '⚠ Account suspended', 'Please contact support to restore service.');
    if (c.email) sendEmail(c.email, 'mes Network — account suspended',
      `Hi ${c.name},\n\nYour account has been temporarily suspended. Please reply to this email or contact support.\n\nmes Network team`);
  }

  state.events.push({ ts: Date.now(), method: 'ADMIN', path: `[STATUS] ${c.name}: ${was || '?'} → ${status}` });
  console.log(`         ★ CUSTOMER STATUS → ${c.name}: ${was} → ${status}`);
  logAdminAction(req, 'customer.set_status', c.id, `${was} → ${status}`);
  fireWebhooks('customer.status_changed', { customer: c, from: was, to: status });
  res.json({ ok: true, customer: c });
});

// Admin: send a notification to one customer or broadcast to all
app.post('/admin/api/notify', adminAuth, (req, res) => {
  const { customer_id, kind, title, body, broadcast, plan_filter, tenant_id_filter } = req.body;
  let attempted = 0, in_app = 0, push_sent = 0, push_skipped_quiet = 0, no_push_sub = 0;

  function deliverTo(c) {
    if (c.status === 'archived') return;
    if (plan_filter && c.plan !== plan_filter) return;
    if (tenant_id_filter && c.tenant_id !== tenant_id_filter) return;
    attempted++;
    const result = pushNotification(c.id, kind || 'info', title || '', body || '');
    if (result === null) push_skipped_quiet++;
    else {
      in_app++;
      const subs = (state.push_subscriptions || {})[c.id] || [];
      if (subs.length === 0) no_push_sub++;
      else push_sent += subs.length;
    }
  }

  if (broadcast) {
    for (const c of Object.values(state.customers)) {
      if (!c.demo) deliverTo(c);
    }
  } else if (customer_id) {
    if (!state.customers[customer_id]) return res.status(404).json({ error: 'customer not found' });
    deliverTo(state.customers[customer_id]);
  } else {
    return res.status(400).json({ error: 'specify customer_id or broadcast=true' });
  }
  saveState();
  // Record this campaign for later analysis
  if (!state.notification_campaigns) state.notification_campaigns = [];
  if (broadcast || plan_filter || tenant_id_filter) {
    state.notification_campaigns.unshift({
      id: 'camp-' + shortId(8),
      ts: Date.now(),
      title, body, kind,
      filters: { broadcast, plan_filter, tenant_id_filter },
      stats: { attempted, in_app, push_sent, push_skipped_quiet, no_push_sub },
      sent_by: req.adminUser || 'admin',
    });
    if (state.notification_campaigns.length > 100) state.notification_campaigns.length = 100;
    saveState();
  }
  logAdminAction(req, 'notify.bulk', broadcast ? '*' : customer_id, `attempted=${attempted} push=${push_sent}`);
  console.log(`         ★ NOTIFY → ${broadcast ? 'broadcast' : customer_id} title="${title}" attempted=${attempted} push=${push_sent}`);
  res.json({ ok: true, sent: attempted, in_app, push_sent, push_skipped_quiet, no_push_sub });
});

app.get('/admin/api/notify/campaigns', adminAuth, (req, res) => {
  res.json({ campaigns: state.notification_campaigns || [] });
});

// Assign a box (MAC) to a customer
app.post('/admin/api/customers/assign-box', adminAuth, (req, res) => {
  const mac = normalizeMac(req.body.mac || '');
  const customer_id = req.body.customer_id;
  const m = state.authorized_macs[mac];
  if (!m) return res.status(404).json({ error: 'mac not authorized — authorize it first' });
  const c = state.customers[customer_id];
  if (!c) return res.status(404).json({ error: 'customer not found' });
  m.customer_id = customer_id;
  m.customer_name = c.name;
  saveState();
  console.log(`         ★ BOX ASSIGNED → ${mac} → ${c.name}`);
  res.json({ ok: true, mac, customer: c });
});

// ─── License management admin API ───
app.get('/admin/api/macs', adminAuth, (req, res) => {
  res.json({
    authorized: Object.values(state.authorized_macs),
    issued: Object.entries(state.issued_licenses).map(([mac, lic]) => ({
      mac,
      customer: lic.DATA.CUSTOMER,
      issued_at: lic.DATA.ISSUED_AT,
      uuid: lic.DATA.UUID,
    })),
  });
});

app.post('/admin/api/macs/authorize', adminAuth, (req, res) => {
  const mac = normalizeMac(req.body.mac || '');
  if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(mac)) {
    return res.status(400).json({ error: 'invalid mac', mac });
  }
  const cid = req.body.customer_id;
  const cust = cid ? state.customers[cid] : null;
  state.authorized_macs[mac] = {
    mac,
    customer_id: cust ? cust.id : (req.body.customer_id || null),
    customer_name: cust ? cust.name : (req.body.customer_name || ''),
    type: req.body.type || 'navy',
    authorized_at: new Date().toISOString(),
    notes: req.body.notes || '',
  };
  saveState();
  console.log(`         ★ MAC AUTHORIZED → ${mac}  customer=${(cust && cust.name) || req.body.customer_name || '(none)'}`);
  logAdminAction(req, 'mac.authorize', mac, (cust && cust.name) || req.body.customer_name || '');
  fireWebhooks('mac.authorized', { mac, customer_id: cust && cust.id, customer_name: cust && cust.name, type: req.body.type });
  res.json({ ok: true, mac, ...state.authorized_macs[mac] });
});

app.post('/admin/api/macs/revoke', adminAuth, (req, res) => {
  const mac = normalizeMac(req.body.mac || '');
  if (!mac) return res.status(400).json({ error: 'mac required' });
  // Full cleanup — old endpoint only cleared auth, leaving stale box_state /
  // box_devices / box_throughput entries that re-appeared in the box list.
  delete state.authorized_macs[mac];
  delete state.issued_licenses[mac];
  delete state.box_state[mac];
  delete state.box_devices[mac];
  delete state.box_throughput[mac];
  delete state.box_commands[mac];
  delete state.box_network_modes[mac];
  if (state.box_integrity_baseline) delete state.box_integrity_baseline[mac];
  // Drop any active box session tokens for this MAC
  for (const [tok, sess] of Object.entries(state.box_sessions || {})) {
    if (sess && sess.mac === mac) delete state.box_sessions[tok];
  }
  saveState();
  console.log(`         ★ MAC REVOKED + CLEANED → ${mac}`);
  logAdminAction(req, 'mac.revoke', mac, '');
  res.json({ ok: true, mac, cleaned: true });
});

// Get the license-issued blob for a specific MAC (admin convenience)
app.get('/admin/api/license/:mac', adminAuth, (req, res) => {
  const mac = normalizeMac(req.params.mac);
  const lic = state.issued_licenses[mac];
  if (!lic) return res.status(404).json({ error: 'no license issued for this mac' });
  res.json(lic);
});

app.get('/admin/api/state', adminAuth, (req, res) => {
  const now = Date.now();
  const ONLINE_THRESHOLD_MS = 30 * 60 * 1000;  // box considered online if check-in within 30 min
  const groups = Object.values(state.groups).map(g => ({
    gid: g._id || g.gid,
    name: g.name,
    appId: g.appId,
    member_count: (g.eids instanceof Set ? g.eids.size : (g.eids || []).length),
    members: Array.from(g.eids instanceof Set ? g.eids : (g.eids || [])),
    symKey_count: (g.symmetricKeys || []).length,
    createdAt: g.createdAt,
  }));
  const endpoints = Object.entries(state.endpoints).map(([eid, e]) => ({
    eid,
    name: e.name,
    appId: e.appId,
    pubkey_present: !!e.publicKey,
    createdAt: new Date(e.createdAt).toISOString(),
  }));
  const rendezvous = Object.entries(state.rendezvous).map(([rid, r]) => ({
    rid,
    has_app_payload: !!r.appPayload,
    createdAt: new Date(r.createdAt).toISOString(),
    expiresAt: new Date(r.expiresAt).toISOString(),
  }));
  res.json({
    server: { uptime_sec: Math.round(process.uptime()), now: new Date().toISOString() },
    counts: {
      groups: groups.length,
      endpoints: endpoints.length,
      rendezvous: rendezvous.length,
      checkins_24h: state.checkins.filter(c => Date.now() - c.ts < 86400000).length,
      events_recent: state.events.slice(-100).length,
      authorized_macs: Object.keys(state.authorized_macs).length,
      issued_licenses: Object.keys(state.issued_licenses).length,
      customers: Object.keys(state.customers || {}).length,
      family_members: Object.values(state.family_members || {}).reduce((n, arr) => n + arr.length, 0),
      schedules: Object.values(state.schedules || {}).reduce((n, arr) => n + arr.length, 0),
      pending_customers: Object.values(state.customers || {}).filter(c => c.status === 'pending').length,
      notifications_unread: Object.values(state.notifications || {}).reduce((n, arr) => n + arr.filter(x => !x.read).length, 0),
    },
    customers: visibleCustomers(req),
    groups,
    endpoints,
    rendezvous,
    boxes_online: Object.values(state.authorized_macs).filter(m => m.last_seen && (now - m.last_seen < ONLINE_THRESHOLD_MS)).length,
    authorized_macs: Object.values(state.authorized_macs).map(m => ({
      ...m,
      online: !!(m.last_seen && (now - m.last_seen < ONLINE_THRESHOLD_MS)),
      last_seen_ago_min: m.last_seen ? Math.round((now - m.last_seen) / 60000) : null,
    })),
    issued_licenses: Object.entries(state.issued_licenses).map(([mac, lic]) => ({
      mac,
      customer: lic.DATA.CUSTOMER,
      issued_at: lic.DATA.ISSUED_AT,
      uuid: lic.DATA.UUID,
    })),
    recent_checkins: state.checkins.slice(-20).reverse(),
    recent_events: state.events.slice(-50).reverse(),
  });
});

// New Firewalla-MSP-style dashboard (default at /admin)
app.get('/admin', adminAuth, (req, res) => {
  try {
    const html = fs.readFileSync(path.join(__dirname, 'admin-v2.html'), 'utf8');
    res.type('html').send(html);
  } catch {
    res.type('html').send(DASHBOARD_HTML);   // fallback
  }
});
// Legacy admin (kept for full-feature access while v2 is filled out)
app.get('/admin/v1', adminAuth, (req, res) => {
  res.type('html').send(DASHBOARD_HTML);
});
app.get('/admin/v2', adminAuth, (req, res) => {
  try {
    const html = fs.readFileSync(path.join(__dirname, 'admin-v2.html'), 'utf8');
    res.type('html').send(html);
  } catch (e) {
    res.status(500).send('admin-v2 not available: ' + e.message);
  }
});

// Customer-facing portal — Firewalla MSP-style desktop dashboard (responsive on mobile)
app.get(['/portal', '/portal/'], (req, res) => {
  try {
    const html = fs.readFileSync(path.join(__dirname, 'customer-portal.html'), 'utf8');
    res.type('html').send(html);
  } catch (e) {
    res.status(500).send('portal not available: ' + e.message);
  }
});
// ════════════════════════════════════════════════════════════════════════
// TIER 2 — THREAT DETECTION DEPTH
//   A) Suricata IDS ingest (POST /api/box/ids-alerts)
//   B) DGA / beaconing detection (cloud-side analytics over flows)
//   C) Per-device CVE matching (data/device-cves.json)
//   D) Per-alarm packet capture (POST /api/box/pcap-upload/:id +
//                                GET /api/customer/alarms/:id/pcap)
// ════════════════════════════════════════════════════════════════════════

// ─── State tables (idempotent init) ──────────────────────────────────────
if (!state.suricata_alerts) state.suricata_alerts = {};     // { box_mac: { flow_id: ts } }
if (!state.beacon_tracker) state.beacon_tracker = {};       // { customer_id: { 'src_mac|dst_ip': [ts, ts, ...] } }
if (!state.dga_tracker)    state.dga_tracker    = {};       // { customer_id: { src_mac: [ts, ts, ...] } }
if (!state.device_cve_last) state.device_cve_last = {};     // { 'cid|mac|cve': ts } — 7-day dedupe

// ─── (A) Suricata EVE ingest ─────────────────────────────────────────────
// Box ships batches every 60s. We dedupe by flow_id+signature_id per box_mac,
// then fire `ids_match` alarms. Severity maps from Suricata's `alert.severity`
// (1=critical … 4=low).
function _suricataSevToString(n) {
  return ({ 1: 'critical', 2: 'high', 3: 'medium', 4: 'low' })[parseInt(n) || 3] || 'medium';
}
app.post('/api/box/ids-alerts', boxAuth, (req, res) => {
  const alerts = Array.isArray(req.body.alerts) ? req.body.alerts : [];
  const bag = state.suricata_alerts[req.boxMac] = state.suricata_alerts[req.boxMac] || {};
  // GC entries older than 24h
  const cutoff = Date.now() - 24 * 3600_000;
  for (const k of Object.keys(bag)) if (bag[k] < cutoff) delete bag[k];
  let fired = 0, deduped = 0;
  for (const ev of alerts.slice(0, 200)) {
    if (!ev || !ev.alert) continue;
    const key = `${ev.flow_id || 0}|${ev.alert.signature_id || 0}`;
    if (bag[key]) { deduped++; continue; }
    bag[key] = Date.now();
    const sev = _suricataSevToString(ev.alert.severity);
    if (req.boxCustomerId && typeof fireSyntheticAlarm === 'function') {
      fireSyntheticAlarm(req.boxCustomerId, req.boxMac, sev, 'ids_match',
        `IDS: ${ev.alert.signature || 'Suricata alert'}`,
        `Suricata flagged traffic from ${ev.src_ip || '?'} → ${ev.dst_ip || '?'} (sig ${ev.alert.signature_id || '?'}, category: ${ev.alert.category || 'n/a'}).`,
        {
          signature_id: ev.alert.signature_id,
          signature:    ev.alert.signature,
          category:     ev.alert.category,
          src_ip:       ev.src_ip || '',
          dst_ip:       ev.dst_ip || '',
        });
      fired++;
    }
  }
  res.json({ ok: true, accepted: alerts.length, fired, deduped });
});

// ─── (B) DGA detection ───────────────────────────────────────────────────
// looksLikeDGA(domain) returns a 0..1 score combining four heuristics.
// >0.8 = treat as DGA-candidate. We track per-device hits in state.dga_tracker
// and fire `dga_suspected` when a device hits >3 such domains within 1 hour.
const COMMON_BIGRAMS = new Set([
  'th','he','in','er','an','re','on','at','en','nd','ti','es','or','te','of',
  'ed','is','it','al','ar','st','to','nt','ng','se','ha','as','ou','io','le',
  've','co','me','de','hi','ri','ro','ic','ne','ea','ra','ce','li','ch','ll',
]);
function shannonEntropy(s) {
  if (!s) return 0;
  const freq = {};
  for (const c of s) freq[c] = (freq[c] || 0) + 1;
  const len = s.length;
  let h = 0;
  for (const c of Object.keys(freq)) {
    const p = freq[c] / len;
    h -= p * Math.log2(p);
  }
  return h;
}
function looksLikeDGA(domain) {
  if (!domain || typeof domain !== 'string') return 0;
  // Take the SLD only (drop TLD + subdomains). Real DGA usually targets the SLD.
  const parts = domain.toLowerCase().replace(/[^a-z0-9.\-]/g, '').split('.');
  if (parts.length < 2) return 0;
  const sld = parts[parts.length - 2];
  if (sld.length < 8) return 0;          // too short to score
  let score = 0;
  // Heuristic 1: length (>12 strong, ≥10 mild)
  if (sld.length > 12) score += 0.20;
  else if (sld.length >= 10) score += 0.10;
  // Heuristic 2: Shannon entropy. Real DGAs tend toward 3.0–4.0 bits/char.
  // 12-char strings physically can't reach 3.8 (max ≈ log2(12) ≈ 3.58),
  // so we keep tiered thresholds.
  const h = shannonEntropy(sld);
  if (h >= 3.8) score += 0.35;
  else if (h >= 3.4) score += 0.25;
  else if (h >= 3.0) score += 0.15;
  // Heuristic 3: vowel ratio — natural English ~0.38; <0.20 is suspect.
  const vowels = (sld.match(/[aeiou]/g) || []).length;
  const ratio = vowels / sld.length;
  if (ratio < 0.15)      score += 0.25;
  else if (ratio < 0.25) score += 0.15;
  // Heuristic 4: common-English bigram density (target ≤ 10% for DGAs).
  let hits = 0;
  for (let i = 0; i < sld.length - 1; i++) {
    if (COMMON_BIGRAMS.has(sld.substr(i, 2))) hits++;
  }
  const bgRatio = hits / Math.max(1, sld.length - 1);
  if (bgRatio < 0.05)      score += 0.30;
  else if (bgRatio < 0.10) score += 0.20;
  else if (bgRatio < 0.15) score += 0.10;
  // Heuristic 5: digit-mixed long string is extra suspicious.
  if (/[0-9]/.test(sld) && sld.length >= 10) score += 0.10;
  return Math.min(1, score);
}

function _trackDgaHit(customer_id, src_mac, domain) {
  if (!customer_id) return;
  const b = state.dga_tracker[customer_id] = state.dga_tracker[customer_id] || {};
  const k = (src_mac || 'unknown').toLowerCase();
  const now = Date.now();
  b[k] = (b[k] || []).filter(t => now - t < 3600_000);
  b[k].push(now);
  if (b[k].length >= 3 && typeof fireSyntheticAlarm === 'function') {
    fireSyntheticAlarm(customer_id, null, 'high', 'dga_suspected',
      `Possible DGA / malware C2 domain pattern`,
      `Device ${src_mac || 'unknown'} has resolved ${b[k].length} algorithmically-generated domains in the last hour. Latest: ${domain}. This pattern is typical of malware command-and-control beacons.`,
      { device_mac: src_mac, dst_domain: domain });
    // After firing reset the counter so we don't spam (30-min dedupe in fireSyntheticAlarm anyway)
    b[k] = [];
  }
}

function _trackBeacon(customer_id, src_mac, dst_ip, ts, bytes) {
  if (!customer_id || !src_mac || !dst_ip) return;
  const b = state.beacon_tracker[customer_id] = state.beacon_tracker[customer_id] || {};
  const k = `${src_mac.toLowerCase()}|${dst_ip}`;
  const now = ts || Date.now();
  const win = 4 * 3600_000;
  b[k] = (b[k] || []).filter(p => now - p.ts < win);
  b[k].push({ ts: now, bytes: bytes || 0 });
  if (b[k].length < 5) return;
  // Inter-arrival std dev
  const seq = b[k].slice().sort((x, y) => x.ts - y.ts);
  const deltas = [];
  for (let i = 1; i < seq.length; i++) deltas.push((seq[i].ts - seq[i-1].ts) / 1000);
  const mean = deltas.reduce((a, x) => a + x, 0) / deltas.length;
  const variance = deltas.reduce((a, x) => a + (x - mean) ** 2, 0) / deltas.length;
  const sd = Math.sqrt(variance);
  const totalBytes = seq.reduce((a, p) => a + p.bytes, 0);
  if (sd < 30 && totalBytes < 100 * 1024 && typeof fireSyntheticAlarm === 'function') {
    fireSyntheticAlarm(customer_id, null, 'high', 'c2_beacon_suspected',
      `Possible C2 beaconing detected`,
      `Device ${src_mac} reached ${dst_ip} ${seq.length} times at ~${mean.toFixed(0)}s intervals (σ=${sd.toFixed(1)}s) with only ${(totalBytes/1024).toFixed(1)} KB total — the signature of a malware beacon checking in with its C2 server.`,
      { device_mac: src_mac, dst_ip });
    b[k] = [];
  }
}

// Hook the existing flow-ingest path via setImmediate. We do NOT touch the
// POST /api/box/flows handler; instead, we listen for the post-ingest by
// monkey-patching tallyFlow (best-effort, only if it exists).
// Cleaner alternative: walk state.flows in a periodic scanner.
setInterval(function tier2FlowScanner() {
  try {
    const cutoff = Date.now() - 60_000;          // last 60s of flows
    const recent = state.flows.filter(f => f.ts >= cutoff);
    for (const f of recent) {
      if (f._t2_seen) continue;
      f._t2_seen = true;
      const cid = f.customer_id;
      if (!cid) continue;
      if (f.dst_domain) {
        const score = looksLikeDGA(f.dst_domain);
        if (score > 0.8) _trackDgaHit(cid, f.src_mac, f.dst_domain);
      }
      if (f.src_mac && f.dst_ip) {
        _trackBeacon(cid, f.src_mac, f.dst_ip, f.ts, (f.bytes_up || 0) + (f.bytes_down || 0));
      }
    }
  } catch (e) { console.error('tier2 flow scan err:', e.message); }
}, 60_000);

// ─── (C) Per-device CVE matching ────────────────────────────────────────
let DEVICE_CVES = [];
function loadDeviceCves() {
  // Prefer data/ in source tree; fallback to /data/ when running in Docker.
  const candidates = [
    path.join(__dirname, 'data', 'device-cves.json'),
    '/data/device-cves.json',
    '/app/data/device-cves.json',
  ];
  for (const p of candidates) {
    try {
      if (fs.existsSync(p)) {
        DEVICE_CVES = JSON.parse(fs.readFileSync(p, 'utf8'));
        console.log(`         🛡  Loaded ${DEVICE_CVES.length} device CVEs from ${p}`);
        return;
      }
    } catch (e) { console.error('CVE load fail:', e.message); }
  }
  console.error('         ⚠ device-cves.json not found in any candidate path');
}
loadDeviceCves();

function _matchVendorPattern(pat, vendor) {
  if (!pat || pat === '*') return true;
  if (!vendor) return false;
  // Case-insensitive substring + wildcard for now.
  if (pat.endsWith('*')) return vendor.toLowerCase().startsWith(pat.slice(0, -1).toLowerCase());
  return vendor.toLowerCase().includes(pat.toLowerCase());
}
function cvesForDevice(device) {
  if (!device || !device.vendor) return [];
  const out = [];
  for (const c of DEVICE_CVES) {
    if (!_matchVendorPattern(c.vendor_pattern, device.vendor)) continue;
    if (c.model_pattern && c.model_pattern !== '*' && device.model && !_matchVendorPattern(c.model_pattern, device.model)) continue;
    out.push(c);
  }
  return out;
}
function scanDeviceCves(customer_id, opts = {}) {
  if (!customer_id) return { scanned: 0, alarms: 0 };
  // Find all boxes for this customer, then enumerate their devices.
  const myMacs = Object.values(state.authorized_macs).filter(m => m.customer_id === customer_id);
  let scanned = 0, alarms = 0;
  const cutoff7d = Date.now() - 7 * 24 * 3600_000;
  for (const m of myMacs) {
    const bucket = state.box_devices[m.mac] || {};
    for (const d of Object.values(bucket)) {
      scanned++;
      const matches = cvesForDevice(d);
      for (const c of matches) {
        const dedup = `${customer_id}|${d.mac}|${c.cve}`;
        const last = state.device_cve_last[dedup] || 0;
        if (last > cutoff7d) continue;            // alarmed for this device+CVE in last 7d
        state.device_cve_last[dedup] = Date.now();
        const sev = (c.severity === 'critical') ? 'critical'
                  : (c.severity === 'high')     ? 'high'
                  : 'medium';
        if (typeof fireSyntheticAlarm === 'function') {
          fireSyntheticAlarm(customer_id, m.mac, sev, 'device_cve_match',
            `Vulnerable device: ${d.vendor || 'Unknown'} (${c.cve})`,
            `${c.description} — applies to device ${d.hostname || d.mac} (${d.vendor || '?'}). See nvd.nist.gov/vuln/detail/${c.cve} for remediation.`,
            { device_mac: d.mac, cve: c.cve, vendor: d.vendor || '', description: c.description });
          alarms++;
        }
      }
    }
  }
  return { scanned, alarms };
}

// Daily CVE scan per customer (staggered start to avoid thundering herd)
setTimeout(() => {
  setInterval(() => {
    for (const cid of Object.keys(state.customers || {})) {
      try { scanDeviceCves(cid); } catch (e) { console.error('cve scan err:', e.message); }
    }
  }, 24 * 3600_000);
  // First pass 2 minutes after boot
  setTimeout(() => {
    for (const cid of Object.keys(state.customers || {})) {
      try { scanDeviceCves(cid); } catch (e) { console.error('cve scan err:', e.message); }
    }
  }, 2 * 60_000);
}, 5000);

// Also scan when /api/box/devices fires (new device just appeared).
// We monkey-wrap by adding a route AFTER the original; the original already
// responded, so we just queue a scan asynchronously via setImmediate.
// Implementation note: use express middleware that runs AFTER the original
// route — done by registering an app.use for the same path that calls next()
// quietly. Simpler: schedule scan on every device-bucket update via a tick.
let _lastDevTick = 0;
setInterval(() => {
  // If state.box_devices was touched in the last 60s, rescan affected customers.
  const now = Date.now();
  for (const [mac, bucket] of Object.entries(state.box_devices || {})) {
    const mostRecent = Math.max(0, ...Object.values(bucket).map(d => d.last_seen || 0));
    if (mostRecent > _lastDevTick) {
      const m = state.authorized_macs[mac];
      if (m && m.customer_id) {
        try { scanDeviceCves(m.customer_id); } catch {}
      }
    }
  }
  _lastDevTick = now;
}, 5 * 60_000);

// Customer endpoint: list CVE matches for a specific device.
app.get('/api/customer/devices/:mac/cves', customerAuth, (req, res) => {
  const c = req.customer;
  const mac = normalizeMac(req.params.mac);
  const myMacs = Object.values(state.authorized_macs).filter(m => m.customer_id === c.id);
  let device = null;
  for (const b of myMacs) {
    const bucket = state.box_devices[b.mac] || {};
    if (bucket[mac]) { device = bucket[mac]; break; }
  }
  if (!device) return res.status(404).json({ error: 'device_not_found' });
  const matches = cvesForDevice(device).map(c => ({
    cve: c.cve,
    severity: c.severity,
    description: c.description,
    vendor_pattern: c.vendor_pattern,
    nvd_url: `https://nvd.nist.gov/vuln/detail/${c.cve}`,
  }));
  res.json({ mac, device: { mac: device.mac, vendor: device.vendor, hostname: device.hostname }, matches });
});

// ─── (D) PCAP upload + download endpoints ───────────────────────────────
const PCAP_DIR = process.env.PCAP_DIR || '/data/pcaps';
try { fs.mkdirSync(PCAP_DIR, { recursive: true }); } catch {}

// Box uploads the captured .pcap as base64 in JSON (simpler than multipart,
// keeps the existing JSON-only request pipeline working).
app.post('/api/box/pcap-upload/:alarm_id', boxAuth, express.json({ limit: '12mb' }), (req, res) => {
  const id = String(req.params.alarm_id).replace(/[^a-zA-Z0-9_-]/g, '');
  if (!id || id.length < 4) return res.status(400).json({ error: 'bad_alarm_id' });
  const b64 = String(req.body.b64 || '');
  if (!b64 || b64.length > 12 * 1024 * 1024) return res.status(400).json({ error: 'bad_payload' });
  try {
    const buf = Buffer.from(b64, 'base64');
    const out = path.join(PCAP_DIR, id + '.pcap');
    fs.writeFileSync(out, buf);
    // Bind to alarm record
    const a = state.alarms.find(x => x.id === id);
    if (a) {
      a.pcap_path = out;
      a.pcap_size = buf.length;
      a.pcap_uploaded_at = Date.now();
      if (a.customer_id && typeof customerSseEmit === 'function') {
        customerSseEmit(a.customer_id, 'alarm-update', { id: a.id, pcap_path: out, pcap_size: buf.length });
      }
    }
    res.json({ ok: true, alarm_id: id, size: buf.length, path: out, bound_to_alarm: !!a });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Customer downloads the pcap.
app.get('/api/customer/alarms/:id/pcap', customerAuth, (req, res) => {
  const id = String(req.params.id).replace(/[^a-zA-Z0-9_-]/g, '');
  const a = state.alarms.find(x => x.id === id);
  if (!a) return res.status(404).json({ error: 'alarm_not_found' });
  if (a.customer_id !== req.customer.id) return res.status(403).json({ error: 'forbidden' });
  if (!a.pcap_path || !fs.existsSync(a.pcap_path)) return res.status(404).json({ error: 'pcap_not_available' });
  res.setHeader('Content-Type', 'application/vnd.tcpdump.pcap');
  res.setHeader('Content-Disposition', `attachment; filename="alarm-${id}.pcap"`);
  res.sendFile(a.pcap_path);
});

// Trigger pcap-capture on the box when a high/critical alarm has both IPs.
// Privacy: skip if dst_domain hits financial / health / government TLDs.
const PCAP_SKIP_TLD_RE = /(^|\.)(bank|health|gov|mil)(\.|$)/i;
function maybeQueuePcapCapture(a) {
  if (!a) return;
  if (a.severity !== 'high' && a.severity !== 'critical') return;
  if (!a.box_mac) return;
  // Pull src/dst IPs from extras or top-level fields
  const src = a.src_ip || (a.extras && a.extras.src_ip) || '';
  const dst = a.dst_ip || (a.extras && a.extras.dst_ip) || '';
  if (!src || !dst) return;
  if (a.dst_domain && PCAP_SKIP_TLD_RE.test(String(a.dst_domain).toLowerCase())) {
    console.log(`         🔒 pcap skipped (sensitive TLD): ${a.dst_domain}`);
    return;
  }
  // Make sure the box is online
  const bs = state.box_state[a.box_mac];
  if (!bs || (Date.now() - bs.last_heartbeat) > 5 * 60_000) return;
  if (!state.box_commands[a.box_mac]) state.box_commands[a.box_mac] = [];
  // Don't queue twice for the same alarm
  if (state.box_commands[a.box_mac].some(c => c.action === 'pcap-capture' && c.args && c.args.alarm_id === a.id)) return;
  state.box_commands[a.box_mac].push({
    id: (typeof shortId === 'function' ? shortId(16) : ('cmd' + Math.random().toString(36).slice(2, 14))),
    action: 'pcap-capture',
    args: { alarm_id: a.id, src_ip: src, dst_ip: dst, duration_s: 8, max_packets: 100, dst_domain: a.dst_domain || '' },
    status: 'pending',
    created_at: Date.now(),
    result: null,
    completed_at: null,
  });
  if (state.box_commands[a.box_mac].length > 100) state.box_commands[a.box_mac].shift();
  console.log(`         📸 pcap queued for alarm ${a.id} (${a.severity}, ${src}→${dst})`);
}

// Customer-facing IDS status (for the PWA's Suricata sub-view)
app.get('/api/customer/ids-status', customerAuth, (req, res) => {
  const c = req.customer;
  const myMacs = Object.values(state.authorized_macs).filter(m => m.customer_id === c.id);
  const alerts = state.alarms.filter(a => a.customer_id === c.id && a.kind === 'ids_match').slice(0, 20);
  // Total alerts recorded by this customer in last 24h
  const cutoff = Date.now() - 24 * 3600_000;
  const recent = state.alarms.filter(a => a.customer_id === c.id && a.kind === 'ids_match' && a.ts >= cutoff).length;
  // Pull `state.suricata_alerts[box_mac]` size as a coarse rule-hit metric
  let hits = 0;
  for (const m of myMacs) {
    hits += Object.keys(state.suricata_alerts[m.mac] || {}).length;
  }
  res.json({
    boxes: myMacs.map(m => m.mac),
    recent_24h: recent,
    total_known: hits,
    last_20: alerts.map(a => ({
      id: a.id, ts: a.ts, severity: a.severity, title: a.title, body: a.body,
      signature_id: a.signature_id, src_ip: a.src_ip, dst_ip: a.dst_ip, category: a.category,
    })),
  });
});

// Customer-facing IDS commands (proxy to box via existing /box/action plumbing).
// We use the same pattern as /api/customer/box/action — enqueue + wait 15s.
app.post('/api/customer/ids-action', customerAuth, async (req, res) => {
  const c = req.customer;
  const action = String(req.body.action || '');
  const allowed = ['suricata-status', 'suricata-restart', 'suricata-update-rules', 'suricata-install'];
  if (!allowed.includes(action)) return res.status(400).json({ error: 'unknown_action', allowed });
  const myMacs = Object.values(state.authorized_macs).filter(m => m.customer_id === c.id);
  if (!myMacs.length) return res.status(404).json({ error: 'no_box' });
  const targetMac = myMacs[0].mac;
  const bs = state.box_state[targetMac];
  if (!bs || (Date.now() - bs.last_heartbeat) > 5 * 60_000) return res.status(503).json({ error: 'box_offline' });
  if (!state.box_commands[targetMac]) state.box_commands[targetMac] = [];
  const cmd = {
    id: (typeof shortId === 'function' ? shortId(16) : ('cmd' + Math.random().toString(36).slice(2, 14))),
    action, args: {}, status: 'pending', created_at: Date.now(), result: null, completed_at: null,
  };
  state.box_commands[targetMac].push(cmd);
  if (state.box_commands[targetMac].length > 100) state.box_commands[targetMac].shift();
  // Wait up to 30s for the box (rule-update can be slow)
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    await new Promise(r => setTimeout(r, 250));
    const c2 = (state.box_commands[targetMac] || []).find(x => x.id === cmd.id);
    if (c2 && c2.status === 'completed') return res.json({ ok: true, result: c2.result });
    if (c2 && c2.status === 'failed')    return res.json({ ok: false, error: c2.result && c2.result.error });
  }
  res.json({ ok: true, status: 'queued', mac: targetMac });
});


// Catch-all 404 — JSON for API/box paths, branded HTML for everything else
app.use((req, res) => {
  if (Math.random() < 0.05 || /^\/(api|admin|iot|bone|license|firmware|box|ddns|nic)/.test(req.path)) {
    console.log(`         ⚠ UNHANDLED: ${req.method} ${req.path}`);
  }
  // API paths get JSON
  if (/^\/(api|admin|iot|bone|license|firmware|box|ddns|nic)/.test(req.path) || (req.headers.accept || '').includes('json')) {
    return res.status(404).json({ error: 'not_found', path: req.path });
  }
  const branding = effectiveBranding(tenantForRequest(req));
  res.status(404).type('html').send(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>404 — ${branding.brand_name}</title>
<style>body{font-family:system-ui;background:#0f1419;color:#e3e9f0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;text-align:center;padding:20px;}
h1{color:${branding.brand_color};font-size:5em;margin:0;line-height:1;}
h2{color:#fff;margin:14px 0;font-weight:500;}p{color:#8aa0c0;}
a{display:inline-block;margin-top:20px;background:${branding.brand_color};color:#000;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600;}
</style></head><body><div>
<h1>404</h1>
<h2>This page doesn't exist.</h2>
<p>You might be looking for the customer portal or admin panel.</p>
<a href="/">← Home</a>
</div></body></html>`);
});

// Express 5xx error handler — branded
app.use((err, req, res, next) => {
  console.error('         🔥 ERROR:', req.method, req.path, '-', err.message);
  if ((req.headers.accept || '').includes('json') || /^\/(api|admin|iot|bone)/.test(req.path)) {
    return res.status(500).json({ error: 'server_error', message: 'something went wrong; the team has been notified' });
  }
  const branding = effectiveBranding(tenantForRequest(req));
  res.status(500).type('html').send(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Error — ${branding.brand_name}</title>
<style>body{font-family:system-ui;background:#0f1419;color:#e3e9f0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;text-align:center;padding:20px;}
h1{color:#ff5c5c;font-size:5em;margin:0;}
h2{color:#fff;margin:14px 0;font-weight:500;}
p{color:#8aa0c0;}a{display:inline-block;margin-top:20px;background:${branding.brand_color};color:#000;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600;}
</style></head><body><div>
<h1>5xx</h1><h2>Something broke on our end.</h2>
<p>Refresh the page or try again in a moment.</p>
<a href="/">← Home</a>
</div></body></html>`);
});

// ─── Dashboard HTML (single-file SPA, polls /admin/api/state) ───
const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<title>mes Cloud · Firewalla Controller</title>
<script src="/admin/qrcode.min.js"></script>
<style>
  * { box-sizing: border-box; }
  body { font-family: -apple-system, system-ui, sans-serif; margin: 0; background: #0f1419; color: #d8dee9; }
  header { background: linear-gradient(90deg, #1a2332, #0f1419); padding: 18px 24px; border-bottom: 1px solid #2a3340; display: flex; align-items: center; justify-content: space-between; }
  header h1 { margin: 0; font-size: 1.2em; color: #ff8c42; font-weight: 600; }
  header .meta { font-size: .8em; color: #6c7686; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; padding: 24px; }
  .card { background: #1a2028; border: 1px solid #2a3340; border-radius: 10px; padding: 18px; }
  .card h2 { margin: 0 0 12px 0; font-size: .85em; color: #8aa0c0; text-transform: uppercase; letter-spacing: 1px; font-weight: 500; }
  .num { font-size: 2.4em; font-weight: 700; color: #fff; line-height: 1; }
  .num.accent { color: #3ad29f; }
  .num.warn { color: #ff8c42; }
  table { width: 100%; border-collapse: collapse; font-size: .82em; }
  th { color: #6c7686; text-align: left; padding: 8px 6px; border-bottom: 1px solid #2a3340; font-weight: 500; font-size: .75em; text-transform: uppercase; }
  td { padding: 10px 6px; border-bottom: 1px solid #1f2530; vertical-align: top; }
  td.mono { font-family: 'SF Mono', Monaco, monospace; font-size: .85em; color: #a3b1c6; }
  .pill { display: inline-block; padding: 2px 9px; border-radius: 99px; font-size: .7em; background: #2a3340; }
  .pill.ok { background: #1f4f3d; color: #3ad29f; }
  .pill.warn { background: #4a3520; color: #ff8c42; }
  .full { grid-column: 1 / -1; }
  .stat-row { display: flex; gap: 12px; }
  .stat-row > div { flex: 1; }
  footer { padding: 12px 24px; color: #4a5366; font-size: .75em; border-top: 1px solid #2a3340; }
  .live-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #3ad29f; margin-right: 6px; animation: pulse 2s infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
  .empty { color: #4a5366; font-style: italic; padding: 8px 0; }
  code { background: #0f1419; padding: 1px 5px; border-radius: 3px; font-size: .85em; color: #ff8c42; }
</style>
</head><body>
<header>
  <h1>📦 mes Cloud · Firewalla Controller</h1>
  <div class="meta">
    <input id="global-search" placeholder="🔎 search customers / MACs / notes…" oninput="globalSearch()" style="background:#0f1419;border:1px solid #2a3340;color:#d8dee9;padding:5px 12px;border-radius:99px;font-size:.85em;width:240px;margin-${'inline-end'}:10px;">
    <span class="live-dot"></span><span id="ts">loading…</span> · uptime <span id="uptime">-</span>
    <span style="cursor:pointer;background:#0f1419;padding:4px 10px;border-radius:99px;border:1px solid #2a3340;margin-${'inline-start'}:10px;font-size:.75em;" onclick="toggleAdminLang()">🌐 <span id="admin-lang-label">عربي</span></span>
  </div>
</header>

<!-- Search results dropdown -->
<div id="search-results" style="display:none;position:fixed;top:60px;right:24px;width:320px;max-height:60vh;overflow-y:auto;background:#1a2028;border:1px solid #2a3340;border-radius:10px;padding:10px;z-index:50;box-shadow:0 8px 24px rgba(0,0,0,.5);"></div>

<div class="grid">
  <div class="card"><h2>Customers</h2><div class="num accent" id="cnt-customers">-</div></div>
  <div class="card"><h2>Boxes Online</h2><div class="num accent" id="cnt-online">-</div></div>
  <div class="card" id="pending-card" style="border-left:3px solid var(--warn);"><h2>Pending approvals</h2><div class="num warn" id="cnt-pending">-</div></div>
  <div class="card"><h2>Family Members</h2><div class="num accent" id="cnt-family">-</div></div>
  <div class="card"><h2>Schedules</h2><div class="num accent" id="cnt-schedules">-</div></div>
  <div class="card"><h2>Paired Boxes</h2><div class="num" id="cnt-endpoints">-</div></div>
  <div class="card"><h2>Issued Licenses</h2><div class="num" id="cnt-licensed">-</div></div>
  <div class="card"><h2>Authorized MACs</h2><div class="num" id="cnt-authorized">-</div></div>
  <div class="card"><h2>Active Groups</h2><div class="num" id="cnt-groups">-</div></div>

  <div class="card full">
    <h2>Box Fleet — live status</h2>
    <table id="boxes-fleet">
      <thead><tr><th>MAC</th><th>Customer</th><th>Online</th><th>Public IP</th><th>Version</th><th>Devices</th><th>CPU</th><th>RAM</th><th>Temp</th><th>Last seen</th></tr></thead>
      <tbody><tr><td colspan="10" class="empty">No boxes have checked in yet — install the agent: <code>curl -fsSL /box/install.sh | sudo bash -s -- --mac &lt;MAC&gt; --secret &lt;SECRET&gt;</code></td></tr></tbody>
    </table>
  </div>

  <div class="card" id="queue-health-card">
    <h2>🚦 Queue health</h2>
    <div id="qh-light" style="font-size:2em;">⚪</div>
    <div id="qh-detail" style="font-size:.78em;color:#aab2c0;margin-top:6px;">loading…</div>
  </div>

  <div class="card full">
    <h2>📈 Business intel</h2>
    <div id="biz-intel" style="display:grid;grid-template-columns:repeat(auto-fit, minmax(180px, 1fr));gap:14px;">
      <div style="padding:14px;background:#0f1419;border-radius:8px;"><div style="color:#8aa0c0;font-size:.75em;text-transform:uppercase;">MRR</div><div class="num accent" id="bi-mrr">-</div><div style="color:#6c7686;font-size:.75em;" id="bi-mrr-lbp">-</div></div>
      <div style="padding:14px;background:#0f1419;border-radius:8px;"><div style="color:#8aa0c0;font-size:.75em;text-transform:uppercase;">Customers</div><div class="num" id="bi-cust">-</div></div>
      <div style="padding:14px;background:#0f1419;border-radius:8px;"><div style="color:#8aa0c0;font-size:.75em;text-transform:uppercase;">Funnel</div><div id="bi-funnel" style="font-size:.85em;color:#aab2c0;">-</div></div>
      <div style="padding:14px;background:#0f1419;border-radius:8px;"><div style="color:#8aa0c0;font-size:.75em;text-transform:uppercase;">Plan mix</div><div id="bi-plans" style="font-size:.85em;color:#aab2c0;">-</div></div>
      <div style="padding:14px;background:#0f1419;border-radius:8px;"><div style="color:#8aa0c0;font-size:.75em;text-transform:uppercase;">Weekly signups (12 wk)</div><div id="bi-signups" style="display:flex;gap:1px;align-items:flex-end;height:46px;margin-top:6px;"></div></div>
    </div>
  </div>

  <div class="card full">
    <h2>👥 Customer health (worst 5)</h2>
    <table id="health-table">
      <thead><tr><th>Customer</th><th>Plan</th><th>Score</th><th>Reasons</th></tr></thead>
      <tbody><tr><td colspan="4" class="empty">loading…</td></tr></tbody>
    </table>
    <div id="health-buckets" style="margin-top:8px;color:#aab2c0;font-size:.85em;"></div>
  </div>

  <div class="card">
    <h2>🎁 Top referrers</h2>
    <div id="ref-list" style="font-size:.85em;color:#aab2c0;">loading…</div>
  </div>

  <div class="card full" style="border-left:3px solid #ffb84a;">
    <h2>Pending — needs your action</h2>
    <div id="pending-queue" style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;">
      <div><h3 style="font-size:.9em;color:#8aa0c0;">📦 Hardware orders</h3><div id="q-hw-orders"><p class="empty">none</p></div></div>
      <div><h3 style="font-size:.9em;color:#8aa0c0;">⭐ Plan requests</h3><div id="q-plan-requests"><p class="empty">none</p></div></div>
      <div><h3 style="font-size:.9em;color:#8aa0c0;">📦 Pending boxes</h3><div id="q-pending-boxes"><p class="empty">none</p></div></div>
    </div>
  </div>

  <div class="card full">
    <h2>Speed-test fleet (last 7 days, ↓ Mbps avg)</h2>
    <button onclick="runFleetSpeedtest()" style="padding:6px 12px;background:#0f1419;color:#3ad29f;border:1px solid #3ad29f;border-radius:6px;cursor:pointer;font-size:.8em;margin-bottom:10px;">⚡ Run on all online boxes</button>
    <table id="speedtest-fleet-table">
      <thead><tr><th>Box MAC</th><th>Customer</th><th>Latest ↓</th><th>Latest ↑</th><th>Latest ms</th><th>7d avg ↓</th><th>7d avg ↑</th><th>Tests</th><th>Last seen</th></tr></thead>
      <tbody><tr><td colspan="9" class="empty">No speed tests recorded yet.</td></tr></tbody>
    </table>
  </div>

  <div class="card full">
    <h2>Recent alarms</h2>
    <table id="alarms-table">
      <thead><tr><th>Time</th><th>Severity</th><th>Customer</th><th>Box</th><th>Kind</th><th>Title</th></tr></thead>
      <tbody><tr><td colspan="6" class="empty">No alarms.</td></tr></tbody>
    </table>
  </div>

  <div class="card">
    <h2>Threat intel feed</h2>
    <div id="threat-feed-stat">
      <div class="num accent" id="tf-count">-</div>
      <div style="font-size:.8em;color:#6c7686;margin-top:6px;" id="tf-meta">loading…</div>
      <button onclick="refreshThreatFeed()" style="margin-top:8px;padding:6px 12px;background:#0f1419;color:#3ad29f;border:1px solid #3ad29f;border-radius:6px;cursor:pointer;font-size:.8em;">Refresh now</button>
    </div>
  </div>

  <div class="card full">
    <h2>Customers</h2>
    <input id="cust-search" placeholder="🔎 Search by name, phone, email, or status..." oninput="refresh()" style="width:100%;padding:10px 14px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:8px;font-size:.95em;margin-bottom:14px;">
    <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;">
      <input id="cust-name" placeholder="Customer name *" style="flex:2;min-width:160px;padding:8px 10px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:6px;">
      <input id="cust-phone" placeholder="Phone (e.g. +961 ...)" style="flex:1;min-width:140px;padding:8px 10px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:6px;">
      <input id="cust-email" placeholder="Email (optional)" style="flex:2;min-width:160px;padding:8px 10px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:6px;">
      <select id="cust-plan" style="padding:8px 10px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:6px;">
        <option value="basic">Basic</option><option value="family">Family</option><option value="pro">Pro</option><option value="business">Business</option>
      </select>
      <button id="cust-create-btn" style="padding:8px 16px;background:#3ad29f;color:#000;border:none;border-radius:6px;cursor:pointer;font-weight:600;">Add Customer</button>
    </div>
    <table id="customers">
      <thead><tr><th>Name</th><th>Phone</th><th>Plan</th><th>Status</th><th>Boxes</th><th>Created</th><th>Actions</th></tr></thead>
      <tbody></tbody>
    </table>
  </div>

  <div class="card full">
    <h2>Broadcast notification</h2>
    <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;">
      <input id="notif-title" placeholder="Title (e.g. Maintenance window)" style="flex:2;min-width:160px;padding:8px 10px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:6px;">
      <input id="notif-body" placeholder="Message body" style="flex:3;min-width:200px;padding:8px 10px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:6px;">
      <select id="notif-kind" style="padding:8px 10px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:6px;">
        <option value="info">Info</option><option value="success">Success</option><option value="warn">Warn</option><option value="system">System</option>
      </select>
      <button onclick="broadcastNotif()" style="padding:8px 16px;background:#3ad29f;color:#000;border:none;border-radius:6px;cursor:pointer;font-weight:600;">Send to all active customers</button>
    </div>
  </div>

  <div class="card full">
    <h2>License Management — Authorized MACs</h2>
    <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;">
      <input id="new-mac" placeholder="MAC (e.g. 20:6d:31:11:15:f8) *" style="flex:2;min-width:180px;padding:8px 10px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:6px;font-family:monospace;">
      <select id="new-cust-id" style="flex:2;min-width:180px;padding:8px 10px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:6px;">
        <option value="">— assign to customer (optional) —</option>
      </select>
      <select id="new-type" style="padding:8px 10px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:6px;">
        <option>navy</option><option>purple</option><option>gold</option><option>custom</option>
      </select>
      <button id="auth-btn" style="padding:8px 16px;background:#3ad29f;color:#000;border:none;border-radius:6px;cursor:pointer;font-weight:600;">Authorize</button>
    </div>
    <table id="macs">
      <thead><tr><th>MAC</th><th>Customer</th><th>Type</th><th>Status</th><th>Authorized</th><th>License Issued</th><th></th></tr></thead>
      <tbody></tbody>
    </table>
  </div>

  <div class="card full">
    <h2>Support — customer chat threads</h2>
    <div id="support-threads" style="margin-bottom:12px;"></div>
  </div>

  <div class="card full">
    <h2>System metrics</h2>
    <div id="sys-metrics" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;font-size:.85em;color:#8aa0c0;"></div>
  </div>

  <div class="card full">
    <h2>Invoices</h2>
    <div style="margin-bottom:12px;display:flex;gap:8px;flex-wrap:wrap;">
      <input id="inv-period" placeholder="YYYY-MM (default: this month)" style="flex:1;min-width:180px;padding:8px 10px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:6px;font-family:monospace;">
      <button onclick="generateInvoices()" style="padding:8px 16px;background:#3ad29f;color:#000;border:none;border-radius:6px;cursor:pointer;font-weight:600;">Generate for all active customers</button>
    </div>
    <div id="invoices-admin"></div>
  </div>

  <div class="card full">
    <h2>OTA firmware</h2>
    <p style="color:#8aa0c0;font-size:.85em;margin:0 0 10px 0;">Upload a binary, automatically signed with your Ed25519 key. Boxes verify the signature before installing. Public download endpoint: <code>/firmware/download/&lt;model&gt;/&lt;version&gt;</code>.</p>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;">
      <input id="fw-version" placeholder="version (e.g. 1.2.3)" style="flex:1;min-width:120px;padding:8px 10px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:6px;">
      <select id="fw-model" style="padding:8px 10px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:6px;">
        <option value="navy">navy</option><option value="purple">purple</option><option value="gold">gold</option><option value="custom">custom</option>
      </select>
      <input id="fw-notes" placeholder="release notes" style="flex:2;min-width:160px;padding:8px 10px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:6px;">
      <input type="file" id="fw-file" accept="*/*">
      <button onclick="uploadFirmware()" style="padding:8px 16px;background:#3ad29f;color:#000;border:none;border-radius:6px;cursor:pointer;font-weight:600;">Upload</button>
    </div>
    <div id="firmwares-list"></div>
  </div>

  <div class="card full">
    <h2>30-day trends</h2>
    <div id="trends-grid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;"></div>
  </div>

  <div class="card full">
    <h2>Customer invitations</h2>
    <p style="color:#8aa0c0;margin:0 0 12px 0;font-size:.85em;">Pre-create a customer account and send them a clickable link. They claim it once and are auto-signed-in.</p>
    <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;">
      <input id="inv-name" placeholder="Customer name" style="flex:2;min-width:140px;padding:8px 10px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:6px;">
      <input id="inv-phone" placeholder="+961 7X XXX XXX" style="flex:2;min-width:140px;padding:8px 10px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:6px;">
      <input id="inv-email" placeholder="email (optional, sends invite)" style="flex:2;min-width:140px;padding:8px 10px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:6px;">
      <select id="inv-plan" style="padding:8px 10px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:6px;">
        <option value="basic">basic</option><option value="family">family</option><option value="pro">pro</option><option value="business">business</option>
      </select>
      <button onclick="createInvite()" style="padding:8px 16px;background:#3ad29f;color:#000;border:none;border-radius:6px;cursor:pointer;font-weight:600;">Generate invite</button>
    </div>
    <div id="invite-result" style="margin-top:8px;"></div>
  </div>

  <div class="card full">
    <h2>Branding</h2>
    <p style="color:#8aa0c0;font-size:.85em;margin:0 0 12px 0;">Visible to customers in the PWA + status page.</p>
    <div id="brand-form" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;margin-bottom:10px;"></div>
    <button onclick="saveBranding()" style="padding:8px 16px;background:#3ad29f;color:#000;border:none;border-radius:6px;cursor:pointer;font-weight:600;">Save branding</button>
  </div>

  <div class="card full">
    <h2>2FA — your own account</h2>
    <p style="color:#8aa0c0;margin:0 0 12px 0;font-size:.85em;">Add Google Authenticator-style 2-factor auth to your admin login. After enabling, send <code>X-Admin-OTP</code> header on every request.</p>
    <div id="my2fa-state"></div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;">
      <button onclick="setup2FA()" style="padding:8px 16px;background:#3ad29f;color:#000;border:none;border-radius:6px;cursor:pointer;font-weight:600;">Setup 2FA</button>
      <button onclick="disable2FA()" style="padding:8px 16px;background:#4a3520;color:#ff8c42;border:1px solid #ff8c42;border-radius:6px;cursor:pointer;">Disable 2FA</button>
    </div>
    <div id="2fa-output" style="margin-top:14px;"></div>
  </div>

  <div class="card full">
    <h2>Bulk customer import</h2>
    <p style="color:#8aa0c0;margin:0 0 12px 0;font-size:.85em;">Upload a CSV with columns <code>name,phone</code> (required) plus optional <code>email,plan,address,status</code>. Existing phones are skipped.</p>
    <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
      <input type="file" id="bulk-csv" accept=".csv,text/csv">
      <button onclick="bulkImport()" style="padding:10px 18px;background:#3ad29f;color:#000;border:none;border-radius:6px;cursor:pointer;font-weight:600;">Import</button>
      <a href="data:text/csv;charset=utf-8,name,phone,email,plan,address%0AAhmad%20Demo,%2B961%2071%200000%2001,demo%40example.com,family,Beirut" download="sample.csv" style="font-size:.85em;color:#3ad29f;">📋 sample.csv</a>
    </div>
    <div id="bulk-result" style="margin-top:12px;"></div>
  </div>

  <div class="card full">
    <h2>Admin users</h2>
    <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;">
      <input id="adm-user" placeholder="username" style="flex:1;min-width:120px;padding:8px 10px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:6px;font-family:monospace;">
      <input id="adm-name" placeholder="display name" style="flex:1;min-width:120px;padding:8px 10px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:6px;">
      <input id="adm-pwd" type="password" placeholder="password" style="flex:1;min-width:120px;padding:8px 10px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:6px;">
      <select id="adm-role" style="padding:8px 10px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:6px;">
        <option value="admin">admin</option><option value="support">support</option><option value="readonly">readonly</option>
      </select>
      <button onclick="addAdmin()" style="padding:8px 16px;background:#3ad29f;color:#000;border:none;border-radius:6px;cursor:pointer;font-weight:600;">Add admin</button>
    </div>
    <div id="admins-list"></div>
  </div>

  <div class="card full">
    <h2>API keys</h2>
    <p style="color:#8aa0c0;font-size:.85em;margin:0 0 12px 0;">Use <code>X-API-Key: &lt;key&gt;</code> header instead of Basic auth. For automation, CRMs, billing systems.</p>
    <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;">
      <input id="apikey-name" placeholder="name (e.g. Billing CRM)" style="flex:2;min-width:160px;padding:8px 10px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:6px;">
      <select id="apikey-role" style="padding:8px 10px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:6px;">
        <option value="readonly">readonly</option><option value="admin" selected>admin</option><option value="super">super</option>
      </select>
      <button onclick="createApiKey()" style="padding:8px 16px;background:#3ad29f;color:#000;border:none;border-radius:6px;cursor:pointer;font-weight:600;">Create</button>
    </div>
    <div id="apikeys-list"></div>
  </div>

  <div class="card full">
    <h2>Webhook signature debugger</h2>
    <p style="color:#8aa0c0;font-size:.85em;margin:0 0 12px 0;">Verify that your endpoint computes the same HMAC. Paste a payload (the raw body the webhook would POST) and the webhook's secret.</p>
    <textarea id="sig-payload" placeholder='{"event":"customer.signup","ts":1234567890,"payload":{...}}' rows="3" style="width:100%;padding:8px 10px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:6px;font-family:monospace;margin-bottom:8px;"></textarea>
    <div style="display:flex;gap:8px;flex-wrap:wrap;">
      <input id="sig-secret" placeholder="webhook secret (hex)" style="flex:2;min-width:200px;padding:8px 10px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:6px;font-family:monospace;">
      <button onclick="testSig()" style="padding:8px 16px;background:#3ad29f;color:#000;border:none;border-radius:6px;cursor:pointer;font-weight:600;">Compute</button>
    </div>
    <div id="sig-result" style="margin-top:10px;font-family:monospace;font-size:.85em;"></div>
  </div>

  <div class="card full">
    <h2>Webhooks</h2>
    <p style="color:#8aa0c0;margin:0 0 10px 0;font-size:.85em;">POSTs to your URL on customer events. Body signed with HMAC-SHA256 in <code>X-MES-Signature</code>.</p>
    <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;">
      <input id="hook-name" placeholder="name (e.g. Billing webhook)" style="flex:1;min-width:140px;padding:8px 10px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:6px;">
      <input id="hook-url" placeholder="https://your-billing-system/webhook" style="flex:2;min-width:200px;padding:8px 10px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:6px;">
      <input id="hook-events" placeholder="* (or customer.signup,license.issued)" style="flex:1;min-width:140px;padding:8px 10px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:6px;">
      <button onclick="addWebhook()" style="padding:8px 16px;background:#3ad29f;color:#000;border:none;border-radius:6px;cursor:pointer;font-weight:600;">Add</button>
    </div>
    <div id="webhooks-list"></div>
  </div>

  <div class="card full">
    <h2>Webhook delivery queue</h2>
    <p style="color:#8aa0c0;font-size:.85em;margin:0 0 12px 0;">Pending + retrying webhook deliveries. Successful deliveries are removed; failures retry with backoff (0s, 30s, 2m, 10m, 1h) then give up.</p>
    <div id="webhook-queue-list"></div>
  </div>

  <div class="card full">
    <h2>Admin audit log</h2>
    <div style="display:flex;gap:8px;margin-bottom:10px;flex-wrap:wrap;">
      <input id="audit-search" placeholder="🔎 Search action / target / details..." oninput="loadAudit()" style="flex:2;min-width:200px;padding:8px 12px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:6px;font-size:.9em;">
      <select id="audit-admin-filter" onchange="loadAudit()" style="padding:8px 12px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:6px;font-size:.9em;">
        <option value="">All admins</option>
      </select>
      <select id="audit-action-filter" onchange="loadAudit()" style="padding:8px 12px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:6px;font-size:.9em;">
        <option value="">All actions</option>
      </select>
      <select id="audit-time-filter" onchange="loadAudit()" style="padding:8px 12px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:6px;font-size:.9em;">
        <option value="">All time</option>
        <option value="1h">Last 1h</option>
        <option value="24h" selected>Last 24h</option>
        <option value="7d">Last 7 days</option>
        <option value="30d">Last 30 days</option>
      </select>
    </div>
    <div id="audit-list" style="max-height:480px;overflow-y:auto;"></div>
  </div>

  <div class="card full" style="border-left:3px solid #ff5c5c;">
    <h2 style="color:#ff5c5c;">Danger zone</h2>
    <p style="color:#8aa0c0;font-size:.85em;margin:0 0 12px 0;">Super-admin only. Both actions are reversible only via backup.</p>
    <div style="display:flex;gap:10px;flex-wrap:wrap;">
      <button onclick="seedDemo()" style="padding:8px 16px;background:#1f3a5e;color:#5a8cdc;border:1px solid #5a8cdc;border-radius:6px;cursor:pointer;">🌱 Seed demo customers</button>
      <button onclick="resetState()" style="padding:8px 16px;background:#4a2020;color:#ff5c5c;border:1px solid #ff5c5c;border-radius:6px;cursor:pointer;">🗑 Reset state (keep admins+keys)</button>
    </div>
  </div>

  <div class="card full">
    <h2>Backup &amp; restore</h2>
    <p style="color:#8aa0c0;margin:0 0 12px 0;font-size:.85em;">Daily auto-backup runs to /var/backups (retains 14 days). You can also download / upload a backup manually.</p>
    <div style="display:flex;gap:10px;flex-wrap:wrap;">
      <button onclick="downloadBackup()" style="padding:10px 18px;background:#3ad29f;color:#000;border:none;border-radius:6px;cursor:pointer;font-weight:600;">💾 Download backup</button>
      <input type="file" id="restore-file" accept=".json" onchange="restoreBackup(this)" style="display:none;">
      <button onclick="document.getElementById('restore-file').click()" style="padding:10px 18px;background:#4a3520;color:#ff8c42;border:1px solid #ff8c42;border-radius:6px;cursor:pointer;">⬆ Restore from backup</button>
    </div>
  </div>

  <div class="card full">
    <h2>Exports</h2>
    <p style="color:#8aa0c0;margin:0 0 12px 0;font-size:.85em;">Download CSV files for billing/CRM imports.</p>
    <div style="display:flex;gap:10px;flex-wrap:wrap;">
      <button onclick="dlCsv('customers.csv')" style="padding:8px 16px;background:#2a3340;color:#d8dee9;border:1px solid #3ad29f;border-radius:6px;cursor:pointer;">📋 customers.csv</button>
      <button onclick="dlCsv('events.csv')" style="padding:8px 16px;background:#2a3340;color:#d8dee9;border:1px solid #3ad29f;border-radius:6px;cursor:pointer;">📋 events.csv (last 1000)</button>
      <button onclick="dlCsv('licenses.csv')" style="padding:8px 16px;background:#2a3340;color:#d8dee9;border:1px solid #3ad29f;border-radius:6px;cursor:pointer;">📋 licenses.csv</button>
    </div>
  </div>

  <div class="card full">
    <h2>Paired endpoints (eptLogins)</h2>
    <table id="endpoints">
      <thead><tr><th>EID</th><th>Name</th><th>App ID</th><th>RSA pubkey</th><th>Logged in</th></tr></thead>
      <tbody></tbody>
    </table>
  </div>

  <div class="card full">
    <h2>Groups</h2>
    <table id="groups">
      <thead><tr><th>GID</th><th>Name</th><th>App ID</th><th>Members</th><th>Sym Keys</th><th>Created</th></tr></thead>
      <tbody></tbody>
    </table>
  </div>

  <div class="card">
    <h2>Recent rendezvous</h2>
    <table id="rendezvous">
      <thead><tr><th>RID</th><th>App posted</th><th>Created</th></tr></thead>
      <tbody></tbody>
    </table>
  </div>

  <div class="card">
    <h2>Recent check-ins</h2>
    <table id="checkins">
      <thead><tr><th>MAC</th><th>When</th></tr></thead>
      <tbody></tbody>
    </table>
  </div>

  <div class="card full">
    <h2>Live request stream (most recent first)</h2>
    <div style="margin-bottom:12px;display:flex;gap:6px;flex-wrap:wrap;">
      <button class="filt active" data-filter="all" onclick="setFilter('all')" style="padding:4px 10px;background:#3ad29f;color:#000;border:none;border-radius:4px;cursor:pointer;font-size:.8em;">All</button>
      <button class="filt" data-filter="CUSTOMER" onclick="setFilter('CUSTOMER')" style="padding:4px 10px;background:#2a3340;color:#d8dee9;border:none;border-radius:4px;cursor:pointer;font-size:.8em;">Customer actions</button>
      <button class="filt" data-filter="ADMIN" onclick="setFilter('ADMIN')" style="padding:4px 10px;background:#2a3340;color:#d8dee9;border:none;border-radius:4px;cursor:pointer;font-size:.8em;">Admin actions</button>
      <button class="filt" data-filter="GET" onclick="setFilter('GET')" style="padding:4px 10px;background:#2a3340;color:#d8dee9;border:none;border-radius:4px;cursor:pointer;font-size:.8em;">Box GETs</button>
      <button class="filt" data-filter="POST" onclick="setFilter('POST')" style="padding:4px 10px;background:#2a3340;color:#d8dee9;border:none;border-radius:4px;cursor:pointer;font-size:.8em;">Box POSTs</button>
    </div>
    <table id="events">
      <thead><tr><th>Time</th><th>Method</th><th>Path</th><th>From</th></tr></thead>
      <tbody></tbody>
    </table>
  </div>
</div>

<footer>Auto-refresh every 3 seconds · auth: <code>admin / \${ADMIN_PASSWORD env var}</code> · API: <code>/admin/api/state</code></footer>

<script>
// Admin i18n
const ADMIN_I18N = {
  en: {
    'Paired Boxes':'Paired Boxes','Authorized MACs':'Authorized MACs','Issued Licenses':'Issued Licenses',
    'Active Groups':'Active Groups','Open Rendezvous':'Open Rendezvous','Check-ins (24h)':'Check-ins (24h)',
    'Customers':'Customers','Pending approvals':'Pending approvals','Family Members':'Family Members',
    'Schedules':'Schedules','License Management — Authorized MACs':'License Management — Authorized MACs',
    'Paired endpoints (eptLogins)':'Paired endpoints (eptLogins)','Groups':'Groups',
    'Recent rendezvous':'Recent rendezvous','Recent check-ins':'Recent check-ins',
    'Live request stream (most recent first)':'Live request stream (most recent first)',
    'Broadcast notification':'Broadcast notification','MAC':'MAC','Customer':'Customer','Type':'Type',
    'Authorized':'Authorized','License Issued':'License Issued','Name':'Name','Phone':'Phone','Plan':'Plan',
    'Status':'Status','Boxes':'Boxes','Created':'Created','Actions':'Actions',
  },
  ar: {
    'Paired Boxes':'الأجهزة المربوطة','Authorized MACs':'MACs مصرّحة','Issued Licenses':'الرخص الممنوحة',
    'Active Groups':'المجموعات النشطة','Open Rendezvous':'نقاط الالتقاء','Check-ins (24h)':'تسجيلات (٢٤س)',
    'Customers':'الزبائن','Pending approvals':'بانتظار الموافقة','Family Members':'أفراد العائلة',
    'Schedules':'الجداول','License Management — Authorized MACs':'إدارة الرخص — MACs المصرّحة',
    'Paired endpoints (eptLogins)':'النقاط المسجّلة','Groups':'المجموعات',
    'Recent rendezvous':'نقاط التقاء حديثة','Recent check-ins':'تسجيلات حديثة',
    'Live request stream (most recent first)':'تيار الطلبات المباشر','Broadcast notification':'إشعار جماعي',
    'MAC':'العنوان','Customer':'الزبون','Type':'النوع','Authorized':'تاريخ التصريح','License Issued':'رخصة',
    'Name':'الاسم','Phone':'الهاتف','Plan':'الباقة','Status':'الحالة','Boxes':'الأجهزة',
    'Created':'تاريخ الإنشاء','Actions':'إجراءات',
    'Boxes Online':'الأجهزة المتصلة','Box Fleet — live status':'الأجهزة — الحالة المباشرة',
    'Recent alarms':'إنذارات حديثة','Threat intel feed':'مصدر معلومات التهديدات',
    'Speed-test fleet (last 7 days, ↓ Mbps avg)':'نتائج اختبارات السرعة (آخر 7 أيام، متوسط ↓)',
    'Admin audit log':'سجل المسؤولين','Box MAC':'MAC الجهاز',
    'Time':'الوقت','Severity':'الخطورة','Box':'الجهاز','Kind':'النوع','Title':'العنوان',
    'Latest ↓':'آخر ↓','Latest ↑':'آخر ↑','Latest ms':'آخر ms','7d avg ↓':'متوسط 7 أيام ↓',
    '7d avg ↑':'متوسط 7 أيام ↑','Tests':'اختبارات','Last seen':'آخر ظهور','Online':'متصل',
    'Public IP':'IP العام','Version':'النسخة','Devices':'الأجهزة','CPU':'المعالج','RAM':'الذاكرة','Temp':'الحرارة',
    'Email':'البريد','Address':'العنوان','Notes':'ملاحظات','Add Customer':'إضافة زبون',
    'Send to all active customers':'إرسال لكل الزبائن','Edit':'تعديل','Delete':'حذف','Save':'حفظ',
    'Cancel':'إلغاء','Refresh':'تحديث','Run on all online boxes':'تشغيل على كل الأجهزة المتصلة',
    'Refresh now':'حدّث الآن','Generate for all active customers':'إنشاء فواتير الجميع',
    'Brand name':'اسم العلامة','Brand color':'لون العلامة','Accent color':'اللون الثانوي',
    'Logo URL (https://…)':'رابط الشعار','Support phone':'رقم الدعم','Brand domain':'النطاق',
    'Admin email':'بريد المسؤول',
  },
};
let adminLang = localStorage.getItem('adminLang') || 'en';
function applyAdminLang() {
  document.body.dir = adminLang === 'ar' ? 'rtl' : 'ltr';
  document.documentElement.lang = adminLang;
  // Translate headers (h1, h2, h3), table headers, buttons, labels
  document.querySelectorAll('h1, h2, h3, th, button, label, .pill').forEach(el => {
    // Skip elements with children (would clobber HTML); only pure-text leaves
    if (el.children.length > 0 && el.tagName !== 'BUTTON') return;
    if (!el.dataset.orig) el.dataset.orig = el.textContent.trim();
    const t = ADMIN_I18N[adminLang][el.dataset.orig];
    if (t) el.textContent = t;
    else if (adminLang === 'en' && el.dataset.orig) el.textContent = el.dataset.orig;
  });
  const lbl = document.getElementById('admin-lang-label');
  if (lbl) lbl.textContent = adminLang === 'ar' ? 'EN' : 'عربي';
}
// Re-apply after dynamic content loads
const _origRefresh = typeof refresh === 'function' ? refresh : null;
setInterval(() => { if (adminLang !== 'en') applyAdminLang(); }, 5000);
function toggleAdminLang() { adminLang = adminLang === 'en' ? 'ar' : 'en'; localStorage.setItem('adminLang', adminLang); applyAdminLang(); }

function fmt(iso) { try { return new Date(iso).toLocaleString(); } catch { return iso; } }
function fmtSec(s) { const m=Math.floor(s/60), h=Math.floor(m/60); return h?h+'h '+(m%60)+'m':m?m+'m':s+'s'; }
function pill(t, cls) { return '<span class="pill '+(cls||'')+'">'+t+'</span>'; }
function row(cells) { return '<tr>' + cells.map(c=>'<td>'+c+'</td>').join('') + '</tr>'; }

async function refresh() {
  try {
    const r = await fetch('/admin/api/state', { credentials: 'include' });
    if (!r.ok) { document.getElementById('ts').innerText = 'auth error'; return; }
    const d = await r.json();
    document.getElementById('ts').innerText = new Date(d.server.now).toLocaleTimeString();
    document.getElementById('uptime').innerText = fmtSec(d.server.uptime_sec);
    document.getElementById('cnt-customers').innerText = d.counts.customers || 0;
    document.getElementById('cnt-online').innerText = d.boxes_online || 0;
    document.getElementById('cnt-pending').innerText = d.counts.pending_customers || 0;
    document.getElementById('cnt-family').innerText = d.counts.family_members || 0;
    document.getElementById('cnt-schedules').innerText = d.counts.schedules || 0;
    document.getElementById('cnt-endpoints').innerText = d.counts.endpoints;
    document.getElementById('cnt-authorized').innerText = d.counts.authorized_macs || 0;
    document.getElementById('cnt-licensed').innerText = d.counts.issued_licenses || 0;
    document.getElementById('cnt-groups').innerText = d.counts.groups;
    if (document.getElementById('cnt-checkins')) document.getElementById('cnt-checkins').innerText = d.counts.checkins_24h;
    document.getElementById('pending-card').style.display = (d.counts.pending_customers > 0) ? '' : 'none';

    // Customers table
    const customers = d.customers || [];
    const macsByCust = {};
    (d.authorized_macs || []).forEach(m => {
      if (m.customer_id) {
        if (!macsByCust[m.customer_id]) macsByCust[m.customer_id] = [];
        macsByCust[m.customer_id].push(m);
      }
    });
    // Apply search filter
    const q = (document.getElementById('cust-search').value || '').toLowerCase().trim();
    const filtered = q ? customers.filter(c => {
      return (c.name || '').toLowerCase().includes(q)
          || (c.phone || '').toLowerCase().includes(q)
          || (c.email || '').toLowerCase().includes(q)
          || (c.status || '').toLowerCase().includes(q)
          || (c.plan || '').toLowerCase().includes(q);
    }) : customers;
    const customersToShow = filtered;

    document.querySelector('#customers tbody').innerHTML =
      customersToShow.length ? customersToShow.map(c => {
        const boxes = macsByCust[c.id] || [];
        const status = c.status || 'active';
        const statusPill = status === 'active' ? pill('Active', 'ok')
          : status === 'pending' ? pill('Pending', 'warn')
          : pill('Suspended', '');
        const actions = [];
        if (status === 'pending') actions.push('<button onclick="setCustStatus(\\''+c.id+'\\',\\'active\\')" style="padding:4px 10px;background:#1f4f3d;color:#3ad29f;border:1px solid #3ad29f;border-radius:4px;cursor:pointer;font-size:.85em;">Approve</button>');
        if (status === 'active') actions.push('<button onclick="setCustStatus(\\''+c.id+'\\',\\'suspended\\')" style="padding:4px 10px;background:#4a3520;color:#ff8c42;border:1px solid #ff8c42;border-radius:4px;cursor:pointer;font-size:.85em;">Suspend</button>');
        if (status === 'suspended') actions.push('<button onclick="setCustStatus(\\''+c.id+'\\',\\'active\\')" style="padding:4px 10px;background:#1f4f3d;color:#3ad29f;border:1px solid #3ad29f;border-radius:4px;cursor:pointer;font-size:.85em;">Reactivate</button>');
        const notesCount = (c.staff_notes || []).length;
        const noteLabel = notesCount > 0 ? '📝 ' + notesCount : '+ Note';
        actions.push('<button onclick="impersonate(\\''+c.id+'\\')" title="View PWA as this customer (audited, 1h)" style="padding:4px 10px;background:#1f3a5e;color:#5a8cdc;border:1px solid #5a8cdc;border-radius:4px;cursor:pointer;font-size:.85em;margin-${'inline-end'}:4px;">👁</button>');
        actions.push('<button onclick="addNote(\\''+c.id+'\\')" title="' + (c.staff_notes && c.staff_notes[0] ? c.staff_notes[0].body.replace(/"/g,"&quot;").slice(0,80) : 'Add internal staff note') + '" style="padding:4px 10px;background:#1f3a5e;color:#5a8cdc;border:1px solid #5a8cdc;border-radius:4px;cursor:pointer;font-size:.85em;">'+noteLabel+'</button>');
        actions.push('<button onclick="deleteCustomer(\\''+c.id+'\\')" style="padding:4px 10px;background:#4a3520;color:#ff8c42;border:1px solid #ff8c42;border-radius:4px;cursor:pointer;font-size:.85em;">Delete</button>');
        return row([
          '<strong>' + (c.name || '-') + '</strong>' + (c.email ? '<br><span style="font-size:.75em;color:#6c7686">' + c.email + '</span>' : '') + (c.self_signup ? '<br><span class="pill" style="font-size:.65em;">self-signup</span>' : ''),
          c.phone || '<i style="color:#4a5366">-</i>',
          '<span class="pill">' + (c.plan || 'basic') + '</span>',
          statusPill,
          boxes.length ? boxes.map(m => '<span class="mono" style="font-size:.85em">' + m.mac + '</span>').join('<br>') : '<i style="color:#4a5366">no box</i>',
          fmt(c.created_at),
          actions.join(' '),
        ]);
      }).join('') : (q ? '<tr><td colspan="7" class="empty">No matches for "' + q + '"</td></tr>' : '<tr><td colspan="7" class="empty">No customers yet — add one above</td></tr>');

    // Populate the customer dropdown in MAC authorization section
    const sel = document.getElementById('new-cust-id');
    const currentSel = sel.value;
    sel.innerHTML = '<option value="">— assign to customer (optional) —</option>' +
      customers.map(c => '<option value="' + c.id + '">' + c.name + '</option>').join('');
    sel.value = currentSel;

    const issuedByMac = {};
    (d.issued_licenses || []).forEach(l => issuedByMac[l.mac] = l);
    document.querySelector('#macs tbody').innerHTML =
      (d.authorized_macs || []).length ? d.authorized_macs.map(m => {
        const statusPill = m.online
          ? pill('● online' + (m.last_seen_ago_min !== null ? ' · ' + m.last_seen_ago_min + 'm ago' : ''), 'ok')
          : (m.last_seen_ago_min !== null
              ? pill('○ offline · ' + m.last_seen_ago_min + 'm ago', '')
              : pill('never seen', ''));
        return row([
          '<span class="mono">' + m.mac + '</span>',
          m.customer_name || '<i style="color:#4a5366">(none)</i>',
          '<span class="pill">' + (m.type || 'unknown') + '</span>',
          statusPill,
          fmt(m.authorized_at),
          issuedByMac[m.mac] ? pill('YES · ' + issuedByMac[m.mac].uuid.slice(0,8) + '…', 'ok') : pill('not yet', ''),
          '<button onclick="revokeMac(\\''+m.mac+'\\')" style="padding:4px 10px;background:#4a3520;color:#ff8c42;border:1px solid #ff8c42;border-radius:4px;cursor:pointer;font-size:.85em;">Revoke</button>'
        ]);
      }).join('') : '<tr><td colspan="7" class="empty">No MACs authorized yet — add one above</td></tr>';

    document.querySelector('#endpoints tbody').innerHTML =
      d.endpoints.length ? d.endpoints.map(e => row([
        '<span class="mono">' + e.eid.slice(0, 16) + '…</span>',
        e.name || '-',
        '<span class="mono">' + (e.appId || '-') + '</span>',
        e.pubkey_present ? pill('present', 'ok') : pill('missing', 'warn'),
        fmt(e.createdAt),
      ])).join('') : '<tr><td colspan="5" class="empty">No paired boxes yet</td></tr>';

    document.querySelector('#groups tbody').innerHTML =
      d.groups.length ? d.groups.map(g => row([
        '<span class="mono">' + g.gid.slice(0, 16) + '…</span>',
        g.name || '-',
        '<span class="mono">' + (g.appId || '-') + '</span>',
        pill(g.member_count + ' member' + (g.member_count===1?'':'s'), g.member_count > 1 ? 'ok' : ''),
        g.symKey_count,
        fmt(g.createdAt),
      ])).join('') : '<tr><td colspan="6" class="empty">No groups</td></tr>';

    document.querySelector('#rendezvous tbody').innerHTML =
      d.rendezvous.length ? d.rendezvous.map(r => row([
        '<span class="mono">' + r.rid.slice(0, 12) + '…</span>',
        r.has_app_payload ? pill('YES', 'ok') : pill('waiting', ''),
        fmt(r.createdAt),
      ])).join('') : '<tr><td colspan="3" class="empty">None active</td></tr>';

    document.querySelector('#checkins tbody').innerHTML =
      d.recent_checkins.length ? d.recent_checkins.map(c => row([
        '<span class="mono">' + c.mac + '</span>',
        fmt(new Date(c.ts).toISOString()),
      ])).join('') : '<tr><td colspan="2" class="empty">No check-ins yet</td></tr>';

    let evts = d.recent_events;
    if (window.__filter && window.__filter !== 'all') {
      evts = evts.filter(e => e.method === window.__filter);
    }
    document.querySelector('#events tbody').innerHTML =
      evts.length ? evts.slice(0, 50).map(e => {
        const cls = e.method === 'CUSTOMER' ? 'ok' : e.method === 'ADMIN' ? 'warn' : '';
        return row([
          new Date(e.ts).toLocaleTimeString(),
          '<span class="pill ' + cls + '">' + e.method + '</span>',
          '<span class="mono">' + e.path + '</span>',
          '<span class="mono">' + (e.ip || '-') + '</span>',
        ]);
      }).join('') : '<tr><td colspan="4" class="empty">No requests match filter</td></tr>';
  } catch (e) {
    document.getElementById('ts').innerText = 'error: ' + e.message;
  }
}
async function authorizeMac() {
  const mac = document.getElementById('new-mac').value.trim();
  const customer_id = document.getElementById('new-cust-id').value;
  const type = document.getElementById('new-type').value;
  if (!mac) { alert('Enter a MAC'); return; }

  // Resolve customer name from selected ID (used as customer_name on the MAC record)
  let customer_name = '';
  if (customer_id) {
    const opt = document.getElementById('new-cust-id').selectedOptions[0];
    customer_name = opt ? opt.textContent : '';
  }

  const r = await fetch('/admin/api/macs/authorize', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mac, customer_name, type }),
    credentials: 'include',
  });
  if (!r.ok) { alert('Authorize failed: ' + (await r.text())); return; }

  // If a customer was selected, assign the box
  if (customer_id) {
    await fetch('/admin/api/customers/assign-box', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mac, customer_id }),
      credentials: 'include',
    });
  }
  document.getElementById('new-mac').value = '';
  document.getElementById('new-cust-id').value = '';
  refresh();
}

async function createCustomer() {
  const name = document.getElementById('cust-name').value.trim();
  if (!name) { alert('Enter a customer name'); return; }
  const r = await fetch('/admin/api/customers/create', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name,
      phone: document.getElementById('cust-phone').value.trim(),
      email: document.getElementById('cust-email').value.trim(),
      plan: document.getElementById('cust-plan').value,
    }),
    credentials: 'include',
  });
  if (r.ok) {
    document.getElementById('cust-name').value = '';
    document.getElementById('cust-phone').value = '';
    document.getElementById('cust-email').value = '';
    refresh();
  } else {
    alert('Failed: ' + (await r.text()));
  }
}

async function deleteCustomer(id) {
  if (!confirm('Delete this customer? Their boxes will be unassigned but not revoked.')) return;
  await fetch('/admin/api/customers/delete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id }),
    credentials: 'include',
  });
  refresh();
}

async function setCustStatus(id, status) {
  if (status === 'suspended' && !confirm('Suspend this customer? They won\\'t be able to sign in.')) return;
  await fetch('/admin/api/customers/set-status', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id, status }),
    credentials: 'include',
  });
  refresh();
}

// ─── Global search ───
let _searchTimer;
function globalSearch() {
  clearTimeout(_searchTimer);
  const q = document.getElementById('global-search').value.trim();
  const results = document.getElementById('search-results');
  if (q.length < 2) { results.style.display = 'none'; results.innerHTML = ''; return; }
  _searchTimer = setTimeout(async function() {
    const r = await fetch('/admin/api/search?q=' + encodeURIComponent(q), { credentials: 'include' });
    const d = await r.json();
    if (!d.results || !d.results.length) {
      results.innerHTML = '<p style="color:#6c7686;font-size:.85em;text-align:center;padding:14px;">No matches for "' + q + '"</p>';
    } else {
      results.innerHTML = d.results.map(function(x) {
        const icon = x.kind === 'customer' ? '👤' : x.kind === 'mac' ? '🔑' : x.kind === 'note' ? '📝' : '📋';
        return '<div style="padding:10px 12px;border-bottom:1px solid #1f2530;display:flex;align-items:center;gap:10px;">' +
          '<span style="font-size:1.2em;">' + icon + '</span>' +
          '<div style="flex:1;min-width:0;"><div style="font-size:.9em;color:#fff;">' + x.label + '</div>' +
          '<div style="font-size:.75em;color:#6c7686;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + (x.sub || '') + '</div></div>' +
          '<span class="pill" style="font-size:.7em;">' + x.kind + '</span></div>';
      }).join('') + (d.total > d.results.length ? '<p style="color:#6c7686;font-size:.7em;text-align:center;padding:6px;">' + d.total + ' total · showing ' + d.results.length + '</p>' : '');
    }
    results.style.display = 'block';
  }, 250);
}
document.addEventListener('click', function(e) {
  if (!e.target.closest('#search-results') && !e.target.closest('#global-search')) {
    document.getElementById('search-results').style.display = 'none';
  }
});

// ─── Branding ───
async function loadBranding() {
  try {
    const r = await fetch('/admin/api/config', { credentials: 'include' });
    const d = await r.json();
    const c = d.config;
    const fields = [
      ['brand_name', 'Brand name', 'text'],
      ['brand_color', 'Brand color', 'color'],
      ['brand_accent', 'Accent color', 'color'],
      ['brand_logo_url', 'Logo URL (https://…)', 'text'],
      ['brand_support_phone', 'Support phone', 'text'],
      ['brand_domain', 'Brand domain', 'text'],
      ['admin_email', 'Admin email', 'email'],
      ['email_from', 'Email "from"', 'email'],
    ];
    document.getElementById('brand-form').innerHTML = fields.map(function(f) {
      const k = f[0], lbl = f[1], type = f[2];
      let val = (c[k] !== undefined && c[k] !== null) ? c[k] : '';
      // <input type="color"> rejects empty/non-#rrggbb values — provide sane defaults
      if (type === 'color' && !/^#[0-9a-f]{6}$/i.test(val)) val = (k === 'brand_accent' ? '#3ad29f' : '#ff8c42');
      return '<div><label style="display:block;font-size:.75em;color:#8aa0c0;margin-bottom:4px;">' + lbl + '</label>' +
        '<input id="brand-' + k + '" type="' + type + '" value="' + (val + '').replace(/"/g, '&quot;') + '" ' +
        'style="width:100%;padding:8px 10px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:6px;' +
        (type === 'color' ? 'height:40px;' : '') + '"></div>';
    }).join('');
  } catch {}
}
async function saveBranding() {
  const fields = ['brand_name', 'brand_color', 'brand_accent', 'brand_logo_url', 'brand_support_phone', 'brand_domain', 'admin_email', 'email_from'];
  const body = {};
  for (const k of fields) {
    const el = document.getElementById('brand-' + k);
    if (el) body[k] = el.value;
  }
  const r = await fetch('/admin/api/config', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body), credentials: 'include',
  });
  alert(r.ok ? '✓ Branding saved · changes apply on next PWA load' : 'Failed');
}
setTimeout(loadBranding, 1500);

// ─── API keys ───
async function loadApiKeys() {
  try {
    const r = await fetch('/admin/api/keys', { credentials: 'include' });
    const d = await r.json();
    const el = document.getElementById('apikeys-list');
    if (!d.keys.length) { el.innerHTML = '<p style="color:#6c7686;font-size:.85em;text-align:center;padding:14px;">No API keys yet.</p>'; return; }
    el.innerHTML = '<table><thead><tr><th>Name</th><th>Role</th><th>Status</th><th>Created</th><th>Last used</th><th></th></tr></thead><tbody>' +
      d.keys.map(function(k){
        return '<tr>' +
          '<td><strong>' + k.name + '</strong><br><span style="font-size:.7em;color:#6c7686;font-family:monospace;">' + k.id + '</span></td>' +
          '<td><span class="pill">' + k.role + '</span></td>' +
          '<td>' + (k.active ? '<span class="pill ok">enabled</span>' : '<span class="pill warn">disabled</span>') + '</td>' +
          '<td style="font-size:.85em;">' + fmt(k.created_at) + '</td>' +
          '<td style="font-size:.85em;color:#8aa0c0;">' + (k.last_used_at ? fmt(new Date(k.last_used_at).toISOString()) + '<br>' + (k.last_used_ip || '') : 'never') + '</td>' +
          '<td>' +
          '<button onclick="toggleKey(\\'' + k.id + '\\')" style="padding:4px 10px;background:#2a3340;color:#d8dee9;border:1px solid #2a3340;border-radius:4px;cursor:pointer;font-size:.85em;margin-${'inline-end'}:4px;">' + (k.active ? 'Disable' : 'Enable') + '</button>' +
          '<button onclick="delKey(\\'' + k.id + '\\')" style="padding:4px 10px;background:#4a3520;color:#ff8c42;border:1px solid #ff8c42;border-radius:4px;cursor:pointer;font-size:.85em;">Delete</button>' +
          '</td></tr>';
      }).join('') + '</tbody></table>';
  } catch {}
}
async function createApiKey() {
  const name = document.getElementById('apikey-name').value.trim();
  const role = document.getElementById('apikey-role').value;
  if (!name) { alert('Name required'); return; }
  const r = await fetch('/admin/api/keys/create', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, role, scopes: ['*'] }), credentials: 'include',
  });
  const d = await r.json();
  if (!r.ok) { alert('Failed: ' + (d.error || r.status)); return; }
  // Show the key ONCE
  prompt('🔑 Save this API key NOW. It will not be shown again.\\n\\nUse with: X-API-Key: <key>\\n\\n', d.key);
  document.getElementById('apikey-name').value = '';
  loadApiKeys();
}
async function toggleKey(id) {
  await fetch('/admin/api/keys/toggle', { method:'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id }), credentials:'include' });
  loadApiKeys();
}
async function delKey(id) {
  if (!confirm('Delete this API key? Any system using it will break immediately.')) return;
  await fetch('/admin/api/keys/delete', { method:'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id }), credentials:'include' });
  loadApiKeys();
}
setInterval(loadApiKeys, 15000); setTimeout(loadApiKeys, 1800);

// ─── Webhook queue display ───
async function loadWebhookQueue() {
  try {
    const r = await fetch('/admin/api/webhook-queue', { credentials: 'include' });
    const d = await r.json();
    const el = document.getElementById('webhook-queue-list');
    if (!d.items.length) { el.innerHTML = '<p style="color:#6c7686;font-size:.85em;text-align:center;padding:14px;">Queue empty (all deliveries succeeded or gave up).</p>'; return; }
    el.innerHTML = '<table><thead><tr><th>Event</th><th>URL</th><th>Attempts</th><th>Next retry</th><th>Last error</th></tr></thead><tbody>' +
      d.items.map(function(i){
        return '<tr>' +
          '<td><span class="pill">' + i.event + '</span></td>' +
          '<td style="font-family:monospace;font-size:.8em;color:#8aa0c0;">' + i.url + '</td>' +
          '<td>' + i.attempts + '</td>' +
          '<td>' + (i.next_in_sec > 0 ? 'in ' + i.next_in_sec + 's' : 'now') + '</td>' +
          '<td style="font-size:.85em;color:#ff5c5c;">' + (i.last_error || '-') + '</td>' +
          '</tr>';
      }).join('') + '</tbody></table>' + '<p style="color:#6c7686;font-size:.75em;margin-top:8px;">Total queued: ' + d.queued + '</p>';
  } catch {}
}
setInterval(loadWebhookQueue, 5000); setTimeout(loadWebhookQueue, 2200);

// ─── Customer impersonation ───
async function impersonate(cid) {
  if (!confirm('Open a 1-hour customer session as this user?\\n\\nThe customer will be notified that you accessed their account.')) return;
  const r = await fetch('/admin/api/customers/impersonate', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id: cid }), credentials: 'include',
  });
  const d = await r.json();
  if (!r.ok) { alert('Failed: ' + (d.error || r.status)); return; }
  // Open the PWA with the impersonate token in a new tab
  window.open(d.url, '_blank');
}

async function generateInvoices() {
  const period = document.getElementById('inv-period').value.trim();
  if (!confirm('Generate invoices for ' + (period || 'this month') + '?')) return;
  const r = await fetch('/admin/api/invoices/generate-month', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ period }), credentials: 'include',
  });
  const d = await r.json();
  alert(r.ok ? ('Created ' + d.created + ' new invoices · skipped ' + d.existed + ' (already existed)') : ('Failed: ' + (d.error || r.status)));
  loadInvoicesAdmin();
}

async function loadInvoicesAdmin() {
  try {
    const r = await fetch('/admin/api/invoices', { credentials: 'include' });
    const d = await r.json();
    const el = document.getElementById('invoices-admin');
    if (!d.invoices.length) { el.innerHTML = '<p style="color:#6c7686;font-size:.85em;text-align:center;padding:14px;">No invoices yet — click "Generate" above.</p>'; return; }
    el.innerHTML = '<table><thead><tr><th>Period</th><th>Customer</th><th>Plan</th><th>Amount</th><th>Status</th><th></th></tr></thead><tbody>' +
      d.invoices.slice(0, 30).map(function(inv){
        return '<tr>' +
          '<td><span class="mono">' + inv.period + '</span></td>' +
          '<td>' + (inv.customer_name || '-') + '</td>' +
          '<td><span class="pill">' + inv.plan + '</span></td>' +
          '<td><strong>' + inv.currency + ' ' + inv.amount.toFixed(2) + '</strong></td>' +
          '<td>' + (inv.status === 'paid' ? '<span class="pill ok">paid</span>' : '<span class="pill warn">unpaid</span>') + '</td>' +
          '<td>' + (inv.status === 'paid'
            ? '<button onclick="markInvoice(\\'' + inv.id + '\\',\\'unpaid\\')" style="padding:4px 10px;background:#4a3520;color:#ff8c42;border:1px solid #ff8c42;border-radius:4px;cursor:pointer;font-size:.85em;">Unmark</button>'
            : '<button onclick="markInvoice(\\'' + inv.id + '\\',\\'paid\\')" style="padding:4px 10px;background:#1f4f3d;color:#3ad29f;border:1px solid #3ad29f;border-radius:4px;cursor:pointer;font-size:.85em;">Mark paid</button>') + '</td>' +
          '</tr>';
      }).join('') + '</tbody></table>';
  } catch {}
}
async function markInvoice(id, status) {
  await fetch('/admin/api/invoices/mark', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id, status }), credentials: 'include',
  });
  loadInvoicesAdmin();
}
setInterval(loadInvoicesAdmin, 15000);
setTimeout(loadInvoicesAdmin, 1500);

async function uploadFirmware() {
  const f = document.getElementById('fw-file').files[0];
  const version = document.getElementById('fw-version').value.trim();
  const model = document.getElementById('fw-model').value;
  const notes = document.getElementById('fw-notes').value.trim();
  if (!f) { alert('Pick a firmware file'); return; }
  if (!version) { alert('Version required'); return; }
  const buf = await f.arrayBuffer();
  const url = '/admin/api/firmware/upload?version=' + encodeURIComponent(version) + '&model=' + encodeURIComponent(model) + '&notes=' + encodeURIComponent(notes);
  const r = await fetch(url, {
    method: 'POST', headers: { 'Content-Type': 'application/octet-stream' },
    body: buf, credentials: 'include',
  });
  const d = await r.json();
  alert(r.ok ? ('Uploaded · sha256=' + d.manifest.sha256.slice(0,16) + '…') : ('Failed: ' + (d.error || r.status)));
  loadFirmwares();
}
async function loadFirmwares() {
  try {
    const r = await fetch('/admin/api/firmware', { credentials: 'include' });
    const d = await r.json();
    const el = document.getElementById('firmwares-list');
    if (!d.firmwares.length) { el.innerHTML = '<p style="color:#6c7686;font-size:.85em;text-align:center;padding:14px;">No firmware uploaded yet.</p>'; return; }
    el.innerHTML = '<table><thead><tr><th>Model</th><th>Version</th><th>SHA256</th><th>Size</th><th>Signed</th><th>Notes</th><th></th></tr></thead><tbody>' +
      d.firmwares.map(function(f){
        return '<tr>' +
          '<td><span class="pill">' + f.model + '</span></td>' +
          '<td><span class="mono">' + f.version + '</span></td>' +
          '<td><span class="mono" style="font-size:.75em;">' + f.sha256.slice(0,16) + '…</span></td>' +
          '<td>' + (f.size / 1024 / 1024).toFixed(2) + ' MB</td>' +
          '<td>' + (f.signed_at || '').slice(0, 10) + '</td>' +
          '<td>' + (f.notes || '') + '</td>' +
          '<td><button onclick="if(confirm(\\'Delete?\\'))fetch(\\'/admin/api/firmware/delete\\',{method:\\'POST\\',headers:{\\'Content-Type\\':\\'application/json\\'},body:JSON.stringify({key:\\'' + f.model + '-' + f.version + '\\'}),credentials:\\'include\\'}).then(loadFirmwares)" style="padding:4px 10px;background:#4a3520;color:#ff8c42;border:1px solid #ff8c42;border-radius:4px;cursor:pointer;font-size:.85em;">Delete</button></td>' +
          '</tr>';
      }).join('') + '</tbody></table>';
  } catch {}
}
setInterval(loadFirmwares, 30000);
setTimeout(loadFirmwares, 2500);

async function loadBoxFleet() {
  try {
    const r = await fetch('/admin/api/boxes', { credentials: 'include' }).then(x => x.json());
    const tb = document.querySelector('#boxes-fleet tbody');
    if (!r.boxes || !r.boxes.length) {
      tb.innerHTML = '<tr><td colspan="10" class="empty">No boxes have checked in yet</td></tr>';
      return;
    }
    tb.innerHTML = r.boxes.sort((a,b)=>(b.last_heartbeat||0)-(a.last_heartbeat||0)).map(b => {
      const online = b.online ? '<span class="pill ok">●</span>' : '<span class="pill warn">offline</span>';
      const ago = b.last_heartbeat ? Math.round((Date.now()-b.last_heartbeat)/1000) + 's ago' : 'never';
      return '<tr><td class="mono">' + b.mac + '</td><td>' + (b.customer_name || '<span class="empty">unassigned</span>') + '</td>' +
             '<td>' + online + '</td><td class="mono">' + (b.public_ip || '-') + '</td><td>' + (b.version || '-') + '</td>' +
             '<td>' + (b.device_count || 0) + '</td><td>' + (b.cpu_pct || 0) + '%</td><td>' + (b.ram_pct || 0) + '%</td>' +
             '<td>' + (b.temp_c != null ? b.temp_c + '°C' : '-') + '</td><td>' + ago + '</td></tr>';
    }).join('');
  } catch {}
}
setInterval(loadBoxFleet, 10000); setTimeout(loadBoxFleet, 1500);

async function loadAlarmsTable() {
  try {
    const r = await fetch('/admin/api/alarms?limit=50', { credentials: 'include' }).then(x => x.json());
    const tb = document.querySelector('#alarms-table tbody');
    if (!r.alarms || !r.alarms.length) { tb.innerHTML = '<tr><td colspan="6" class="empty">No alarms.</td></tr>'; return; }
    const sevPill = s => '<span class="pill" style="background:' + ({low:'#1f4f3d',medium:'#4a3520',high:'#5a2c20',critical:'#5a1c20'}[s]||'#2a3340') + ';color:' + ({low:'#3ad29f',medium:'#ffb84a',high:'#ff8c42',critical:'#ff5c5c'}[s]||'#fff') + ';">' + s + '</span>';
    tb.innerHTML = r.alarms.map(a => '<tr><td>' + new Date(a.ts).toLocaleString() + '</td><td>' + sevPill(a.severity) + '</td>' +
      '<td>' + (a.customer_id || '-') + '</td><td class="mono">' + (a.box_mac || '-') + '</td>' +
      '<td>' + a.kind + '</td><td>' + (a.title || '') + '</td></tr>').join('');
  } catch {}
}
setInterval(loadAlarmsTable, 15000); setTimeout(loadAlarmsTable, 2000);

async function loadSpeedtestFleet() {
  try {
    const r = await fetch('/admin/api/speedtest-fleet', { credentials: 'include' }).then(x => x.json());
    const tb = document.querySelector('#speedtest-fleet-table tbody');
    if (!r.fleet || !r.fleet.length) { tb.innerHTML = '<tr><td colspan="9" class="empty">No speed tests recorded yet.</td></tr>'; return; }
    tb.innerHTML = r.fleet.map(b => {
      const l = b.latest;
      const ago = l && l.ts ? new Date(l.ts).toLocaleString() : '-';
      const slow = b.week_avg_down > 0 && b.week_avg_down < 10 ? 'style="color:#ff5c5c;"' : '';
      return '<tr><td class="mono">' + b.mac + '</td><td>' + (b.customer_name || '<span class="empty">unassigned</span>') + '</td>'
        + '<td ' + slow + '>' + (l ? l.down_mbps.toFixed(1) + ' Mbps' : '-') + '</td>'
        + '<td>' + (l ? l.up_mbps.toFixed(1) + ' Mbps' : '-') + '</td>'
        + '<td>' + (l ? Math.round(l.latency_ms) + ' ms' : '-') + '</td>'
        + '<td ' + slow + '>' + (b.week_avg_down ? b.week_avg_down.toFixed(1) : '-') + '</td>'
        + '<td>' + (b.week_avg_up ? b.week_avg_up.toFixed(1) : '-') + '</td>'
        + '<td>' + b.total_tests + '</td><td>' + ago + '</td></tr>';
    }).join('');
  } catch {}
}
async function runFleetSpeedtest() {
  if (!confirm('Run speed test on all online boxes now? This takes ~30s per box.')) return;
  try {
    await fetch('/admin/api/speedtest-fleet/run-now', { method: 'POST', credentials: 'include' });
    setTimeout(loadSpeedtestFleet, 60000);
    alert('Speed tests queued. Check back in a minute.');
  } catch (e) { alert(e.message); }
}
setInterval(loadSpeedtestFleet, 30000); setTimeout(loadSpeedtestFleet, 3000);

async function loadPendingQueue() {
  try {
    const [hw, pr, pb] = await Promise.all([
      fetch('/admin/api/hw-orders', { credentials: 'include' }).then(r => r.json()),
      fetch('/admin/api/plan-requests', { credentials: 'include' }).then(r => r.json()),
      fetch('/admin/api/pending-boxes', { credentials: 'include' }).then(r => r.json()),
    ]);
    const pendingHw = (hw.orders || []).filter(o => o.status === 'received' || o.status === 'prepping');
    const pendingPr = (pr.requests || []).filter(p => p.status === 'pending');
    const pendingPb = (pb.pending || []);

    const renderRow = (lines) => '<div style="padding:6px;background:#0f1419;border-radius:5px;margin-bottom:4px;font-size:.82em;">' + lines.join('<br>') + '</div>';

    document.querySelector('#q-hw-orders').innerHTML = pendingHw.length ? pendingHw.map(o =>
      renderRow([
        '<strong>' + o.customer_name + '</strong> · ' + o.model,
        '<span style="color:#aab2c0;">' + o.address.slice(0, 60) + '</span>',
        '<span style="color:#6c7686;">' + new Date(o.created_at).toLocaleDateString() + ' · ' + o.status + '</span>',
      ])).join('') : '<p class="empty">none</p>';

    document.querySelector('#q-plan-requests').innerHTML = pendingPr.length ? pendingPr.map(r =>
      renderRow([
        '<strong>' + r.customer_name + '</strong>',
        r.current_plan + ' → <span style="color:#3ad29f;">' + r.requested_plan + '</span>',
        '<button onclick="decidePlanReq(\'' + r.id + '\', \'approve\')" style="padding:2px 8px;background:#3ad29f;color:#000;border:none;border-radius:4px;cursor:pointer;font-size:.8em;margin-right:4px;">Approve</button>'
        + '<button onclick="decidePlanReq(\'' + r.id + '\', \'decline\')" style="padding:2px 8px;background:#4a3520;color:#ff8c42;border:none;border-radius:4px;cursor:pointer;font-size:.8em;">Decline</button>',
      ])).join('') : '<p class="empty">none</p>';

    document.querySelector('#q-pending-boxes').innerHTML = pendingPb.length ? pendingPb.map(b =>
      renderRow([
        '<span class="mono">' + b.mac + '</span>',
        'Code: <strong>' + b.code + '</strong>',
        '<span style="color:#6c7686;">' + b.model + ' · ' + new Date(b.registered_at).toLocaleString() + '</span>',
      ])).join('') : '<p class="empty">none</p>';
  } catch {}
}
async function decidePlanReq(id, decision) {
  if (!confirm(decision + ' this plan request?')) return;
  await fetch('/admin/api/plan-requests/decide', {
    method: 'POST', credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id, decision }),
  });
  loadPendingQueue();
}
setInterval(loadPendingQueue, 30000); setTimeout(loadPendingQueue, 1500);

async function loadBizIntel() {
  try {
    const r = await fetch('/admin/api/biz-intel', { credentials: 'include' }).then(x => x.json());
    document.getElementById('bi-mrr').innerText = '$' + r.mrr_usd.toLocaleString();
    document.getElementById('bi-mrr-lbp').innerText = '≈ ' + Math.round(r.mrr_lbp).toLocaleString() + ' LBP';
    document.getElementById('bi-cust').innerText = r.customer_count;
    document.getElementById('bi-funnel').innerHTML =
      '<div>Signed up: <strong>' + r.funnel.signed_up + '</strong></div>'
      + '<div>Claimed box: <strong>' + r.funnel.claimed_box + '</strong></div>'
      + '<div>Active box: <strong>' + r.funnel.active_box + '</strong></div>';
    document.getElementById('bi-plans').innerHTML =
      Object.entries(r.plan_distribution).map(([p, n]) => '<div>' + p + ': <strong>' + n + '</strong></div>').join('');
    const max = Math.max(...r.weekly_signups.map(w => w.signups), 1);
    document.getElementById('bi-signups').innerHTML = r.weekly_signups.map(w =>
      '<div title="' + w.week_start + ': ' + w.signups + '" style="flex:1;background:#3ad29f;height:' + Math.max(2, (w.signups/max)*42) + 'px;border-radius:1px;"></div>'
    ).join('');
  } catch {}
}
setInterval(loadBizIntel, 60000); setTimeout(loadBizIntel, 2500);

async function loadQueueHealth() {
  try {
    const r = await fetch('/admin/api/queue-health', { credentials: 'include' }).then(x => x.json());
    const light = document.getElementById('qh-light');
    const detail = document.getElementById('qh-detail');
    const colors = { green: '🟢', yellow: '🟡', red: '🔴' };
    light.innerText = colors[r.health.status] || '⚪';
    const q = r.queues;
    const items = [];
    if (q.box_commands_pending) items.push('cmds: ' + q.box_commands_pending);
    if (q.webhook_pending) items.push('webhooks: ' + q.webhook_pending);
    if (q.webhook_failed) items.push('webhook fail: ' + q.webhook_failed);
    if (q.support_unread) items.push('support: ' + q.support_unread);
    if (q.hw_orders_pending) items.push('hw: ' + q.hw_orders_pending);
    if (q.plan_requests_pending) items.push('plan req: ' + q.plan_requests_pending);
    if (q.open_outages) items.push('outages: ' + q.open_outages);
    detail.innerText = items.length ? items.join(' · ') : 'all queues clear';
  } catch {}
}
setInterval(loadQueueHealth, 15000); setTimeout(loadQueueHealth, 1500);

async function loadHealthTable() {
  try {
    const r = await fetch('/admin/api/customers/health-summary', { credentials: 'include' }).then(x => x.json());
    const tb = document.querySelector('#health-table tbody');
    if (!r.customers || !r.customers.length) { tb.innerHTML = '<tr><td colspan="4" class="empty">No customers</td></tr>'; return; }
    tb.innerHTML = r.customers.slice(0, 5).map(c => {
      const color = c.score < 50 ? '#ff5c5c' : (c.score < 75 ? '#ffb84a' : '#3ad29f');
      return '<tr><td>' + c.name + '</td><td><span class="pill">' + c.plan + '</span></td>'
        + '<td><span class="pill" style="background:' + color + ';color:#000;">' + c.score + '/100</span></td>'
        + '<td style="font-size:.85em;color:#aab2c0;">' + (c.reasons || []).join(', ') + '</td></tr>';
    }).join('');
    document.getElementById('health-buckets').innerText =
      'at-risk: ' + r.buckets.at_risk + ' · warning: ' + r.buckets.warning + ' · healthy: ' + r.buckets.healthy;
  } catch {}
}
setInterval(loadHealthTable, 60000); setTimeout(loadHealthTable, 3500);

async function loadReferrers() {
  try {
    const r = await fetch('/admin/api/referrals', { credentials: 'include' }).then(x => x.json());
    const el = document.getElementById('ref-list');
    if (!r.referrers || !r.referrers.length) { el.innerHTML = '<p style="color:#6c7686;text-align:center;padding:8px;">No referrals yet</p>'; return; }
    el.innerHTML = r.referrers.slice(0, 5).map(t =>
      '<div style="display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid #1f2530;">'
      + '<span>' + t.referrer_name + '</span><span style="color:#3ad29f;">' + t.count + ' refs</span></div>'
    ).join('') + '<div style="margin-top:6px;color:#6c7686;font-size:.78em;">Total: ' + r.total_referrals + '</div>';
  } catch {}
}
setInterval(loadReferrers, 60000); setTimeout(loadReferrers, 4500);

async function loadThreatFeed() {
  try {
    const r = await fetch('/admin/api/threat-feed', { credentials: 'include' }).then(x => x.json());
    document.getElementById('tf-count').innerText = r.domain_count.toLocaleString();
    const ago = r.last_update ? Math.round((Date.now()-r.last_update)/60000) + ' min ago' : 'never';
    document.getElementById('tf-meta').innerText = 'last update: ' + ago + ' · sources: ' + (r.sources.join(', ') || 'none');
  } catch {}
}
async function refreshThreatFeed() {
  document.getElementById('tf-meta').innerText = 'refreshing…';
  try {
    await fetch('/admin/api/threat-feed/refresh', { method: 'POST', credentials: 'include' });
    setTimeout(loadThreatFeed, 1000);
  } catch (e) { alert(e.message); }
}
setInterval(loadThreatFeed, 60000); setTimeout(loadThreatFeed, 3000);

function trendSparklineSvg(arr, color, w, h) {
  w = w || 200; h = h || 40;
  if (!arr || !arr.length) return '';
  const max = Math.max.apply(null, arr.concat([1]));
  const step = w / (arr.length - 1);
  const pts = arr.map(function(v, i) { return (i*step).toFixed(1) + ',' + (h - (v/max)*h).toFixed(1); }).join(' ');
  return '<svg width="' + w + '" height="' + h + '" viewBox="0 0 ' + w + ' ' + h + '">' +
    '<polyline points="' + pts + '" fill="none" stroke="' + color + '" stroke-width="2"/>' +
    '<polyline points="0,' + h + ' ' + pts + ' ' + w + ',' + h + '" fill="' + color + '22" stroke="none"/>' +
    '</svg>';
}

async function loadTrends() {
  try {
    const r = await fetch('/admin/api/trends', { credentials: 'include' });
    const d = await r.json();
    document.getElementById('trends-grid').innerHTML = [
      ['Signups (30d)', d.totals.signups, d.signups, '#3ad29f'],
      ['Customer actions (30d)', d.totals.actions, d.actions, '#ff8c42'],
      ['Box check-ins (30d)', d.totals.checkins, d.checkins, '#5a8cdc'],
    ].map(function(row) {
      const label = row[0], total = row[1], series = row[2], color = row[3];
      return '<div style="background:#0f1419;border-radius:10px;padding:14px;">' +
        '<div style="font-size:.7em;color:#8aa0c0;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;">' + label + '</div>' +
        '<div style="font-size:1.6em;color:#fff;font-weight:700;">' + total + '</div>' +
        trendSparklineSvg(series, color) +
        '<div style="font-size:.7em;color:#6c7686;margin-top:4px;">last 30 days · today on right</div>' +
        '</div>';
    }).join('');
  } catch (e) {}
}
setInterval(loadTrends, 30000);
setTimeout(loadTrends, 2000);

async function seedDemo() {
  if (!confirm('Add 3 demo customers?')) return;
  const r = await fetch('/admin/api/seed-demo', { method:'POST', credentials: 'include' });
  const d = await r.json();
  alert(r.ok ? ('Created ' + d.created + ' demo customers') : ('Failed: ' + (d.error || r.status)));
  if (r.ok) refresh();
}

async function resetState() {
  const c = prompt('⚠ THIS WIPES ALL CUSTOMERS AND DATA.\\nKeeps: admin accounts, Ed25519 keypair, config.\\n\\nType YES_RESET_EVERYTHING to confirm:');
  if (c !== 'YES_RESET_EVERYTHING') { alert('Cancelled'); return; }
  const r = await fetch('/admin/api/reset-state', {
    method:'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ confirm: 'YES_RESET_EVERYTHING' }), credentials: 'include',
  });
  alert(r.ok ? '✓ State reset' : 'Failed');
  if (r.ok) location.reload();
}

async function addNote(cid) {
  const body = prompt('Internal note for this customer (admins-only, not visible to customer):');
  if (!body) return;
  await fetch('/admin/api/customers/note', {
    method:'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id: cid, body }), credentials: 'include',
  });
  refresh();
}

async function createInvite() {
  const name = document.getElementById('inv-name').value.trim();
  const phone = document.getElementById('inv-phone').value.trim();
  const email = document.getElementById('inv-email').value.trim();
  const plan = document.getElementById('inv-plan').value;
  if (!name || !phone) { alert('Name + phone required'); return; }
  const r = await fetch('/admin/api/customers/invite', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, phone, email, plan }), credentials: 'include',
  });
  const d = await r.json();
  if (!r.ok) { alert('Failed: ' + (d.error || r.status)); return; }
  document.getElementById('invite-result').innerHTML =
    '<div style="background:#1f4f3d;padding:14px;border-radius:8px;border-left:3px solid #3ad29f;">' +
    '<strong style="color:#3ad29f;">✓ Invite created</strong><br>' +
    '<div style="margin-top:8px;font-size:.85em;">Send this link to the customer (' + d.expires_in_days + '-day expiry):</div>' +
    '<div style="margin-top:6px;background:#0f1419;padding:10px;border-radius:6px;font-family:monospace;font-size:.85em;word-break:break-all;">' + d.invite_url + '</div>' +
    '<button onclick="navigator.clipboard.writeText(\\''+d.invite_url+'\\').then(()=>this.textContent=\\'Copied!\\')" style="padding:6px 14px;margin-top:10px;background:#3ad29f;color:#000;border:none;border-radius:4px;cursor:pointer;font-size:.85em;">Copy link</button>' +
    '</div>';
  document.getElementById('inv-name').value = '';
  document.getElementById('inv-phone').value = '';
  document.getElementById('inv-email').value = '';
  refresh();
}

async function setup2FA() {
  const r = await fetch('/admin/api/admins/2fa/setup', { method:'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include' });
  const d = await r.json();
  if (!r.ok) { alert('Failed: ' + (d.error || r.status)); return; }
  document.getElementById('2fa-output').innerHTML =
    '<div style="background:#1f3a5e;padding:14px;border-radius:8px;border-left:3px solid #5a8cdc;">' +
    '<strong style="color:#5a8cdc;">2FA setup — scan with Google Authenticator / 1Password / Authy</strong>' +
    '<div style="display:flex;gap:18px;margin-top:14px;align-items:flex-start;flex-wrap:wrap;">' +
    '  <div style="background:#fff;padding:10px;border-radius:8px;"><canvas id="totp-qr"></canvas></div>' +
    '  <div style="flex:1;min-width:200px;">' +
    '    <div style="font-size:.8em;color:#8aa0c0;">Or type this secret manually:</div>' +
    '    <div style="font-family:monospace;font-size:.95em;background:#0f1419;padding:8px;border-radius:4px;letter-spacing:2px;margin:6px 0;">' + d.secret + '</div>' +
    '    <div style="font-size:.8em;color:#8aa0c0;">After adding to your authenticator, enter the 6-digit code:</div>' +
    '    <div style="margin-top:10px;display:flex;gap:8px;">' +
    '      <input id="totp-code" placeholder="000000" maxlength="6" style="flex:1;padding:8px 10px;background:#0f1419;border:1px solid #2a3340;color:#d8dee9;border-radius:6px;font-family:monospace;letter-spacing:4px;text-align:center;">' +
    '      <button onclick="verify2FA()" style="padding:8px 16px;background:#3ad29f;color:#000;border:none;border-radius:6px;cursor:pointer;font-weight:600;">Activate</button>' +
    '    </div>' +
    '  </div>' +
    '</div></div>';
  // Render the QR code into the canvas
  if (window.QRCode && QRCode.toCanvas) {
    QRCode.toCanvas(document.getElementById('totp-qr'), d.otpauth_url, { width: 180, margin: 1 }, function(err) {
      if (err) console.error('QR render failed:', err);
    });
  }
}

async function verify2FA() {
  const code = document.getElementById('totp-code').value.trim();
  const r = await fetch('/admin/api/admins/2fa/verify', {
    method:'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }), credentials: 'include',
  });
  const d = await r.json();
  if (r.ok) {
    alert('✓ 2FA enabled!\\n\\nFrom now on, send the X-Admin-OTP header with each request.\\n\\nNote: this browser session will keep working until refresh; reload to test.');
  } else {
    alert('Failed: ' + (d.error || 'wrong code'));
  }
}

async function disable2FA() {
  if (!confirm('Disable 2FA?')) return;
  await fetch('/admin/api/admins/2fa/disable', { method:'POST', credentials: 'include' });
  alert('2FA disabled');
}

async function bulkImport() {
  const f = document.getElementById('bulk-csv').files[0];
  if (!f) { alert('Pick a CSV file'); return; }
  const text = await f.text();
  const r = await fetch('/admin/api/customers/bulk-import', {
    method: 'POST',
    headers: { 'Content-Type': 'text/csv' },
    body: text,
    credentials: 'include',
  });
  const d = await r.json();
  if (!r.ok) {
    document.getElementById('bulk-result').innerHTML = '<p style="color:#ff5c5c;">Error: ' + (d.error || r.status) + '</p>';
    return;
  }
  document.getElementById('bulk-result').innerHTML =
    '<p style="color:#3ad29f;">✓ Created <strong>' + d.created + '</strong> customers · skipped <strong>' + d.skipped + '</strong></p>' +
    (d.skipped > 0 ? '<details><summary style="cursor:pointer;color:#8aa0c0;font-size:.85em">View skipped</summary><pre style="font-size:.75em;background:#0f1419;padding:10px;border-radius:6px;">' + JSON.stringify(d.skipped_list, null, 2) + '</pre></details>' : '');
  refresh();
}

async function loadAdmins() {
  try {
    const r = await fetch('/admin/api/admins', { credentials: 'include' });
    const d = await r.json();
    const me = d.me;
    const list = d.admins;
    document.getElementById('admins-list').innerHTML =
      list.length ? '<table><thead><tr><th>Username</th><th>Name</th><th>Role</th><th>Status</th><th>Created</th><th></th></tr></thead><tbody>' +
        list.map(a => \`<tr>
          <td><span class="mono">\${a.username}</span>\${a.username === me.user ? ' <span class="pill ok">you</span>' : ''}</td>
          <td>\${a.name}</td>
          <td><span class="pill">\${a.role}</span></td>
          <td>\${a.active ? '<span class="pill ok">active</span>' : '<span class="pill warn">disabled</span>'}</td>
          <td>\${fmt(a.created_at)}</td>
          <td>\${a.username === me.user ? '<i style="color:#4a5366">(self)</i>' : '<button onclick="delAdmin(\\''+a.username+'\\')" style="padding:4px 10px;background:#4a3520;color:#ff8c42;border:1px solid #ff8c42;border-radius:4px;cursor:pointer;font-size:.85em;">Delete</button>'}</td>
        </tr>\`).join('') + '</tbody></table>'
      : '<p style="color:#6c7686;font-size:.85em;text-align:center;padding:14px;">No sub-admins yet — using bootstrap admin.</p>';
  } catch {}
}
setInterval(loadAdmins, 8000); setTimeout(loadAdmins, 1200);

async function addAdmin() {
  const username = document.getElementById('adm-user').value.trim();
  const name = document.getElementById('adm-name').value.trim();
  const password = document.getElementById('adm-pwd').value;
  const role = document.getElementById('adm-role').value;
  if (!username || !password) { alert('Username + password required'); return; }
  const r = await fetch('/admin/api/admins/create', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, name, password, role }),
    credentials: 'include',
  });
  if (r.ok) {
    document.getElementById('adm-user').value = '';
    document.getElementById('adm-name').value = '';
    document.getElementById('adm-pwd').value = '';
    loadAdmins();
  } else {
    alert('Failed: ' + (await r.text()));
  }
}
async function delAdmin(u) {
  if (!confirm('Delete admin "' + u + '"?')) return;
  await fetch('/admin/api/admins/delete', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: u }), credentials: 'include',
  });
  loadAdmins();
}

async function loadWebhooks() {
  try {
    const r = await fetch('/admin/api/webhooks', { credentials: 'include' });
    const d = await r.json();
    document.getElementById('webhooks-list').innerHTML =
      d.webhooks.length ? '<table><thead><tr><th>Name</th><th>URL</th><th>Events</th><th>Status</th><th></th></tr></thead><tbody>' +
        d.webhooks.map(h => \`<tr>
          <td>\${h.name}</td>
          <td style="font-family:monospace;font-size:.8em;color:#8aa0c0;">\${h.url}</td>
          <td>\${h.events.map(e => '<span class="pill" style="font-size:.7em;">' + e + '</span>').join(' ')}</td>
          <td>\${h.enabled ? '<span class="pill ok">enabled</span>' : '<span class="pill">off</span>'}</td>
          <td>
            <button onclick="testHook('\${h.id}')" style="padding:4px 10px;background:#1f3a5e;color:#5a8cdc;border:1px solid #5a8cdc;border-radius:4px;cursor:pointer;font-size:.85em;margin-${'inline-end'}:4px;">Test</button>
            <button onclick="delHook('\${h.id}')" style="padding:4px 10px;background:#4a3520;color:#ff8c42;border:1px solid #ff8c42;border-radius:4px;cursor:pointer;font-size:.85em;">Delete</button>
          </td>
        </tr>\`).join('') + '</tbody></table>'
      : '<p style="color:#6c7686;font-size:.85em;text-align:center;padding:14px;">No webhooks configured.</p>';
  } catch {}
}
setInterval(loadWebhooks, 10000); setTimeout(loadWebhooks, 1500);

async function addWebhook() {
  const name = document.getElementById('hook-name').value.trim();
  const url = document.getElementById('hook-url').value.trim();
  const eventsStr = document.getElementById('hook-events').value.trim() || '*';
  if (!url) { alert('URL required'); return; }
  const events = eventsStr.split(',').map(s => s.trim()).filter(Boolean);
  const r = await fetch('/admin/api/webhooks', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, url, events }), credentials: 'include',
  });
  if (r.ok) {
    const d = await r.json();
    alert('Webhook added\\n\\nSecret (save this — used to sign requests):\\n' + d.webhook.secret);
    document.getElementById('hook-name').value = '';
    document.getElementById('hook-url').value = '';
    document.getElementById('hook-events').value = '';
    loadWebhooks();
  } else alert('Failed');
}
async function testHook(id) {
  const r = await fetch('/admin/api/webhooks/test', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id }), credentials: 'include',
  });
  alert(r.ok ? 'Test ping sent — check your endpoint logs' : 'Failed');
}
async function delHook(id) {
  if (!confirm('Delete this webhook?')) return;
  await fetch('/admin/api/webhooks/delete', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id }), credentials: 'include',
  });
  loadWebhooks();
}

async function loadAudit() {
  try {
    const r = await fetch('/admin/api/audit', { credentials: 'include' });
    const d = await r.json();
    const allActions = d.actions || [];

    // Populate filter dropdowns once
    const adminSel = document.getElementById('audit-admin-filter');
    const actionSel = document.getElementById('audit-action-filter');
    if (adminSel && adminSel.options.length === 1) {
      const admins = Array.from(new Set(allActions.map(a => a.admin))).sort();
      for (const a of admins) { const o = document.createElement('option'); o.value = o.textContent = a; adminSel.appendChild(o); }
    }
    if (actionSel && actionSel.options.length === 1) {
      const acts = Array.from(new Set(allActions.map(a => a.action))).sort();
      for (const a of acts) { const o = document.createElement('option'); o.value = o.textContent = a; actionSel.appendChild(o); }
    }

    // Apply filters
    const q       = (document.getElementById('audit-search')?.value || '').toLowerCase();
    const adminF  = document.getElementById('audit-admin-filter')?.value || '';
    const actionF = document.getElementById('audit-action-filter')?.value || '';
    const timeF   = document.getElementById('audit-time-filter')?.value || '';
    const timeCutoff = ({ '1h': 1, '24h': 24, '7d': 24*7, '30d': 24*30 })[timeF];
    const cutoffMs = timeCutoff ? Date.now() - timeCutoff * 3600_000 : 0;

    const filtered = allActions.filter(a => {
      if (adminF && a.admin !== adminF) return false;
      if (actionF && a.action !== actionF) return false;
      if (cutoffMs && a.ts < cutoffMs) return false;
      if (q) {
        const blob = (a.action + ' ' + (a.target || '') + ' ' + (a.details || '')).toLowerCase();
        if (!blob.includes(q)) return false;
      }
      return true;
    });

    document.getElementById('audit-list').innerHTML =
      filtered.length ? '<table><thead><tr><th>Time</th><th>Admin</th><th>Action</th><th>Target</th><th>Details</th></tr></thead><tbody>' +
        filtered.slice(0, 200).map(a => \`<tr>
          <td>\${new Date(a.ts).toLocaleString()}</td>
          <td><span class="pill">\${a.admin}</span></td>
          <td><span class="mono">\${a.action}</span></td>
          <td><span class="mono" style="font-size:.85em;">\${a.target || '-'}</span></td>
          <td style="font-size:.85em;color:#8aa0c0;">\${a.details || ''}</td>
        </tr>\`).join('') + '</tbody></table>'
        + (filtered.length > 200 ? '<div style="text-align:center;padding:6px;color:#6c7686;font-size:.8em;">…showing 200 of ' + filtered.length + ' — refine filters to narrow</div>' : '')
      : '<p style="color:#6c7686;font-size:.85em;text-align:center;padding:14px;">No matching admin actions.</p>';
  } catch {}
}
setInterval(loadAudit, 6000); setTimeout(loadAudit, 1800);

async function testSig() {
  const payload = document.getElementById('sig-payload').value.trim();
  const secret = document.getElementById('sig-secret').value.trim();
  if (!payload || !secret) { alert('Both fields required'); return; }
  const r = await fetch('/admin/api/webhook-sig-test', {
    method:'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ payload, secret }), credentials: 'include',
  });
  const d = await r.json();
  document.getElementById('sig-result').innerHTML =
    '<div style="background:#1f4f3d;padding:10px;border-radius:6px;color:#3ad29f;">Expected: <strong>' + d.expected_signature + '</strong></div>';
}

async function downloadBackup() {
  const pwd = prompt('Encrypt with password? (recommended — 8+ chars; press Cancel for plaintext)');
  const params = pwd && pwd.length >= 8 ? '?password=' + encodeURIComponent(pwd) : '';
  const r = await fetch('/admin/api/backup' + params, { credentials: 'include' });
  if (!r.ok) { alert('Failed: ' + r.status); return; }
  const blob = await r.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const suffix = pwd && pwd.length >= 8 ? '.enc' : '';
  a.href = url; a.download = 'mes-cloud-backup-' + new Date().toISOString().slice(0,10) + suffix + '.json';
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}

async function restoreBackup(input) {
  const f = input.files[0]; if (!f) return;
  if (!confirm('Restore from this backup? It will overwrite current data.')) { input.value = ''; return; }
  const text = await f.text();
  let bundle;
  try { bundle = JSON.parse(text); } catch { alert('Invalid backup file'); return; }
  const headers = { 'Content-Type': 'application/json' };
  if (bundle.encrypted) {
    const pwd = prompt('This backup is encrypted. Enter password:');
    if (!pwd) return;
    headers['X-Backup-Password'] = pwd;
  }
  const r = await fetch('/admin/api/restore', {
    method: 'POST', headers, body: JSON.stringify(bundle), credentials: 'include',
  });
  const d = await r.json().catch(() => ({}));
  alert(r.ok ? '✓ Restore complete — refreshing' : ('✗ Restore failed: ' + (d.error || r.status)));
  if (r.ok) location.reload();
}

async function loadSysMetrics() {
  try {
    const r = await fetch('/admin/api/sysmetrics', { credentials: 'include' });
    const d = await r.json();
    document.getElementById('sys-metrics').innerHTML = [
      ['Memory', \`\${d.mem_used_mb || 0} / \${d.mem_total_mb || 0} MB (\${d.mem_pct || 0}%)\`],
      ['Load avg', \`\${d.load_1m || 0} · \${d.load_5m || 0} · \${d.load_15m || 0}\`],
      ['Cloud uptime', \`\${d.process_uptime_h || 0}h\`],
      ['Cloud RSS', \`\${d.process_rss_mb || 0} MB\`],
      ['Data disk', \`\${d.disk_total_mb ? Math.round((d.disk_total_mb - d.disk_free_mb)) + ' / ' + d.disk_total_mb + ' MB' : '—'}\`],
    ].map(([k, v]) => \`<div style="background:#0f1419;padding:10px;border-radius:8px;"><div style="font-size:.7em;text-transform:uppercase;letter-spacing:1px;">\${k}</div><div style="color:#fff;font-size:1em;font-weight:600;margin-top:4px;">\${v}</div></div>\`).join('');
  } catch {}
}
setInterval(loadSysMetrics, 10000);
setTimeout(loadSysMetrics, 800);

async function loadSupport() {
  try {
    const r = await fetch('/admin/api/support', { credentials: 'include' });
    const d = await r.json();
    const el = document.getElementById('support-threads');
    if (!d.threads.length) { el.innerHTML = '<p style="color:#6c7686;font-size:.85em;text-align:center;padding:14px;">No support threads yet</p>'; return; }
    el.innerHTML = '<table><thead><tr><th>Customer</th><th>Last message</th><th>From</th><th>Unread</th><th></th></tr></thead><tbody>' +
      d.threads.map(t => {
        const ts = t.last_ts ? new Date(t.last_ts).toLocaleString() : '—';
        return \`<tr>
          <td><strong>\${t.customer_name}</strong><br><span style="font-size:.75em;color:#6c7686">\${t.customer_phone}</span></td>
          <td><span style="font-size:.85em">\${t.last_body || '—'}</span><br><span style="font-size:.7em;color:#6c7686">\${ts}</span></td>
          <td><span class="pill \${t.last_from==='customer'?'warn':'ok'}">\${t.last_from || '-'}</span></td>
          <td>\${t.unread > 0 ? '<span class="pill warn">' + t.unread + ' unread</span>' : '<span class="pill ok">0</span>'}</td>
          <td><button onclick="openChat('\${t.customer_id}')" style="padding:4px 10px;background:#1f4f3d;color:#3ad29f;border:1px solid #3ad29f;border-radius:4px;cursor:pointer;font-size:.85em;">Open</button></td>
        </tr>\`;
      }).join('') + '</tbody></table>';
  } catch {}
}
setInterval(loadSupport, 5000);
setTimeout(loadSupport, 1000);

async function openChat(cid) {
  const r = await fetch('/admin/api/support/' + cid, { credentials: 'include' });
  const d = await r.json();
  const lines = d.messages.map(m => {
    const t = new Date(m.ts).toLocaleTimeString();
    const pre = m.from === 'admin' ? '➜ YOU' : '← ' + (d.customer.name || 'CUSTOMER');
    return pre + ' [' + t + ']\\n' + m.body;
  }).join('\\n\\n');
  const reply = prompt('Conversation with ' + d.customer.name + ':\\n\\n' + (lines || '(empty)') + '\\n\\nYour reply (cancel to close):');
  if (reply && reply.trim()) {
    await fetch('/admin/api/support/' + cid + '/reply', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ body: reply.trim() }),
      credentials: 'include',
    });
    loadSupport();
  }
}

async function dlCsv(name) {
  // Use fetch+blob so basic-auth credentials carry through
  const r = await fetch('/admin/api/export/' + name, { credentials: 'include' });
  if (!r.ok) { alert('Failed: ' + r.status); return; }
  const blob = await r.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}

function setFilter(f) {
  window.__filter = f;
  document.querySelectorAll('.filt').forEach(b => {
    const active = b.dataset.filter === f;
    b.style.background = active ? '#3ad29f' : '#2a3340';
    b.style.color = active ? '#000' : '#d8dee9';
  });
  refresh();
}

async function broadcastNotif() {
  const title = document.getElementById('notif-title').value.trim();
  const body = document.getElementById('notif-body').value.trim();
  const kind = document.getElementById('notif-kind').value;
  if (!title) { alert('Title required'); return; }
  if (!confirm('Send to ALL active customers?')) return;
  const r = await fetch('/admin/api/notify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ broadcast: true, title, body, kind }),
    credentials: 'include',
  });
  const res = await r.json();
  alert('Sent to ' + (res.sent || 0) + ' customers');
  document.getElementById('notif-title').value = '';
  document.getElementById('notif-body').value = '';
  refresh();
}

document.getElementById('cust-create-btn').addEventListener('click', createCustomer);
async function revokeMac(mac) {
  if (!confirm('Revoke license for ' + mac + '?')) return;
  await fetch('/admin/api/macs/revoke', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mac }),
    credentials: 'include',
  });
  refresh();
}
document.getElementById('auth-btn').addEventListener('click', authorizeMac);

refresh();
setInterval(refresh, 3000);
applyAdminLang();
// Re-apply translations after each render (text gets re-set by refresh)
const _origRefresh = refresh;
refresh = async function() { await _origRefresh(); applyAdminLang(); };
</script>
</body></html>`;

// ════════════════════════════════════════════════════════════════════════
// ─── Start ───
const PORT = parseInt(process.env.PORT) || 8080;
const HOST = process.env.HOST || '0.0.0.0';

const server = http.createServer(app);
server.listen(PORT, HOST, () => {
  console.log('');
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('   Mock Firewalla Cloud running on http://' + HOST + ':' + PORT);
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('   Status:  curl http://localhost:' + PORT + '/');
  console.log('   Logs:    every request prints below');
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('');
});

// Graceful shutdown — save state on the way out
function shutdown() {
  console.log('Saving state before shutdown...');
  saveState();
  server.close(() => process.exit(0));
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
