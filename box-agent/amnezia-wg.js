'use strict';
/*
 * amnezia-wg.js — AmneziaWG server (obfuscated WireGuard).
 *
 * AmneziaWG is a WireGuard fork that adds packet-shape obfuscation params
 * (Jc, Jmin, Jmax, S1, S2, H1-H4) so traffic looks like random TCP/noise
 * instead of the easily-fingerprintable WireGuard handshake. Useful for
 * users in Iran, China, Russia, or any DPI-blocking network.
 *
 * NOTE — this module currently ships as a SCAFFOLD only:
 *
 *   Why: AmneziaWG isn't packaged in Debian/Ubuntu apt repos. Real install
 *   requires either compiling amneziawg-tools + amneziawg-go from source
 *   (Rust + Go toolchains on the Pi) or downloading the prebuilt ARM64
 *   binaries from the GitHub release. The bake-from-source path takes
 *   ~25 min on a Pi4 and the download path varies with each release —
 *   we don't pin to a specific version yet.
 *
 *   What we DO ship: full API surface (server setup, peer CRUD, status,
 *   download peer .awg config) so the PWA/cloud are ready. install() and
 *   setupServer() return a clear "needs manual install" message; that
 *   propagates to the UI which shows the manual install steps.
 *
 *   Manual install steps (paste on the Pi):
 *     sudo apt install -y golang-go git make
 *     cd /tmp && git clone https://github.com/amnezia-vpn/amneziawg-go
 *     cd amneziawg-go && make && sudo cp amneziawg-go /usr/local/bin/
 *     cd /tmp && git clone https://github.com/amnezia-vpn/amneziawg-tools
 *     cd amneziawg-tools/src && make && sudo make install
 *     sudo ln -sf /usr/bin/awg /usr/local/bin/awg  # path harmonisation
 *
 *   Once installed, this module's install() will detect `awg` in PATH and
 *   start functioning.
 *
 * Public API (mirrors box-agent/wg-client + the existing wg server shape):
 *   install()                                  -> { ok, installed? } | { ok:false, error:'amneziawg_not_installed' }
 *   setupServer({listen_port?, network_cidr?}) -> { ok, port, network } | needs_manual
 *   addPeer({label})                           -> { ok, peer_id, conf_text }
 *   removePeer(peer_id)                        -> { ok }
 *   listPeers()                                -> [ { id, label, ip, pubkey } ]
 *   getPeerConf(peer_id)                       -> { ok, conf_text }
 *   getStatus()                                -> { ok, installed, configured, port, peers_total, peers_connected }
 */

const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');

const STATE_DIR  = '/etc/mes-awg';
const META_FILE  = path.join(STATE_DIR, 'meta.json');
const PEERS_FILE = path.join(STATE_DIR, 'peers.json');
const SERVER_KEY = path.join(STATE_DIR, 'server.key');
const SERVER_PUB = path.join(STATE_DIR, 'server.pub');
const AWG_CONF   = '/etc/amnezia/amneziawg/awg0.conf';

const MANUAL_INSTALL_HINT =
  'AmneziaWG binaries are not in apt. Install manually:\n' +
  '  sudo apt install -y golang-go git make\n' +
  '  cd /tmp && git clone https://github.com/amnezia-vpn/amneziawg-go && cd amneziawg-go && make && sudo cp amneziawg-go /usr/local/bin/\n' +
  '  cd /tmp && git clone https://github.com/amnezia-vpn/amneziawg-tools && cd amneziawg-tools/src && make && sudo make install';

function sh(cmd, opts = {}) {
  try { return execSync(cmd, { encoding: 'utf8', timeout: 8_000, stdio: ['ignore', 'pipe', 'pipe'], ...opts }).trim(); }
  catch (e) { return null; }
}

function have(bin) { return !!sh(`which ${bin}`); }

function isAwgInstalled() {
  // Either awg-quick or awg in PATH counts as installed
  return have('awg') || have('awg-quick');
}

function ensureDirs() {
  try { fs.mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 }); } catch {}
}

function readMeta() { try { return JSON.parse(fs.readFileSync(META_FILE, 'utf8')); } catch { return {}; } }
function writeMeta(m) { ensureDirs(); fs.writeFileSync(META_FILE, JSON.stringify(m, null, 2), { mode: 0o600 }); }
function readPeers() { try { return JSON.parse(fs.readFileSync(PEERS_FILE, 'utf8')); } catch { return []; } }
function writePeers(p) { ensureDirs(); fs.writeFileSync(PEERS_FILE, JSON.stringify(p, null, 2), { mode: 0o600 }); }

// ─── public API ─────────────────────────────────────────────────────────

function install() {
  if (isAwgInstalled()) {
    return { ok: true, already_installed: true, version: sh('awg --version 2>/dev/null') || '' };
  }
  // We don't try apt — it doesn't have it. We don't try to compile —
  // takes 25+ min, may fail, blocks first-boot. Surface a clear message.
  return {
    ok: false,
    error: 'amneziawg_not_installed',
    hint: MANUAL_INSTALL_HINT,
    docs_url: 'https://github.com/amnezia-vpn/amneziawg-tools',
  };
}

function _genKeypair() {
  // If wg or awg are around, use them; else fall back to crypto's x25519
  if (have('awg')) {
    const priv = sh('awg genkey');
    const pub  = sh(`echo '${priv}' | awg pubkey`);
    return { priv, pub };
  }
  if (have('wg')) {
    const priv = sh('wg genkey');
    const pub  = sh(`echo '${priv}' | wg pubkey`);
    return { priv, pub };
  }
  // Crypto fallback: generate an X25519 keypair, base64-encode raw bytes
  // (matches WireGuard's key format).
  const kp = crypto.generateKeyPairSync('x25519');
  const privRaw = kp.privateKey.export({ format: 'der', type: 'pkcs8' });
  const pubRaw  = kp.publicKey.export({ format: 'der', type: 'spki' });
  // The raw 32 bytes are at the tail of the DER encoding for both keys
  const priv = privRaw.subarray(privRaw.length - 32).toString('base64');
  const pub  = pubRaw.subarray(pubRaw.length - 32).toString('base64');
  return { priv, pub };
}

function _ensureServerKeys() {
  if (fs.existsSync(SERVER_KEY) && fs.existsSync(SERVER_PUB)) {
    return {
      priv: fs.readFileSync(SERVER_KEY, 'utf8').trim(),
      pub:  fs.readFileSync(SERVER_PUB, 'utf8').trim(),
    };
  }
  const kp = _genKeypair();
  if (!kp.priv || !kp.pub) throw new Error('keypair_gen_failed');
  ensureDirs();
  fs.writeFileSync(SERVER_KEY, kp.priv + '\n', { mode: 0o600 });
  fs.writeFileSync(SERVER_PUB, kp.pub + '\n',  { mode: 0o644 });
  return kp;
}

function _genObfuscationParams() {
  // The AmneziaWG obfuscation parameters. These are the "junk packet"
  // (Jc, Jmin, Jmax) and "magic header" (H1-H4, S1, S2) knobs that
  // make AWG handshakes look like random noise instead of WireGuard.
  // Sensible defaults from the AmneziaVPN client.
  function rndInt(min, max) { return crypto.randomInt(min, max + 1); }
  return {
    Jc:  rndInt(4, 12),
    Jmin: 40,
    Jmax: 70,
    S1:  rndInt(15, 150),
    S2:  rndInt(15, 150),
    H1:  rndInt(5,  2147483647),
    H2:  rndInt(5,  2147483647),
    H3:  rndInt(5,  2147483647),
    H4:  rndInt(5,  2147483647),
  };
}

function setupServer(opts = {}) {
  if (!isAwgInstalled()) {
    return { ok: false, error: 'amneziawg_not_installed', hint: MANUAL_INSTALL_HINT, manual_install_required: true };
  }
  const port    = parseInt(opts.listen_port, 10) || 51821;
  const network = String(opts.network_cidr || '10.99.20.0/24');
  const m = network.match(/^(\d+\.\d+\.\d+)\.\d+\/(\d+)$/);
  if (!m) return { ok: false, error: 'bad_network_cidr' };

  ensureDirs();
  let keys;
  try { keys = _ensureServerKeys(); }
  catch (e) { return { ok: false, error: 'keygen_failed', detail: e.message }; }

  const meta = readMeta();
  meta.port = port;
  meta.network = network;
  meta.server_pubkey = keys.pub;
  meta.server_address = m[1] + '.1/24';
  meta.obfuscation = meta.obfuscation || _genObfuscationParams();
  meta.setup_at = new Date().toISOString();
  writeMeta(meta);

  // Write awg0.conf so awg-quick can bring it up
  try { fs.mkdirSync(path.dirname(AWG_CONF), { recursive: true, mode: 0o700 }); } catch {}
  const conf = _buildServerConf(meta, readPeers());
  fs.writeFileSync(AWG_CONF, conf, { mode: 0o600 });

  // Best-effort interface bring-up — if awg-quick is present
  if (have('awg-quick')) {
    sh('awg-quick down awg0 2>/dev/null');
    const upOut = sh('awg-quick up awg0 2>&1');
    if (upOut === null || /error|fail/i.test(upOut || '')) {
      return { ok: true, port, network, server_pubkey: keys.pub, warn: 'awg-quick up returned non-zero', detail: (upOut || '').slice(0, 400) };
    }
  }

  return { ok: true, port, network, server_pubkey: keys.pub };
}

function _buildServerConf(meta, peers) {
  const o = meta.obfuscation || {};
  let conf = `# /etc/amnezia/amneziawg/awg0.conf — generated by mes-awg
[Interface]
PrivateKey = ${fs.readFileSync(SERVER_KEY, 'utf8').trim()}
Address = ${meta.server_address}
ListenPort = ${meta.port}
Jc = ${o.Jc || 4}
Jmin = ${o.Jmin || 40}
Jmax = ${o.Jmax || 70}
S1 = ${o.S1 || 50}
S2 = ${o.S2 || 100}
H1 = ${o.H1 || 1}
H2 = ${o.H2 || 2}
H3 = ${o.H3 || 3}
H4 = ${o.H4 || 4}
`;
  for (const p of peers) {
    conf += `
[Peer]
# ${p.label}
PublicKey = ${p.pubkey}
AllowedIPs = ${p.ip}/32
`;
  }
  return conf;
}

function _safeLabel(label) {
  const s = String(label || '').toLowerCase().replace(/[^a-z0-9]+/g, '').slice(0, 16);
  if (!s) throw new Error('label must contain at least one alphanumeric character');
  return s;
}

function _nextPeerIp(meta, peers) {
  // server takes .1 — peers start at .2
  const base = meta.network.replace(/\.\d+\/\d+$/, '');
  const used = new Set(peers.map(p => p.ip));
  for (let i = 2; i < 255; i++) {
    const ip = `${base}.${i}`;
    if (!used.has(ip)) return ip;
  }
  throw new Error('peer_pool_exhausted');
}

function addPeer(opts = {}) {
  const meta = readMeta();
  if (!meta.port) return { ok: false, error: 'server_not_setup' };
  const label = _safeLabel(opts.label || 'peer');
  const peers = readPeers();
  const peer_id = 'awg-' + label + '-' + crypto.randomBytes(3).toString('hex');
  const ip = _nextPeerIp(meta, peers);
  const kp = _genKeypair();
  if (!kp.priv || !kp.pub) return { ok: false, error: 'keypair_gen_failed' };
  const o = meta.obfuscation || {};
  const endpoint_host = meta.endpoint_host || '0.0.0.0';
  const conf_text = `# AmneziaWG peer config for ${label}
[Interface]
PrivateKey = ${kp.priv}
Address = ${ip}/32
DNS = 1.1.1.1
Jc = ${o.Jc || 4}
Jmin = ${o.Jmin || 40}
Jmax = ${o.Jmax || 70}
S1 = ${o.S1 || 50}
S2 = ${o.S2 || 100}
H1 = ${o.H1 || 1}
H2 = ${o.H2 || 2}
H3 = ${o.H3 || 3}
H4 = ${o.H4 || 4}

[Peer]
PublicKey = ${meta.server_pubkey}
Endpoint = ${endpoint_host}:${meta.port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`;
  const peer = { id: peer_id, label: opts.label || label, ip, pubkey: kp.pub, created_at: Date.now() };
  peers.push(peer);
  writePeers(peers);
  // Re-render server conf with the new peer
  try { fs.writeFileSync(AWG_CONF, _buildServerConf(meta, peers), { mode: 0o600 }); } catch {}
  // syncconf is the proper way to live-update a running awg interface
  if (isAwgInstalled() && have('awg')) {
    sh(`awg syncconf awg0 <(awg-quick strip awg0) 2>/dev/null`, { shell: '/bin/bash' });
  }
  return { ok: true, peer_id, peer, conf_text };
}

function removePeer(peer_id) {
  if (!peer_id || typeof peer_id !== 'string') return { ok: false, error: 'bad_peer_id' };
  const peers = readPeers();
  const idx = peers.findIndex(p => p.id === peer_id);
  if (idx === -1) return { ok: false, error: 'peer_not_found' };
  peers.splice(idx, 1);
  writePeers(peers);
  const meta = readMeta();
  if (meta.port) {
    try { fs.writeFileSync(AWG_CONF, _buildServerConf(meta, peers), { mode: 0o600 }); } catch {}
    if (isAwgInstalled() && have('awg')) {
      sh(`awg syncconf awg0 <(awg-quick strip awg0) 2>/dev/null`, { shell: '/bin/bash' });
    }
  }
  return { ok: true };
}

function listPeers() {
  return readPeers().map(p => ({ id: p.id, label: p.label, ip: p.ip, pubkey: p.pubkey, created_at: p.created_at }));
}

function getPeerConf(peer_id) {
  // We don't store the peer's private key (it's generated and returned on
  // addPeer only). Re-issuing requires regenerating — so getPeerConf is
  // a placeholder that returns the public material only, useful for
  // troubleshooting but NOT for client setup.
  const peers = readPeers();
  const p = peers.find(x => x.id === peer_id);
  if (!p) return { ok: false, error: 'peer_not_found' };
  return {
    ok: true,
    peer: { id: p.id, label: p.label, ip: p.ip, pubkey: p.pubkey },
    note: 'For security the peer private key is only returned once (at creation). To get a fresh conf, delete and re-create the peer.',
  };
}

function getStatus() {
  const installed = isAwgInstalled();
  const meta = readMeta();
  const peers = readPeers();
  let peers_connected = 0;
  let iface_up = false;
  if (installed && have('awg')) {
    const out = sh('awg show awg0 dump 2>/dev/null') || '';
    if (out) iface_up = true;
    const lines = out.split('\n').filter(Boolean);
    // first line is interface; subsequent are peers
    for (let i = 1; i < lines.length; i++) {
      const cols = lines[i].split('\t');
      // col[4] = last handshake (sec since epoch). Consider <3 min as connected.
      if (cols.length >= 5) {
        const lh = parseInt(cols[4], 10) || 0;
        if (lh && (Date.now() / 1000 - lh) < 180) peers_connected++;
      }
    }
  }
  return {
    ok: true,
    installed,
    configured: !!meta.port,
    manual_install_required: !installed,
    manual_install_hint: installed ? null : MANUAL_INSTALL_HINT,
    port: meta.port || null,
    network: meta.network || null,
    server_pubkey: meta.server_pubkey || null,
    iface_up,
    peers_total: peers.length,
    peers_connected,
  };
}

module.exports = {
  install,
  setupServer,
  addPeer,
  removePeer,
  listPeers,
  getPeerConf,
  getStatus,
};
