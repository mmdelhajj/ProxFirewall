// box-agent/openvpn.js
//
// Self-contained OpenVPN server module for the mes-net.lb box agent.
// Complements the existing WireGuard support by offering an OpenVPN endpoint
// for clients on networks that block UDP/51820 or otherwise require the
// broader compatibility profile (TCP/443 fallback, mature TLS stack, etc.).
//
// All state is kept in /etc/openvpn/server-mes/ to avoid colliding with any
// other openvpn instances that may already exist on the box. PKI is built
// directly with openssl (no easy-rsa dep) to keep install footprint small.
//
// Public API:
//   installAndInitServer(opts)
//   addClient(name)   -> { name, ovpn_text }
//   revokeClient(name)
//   listClients()     -> [{ name, created_at, revoked }]
//   getStatus()       -> { running, port, listening_on, connected_clients[] }
//   uninstallAll()

'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync, spawnSync } = require('child_process');

// ---------------------------------------------------------------------------
// Paths & constants
// ---------------------------------------------------------------------------

const STATE_DIR    = '/etc/openvpn/server-mes';
const PKI_DIR      = path.join(STATE_DIR, 'pki');
const CLIENTS_DIR  = path.join(STATE_DIR, 'clients');
const PROFILES_DIR = path.join(STATE_DIR, 'profiles');
const META_FILE    = path.join(STATE_DIR, 'clients.json');

const CA_KEY       = path.join(PKI_DIR, 'ca.key');
const CA_CRT       = path.join(PKI_DIR, 'ca.crt');
const CA_SRL       = path.join(PKI_DIR, 'ca.srl');
const SERVER_KEY   = path.join(PKI_DIR, 'server.key');
const SERVER_CSR   = path.join(PKI_DIR, 'server.csr');
const SERVER_CRT   = path.join(PKI_DIR, 'server.crt');
const DH_PEM       = path.join(PKI_DIR, 'dh.pem');
const TLS_CRYPT    = path.join(PKI_DIR, 'tls-crypt.key');
const CRL_PEM      = path.join(PKI_DIR, 'crl.pem');
const INDEX_TXT    = path.join(PKI_DIR, 'index.txt');
const SERIAL_TXT   = path.join(PKI_DIR, 'serial');
const OPENSSL_CNF  = path.join(PKI_DIR, 'openssl.cnf');

const SERVER_CONF  = path.join(STATE_DIR, 'server.conf');
const SYSTEMD_UNIT = 'openvpn-server@server-mes';   // /etc/openvpn/server/server-mes.conf is the standard path
const SERVER_LINK  = '/etc/openvpn/server/server-mes.conf';
const STATUS_LOG   = path.join(STATE_DIR, 'openvpn-status.log');

// ---------------------------------------------------------------------------
// Tiny shell helpers
// ---------------------------------------------------------------------------

function sh(cmd, opts = {}) {
  return execSync(cmd, { stdio: ['ignore', 'pipe', 'pipe'], ...opts }).toString();
}

function shTry(cmd, opts = {}) {
  try { return { ok: true, out: sh(cmd, opts) }; }
  catch (e) { return { ok: false, out: (e.stdout || '').toString(), err: (e.stderr || '').toString(), code: e.status }; }
}

function ensureDir(d, mode = 0o700) {
  fs.mkdirSync(d, { recursive: true, mode });
  try { fs.chmodSync(d, mode); } catch (_) { /* noop */ }
}

function writeFile(p, content, mode = 0o600) {
  fs.writeFileSync(p, content, { mode });
  try { fs.chmodSync(p, mode); } catch (_) { /* noop */ }
}

function readMeta() {
  if (!fs.existsSync(META_FILE)) return { clients: {} };
  try { return JSON.parse(fs.readFileSync(META_FILE, 'utf8')); }
  catch (_) { return { clients: {} }; }
}

function writeMeta(meta) {
  writeFile(META_FILE, JSON.stringify(meta, null, 2), 0o600);
}

function detectIface() {
  // Pick the iface holding the default route — used in NAT/firewall hints.
  const out = shTry("ip -4 route show default | awk '{print $5; exit}'");
  return out.ok ? out.out.trim() || 'eth0' : 'eth0';
}

function publicIP() {
  // Best-effort — consumer can override via opts.public_ip.
  const r = shTry("ip -4 route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i==\"src\"){print $(i+1); exit}}'");
  if (r.ok && r.out.trim()) return r.out.trim();
  return '127.0.0.1';
}

// ---------------------------------------------------------------------------
// PKI — direct openssl invocations (no easy-rsa)
// ---------------------------------------------------------------------------

const OPENSSL_CONFIG_TEMPLATE = `
# Minimal openssl CA config used by box-agent/openvpn.js
HOME            = .
RANDFILE        = $ENV::HOME/.rnd

[ ca ]
default_ca = CA_default

[ CA_default ]
dir              = ${PKI_DIR}
certs            = $dir
new_certs_dir    = $dir
database         = $dir/index.txt
serial           = $dir/serial
crl              = $dir/crl.pem
RANDFILE         = $dir/.rand
default_md       = sha256
policy           = policy_any
default_days     = 3650
default_crl_days = 3650
unique_subject   = no
copy_extensions  = none

[ policy_any ]
commonName             = supplied
countryName            = optional
stateOrProvinceName    = optional
organizationName       = optional
organizationalUnitName = optional
emailAddress           = optional

[ req ]
default_bits       = 2048
default_md         = sha256
prompt             = no
distinguished_name = req_dn

[ req_dn ]
CN = placeholder
`;

function ensureOpensslPresent() {
  const r = shTry('which openssl');
  if (!r.ok) {
    sh('DEBIAN_FRONTEND=noninteractive apt-get update -y');
    sh('DEBIAN_FRONTEND=noninteractive apt-get install -y openssl');
  }
}

function ensureOpenvpnPkg() {
  const r = shTry('which openvpn');
  if (!r.ok) {
    sh('DEBIAN_FRONTEND=noninteractive apt-get update -y');
    sh('DEBIAN_FRONTEND=noninteractive apt-get install -y openvpn');
  }
}

function initPKI() {
  ensureDir(STATE_DIR, 0o750);
  ensureDir(PKI_DIR, 0o700);
  ensureDir(CLIENTS_DIR, 0o700);
  ensureDir(PROFILES_DIR, 0o700);

  // OpenSSL CA bookkeeping files
  if (!fs.existsSync(INDEX_TXT))  writeFile(INDEX_TXT, '', 0o600);
  if (!fs.existsSync(SERIAL_TXT)) writeFile(SERIAL_TXT, '01\n', 0o600);
  writeFile(OPENSSL_CNF, OPENSSL_CONFIG_TEMPLATE, 0o600);

  // CA
  if (!fs.existsSync(CA_KEY) || !fs.existsSync(CA_CRT)) {
    sh(`openssl genrsa -out ${CA_KEY} 4096`);
    sh(`openssl req -x509 -new -nodes -key ${CA_KEY} -sha256 -days 3650 ` +
       `-out ${CA_CRT} -subj '/CN=mes-ovpn-ca'`);
    fs.chmodSync(CA_KEY, 0o600);
    fs.chmodSync(CA_CRT, 0o644);
  }

  // Server cert
  if (!fs.existsSync(SERVER_KEY) || !fs.existsSync(SERVER_CRT)) {
    sh(`openssl genrsa -out ${SERVER_KEY} 2048`);
    sh(`openssl req -new -key ${SERVER_KEY} -out ${SERVER_CSR} -subj '/CN=server'`);
    sh(`openssl x509 -req -in ${SERVER_CSR} -CA ${CA_CRT} -CAkey ${CA_KEY} ` +
       `-CAcreateserial -CAserial ${CA_SRL} -out ${SERVER_CRT} -days 3650 -sha256`);
    fs.chmodSync(SERVER_KEY, 0o600);
    fs.chmodSync(SERVER_CRT, 0o644);
  }

  // tls-crypt key (HMAC + symmetric encrypt of the control channel)
  if (!fs.existsSync(TLS_CRYPT)) {
    sh(`openvpn --genkey secret ${TLS_CRYPT}`);
    fs.chmodSync(TLS_CRYPT, 0o600);
  }

  // DH params — modern OpenVPN with ECDH negotiates this on its own when
  // `dh none` is used, so we skip the (slow) `openssl dhparam` generation
  // entirely. Server.conf below sets `dh none` + ECDH curve.

  // Empty CRL so server can start with `crl-verify`
  if (!fs.existsSync(CRL_PEM)) {
    const r = shTry(`openssl ca -gencrl -keyfile ${CA_KEY} -cert ${CA_CRT} ` +
                    `-out ${CRL_PEM} -config ${OPENSSL_CNF}`);
    if (!r.ok) {
      // Fall back to an empty placeholder; server with crl-verify would refuse,
      // so on failure we just omit crl-verify in server.conf below.
      try { fs.unlinkSync(CRL_PEM); } catch (_) {}
    } else {
      fs.chmodSync(CRL_PEM, 0o644);
    }
  }
}

// ---------------------------------------------------------------------------
// Server config
// ---------------------------------------------------------------------------

function buildServerConf(opts) {
  const proto    = opts.proto || 'udp';                  // 'udp' or 'tcp'
  const port     = opts.port  || (proto === 'tcp' ? 443 : 1194);
  const subnet   = opts.subnet || '10.99.0.0';
  const netmask  = opts.netmask || '255.255.255.0';
  const dns1     = opts.dns1 || '1.1.1.1';
  const dns2     = opts.dns2 || '1.0.0.1';
  const haveCrl  = fs.existsSync(CRL_PEM);

  return `# ${SERVER_CONF}
# Managed by box-agent/openvpn.js -- do not edit by hand.

port ${port}
proto ${proto}
dev tun

ca   ${CA_CRT}
cert ${SERVER_CRT}
key  ${SERVER_KEY}
dh none
ecdh-curve prime256v1
tls-crypt ${TLS_CRYPT}
${haveCrl ? `crl-verify ${CRL_PEM}` : `# crl-verify disabled (CRL not generated)`}

topology subnet
server ${subnet} ${netmask}
ifconfig-pool-persist ${path.join(STATE_DIR, 'ipp.txt')}

push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS ${dns1}"
push "dhcp-option DNS ${dns2}"
push "block-outside-dns"

keepalive 10 60
persist-key
persist-tun

# Crypto
auth SHA256
cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM
tls-version-min 1.2
remote-cert-tls client

user nobody
group nogroup

status ${STATUS_LOG} 10
verb 3
explicit-exit-notify ${proto === 'udp' ? 1 : 0}
`;
}

function writeServerConf(opts) {
  const cfg = buildServerConf(opts);
  writeFile(SERVER_CONF, cfg, 0o640);

  // Symlink into /etc/openvpn/server/ so the standard
  // openvpn-server@server-mes.service unit picks it up.
  ensureDir('/etc/openvpn/server', 0o755);
  try { fs.unlinkSync(SERVER_LINK); } catch (_) {}
  fs.symlinkSync(SERVER_CONF, SERVER_LINK);
}

function enableIPForward() {
  shTry('sysctl -w net.ipv4.ip_forward=1');
  const f = '/etc/sysctl.d/99-mes-openvpn.conf';
  if (!fs.existsSync(f)) writeFile(f, 'net.ipv4.ip_forward=1\n', 0o644);
}

function startService() {
  shTry('systemctl daemon-reload');
  shTry(`systemctl enable ${SYSTEMD_UNIT}.service`);
  shTry(`systemctl restart ${SYSTEMD_UNIT}.service`);
}

// ---------------------------------------------------------------------------
// Public: installAndInitServer
// ---------------------------------------------------------------------------

function installAndInitServer(opts = {}) {
  ensureOpensslPresent();
  ensureOpenvpnPkg();
  initPKI();
  writeServerConf(opts);
  enableIPForward();
  startService();

  const meta = readMeta();
  meta.server = {
    proto:      opts.proto  || 'udp',
    port:       opts.port   || (opts.proto === 'tcp' ? 443 : 1194),
    subnet:     opts.subnet || '10.99.0.0/24',
    public_ip:  opts.public_ip || publicIP(),
    iface:      detectIface(),
    initialized_at: new Date().toISOString(),
  };
  writeMeta(meta);

  return {
    ok: true,
    state_dir: STATE_DIR,
    server: meta.server,
    note: 'Default UDP/1194. Pass {proto:"tcp", port:443} to bypass picky firewalls.',
  };
}

// ---------------------------------------------------------------------------
// Client cert lifecycle
// ---------------------------------------------------------------------------

function safeName(name) {
  if (!name || typeof name !== 'string') throw new Error('client name required');
  if (!/^[A-Za-z0-9._-]{1,32}$/.test(name)) {
    throw new Error('client name must match [A-Za-z0-9._-]{1,32}');
  }
  return name;
}

function clientPaths(name) {
  return {
    key: path.join(CLIENTS_DIR, `${name}.key`),
    csr: path.join(CLIENTS_DIR, `${name}.csr`),
    crt: path.join(CLIENTS_DIR, `${name}.crt`),
    ovpn: path.join(PROFILES_DIR, `${name}.ovpn`),
  };
}

function generateClientCert(name) {
  const p = clientPaths(name);
  if (fs.existsSync(p.crt)) {
    throw new Error(`client '${name}' already exists`);
  }
  sh(`openssl genrsa -out ${p.key} 2048`);
  sh(`openssl req -new -key ${p.key} -out ${p.csr} -subj '/CN=${name}'`);
  sh(`openssl x509 -req -in ${p.csr} -CA ${CA_CRT} -CAkey ${CA_KEY} ` +
     `-CAserial ${CA_SRL} -out ${p.crt} -days 3650 -sha256`);
  fs.chmodSync(p.key, 0o600);
  fs.chmodSync(p.crt, 0o644);
  try { fs.unlinkSync(p.csr); } catch (_) {}
  return p;
}

function buildOvpnText(name, p) {
  const meta = readMeta();
  const srv = meta.server || {};
  const proto = srv.proto || 'udp';
  const port  = srv.port  || (proto === 'tcp' ? 443 : 1194);
  const host  = srv.public_ip || publicIP();

  const ca        = fs.readFileSync(CA_CRT, 'utf8').trim();
  const cert      = fs.readFileSync(p.crt, 'utf8').trim();
  const key       = fs.readFileSync(p.key, 'utf8').trim();
  const tlsCrypt  = fs.readFileSync(TLS_CRYPT, 'utf8').trim();

  return `# ${name}.ovpn -- generated ${new Date().toISOString()}
client
dev tun
proto ${proto}
remote ${host} ${port}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA256
cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM
tls-version-min 1.2
verb 3

<ca>
${ca}
</ca>
<cert>
${cert}
</cert>
<key>
${key}
</key>
<tls-crypt>
${tlsCrypt}
</tls-crypt>
`;
}

function addClient(name) {
  safeName(name);
  if (!fs.existsSync(CA_CRT)) {
    throw new Error('PKI not initialized — call installAndInitServer first');
  }
  const p = generateClientCert(name);
  const ovpn = buildOvpnText(name, p);
  writeFile(p.ovpn, ovpn, 0o600);

  const meta = readMeta();
  meta.clients = meta.clients || {};
  meta.clients[name] = {
    name,
    created_at: new Date().toISOString(),
    revoked: false,
  };
  writeMeta(meta);

  return { name, ovpn_text: ovpn, ovpn_path: p.ovpn };
}

function revokeClient(name) {
  safeName(name);
  const p = clientPaths(name);
  if (!fs.existsSync(p.crt)) {
    throw new Error(`unknown client '${name}'`);
  }

  const r = shTry(`openssl ca -revoke ${p.crt} -keyfile ${CA_KEY} -cert ${CA_CRT} ` +
                  `-config ${OPENSSL_CNF}`);
  shTry(`openssl ca -gencrl -keyfile ${CA_KEY} -cert ${CA_CRT} ` +
        `-out ${CRL_PEM} -config ${OPENSSL_CNF}`);
  try { fs.chmodSync(CRL_PEM, 0o644); } catch (_) {}

  // Remove client artifacts (key/profile); keep .crt for CRL audit trail.
  try { fs.unlinkSync(p.key); }  catch (_) {}
  try { fs.unlinkSync(p.ovpn); } catch (_) {}

  const meta = readMeta();
  if (meta.clients && meta.clients[name]) {
    meta.clients[name].revoked = true;
    meta.clients[name].revoked_at = new Date().toISOString();
    writeMeta(meta);
  }

  // Reload server so CRL takes effect (SIGHUP via systemctl reload).
  shTry(`systemctl reload ${SYSTEMD_UNIT}.service`);

  return { name, revoked: true, openssl_ok: r.ok };
}

function listClients() {
  const meta = readMeta();
  const map  = meta.clients || {};
  return Object.keys(map).map(n => ({
    name:       map[n].name,
    created_at: map[n].created_at,
    revoked:    !!map[n].revoked,
    revoked_at: map[n].revoked_at || null,
    has_profile: fs.existsSync(clientPaths(n).ovpn),
  }));
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

function parseStatusLog() {
  if (!fs.existsSync(STATUS_LOG)) return [];
  const lines = fs.readFileSync(STATUS_LOG, 'utf8').split('\n');
  const clients = [];
  let inClientList = false;
  for (const line of lines) {
    if (line.startsWith('OpenVPN CLIENT LIST')) { inClientList = true; continue; }
    if (line.startsWith('ROUTING TABLE'))       { inClientList = false; continue; }
    if (!inClientList) continue;
    if (line.startsWith('Common Name') || line.startsWith('Updated,')) continue;
    if (!line.trim()) continue;
    const parts = line.split(',');
    if (parts.length < 5) continue;
    clients.push({
      name:       parts[0],
      real_addr:  parts[1],
      bytes_recv: Number(parts[2]) || 0,
      bytes_sent: Number(parts[3]) || 0,
      since:      parts[4],
    });
  }
  return clients;
}

function getStatus() {
  const meta = readMeta();
  const srv  = meta.server || {};
  const sys  = shTry(`systemctl is-active ${SYSTEMD_UNIT}.service`);
  const running = sys.ok && sys.out.trim() === 'active';

  let listening_on = null;
  const ssOut = shTry(`ss -lnup 2>/dev/null | grep -E ':${srv.port || 1194}\\b'`);
  if (ssOut.ok && ssOut.out.trim()) {
    listening_on = ssOut.out.trim().split('\n')[0];
  }

  return {
    running,
    proto:        srv.proto || 'udp',
    port:         srv.port  || 1194,
    subnet:       srv.subnet,
    public_ip:    srv.public_ip,
    listening_on,
    connected_clients: parseStatusLog(),
  };
}

// ---------------------------------------------------------------------------
// Teardown
// ---------------------------------------------------------------------------

function uninstallAll() {
  shTry(`systemctl stop ${SYSTEMD_UNIT}.service`);
  shTry(`systemctl disable ${SYSTEMD_UNIT}.service`);
  try { fs.unlinkSync(SERVER_LINK); } catch (_) {}
  // Remove all state, including PKI and profiles
  shTry(`rm -rf ${STATE_DIR}`);
  shTry('rm -f /etc/sysctl.d/99-mes-openvpn.conf');
  return { ok: true, removed: STATE_DIR };
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  installAndInitServer,
  addClient,
  revokeClient,
  listClients,
  getStatus,
  uninstallAll,

  // exposed for tests / debugging
  _internal: {
    STATE_DIR, PKI_DIR, CLIENTS_DIR, PROFILES_DIR,
    buildServerConf, parseStatusLog, clientPaths,
  },
};
