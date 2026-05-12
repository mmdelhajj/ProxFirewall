'use strict';
/*
 * ipsec.js — IPsec / IKEv2 VPN server (strongSwan).
 *
 * Adds an IKEv2 VPN endpoint to the box. Used by customers who:
 *   - Want native iOS / macOS VPN integration (works without any 3rd-party app)
 *   - Need to traverse business firewalls that block WireGuard's UDP ports
 *   - Prefer username+password auth (EAP-MSCHAPv2) over key files
 *
 * Auth: IKEv2 + EAP-MSCHAPv2 with a self-signed server cert (CA generated
 * on first setup). iOS/macOS/Windows all speak this out of the box.
 *
 * Network requirements:
 *   Requires UDP/500 + UDP/4500 reachable from the WAN side. In Router or
 *   Bridge mode the box is on the WAN; in Simple mode (ARP spoof) it is
 *   NOT on the WAN, so the customer's actual gateway must port-forward
 *   500+4500 to the Pi for this to be reachable from the internet.
 *
 * Public API:
 *   install()                                              -> { ok }
 *   setupServer({domain_or_ip, ca_cn?})                    -> { ok, ca_cert, server_cn }
 *   addUser({username, password})                          -> { ok, username }
 *   removeUser({username})                                 -> { ok }
 *   listUsers()                                            -> [ { username } ]
 *   generateMobileConfig({username, password, vpn_name})   -> { ok, plist }
 *   getStatus()                                            -> { running, ... }
 */

const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');

const STATE_DIR   = '/etc/mes-ipsec';
const PKI_DIR     = path.join(STATE_DIR, 'pki');
const META_FILE   = path.join(STATE_DIR, 'meta.json');
const IPSEC_CONF  = '/etc/ipsec.conf';
const IPSEC_SECRETS = '/etc/ipsec.secrets';
const SERVER_KEY  = path.join(PKI_DIR, 'server-key.pem');
const SERVER_CRT  = path.join(PKI_DIR, 'server-cert.pem');
const CA_KEY      = path.join(PKI_DIR, 'ca-key.pem');
const CA_CRT      = path.join(PKI_DIR, 'ca-cert.pem');

const MES_MARKER  = '# === mes-ipsec users ===';
const MES_END     = '# === end mes-ipsec users ===';

function sh(cmd, opts = {}) {
  try { return execSync(cmd, { encoding: 'utf8', timeout: 15_000, stdio: ['ignore', 'pipe', 'pipe'], ...opts }).trim(); }
  catch (e) { return null; }
}

function shThrow(cmd, opts = {}) {
  return execSync(cmd, { encoding: 'utf8', timeout: 60_000, stdio: ['ignore', 'pipe', 'pipe'], ...opts }).trim();
}

function have(bin) { return !!sh(`which ${bin}`); }

function ensureDirs() {
  try { fs.mkdirSync(STATE_DIR, { recursive: true, mode: 0o750 }); } catch {}
  try { fs.mkdirSync(PKI_DIR, { recursive: true, mode: 0o700 }); } catch {}
}

function readMeta() {
  try { return JSON.parse(fs.readFileSync(META_FILE, 'utf8')); } catch { return {}; }
}
function writeMeta(m) { fs.writeFileSync(META_FILE, JSON.stringify(m, null, 2), { mode: 0o600 }); }

// ─── install ────────────────────────────────────────────────────────────

function install() {
  if (have('ipsec') || have('swanctl')) {
    return { ok: true, already_installed: true };
  }
  try {
    shThrow('DEBIAN_FRONTEND=noninteractive apt-get update -y', { timeout: 120_000 });
    shThrow('DEBIAN_FRONTEND=noninteractive apt-get install -y strongswan strongswan-pki libcharon-extra-plugins libstrongswan-extra-plugins', { timeout: 240_000 });
  } catch (e) {
    return { ok: false, error: 'apt_install_failed', detail: (e.message || '').slice(0, 500) };
  }
  return { ok: true, installed: true };
}

// ─── PKI ────────────────────────────────────────────────────────────────

function _generateCA(ca_cn) {
  if (fs.existsSync(CA_KEY) && fs.existsSync(CA_CRT)) return;
  // Use strongswan pki if available, fall back to openssl
  if (have('pki')) {
    try {
      shThrow(`pki --gen --type rsa --size 4096 --outform pem > ${CA_KEY}`, { shell: '/bin/bash' });
      fs.chmodSync(CA_KEY, 0o600);
      shThrow(`pki --self --ca --lifetime 3650 --in ${CA_KEY} --type rsa --dn "CN=${ca_cn}" --outform pem > ${CA_CRT}`, { shell: '/bin/bash' });
      fs.chmodSync(CA_CRT, 0o644);
      return;
    } catch (e) { /* fall through to openssl */ }
  }
  shThrow(`openssl genrsa -out ${CA_KEY} 4096`);
  fs.chmodSync(CA_KEY, 0o600);
  shThrow(`openssl req -x509 -new -nodes -key ${CA_KEY} -sha256 -days 3650 -out ${CA_CRT} -subj '/CN=${ca_cn}'`);
  fs.chmodSync(CA_CRT, 0o644);
}

function _generateServerCert(domain_or_ip) {
  if (fs.existsSync(SERVER_KEY) && fs.existsSync(SERVER_CRT)) return;
  // Server cert with SAN matching what the client will use to connect
  const isIp = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(domain_or_ip);
  const sanType = isIp ? 'IP' : 'DNS';
  shThrow(`openssl genrsa -out ${SERVER_KEY} 2048`);
  fs.chmodSync(SERVER_KEY, 0o600);
  const csr = path.join(PKI_DIR, 'server.csr');
  shThrow(`openssl req -new -key ${SERVER_KEY} -out ${csr} -subj '/CN=${domain_or_ip}'`);
  // Sign with our CA and add the proper subjectAltName for iOS' strict cert check
  const extFile = path.join(PKI_DIR, 'server-ext.cnf');
  fs.writeFileSync(extFile, [
    'subjectAltName = ' + sanType + ':' + domain_or_ip,
    'extendedKeyUsage = serverAuth, 1.3.6.1.5.5.8.2.2',
    'keyUsage = digitalSignature, keyEncipherment',
  ].join('\n') + '\n');
  shThrow(`openssl x509 -req -in ${csr} -CA ${CA_CRT} -CAkey ${CA_KEY} -CAcreateserial -out ${SERVER_CRT} -days 3650 -sha256 -extfile ${extFile}`);
  fs.chmodSync(SERVER_CRT, 0o644);
  try { fs.unlinkSync(csr); } catch {}
}

// ─── config writers ─────────────────────────────────────────────────────

function _writeIpsecConf(domain_or_ip) {
  const cfg = `# /etc/ipsec.conf — generated by mes-ipsec
config setup
    charondebug="ike 1, knl 1, cfg 0"
    uniqueids=no

conn mes-ikev2-eap
    auto=add
    compress=no
    type=tunnel
    keyexchange=ikev2
    fragmentation=yes
    forceencaps=yes
    dpdaction=clear
    dpddelay=300s
    rekey=no
    left=%any
    leftid=@${domain_or_ip}
    leftcert=${SERVER_CRT}
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    right=%any
    rightid=%any
    rightauth=eap-mschapv2
    rightdns=1.1.1.1,8.8.8.8
    rightsourceip=10.20.30.0/24
    rightsendcert=never
    eap_identity=%identity
    ike=chacha20poly1305-sha512-curve25519-prfsha512,aes256gcm16-sha384-prfsha384-ecp384,aes256-sha256-modp2048,aes256-sha1-modp2048,3des-sha1-modp1024!
    esp=chacha20poly1305-sha512,aes256gcm16-ecp384,aes256-sha256,aes256-sha1,3des-sha1!
`;
  fs.writeFileSync(IPSEC_CONF, cfg, { mode: 0o644 });
}

function _ensureSecretsBlock() {
  let txt = '';
  try { txt = fs.readFileSync(IPSEC_SECRETS, 'utf8'); } catch {}
  // Strip any prior managed block (idempotent), and ensure the CA line is set
  if (txt.indexOf(MES_MARKER) !== -1) {
    const re = new RegExp(MES_MARKER + '[\\s\\S]*?' + MES_END, 'm');
    txt = txt.replace(re, '');
  }
  const caLine = `: RSA ${SERVER_KEY}\n`;
  if (txt.indexOf(caLine.trim()) === -1) {
    txt = (txt.trim() ? (txt.trim() + '\n') : '') + caLine;
  }
  txt += '\n' + MES_MARKER + '\n' + MES_END + '\n';
  fs.writeFileSync(IPSEC_SECRETS, txt, { mode: 0o600 });
  fs.chmodSync(IPSEC_SECRETS, 0o600);
}

function _readManagedUsers() {
  let txt = '';
  try { txt = fs.readFileSync(IPSEC_SECRETS, 'utf8'); } catch { return []; }
  const start = txt.indexOf(MES_MARKER);
  const end   = txt.indexOf(MES_END);
  if (start === -1 || end === -1) return [];
  const block = txt.slice(start + MES_MARKER.length, end);
  const users = [];
  for (const line of block.split('\n')) {
    const m = line.match(/^([a-zA-Z0-9._-]+)\s*:\s*EAP\s*"(.*)"\s*$/);
    if (m) users.push({ username: m[1] });
  }
  return users;
}

function _writeManagedUsers(users) {
  let txt = '';
  try { txt = fs.readFileSync(IPSEC_SECRETS, 'utf8'); } catch {}
  const start = txt.indexOf(MES_MARKER);
  const end   = txt.indexOf(MES_END);
  const block = MES_MARKER + '\n' + users.map(u => `${u.username} : EAP "${u.password.replace(/"/g, '\\"')}"`).join('\n') + (users.length ? '\n' : '') + MES_END;
  let next;
  if (start !== -1 && end !== -1) {
    next = txt.slice(0, start) + block + txt.slice(end + MES_END.length);
  } else {
    next = (txt.trim() ? (txt.trim() + '\n') : '') + block + '\n';
  }
  // Ensure CA line for server cert is present
  if (next.indexOf(': RSA ' + SERVER_KEY) === -1) {
    next = `: RSA ${SERVER_KEY}\n` + next;
  }
  fs.writeFileSync(IPSEC_SECRETS, next, { mode: 0o600 });
  fs.chmodSync(IPSEC_SECRETS, 0o600);
}

function _reloadStrongswan() {
  // strongSwan 6.x ships only `strongswan.service` + swanctl (no legacy
  // `ipsec` binary). strongSwan 5.x ships `strongswan-starter.service`
  // and the legacy `ipsec` CLI which speaks /etc/ipsec.conf. We support
  // both — try -starter first (uses our ipsec.conf), fall back to the
  // modern `strongswan` unit (which needs an extra swanctl import).
  if (sh('systemctl list-unit-files strongswan-starter.service 2>/dev/null | grep -q strongswan-starter')) {
    if (sh('systemctl is-active strongswan-starter 2>/dev/null') === 'active') {
      sh('systemctl reload strongswan-starter || systemctl restart strongswan-starter');
    } else {
      sh('systemctl enable --now strongswan-starter');
    }
  } else if (sh('systemctl list-unit-files strongswan.service 2>/dev/null | grep -q strongswan')) {
    if (sh('systemctl is-active strongswan 2>/dev/null') !== 'active') {
      sh('systemctl enable --now strongswan');
    }
    // For strongSwan 6 there's no /etc/ipsec.conf reader; users will need
    // a swanctl.conf import. We write a best-effort swanctl config too.
    _writeSwanctlConf();
    sh('swanctl --load-all 2>/dev/null || /usr/sbin/swanctl --load-all 2>/dev/null');
  }
  // Legacy `ipsec` CLI reload for 5.x setups
  sh('ipsec rereadall 2>/dev/null');
  sh('ipsec update 2>/dev/null');
}

function _writeSwanctlConf() {
  // Minimal swanctl-format mirror of the conn defined in /etc/ipsec.conf,
  // so strongSwan 6.x can serve it. Users still go through our `addUser`
  // path; we just translate the secrets format.
  const meta = readMeta();
  if (!meta.domain_or_ip) return;
  const swanctlDir = '/etc/swanctl';
  try { fs.mkdirSync(swanctlDir + '/conf.d', { recursive: true }); } catch {}
  try { fs.mkdirSync(swanctlDir + '/x509', { recursive: true }); } catch {}
  try { fs.mkdirSync(swanctlDir + '/x509ca', { recursive: true }); } catch {}
  try { fs.mkdirSync(swanctlDir + '/private', { recursive: true }); } catch {}
  try { fs.copyFileSync(SERVER_CRT, swanctlDir + '/x509/mes-server.pem'); } catch {}
  try { fs.copyFileSync(SERVER_KEY, swanctlDir + '/private/mes-server.pem'); fs.chmodSync(swanctlDir + '/private/mes-server.pem', 0o600); } catch {}
  try { fs.copyFileSync(CA_CRT,     swanctlDir + '/x509ca/mes-ca.pem'); } catch {}
  const conf = `# /etc/swanctl/conf.d/mes-ipsec.conf — generated by mes-ipsec
connections {
    mes-ikev2-eap {
        version = 2
        proposals = aes256gcm16-sha384-prfsha384-ecp384,aes256-sha256-modp2048,default
        rekey_time = 0s
        pools = mes-pool
        fragmentation = yes
        dpd_delay = 300s
        send_certreq = no
        local_addrs  = %any
        local {
            certs = mes-server.pem
            id = ${meta.domain_or_ip}
        }
        remote {
            auth = eap-mschapv2
            eap_id = %any
        }
        children {
            mes-ikev2-eap-children {
                local_ts = 0.0.0.0/0
                rekey_time = 0s
                dpd_action = clear
                esp_proposals = aes256gcm16-ecp384,aes256-sha256,default
            }
        }
    }
}
pools {
    mes-pool {
        addrs = 10.20.30.0/24
        dns = 1.1.1.1,8.8.8.8
    }
}
secrets {
    private-mes-server {
        file = mes-server.pem
    }
${_buildSwanctlEapSecrets()}
}
`;
  fs.writeFileSync(swanctlDir + '/conf.d/mes-ipsec.conf', conf, { mode: 0o600 });
}

function _buildSwanctlEapSecrets() {
  // Emit `eap-foo { id = user; secret = "..." }` blocks for each managed user.
  let txt = '';
  try { txt = fs.readFileSync(IPSEC_SECRETS, 'utf8'); } catch { return ''; }
  const start = txt.indexOf(MES_MARKER);
  const end   = txt.indexOf(MES_END);
  if (start === -1 || end === -1) return '';
  const block = txt.slice(start + MES_MARKER.length, end);
  let out = '';
  let i = 0;
  for (const line of block.split('\n')) {
    const m = line.match(/^([a-zA-Z0-9._-]+)\s*:\s*EAP\s*"(.*)"\s*$/);
    if (m) {
      i++;
      out += `    eap-mes-${i} {
        id = ${m[1]}
        secret = "${m[2].replace(/"/g, '\\"')}"
    }
`;
    }
  }
  return out;
}

function _enableIpForward() {
  sh('sysctl -w net.ipv4.ip_forward=1');
  sh('sysctl -w net.ipv4.conf.all.accept_redirects=0');
  sh('sysctl -w net.ipv4.conf.all.send_redirects=0');
  const f = '/etc/sysctl.d/99-mes-ipsec.conf';
  if (!fs.existsSync(f)) {
    fs.writeFileSync(f,
      'net.ipv4.ip_forward=1\n' +
      'net.ipv4.conf.all.accept_redirects=0\n' +
      'net.ipv4.conf.all.send_redirects=0\n',
      { mode: 0o644 });
  }
}

// ─── public API ─────────────────────────────────────────────────────────

function setupServer(opts = {}) {
  if (!have('openssl')) return { ok: false, error: 'openssl_missing', hint: 'apt-get install -y openssl' };
  if (!have('ipsec') && !have('swanctl')) {
    return { ok: false, error: 'strongswan_not_installed', hint: 'Call install() first' };
  }
  const domain_or_ip = String(opts.domain_or_ip || '').trim();
  if (!domain_or_ip) return { ok: false, error: 'domain_or_ip_required' };
  const ca_cn = String(opts.ca_cn || 'mes-ipsec-ca').trim();

  ensureDirs();
  try {
    _generateCA(ca_cn);
    _generateServerCert(domain_or_ip);
  } catch (e) {
    return { ok: false, error: 'pki_generation_failed', detail: (e.message || '').slice(0, 500) };
  }

  // Symlink server cert/key into strongswan's expected locations so swanctl
  // and ipsec.conf can both find them.
  try { fs.mkdirSync('/etc/ipsec.d/certs', { recursive: true }); } catch {}
  try { fs.mkdirSync('/etc/ipsec.d/private', { recursive: true }); } catch {}
  try { fs.mkdirSync('/etc/ipsec.d/cacerts', { recursive: true }); } catch {}
  try { fs.copyFileSync(SERVER_CRT, '/etc/ipsec.d/certs/mes-server.pem'); } catch {}
  try { fs.copyFileSync(SERVER_KEY, '/etc/ipsec.d/private/mes-server.pem'); fs.chmodSync('/etc/ipsec.d/private/mes-server.pem', 0o600); } catch {}
  try { fs.copyFileSync(CA_CRT,     '/etc/ipsec.d/cacerts/mes-ca.pem'); } catch {}

  _writeIpsecConf(domain_or_ip);
  _ensureSecretsBlock();
  _enableIpForward();
  _reloadStrongswan();

  const meta = readMeta();
  meta.domain_or_ip = domain_or_ip;
  meta.ca_cn = ca_cn;
  meta.setup_at = new Date().toISOString();
  writeMeta(meta);

  let ca_cert = '';
  try { ca_cert = fs.readFileSync(CA_CRT, 'utf8'); } catch {}
  return { ok: true, domain_or_ip, ca_cn, ca_cert, server_cn: domain_or_ip };
}

function addUser(opts = {}) {
  const username = String(opts.username || '').trim();
  const password = String(opts.password || '');
  if (!/^[a-zA-Z0-9._-]{1,32}$/.test(username)) return { ok: false, error: 'bad_username' };
  if (!password || password.length < 6 || password.length > 128) return { ok: false, error: 'bad_password' };
  ensureDirs();
  const users = _readManagedUsers();
  if (users.find(u => u.username === username)) return { ok: false, error: 'user_exists' };
  // We need the password to write the secrets file; read it back as it isn't stored on disk anywhere else
  users.push({ username, password });
  _writeManagedUsers(users);
  _reloadStrongswan();
  return { ok: true, username };
}

function removeUser(opts = {}) {
  const username = String(opts.username || '').trim();
  if (!/^[a-zA-Z0-9._-]{1,32}$/.test(username)) return { ok: false, error: 'bad_username' };
  // We need to keep current passwords intact while only removing one user.
  // Parse, drop, re-write — but we can only re-write a user we know the
  // password of. Solution: read the raw secrets, strip the matching line,
  // and write it back directly (don't re-derive from _readManagedUsers).
  let txt = '';
  try { txt = fs.readFileSync(IPSEC_SECRETS, 'utf8'); } catch { return { ok: false, error: 'no_secrets_file' }; }
  const start = txt.indexOf(MES_MARKER);
  const end   = txt.indexOf(MES_END);
  if (start === -1 || end === -1) return { ok: false, error: 'managed_block_missing' };
  const head  = txt.slice(0, start + MES_MARKER.length);
  const tail  = txt.slice(end);
  const block = txt.slice(start + MES_MARKER.length, end);
  const re = new RegExp('^' + username.replace(/[.+*?^$()[\]{}|\\]/g, '\\$&') + '\\s*:\\s*EAP\\s*".*"\\s*$', 'm');
  if (!re.test(block)) return { ok: false, error: 'user_not_found' };
  const next = head + block.replace(re, '').replace(/\n\n+/g, '\n') + tail;
  fs.writeFileSync(IPSEC_SECRETS, next, { mode: 0o600 });
  fs.chmodSync(IPSEC_SECRETS, 0o600);
  _reloadStrongswan();
  return { ok: true, username };
}

function listUsers() {
  return _readManagedUsers().map(u => ({ username: u.username }));
}

function generateMobileConfig(opts = {}) {
  const username = String(opts.username || '').trim();
  const password = String(opts.password || '');
  const vpn_name = String(opts.vpn_name || 'mes IPsec VPN').slice(0, 40);
  if (!/^[a-zA-Z0-9._-]{1,32}$/.test(username)) return { ok: false, error: 'bad_username' };

  const meta = readMeta();
  if (!meta.domain_or_ip) return { ok: false, error: 'server_not_setup' };

  // Embed the CA cert as base64 so iOS trusts the self-signed server cert.
  let caDer = '';
  try {
    // Convert PEM to DER → base64
    const pem = fs.readFileSync(CA_CRT, 'utf8');
    const b = pem.replace(/-----BEGIN CERTIFICATE-----/g, '')
                 .replace(/-----END CERTIFICATE-----/g, '')
                 .replace(/\s+/g, '');
    // For mobileconfig, the PayloadContent for com.apple.security.root takes
    // raw DER as base64; b is already the cert's base64-encoded DER. Apple's
    // tools normally wrap to 76 cols, but most parsers accept any.
    caDer = b;
  } catch {}

  const payloadUuid  = crypto.randomUUID();
  const vpnUuid      = crypto.randomUUID();
  const caUuid       = crypto.randomUUID();
  const orgId        = 'lb.net.mes.vpn';

  const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadIdentifier</key><string>${orgId}.${username}</string>
  <key>PayloadUUID</key><string>${payloadUuid}</string>
  <key>PayloadDisplayName</key><string>${vpn_name}</string>
  <key>PayloadDescription</key><string>IKEv2 VPN profile for ${username}</string>
  <key>PayloadOrganization</key><string>mes Network</string>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key><string>com.apple.security.root</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadIdentifier</key><string>${orgId}.ca.${caUuid}</string>
      <key>PayloadUUID</key><string>${caUuid}</string>
      <key>PayloadDisplayName</key><string>${vpn_name} CA</string>
      <key>PayloadCertificateFileName</key><string>mes-ca.cer</string>
      <key>PayloadContent</key>
      <data>
${caDer.replace(/(.{64})/g, '$1\n')}
      </data>
    </dict>
    <dict>
      <key>PayloadType</key><string>com.apple.vpn.managed</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadIdentifier</key><string>${orgId}.vpn.${vpnUuid}</string>
      <key>PayloadUUID</key><string>${vpnUuid}</string>
      <key>PayloadDisplayName</key><string>${vpn_name}</string>
      <key>UserDefinedName</key><string>${vpn_name}</string>
      <key>VPNType</key><string>IKEv2</string>
      <key>IKEv2</key>
      <dict>
        <key>RemoteAddress</key><string>${meta.domain_or_ip}</string>
        <key>RemoteIdentifier</key><string>${meta.domain_or_ip}</string>
        <key>LocalIdentifier</key><string>${username}</string>
        <key>AuthenticationMethod</key><string>None</string>
        <key>ExtendedAuthEnabled</key><integer>1</integer>
        <key>AuthName</key><string>${username}</string>
        <key>AuthPassword</key><string>${password.replace(/[<>&]/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]))}</string>
        <key>UseConfigurationAttributeInternalIPSubnet</key><integer>0</integer>
        <key>DeadPeerDetectionRate</key><string>Medium</string>
        <key>DisableMOBIKE</key><integer>0</integer>
        <key>DisableRedirect</key><integer>0</integer>
        <key>EnableCertificateRevocationCheck</key><integer>0</integer>
        <key>EnablePFS</key><integer>1</integer>
        <key>NATKeepAliveInterval</key><integer>20</integer>
        <key>IKESecurityAssociationParameters</key>
        <dict>
          <key>EncryptionAlgorithm</key><string>AES-256-GCM</string>
          <key>IntegrityAlgorithm</key><string>SHA2-384</string>
          <key>DiffieHellmanGroup</key><integer>20</integer>
          <key>LifeTimeInMinutes</key><integer>1440</integer>
        </dict>
        <key>ChildSecurityAssociationParameters</key>
        <dict>
          <key>EncryptionAlgorithm</key><string>AES-256-GCM</string>
          <key>IntegrityAlgorithm</key><string>SHA2-384</string>
          <key>DiffieHellmanGroup</key><integer>20</integer>
          <key>LifeTimeInMinutes</key><integer>1440</integer>
        </dict>
      </dict>
    </dict>
  </array>
</dict>
</plist>
`;
  return { ok: true, plist, filename: `mes-ipsec-${username}.mobileconfig` };
}

function getStatus() {
  const meta = readMeta();
  const installed = have('ipsec') || have('swanctl');
  if (!installed) return { ok: true, installed: false, configured: false };

  let running = false;
  if (sh('systemctl is-active strongswan-starter 2>/dev/null') === 'active') running = true;
  else if (sh('systemctl is-active strongswan 2>/dev/null') === 'active') running = true;

  // Status: prefer legacy ipsec, fall back to swanctl
  let statusall = '';
  if (have('ipsec')) {
    try { statusall = sh('ipsec statusall 2>/dev/null') || ''; } catch {}
  } else if (have('swanctl')) {
    try { statusall = (sh('swanctl --list-sas 2>/dev/null') || '') + '\n' + (sh('swanctl --list-conns 2>/dev/null') || ''); } catch {}
  }

  // Parse connected user count + remote IPs from statusall
  const connections = [];
  for (const line of statusall.split('\n')) {
    const m = line.match(/^\s*mes-ikev2-eap.*ESTABLISHED.*?\s+(\d+\.\d+\.\d+\.\d+)\[/);
    if (m) connections.push({ remote_ip: m[1] });
    const m2 = line.match(/^\s*remote\s+'([^']+)'\s+@\s+(\d+\.\d+\.\d+\.\d+)/);  // swanctl line shape
    if (m2) connections.push({ remote_id: m2[1], remote_ip: m2[2] });
  }

  return {
    ok: true,
    installed,
    configured: !!meta.domain_or_ip,
    domain_or_ip: meta.domain_or_ip || null,
    running,
    users: _readManagedUsers().length,
    connections,
    status_excerpt: statusall.slice(0, 1500),
  };
}

module.exports = {
  install,
  setupServer,
  addUser,
  removeUser,
  listUsers,
  generateMobileConfig,
  getStatus,
};
