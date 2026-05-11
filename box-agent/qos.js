'use strict';
/*
 * qos.js — QoS / Smart Queue / per-device priority + cap.
 *
 * Uses tc qdisc cake (preferred) or fq_codel (fallback) on the WAN iface.
 * Per-MAC priority and rate-cap via iptables MARK + tc class.
 *
 * Class IDs:
 *   1:1   root HTB (only used if user requests caps; cake handles fairness alone)
 *   1:10  high     prio 1
 *   1:20  normal   prio 2  (default)
 *   1:30  low      prio 3
 *   1:40  throttle prio 4 (capped to 256kbit)
 *
 * State persisted at /var/lib/mes-box-agent/qos.state.json
 */

const fs   = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const STATE_PATH = '/var/lib/mes-box-agent/qos.state.json';
try { fs.mkdirSync(path.dirname(STATE_PATH), { recursive: true }); } catch {}

let _state = {
  enabled: false,
  wan_iface: null,
  qdisc: null,            // 'cake' | 'fq_codel'
  down_mbps: 0,
  up_mbps: 0,
  device_priorities: {},  // mac → 'high'|'normal'|'low'|'throttle'
  device_caps: {},        // mac → { down_kbps, up_kbps }
  applied_at: null,
};
try { _state = { ..._state, ...JSON.parse(fs.readFileSync(STATE_PATH, 'utf8')) }; } catch {}
function save() { try { fs.writeFileSync(STATE_PATH, JSON.stringify(_state, null, 2)); } catch {} }

function sh(cmd) {
  try { return execSync(cmd, { encoding: 'utf8', timeout: 8_000, stdio: ['ignore', 'pipe', 'pipe'] }).trim(); }
  catch { return null; }
}

function have(bin) { return !!sh(`which ${bin}`); }

function cakeAvailable() {
  // Probe by running tc qdisc add on a temp ifb if available. Cheaper: parse modules list.
  const probe = sh('tc qdisc add dev lo root cake 2>&1 || true');
  // Cleanup
  sh('tc qdisc del dev lo root 2>/dev/null');
  return probe !== null && !/Unknown qdisc/i.test(probe);
}

function detectWan() {
  const out = sh('ip route show default | head -1');
  if (!out) return null;
  const m = out.match(/dev (\S+)/);
  return m ? m[1] : null;
}

function normMac(mac) {
  if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(mac || '')) return null;
  return mac.toLowerCase();
}

const PRIO_CLASS = {
  high:     { id: 10, prio: 1 },
  normal:   { id: 20, prio: 2 },
  low:      { id: 30, prio: 3 },
  throttle: { id: 40, prio: 4 },
};

function applyCake({ wan_iface, down_mbps, up_mbps } = {}) {
  if (!have('tc')) return { ok: false, error: 'tc_not_installed' };
  const wan = wan_iface || _state.wan_iface || detectWan();
  if (!wan) return { ok: false, error: 'wan_iface_unknown' };
  const down = parseInt(down_mbps) || 100;
  const up   = parseInt(up_mbps)   || 20;

  const useCake = cakeAvailable();
  const qdisc = useCake ? 'cake' : 'fq_codel';

  // Egress on WAN (uplink shaping)
  if (useCake) {
    sh(`tc qdisc replace dev ${wan} root cake bandwidth ${up}mbit`);
  } else {
    sh(`tc qdisc replace dev ${wan} root fq_codel`);
  }

  _state.enabled = true;
  _state.wan_iface = wan;
  _state.qdisc = qdisc;
  _state.down_mbps = down;
  _state.up_mbps = up;
  _state.applied_at = Date.now();
  save();

  // Re-apply per-device priorities
  for (const [mac, cls] of Object.entries(_state.device_priorities)) {
    try { _applyDevicePrio(mac, cls); } catch {}
  }
  return { ok: true, qdisc, wan_iface: wan, down_mbps: down, up_mbps: up };
}

function _ensureMarkChain() {
  // Ensure mangle POSTROUTING has a jump to a dedicated chain (idempotent)
  if (sh(`iptables -t mangle -nL MES_QOS 2>/dev/null`) === null) {
    sh(`iptables -t mangle -N MES_QOS`);
  }
  if (sh(`iptables -t mangle -C POSTROUTING -j MES_QOS 2>/dev/null`) === null) {
    sh(`iptables -t mangle -A POSTROUTING -j MES_QOS`);
  }
  if (sh(`iptables -t mangle -nL MES_QOS_PRE 2>/dev/null`) === null) {
    sh(`iptables -t mangle -N MES_QOS_PRE`);
  }
  if (sh(`iptables -t mangle -C PREROUTING -j MES_QOS_PRE 2>/dev/null`) === null) {
    sh(`iptables -t mangle -A PREROUTING -j MES_QOS_PRE`);
  }
}

function _applyDevicePrio(mac, cls) {
  if (!PRIO_CLASS[cls]) return;
  _ensureMarkChain();
  const m = mac.toLowerCase();
  const mark = PRIO_CLASS[cls].id;
  // Drop any prior mark for this MAC
  for (const k of Object.keys(PRIO_CLASS)) {
    const oldMark = PRIO_CLASS[k].id;
    while (sh(`iptables -t mangle -C MES_QOS_PRE -m mac --mac-source ${m} -j MARK --set-mark ${oldMark} 2>/dev/null`) !== null) {
      if (sh(`iptables -t mangle -D MES_QOS_PRE -m mac --mac-source ${m} -j MARK --set-mark ${oldMark}`) === null) break;
    }
  }
  sh(`iptables -t mangle -A MES_QOS_PRE -m mac --mac-source ${m} -j MARK --set-mark ${mark}`);
}

function setDevicePriority({ mac, class: cls } = {}) {
  const m = normMac(mac);
  if (!m) return { ok: false, error: 'bad_mac' };
  if (!PRIO_CLASS[cls]) return { ok: false, error: 'bad_class', allowed: Object.keys(PRIO_CLASS) };
  _applyDevicePrio(m, cls);
  _state.device_priorities[m] = cls;
  save();
  return { ok: true, mac: m, class: cls };
}

function setDeviceCap({ mac, down_kbps, up_kbps } = {}) {
  const m = normMac(mac);
  if (!m) return { ok: false, error: 'bad_mac' };
  const downK = parseInt(down_kbps) || 0;
  const upK   = parseInt(up_kbps)   || 0;
  // Look up device IP from ARP — needed for DOWNLOAD cap which matches on
  // destination IP (no `--mac-destination` exists in iptables). Upload cap
  // can still use source MAC since that's preserved on egress packets.
  let devIp = null;
  try {
    const out = sh(`ip neigh show | grep -i ${m}`);
    if (out) devIp = (out.split(/\s+/)[0]) || null;
  } catch {}
  const tag = m.replace(/:/g, '');
  const comment = `mes_qos_cap_${tag}`;
  // Remove ALL prior cap rules for this MAC. `iptables -C` requires exact-match
  // including all match modules (hashlimit args), so the old approach missed
  // any rule whose spec differs (e.g. different rate, different burst).
  // Instead: dump `iptables -S FORWARD`, find lines that contain our comment,
  // and turn them into delete commands by swapping the leading `-A` for `-D`.
  const dropOldRules = () => {
    let listing;
    try { listing = execSync('iptables -S FORWARD', { encoding: 'utf8' }); }
    catch { return 0; }
    let removed = 0;
    for (const line of listing.split('\n')) {
      if (!line.startsWith('-A FORWARD')) continue;
      if (!line.includes(comment)) continue;
      const delCmd = 'iptables ' + line.replace(/^-A /, '-D ');
      try { execSync(delCmd, { stdio: 'ignore' }); removed++; } catch {}
    }
    return removed;
  };
  dropOldRules();
  // iptables `hashlimit-above NNNkb/s` is interpreted as kilo-BYTES per second
  // (not kilo-bits). User input is in kbps (kilo-BITS per second). Convert: /8.
  // Example: user sets 5000 kbps (5 Mbps) → pass 625kb/s to iptables (625 KB/s).
  const upKB   = Math.max(1, Math.round(upK   / 8));
  const downKB = Math.max(1, Math.round(downK / 8));
  // INSERT at top of FORWARD (-I FORWARD 1), NOT append. The simple-mode module
  // installs a `state RELATED,ESTABLISHED -j ACCEPT` rule that would accept
  // every TCP packet of an open connection before our hashlimit fires.
  //
  // Upload uses source-IP match (NOT `-m mac --mac-source`). xt_mac has been
  // observed to silently no-op in FORWARD chain on Pi 4 / certain kernels —
  // using source IP (which the agent already knows from ARP) is reliable.
  if (upK > 0 && devIp) {
    sh(`iptables -I FORWARD 1 -s ${devIp} -m hashlimit ` +
       `--hashlimit-above ${upKB}kb/s --hashlimit-burst ${Math.max(upKB, 32)}kb ` +
       `--hashlimit-mode srcip --hashlimit-name mes_up_${tag} ` +
       `-m comment --comment "${comment}" -j DROP`);
  }
  if (downK > 0 && devIp) {
    sh(`iptables -I FORWARD 1 -d ${devIp} -m hashlimit ` +
       `--hashlimit-above ${downKB}kb/s --hashlimit-burst ${Math.max(downKB, 32)}kb ` +
       `--hashlimit-mode dstip --hashlimit-name mes_dn_${tag} ` +
       `-m comment --comment "${comment}" -j DROP`);
  }
  const knownIps = new Set((_state.device_caps[m]?.known_ips || []));
  if (devIp) knownIps.add(devIp);
  _state.device_caps[m] = { down_kbps: downK, up_kbps: upK, known_ips: Array.from(knownIps), ip: devIp };
  save();
  const applied = [];
  if (upK > 0) applied.push(`upload @ ${upK} kbps`);
  if (downK > 0 && devIp) applied.push(`download @ ${downK} kbps (ip ${devIp})`);
  if (downK > 0 && !devIp) applied.push(`download skipped — device IP unknown (not in ARP)`);
  return { ok: true, mac: m, down_kbps: downK, up_kbps: upK, ip: devIp, note: applied.join(', ') || 'cap cleared' };
}

function getStatus() {
  const wan = _state.wan_iface || detectWan();
  const qdisc_now = wan ? sh(`tc qdisc show dev ${wan} root 2>/dev/null`) : null;
  return {
    ..._state,
    wan_iface_now: wan,
    current_qdisc: qdisc_now,
    cake_available: cakeAvailable(),
    tc_installed: have('tc'),
  };
}

function clear() {
  const wan = _state.wan_iface || detectWan();
  if (wan && have('tc')) {
    sh(`tc qdisc del dev ${wan} root 2>/dev/null`);
  }
  // Wipe iptables MES_QOS chains
  sh(`iptables -t mangle -F MES_QOS_PRE 2>/dev/null`);
  sh(`iptables -t mangle -F MES_QOS 2>/dev/null`);
  // Clear caps
  for (const mac of Object.keys(_state.device_caps)) {
    const m = mac;
    while (sh(`iptables -C FORWARD -m mac --mac-source ${m} -m comment --comment "mes_qos_cap_${m.replace(/:/g,'')}" -j DROP 2>/dev/null`) !== null) {
      sh(`iptables -D FORWARD -m mac --mac-source ${m} -m comment --comment "mes_qos_cap_${m.replace(/:/g,'')}" -j DROP`);
    }
  }
  _state = { enabled: false, wan_iface: null, qdisc: null, down_mbps: 0, up_mbps: 0,
             device_priorities: {}, device_caps: {}, applied_at: null };
  save();
  return { ok: true, cleared: true };
}

module.exports = { applyCake, setDevicePriority, setDeviceCap, getStatus, clear };
