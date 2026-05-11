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
  if (!have('tc')) return { ok: false, error: 'tc_not_installed' };
  const wan = _state.wan_iface || detectWan();
  if (!wan) return { ok: false, error: 'wan_iface_unknown' };

  // Use IFB for ingress shaping (download cap) — kept simple: only mark + apply
  // a leaf class on egress. Per-MAC tc class on existing cake is messy, so we
  // emulate caps via iptables -m hashlimit which is simpler + works without
  // tearing down cake.
  const downK = parseInt(down_kbps) || 0;
  const upK   = parseInt(up_kbps)   || 0;
  // Remove prior cap rules for this MAC
  while (sh(`iptables -C FORWARD -m mac --mac-source ${m} -m comment --comment "mes_qos_cap_${m.replace(/:/g,'')}" -j ACCEPT 2>/dev/null`) !== null) {
    sh(`iptables -D FORWARD -m mac --mac-source ${m} -m comment --comment "mes_qos_cap_${m.replace(/:/g,'')}" -j ACCEPT`);
  }
  if (upK > 0) {
    sh(`iptables -A FORWARD -m mac --mac-source ${m} -m hashlimit ` +
       `--hashlimit-above ${upK}kb/s --hashlimit-burst ${Math.max(upK*2, 64)}kb ` +
       `--hashlimit-mode srcmac --hashlimit-name mes_up_${m.replace(/:/g,'')} ` +
       `-m comment --comment "mes_qos_cap_${m.replace(/:/g,'')}" -j DROP`);
  }
  _state.device_caps[m] = { down_kbps: downK, up_kbps: upK };
  save();
  return { ok: true, mac: m, down_kbps: downK, up_kbps: upK, note: upK > 0 ? 'upload cap applied via hashlimit' : 'cap cleared' };
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
