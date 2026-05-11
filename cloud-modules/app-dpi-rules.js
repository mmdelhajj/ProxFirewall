'use strict';

/*
 * app-dpi-rules.js
 *
 * Self-contained module that converts captured TLS SNI / JA3 fingerprints
 * into actionable "block this app" rule suggestions, similar to how
 * Firewalla's app-blocking feature works under the hood.
 *
 * Data flow:
 *   1) Box agents capture TLS ClientHello -> extract SNI + JA3 hash.
 *   2) Cloud calls identifyApp({sni, ja3}) to recognize the app.
 *   3) UI groups identifications via identifyApps(handshakes).
 *   4) User clicks "Block TikTok" -> suggestBlockRule('TikTok') returns
 *      a rule object that the policy service can persist.
 *
 * No external dependencies. CommonJS export.
 */

// ---------------------------------------------------------------------------
// App database
// ---------------------------------------------------------------------------
//
// Each entry:
//   app:           canonical display name
//   category:      'social' | 'video' | 'messaging' | 'gaming' | 'cloud' | 'ai'
//   sni_patterns:  list of SNI globs. '*' matches one or more labels at the
//                  beginning of the host. Bare hostnames must match exactly.
//   ja3_md5:       optional list of known-good JA3 fingerprints for the app's
//                  client. Most pure-mobile apps have stable JA3s; browsers
//                  do not, so we leave them empty for browser-only apps.
//   common_ports:  ports usually associated with the app (for rule scope).

const APP_DB = [
  // -------- Social --------
  {
    app: 'TikTok',
    category: 'social',
    sni_patterns: [
      '*.tiktokv.com',
      '*.tiktokcdn.com',
      '*.tiktokcdn-us.com',
      '*.musical.ly',
      '*.byteoversea.com',
      '*.tiktok.com',
      'tiktok.com',
    ],
    ja3_md5: ['1a4b8e75c0ad5b8a8e9b03f2d7a96a14'],
    common_ports: [443],
  },
  {
    app: 'Instagram',
    category: 'social',
    sni_patterns: [
      '*.cdninstagram.com',
      '*.instagram.com',
      'instagram.com',
      'i.instagram.com',
    ],
    ja3_md5: [],
    common_ports: [443],
  },
  {
    app: 'Facebook',
    category: 'social',
    sni_patterns: [
      '*.facebook.com',
      '*.fbcdn.net',
      '*.fbsbx.com',
      'facebook.com',
    ],
    ja3_md5: [],
    common_ports: [443],
  },
  {
    app: 'Twitter',
    category: 'social',
    sni_patterns: [
      '*.twitter.com',
      '*.twimg.com',
      '*.x.com',
      'twitter.com',
      'x.com',
    ],
    ja3_md5: [],
    common_ports: [443],
  },
  {
    app: 'Snapchat',
    category: 'social',
    sni_patterns: [
      '*.snapchat.com',
      '*.sc-cdn.net',
      '*.snap-dev.net',
      'snapchat.com',
    ],
    ja3_md5: [],
    common_ports: [443],
  },
  {
    app: 'Reddit',
    category: 'social',
    sni_patterns: [
      '*.reddit.com',
      '*.redditmedia.com',
      '*.redd.it',
      'reddit.com',
    ],
    ja3_md5: [],
    common_ports: [443],
  },
  {
    app: 'LinkedIn',
    category: 'social',
    sni_patterns: [
      '*.linkedin.com',
      '*.licdn.com',
      'linkedin.com',
    ],
    ja3_md5: [],
    common_ports: [443],
  },

  // -------- Video --------
  {
    app: 'YouTube',
    category: 'video',
    sni_patterns: [
      '*.youtube.com',
      '*.googlevideo.com',
      '*.ytimg.com',
      'youtube.com',
      'youtu.be',
    ],
    ja3_md5: [],
    common_ports: [443],
  },
  {
    app: 'Netflix',
    category: 'video',
    sni_patterns: [
      '*.netflix.com',
      '*.nflxvideo.net',
      '*.nflximg.net',
      '*.nflxso.net',
      'netflix.com',
    ],
    ja3_md5: [],
    common_ports: [443],
  },
  {
    app: 'Twitch',
    category: 'video',
    sni_patterns: [
      '*.twitch.tv',
      '*.ttvnw.net',
      '*.jtvnw.net',
      'twitch.tv',
    ],
    ja3_md5: [],
    common_ports: [443],
  },
  {
    app: 'Disney+',
    category: 'video',
    sni_patterns: [
      '*.disneyplus.com',
      '*.disney-plus.net',
      '*.bamgrid.com',
      'disneyplus.com',
    ],
    ja3_md5: [],
    common_ports: [443],
  },
  {
    app: 'Hulu',
    category: 'video',
    sni_patterns: [
      '*.hulu.com',
      '*.huluim.com',
      '*.hulustream.com',
      'hulu.com',
    ],
    ja3_md5: [],
    common_ports: [443],
  },
  {
    app: 'HBO Max',
    category: 'video',
    sni_patterns: [
      '*.hbomax.com',
      '*.max.com',
      '*.hbomaxcdn.com',
      'hbomax.com',
    ],
    ja3_md5: [],
    common_ports: [443],
  },

  // -------- Messaging --------
  {
    app: 'WhatsApp',
    category: 'messaging',
    sni_patterns: [
      '*.whatsapp.com',
      '*.whatsapp.net',
      '*.wa.me',
      'whatsapp.com',
    ],
    ja3_md5: ['e7d705a3286e19ea42f587b344ee6865'],
    common_ports: [443, 5222],
  },
  {
    app: 'Telegram',
    category: 'messaging',
    sni_patterns: [
      '*.telegram.org',
      '*.t.me',
      '*.tdesktop.com',
      'telegram.org',
      't.me',
    ],
    ja3_md5: [],
    common_ports: [443],
  },
  {
    app: 'Signal',
    category: 'messaging',
    sni_patterns: [
      '*.signal.org',
      '*.signalusers.org',
      '*.whispersystems.org',
      'signal.org',
    ],
    ja3_md5: [],
    common_ports: [443],
  },
  {
    app: 'Discord',
    category: 'messaging',
    sni_patterns: [
      '*.discord.com',
      '*.discordapp.com',
      '*.discordapp.net',
      '*.discord.gg',
      'discord.com',
    ],
    ja3_md5: [],
    common_ports: [443],
  },
  {
    app: 'WeChat',
    category: 'messaging',
    sni_patterns: [
      '*.wechat.com',
      '*.weixin.qq.com',
      '*.wx.qq.com',
      'wechat.com',
    ],
    ja3_md5: [],
    common_ports: [443, 8080],
  },

  // -------- Gaming --------
  {
    app: 'Roblox',
    category: 'gaming',
    sni_patterns: [
      '*.roblox.com',
      '*.rbxcdn.com',
      '*.robloxlabs.com',
      'roblox.com',
    ],
    ja3_md5: [],
    common_ports: [443],
  },
  {
    app: 'Fortnite',
    category: 'gaming',
    sni_patterns: [
      '*.epicgames.com',
      '*.unrealengine.com',
      '*.fortnite.com',
      '*.ol.epicgames.com',
      'epicgames.com',
    ],
    ja3_md5: [],
    common_ports: [443, 5222],
  },
  {
    app: 'Steam',
    category: 'gaming',
    sni_patterns: [
      '*.steampowered.com',
      '*.steamcommunity.com',
      '*.steamcontent.com',
      '*.steamstatic.com',
      'steampowered.com',
    ],
    ja3_md5: [],
    common_ports: [443, 27015, 27036],
  },
  {
    app: 'Xbox Live',
    category: 'gaming',
    sni_patterns: [
      '*.xboxlive.com',
      '*.xbox.com',
      '*.xboxservices.com',
      'xboxlive.com',
    ],
    ja3_md5: [],
    common_ports: [443, 3074],
  },
  {
    app: 'PlayStation Network',
    category: 'gaming',
    sni_patterns: [
      '*.playstation.net',
      '*.playstation.com',
      '*.sonyentertainmentnetwork.com',
      '*.np.community.playstation.net',
      'playstation.net',
    ],
    ja3_md5: [],
    common_ports: [443, 3478, 3479, 3480],
  },

  // -------- Cloud --------
  {
    app: 'iCloud',
    category: 'cloud',
    sni_patterns: [
      '*.icloud.com',
      '*.icloud-content.com',
      '*.apple-cloudkit.com',
      'icloud.com',
    ],
    ja3_md5: [],
    common_ports: [443],
  },
  {
    app: 'Google Drive',
    category: 'cloud',
    sni_patterns: [
      'drive.google.com',
      '*.drive.google.com',
      '*.docs.google.com',
      'docs.google.com',
    ],
    ja3_md5: [],
    common_ports: [443],
  },
  {
    app: 'Dropbox',
    category: 'cloud',
    sni_patterns: [
      '*.dropbox.com',
      '*.dropboxusercontent.com',
      '*.dropboxstatic.com',
      'dropbox.com',
    ],
    ja3_md5: [],
    common_ports: [443],
  },
  {
    app: 'OneDrive',
    category: 'cloud',
    sni_patterns: [
      'onedrive.live.com',
      '*.onedrive.live.com',
      '*.onedrive.com',
      '*.storage.live.com',
    ],
    ja3_md5: [],
    common_ports: [443],
  },

  // -------- AI --------
  {
    app: 'ChatGPT',
    category: 'ai',
    sni_patterns: [
      'chat.openai.com',
      'chatgpt.com',
      '*.chatgpt.com',
      '*.openai.com',
      'api.openai.com',
    ],
    ja3_md5: [],
    common_ports: [443],
  },
  {
    app: 'Claude',
    category: 'ai',
    sni_patterns: [
      'claude.ai',
      '*.claude.ai',
      '*.anthropic.com',
      'api.anthropic.com',
    ],
    ja3_md5: [],
    common_ports: [443],
  },
  {
    app: 'Gemini',
    category: 'ai',
    sni_patterns: [
      'gemini.google.com',
      '*.gemini.google.com',
      'bard.google.com',
      'aistudio.google.com',
    ],
    ja3_md5: [],
    common_ports: [443],
  },
];

// ---------------------------------------------------------------------------
// Indexes (built once)
// ---------------------------------------------------------------------------

// JA3 -> app, for O(1) lookups.
const JA3_INDEX = (() => {
  const m = new Map();
  for (const entry of APP_DB) {
    for (const j of entry.ja3_md5 || []) {
      m.set(j.toLowerCase(), entry);
    }
  }
  return m;
})();

// App name (case-insensitive) -> app entry.
const APP_INDEX = (() => {
  const m = new Map();
  for (const entry of APP_DB) m.set(entry.app.toLowerCase(), entry);
  return m;
})();

// ---------------------------------------------------------------------------
// SNI matching
// ---------------------------------------------------------------------------

function _normalizeHost(h) {
  if (!h || typeof h !== 'string') return '';
  return h.trim().toLowerCase().replace(/\.$/, '');
}

// Match an SNI host against a pattern. Patterns:
//   "example.com"   -> exact match
//   "*.example.com" -> matches one-or-more labels before "example.com"
// Returns 1.0 for exact, 0.8 for wildcard, 0.6 for partial root-domain match,
// or 0 for no match.
function _matchPattern(host, pattern) {
  if (!host || !pattern) return 0;
  const h = _normalizeHost(host);
  const p = _normalizeHost(pattern);

  if (p.startsWith('*.')) {
    const suffix = p.slice(2);
    if (h === suffix) return 0.8; // bare apex when pattern wildcard expects sub
    if (h.endsWith('.' + suffix)) return 0.8;
    return 0;
  }

  if (h === p) return 1.0;

  // Partial: same registrable domain. e.g. host = "ads.tiktok.com",
  // pattern = "tiktok.com" -> 0.6 (lower confidence; could be third party).
  if (h.endsWith('.' + p)) return 0.6;

  return 0;
}

// Find best app by SNI alone. Returns {entry, score} or null.
function _matchSni(sni) {
  const host = _normalizeHost(sni);
  if (!host) return null;

  let best = null;
  for (const entry of APP_DB) {
    for (const pattern of entry.sni_patterns) {
      const score = _matchPattern(host, pattern);
      if (score > 0 && (!best || score > best.score)) {
        best = { entry, score };
        if (score === 1.0) return best; // can't beat exact
      }
    }
  }
  return best;
}

// ---------------------------------------------------------------------------
// Public: identifyApp
// ---------------------------------------------------------------------------

/**
 * Identify an app from a single TLS handshake.
 *
 * @param {Object} sniHandshake - { sni: string, ja3?: string }
 * @returns {{app: string, category: string, confidence: number, by: 'sni'|'ja3'|'both'} | null}
 */
function identifyApp(sniHandshake) {
  if (!sniHandshake || typeof sniHandshake !== 'object') return null;

  const sni = sniHandshake.sni || sniHandshake.host || '';
  const ja3 = (sniHandshake.ja3 || sniHandshake.ja3_md5 || '').toLowerCase();

  const sniHit = _matchSni(sni);
  const ja3Entry = ja3 ? JA3_INDEX.get(ja3) : null;

  if (sniHit && ja3Entry && sniHit.entry.app === ja3Entry.app) {
    // Both agree: bump confidence, capped at 1.0.
    return {
      app: sniHit.entry.app,
      category: sniHit.entry.category,
      confidence: Math.min(1.0, sniHit.score + 0.2),
      by: 'both',
    };
  }

  if (sniHit) {
    return {
      app: sniHit.entry.app,
      category: sniHit.entry.category,
      confidence: sniHit.score,
      by: 'sni',
    };
  }

  if (ja3Entry) {
    // JA3 alone is much weaker - many apps share a TLS library.
    return {
      app: ja3Entry.app,
      category: ja3Entry.category,
      confidence: 0.4,
      by: 'ja3',
    };
  }

  return null;
}

// ---------------------------------------------------------------------------
// Public: identifyApps (batch)
// ---------------------------------------------------------------------------

/**
 * Group a batch of handshakes by recognized app.
 *
 * @param {Array<Object>} handshakes
 * @returns {Object} { [appName]: { count, category, sample_handshakes, suggested_rule } }
 */
function identifyApps(handshakes) {
  const out = {};
  if (!Array.isArray(handshakes)) return out;

  for (const h of handshakes) {
    const id = identifyApp(h);
    if (!id) continue;

    if (!out[id.app]) {
      out[id.app] = {
        count: 0,
        category: id.category,
        max_confidence: 0,
        sample_handshakes: [],
        suggested_rule: suggestBlockRule(id.app),
      };
    }
    const bucket = out[id.app];
    bucket.count += 1;
    if (id.confidence > bucket.max_confidence) bucket.max_confidence = id.confidence;
    if (bucket.sample_handshakes.length < 5) {
      bucket.sample_handshakes.push({
        sni: h.sni || h.host || null,
        ja3: h.ja3 || h.ja3_md5 || null,
        confidence: id.confidence,
        by: id.by,
      });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Public: getKnownApps
// ---------------------------------------------------------------------------

function getKnownApps() {
  // Return a defensive shallow clone so callers can't mutate the DB.
  return APP_DB.map((e) => ({
    app: e.app,
    category: e.category,
    sni_patterns: e.sni_patterns.slice(),
    ja3_md5: (e.ja3_md5 || []).slice(),
    common_ports: (e.common_ports || []).slice(),
  }));
}

// ---------------------------------------------------------------------------
// Public: suggestBlockRule
// ---------------------------------------------------------------------------

/**
 * Build a one-click block-rule suggestion for the given app.
 *
 * Strategy:
 *   - If the app has a stable JA3 fingerprint, prefer JA3 (most surgical).
 *   - Otherwise, use a domain-category rule (matches all SNI patterns).
 *   - As a last resort, a single-domain rule.
 *
 * @param {string} app - canonical app name (case-insensitive)
 * @returns {{type:string, value:any, scope:string, action:'block', app:string, category:string} | null}
 */
function suggestBlockRule(app) {
  if (!app) return null;
  const entry = APP_INDEX.get(String(app).toLowerCase());
  if (!entry) return null;

  // Prefer JA3 when available and exact - it's the same rule Firewalla
  // uses internally for "Block TikTok" on iOS.
  if (entry.ja3_md5 && entry.ja3_md5.length > 0) {
    return {
      type: 'ja3',
      value: entry.ja3_md5.slice(),
      scope: 'device',
      action: 'block',
      app: entry.app,
      category: entry.category,
      ports: entry.common_ports.slice(),
      note: 'Match TLS ClientHello fingerprint (most precise).',
    };
  }

  // Otherwise, use a category-style rule that covers all SNI patterns.
  return {
    type: 'category',
    value: {
      app: entry.app,
      domains: entry.sni_patterns.slice(),
    },
    scope: 'device',
    action: 'block',
    app: entry.app,
    category: entry.category,
    ports: entry.common_ports.slice(),
    note: 'Match SNI in TLS ClientHello against any of the listed domains.',
  };
}

// ---------------------------------------------------------------------------
// Recent-app ring buffer (in-memory)
// ---------------------------------------------------------------------------
//
// Structure:
//   _recent[customer_id] = Array<{app, mac, ts}>  (capped, newest last)
//
// We keep this small on purpose - it's only meant for "recently identified
// apps" in the dashboard. For long-term history the real cloud would push
// these to a TSDB.

const RECENT_PER_CUSTOMER = 500;
const _recent = Object.create(null);

function recordIdentification(customer_id, mac, app, ts) {
  if (!customer_id || !app) return false;
  const t = typeof ts === 'number' ? ts : Date.now();
  if (!_recent[customer_id]) _recent[customer_id] = [];
  const buf = _recent[customer_id];
  buf.push({ app: String(app), mac: mac || null, ts: t });
  if (buf.length > RECENT_PER_CUSTOMER) {
    buf.splice(0, buf.length - RECENT_PER_CUSTOMER);
  }
  return true;
}

/**
 * Aggregate the ring buffer into "what apps did this customer use, on what
 * MACs, when last seen, how often".
 *
 * @param {string} customer_id
 * @returns {Array<{app, mac, last_seen, count}>}
 */
function getRecentApps(customer_id) {
  const buf = _recent[customer_id];
  if (!buf || buf.length === 0) return [];

  // Key by app+mac so the dashboard can show per-device breakdown.
  const key = (app, mac) => app + '||' + (mac || '');
  const agg = new Map();

  for (const row of buf) {
    const k = key(row.app, row.mac);
    let cur = agg.get(k);
    if (!cur) {
      cur = { app: row.app, mac: row.mac, last_seen: row.ts, count: 0 };
      agg.set(k, cur);
    }
    cur.count += 1;
    if (row.ts > cur.last_seen) cur.last_seen = row.ts;
  }

  return Array.from(agg.values()).sort((a, b) => b.last_seen - a.last_seen);
}

// Test-only: clear ring buffer. Not exported in the public surface.
function _resetRecent() {
  for (const k of Object.keys(_recent)) delete _recent[k];
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  identifyApp,
  identifyApps,
  getKnownApps,
  suggestBlockRule,
  recordIdentification,
  getRecentApps,
  // internal, exported for tests
  _resetRecent,
};
