'use strict';
/*
 * nl-flow-search.js
 *
 * Natural-language → flow filter DSL for the mock Firewalla cloud.
 * Mirrors Firewalla MSP 2.9's "Search Flows with Firewalla AI" feature.
 *
 * Two engines:
 *   1. LLM mode: if MES_LLM_API_URL + MES_LLM_API_KEY are present in env,
 *      we POST the natural query to the configured endpoint and parse the
 *      JSON object it returns.
 *   2. Heuristic mode (fallback): pure regex/keyword extraction. No deps.
 *
 * Pure Node.js. No npm packages.
 */

const https = require('https');
const http = require('http');
const url = require('url');

// ---------------------------------------------------------------------------
// Country name → ISO-3166-alpha-2 map (>= 30 entries).
// ---------------------------------------------------------------------------
const COUNTRY_CODES = {
  'united states': 'US', 'usa': 'US', 'us': 'US', 'america': 'US',
  'united kingdom': 'GB', 'uk': 'GB', 'britain': 'GB', 'england': 'GB',
  'russia': 'RU', 'russian federation': 'RU',
  'china': 'CN', 'prc': 'CN',
  'japan': 'JP',
  'germany': 'DE',
  'france': 'FR',
  'canada': 'CA',
  'australia': 'AU',
  'india': 'IN',
  'brazil': 'BR',
  'mexico': 'MX',
  'spain': 'ES',
  'italy': 'IT',
  'netherlands': 'NL', 'holland': 'NL',
  'sweden': 'SE',
  'norway': 'NO',
  'finland': 'FI',
  'denmark': 'DK',
  'poland': 'PL',
  'turkey': 'TR',
  'ukraine': 'UA',
  'south korea': 'KR', 'korea': 'KR',
  'north korea': 'KP',
  'iran': 'IR',
  'iraq': 'IQ',
  'israel': 'IL',
  'saudi arabia': 'SA',
  'uae': 'AE', 'united arab emirates': 'AE',
  'lebanon': 'LB',
  'egypt': 'EG',
  'south africa': 'ZA',
  'nigeria': 'NG',
  'singapore': 'SG',
  'hong kong': 'HK',
  'taiwan': 'TW',
  'vietnam': 'VN',
  'indonesia': 'ID',
  'thailand': 'TH',
  'pakistan': 'PK',
  'switzerland': 'CH',
  'belgium': 'BE',
  'ireland': 'IE',
  'portugal': 'PT',
  'greece': 'GR',
  'argentina': 'AR',
  'chile': 'CL',
};

// Category keyword lookup
const CATEGORY_KEYWORDS = {
  'social': 'social',
  'social media': 'social',
  'video': 'video',
  'streaming': 'video',
  'ads': 'ads',
  'advertising': 'ads',
  'advertisement': 'ads',
  'malware': 'malware',
  'malicious': 'malware',
  'porn': 'porn',
  'adult': 'porn',
  'gaming': 'games',
  'games': 'games',
  'shopping': 'shopping',
  'news': 'news',
  'vpn': 'vpn',
  'proxy': 'vpn',
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function nowSec() { return Math.floor(Date.now() / 1000); }

function startOfTodaySec() {
  const d = new Date();
  d.setHours(0, 0, 0, 0);
  return Math.floor(d.getTime() / 1000);
}

function parseSizeToBytes(numStr, unit) {
  const n = parseFloat(numStr);
  if (!isFinite(n)) return null;
  const u = (unit || 'b').toLowerCase();
  const mult = u.startsWith('g') ? 1024 * 1024 * 1024
    : u.startsWith('m') ? 1024 * 1024
    : u.startsWith('k') ? 1024
    : 1;
  return Math.round(n * mult);
}

function emptyFilter() {
  return {
    ts_gte: undefined,
    ts_lte: undefined,
    src_macs: [],
    dst_domains: [],
    countries: [],
    blocked: undefined,
    category: undefined,
    bytes_gte: undefined,
    bytes_lte: undefined,
    limit: undefined,
  };
}

// ---------------------------------------------------------------------------
// Heuristic parser
// ---------------------------------------------------------------------------
function heuristicParse(query) {
  const q = String(query || '').toLowerCase();
  const f = emptyFilter();
  const reasons = [];

  // ---- Time windows ----
  let m;
  if (/\blast\s+24\s*h(ours?)?\b|\bpast\s+day\b|\bin\s+the\s+last\s+day\b/.test(q)) {
    f.ts_gte = nowSec() - 86400;
    reasons.push('time: last 24h');
  } else if (/\btoday\b/.test(q)) {
    f.ts_gte = startOfTodaySec();
    reasons.push('time: today');
  } else if (/\byesterday\b/.test(q)) {
    f.ts_gte = startOfTodaySec() - 86400;
    f.ts_lte = startOfTodaySec();
    reasons.push('time: yesterday');
  } else if (/\blast\s+week\b|\bpast\s+week\b|\bthis\s+week\b/.test(q)) {
    f.ts_gte = nowSec() - 7 * 86400;
    reasons.push('time: last week');
  } else if (/\blast\s+month\b|\bpast\s+month\b/.test(q)) {
    f.ts_gte = nowSec() - 30 * 86400;
    reasons.push('time: last month');
  } else if ((m = q.match(/\blast\s+(\d+)\s*(h|hr|hour|hours|m|min|minutes|d|day|days)\b/))) {
    const n = parseInt(m[1], 10);
    const u = m[2];
    let secs;
    if (u.startsWith('m') && u !== 'm') secs = n * 60;
    else if (u === 'm') secs = n * 60;
    else if (u.startsWith('h')) secs = n * 3600;
    else secs = n * 86400;
    f.ts_gte = nowSec() - secs;
    reasons.push(`time: last ${n}${u}`);
  } else if ((m = q.match(/\bsince\s+(\d{1,2})\s*(am|pm)\b/))) {
    let hour = parseInt(m[1], 10) % 12;
    if (m[2] === 'pm') hour += 12;
    const d = new Date();
    d.setHours(hour, 0, 0, 0);
    if (d.getTime() > Date.now()) d.setDate(d.getDate() - 1);
    f.ts_gte = Math.floor(d.getTime() / 1000);
    reasons.push(`time: since ${m[1]}${m[2]}`);
  }

  // ---- Country detection ----
  // Sort keys longest-first so multi-word names ("united states") win.
  const countryKeys = Object.keys(COUNTRY_CODES).sort((a, b) => b.length - a.length);
  for (const name of countryKeys) {
    const re = new RegExp(`(?:^|[^a-z])${name.replace(/\s+/g, '\\s+')}(?:[^a-z]|$)`, 'i');
    if (re.test(q)) {
      const code = COUNTRY_CODES[name];
      if (!f.countries.includes(code)) {
        f.countries.push(code);
        reasons.push(`country: ${code} (${name})`);
      }
    }
  }
  // Bare 2-letter ISO code like "from US" / "to RU"
  const isoMatch = q.match(/\b(?:from|to|in)\s+([a-z]{2})\b/i);
  if (isoMatch) {
    const c = isoMatch[1].toUpperCase();
    if (!f.countries.includes(c)) {
      f.countries.push(c);
      reasons.push(`country: ${c} (iso)`);
    }
  }

  // ---- Status (blocked/allowed) ----
  if (/\bnot\s+blocked\b|\ballowed\b|\bpassed\b/.test(q)) {
    f.blocked = false;
    reasons.push('status: allowed');
  } else if (/\bblocked\b|\bdenied\b|\bdropped\b/.test(q)) {
    f.blocked = true;
    reasons.push('status: blocked');
  }

  // ---- Category ----
  for (const [kw, cat] of Object.entries(CATEGORY_KEYWORDS)) {
    const re = new RegExp(`\\b${kw}\\b`, 'i');
    if (re.test(q)) {
      f.category = cat;
      reasons.push(`category: ${cat}`);
      break;
    }
  }

  // ---- Volume / byte thresholds ----
  // "more than 100 MB", "over 1GB", ">= 50 mb"
  const gtMatch = q.match(/(?:more than|over|greater than|larger than|>=?|above)\s*(\d+(?:\.\d+)?)\s*(g|gb|m|mb|k|kb|b|bytes?)\b/i);
  if (gtMatch) {
    const bytes = parseSizeToBytes(gtMatch[1], gtMatch[2]);
    if (bytes != null) {
      f.bytes_gte = bytes;
      reasons.push(`bytes >= ${bytes}`);
    }
  }
  const ltMatch = q.match(/(?:less than|under|fewer than|smaller than|<=?|below)\s*(\d+(?:\.\d+)?)\s*(g|gb|m|mb|k|kb|b|bytes?)\b/i);
  if (ltMatch) {
    const bytes = parseSizeToBytes(ltMatch[1], ltMatch[2]);
    if (bytes != null) {
      f.bytes_lte = bytes;
      reasons.push(`bytes <= ${bytes}`);
    }
  }

  // ---- Device hints ----
  const deviceWords = [
    'iphone', 'ipad', 'macbook', 'imac', 'mac mini', 'apple tv', 'airpods',
    'android', 'pixel', 'samsung', 'galaxy',
    'xbox', 'playstation', 'ps4', 'ps5', 'switch',
    'roku', 'firetv', 'fire tv', 'chromecast', 'shield',
    'thermostat', 'nest', 'echo', 'alexa', 'ring',
    'laptop', 'desktop', 'printer', 'camera', 'tv',
  ];
  for (const w of deviceWords) {
    const re = new RegExp(`\\b${w.replace(/\s+/g, '\\s+')}\\b`, 'i');
    if (re.test(q)) {
      // we keep the device name in dst_domains? No — store as a hostname pattern
      // we'll re-use dst_domains[] to also match against device hostname.
      f.src_macs.push('hostname:' + w.replace(/\s+/g, ''));
      reasons.push(`device: ${w}`);
    }
  }
  // explicit "device: foo" syntax
  const dev = q.match(/device:\s*([a-z0-9._:-]+)/i);
  if (dev) {
    f.src_macs.push(dev[1]);
    reasons.push(`device: ${dev[1]}`);
  }

  // ---- Domain hints ----
  // explicit "domain: foo.com" or bare "youtube.com"
  const dom = q.match(/(?:domain|host|to):\s*([a-z0-9.-]+\.[a-z]{2,})/i);
  if (dom) {
    f.dst_domains.push(dom[1].toLowerCase());
    reasons.push(`domain: ${dom[1]}`);
  } else {
    const bare = q.match(/\b([a-z0-9-]+\.(?:com|net|org|io|co|tv|me|app|gov|edu|ru|cn|uk|de|fr|jp))\b/i);
    if (bare) {
      f.dst_domains.push(bare[1].toLowerCase());
      reasons.push(`domain: ${bare[1]}`);
    }
  }

  // ---- Limit ----
  const lim = q.match(/\b(?:top|first|limit)\s+(\d+)\b/);
  if (lim) {
    f.limit = parseInt(lim[1], 10);
    reasons.push(`limit: ${f.limit}`);
  }

  return {
    filter: f,
    explanation: reasons.length ? reasons.join('; ') : 'no signals matched; returning unfiltered',
    engine: 'heuristic',
  };
}

// ---------------------------------------------------------------------------
// LLM mode
// ---------------------------------------------------------------------------
function postJSON(endpoint, headers, body, timeoutMs) {
  return new Promise((resolve, reject) => {
    let parsed;
    try { parsed = url.parse(endpoint); } catch (e) { return reject(e); }
    const lib = parsed.protocol === 'http:' ? http : https;
    const payload = Buffer.from(JSON.stringify(body));
    const req = lib.request({
      method: 'POST',
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.path,
      headers: Object.assign({
        'content-type': 'application/json',
        'content-length': payload.length,
      }, headers || {}),
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const txt = Buffer.concat(chunks).toString('utf8');
        if (res.statusCode >= 200 && res.statusCode < 300) {
          try { resolve(JSON.parse(txt)); }
          catch (e) { reject(new Error('llm: bad json: ' + txt.slice(0, 200))); }
        } else {
          reject(new Error('llm: http ' + res.statusCode + ': ' + txt.slice(0, 200)));
        }
      });
    });
    req.on('error', reject);
    if (timeoutMs) req.setTimeout(timeoutMs, () => req.destroy(new Error('llm: timeout')));
    req.write(payload);
    req.end();
  });
}

const LLM_SYSTEM_PROMPT = [
  'You translate a natural-language network-flow search query into a JSON filter.',
  'Reply with ONLY a JSON object (no prose, no code fences) with these optional keys:',
  '  ts_gte (unix seconds), ts_lte (unix seconds),',
  '  src_macs (string[]), dst_domains (string[] suffix matches), countries (ISO-3166 alpha-2 string[]),',
  '  blocked (boolean), category (string), bytes_gte (number), bytes_lte (number), limit (number).',
  'Omit unknown keys. Use ISO codes (US, RU, CN, ...).',
].join(' ');

async function llmParse(query, ctx) {
  const endpoint = process.env.MES_LLM_API_URL;
  const apiKey = process.env.MES_LLM_API_KEY;
  if (!endpoint || !apiKey) throw new Error('llm: env not configured');

  const body = {
    model: process.env.MES_LLM_MODEL || 'gpt-4o-mini',
    temperature: 0,
    response_format: { type: 'json_object' },
    messages: [
      { role: 'system', content: LLM_SYSTEM_PROMPT },
      { role: 'user', content: 'Now: ' + nowSec() + '. Query: ' + String(query) },
    ],
  };
  const headers = { authorization: 'Bearer ' + apiKey };
  const resp = await postJSON(endpoint, headers, body, 8000);

  // Accept OpenAI-shaped or bare-JSON-shaped responses.
  let content = null;
  if (resp && resp.choices && resp.choices[0]) {
    content = resp.choices[0].message ? resp.choices[0].message.content : resp.choices[0].text;
  } else if (resp && resp.content) {
    content = typeof resp.content === 'string' ? resp.content
      : Array.isArray(resp.content) && resp.content[0] ? resp.content[0].text : null;
  } else if (resp && typeof resp === 'object' && !resp.choices) {
    content = JSON.stringify(resp);
  }
  if (!content) throw new Error('llm: empty response');

  let obj;
  try { obj = JSON.parse(content); }
  catch (e) {
    const m = content.match(/\{[\s\S]*\}/);
    if (!m) throw new Error('llm: no json in response');
    obj = JSON.parse(m[0]);
  }

  // Sanitize into our filter shape.
  const f = emptyFilter();
  if (typeof obj.ts_gte === 'number') f.ts_gte = obj.ts_gte;
  if (typeof obj.ts_lte === 'number') f.ts_lte = obj.ts_lte;
  if (Array.isArray(obj.src_macs)) f.src_macs = obj.src_macs.map(String);
  if (Array.isArray(obj.dst_domains)) f.dst_domains = obj.dst_domains.map((s) => String(s).toLowerCase());
  if (Array.isArray(obj.countries)) f.countries = obj.countries.map((s) => String(s).toUpperCase());
  if (typeof obj.blocked === 'boolean') f.blocked = obj.blocked;
  if (typeof obj.category === 'string') f.category = obj.category;
  if (typeof obj.bytes_gte === 'number') f.bytes_gte = obj.bytes_gte;
  if (typeof obj.bytes_lte === 'number') f.bytes_lte = obj.bytes_lte;
  if (typeof obj.limit === 'number') f.limit = obj.limit;

  return {
    filter: f,
    explanation: obj.explanation || 'parsed by LLM',
    engine: 'llm',
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
async function parse(naturalQuery, ctx) {
  if (process.env.MES_LLM_API_URL && process.env.MES_LLM_API_KEY) {
    try {
      return await llmParse(naturalQuery, ctx);
    } catch (e) {
      const fallback = heuristicParse(naturalQuery);
      fallback.engine = 'heuristic-after-llm-error';
      fallback.explanation = '[llm error: ' + e.message + '] ' + fallback.explanation;
      return fallback;
    }
  }
  return heuristicParse(naturalQuery);
}

function flowMatchesFilter(flow, f) {
  if (!flow) return false;
  const ts = flow.ts || flow.timestamp || flow._ts || 0;
  if (f.ts_gte != null && ts < f.ts_gte) return false;
  if (f.ts_lte != null && ts > f.ts_lte) return false;

  if (f.blocked != null) {
    const blocked = !!(flow.blocked || flow.block || flow.action === 'block' || flow.action === 'allow:block');
    if (blocked !== f.blocked) return false;
  }

  if (f.countries && f.countries.length) {
    const c = (flow.country || flow.dst_country || flow.dstCountry || '').toUpperCase();
    if (!f.countries.includes(c)) return false;
  }

  if (f.category) {
    const cat = (flow.category || flow.dst_category || '').toLowerCase();
    if (cat !== f.category.toLowerCase()) return false;
  }

  if (f.dst_domains && f.dst_domains.length) {
    const host = (flow.host || flow.domain || flow.dst_host || flow.dstDomain || '').toLowerCase();
    const ok = f.dst_domains.some((d) => host === d || host.endsWith('.' + d));
    if (!ok) return false;
  }

  if (f.src_macs && f.src_macs.length) {
    const mac = (flow.mac || flow.src_mac || flow.srcMac || '').toLowerCase();
    const hostname = (flow.hostname || flow.device || flow.deviceName || '').toLowerCase();
    const ok = f.src_macs.some((s) => {
      const v = String(s).toLowerCase();
      if (v.startsWith('hostname:')) return hostname.includes(v.slice('hostname:'.length));
      return mac === v || hostname.includes(v);
    });
    if (!ok) return false;
  }

  const bytes = (flow.bytes != null) ? flow.bytes
    : (flow.upload || 0) + (flow.download || 0);
  if (f.bytes_gte != null && bytes < f.bytes_gte) return false;
  if (f.bytes_lte != null && bytes > f.bytes_lte) return false;

  return true;
}

function applyFilter(flows, filter) {
  if (!Array.isArray(flows)) return [];
  if (!filter) return flows.slice();
  let out = flows.filter((fl) => flowMatchesFilter(fl, filter));
  if (filter.limit && filter.limit > 0) out = out.slice(0, filter.limit);
  return out;
}

async function search(flows, naturalQuery) {
  const parsed = await parse(naturalQuery);
  const results = applyFilter(flows, parsed.filter);
  return {
    engine: parsed.engine,
    explanation: parsed.explanation,
    filter: parsed.filter,
    count: results.length,
    results: results,
  };
}

module.exports = {
  parse,
  applyFilter,
  search,
  // exposed for tests
  _heuristicParse: heuristicParse,
  _COUNTRY_CODES: COUNTRY_CODES,
};
