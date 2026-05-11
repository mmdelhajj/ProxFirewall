/**
 * behavior-baseline.js - Per-device behavior baselining + outlier scoring
 *
 * Replaces the old "3x spike" heuristic with a real statistical model.
 * Mirrors Firewalla's behavior anomaly detection.
 *
 * For every device MAC seen in cloud flow records we maintain a rolling
 * 14-day baseline of:
 *   - Hourly bytes-per-hour distribution     (24-bucket mean / stddev)
 *   - Destination diversity (unique domains/hour, new-vs-known ratio)
 *   - Periodicity (do connections appear at fixed intervals = beacon?)
 *   - Country diversity (avg unique countries/day)
 *
 * New flows are scored by combining z-score / IQR / set-novelty signals
 * into a 0..100 anomaly score; > 50 is an anomaly, > 75 is high severity.
 *
 * Pure JS, no ML libs. Exposed via require() from the main Express server.
 * This module does not register any HTTP routes itself.
 */

'use strict';

// ---------------------------------------------------------------------------
// Tunables
// ---------------------------------------------------------------------------
const DEFAULTS = {
  window_days:           14,          // rolling baseline window
  learning_phase_ms:     48 * 3600e3, // first 48h per device = score 0
  hour_bucket_min_n:     5,           // need >=N samples in a bucket before z-scoring
  beacon_min_hits:       5,           // 5+ connections at fixed interval
  beacon_jitter_pct:     0.10,        // ±10% interval jitter allowed
  beacon_window_recent:  50,          // last N inter-arrival deltas considered
  recent_anomaly_buf:    500,         // ring buffer size for getRecentAnomalies()
  domain_memory_max:     2000,        // cap unique domains tracked per device
  country_memory_max:    50,          // cap unique countries tracked per device
};

const MS_PER_DAY  = 24 * 3600 * 1000;
const MS_PER_HOUR = 3600 * 1000;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
// state.device_baselines[mac] = { ...baseline... }
const state = {
  device_baselines: Object.create(null),
};

// Ring buffer of recent anomaly findings for the dashboard.
const _recentAnomalies = [];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function _now() { return Date.now(); }

function _emptyBaseline(now) {
  const hourly = new Array(24);
  for (let i = 0; i < 24; i++) {
    // running stats per hour-of-day, plus a small ring of recent samples
    // so we can drop ones older than window_days.
    hourly[i] = {
      samples: [],            // [{ts, bytes}]
      mean: 0,
      stddev: 0,
    };
  }
  return {
    first_seen:           now,
    last_seen:            now,
    samples_seen:         0,
    hourly_buckets:       hourly,
    // domain memory: domain -> last_seen_ts
    domain_seen:          Object.create(null),
    // per-hour unique-domain counts: [{ts_hour, set:Set}]
    hourly_domain_log:    [],
    unique_domains_per_hr_avg: 0,
    new_domain_rate_avg:  0,    // avg ratio of new domains/hour
    // beacon: log inter-arrival deltas per destination
    last_seen_per_dst:    Object.create(null),  // dst -> ts
    intervals_per_dst:    Object.create(null),  // dst -> [delta_ms, ...]
    periodicity_hits:     0,
    // country memory: country -> last_seen_ts
    country_seen:         Object.create(null),
    // per-day unique-country counts: [{day_idx, set:Set}]
    daily_country_log:    [],
    country_diversity_avg: 0,
  };
}

function _hourOfDay(ts)  { return new Date(ts).getUTCHours(); }
function _hourBucket(ts) { return Math.floor(ts / MS_PER_HOUR); }
function _dayBucket(ts)  { return Math.floor(ts / MS_PER_DAY); }

// Welford-ish recompute from samples array (small N per hour bucket, fine).
function _recomputeHourStats(bucket) {
  const n = bucket.samples.length;
  if (n === 0) { bucket.mean = 0; bucket.stddev = 0; return; }
  let sum = 0;
  for (let i = 0; i < n; i++) sum += bucket.samples[i].bytes;
  const mean = sum / n;
  let sq = 0;
  for (let i = 0; i < n; i++) {
    const d = bucket.samples[i].bytes - mean;
    sq += d * d;
  }
  bucket.mean = mean;
  bucket.stddev = n > 1 ? Math.sqrt(sq / (n - 1)) : 0;
}

// Drop samples / log entries older than window_days.
function _evict(b, now) {
  const cutoff = now - DEFAULTS.window_days * MS_PER_DAY;

  for (let h = 0; h < 24; h++) {
    const bucket = b.hourly_buckets[h];
    if (!bucket.samples.length) continue;
    let drop = 0;
    while (drop < bucket.samples.length && bucket.samples[drop].ts < cutoff) drop++;
    if (drop) bucket.samples.splice(0, drop);
    _recomputeHourStats(bucket);
  }

  for (const d of Object.keys(b.domain_seen)) {
    if (b.domain_seen[d] < cutoff) delete b.domain_seen[d];
  }
  // also enforce hard cap to keep memory bounded
  const dkeys = Object.keys(b.domain_seen);
  if (dkeys.length > DEFAULTS.domain_memory_max) {
    dkeys.sort((a, c) => b.domain_seen[a] - b.domain_seen[c]);
    const drop = dkeys.length - DEFAULTS.domain_memory_max;
    for (let i = 0; i < drop; i++) delete b.domain_seen[dkeys[i]];
  }

  for (const c of Object.keys(b.country_seen)) {
    if (b.country_seen[c] < cutoff) delete b.country_seen[c];
  }
  const ckeys = Object.keys(b.country_seen);
  if (ckeys.length > DEFAULTS.country_memory_max) {
    ckeys.sort((a, c) => b.country_seen[a] - b.country_seen[c]);
    const drop = ckeys.length - DEFAULTS.country_memory_max;
    for (let i = 0; i < drop; i++) delete b.country_seen[ckeys[i]];
  }

  // hourly_domain_log: keep entries within window
  const hCutoff = _hourBucket(cutoff);
  while (b.hourly_domain_log.length && b.hourly_domain_log[0].ts_hour < hCutoff) {
    b.hourly_domain_log.shift();
  }
  // daily_country_log: keep entries within window
  const dCutoff = _dayBucket(cutoff);
  while (b.daily_country_log.length && b.daily_country_log[0].day_idx < dCutoff) {
    b.daily_country_log.shift();
  }

  // intervals: drop oldest beyond beacon_window_recent
  for (const dst of Object.keys(b.intervals_per_dst)) {
    const arr = b.intervals_per_dst[dst];
    if (arr.length > DEFAULTS.beacon_window_recent) {
      arr.splice(0, arr.length - DEFAULTS.beacon_window_recent);
    }
  }
  // forget last_seen_per_dst if past window
  for (const dst of Object.keys(b.last_seen_per_dst)) {
    if (b.last_seen_per_dst[dst] < cutoff) {
      delete b.last_seen_per_dst[dst];
      delete b.intervals_per_dst[dst];
    }
  }
}

// Recompute summary aggregates used by getBaseline()/score().
function _recomputeAggregates(b) {
  // unique_domains_per_hr_avg + new_domain_rate_avg
  if (b.hourly_domain_log.length) {
    let totalU = 0, totalNew = 0, totalSeen = 0;
    for (const h of b.hourly_domain_log) {
      totalU += h.set.size;
      totalNew += h.new_count || 0;
      totalSeen += h.set.size;
    }
    b.unique_domains_per_hr_avg = totalU / b.hourly_domain_log.length;
    b.new_domain_rate_avg = totalSeen ? (totalNew / totalSeen) : 0;
  } else {
    b.unique_domains_per_hr_avg = 0;
    b.new_domain_rate_avg = 0;
  }

  // country_diversity_avg
  if (b.daily_country_log.length) {
    let s = 0;
    for (const d of b.daily_country_log) s += d.set.size;
    b.country_diversity_avg = s / b.daily_country_log.length;
  } else {
    b.country_diversity_avg = 0;
  }

  // periodicity_hits = how many destinations look beacon-ish right now
  let hits = 0;
  for (const dst of Object.keys(b.intervals_per_dst)) {
    if (_isBeacon(b.intervals_per_dst[dst])) hits++;
  }
  b.periodicity_hits = hits;
}

// Beacon detector: look at last N inter-arrival deltas, take median, and see
// if 5+ of them are within ±jitter of that median.
function _isBeacon(deltas) {
  if (!deltas || deltas.length < DEFAULTS.beacon_min_hits) return false;
  const arr = deltas.slice().sort((a, b) => a - b);
  const median = arr[Math.floor(arr.length / 2)];
  if (median <= 0) return false;
  const tol = median * DEFAULTS.beacon_jitter_pct;
  let hits = 0;
  for (const d of deltas) if (Math.abs(d - median) <= tol) hits++;
  return hits >= DEFAULTS.beacon_min_hits;
}

function _pushAnomaly(rec) {
  _recentAnomalies.push(rec);
  if (_recentAnomalies.length > DEFAULTS.recent_anomaly_buf) {
    _recentAnomalies.splice(0, _recentAnomalies.length - DEFAULTS.recent_anomaly_buf);
  }
}

// ---------------------------------------------------------------------------
// Update path
// ---------------------------------------------------------------------------
function _updateBaseline(b, flow, now) {
  const bytes = (flow.bytes_up || 0) + (flow.bytes_down || 0);
  const hod = _hourOfDay(flow.ts || now);
  const hourBucket = b.hourly_buckets[hod];

  hourBucket.samples.push({ ts: flow.ts || now, bytes });
  _recomputeHourStats(hourBucket);

  // domain bookkeeping
  const dom = (flow.dst_domain || flow.dst_ip || '').toLowerCase();
  const wasKnown = !!b.domain_seen[dom];
  if (dom) b.domain_seen[dom] = flow.ts || now;

  const hBkt = _hourBucket(flow.ts || now);
  let hLog = b.hourly_domain_log[b.hourly_domain_log.length - 1];
  if (!hLog || hLog.ts_hour !== hBkt) {
    hLog = { ts_hour: hBkt, set: new Set(), new_count: 0 };
    b.hourly_domain_log.push(hLog);
  }
  if (dom) {
    const before = hLog.set.size;
    hLog.set.add(dom);
    if (hLog.set.size > before && !wasKnown) hLog.new_count++;
  }

  // country bookkeeping
  const country = flow.country || '';
  const countryWasKnown = !!b.country_seen[country];
  if (country) b.country_seen[country] = flow.ts || now;
  const dBkt = _dayBucket(flow.ts || now);
  let dLog = b.daily_country_log[b.daily_country_log.length - 1];
  if (!dLog || dLog.day_idx !== dBkt) {
    dLog = { day_idx: dBkt, set: new Set() };
    b.daily_country_log.push(dLog);
  }
  if (country) dLog.set.add(country);

  // beacon bookkeeping (per-dst inter-arrival deltas)
  const beaconKey = dom || flow.dst_ip;
  if (beaconKey) {
    const last = b.last_seen_per_dst[beaconKey];
    if (last) {
      const delta = (flow.ts || now) - last;
      if (delta > 0) {
        const arr = b.intervals_per_dst[beaconKey] || (b.intervals_per_dst[beaconKey] = []);
        arr.push(delta);
        if (arr.length > DEFAULTS.beacon_window_recent) arr.shift();
      }
    }
    b.last_seen_per_dst[beaconKey] = flow.ts || now;
  }

  b.last_seen = Math.max(b.last_seen, flow.ts || now);
  b.samples_seen++;

  _evict(b, now);
  _recomputeAggregates(b);

  return { wasKnownDomain: wasKnown, wasKnownCountry: countryWasKnown, bytes, hod };
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------
function score(flow, baseline) {
  const reasons = [];
  let s = 0;

  if (!baseline) return { score: 0, reasons: ['no baseline'] };

  // Learning phase: score 0 for first 48h.
  const learning = (_now() - baseline.first_seen) < DEFAULTS.learning_phase_ms;
  if (learning) return { score: 0, reasons: ['learning'] };

  const ts = flow.ts || _now();
  const hod = _hourOfDay(ts);
  const bytes = (flow.bytes_up || 0) + (flow.bytes_down || 0);
  const hb = baseline.hourly_buckets[hod];

  // Rule 1: traffic spike for THIS hour > mean + 3*stddev
  if (hb && hb.samples.length >= DEFAULTS.hour_bucket_min_n) {
    const threshold = hb.mean + 3 * hb.stddev;
    if (bytes > threshold && bytes > hb.mean * 1.5) {
      s += 30;
      reasons.push('traffic spike');
    }
  }

  // Rule 2: unfamiliar domain AND new-domain rate above baseline
  const dom = (flow.dst_domain || flow.dst_ip || '').toLowerCase();
  if (dom && !baseline.domain_seen[dom]) {
    // current hour's new-domain ratio so far
    const hBkt = _hourBucket(ts);
    const last = baseline.hourly_domain_log[baseline.hourly_domain_log.length - 1];
    let ratioNow = 1;
    if (last && last.ts_hour === hBkt && last.set.size > 0) {
      ratioNow = (last.new_count || 0) / last.set.size;
    }
    if (ratioNow > Math.max(baseline.new_domain_rate_avg, 0.05)) {
      s += 20;
      reasons.push('unfamiliar domain');
    }
  }

  // Rule 3: country never visited before
  const country = flow.country || '';
  if (country && !baseline.country_seen[country]) {
    s += 15;
    reasons.push('new country');
  }

  // Rule 4: beaconing
  const beaconKey = dom || flow.dst_ip;
  if (beaconKey && baseline.intervals_per_dst[beaconKey]
      && _isBeacon(baseline.intervals_per_dst[beaconKey])) {
    s += 25;
    reasons.push('beaconing pattern');
  }

  if (s > 100) s = 100;
  return { score: s, reasons };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
function ingest(flow) {
  if (!flow || !flow.src_mac) return null;
  const mac = String(flow.src_mac).toLowerCase();
  const now = _now();

  let b = state.device_baselines[mac];
  if (!b) {
    b = state.device_baselines[mac] = _emptyBaseline(flow.ts || now);
  }

  // Score BEFORE updating so the new flow itself is judged against history.
  const result = score(flow, b);

  _updateBaseline(b, flow, now);

  if (result.score >= 50) {
    const finding = {
      mac,
      ts: flow.ts || now,
      score: result.score,
      severity: result.score >= 75 ? 'high' : 'medium',
      reasons: result.reasons.slice(),
      customer_id: flow.customer_id || null,
      dst_domain: flow.dst_domain || null,
      dst_ip: flow.dst_ip || null,
      country: flow.country || null,
    };
    _pushAnomaly(finding);
    return finding;
  }
  return null;
}

function getBaseline(mac) {
  if (!mac) return null;
  const b = state.device_baselines[String(mac).toLowerCase()];
  if (!b) return null;
  const hourly_bytes_mean = new Array(24);
  const hourly_bytes_stddev = new Array(24);
  for (let i = 0; i < 24; i++) {
    hourly_bytes_mean[i]   = b.hourly_buckets[i].mean;
    hourly_bytes_stddev[i] = b.hourly_buckets[i].stddev;
  }
  return {
    hourly_bytes_mean,
    hourly_bytes_stddev,
    unique_domains_per_hr_avg: b.unique_domains_per_hr_avg,
    periodicity_hits:          b.periodicity_hits,
    country_diversity_avg:     b.country_diversity_avg,
    samples_seen:              b.samples_seen,
    learning:                  (_now() - b.first_seen) < DEFAULTS.learning_phase_ms,
    first_seen:                b.first_seen,
    last_seen:                 b.last_seen,
  };
}

function prune(maxAgeDays) {
  const cutoff = _now() - (maxAgeDays || DEFAULTS.window_days) * MS_PER_DAY;
  let removed = 0;
  for (const mac of Object.keys(state.device_baselines)) {
    if (state.device_baselines[mac].last_seen < cutoff) {
      delete state.device_baselines[mac];
      removed++;
    }
  }
  return removed;
}

function getRecentAnomalies(limit) {
  const n = limit || 100;
  return _recentAnomalies.slice(-n).reverse();
}

// Snapshot/restore. Sets need to be serialised as arrays.
function exportSnapshot() {
  const out = Object.create(null);
  for (const mac of Object.keys(state.device_baselines)) {
    const b = state.device_baselines[mac];
    out[mac] = {
      first_seen: b.first_seen,
      last_seen:  b.last_seen,
      samples_seen: b.samples_seen,
      hourly_buckets: b.hourly_buckets.map(h => ({
        samples: h.samples.slice(),
        mean: h.mean,
        stddev: h.stddev,
      })),
      domain_seen: Object.assign({}, b.domain_seen),
      hourly_domain_log: b.hourly_domain_log.map(h => ({
        ts_hour: h.ts_hour,
        set: Array.from(h.set),
        new_count: h.new_count || 0,
      })),
      unique_domains_per_hr_avg: b.unique_domains_per_hr_avg,
      new_domain_rate_avg:       b.new_domain_rate_avg,
      last_seen_per_dst: Object.assign({}, b.last_seen_per_dst),
      intervals_per_dst: Object.fromEntries(
        Object.entries(b.intervals_per_dst).map(([k, v]) => [k, v.slice()])
      ),
      periodicity_hits:  b.periodicity_hits,
      country_seen:      Object.assign({}, b.country_seen),
      daily_country_log: b.daily_country_log.map(d => ({
        day_idx: d.day_idx, set: Array.from(d.set),
      })),
      country_diversity_avg: b.country_diversity_avg,
    };
  }
  return { version: 1, exported_at: _now(), baselines: out };
}

function importSnapshot(snap) {
  if (!snap || !snap.baselines) return 0;
  let n = 0;
  for (const mac of Object.keys(snap.baselines)) {
    const s = snap.baselines[mac];
    const b = _emptyBaseline(s.first_seen || _now());
    b.first_seen   = s.first_seen   || b.first_seen;
    b.last_seen    = s.last_seen    || b.last_seen;
    b.samples_seen = s.samples_seen || 0;
    if (Array.isArray(s.hourly_buckets) && s.hourly_buckets.length === 24) {
      for (let i = 0; i < 24; i++) {
        const src = s.hourly_buckets[i] || {};
        b.hourly_buckets[i].samples = Array.isArray(src.samples) ? src.samples.slice() : [];
        b.hourly_buckets[i].mean    = src.mean   || 0;
        b.hourly_buckets[i].stddev  = src.stddev || 0;
      }
    }
    b.domain_seen = Object.assign(Object.create(null), s.domain_seen || {});
    b.hourly_domain_log = (s.hourly_domain_log || []).map(h => ({
      ts_hour: h.ts_hour, set: new Set(h.set || []), new_count: h.new_count || 0,
    }));
    b.unique_domains_per_hr_avg = s.unique_domains_per_hr_avg || 0;
    b.new_domain_rate_avg       = s.new_domain_rate_avg || 0;
    b.last_seen_per_dst = Object.assign(Object.create(null), s.last_seen_per_dst || {});
    b.intervals_per_dst = Object.create(null);
    for (const k of Object.keys(s.intervals_per_dst || {})) {
      b.intervals_per_dst[k] = (s.intervals_per_dst[k] || []).slice();
    }
    b.periodicity_hits = s.periodicity_hits || 0;
    b.country_seen     = Object.assign(Object.create(null), s.country_seen || {});
    b.daily_country_log = (s.daily_country_log || []).map(d => ({
      day_idx: d.day_idx, set: new Set(d.set || []),
    }));
    b.country_diversity_avg = s.country_diversity_avg || 0;
    state.device_baselines[mac] = b;
    n++;
  }
  return n;
}

// ---------------------------------------------------------------------------
module.exports = {
  ingest,
  getBaseline,
  score,
  prune,
  getRecentAnomalies,
  exportSnapshot,
  importSnapshot,
  // exposed for tests / dashboard
  _state: state,
  _DEFAULTS: DEFAULTS,
};
