// In-memory sliding-window rate limiter + daily token budget +
// circuit breaker. All three are state-trackers that need to survive
// across requests within one process. Single-process; for horizontal
// scaling, swap to Redis with the same API.
//
// Typical key shape is `(caller_did, peer_slug)` so a noisy peer can
// saturate one tenant without affecting their others, and one bad
// caller saturates one tenant without poisoning the gateway-wide quota.

const SWEEP_INTERVAL_MS = 60_000;

/**
 * Sliding window rate limiter. Keeps a list of request timestamps
 * per key.
 *
 * Bucket count is bounded by `maxBuckets`. When a new key arrives at
 * the cap, the OLDEST bucket (insertion order) is evicted. This
 * prevents unbounded memory growth from attacker-controlled keys
 * (e.g. a flood of synthetic caller_dids) while letting legitimate
 * traffic continue. The trade-off: a real user whose bucket is
 * evicted under flood gets a fresh window — degraded rate-limiting
 * but not service denial. Set `maxBuckets` based on legitimate
 * traffic volume; see SECURITY.md for sizing guidance.
 */
export class RateLimiter {
  constructor({ requestsPerMinute, maxBuckets = 100_000 } = {}) {
    if (!Number.isFinite(requestsPerMinute) || requestsPerMinute <= 0) {
      throw new Error('requestsPerMinute must be a positive number');
    }
    if (!Number.isFinite(maxBuckets) || maxBuckets <= 0) {
      throw new Error('maxBuckets must be a positive number');
    }
    this.limit = requestsPerMinute;
    this.maxBuckets = maxBuckets;
    this.windowMs = 60_000;
    this.buckets = new Map();
    this.sweepInterval = setInterval(() => this.sweep(), SWEEP_INTERVAL_MS);
    if (this.sweepInterval.unref) this.sweepInterval.unref();
  }

  /**
   * Atomic check-and-record. Returns true if the request is allowed
   * and records it. Returns false if the request would exceed the rate.
   */
  consume(key) {
    const now = Date.now();
    const cutoff = now - this.windowMs;
    let bucket = this.buckets.get(key);
    if (!bucket) {
      // Make room for the new bucket if we're at the cap. Sweep
      // first; if still full, evict the oldest. Map iteration order
      // is insertion order so the first key is the oldest.
      if (this.buckets.size >= this.maxBuckets) {
        this.sweep();
        if (this.buckets.size >= this.maxBuckets) {
          const oldest = this.buckets.keys().next().value;
          this.buckets.delete(oldest);
        }
      }
      bucket = [];
      this.buckets.set(key, bucket);
    }
    // Splice once instead of shift() in a loop — shift() is O(n) per
    // call, so a high-volume bucket pruning was O(n²). splice with
    // the cutoff index is O(n).
    if (bucket.length > 0 && bucket[0] < cutoff) {
      let idx = 0;
      while (idx < bucket.length && bucket[idx] < cutoff) idx += 1;
      bucket.splice(0, idx);
    }
    if (bucket.length >= this.limit) return false;
    bucket.push(now);
    return true;
  }

  sweep() {
    const cutoff = Date.now() - this.windowMs;
    for (const [k, bucket] of this.buckets) {
      if (bucket.length > 0 && bucket[0] < cutoff) {
        let idx = 0;
        while (idx < bucket.length && bucket[idx] < cutoff) idx += 1;
        bucket.splice(0, idx);
      }
      if (bucket.length === 0) this.buckets.delete(k);
    }
  }

  size() {
    return this.buckets.size;
  }

  stop() {
    clearInterval(this.sweepInterval);
  }
}

/**
 * Daily token budget per key. Resets at 00:00 UTC. Estimate is crude
 * (bytes / 4) — close enough for a defensive cap. The actual LLM-side
 * spend tracking is on the provider's side; this is just to stop a
 * runaway peer from burning a tenant's budget in seconds.
 */
export class DailyTokenBudget {
  constructor({ tokensPerDay, maxBuckets = 100_000 } = {}) {
    if (!Number.isFinite(tokensPerDay) || tokensPerDay <= 0) {
      throw new Error('tokensPerDay must be a positive number');
    }
    if (!Number.isFinite(maxBuckets) || maxBuckets <= 0) {
      throw new Error('maxBuckets must be a positive number');
    }
    this.limit = tokensPerDay;
    this.maxBuckets = maxBuckets;
    this.buckets = new Map(); // key -> { tokens, day }
  }

  todayUtc() {
    return new Date().toISOString().slice(0, 10);
  }

  estimate(req) {
    // Rough heuristic: every 4 bytes of body ≈ 1 token. Be defensive:
    // an attacker could send `Content-Length: NaN` (or Infinity, or
    // negative). Number(...) returns NaN for "NaN" / unparseable.
    // Without isFinite() we'd push NaN downstream, where consume()
    // does `bucket.tokens + tokens` → NaN, then `NaN > limit` is
    // always false → request always allowed → budget is poisoned for
    // that key forever.
    const len = req.headers && req.headers['content-length'];
    if (typeof len === 'string') {
      const n = Number(len);
      if (Number.isFinite(n) && n >= 0) return Math.ceil(n / 4);
    }
    if (req.body) {
      try { return Math.ceil(JSON.stringify(req.body).length / 4); } catch { /* fall through */ }
    }
    return 0;
  }

  consume(key, tokens) {
    // Defensive guard: only finite, non-negative token counts ever
    // mutate bucket state. NaN/Infinity/negative would poison the
    // bucket via `bucket.tokens += tokens`.
    if (!Number.isFinite(tokens) || tokens < 0) tokens = 0;
    const day = this.todayUtc();
    let bucket = this.buckets.get(key);
    if (!bucket || bucket.day !== day) {
      // If we're at the bucket cap, sweep stale buckets (different
      // day) first; if still full, evict the oldest. Bounds memory
      // under attacker-controlled key floods. Trade-off: an evicted
      // legit bucket loses its accumulated daily count and starts
      // fresh — degraded budget enforcement, not service denial.
      // See SECURITY.md for sizing guidance on maxBuckets.
      if (!bucket && this.buckets.size >= this.maxBuckets) {
        for (const [k, b] of this.buckets) {
          if (b.day !== day) this.buckets.delete(k);
        }
        if (this.buckets.size >= this.maxBuckets) {
          const oldest = this.buckets.keys().next().value;
          this.buckets.delete(oldest);
        }
      }
      bucket = { tokens: 0, day };
      this.buckets.set(key, bucket);
    }
    if (bucket.tokens + tokens > this.limit) {
      return { allowed: false, used: bucket.tokens, limit: this.limit, remaining: this.limit - bucket.tokens };
    }
    bucket.tokens += tokens;
    return { allowed: true, used: bucket.tokens, limit: this.limit, remaining: this.limit - bucket.tokens };
  }

  size() {
    return this.buckets.size;
  }
}

/**
 * Circuit breaker per peer slug. Counts consecutive 429s from
 * upstream; opens after `threshold` failures, stays open for
 * `cooldownMs`. While open, the gateway short-circuits with 503 so
 * we don't keep hammering an overloaded upstream.
 */
const DEFAULT_THRESHOLD = 3;
const DEFAULT_COOLDOWN_MS = 15 * 60 * 1000;

export class CircuitBreaker {
  constructor({ threshold = DEFAULT_THRESHOLD, cooldownMs = DEFAULT_COOLDOWN_MS, maxPeers = 10_000 } = {}) {
    this.threshold = threshold;
    this.cooldownMs = cooldownMs;
    this.maxPeers = maxPeers;
    this.state = new Map(); // slug -> { consecutive429s, openUntil }
  }

  isOpen(slug) {
    const s = this.state.get(slug);
    if (!s) return false;
    if (s.openUntil && s.openUntil > Date.now()) return true;
    if (s.openUntil && s.openUntil <= Date.now()) {
      this.state.delete(slug);
    }
    return false;
  }

  record(slug, status) {
    let s = this.state.get(slug);
    if (status === 429) {
      if (!s) {
        // Bound peer-state map. Slugs aren't typically attacker-
        // controlled but keeping consistency with the other
        // bucket-cap defenses. On overflow, evict the oldest
        // (peer with the longest-passed last-update).
        if (this.state.size >= this.maxPeers) {
          const oldest = this.state.keys().next().value;
          if (oldest !== undefined) this.state.delete(oldest);
        }
        s = { consecutive429s: 0, openUntil: null };
      }
      s.consecutive429s += 1;
      if (s.consecutive429s >= this.threshold) {
        s.openUntil = Date.now() + this.cooldownMs;
      }
      this.state.set(slug, s);
    } else if (status >= 200 && status < 500) {
      // Any non-5xx-non-429 resets the counter.
      if (s) this.state.delete(slug);
    }
  }

  size() {
    return this.state.size;
  }

  cooldownRemaining(slug) {
    const s = this.state.get(slug);
    if (!s?.openUntil) return 0;
    return Math.max(0, s.openUntil - Date.now());
  }
}
