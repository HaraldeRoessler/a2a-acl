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
 * Sliding window rate limiter. Keeps a list of request timestamps per
 * key, prunes anything outside the window on each check.
 */
export class RateLimiter {
  constructor({ requestsPerMinute }) {
    if (!Number.isFinite(requestsPerMinute) || requestsPerMinute <= 0) {
      throw new Error('requestsPerMinute must be a positive number');
    }
    this.limit = requestsPerMinute;
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
      bucket = [];
      this.buckets.set(key, bucket);
    }
    while (bucket.length > 0 && bucket[0] < cutoff) bucket.shift();
    if (bucket.length >= this.limit) return false;
    bucket.push(now);
    return true;
  }

  sweep() {
    const cutoff = Date.now() - this.windowMs;
    for (const [k, bucket] of this.buckets) {
      while (bucket.length > 0 && bucket[0] < cutoff) bucket.shift();
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
  constructor({ tokensPerDay }) {
    if (!Number.isFinite(tokensPerDay) || tokensPerDay <= 0) {
      throw new Error('tokensPerDay must be a positive number');
    }
    this.limit = tokensPerDay;
    this.buckets = new Map(); // key -> { tokens, day }
  }

  todayUtc() {
    return new Date().toISOString().slice(0, 10);
  }

  estimate(req) {
    // Rough heuristic: every 4 bytes of body ≈ 1 token.
    const len = req.headers && req.headers['content-length'];
    if (typeof len === 'string') return Math.ceil(Number(len) / 4);
    if (req.body) {
      try { return Math.ceil(JSON.stringify(req.body).length / 4); } catch { /* fall through */ }
    }
    return 0;
  }

  consume(key, tokens) {
    const day = this.todayUtc();
    let bucket = this.buckets.get(key);
    if (!bucket || bucket.day !== day) {
      bucket = { tokens: 0, day };
      this.buckets.set(key, bucket);
    }
    if (bucket.tokens + tokens > this.limit) {
      return { allowed: false, used: bucket.tokens, limit: this.limit, remaining: this.limit - bucket.tokens };
    }
    bucket.tokens += tokens;
    return { allowed: true, used: bucket.tokens, limit: this.limit, remaining: this.limit - bucket.tokens };
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
  constructor({ threshold = DEFAULT_THRESHOLD, cooldownMs = DEFAULT_COOLDOWN_MS } = {}) {
    this.threshold = threshold;
    this.cooldownMs = cooldownMs;
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
      if (!s) s = { consecutive429s: 0, openUntil: null };
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

  cooldownRemaining(slug) {
    const s = this.state.get(slug);
    if (!s?.openUntil) return 0;
    return Math.max(0, s.openUntil - Date.now());
  }
}
