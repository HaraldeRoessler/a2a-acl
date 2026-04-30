// TTL-cached resolvers. Each takes a `resolve` (or `check`) callback
// from the caller — the library doesn't know HOW you store keys / trust
// scores / revocations, just WHEN to ask and HOW LONG to remember the
// answer.
//
// Pattern: positive results cached longer than negatives. Transient
// failures (resolver throws) propagate up so the verify step can fail
// closed without poisoning the cache for the next request.

const DEFAULT_TTL_POS_MS = 5 * 60 * 1000;
const DEFAULT_TTL_NEG_MS = 30 * 1000;
const DEFAULT_MAX_CACHE = 10_000;

/**
 * Generic TTL cache around a resolver callback. Subclasses below adapt
 * this to specific use cases (KeyResolver, TrustResolver, ...).
 *
 * In-flight promise dedup: if N concurrent requests arrive for the
 * same uncached key, only ONE call reaches the underlying resolve()
 * callback. The other N-1 await the same promise. This protects the
 * caller's storage backend (e.g. CP DB) from thundering-herd loads
 * triggered by a flood of inbound A2A requests for the same DID/key.
 */
class TtlResolver {
  /**
   * @param {object} opts
   *   @param {(key: string) => Promise<any>} opts.resolve  resolver callback
   *   @param {number} [opts.ttlPositiveMs]  cache duration for non-null results
   *   @param {number} [opts.ttlNegativeMs]  cache duration for null/missing results
   */
  constructor({
    resolve,
    ttlPositiveMs = DEFAULT_TTL_POS_MS,
    ttlNegativeMs = DEFAULT_TTL_NEG_MS,
    maxSize = DEFAULT_MAX_CACHE,
    maxInflight = 1_000,
  }) {
    if (typeof resolve !== 'function') throw new Error('resolve callback required');
    if (!Number.isFinite(maxSize) || maxSize <= 0) throw new Error('maxSize must be a positive number');
    if (!Number.isFinite(maxInflight) || maxInflight <= 0) throw new Error('maxInflight must be a positive number');
    this._resolve = resolve;
    this._ttlPos = ttlPositiveMs;
    this._ttlNeg = ttlNegativeMs;
    this._maxSize = maxSize;
    this._maxInflight = maxInflight;
    this._cache = new Map();
    this._inflight = new Map(); // key -> Promise<value>
  }

  // Sweep expired entries. Called opportunistically before forced
  // evictions so we don't displace cache lines that would have
  // expired on their own anyway.
  _sweepExpired() {
    const now = Date.now();
    for (const [k, v] of this._cache) {
      if (v.expiresAt <= now) this._cache.delete(k);
    }
  }

  // Bound the cache size. Bounds memory under attacker-controlled
  // key floods (e.g. millions of unique key_id / DID values within a
  // single TTL window). On overflow: sweep expired first, then evict
  // the oldest unexpired entry (FIFO via Map insertion order).
  _enforceCap() {
    if (this._cache.size <= this._maxSize) return;
    this._sweepExpired();
    while (this._cache.size > this._maxSize) {
      const oldest = this._cache.keys().next().value;
      if (oldest === undefined) break;
      this._cache.delete(oldest);
    }
  }

  async _get(key) {
    const cached = this._cache.get(key);
    if (cached && cached.expiresAt > Date.now()) return cached.value;

    // Dedup concurrent misses for the same key.
    const inflight = this._inflight.get(key);
    if (inflight) return inflight;

    // Bound the in-flight map. Without this, an attacker who floods
    // requests with unique keys (each evicted from the bounded
    // _cache on insertion) creates an unbounded number of pending
    // promises, each holding a slow resolver call. Fail-closed: if
    // we can't track new in-flight work we throw, which propagates
    // up to the verify step as a fail-closed reason.
    if (this._inflight.size >= this._maxInflight) {
      throw new Error('inflight_cap_exceeded');
    }

    const promise = (async () => {
      try {
        const value = await this._resolve(key);
        const ttl = value === null || value === undefined ? this._ttlNeg : this._ttlPos;
        this._cache.set(key, { value, expiresAt: Date.now() + ttl });
        this._enforceCap();
        return value;
      } finally {
        // Always remove the in-flight entry — whether resolve succeeded,
        // returned null, or threw. On throw we deliberately do NOT cache
        // the failure so transient errors can self-heal on retry.
        this._inflight.delete(key);
      }
    })();
    this._inflight.set(key, promise);
    return promise;
  }

  inflightSize() {
    return this._inflight.size;
  }

  invalidate(key) {
    this._cache.delete(key);
  }

  size() {
    return this._cache.size;
  }
}

/**
 * Resolves AAE sig_key_id → public key material.
 * Caller's `resolve(keyId)` should return:
 *   { public_key_b64url: 'base64url-32-bytes', sig_alg: 'Ed25519' }
 * or null if the key isn't recognised. Throw on transient failures so
 * the verify step fails closed.
 */
export class KeyResolver {
  constructor(opts) {
    this._inner = new TtlResolver(opts);
  }
  resolve(keyId) {
    return this._inner._get(keyId);
  }
  invalidate(keyId) {
    this._inner.invalidate(keyId);
  }
  size() {
    return this._inner.size();
  }
}

/**
 * Resolves DID → trust score (number).
 * Caller's `resolve(did)` should return:
 *   { score: 0.85 }  (or just a number)
 * or null/undefined for unknown DIDs (treated as score 0).
 */
export class TrustResolver {
  constructor(opts) {
    this._inner = new TtlResolver(opts);
  }
  async getScore(did) {
    const v = await this._inner._get(did);
    if (v === null || v === undefined) return 0;
    // Reject NaN/Infinity. Without isFinite, an attacker (or a buggy
    // resolver) returning NaN would bypass the trust gate: `NaN <
    // threshold` is false in JS, so the request would be allowed.
    // Coerce to 0 so the gate fails closed instead.
    if (typeof v === 'number') return Number.isFinite(v) ? v : 0;
    if (typeof v?.score === 'number') return Number.isFinite(v.score) ? v.score : 0;
    return 0;
  }
  invalidate(did) {
    this._inner.invalidate(did);
  }
  size() {
    return this._inner.size();
  }
}

/**
 * Checks whether an envelope jti has been revoked.
 * Caller's `check(jti)` returns true if revoked, false otherwise.
 * Throw on transient failures.
 */
export class RevocationChecker {
  /**
   * @param {object} opts
   *   @param {(jti: string) => Promise<boolean>} opts.check
   *   @param {number} [opts.ttlMs]
   *   @param {number} [opts.maxSize]
   */
  constructor({
    check,
    ttlMs = DEFAULT_TTL_NEG_MS,
    maxSize = DEFAULT_MAX_CACHE,
    maxInflight = 1_000,
  }) {
    if (typeof check !== 'function') throw new Error('check callback required');
    if (!Number.isFinite(maxSize) || maxSize <= 0) throw new Error('maxSize must be a positive number');
    if (!Number.isFinite(maxInflight) || maxInflight <= 0) throw new Error('maxInflight must be a positive number');
    this._check = check;
    this._ttlMs = ttlMs;
    this._maxSize = maxSize;
    this._maxInflight = maxInflight;
    this._cache = new Map();
    this._inflight = new Map(); // jti -> Promise<boolean>
  }

  async isRevoked(jti) {
    const cached = this._cache.get(jti);
    if (cached && cached.expiresAt > Date.now()) return cached.revoked;

    // Dedup concurrent misses for the same jti — same pattern as
    // TtlResolver. Without this, 1000 simultaneous requests for the
    // same jti each call this._check (revocation backend) once.
    const inflight = this._inflight.get(jti);
    if (inflight) return inflight;
    if (this._inflight.size >= this._maxInflight) {
      throw new Error('inflight_cap_exceeded');
    }

    const promise = (async () => {
      try {
        const revoked = await this._check(jti);
        this._cache.set(jti, { revoked, expiresAt: Date.now() + this._ttlMs });
        // Bound memory under jti flood: sweep expired, then evict oldest.
        if (this._cache.size > this._maxSize) {
          const now = Date.now();
          for (const [k, v] of this._cache) {
            if (v.expiresAt <= now) this._cache.delete(k);
          }
          while (this._cache.size > this._maxSize) {
            const oldest = this._cache.keys().next().value;
            if (oldest === undefined) break;
            this._cache.delete(oldest);
          }
        }
        return revoked;
      } finally {
        this._inflight.delete(jti);
      }
    })();
    this._inflight.set(jti, promise);
    return promise;
  }

  invalidate(jti) {
    this._cache.delete(jti);
  }

  size() {
    return this._cache.size;
  }
}
