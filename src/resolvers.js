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

/**
 * Generic TTL cache around a resolver callback. Subclasses below adapt
 * this to specific use cases (KeyResolver, TrustResolver, ...).
 */
class TtlResolver {
  /**
   * @param {object} opts
   *   @param {(key: string) => Promise<any>} opts.resolve  resolver callback
   *   @param {number} [opts.ttlPositiveMs]  cache duration for non-null results
   *   @param {number} [opts.ttlNegativeMs]  cache duration for null/missing results
   */
  constructor({ resolve, ttlPositiveMs = DEFAULT_TTL_POS_MS, ttlNegativeMs = DEFAULT_TTL_NEG_MS }) {
    if (typeof resolve !== 'function') throw new Error('resolve callback required');
    this._resolve = resolve;
    this._ttlPos = ttlPositiveMs;
    this._ttlNeg = ttlNegativeMs;
    this._cache = new Map();
  }

  async _get(key) {
    const cached = this._cache.get(key);
    if (cached && cached.expiresAt > Date.now()) return cached.value;
    const value = await this._resolve(key);
    const ttl = value === null || value === undefined ? this._ttlNeg : this._ttlPos;
    this._cache.set(key, { value, expiresAt: Date.now() + ttl });
    return value;
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
    if (typeof v === 'number') return v;
    if (typeof v.score === 'number') return v.score;
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
   */
  constructor({ check, ttlMs = DEFAULT_TTL_NEG_MS }) {
    if (typeof check !== 'function') throw new Error('check callback required');
    this._check = check;
    this._ttlMs = ttlMs;
    this._cache = new Map();
  }

  async isRevoked(jti) {
    const cached = this._cache.get(jti);
    if (cached && cached.expiresAt > Date.now()) return cached.revoked;
    const revoked = await this._check(jti);
    this._cache.set(jti, { revoked, expiresAt: Date.now() + this._ttlMs });
    return revoked;
  }

  invalidate(jti) {
    this._cache.delete(jti);
  }

  size() {
    return this._cache.size;
  }
}
