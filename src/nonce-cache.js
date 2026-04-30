// Replay protection — short-window jti cache. The verify step rejects
// any envelope whose jti has already been seen within its lifetime.
//
// Single-process; for horizontal scaling, swap to a Redis-backed
// implementation with the same API (.seen(jti, expSec) → boolean).

const MAX_ENTRIES = 10_000;

export class NonceCache {
  constructor({ sweepIntervalMs = 30_000, maxEntries = MAX_ENTRIES } = {}) {
    this.maxEntries = maxEntries;
    this.cache = new Map();
    this.sweepInterval = setInterval(() => this.sweep(), sweepIntervalMs);
    if (this.sweepInterval.unref) this.sweepInterval.unref();
  }

  /**
   * Returns true if this is the FIRST time we've seen this jti
   * (caller should accept). Returns false on replay.
   */
  seen(jti, expSec) {
    if (this.cache.has(jti)) return false;
    if (this.cache.size >= this.maxEntries) {
      // Drop oldest (Map iteration order = insertion order).
      const oldest = this.cache.keys().next().value;
      this.cache.delete(oldest);
    }
    this.cache.set(jti, expSec);
    return true;
  }

  sweep() {
    const now = Math.floor(Date.now() / 1000);
    for (const [jti, exp] of this.cache) {
      if (exp <= now) this.cache.delete(jti);
    }
  }

  size() {
    return this.cache.size;
  }

  stop() {
    clearInterval(this.sweepInterval);
  }
}
