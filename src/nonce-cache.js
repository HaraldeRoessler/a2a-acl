// Replay protection — short-window jti cache. The verify step rejects
// any envelope whose jti has already been seen within its lifetime.
//
// Single-process; for horizontal scaling, swap to a Redis-backed
// implementation with the same API (.seen(jti, expSec) → boolean).
//
// IMPORTANT: this class starts a setInterval at construction. Treat
// it as a per-process singleton — instantiate once at server startup,
// never inside request handlers. If you must discard a NonceCache
// (tests, hot-reload), call `.stop()` first or the timer leaks.
// The interval is unref'd so it won't block process exit, but the
// memory footprint of orphaned timers and Map state is real.

const MAX_ENTRIES = 10_000;

export class NonceCache {
  constructor({ sweepIntervalMs = 30_000, maxEntries = MAX_ENTRIES } = {}) {
    this.maxEntries = maxEntries;
    this.cache = new Map();
    this.sweepInterval = setInterval(() => this.sweep(), sweepIntervalMs);
    if (this.sweepInterval.unref) this.sweepInterval.unref();
  }

  /**
   * Returns:
   *   true          — first sight, caller should accept
   *   false         — replay, caller must reject
   *   'cache_full'  — sweep ran but cache is still saturated; caller
   *                   must reject (fail-closed). Evicting the oldest
   *                   entry would create a replay window for envelopes
   *                   the attacker can keep alive past our memory of
   *                   their jti.
   *
   * If you're seeing 'cache_full' regularly, raise `maxEntries` or
   * shorten envelope `exp` so entries naturally drain.
   */
  seen(jti, expSec) {
    if (this.cache.has(jti)) return false;
    if (this.cache.size >= this.maxEntries) {
      // Try to make room by sweeping expired entries first.
      this.sweep();
      if (this.cache.size >= this.maxEntries) {
        // Still full → fail-closed. We cannot evict an unexpired entry
        // without opening a replay hole.
        return 'cache_full';
      }
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
