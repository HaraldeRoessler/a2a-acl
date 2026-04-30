# Changelog

## 0.1.1 — 2026-04-30

Security hardening release. No breaking API changes for callers using
the library as documented; behavioural changes in the verify path
that some malformed envelopes will now be rejected (correctly).

### Fixed

- **Audience check is now strict.** Previously, envelopes with a
  missing `aud` field passed the audience check (only mismatches were
  rejected). An attacker who could persuade a buggy issuer to mint an
  audless envelope could replay it across audiences. Now: when
  `expectedAud` is set (default), `env.aud` MUST be present and equal.
  Pass `expectedAud: null` to disable (not recommended).

- **Expiry is now required by default.** A signing-key compromise
  today should not invalidate a year of past envelopes. Envelopes
  without `exp` are rejected unless the caller explicitly sets
  `requireExp: false`.

- **Max envelope lifetime cap.** New `maxLifetimeSec` option (default
  300) rejects envelopes whose `exp` is more than that far in the
  future — defends against compromised-key long-term replay.

- **Type validation on envelope fields.** `iss`, `sub`, `jti`, `aud`,
  `exp`, `iat`, `hop` now strictly type-checked before use. Buggy
  issuers sending `exp: "1700000000"` (string) or `iat: true`
  (boolean) get explicit rejection rather than silent JS coercion.

- **NonceCache fail-closed when full.** Previously evicted the oldest
  entry when at `maxEntries`, opening a replay window: an attacker
  who flooded with 10001 distinct jti values could then replay a
  captured earlier envelope. Now: sweeps expired entries first; if
  still full, returns a `'cache_full'` sentinel and the verify step
  rejects with `nonce_cache_full`. Operators seeing this should raise
  `maxEntries` or shorten envelope lifetimes.

- **TtlResolver in-flight dedup.** Concurrent uncached requests for
  the same key now share a single underlying `resolve()` call,
  preventing thundering-herd loads against the caller's storage
  backend during a flood.

### Added

- `iatSkewSec` option (default 60) to make clock-skew tolerance
  configurable.
- `SECURITY.md` with vulnerability disclosure policy, threat model,
  and explicit non-goals (SQL injection, body size, multi-replica
  replay).
- 17 new security regression tests in `test/security.test.js`.

## 0.1.0 — 2026-04-30

Initial extraction. Per-tool capability ACL + AAE envelope
verification for agent-to-agent communication. Drop-in Express
middleware. MIT.
