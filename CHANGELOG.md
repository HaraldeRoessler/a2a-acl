# Changelog

## 0.1.2 — 2026-04-30

Second-pass security review. 10 issues found by external review;
all fixed.

### Fixed (HIGH)

- **No err.message leakage in HTTP responses** (`middleware.js`). The
  `verifyAaeMiddleware` 503 response previously included
  `detail: err.message` from the resolver-throw catch — a probing
  attacker could extract internal paths, DB driver strings, library
  internals. Removed; details now logged server-side only.

- **Bucket-cap on RateLimiter and DailyTokenBudget**
  (`rate-limit.js`). Both classes used attacker-controlled keys
  (`${callerDid}|${slug}`) for their backing Maps with no upper
  bound — an attacker churning unique synthetic DIDs could exhaust
  memory. Added `maxBuckets` (default 100,000) with sweep-then-FIFO
  eviction. The trade-off is documented in SECURITY.md: degraded
  rate-limiting under attack, not service denial.

- **`__proto__` canonicalisation hazard fixed via strict allowlist**
  (`aae.js`). Previously canonicalised over `{ ...env }` which
  includes any key the JSON parser produces. Different runtimes
  (Python, Go, Rust) handle `__proto__` differently — the signer
  and verifier could disagree, opening either signature-verification
  bypass or false rejection. Now the verifier enumerates a strict
  allowlist of known envelope fields (`v, iss, sub, aud, exp, iat,
  jti, sig_key_id, sig_alg, hop, perm`) and ignores everything else
  on the parsed envelope. Any future field requires an explicit
  library bump.

- **`inferCapability` validates wing/room/tool segments**
  (`capability.js`). Previously concatenated unvalidated wing/room
  values from the request body into the capability string, allowing
  an attacker to ship a 10MB `wing` field that flowed into matchAcl,
  audit logs, and error responses. Now validated against
  `[a-z][a-z0-9-]{0,30}` BEFORE composing the capability — any
  invalid input returns null, the ACL middleware then rejects 400.

### Fixed (MEDIUM)

- **TtlResolver max cache size** (`resolvers.js`). Both KeyResolver,
  TrustResolver, and RevocationChecker now cap their backing caches
  at `maxSize` (default 10,000) with sweep-then-FIFO eviction.
  Defends against cache exhaustion via attacker-controlled key_id /
  DID / jti floods.

- **Audit middleware strips query string by default**
  (`middleware.js`). The audit row's `path` field defaults to the
  path without the query string. Many callers leak API keys or
  tokens via query parameters; this prevents those from landing in
  the audit sink unnoticed. Opt-in to query logging via
  `includeQueryInAudit: true`.

### Fixed (LOW)

- **Audit sink failure logged at error, not warn** (`middleware.js`).
  A silent audit-trail gap is a security incident, not a warning. If
  an attacker can cause the sink to throw, operators want a noisy
  signal.

- **Opaque fail reasons in `verifyAae`** (`aae.js`). Previously the
  `key_resolver_failed:`, `key_format_error:`, and
  `sig_verify_error:` reasons embedded sliced underlying error
  messages. Could leak library internals to clients via the 401/503
  response body. Now fixed strings; resolvers should log details
  server-side themselves.

- **NonceCache lifecycle documented** (`nonce-cache.js`). Doc
  comment now states the constructor starts a `setInterval`; the
  class is intended as a per-process singleton; if discarded, the
  caller must `.stop()` first.

### Added

- 17 new regression tests (`test/security-2.test.js`) covering each
  fix above.
- `express` added as a `devDependency` (was already a peerDependency)
  so the leak-test can spin up a real HTTP server.
- All 47 tests pass.

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
