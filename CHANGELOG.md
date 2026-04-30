# Changelog

## 0.1.4 — 2026-04-30

Fourth-pass review. Two reviewers, eight more findings, all
addressed. Most are defence-in-depth on top of the already-strong
0.1.3 surface.

### Fixed

- **`sig` field length cap (LOW-MED)** (`aae.js`). All other string
  fields were 256-char-capped; `sig` was unchecked. An attacker with
  a valid signing key could ship a 10MB base64 sig, decoded to ~7.5MB
  in `b64urlDecode` before signature verification fails. Now: capped
  at 512 chars (Ed25519 sig is ~86 chars; future post-quantum schemes
  fit under the cap or warrant a major bump).

- **`perm` array element count cap (LOW)** (`aae.js`). Array type
  was checked but length wasn't. A signer with a valid key could
  send `perm: new Array(100_000).fill({...})` which gets canonicalised
  into the signed payload + visited per `coversOp()`. Now: 100-element
  cap with explicit `perm_too_long` reason.

- **`coversOp` defensive against null/non-object perm elements
  (MEDIUM)** (`aae.js`). Previous: `p.op` accesses on a null element
  would throw, crashing the request handler. Now: skips non-object
  entries silently. Caller can rely on `coversOp` returning a clean
  boolean.

- **`isPublic` overly broad suffix match (LOW)** (`middleware.js`).
  0.1.3 added `endsWith('/agent-card')` as a fallback for the
  mounted-middleware case. That accidentally matched any URL ending
  in `/agent-card` — e.g. `/internal/something/agent-card` would
  bypass auth. Now: exact match only against canonical paths,
  including the configured basePath's `/agent-card`. The mounted
  case is recognised by `req.path === '/agent-card' && req.baseUrl
  === basePath`.

- **`sanitiseDeep` skips `__proto__` / `constructor` / `prototype`
  keys (VERY LOW)** (`sanitise.js`). Sanitiser was already covering
  values + keys, but `out['__proto__'] = ...` would mutate the
  output's prototype rather than create a data property if upstream
  code passed `__proto__` as an own enumerable. Now: the three
  prototype-pollution-flavoured keys are dropped entirely.

- **`revocationChecker.isRevoked()` throw mapped to distinct reason
  (VERY LOW, observability)** (`aae.js`, `middleware.js`). Previously
  rev-backend errors propagated up as a generic 'aae verify threw'.
  Now: caught at the verify layer and surfaced as
  `revocation_checker_failed`, distinct from `key_resolver_failed`.
  Both still 503 client-side (under the unified `verify_unavailable`
  label), but operators can distinguish in their logs.

- **`CircuitBreaker` numeric param validation (INFO)**
  (`rate-limit.js`). Previously accepted `threshold: NaN` /
  `cooldownMs: Infinity` silently — the breaker would never open
  or never close. Now throws at construct time so a typo in config
  fails loudly.

- **`trustScoreGateMiddleware` `defaultThreshold` validation
  (INFO)** (`middleware.js`). Same pattern. Previously a NaN
  threshold meant `score < threshold` was always false → every
  request bypassed the gate silently. Now throws at construct time.

- **`getExpectedSub` Promise detection (INFO, dev footgun)**
  (`middleware.js`). If the caller accidentally made the callback
  async, the returned Promise was passed as `expectedSub`, then
  `string !== Promise` rejected every request as `wrong_subject`.
  Now: detected explicitly and surfaced as
  `{"error":"middleware_misconfigured"}` (HTTP 500) with a clear
  error log, so the misconfiguration is loud.

### Added

- 16 new regression tests in `test/security-4.test.js` covering
  every fix above.
- 90/90 tests pass (74 from 0.1.3 + 16 new).

### Behavioural change worth noting

- `verifyAaeMiddleware` now returns
  `{"error":"verify_unavailable"}` for both
  `key_resolver_failed` and `revocation_checker_failed` (was
  `{"error":"key_resolver_unavailable"}` for the former in 0.1.3).
  The reason was unified under one label — clients don't need to
  know which backend failed, and the operator-side logs distinguish
  the two via the `result.reason` field.

## 0.1.3 — 2026-04-30

Third-pass security review. Two external reviewers (independently)
found 20 issues; all addressed.

### Fixed (CRITICAL)

- **Cross-peer replay via missing sub validation** (`aae.js`,
  `middleware.js`). `verifyAae` previously accepted `expectedSub`
  in its config but never validated `env.sub` against it — meaning
  any envelope captured for peer alice could be replayed against
  peer bob within the same audience and expiry window. Worse, an
  envelope with `sub` omitted entirely worked against any peer.
  Now: when `expectedSub` is set, `env.sub` MUST be present and
  match. Middleware exposes a new `getExpectedSub` callback (opt-in,
  no breaking default — previous middleware passed `getSlug` as
  expectedSub, which was set-but-ignored).

- **NaN bypass in time / hop / score / token validation**
  (`aae.js`, `middleware.js`, `rate-limit.js`, `resolvers.js`,
  `nonce-cache.js`). `typeof NaN === 'number'`, so envelope fields
  with NaN passed every type check. Comparisons against NaN are
  always false (`NaN < x` and `NaN > x` both false), so NaN-laced
  fields BYPASSED:
    - exp / iat (envelope time checks)
    - hop (recursion depth guard)
    - trust score (gate)
    - Content-Length (token budget — bucket got poisoned)
  Plus `nonceCache.seen(jti, NaN)` permanently saturated the cache
  because `NaN <= now` is false in sweep. Now: every numeric path
  uses `Number.isFinite()` defensively, and NonceCache.sweep treats
  any non-finite expiry as expired.

- **`key_resolver_failed` colon-mismatch regression**
  (`middleware.js`). 0.1.2 changed the verify-side reason from
  `key_resolver_failed:<message>` to a clean `key_resolver_failed`,
  but the middleware still checked `startsWith('key_resolver_failed:')`
  (note the colon). The 503 path was unreachable; resolver failures
  silently fell through to the generic 401 `aae_rejected`, hiding
  transient backend outages and potentially causing callers to
  rotate good envelopes instead of retrying. Fixed.

### Fixed (HIGH)

- **TtlResolver `_inflight` Map unbounded** (`resolvers.js`). 0.1.2
  capped `_cache` but `_inflight` had no bound — an attacker
  flooding requests with unique sig_key_id values, each evicted
  from the bounded cache, could create unbounded pending promises
  each holding a slow resolver call. Now: `maxInflight` cap
  (default 1,000) on both `TtlResolver` and `RevocationChecker`.
  Throws `inflight_cap_exceeded` when full → propagates to
  fail-closed at the verify step.

- **`perm` field never type-validated** (`aae.js`). `SIGNED_FIELDS`
  included 'perm' but `env.perm` was passed through unchecked. An
  attacker setting `perm: "evil-string"` would survive into
  `result.perm`, where `coversOp` would iterate individual
  characters or potentially throw. Now: rejected as
  `perm_invalid_type` if not an array.

### Fixed (MEDIUM)

- **`canonicalize` export diverges from verifier logic**
  (`aae.js`). Cross-language signers reading the exported
  `canonicalize` source might replicate "sort all keys" behavior
  and miss the SIGNED_FIELDS allowlist, producing payloads the
  verifier won't accept. Now: `signablePayload(env)` exported as
  the single source of truth, plus `SIGNED_FIELDS` exported as a
  frozen const. `canonicalize` doc-marked as low-level.

- **Audit sink async rejections unhandled** (`middleware.js`).
  Previous code wrapped `sink(row)` in a synchronous try/catch.
  An async sink returning a rejected Promise was NOT caught and
  could crash Node under `--unhandled-rejections=strict`. Now:
  `Promise.resolve(sink(row)).catch(...)` funnels both sync
  throws and async rejections into the error logger.

- **ROLE_FLIPS regex `g`-flag state risk** (`sanitise.js`).
  Used `.test()` on a shared regex with the `/g` flag — `lastIndex`
  state is mutable and shared across requests. Future refactoring
  could miss matches. Now: fresh RegExp per call, matching the
  defensive pattern already used for OVERRIDE_PHRASES.

- **`sanitiseDeep` didn't sanitise object keys** (`sanitise.js`).
  Property names like `"system: "` or those carrying invisible
  unicode could survive into downstream contexts. Now: keys are
  sanitised too.

### Fixed (LOW)

- **Trust score / threshold leaked in 403 response body**
  (`middleware.js`). Returning these gave attackers a precise
  oracle for probing what their score is and how close to the
  threshold. Now: `{"error":"trust_score_below_threshold"}` only;
  scores logged server-side.

- **`threshold_override` accepted out-of-range values**
  (`middleware.js`). `-1`, `Infinity`, `1.1` would silently apply,
  letting any/no scores pass. Now: `Number.isFinite && >= 0 && <=
  1` validation; out-of-range falls back to gateway default.

- **Unbounded string fields on AAE envelope** (`aae.js`). `iss`,
  `sub`, `jti`, `aud`, `sig_key_id` had no length cap — outsized
  signer values flowed into audit logs, ACL queries, response
  bodies. Now: 256-char cap with explicit `*_too_long` reasons.

- **Rate-limit key collision via `|`** (`middleware.js`). The
  composite key `${callerDid}|${slug}` would collide if a DID
  contained `|`. Now: JSON-encoded tuple — `["a|b","c"]` is
  unambiguously different from `["a","b|c"]`.

- **Public path detection failed when middleware mounted under a
  path** (`middleware.js`). When `app.use('/api/a2a', firewallChain
  (...))`, Express set `req.path` to the path AFTER the mount
  (e.g. `/agent-card`). The PUBLIC_PATHS set contained
  `/api/a2a/agent-card`, so agent-card discovery incorrectly
  required AAE auth. Now: combines `req.baseUrl + req.path` for
  matching, plus suffix-based fallback for the `agent-card` path.

- **CircuitBreaker.state Map had no bound** (`rate-limit.js`).
  Slugs aren't typically attacker-controlled, but consistency with
  the other state-tracker caps. Now: `maxPeers` (default 10,000)
  with FIFO eviction.

- **RateLimiter bucket `Array.shift()` in a loop**
  (`rate-limit.js`). `shift()` is O(n) per call; high-volume
  bucket pruning was O(n²). Replaced with a single `splice`.

### Added

- 27 new regression tests (`test/security-3.test.js`) covering
  every fix above, including a real Express + fetch test for the
  public-path-under-mount fix and the 503 colon-mismatch fix.
- Total tests: 74 (47 from 0.1.2 + 27 new); all pass.

### Changed (intentional behaviour)

- `verifyAaeMiddleware` no longer passes `expectedSub: getSlug(req)`
  by default. The 0.1.2 default was set-but-ignored (sub was never
  validated by `verifyAae`), so this is not a real breaking change
  for callers. Once you understand your signer's sub convention
  (DID? slug? something else?), opt in to validation by setting
  the `getExpectedSub` callback. See SECURITY.md for guidance.

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
