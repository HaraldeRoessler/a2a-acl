// Express middleware factories. Each takes a config object and
// returns an Express middleware function.
//
// The library doesn't ship any concrete I/O — all storage and lookup
// is via callbacks the caller provides:
//
//   keyResolver       — a KeyResolver instance (resolvers.js)
//   trustResolver     — a TrustResolver instance
//   revocationChecker — a RevocationChecker instance
//   nonceCache        — a NonceCache instance
//   matchAcl          — async ({slug, callerDid, capability}) →
//                         {threshold_override?, rule_id, ...} | null
//   getSlug           — (req) → string  (defaults to req.params.slug
//                         or req.firewall.slug if pre-set by upstream)
//   getCapability     — (req) → string | null  (defaults to
//                         inferCapability with basePath option)
//
// Each middleware writes its decision/state onto req.firewall.* so
// downstream stages can read it. Use firewallChain(config) to compose
// the standard order.

import { verifyAae as verifyAaeImpl } from './aae.js';
import { sanitiseDeep } from './sanitise.js';
import { inferCapability } from './capability.js';

/* ───────────────── helpers ───────────────── */

function defaultGetSlug(req) {
  if (req.firewall?.slug) return req.firewall.slug;
  if (req.params?.slug) return req.params.slug;
  return null;
}

function ensureFirewall(req) {
  if (!req.firewall) req.firewall = {};
  return req.firewall;
}

const PUBLIC_PATHS = new Set([
  '/api/a2a/agent-card',
  '/.well-known/agent.json',
]);

function isPublic(req, basePath = '/api/a2a') {
  // When the chain is mounted via app.use('/api/a2a', ...), Express
  // sets req.path to the path AFTER the mount — e.g. '/agent-card'.
  // Combining baseUrl + path reconstructs the original path so
  // PUBLIC_PATHS still matches. originalUrl is also valid but may
  // include a query string.
  const fullPath = (req.baseUrl || '') + (req.path || '');
  if (PUBLIC_PATHS.has(fullPath)) return true;
  if (PUBLIC_PATHS.has(req.path)) return true;
  // Exact match against the configured basePath's agent-card.
  if (basePath && fullPath === `${basePath}/agent-card`) return true;
  if (basePath && req.path === `${basePath}/agent-card`) return true;
  // When the chain is mounted at basePath, req.path === '/agent-card'
  // and req.baseUrl === basePath. Match only this specific shape;
  // do NOT use endsWith('/agent-card') — that would let any URL
  // ending in /agent-card pass auth (e.g. /internal/api/a2a/agent-card).
  if (req.path === '/agent-card' && (req.baseUrl || '') === basePath) return true;
  return false;
}

/* ───────────────── stage 1: AAE verify ───────────────── */

/**
 * Verify the X-Klaw-AAE / X-AAE envelope. On success populates
 * req.firewall.aae + req.firewall.callerDid. On failure: 401 (or 503
 * if the key resolver had a transient error).
 *
 * If you provide `getExpectedSub`, the verifier enforces that
 * env.sub equals what the callback returns. This is the defence
 * against cross-peer replay (an envelope captured for peer alice
 * cannot be replayed against peer bob). Default: not validated
 * (advisory-only) — opt-in once your signer convention is known.
 */
export function verifyAaeMiddleware({
  keyResolver, revocationChecker, nonceCache,
  expectedAud,
  getExpectedSub,
  getSlug = defaultGetSlug,
  basePath = '/api/a2a',
  logger = null,
}) {
  if (!keyResolver) throw new Error('verifyAaeMiddleware requires keyResolver');
  if (!revocationChecker) throw new Error('verifyAaeMiddleware requires revocationChecker');
  if (!nonceCache) throw new Error('verifyAaeMiddleware requires nonceCache');

  return async function verifyAae(req, res, next) {
    const fw = ensureFirewall(req);

    if (isPublic(req, basePath)) {
      fw.public = true;
      fw.callerDid = 'anonymous';
      return next();
    }

    const headerVal = req.headers['x-klaw-aae'] || req.headers['x-aae'];

    // Resolve expectedSub synchronously. If the caller's getExpectedSub
    // returns a Promise (an accidentally-async function), passing the
    // Promise to verifyAaeImpl would cause `env.sub !== expectedSub`
    // to compare a string to a Promise — every request would 401 with
    // 'wrong_subject'. Catch this footgun explicitly with a clear
    // operator-side error so the misconfiguration is loud.
    let expectedSubValue;
    if (typeof getExpectedSub === 'function') {
      expectedSubValue = getExpectedSub(req);
      if (expectedSubValue && typeof expectedSubValue.then === 'function') {
        logger?.error?.({}, 'getExpectedSub must be synchronous');
        return res.status(500).json({ error: 'middleware_misconfigured' });
      }
    }

    let result;
    try {
      result = await verifyAaeImpl(headerVal, {
        keyResolver,
        revocationChecker,
        nonceCache,
        expectedAud: expectedAud === null ? null : (expectedAud ?? 'a2a-ingress'),
        expectedSub: expectedSubValue,
      });
    } catch (err) {
      // Log details server-side; never include err.message in the
      // HTTP response body (it can leak internal paths, library
      // names, DB driver strings to a probing attacker).
      logger?.error?.({ err: err.message }, 'aae verify threw');
      return res.status(503).json({ error: 'verify_unavailable' });
    }

    if (!result.verified) {
      logger?.warn?.({
        reason: result.reason,
        jti: result.jti,
        issuer: result.issuer,
        slug: getSlug(req),
      }, 'aae rejected');
      // Backend-failure reasons → 503 so callers retry. Key resolver
      // and revocation checker are both fail-closed dependencies; if
      // either is unavailable we can't decide on the envelope.
      // 0.1.2 had a bug here where the check was startsWith with a
      // trailing colon that never matched — fixed in 0.1.3 with
      // exact match. revocation_checker_failed added in 0.1.4 to
      // distinguish in operator logs.
      if (result.reason === 'key_resolver_failed' || result.reason === 'revocation_checker_failed') {
        return res.status(503).json({ error: 'verify_unavailable' });
      }
      return res.status(401).json({ error: 'aae_rejected', reason: result.reason });
    }

    fw.aae = result;
    fw.callerDid = result.issuer;
    next();
  };
}

/* ───────────────── stage 2: per-tool ACL ───────────────── */

/**
 * Look up (peer_slug, caller_did, capability) in the caller's ACL
 * store. Sets req.firewall.aclRule on success. On no match: 403.
 *
 * matchAcl callback:
 *   async ({ slug, callerDid, capability }) =>
 *     { threshold_override?: number, rule_id?, ... } | null
 *
 * MUST run AFTER verifyAaeMiddleware (needs req.firewall.callerDid).
 * Run BEFORE trustScoreGateMiddleware so the matched rule's
 * threshold_override drives the trust check.
 */
export function aclCheckMiddleware({ matchAcl, getSlug = defaultGetSlug, getCapability, basePath = '/api/a2a', logger = null }) {
  if (typeof matchAcl !== 'function') throw new Error('aclCheckMiddleware requires matchAcl callback');
  const inferCap = getCapability ?? ((req) => inferCapability(req, { basePath }));

  return async function aclCheck(req, res, next) {
    const fw = ensureFirewall(req);
    if (fw.public) return next();

    const slug = getSlug(req);
    const callerDid = fw.callerDid;
    if (!slug || !callerDid || callerDid === 'anonymous') {
      return res.status(401).json({ error: 'no_caller_identity' });
    }
    const capability = inferCap(req);
    if (!capability) {
      return res.status(400).json({ error: 'unrecognised_a2a_endpoint' });
    }

    let match;
    try {
      match = await matchAcl({ slug, callerDid, capability });
    } catch (err) {
      logger?.error?.({ err: err.message }, 'matchAcl threw');
      return res.status(503).json({ error: 'acl_resolver_unavailable' });
    }
    if (!match) {
      logger?.warn?.({ slug, did: callerDid, capability }, 'acl: no rule grants this combo');
      return res.status(403).json({ error: 'acl_no_capability_grant', capability });
    }
    fw.aclRule = match;
    next();
  };
}

/* ───────────────── stage 3: trust score gate ───────────────── */

/**
 * Caller's trust score must clear the matched rule's threshold_override
 * (if set) or the gateway-default threshold. On fail: 403. On resolver
 * outage: 503 fail-closed.
 *
 * MUST run after aclCheckMiddleware so the rule's override is on
 * req.firewall.aclRule.
 */
export function trustScoreGateMiddleware({ trustResolver, defaultThreshold = 0.7, logger = null }) {
  if (!trustResolver) throw new Error('trustScoreGateMiddleware requires trustResolver');
  // Defence against silent misconfiguration. NaN passes typeof===
  // 'number' but means `score < threshold` is always false → every
  // request would silently bypass the gate. Catch this at construct
  // time so a typo in config fails loudly rather than at runtime.
  if (!Number.isFinite(defaultThreshold) || defaultThreshold < 0 || defaultThreshold > 1) {
    throw new Error('defaultThreshold must be a finite number between 0 and 1');
  }

  return async function trustScoreGate(req, res, next) {
    const fw = ensureFirewall(req);
    if (fw.public) return next();

    const did = fw.callerDid;
    if (!did || did === 'anonymous') {
      return res.status(401).json({ error: 'no_caller_identity' });
    }

    let score;
    try {
      score = await trustResolver.getScore(did);
    } catch (err) {
      logger?.error?.({ err: err.message, did }, 'trust score resolver failed');
      return res.status(503).json({ error: 'trust_resolver_unavailable' });
    }

    // NaN/Infinity defence: every comparison with NaN is false, so a
    // resolver returning NaN (whether through a buggy backend or a
    // malicious record) would silently bypass the gate. TrustResolver
    // already coerces NaN → 0, but defend in depth here too.
    if (!Number.isFinite(score)) {
      logger?.error?.({ did, score }, 'trust score resolver returned non-finite');
      return res.status(503).json({ error: 'trust_resolver_unavailable' });
    }

    // Range-validate the rule's threshold_override. A malformed ACL
    // row with -1 / +Inf / 1.1 should not silently drive the gate —
    // fall back to the gateway default.
    const override = fw.aclRule?.threshold_override;
    let threshold = defaultThreshold;
    let source = 'gateway_default';
    if (Number.isFinite(override) && override >= 0 && override <= 1) {
      threshold = override;
      source = 'rule_override';
    }

    if (score < threshold) {
      logger?.warn?.({ did, score, threshold, source }, 'trust gate denied');
      // Don't include score / threshold in the response body —
      // returning them is a precise oracle for an attacker probing
      // how close they are to passing or what the trust formula
      // weights. Log server-side; tell the client the bare result.
      return res.status(403).json({ error: 'trust_score_below_threshold' });
    }
    fw.trustScore = score;
    next();
  };
}

/* ───────────────── stage 4: payload sanitise ───────────────── */

/**
 * Walk req.body and strip prompt-injection markers. Doesn't reject —
 * strips and forwards. Records hit count to req.firewall.sanitiseHits.
 */
export function sanitiseMiddleware({ logger = null } = {}) {
  return async function sanitise(req, _res, next) {
    const fw = ensureFirewall(req);
    if (fw.public) return next();
    if (req.body && typeof req.body === 'object') {
      const { value, hits } = sanitiseDeep(req.body);
      req.body = value;
      if (hits > 0) {
        fw.sanitiseHits = hits;
        logger?.warn?.({ did: fw.callerDid, hits }, 'payload sanitised');
      }
    }
    next();
  };
}

/* ───────────────── stage 5: hop depth guard ───────────────── */

/**
 * Reject AAE chains deeper than maxHopCount. Protects against
 * recursion loops (A→B→C→A) and bounds cost-amplification.
 */
export function depthGuardMiddleware({ maxHopCount = 3, logger = null } = {}) {
  return async function depthGuard(req, res, next) {
    const fw = ensureFirewall(req);
    if (fw.public) return next();
    const hop = fw.aae?.hop ?? 0;
    // NaN > x is always false in JS. aae.js already validates env.hop
    // is a finite number before populating it; this is defence in
    // depth in case an upstream stage tampered with fw.aae.
    if (!Number.isFinite(hop) || hop > maxHopCount) {
      logger?.warn?.({ hop, max: maxHopCount, did: fw.callerDid }, 'depth guard rejected');
      return res.status(403).json({ error: 'recursion_depth_exceeded', max: maxHopCount });
    }
    next();
  };
}

/* ───────────────── stage 6: circuit breaker ───────────────── */

/**
 * Short-circuit with 503 if the upstream peer slug is in cooldown.
 */
export function circuitOpenCheckMiddleware({ circuitBreaker, getSlug = defaultGetSlug, logger = null }) {
  if (!circuitBreaker) throw new Error('circuitOpenCheckMiddleware requires circuitBreaker');
  return async function circuitOpenCheck(req, res, next) {
    const fw = ensureFirewall(req);
    if (fw.public) return next();
    const slug = getSlug(req);
    if (!slug) return next();
    if (circuitBreaker.isOpen(slug)) {
      const remainingMs = circuitBreaker.cooldownRemaining(slug);
      logger?.warn?.({ slug, remainingMs }, 'circuit open, short-circuiting');
      return res.status(503).json({ error: 'upstream_circuit_open', cooldown_ms: remainingMs });
    }
    next();
  };
}

/* ───────────────── stage 7: rate limit + token budget ───────────────── */

export function rateLimitMiddleware({ rateLimiter, tokenBudget, getSlug = defaultGetSlug, logger = null }) {
  if (!rateLimiter) throw new Error('rateLimitMiddleware requires rateLimiter');

  return async function rateLimit(req, res, next) {
    const fw = ensureFirewall(req);
    if (fw.public) return next();
    const slug = getSlug(req);
    // JSON-encode the tuple instead of `${a}|${b}` — defends
    // against collision attacks where an attacker crafts a callerDid
    // containing the chosen separator. With JSON.stringify the
    // outputs are unambiguous: ["a|b","c"] !== ["a","b|c"].
    const key = JSON.stringify([fw.callerDid, slug]);

    if (!rateLimiter.consume(key)) {
      logger?.warn?.({ did: fw.callerDid, slug, limit: rateLimiter.limit }, 'rate limit exceeded');
      return res.status(429).json({ error: 'rate_limit_exceeded', limit_per_minute: rateLimiter.limit });
    }

    if (tokenBudget) {
      const tokens = tokenBudget.estimate(req);
      const result = tokenBudget.consume(key, tokens);
      if (!result.allowed) {
        logger?.warn?.({ did: fw.callerDid, slug, used: result.used, limit: result.limit }, 'daily token budget exceeded');
        return res.status(429).json({
          error: 'daily_token_budget_exceeded',
          used: result.used, limit: result.limit,
          resets_at: 'next 00:00 UTC',
        });
      }
      fw.tokenEstimate = tokens;
      fw.tokenUsed = result.used;
    }
    next();
  };
}

/* ───────────────── stage 8: audit ───────────────── */

/**
 * Fire-and-forget audit of the final decision after the response
 * completes. Caller-supplied sink is invoked with the audit row.
 *
 * Defaults to logging the request PATH only (no query string).
 * Query parameters often carry secrets (API keys, tokens, session
 * ids) that callers may not realise are being logged. If you really
 * need the query string, set `includeQueryInAudit: true`.
 *
 * If the sink throws, the failure is logged at ERROR level (was
 * warn) — a missing audit trail has security implications and
 * should be a noisy signal to operators, not a quiet warning.
 */
export function auditMiddleware({ sink = null, logger = null, includeQueryInAudit = false } = {}) {
  return async function audit(req, res, next) {
    res.on('finish', () => {
      const fw = req.firewall ?? {};
      const fullUrl = req.originalUrl ?? req.url ?? '';
      let pathOnly = fullUrl;
      if (!includeQueryInAudit) {
        const q = fullUrl.indexOf('?');
        if (q !== -1) pathOnly = fullUrl.slice(0, q);
      }
      const row = {
        slug: req.params?.slug ?? fw.slug,
        caller: fw.callerDid,
        method: req.method,
        path: pathOnly,
        status: res.statusCode,
        rule_id: fw.aclRule?.rule_id,
        trust_score: fw.trustScore,
        sanitise_hits: fw.sanitiseHits,
        token_used: fw.tokenUsed,
      };
      // The sink may be async (writing to a DB, posting to a queue).
      // A synchronous try/catch does NOT catch a rejected Promise,
      // so an async sink that fails would surface as an unhandled
      // promise rejection — and Node may crash with
      // --unhandled-rejections=strict. Wrap with Promise.resolve so
      // both sync throws and async rejections funnel into the same
      // error logger.
      if (typeof sink === 'function') {
        try {
          Promise.resolve(sink(row)).catch((err) => {
            logger?.error?.(
              { err: err?.message ?? String(err), row },
              'audit sink rejected — audit trail has gaps',
            );
          });
        } catch (err) {
          logger?.error?.(
            { err: err?.message ?? String(err), row },
            'audit sink threw — audit trail has gaps',
          );
        }
      }
      logger?.info?.(row, 'a2a request');
    });
    next();
  };
}

/* ───────────────── chain composer ───────────────── */

/**
 * Compose the standard firewall chain in the canonical order:
 *
 *   1. verifyAae          authenticate caller
 *   2. aclCheck           authorize (caller, capability) pair, captures rule
 *   3. trustScoreGate     authorize at trust level (uses rule's threshold_override)
 *   4. sanitise           strip prompt-injection markers
 *   5. depthGuard         cheap structural reject
 *   6. circuitOpenCheck   bail if peer is sick (only if circuitBreaker provided)
 *   7. rateLimit          cost / abuse limits
 *   8. audit              log + sink final decision
 *
 * Returns an array of middleware functions ready for app.use().
 */
export function firewallChain(config) {
  const chain = [
    verifyAaeMiddleware(config),
    aclCheckMiddleware(config),
    trustScoreGateMiddleware(config),
    sanitiseMiddleware(config),
    depthGuardMiddleware(config),
  ];
  if (config.circuitBreaker) chain.push(circuitOpenCheckMiddleware(config));
  chain.push(rateLimitMiddleware(config));
  chain.push(auditMiddleware(config));
  return chain;
}
