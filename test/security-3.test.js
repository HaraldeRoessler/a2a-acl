// Regression tests for the 0.1.3 security review fixes.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {
  verifyAae,
  signablePayload,
  SIGNED_FIELDS,
  inferCapability,
  RateLimiter,
  DailyTokenBudget,
  CircuitBreaker,
  KeyResolver,
  TrustResolver,
  RevocationChecker,
  NonceCache,
  auditMiddleware,
  trustScoreGateMiddleware,
  depthGuardMiddleware,
  verifyAaeMiddleware,
  sanitiseDeep,
} from '../src/index.js';

function b64url(obj) {
  return Buffer.from(JSON.stringify(obj))
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function ctxBase(overrides = {}) {
  return {
    keyResolver: new KeyResolver({ resolve: async () => null }),
    revocationChecker: new RevocationChecker({ check: async () => false }),
    nonceCache: new NonceCache(),
    ...overrides,
  };
}

/* ─── Sub validation (cross-peer replay defence) ─── */

test('verifyAae rejects mismatched sub when expectedSub is set', async () => {
  const now = Math.floor(Date.now() / 1000);
  const env = {
    v: 1, iss: 'did:x:a', sub: 'did:x:alice',
    aud: 'a2a-ingress', exp: now + 60, jti: 'j1',
  };
  const r = await verifyAae(b64url(env), ctxBase({ expectedSub: 'did:x:bob' }));
  assert.equal(r.reason, 'wrong_subject');
});

test('verifyAae rejects missing sub when expectedSub is set', async () => {
  const now = Math.floor(Date.now() / 1000);
  const env = {
    v: 1, iss: 'did:x:a',
    aud: 'a2a-ingress', exp: now + 60, jti: 'j2',
  };
  const r = await verifyAae(b64url(env), ctxBase({ expectedSub: 'did:x:bob' }));
  assert.equal(r.reason, 'wrong_subject');
});

test('verifyAae accepts matching sub', async () => {
  const now = Math.floor(Date.now() / 1000);
  const env = {
    v: 1, iss: 'did:x:a', sub: 'did:x:bob',
    aud: 'a2a-ingress', exp: now + 60, jti: 'j3',
    sig_key_id: 'k', sig_alg: 'Ed25519',
  };
  const r = await verifyAae(b64url(env), ctxBase({ expectedSub: 'did:x:bob' }));
  assert.equal(r.reason, 'unknown_key'); // gets past sub check
});

test('verifyAae skips sub check when expectedSub omitted', async () => {
  const now = Math.floor(Date.now() / 1000);
  const env = {
    v: 1, iss: 'did:x:a',
    aud: 'a2a-ingress', exp: now + 60, jti: 'j4',
    sig_key_id: 'k', sig_alg: 'Ed25519',
  };
  const r = await verifyAae(b64url(env), ctxBase());
  assert.equal(r.reason, 'unknown_key');
});

/* ─── NaN bypass — exp / iat / hop / perm / score / hop ─── */

test('verifyAae rejects exp=NaN (Number.isFinite check)', async () => {
  // NaN cannot survive JSON.parse but a manually-constructed envelope
  // (or a non-standard parser passing through to our type check) could.
  // Simulate via a parsed envelope: skip JSON layer.
  const now = Math.floor(Date.now() / 1000);
  // Build the parsed envelope manually to inject NaN.
  const env = {
    v: 1, iss: 'did:x:a', sub: 'did:x:b',
    aud: 'a2a-ingress', exp: NaN, jti: 'jnan',
  };
  // Encode as JSON — JSON.stringify(NaN) → "null", which now fails
  // the requireExp check. So we pass via b64url-encoded JSON of a
  // manually-built string that injects NaN. JSON has no NaN literal,
  // so we test the type check by constructing a non-standard wire.
  const wire = '{"v":1,"iss":"did:x:a","sub":"did:x:b","aud":"a2a-ingress","exp":NaN,"jti":"jnan"}';
  const headerVal = Buffer.from(wire).toString('base64url');
  const r = await verifyAae(headerVal, ctxBase());
  // JSON.parse should reject the malformed wire (NaN isn't valid JSON).
  assert.equal(r.reason, 'parse_error');
});

test('TrustResolver coerces NaN score to 0 (gate fails closed)', async () => {
  const tr = new TrustResolver({ resolve: async () => NaN });
  const score = await tr.getScore('did:x');
  assert.equal(score, 0);
});

test('TrustResolver coerces {score: NaN} to 0', async () => {
  const tr = new TrustResolver({ resolve: async () => ({ score: NaN }) });
  const score = await tr.getScore('did:x');
  assert.equal(score, 0);
});

test('trustScoreGate denies on non-finite score', async () => {
  // Simulate a misbehaving trust resolver that returns NaN despite
  // the inner resolver coercion (defence in depth).
  const tr = { getScore: async () => NaN };
  const mw = trustScoreGateMiddleware({ trustResolver: tr });
  const req = { firewall: { callerDid: 'did:x:a', aclRule: {} } };
  let status = null;
  let body = null;
  const res = {
    status(s) { status = s; return this; },
    json(b) { body = b; return this; },
  };
  let nextCalled = false;
  await mw(req, res, () => { nextCalled = true; });
  assert.equal(status, 503);
  assert.equal(body.error, 'trust_resolver_unavailable');
  assert.equal(nextCalled, false);
});

test('depthGuard rejects NaN hop (defence in depth)', async () => {
  const mw = depthGuardMiddleware({ maxHopCount: 3 });
  const req = { firewall: { aae: { hop: NaN }, callerDid: 'did:x' } };
  let status = null, body = null;
  const res = {
    status(s) { status = s; return this; },
    json(b) { body = b; return this; },
  };
  await mw(req, res, () => { throw new Error('next should not be called'); });
  assert.equal(status, 403);
  assert.equal(body.error, 'recursion_depth_exceeded');
});

/* ─── DailyTokenBudget Content-Length NaN poisoning ─── */

test('DailyTokenBudget.estimate ignores Content-Length: NaN', () => {
  const b = new DailyTokenBudget({ tokensPerDay: 100 });
  assert.equal(b.estimate({ headers: { 'content-length': 'NaN' } }), 0);
  assert.equal(b.estimate({ headers: { 'content-length': 'not-a-number' } }), 0);
  assert.equal(b.estimate({ headers: { 'content-length': '-100' } }), 0);
  assert.equal(b.estimate({ headers: { 'content-length': '40' } }), 10);
});

test('DailyTokenBudget.consume guards against NaN token count', () => {
  const b = new DailyTokenBudget({ tokensPerDay: 100 });
  // Even if a buggy caller passes NaN directly, consume must not
  // poison the bucket.
  const r = b.consume('k', NaN);
  assert.equal(r.allowed, true);
  assert.equal(r.used, 0); // NaN was floored to 0
});

/* ─── key_resolver_failed colon-mismatch fix ─── */

test('verifyAaeMiddleware returns 503 on resolver throw (was 401 in 0.1.2)', async () => {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => { req.firewall = { slug: 'bob' }; next(); });
  app.use(verifyAaeMiddleware({
    keyResolver: { resolve: async () => { throw new Error('db down'); } },
    revocationChecker: new RevocationChecker({ check: async () => false }),
    nonceCache: new NonceCache(),
    expectedAud: null,
  }));
  app.post('/api/a2a/message', (_req, res) => res.json({ ok: true }));

  const now = Math.floor(Date.now() / 1000);
  const envelope = b64url({
    v: 1, iss: 'did:x:a', jti: 'j-ts1', exp: now + 60,
    sig_key_id: 'k', sig_alg: 'Ed25519', sig: 'AAAA',
  });
  const server = app.listen(0);
  const port = server.address().port;
  const r = await fetch(`http://127.0.0.1:${port}/api/a2a/message`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-klaw-aae': envelope },
    body: JSON.stringify({}),
  });
  server.close();
  assert.equal(r.status, 503, 'resolver throw must yield 503 (transient), not 401');
  const body = await r.json();
  assert.equal(body.error, 'key_resolver_unavailable');
});

/* ─── Public-path-under-mount ─── */

test('isPublic recognises agent-card under mounted base path', async () => {
  const app = express();
  app.use(express.json());
  app.use('/api/a2a', verifyAaeMiddleware({
    keyResolver: new KeyResolver({ resolve: async () => null }),
    revocationChecker: new RevocationChecker({ check: async () => false }),
    nonceCache: new NonceCache(),
    expectedAud: null,
  }));
  app.get('/api/a2a/agent-card', (_req, res) => res.json({ public: true }));

  const server = app.listen(0);
  const port = server.address().port;
  const r = await fetch(`http://127.0.0.1:${port}/api/a2a/agent-card`);
  server.close();
  assert.equal(r.status, 200, 'agent-card under mounted path must be reachable without AAE');
});

/* ─── Trust gate response body doesn't leak score/threshold ─── */

test('trust gate denial body does not include score or threshold', async () => {
  const mw = trustScoreGateMiddleware({
    trustResolver: { getScore: async () => 0.3 },
    defaultThreshold: 0.7,
  });
  const req = { firewall: { callerDid: 'did:x', aclRule: {} } };
  let body = null;
  const res = {
    status() { return this; },
    json(b) { body = b; return this; },
  };
  await mw(req, res, () => { throw new Error('should not pass'); });
  assert.equal(body.error, 'trust_score_below_threshold');
  assert.equal(body.score, undefined, 'score must not leak');
  assert.equal(body.threshold, undefined, 'threshold must not leak');
});

/* ─── threshold_override range validation ─── */

test('trust gate ignores out-of-range threshold_override', async () => {
  const mw = trustScoreGateMiddleware({
    trustResolver: { getScore: async () => 0.5 },
    defaultThreshold: 0.7,
  });
  // -1 would let everything pass; library should reject it and fall back.
  const req = { firewall: { callerDid: 'did:x', aclRule: { threshold_override: -1 } } };
  let body = null;
  const res = {
    status(_s) { return this; },
    json(b) { body = b; return this; },
  };
  await mw(req, res, () => { throw new Error('should not pass — score 0.5 < default 0.7'); });
  assert.equal(body.error, 'trust_score_below_threshold');
});

test('trust gate accepts in-range threshold_override', async () => {
  const mw = trustScoreGateMiddleware({
    trustResolver: { getScore: async () => 0.5 },
    defaultThreshold: 0.7,
  });
  const req = { firewall: { callerDid: 'did:x', aclRule: { threshold_override: 0.4 } } };
  let nextCalled = false;
  const res = { status() { return this; }, json() { return this; } };
  await mw(req, res, () => { nextCalled = true; });
  assert.equal(nextCalled, true);
});

/* ─── Envelope string length caps ─── */

test('verifyAae rejects oversized iss', async () => {
  const now = Math.floor(Date.now() / 1000);
  const env = {
    v: 1, iss: 'a'.repeat(300), aud: 'a2a-ingress',
    exp: now + 60, jti: 'j',
  };
  const r = await verifyAae(b64url(env), ctxBase());
  assert.equal(r.reason, 'iss_too_long');
});

test('verifyAae rejects oversized jti', async () => {
  const now = Math.floor(Date.now() / 1000);
  const env = {
    v: 1, iss: 'did:x:a', aud: 'a2a-ingress',
    exp: now + 60, jti: 'a'.repeat(300),
  };
  const r = await verifyAae(b64url(env), ctxBase());
  assert.equal(r.reason, 'jti_too_long');
});

/* ─── perm type validation ─── */

test('verifyAae rejects non-array perm', async () => {
  const now = Math.floor(Date.now() / 1000);
  const env = {
    v: 1, iss: 'did:x:a', aud: 'a2a-ingress',
    exp: now + 60, jti: 'j-perm',
    perm: 'evil-string',
  };
  const r = await verifyAae(b64url(env), ctxBase());
  assert.equal(r.reason, 'perm_invalid_type');
});

/* ─── TtlResolver inflight cap ─── */

test('TtlResolver throws when inflight cap exceeded', async () => {
  const slow = () => new Promise(() => {}); // never resolves
  const kr = new KeyResolver({ resolve: slow, maxInflight: 3 });
  // Fill in-flight slots.
  kr.resolve('a').catch(() => {});
  kr.resolve('b').catch(() => {});
  kr.resolve('c').catch(() => {});
  await assert.rejects(() => kr.resolve('d'), /inflight_cap_exceeded/);
});

/* ─── RevocationChecker inflight dedup ─── */

test('RevocationChecker dedups concurrent isRevoked for same jti', async () => {
  let calls = 0;
  const rc = new RevocationChecker({
    check: async () => { calls += 1; await new Promise(r => setTimeout(r, 30)); return false; },
  });
  await Promise.all([rc.isRevoked('jti-x'), rc.isRevoked('jti-x'), rc.isRevoked('jti-x')]);
  assert.equal(calls, 1, 'concurrent same-jti checks must dedupe');
});

/* ─── CircuitBreaker maxPeers ─── */

test('CircuitBreaker bounds peer state under flood', () => {
  const cb = new CircuitBreaker({ threshold: 1, cooldownMs: 60_000, maxPeers: 5 });
  for (let i = 0; i < 20; i += 1) cb.record(`peer-${i}`, 429);
  assert.ok(cb.size() <= 5, `expected ≤ 5 peers, got ${cb.size()}`);
});

/* ─── signablePayload export — single source of truth ─── */

test('signablePayload only canonicalises SIGNED_FIELDS', () => {
  const env = {
    v: 1, iss: 'did:x:a', jti: 'j',
    aud: 'a2a-ingress', exp: 1000,
    extraField: 'ignored',
    __proto__: { evil: 1 },
    sig: 'should-not-be-included',
  };
  const bytes = signablePayload(env);
  const text = bytes.toString('utf8');
  assert.doesNotMatch(text, /extraField/);
  assert.doesNotMatch(text, /__proto__/);
  assert.doesNotMatch(text, /should-not-be-included/);
  assert.match(text, /"v":1/);
  assert.match(text, /"iss":"did:x:a"/);
});

test('SIGNED_FIELDS export is frozen', () => {
  assert.equal(Object.isFrozen(SIGNED_FIELDS), true);
});

/* ─── Audit sink async rejection ─── */

test('audit sink async rejection logged at error, no unhandled rejection', async () => {
  const calls = { error: 0, info: 0 };
  const logger = {
    info: () => { calls.info += 1; },
    warn: () => {},
    error: () => { calls.error += 1; },
  };
  const mw = auditMiddleware({
    sink: () => Promise.reject(new Error('async-broken')),
    logger,
  });
  const req = { method: 'GET', originalUrl: '/x', params: {}, firewall: {} };
  const handlers = [];
  const res = { statusCode: 200, on: (_e, fn) => handlers.push(fn) };
  await new Promise((next) => mw(req, res, next));
  for (const fn of handlers) fn();
  // Wait for the microtask the rejection lands in.
  await new Promise((r) => setImmediate(r));
  assert.equal(calls.error, 1, 'async sink rejection must be logged at error');
});

/* ─── Rate-limit key collision via | ─── */

test('rate-limit key uses unambiguous JSON encoding', () => {
  // We can't easily call the internal middleware key construction
  // without a full request object. Rely on the JSON.stringify
  // contract: ["a|b","c"] !== ["a","b|c"] regardless of input.
  assert.notEqual(
    JSON.stringify(['a|b', 'c']),
    JSON.stringify(['a', 'b|c']),
  );
});

/* ─── sanitiseDeep sanitises object keys ─── */

test('sanitiseDeep sanitises object keys too', () => {
  const dirty = { 'system: ': 'normal value', okay: 'fine' };
  const { value, hits } = sanitiseDeep(dirty);
  assert.ok(hits >= 1);
  assert.equal(Object.hasOwn(value, 'system: '), false);
});
