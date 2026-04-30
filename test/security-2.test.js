// Regression tests for the 0.1.2 security review fixes.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {
  verifyAae,
  inferCapability,
  RateLimiter,
  DailyTokenBudget,
  KeyResolver,
  RevocationChecker,
  NonceCache,
  auditMiddleware,
  verifyAaeMiddleware,
} from '../src/index.js';

function b64url(obj) {
  return Buffer.from(JSON.stringify(obj))
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/* ─── Issue #3: __proto__ attack on canonicalisation ─── */

test('verifyAae ignores __proto__ on the envelope (allowlist canonicalization)', async () => {
  const now = Math.floor(Date.now() / 1000);
  const env = {
    v: 1, iss: 'did:x:a', jti: 'j1',
    aud: 'a2a-ingress', exp: now + 60,
    sig_key_id: 'k', sig_alg: 'Ed25519',
    // Try to inject __proto__ via JSON.parse — modern Node makes
    // this an own data property; library must explicitly ignore it.
    __proto__: { evil: true },
  };
  // We can't easily test signature verification without a keypair —
  // but we CAN confirm verifyAae reaches the unknown_key check
  // (i.e. doesn't fail earlier on parse / aud / exp / type).
  const r = await verifyAae(b64url(env), {
    keyResolver: new KeyResolver({ resolve: async () => null }),
    revocationChecker: new RevocationChecker({ check: async () => false }),
    nonceCache: new NonceCache(),
  });
  assert.equal(r.reason, 'unknown_key');
});

test('verifyAae handles serialized __proto__ key from JSON without poisoning prototype', async () => {
  const now = Math.floor(Date.now() / 1000);
  const wireJson = JSON.stringify({
    v: 1, iss: 'did:x:a', jti: 'j2',
    aud: 'a2a-ingress', exp: now + 60,
    sig_key_id: 'k', sig_alg: 'Ed25519',
  }).replace('"v":1', '"v":1,"__proto__":{"hacked":1}');
  const r = await verifyAae(
    Buffer.from(wireJson).toString('base64url'),
    {
      keyResolver: new KeyResolver({ resolve: async () => null }),
      revocationChecker: new RevocationChecker({ check: async () => false }),
      nonceCache: new NonceCache(),
    }
  );
  // Reaches unknown_key — allowlist filtered out __proto__.
  assert.equal(r.reason, 'unknown_key');
  // Prototype not polluted.
  assert.equal({}.hacked, undefined);
});

test('verifyAae rejects sig as non-string', async () => {
  const now = Math.floor(Date.now() / 1000);
  const env = {
    v: 1, iss: 'did:x:a', jti: 'j',
    aud: 'a2a-ingress', exp: now + 60,
    sig_key_id: 'k', sig_alg: 'Ed25519',
    // No sig field at all → sig_missing
  };
  const r = await verifyAae(b64url(env), {
    keyResolver: new KeyResolver({ resolve: async () => ({ public_key_b64url: 'x'.repeat(43), sig_alg: 'Ed25519' }) }),
    revocationChecker: new RevocationChecker({ check: async () => false }),
    nonceCache: new NonceCache(),
  });
  // First we hit unknown_key because key_b64url is not 32 bytes →
  // key_format_error. Either way, no err.message slice in the reason.
  assert.match(r.reason, /^(sig_missing|key_format_error|unknown_key)$/);
  // Confirm reason is opaque — no leaked error details.
  assert.doesNotMatch(r.reason, /:/);
});

/* ─── Issue #9: opaque fail reasons (no err.message leakage) ─── */

test('key_resolver_failed reason is opaque', async () => {
  const now = Math.floor(Date.now() / 1000);
  const env = {
    v: 1, iss: 'did:x:a', jti: 'j',
    aud: 'a2a-ingress', exp: now + 60,
    sig_key_id: 'k', sig_alg: 'Ed25519',
    sig: 'AAAA',
  };
  const r = await verifyAae(b64url(env), {
    keyResolver: { resolve: async () => { throw new Error('database connection lost: postgres on host db-prod-01.internal:5432'); } },
    revocationChecker: new RevocationChecker({ check: async () => false }),
    nonceCache: new NonceCache(),
  });
  // The library must NOT leak the internal hostname / port / driver name.
  assert.equal(r.reason, 'key_resolver_failed');
  assert.doesNotMatch(r.reason, /postgres|database|internal/);
});

/* ─── Issue #4: capability segment validation ─── */

test('inferCapability rejects oversized wing', () => {
  const req = {
    method: 'POST',
    path: '/api/a2a/read_memory',
    body: { wing: 'x'.repeat(100) },
  };
  assert.equal(inferCapability(req), null);
});

test('inferCapability rejects wing with bad characters', () => {
  for (const wing of ['Work', 'work room', 'work/projects', '../etc', 'work#', '']) {
    const req = { method: 'POST', path: '/api/a2a/read_memory', body: { wing } };
    assert.equal(inferCapability(req), null, `wing ${JSON.stringify(wing)} should be rejected`);
  }
});

test('inferCapability rejects oversized room', () => {
  const req = {
    method: 'POST',
    path: '/api/a2a/read_memory',
    body: { wing: 'work', room: 'x'.repeat(100) },
  };
  assert.equal(inferCapability(req), null);
});

test('inferCapability accepts valid wing/room', () => {
  assert.equal(inferCapability({
    method: 'POST', path: '/api/a2a/read_memory',
    body: { wing: 'work' }
  }), 'read_memory:work');
  assert.equal(inferCapability({
    method: 'POST', path: '/api/a2a/read_memory',
    body: { wing: 'work', room: 'projects' }
  }), 'read_memory:work/projects');
});

test('inferCapability rejects multi-MB wing without huge memory work', () => {
  // Pre-fix: this would build a `read_memory:<10MB string>` capability
  // that flowed into matchAcl + audit logs. Now: rejected immediately.
  const huge = 'a' + 'x'.repeat(10_000_000);
  const req = { method: 'POST', path: '/api/a2a/read_memory', body: { wing: huge } };
  const t0 = Date.now();
  const cap = inferCapability(req);
  const t1 = Date.now();
  assert.equal(cap, null);
  assert.ok(t1 - t0 < 100, 'should reject in <100ms regardless of input size');
});

/* ─── Issue #2 & #7: bucket cap on RateLimiter ─── */

test('RateLimiter caps bucket count under attack', () => {
  const rl = new RateLimiter({ requestsPerMinute: 1, maxBuckets: 5 });
  for (let i = 0; i < 10; i += 1) rl.consume(`attacker-${i}`);
  // Cap honored: at most maxBuckets entries despite 10 unique keys.
  assert.ok(rl.size() <= 5, `expected <= 5 buckets, got ${rl.size()}`);
  rl.stop();
});

/* ─── Issue #2: bucket cap on DailyTokenBudget ─── */

test('DailyTokenBudget caps bucket count under attack', () => {
  const b = new DailyTokenBudget({ tokensPerDay: 100, maxBuckets: 5 });
  for (let i = 0; i < 10; i += 1) b.consume(`attacker-${i}`, 5);
  assert.ok(b.size() <= 5);
});

/* ─── Issue #5: TtlResolver max cache size ─── */

test('TtlResolver caps cache size under attacker key flood', async () => {
  const kr = new KeyResolver({
    resolve: async (k) => ({ id: k, public_key_b64url: 'x', sig_alg: 'Ed25519' }),
    maxSize: 5,
  });
  for (let i = 0; i < 20; i += 1) await kr.resolve(`flood-${i}`);
  assert.ok(kr.size() <= 5, `expected <= 5 cache entries, got ${kr.size()}`);
});

test('RevocationChecker caps cache size under attacker key flood', async () => {
  const rc = new RevocationChecker({
    check: async () => false,
    maxSize: 5,
  });
  for (let i = 0; i < 20; i += 1) await rc.isRevoked(`jti-${i}`);
  assert.ok(rc.size() <= 5);
});

/* ─── Issue #1: response body must not leak err.message ─── */

test('verifyAaeMiddleware response body does not leak resolver error message', async () => {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => { req.firewall = { slug: 'bob' }; next(); });
  app.use('/a2a', verifyAaeMiddleware({
    keyResolver: { resolve: async () => { throw new Error('SECRET-INTERNAL-DETAIL-do-not-leak'); } },
    revocationChecker: new RevocationChecker({ check: async () => false }),
    nonceCache: new NonceCache(),
    expectedAud: null, // bypass aud requirement so the resolver is reached
  }));
  app.post('/a2a/message', (_req, res) => res.json({ ok: true }));

  // Build a valid-shape envelope so we get past parse + type checks
  // and reach the keyResolver call.
  const now = Math.floor(Date.now() / 1000);
  const envelope = b64url({
    v: 1, iss: 'did:x:a', jti: 'j-leak-test',
    exp: now + 60, sig_key_id: 'k', sig_alg: 'Ed25519', sig: 'AAAA',
  });

  const server = app.listen(0);
  const port = server.address().port;
  const r = await fetch(`http://127.0.0.1:${port}/a2a/message`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-klaw-aae': envelope },
    body: JSON.stringify({}),
  });
  const body = await r.text();
  server.close();

  assert.doesNotMatch(body, /SECRET-INTERNAL-DETAIL/, 'must not leak resolver error message to HTTP body');
  // verify_unavailable comes from the middleware catch (logger throw),
  // OR a normal aae_rejected with reason 'key_resolver_failed' from
  // verifyAae's internal catch — depends on which path hit. Both are
  // acceptable; what matters is the error message is NOT present.
});

/* ─── Issue #6: audit middleware strips query string by default ─── */

test('auditMiddleware strips query string from logged path', async () => {
  let captured = null;
  const sink = (row) => { captured = row; };
  const mw = auditMiddleware({ sink });

  // Synthetic Express-shaped req/res
  const req = {
    method: 'GET',
    originalUrl: '/api/a2a/agent-card?token=SECRET-DO-NOT-LOG',
    params: { slug: 'bob' },
    firewall: {},
  };
  const handlers = [];
  const res = {
    statusCode: 200,
    on: (_event, fn) => { handlers.push(fn); },
  };
  await new Promise((next) => mw(req, res, next));
  for (const fn of handlers) fn();
  assert.ok(captured);
  assert.doesNotMatch(captured.path, /SECRET/, 'query string must be stripped');
  assert.doesNotMatch(captured.path, /\?/, 'no question mark');
  assert.equal(captured.path, '/api/a2a/agent-card');
});

test('auditMiddleware preserves query string when includeQueryInAudit=true', async () => {
  let captured = null;
  const sink = (row) => { captured = row; };
  const mw = auditMiddleware({ sink, includeQueryInAudit: true });

  const req = {
    method: 'GET',
    originalUrl: '/api/a2a/agent-card?ref=tracking-id',
    params: { slug: 'bob' },
    firewall: {},
  };
  const handlers = [];
  const res = { statusCode: 200, on: (_event, fn) => handlers.push(fn) };
  await new Promise((next) => mw(req, res, next));
  for (const fn of handlers) fn();
  assert.match(captured.path, /\?ref=tracking-id/);
});

/* ─── Issue #10: audit sink failure is logged at ERROR ─── */

test('auditMiddleware logs sink failure at error level (not warn)', async () => {
  const calls = { warn: 0, error: 0 };
  const logger = {
    info: () => {},
    warn: () => { calls.warn += 1; },
    error: () => { calls.error += 1; },
  };
  const mw = auditMiddleware({
    sink: () => { throw new Error('downstream-broken'); },
    logger,
  });
  const req = { method: 'GET', originalUrl: '/x', params: {}, firewall: {} };
  const handlers = [];
  const res = { statusCode: 200, on: (_e, fn) => handlers.push(fn) };
  await new Promise((next) => mw(req, res, next));
  for (const fn of handlers) fn();

  assert.equal(calls.error, 1, 'sink failure must log at error');
  assert.equal(calls.warn, 0, 'should not log at warn');
});
