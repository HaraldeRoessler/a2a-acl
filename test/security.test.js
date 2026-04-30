// Security-focused regression tests for the hardenings landed in 0.1.1.
//
// These exercise the verifyAae path with synthetic envelopes that
// match what a malicious or buggy issuer might send. We don't have a
// real Ed25519 signing flow in tests (would require keypair fixtures);
// these tests target the pre-signature checks where most policy lives.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyAae } from '../src/aae.js';
import { NonceCache } from '../src/nonce-cache.js';
import { KeyResolver, RevocationChecker } from '../src/resolvers.js';

function b64url(obj) {
  return Buffer.from(JSON.stringify(obj))
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function ctx(overrides = {}) {
  return {
    keyResolver: new KeyResolver({ resolve: async () => null }),
    revocationChecker: new RevocationChecker({ check: async () => false }),
    nonceCache: new NonceCache(),
    ...overrides,
  };
}

test('rejects envelope with missing aud when expectedAud is set', async () => {
  const now = Math.floor(Date.now() / 1000);
  const env = { v: 1, iss: 'did:example:a', jti: 'j1', exp: now + 60 };
  const r = await verifyAae(b64url(env), ctx());
  assert.equal(r.verified, false);
  assert.equal(r.reason, 'wrong_audience');
});

test('rejects envelope with mismatched aud', async () => {
  const now = Math.floor(Date.now() / 1000);
  const env = { v: 1, iss: 'did:example:a', jti: 'j1', exp: now + 60, aud: 'memgate' };
  const r = await verifyAae(b64url(env), ctx({ expectedAud: 'a2a-ingress' }));
  assert.equal(r.reason, 'wrong_audience');
});

test('expectedAud=null disables audience check (escape hatch)', async () => {
  const now = Math.floor(Date.now() / 1000);
  const env = { v: 1, iss: 'did:example:a', jti: 'j1', exp: now + 60, sig_key_id: 'x', sig_alg: 'Ed25519' };
  const r = await verifyAae(b64url(env), ctx({ expectedAud: null }));
  // Reaches the unknown_key check — past audience.
  assert.equal(r.reason, 'unknown_key');
});

test('rejects envelope with no exp when requireExp default-true', async () => {
  const env = { v: 1, iss: 'did:example:a', jti: 'j1', aud: 'a2a-ingress' };
  const r = await verifyAae(b64url(env), ctx());
  assert.equal(r.reason, 'missing_exp');
});

test('rejects envelope with exp too far in the future', async () => {
  const now = Math.floor(Date.now() / 1000);
  const env = {
    v: 1, iss: 'did:example:a', jti: 'j1',
    aud: 'a2a-ingress', exp: now + 86400, // 24h, way past 5min default
  };
  const r = await verifyAae(b64url(env), ctx());
  assert.equal(r.reason, 'exp_too_far');
});

test('caller can raise maxLifetimeSec', async () => {
  const now = Math.floor(Date.now() / 1000);
  const env = {
    v: 1, iss: 'did:example:a', jti: 'j1',
    aud: 'a2a-ingress', exp: now + 3600,
    sig_key_id: 'x', sig_alg: 'Ed25519',
  };
  const r = await verifyAae(b64url(env), ctx({ maxLifetimeSec: 7200 }));
  // Should pass exp checks and reach unknown_key (past lifetime).
  assert.equal(r.reason, 'unknown_key');
});

test('rejects exp as string (type-coercion attack)', async () => {
  const now = Math.floor(Date.now() / 1000);
  const env = {
    v: 1, iss: 'did:example:a', jti: 'j1',
    aud: 'a2a-ingress', exp: String(now + 60),
  };
  const r = await verifyAae(b64url(env), ctx());
  assert.equal(r.reason, 'exp_invalid_type');
});

test('rejects iat as boolean', async () => {
  const now = Math.floor(Date.now() / 1000);
  const env = {
    v: 1, iss: 'did:example:a', jti: 'j1',
    aud: 'a2a-ingress', exp: now + 60, iat: true,
  };
  const r = await verifyAae(b64url(env), ctx());
  assert.equal(r.reason, 'iat_invalid_type');
});

test('rejects jti as number', async () => {
  const now = Math.floor(Date.now() / 1000);
  const env = {
    v: 1, iss: 'did:example:a', jti: 12345,
    aud: 'a2a-ingress', exp: now + 60,
  };
  const r = await verifyAae(b64url(env), ctx());
  assert.equal(r.reason, 'jti_invalid_type');
});

test('rejects empty jti', async () => {
  const now = Math.floor(Date.now() / 1000);
  const env = {
    v: 1, iss: 'did:example:a', jti: '',
    aud: 'a2a-ingress', exp: now + 60,
  };
  const r = await verifyAae(b64url(env), ctx());
  assert.equal(r.reason, 'missing_jti');
});

test('NonceCache rejects new entries when full (no replay window)', () => {
  const c = new NonceCache({ maxEntries: 3 });
  const future = Math.floor(Date.now() / 1000) + 3600;
  assert.equal(c.seen('j1', future), true);
  assert.equal(c.seen('j2', future), true);
  assert.equal(c.seen('j3', future), true);
  // 4th is full + nothing expired → cache_full sentinel
  assert.equal(c.seen('j4', future), 'cache_full');
  // The originals are still rejected on replay (NOT evicted)
  assert.equal(c.seen('j1', future), false);
  c.stop();
});

test('NonceCache allows new entries after natural expiry', () => {
  const c = new NonceCache({ maxEntries: 2 });
  const past = Math.floor(Date.now() / 1000) - 3600;
  const future = Math.floor(Date.now() / 1000) + 3600;
  assert.equal(c.seen('expired1', past), true);
  assert.equal(c.seen('expired2', past), true);
  // Cache full but seen() sweeps expired entries first → makes room
  assert.equal(c.seen('fresh', future), true);
  c.stop();
});

test('TtlResolver dedups in-flight concurrent misses', async () => {
  let calls = 0;
  let resolver;
  const resolve = (key) => new Promise((r) => {
    calls += 1;
    setTimeout(() => r({ key }), 50);
  });
  resolver = new KeyResolver({ resolve });
  const [a, b, c] = await Promise.all([
    resolver.resolve('same'),
    resolver.resolve('same'),
    resolver.resolve('same'),
  ]);
  assert.equal(calls, 1, 'concurrent misses should call resolver once');
  assert.deepEqual(a, b);
  assert.deepEqual(b, c);
});

test('TtlResolver does not cache thrown errors', async () => {
  let calls = 0;
  const resolver = new KeyResolver({
    resolve: async () => { calls += 1; throw new Error('transient'); },
  });
  await assert.rejects(() => resolver.resolve('k'), /transient/);
  await assert.rejects(() => resolver.resolve('k'), /transient/);
  assert.equal(calls, 2, 'failed lookup must not poison cache');
});

test('rejects non-string envelope header', async () => {
  const r = await verifyAae(null, ctx());
  assert.equal(r.reason, 'no_envelope');
  const r2 = await verifyAae(123, ctx());
  assert.equal(r2.reason, 'no_envelope');
});

test('rejects array as envelope (only objects allowed)', async () => {
  const r = await verifyAae(b64url([1, 2, 3]), ctx());
  assert.equal(r.reason, 'parse_error');
});

test('iatSkewSec is configurable', async () => {
  const now = Math.floor(Date.now() / 1000);
  const env = {
    v: 1, iss: 'did:example:a', jti: 'j1',
    aud: 'a2a-ingress', exp: now + 60,
    iat: now + 30, // 30s in future
  };
  // Default skew is 60s — passes
  const r1 = await verifyAae(b64url(env), ctx());
  assert.notEqual(r1.reason, 'iat_in_future');
  // Tighter skew (10s) — rejects
  const r2 = await verifyAae(b64url(env), ctx({ iatSkewSec: 10 }));
  assert.equal(r2.reason, 'iat_in_future');
});
