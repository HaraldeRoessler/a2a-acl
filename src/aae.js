// AAE — Agent Authorization Envelope verification.
//
// Envelope wire format: base64url-encoded JSON. Signature is Ed25519
// over the canonical-stringified SIGNED VIEW of the envelope —
// constructed by enumerating only the allow-listed envelope fields,
// in the order this library defines. The signer MUST follow the same
// rule. This eliminates engine/language-specific differences in how
// extra keys (e.g. `__proto__`) are handled by JSON.parse and
// `Object.keys`.
//
// Canonicalisation: RFC 8785-lite (sort keys, no whitespace, JSON
// stringify scalars).

import { verify as cryptoVerify, createPublicKey } from 'node:crypto';

// Strict allowlist of envelope fields that participate in the
// signature. Anything else in the parsed JSON is ignored — never
// signed over, never trusted. Adding a new field is a breaking change
// that requires a coordinated bump (env.v + library version).
//
// Exported as a const + via signablePayload() so signers in any
// language have one source of truth: build the canonical payload by
// enumerating these fields in this order, ignoring everything else.
export const SIGNED_FIELDS = Object.freeze([
  'v', 'iss', 'sub', 'aud',
  'exp', 'iat', 'jti',
  'sig_key_id', 'sig_alg',
  'hop', 'perm',
]);

// Length caps on string envelope fields. Defends downstream consumers
// (audit log, matchAcl callback, rate-limit key, error responses) from
// log-injection / DB-bloat / memory-pressure via outsized signer fields.
const MAX_STRING_FIELD_LEN = 256;

function isFiniteNumber(v) {
  return typeof v === 'number' && Number.isFinite(v);
}

/**
 * Build the canonical bytes that a signer MUST sign over.
 * Single source of truth for cross-language signer correctness.
 *
 * @param {object} env — the parsed envelope (without `sig`)
 * @returns {Buffer} canonical UTF-8 bytes
 */
export function signablePayload(env) {
  const signed = {};
  for (const k of SIGNED_FIELDS) {
    if (Object.hasOwn(env, k)) signed[k] = env[k];
  }
  return Buffer.from(canonicalize(signed), 'utf8');
}

function b64urlDecode(s) {
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

// RFC 8785-lite canonical JSON.
function canonicalize(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonicalize).join(',') + ']';
  const keys = Object.keys(v).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',') + '}';
}

function fail(reason, partial = {}) {
  return {
    verified: false,
    reason,
    issuer: partial.issuer ?? null,
    expiresAt: partial.expiresAt ?? null,
    jti: partial.jti ?? null,
    coversOp: () => false,
  };
}

function ok(env) {
  return {
    verified: true,
    reason: null,
    issuer: env.iss,
    sub: env.sub ?? null,
    expiresAt: env.exp ? new Date(env.exp * 1000).toISOString() : null,
    jti: env.jti ?? null,
    perm: env.perm ?? [],
    hop: typeof env.hop === 'number' ? env.hop : 0,
    coversOp: (op, wing, room) => coversOp(env.perm ?? [], op, wing, room),
  };
}

function coversOp(perms, op, wing, room) {
  for (const p of perms) {
    if (p.op !== op) continue;
    if (p.wing !== '*' && p.wing !== wing) continue;
    if (p.room && p.room !== '*' && p.room !== room) continue;
    return true;
  }
  return false;
}

// Wrap a raw 32-byte Ed25519 public key in a SubjectPublicKeyInfo DER
// so Node's crypto.createPublicKey can consume it.
function pubKeyFromB64Url(b64url) {
  const raw = Buffer.from(b64url.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  if (raw.length !== 32) throw new Error(`expected 32-byte ed25519 key, got ${raw.length}`);
  const spkiHeader = Buffer.from('302a300506032b6570032100', 'hex');
  const spki = Buffer.concat([spkiHeader, raw]);
  return createPublicKey({ key: spki, format: 'der', type: 'spki' });
}

/**
 * Verify an X-AAE header against caller-supplied trust rules.
 *
 * Defaults are deliberately strict — `aud` and `exp` are required, max
 * envelope lifetime is 5 minutes, only Ed25519 signatures accepted. A
 * caller working with a more permissive issuer (e.g. for migration
 * compatibility) can relax via the options below, but the library
 * defaults to "fail closed".
 *
 * @param {string|undefined} headerVal       — raw header value (base64url JSON)
 * @param {object} ctx
 *   @param {object} ctx.keyResolver         — { resolve: async (key_id) => {public_key_b64url, sig_alg} | null }
 *   @param {object} ctx.revocationChecker   — { isRevoked: async (jti) => boolean }
 *   @param {object} ctx.nonceCache          — { seen: (jti, expSec) => boolean | 'cache_full' }
 *   @param {string} [ctx.expectedAud='a2a-ingress'] — required match; pass `null` to disable (NOT recommended)
 *   @param {string} [ctx.expectedSub]       — if set, env.sub MUST match this exact string. Defends against cross-peer replay.
 *   @param {boolean} [ctx.requireExp=true]  — require env.exp present
 *   @param {number} [ctx.maxLifetimeSec=300] — reject envelopes whose exp is more than this far in the future
 *   @param {number} [ctx.iatSkewSec=60]     — clock-skew tolerance for env.iat
 * @returns {Promise<object>} verification summary
 */
export async function verifyAae(headerVal, ctx) {
  const expectedAud = ctx.expectedAud === null ? null : (ctx.expectedAud ?? 'a2a-ingress');
  const expectedSub = ctx.expectedSub == null ? null : ctx.expectedSub;
  const requireExp = ctx.requireExp !== false;
  const maxLifetimeSec = ctx.maxLifetimeSec ?? 300;
  const iatSkewSec = ctx.iatSkewSec ?? 60;

  if (!headerVal || typeof headerVal !== 'string') {
    return fail('no_envelope');
  }
  let env;
  try {
    env = JSON.parse(b64urlDecode(headerVal).toString('utf8'));
  } catch {
    return fail('parse_error');
  }
  if (env === null || typeof env !== 'object' || Array.isArray(env)) {
    return fail('parse_error');
  }
  if (env.v !== 1) return fail('unsupported_version');

  // Type-validate critical fields BEFORE using them. A buggy/malicious
  // issuer sending "1700000000" (string) for exp would otherwise
  // silently pass via JS type coercion. NaN passes typeof===number
  // but breaks every comparison (NaN<x and NaN>x are both false), so
  // we use Number.isFinite to reject NaN/+Inf/-Inf for any field
  // that participates in time-window or comparison logic.
  if (env.iss != null && typeof env.iss !== 'string') return fail('iss_invalid_type');
  if (env.sub != null && typeof env.sub !== 'string') return fail('sub_invalid_type');
  if (env.jti != null && typeof env.jti !== 'string') return fail('jti_invalid_type');
  if (env.aud != null && typeof env.aud !== 'string') return fail('aud_invalid_type', { issuer: env.iss });
  if (env.sig_key_id != null && typeof env.sig_key_id !== 'string') return fail('key_id_invalid_type', { issuer: env.iss, jti: env.jti });
  if (env.sig_alg != null && typeof env.sig_alg !== 'string') return fail('sig_alg_invalid_type', { issuer: env.iss, jti: env.jti });
  if (env.exp != null && !isFiniteNumber(env.exp)) return fail('exp_invalid_type', { issuer: env.iss, jti: env.jti });
  if (env.iat != null && !isFiniteNumber(env.iat)) return fail('iat_invalid_type', { issuer: env.iss, jti: env.jti });
  if (env.hop != null && !isFiniteNumber(env.hop)) return fail('hop_invalid_type', { issuer: env.iss, jti: env.jti });
  if (env.perm != null && !Array.isArray(env.perm)) return fail('perm_invalid_type', { issuer: env.iss, jti: env.jti });

  // String-field length caps. Outsized signer values flow into
  // audit logs, ACL lookups, rate-limit keys, response bodies — bound
  // memory + log-injection risk at the entry point.
  if (typeof env.iss === 'string' && env.iss.length > MAX_STRING_FIELD_LEN) return fail('iss_too_long', { jti: env.jti });
  if (typeof env.sub === 'string' && env.sub.length > MAX_STRING_FIELD_LEN) return fail('sub_too_long', { issuer: env.iss, jti: env.jti });
  if (typeof env.jti === 'string' && env.jti.length > MAX_STRING_FIELD_LEN) return fail('jti_too_long', { issuer: env.iss });
  if (typeof env.aud === 'string' && env.aud.length > MAX_STRING_FIELD_LEN) return fail('aud_too_long', { issuer: env.iss, jti: env.jti });
  if (typeof env.sig_key_id === 'string' && env.sig_key_id.length > MAX_STRING_FIELD_LEN) return fail('key_id_too_long', { issuer: env.iss, jti: env.jti });

  // Audience: when expectedAud is set, env.aud MUST be present AND match.
  // Skipping the check when env.aud is missing would let an audless envelope
  // pass for any audience — exactly the kind of cross-namespace replay
  // we want to prevent.
  if (expectedAud !== null) {
    if (typeof env.aud !== 'string' || env.aud !== expectedAud) {
      return fail('wrong_audience', { issuer: env.iss, jti: env.jti });
    }
  }

  // Subject: when expectedSub is set, env.sub MUST be present AND
  // match. Defends against cross-peer replay — an envelope captured
  // for peer alice cannot be replayed against peer bob within the
  // same audience and expiry window. If the caller doesn't pass
  // expectedSub, sub is unvalidated (advisory-only).
  if (expectedSub !== null) {
    if (typeof env.sub !== 'string' || env.sub !== expectedSub) {
      return fail('wrong_subject', { issuer: env.iss, jti: env.jti });
    }
  }

  const now = Math.floor(Date.now() / 1000);

  // Expiry: required by default. A compromised signing key today should
  // not invalidate a year of past envelopes, so we want short-lived
  // envelopes only.
  if (env.exp == null) {
    if (requireExp) return fail('missing_exp', { issuer: env.iss, jti: env.jti });
  } else {
    if (env.exp < now) {
      return fail('expired', {
        issuer: env.iss, jti: env.jti,
        expiresAt: new Date(env.exp * 1000).toISOString(),
      });
    }
    // Cap maximum lifetime — refuse envelopes that try to claim a
    // year-long validity window. Defends against compromised-key replay.
    if (env.exp > now + maxLifetimeSec) {
      return fail('exp_too_far', {
        issuer: env.iss, jti: env.jti,
        expiresAt: new Date(env.exp * 1000).toISOString(),
      });
    }
  }

  if (env.iat != null && env.iat > now + iatSkewSec) {
    return fail('iat_in_future', { issuer: env.iss, jti: env.jti });
  }

  // Replay protection — short window so a captured envelope can be
  // presented exactly once. NonceCache returns 'cache_full' if it
  // can't safely accept new entries; we treat that as fail-closed
  // (rather than evicting an old entry that might still be in flight).
  if (typeof env.jti !== 'string' || env.jti.length === 0) {
    return fail('missing_jti', { issuer: env.iss });
  }
  const seenResult = ctx.nonceCache.seen(env.jti, env.exp ?? (now + 60));
  if (seenResult === 'cache_full') {
    return fail('nonce_cache_full', { issuer: env.iss, jti: env.jti });
  }
  if (seenResult !== true) {
    return fail('replay', { issuer: env.iss, jti: env.jti });
  }

  if (await ctx.revocationChecker.isRevoked(env.jti)) {
    return fail('revoked', { issuer: env.iss, jti: env.jti });
  }

  if (!env.sig_key_id) return fail('missing_key_id', { issuer: env.iss, jti: env.jti });
  if (env.sig_alg !== 'Ed25519') return fail('unsupported_sig_alg', { issuer: env.iss, jti: env.jti });
  let keyMaterial;
  try {
    keyMaterial = await ctx.keyResolver.resolve(env.sig_key_id);
  } catch {
    // Fail-closed. Underlying error message is the resolver's
    // responsibility to log — we surface only a fixed reason so we
    // don't leak internal implementation details to the client.
    return fail('key_resolver_failed', { issuer: env.iss, jti: env.jti });
  }
  if (!keyMaterial) return fail('unknown_key', { issuer: env.iss, jti: env.jti });

  let key;
  try {
    key = pubKeyFromB64Url(keyMaterial.public_key_b64url);
  } catch {
    return fail('key_format_error', { issuer: env.iss, jti: env.jti });
  }

  // Build the canonical signed bytes from the allowlist only.
  // signablePayload() is the single source of truth — also exported
  // so signers in any language can construct identical bytes.
  const payload = signablePayload(env);
  const sig = env.sig;
  if (typeof sig !== 'string') return fail('sig_missing', { issuer: env.iss, jti: env.jti });
  let sigBuf;
  try { sigBuf = b64urlDecode(sig); } catch { return fail('sig_decode_error', { issuer: env.iss, jti: env.jti }); }

  let good = false;
  try {
    good = cryptoVerify(null, payload, key, sigBuf);
  } catch {
    // Verification threw (e.g. malformed signature buffer). Don't
    // surface the underlying error — return a fixed reason and let
    // the caller's logger record details from server-side context.
    return fail('sig_verify_error', { issuer: env.iss, jti: env.jti });
  }
  if (!good) return fail('sig_invalid', { issuer: env.iss, jti: env.jti });

  return ok(env);
}

// Low-level helper exported for advanced callers. Most signers should
// use `signablePayload(env)` instead — it enforces the SIGNED_FIELDS
// allowlist. Calling `canonicalize` on a raw envelope (including any
// keys the parser produces) will diverge from what the verifier signs
// over.
export { canonicalize };
