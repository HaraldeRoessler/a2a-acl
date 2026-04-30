// AAE — Agent Authorization Envelope verification.
//
// Envelope wire format: base64url-encoded JSON. Signature is Ed25519
// over the canonical-stringified envelope minus the `sig` field.
// Canonicalisation matches RFC 8785-lite (sort object keys, no
// whitespace) — issuer must use the same canonicalize() to produce
// the signed bytes.

import { verify as cryptoVerify, createPublicKey } from 'node:crypto';

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
 * @param {string|undefined} headerVal       — raw header value (base64url JSON)
 * @param {object} ctx
 *   @param {object} ctx.keyResolver         — { resolve: async (key_id) => {public_key_b64url, sig_alg} | null }
 *   @param {object} ctx.revocationChecker   — { isRevoked: async (jti) => boolean }
 *   @param {object} ctx.nonceCache          — { seen: (jti, expSec) => boolean (true if first time) }
 *   @param {string} [ctx.expectedAud]       — defaults to 'a2a-ingress'
 * @returns {Promise<object>} verification summary
 */
export async function verifyAae(headerVal, ctx) {
  const expectedAud = ctx.expectedAud ?? 'a2a-ingress';
  if (!headerVal) {
    return fail('no_envelope');
  }
  let env;
  try {
    env = JSON.parse(b64urlDecode(headerVal).toString('utf8'));
  } catch {
    return fail('parse_error');
  }
  if (env.v !== 1) return fail('unsupported_version');
  if (env.aud && env.aud !== expectedAud) {
    return fail('wrong_audience', { issuer: env.iss, jti: env.jti });
  }

  const now = Math.floor(Date.now() / 1000);
  if (env.exp && env.exp < now) {
    return fail('expired', { issuer: env.iss, jti: env.jti, expiresAt: new Date(env.exp * 1000).toISOString() });
  }
  if (env.iat && env.iat > now + 60) {
    return fail('iat_in_future', { issuer: env.iss, jti: env.jti });
  }

  // Replay protection — short window so a captured envelope can be
  // presented exactly once before the cache + the natural expiry both
  // reject it.
  if (env.jti) {
    const firstTime = ctx.nonceCache.seen(env.jti, env.exp ?? (now + 60));
    if (!firstTime) {
      return fail('replay', { issuer: env.iss, jti: env.jti });
    }
  } else {
    return fail('missing_jti');
  }

  if (await ctx.revocationChecker.isRevoked(env.jti)) {
    return fail('revoked', { issuer: env.iss, jti: env.jti });
  }

  if (!env.sig_key_id) return fail('missing_key_id', { issuer: env.iss, jti: env.jti });
  if (env.sig_alg !== 'Ed25519') return fail('unsupported_sig_alg', { issuer: env.iss, jti: env.jti });
  let keyMaterial;
  try {
    keyMaterial = await ctx.keyResolver.resolve(env.sig_key_id);
  } catch (err) {
    // Fail-closed: never accept unverified signatures on the public boundary.
    return fail(`key_resolver_failed:${err?.message?.slice(0, 30) ?? 'unknown'}`, { issuer: env.iss, jti: env.jti });
  }
  if (!keyMaterial) return fail('unknown_key', { issuer: env.iss, jti: env.jti });

  let key;
  try {
    key = pubKeyFromB64Url(keyMaterial.public_key_b64url);
  } catch (err) {
    return fail(`key_format_error:${err.message.slice(0, 30)}`, { issuer: env.iss, jti: env.jti });
  }

  // Canonicalize everything except `sig`. The signing side must compute
  // the signature over the same byte sequence — any mismatch (key order,
  // whitespace, type coercion) fails verification.
  const { sig, ...signed } = env;
  const payload = Buffer.from(canonicalize(signed), 'utf8');
  let sigBuf;
  try { sigBuf = b64urlDecode(sig); } catch { return fail('sig_decode_error', { issuer: env.iss, jti: env.jti }); }

  let good = false;
  try {
    good = cryptoVerify(null, payload, key, sigBuf);
  } catch (err) {
    return fail(`sig_verify_error:${err?.message?.slice(0, 30) ?? 'unknown'}`, { issuer: env.iss, jti: env.jti });
  }
  if (!good) return fail('sig_invalid', { issuer: env.iss, jti: env.jti });

  return ok(env);
}

// Exported so callers can reproduce the canonical bytes for issuance.
export { canonicalize };
