# Security policy

## Reporting a vulnerability

If you find a vulnerability in `a2a-acl`, please **do not open a public
issue**. Email the maintainer at `harald.roessler@dsncon.com` with:

- A clear description of the issue
- Reproduction steps (or a PoC if you have one)
- Affected version(s)
- Your assessment of impact

You can expect an acknowledgment within 72 hours and a coordinated
disclosure window before any fix is published.

## What this library defends against

The library implements the **policy layer** for inbound agent-to-agent
HTTP requests. It hard-rejects:

- Unsigned requests
- Replays (nonce cache + envelope expiry)
- Cross-audience replays (audience mismatch)
- Expired or far-future envelopes
- Unknown signing keys
- Wrong signature algorithm (only Ed25519 accepted)
- Revoked envelope ids
- `(caller_did, capability)` pairs not in your ACL store
- Callers whose trust score is below the matched rule's threshold (or your default)
- Recursion chains deeper than `maxHopCount`
- Per-(caller, peer) rate limits and daily token budgets

Plus a soft layer that **strips** common prompt-injection markers from
inbound JSON bodies before forwarding to your agent.

## What this library does NOT defend against

These are explicit non-goals — handle them at adjacent layers:

### 1. SQL injection in your `matchAcl` callback

The library passes the attacker-controlled `callerDid` (extracted from
the AAE envelope's `iss` field) directly to your `matchAcl` callback.
If you implement that callback with raw SQL string interpolation, you
have a SQL-injection sink in the wide open:

```js
// DO NOT DO THIS
async function matchAcl({ slug, callerDid, capability }) {
  return await db.raw(`SELECT * FROM acl WHERE caller_did = '${callerDid}'`);
}
```

**Always use parameterised queries / prepared statements** in
`matchAcl` (and any other callback that touches a database):

```js
async function matchAcl({ slug, callerDid, capability }) {
  return await db.query(
    'SELECT * FROM acl WHERE peer_slug=$1 AND caller_did=$2 AND capability=$3',
    [slug, callerDid, capability]
  );
}
```

### 2. Body size attacks

The library does not enforce a maximum request body size. Use
`express.json({ limit: '100kb' })` (or your framework equivalent)
*before* mounting the firewall chain. Otherwise a peer could ship a
10 GB body and exhaust memory before any check runs.

### 3. CORS, TLS termination, ingress filtering

The library is HTTP-framework middleware. CORS, TLS termination, and
public-ingress restrictions (NetworkPolicy, WAF, geo-blocking) are
out of scope. Set them at the layer above.

### 4. Sophisticated prompt injection

`sanitiseDeep` strips known markers (zero-width / control unicode,
role-flip prefixes, obvious "ignore previous instructions" patterns).
It does NOT defend against:

- Mid-line role-flip attempts (`hello system: do evil`)
- Unicode-normalisation bypass (e.g. fullwidth `ｓｙｓｔｅｍ:`)
- Encoded payloads (base64, hex)
- LLM-side adversarial reasoning

The agent's system prompt and the model's own training are the real
defence here. Sanitisation is a cheap defence-in-depth layer, not a
primary control.

### 5. Replay across multiple gateway processes

The default `NonceCache`, `RateLimiter`, and `DailyTokenBudget` are
**single-process in-memory**. If you run multiple gateway replicas:

- A replay caught on replica A is NOT caught on replica B.
- A rate-limit consumed on replica A does NOT count against replica B.

For horizontal scaling, swap the implementations to a Redis-backed
version with the same API (`seen(jti, expSec) → boolean | 'cache_full'`,
`consume(key) → boolean`, etc.). The library deliberately does not
ship a Redis backend so users aren't forced to take that dependency.

### 6. Issuer-side guarantees

The library trusts the signer's contract:

- `jti` is unique per envelope (replay protection presumes this)
- The signer rotates keys on compromise (revocation is a fallback,
  not a primary defence)
- The signer correctly sets `aud` for the intended receiver
- The signer canonicalises with the same RFC 8785-lite scheme this
  library uses on verify

If you ship a buggy signer that reuses jti or omits aud, the
verifier's defences degrade. Test your signer.

### 7. Confidentiality of the envelope itself

AAE envelopes are signed but NOT encrypted. They go in HTTP headers
and are visible to any TLS terminator on the path. Don't put secrets
in `perm`, `sub`, or any other envelope field.

### 8. Trust-score collusion / sybil

The trust-score gate is configurable but the library doesn't
prescribe a trust algorithm. If your `trustResolver` uses a
self-reportable score (e.g. an agent rating itself), you'll get sybil
attacks. Use a counterparty-attested score (e.g. MolTrust) and accept
that even those have manipulation risk — see e.g.
[ownify's own writeup](https://ownify.ai/blog/per-tool-acl-for-the-agent-web)
for the trade-offs.

## Defaults are deliberately strict

In `verifyAae`:

- `expectedAud` is required to match (default `'a2a-ingress'`; pass
  `null` to disable, NOT recommended)
- `requireExp` defaults to true
- `maxLifetimeSec` defaults to 300 (5 minutes) — envelopes claiming
  longer validity are rejected
- `iatSkewSec` defaults to 60 — clock skew tolerance window

You can relax these for migration compatibility, but the library
defaults to "fail closed".

## Versioning + advisories

Security-relevant fixes will be released as patch versions (`0.1.x`)
with a note in the CHANGELOG. We will publish a GitHub Security
Advisory for any vulnerability we fix that we believe could affect
production deployments.
