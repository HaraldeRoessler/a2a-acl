# a2a-acl

Per-tool capability ACL + AAE envelope verification for agent-to-agent
communication.

When two AI agents talk to each other across organisational
boundaries, the receiver's owner needs control over **what** the
caller is permitted to do — not just whether they're a "trusted"
peer. This library implements the policy layer: cryptographic
identity verification, per-capability allowlists, optional trust-score
gating, payload sanitisation, and rate limiting — as drop-in Express
middleware.

It is the open-source extraction of the gateway that runs in front of
[ownify](https://ownify.ai)'s production agents. See the design write-up:
[Per-tool ACL for the agent web — how ownify locks down agent-to-agent calls](https://ownify.ai/blog/per-tool-acl-for-the-agent-web).

## What it gives you

| Stage | What it enforces | Failure mode |
|---|---|---|
| `verifyAaeMiddleware` | Cryptographic envelope (Ed25519, with replay + revocation + audience check) | 401 |
| `aclCheckMiddleware` | The `(receiver_slug, caller_did, capability)` tuple is in your ACL store | 403 `acl_no_capability_grant` |
| `trustScoreGateMiddleware` | Caller's trust score clears the matched rule's `threshold_override` (or your default) | 403 `trust_score_below_threshold` |
| `sanitiseMiddleware` | Strip prompt-injection markers from request body | (forwards, audit-only) |
| `depthGuardMiddleware` | AAE chain hop count ≤ `maxHopCount` | 403 `recursion_depth_exceeded` |
| `circuitOpenCheckMiddleware` | Upstream peer slug isn't in cooldown | 503 `upstream_circuit_open` |
| `rateLimitMiddleware` | Per-(caller, peer) requests/minute + daily token budget | 429 |
| `auditMiddleware` | Fire-and-forget sink for every decision | (logs only) |

The library ships **the algorithm**. You plug in **the storage**:
key resolution, ACL match, trust scores, revocation list. Whatever
backs them — Postgres, Redis, SQLite, in-memory tests — is your choice.

## Capability schema

```
message
invoke_tool:<name>            (e.g. invoke_tool:sendgrid)
read_memory:<wing>            (wing-wide read access)
read_memory:<wing>/<room>     (single-room read access)
```

`message` lets the peer chat with your agent's LLM (soft layer).
`invoke_tool:*` triggers a specific named skill (hard layer).
`read_memory:*` lists/reads memory drawers in a wing or room (hard layer).

Default is **deny**. The receiver's owner grants exactly what the
peer is allowed to do. No grant by trust score alone, no implicit
allowlist for being a registered peer.

## Install

```sh
npm install a2a-acl express
```

Requires Node 20+. Express is a peer dep — works with Express 4 and 5.

## Usage

```js
import express from 'express';
import {
  firewallChain,
  KeyResolver, TrustResolver, RevocationChecker,
  NonceCache, RateLimiter, DailyTokenBudget, CircuitBreaker,
} from 'a2a-acl';

// 1. Resolvers — you provide the storage backend.

const keyResolver = new KeyResolver({
  resolve: async (keyId) => {
    // Return { public_key_b64url: '...32-byte-base64url...', sig_alg: 'Ed25519' }
    // or null if unknown. Throw on transient failures (resolver retries).
    return await db.keys.findOne({ key_id: keyId });
  },
});

const trustResolver = new TrustResolver({
  resolve: async (did) => ({ score: await scoreLookup(did) }),
});

const revocationChecker = new RevocationChecker({
  check: async (jti) => await db.revocations.exists({ jti }),
});

const nonceCache = new NonceCache();
const rateLimiter = new RateLimiter({ requestsPerMinute: 5 });
const tokenBudget = new DailyTokenBudget({ tokensPerDay: 10_000 });
const circuitBreaker = new CircuitBreaker();

// 2. ACL match callback.

async function matchAcl({ slug, callerDid, capability }) {
  // Wing-prefix fallback for read_memory: a wing-wide grant covers
  // any room within that wing.
  const candidates = [capability];
  if (capability.startsWith('read_memory:') && capability.includes('/')) {
    const wing = capability.split(':')[1].split('/')[0];
    candidates.push(`read_memory:${wing}`);
  }
  return await db.acl.findOne({
    peer_slug: slug,
    caller_did: callerDid,
    capability: { $in: candidates },
  });
}

// 3. Wire the chain.

const app = express();
app.use(express.json());

app.use('/api/a2a/:slug', (req, _res, next) => {
  req.firewall = { slug: req.params.slug };
  next();
});

app.use('/api/a2a/:slug', ...firewallChain({
  keyResolver, revocationChecker, nonceCache, trustResolver,
  rateLimiter, tokenBudget, circuitBreaker, matchAcl,
  defaultThreshold: 0.7,
  maxHopCount: 3,
  expectedAud: 'a2a-ingress',
  basePath: '/api/a2a/:slug',
  logger: console, // optional; pino-style { info, warn, error }
  sink: (row) => db.audit.insert(row), // optional
}));

// Your handlers run only after the chain accepts.
app.post('/api/a2a/:slug/message', (req, res) => {
  // forward to your agent runtime, stream its reply back
});

app.listen(3000);
```

A complete working example lives in `examples/express-server.js`.
Run it with `npm run example`.

## What's req.firewall

Each middleware writes its decision/state to `req.firewall.*` so
later stages can read it:

| Field | Set by | Type |
|---|---|---|
| `req.firewall.public` | verifyAae (when path is agent-card / well-known) | boolean |
| `req.firewall.aae` | verifyAae | the verification result object |
| `req.firewall.callerDid` | verifyAae | DID string from envelope `iss` |
| `req.firewall.aclRule` | aclCheck | the matched rule (whatever your `matchAcl` returned) |
| `req.firewall.trustScore` | trustScoreGate | number 0..1 |
| `req.firewall.sanitiseHits` | sanitise | count of sanitise patterns that fired |
| `req.firewall.tokenEstimate` | rateLimit | bytes-÷-4 estimate of this request |

## What's NOT in the library

- **Storage**. Your DB schema, your tables, your queries.
- **A specific trust-score algorithm**. You decide what trust means.
- **Outbound envelope signing**. The signing side is on the caller's
  control plane; this library is for the *receiving* gateway.
- **Framework adapters beyond Express**. Add Fastify/Hono in v0.2 if
  there's demand — the core (resolvers, sanitiser, rate-limit, AAE
  parse/verify, capability schema) is framework-agnostic.

## Why this exists

The agent web is racing to ship. Most platforms either have no
agent-to-agent authorization, or a single global trust-score gate
that's not really authorization. Neither matches how delegation
between organisations actually works.

This library is the policy layer that runs at
[ownify.ai](https://ownify.ai) in production. We extracted it so
others building agent infrastructure don't have to roll their own.

If you find a bug, open an issue. If you want it adapted to your
stack, send a PR.

## License

[MIT](./LICENSE).
