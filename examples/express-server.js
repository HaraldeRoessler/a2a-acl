// Minimal Express server showing how to wire a2a-acl into an A2A
// receiver. The caller (you) supplies the four async lookup callbacks
// that adapt the library to your storage backend (Postgres, Redis,
// SQLite, in-memory — any of them works).

import express from 'express';
import {
  firewallChain,
  KeyResolver,
  TrustResolver,
  RevocationChecker,
  NonceCache,
  RateLimiter,
  DailyTokenBudget,
  CircuitBreaker,
} from '../src/index.js';

// ─── caller-supplied resolvers ──────────────────────────────────────
//
// In real life you'd hit your own database / control plane. These
// stubs return synthetic data so the example runs standalone.

const FAKE_KEYS = {
  'tenant-alice-v1': {
    public_key_b64url: 'replace-with-32-byte-ed25519-pubkey-base64url',
    sig_alg: 'Ed25519',
  },
};
const FAKE_SCORES = { 'did:example:alice': 0.85 };
const FAKE_REVOKED = new Set();
const FAKE_ACL = [
  { peer_slug: 'bob', caller_did: 'did:example:alice', capability: 'message', threshold_override: null },
  { peer_slug: 'bob', caller_did: 'did:example:alice', capability: 'invoke_tool:weather', threshold_override: 0.9 },
];

const keyResolver = new KeyResolver({
  resolve: async (keyId) => FAKE_KEYS[keyId] ?? null,
});
const trustResolver = new TrustResolver({
  resolve: async (did) => FAKE_SCORES[did] ?? 0,
});
const revocationChecker = new RevocationChecker({
  check: async (jti) => FAKE_REVOKED.has(jti),
});
const nonceCache = new NonceCache();
const rateLimiter = new RateLimiter({ requestsPerMinute: 5 });
const tokenBudget = new DailyTokenBudget({ tokensPerDay: 10_000 });
const circuitBreaker = new CircuitBreaker();

async function matchAcl({ slug, callerDid, capability }) {
  // Wing-prefix fallback: read_memory:work/projects → also match read_memory:work
  const candidates = [capability];
  if (capability.startsWith('read_memory:') && capability.includes('/')) {
    const wing = capability.split(':')[1].split('/')[0];
    candidates.push(`read_memory:${wing}`);
  }
  for (const cap of candidates) {
    const row = FAKE_ACL.find(
      (r) => r.peer_slug === slug && r.caller_did === callerDid && r.capability === cap
    );
    if (row) return row;
  }
  return null;
}

// ─── Express app ────────────────────────────────────────────────────

const app = express();
app.use(express.json());

// In your real app the slug would come from a path param or subdomain.
// Here we hardcode 'bob' so the example is self-contained.
app.use((req, _res, next) => {
  req.firewall = { slug: 'bob' };
  next();
});

app.use('/api/a2a', ...firewallChain({
  keyResolver,
  revocationChecker,
  nonceCache,
  trustResolver,
  rateLimiter,
  tokenBudget,
  circuitBreaker,
  matchAcl,
  defaultThreshold: 0.7,
  maxHopCount: 3,
  expectedAud: 'a2a-ingress',
  basePath: '/api/a2a',
  // Optional: a logger that follows the pino interface (info/warn/error)
  // logger: console,
  // Optional: audit sink — every accepted/denied request lands here.
  // sink: (row) => { ... write to audit table ... },
}));

// Once a request passes the firewall, your handler does the actual
// work — forward to the agent's runtime, return its reply, etc.
app.post('/api/a2a/message', (req, res) => {
  res.json({ ok: true, you_said: req.body });
});
app.post('/api/a2a/invoke_tool', (req, res) => {
  res.json({ ok: true, tool: req.body.tool });
});

const port = process.env.PORT ?? 3000;
app.listen(port, () => {
  console.log(`a2a-acl example listening on :${port}`);
});
