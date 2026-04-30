// @a2a-acl public API.
//
// See README.md for usage. The core idea:
//
//   import { firewallChain, KeyResolver, TrustResolver,
//            RevocationChecker, NonceCache, RateLimiter,
//            DailyTokenBudget, CircuitBreaker } from 'a2a-acl';
//
//   app.use('/api/a2a', ...firewallChain({
//     keyResolver, revocationChecker, nonceCache, trustResolver,
//     rateLimiter, tokenBudget, circuitBreaker,
//     matchAcl: async ({slug, callerDid, capability}) => {...},
//     getSlug: (req) => req.params.slug,
//     defaultThreshold: 0.7, maxHopCount: 3,
//     expectedAud: 'a2a-ingress', basePath: '/api/a2a',
//   }));

export { verifyAae, canonicalize } from './aae.js';
export { NonceCache } from './nonce-cache.js';
export { sanitiseString, sanitiseDeep } from './sanitise.js';
export {
  RateLimiter,
  DailyTokenBudget,
  CircuitBreaker,
} from './rate-limit.js';
export {
  KeyResolver,
  TrustResolver,
  RevocationChecker,
} from './resolvers.js';
export {
  CAP_PATTERN,
  parseCapability,
  inferCapability,
} from './capability.js';
export {
  verifyAaeMiddleware,
  aclCheckMiddleware,
  trustScoreGateMiddleware,
  sanitiseMiddleware,
  depthGuardMiddleware,
  circuitOpenCheckMiddleware,
  rateLimitMiddleware,
  auditMiddleware,
  firewallChain,
} from './middleware.js';
