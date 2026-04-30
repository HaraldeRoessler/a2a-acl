// Content sanitisation for inbound A2A payloads. Walks JSON request
// bodies and strips prompt-injection markers from string values
// before forwarding the request to the receiving agent.
//
// Strategy is conservative: STRIP rather than REJECT. A legitimate
// delegation that happens to include suspicious-looking text loses
// the markers but the rest of the request still flows.
//
// Three classes of markers handled:
//   1. Invisible / control unicode (zero-width, RTL/LRM, unicode tags
//      in the E0000–E007F range).
//   2. Role-flip line prefixes — lines that start with "system:",
//      "assistant:", "user:" can hijack role parsing in some prompt
//      templates.
//   3. Direct override patterns at line starts — "ignore previous
//      instructions", "disregard the above", "you are now", etc.
//
// We deliberately do NOT do AI-detection of subtle adversarial
// content. That's a model-side defence concern. The library only
// handles obvious markers that are cheap to filter.

// Class 1: invisible / control unicode.
const INVISIBLES = /[​-‏‪-‮⁠-⁤⁦-⁯﻿\u{E0000}-\u{E007F}]/gu;

// Class 2: role-flip prefixes at start of line. Multiline + case-insensitive.
const ROLE_FLIPS = /^[ \t]*(system|assistant|user|developer)[ \t]*:/gim;

// Class 3: well-known override phrases at start of line.
const OVERRIDE_PHRASES = [
  /^[ \t]*ignore (the )?(previous|prior|above) (instructions?|prompt|messages?)/gim,
  /^[ \t]*disregard (the )?(previous|prior|above|all) /gim,
  /^[ \t]*forget (everything|all|the above|previous) /gim,
  /^[ \t]*you are now /gim,
  /^[ \t]*act as /gim,
  /^[ \t]*new instructions?:/gim,
  /^[ \t]*<\|im_start\|>/gim, // ChatML markers
  /^[ \t]*<\|im_end\|>/gim,
];

const STRIP_NOTE = '[a2a-acl-stripped]';

/**
 * Sanitise a string. Returns { value, hits } — hits is the count of
 * patterns that fired (for audit). Returns the original with hits=0
 * if nothing matched.
 */
export function sanitiseString(s) {
  if (typeof s !== 'string') return { value: s, hits: 0 };
  let out = s;
  let hits = 0;

  const beforeInv = out.length;
  out = out.replace(INVISIBLES, '');
  if (out.length !== beforeInv) hits += 1;

  // Build a fresh regex per call. ROLE_FLIPS has the /g flag which
  // means RegExp.test() advances `lastIndex` between calls — sharing
  // state across requests would cause missed matches. Same defensive
  // pattern as OVERRIDE_PHRASES below.
  const roleFlipsRe = new RegExp(ROLE_FLIPS.source, ROLE_FLIPS.flags);
  if (roleFlipsRe.test(out)) {
    out = out.replace(new RegExp(ROLE_FLIPS.source, ROLE_FLIPS.flags), (_m, role) => `${STRIP_NOTE} ${role} :`);
    hits += 1;
  }

  for (const pat of OVERRIDE_PHRASES) {
    const re = new RegExp(pat.source, pat.flags);
    if (re.test(out)) {
      out = out.replace(new RegExp(pat.source, pat.flags), (m) => `${STRIP_NOTE} ${m}`);
      hits += 1;
    }
  }

  return { value: out, hits };
}

/**
 * Walk a JSON-shaped value (object, array, primitive) and sanitise
 * every string leaf. Returns { value, hits } — total hits across the
 * structure. Object/array structure is preserved.
 */
export function sanitiseDeep(v) {
  if (v === null || v === undefined) return { value: v, hits: 0 };
  if (typeof v === 'string') return sanitiseString(v);
  if (Array.isArray(v)) {
    const out = [];
    let hits = 0;
    for (const item of v) {
      const { value, hits: h } = sanitiseDeep(item);
      out.push(value);
      hits += h;
    }
    return { value: out, hits };
  }
  if (typeof v === 'object') {
    const out = {};
    let hits = 0;
    for (const [k, vv] of Object.entries(v)) {
      // Sanitise keys too. JSON keys rarely reach LLM prompt context
      // but a property name like "system: " or one carrying invisible
      // unicode could survive into downstream prompts depending on
      // how the receiver renders the request. Cheap to defend.
      const { value: sanitisedKey, hits: kh } = sanitiseString(k);
      const { value: sanitisedVal, hits: vh } = sanitiseDeep(vv);
      out[sanitisedKey] = sanitisedVal;
      hits += kh + vh;
    }
    return { value: out, hits };
  }
  return { value: v, hits: 0 };
}
