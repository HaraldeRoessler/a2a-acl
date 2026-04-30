// Per-tool capability schema. v1 capabilities:
//
//   message
//     Send a free-form message to the agent. The agent's LLM processes
//     and replies. Content is mediated by the agent's prompt/SOUL/etc;
//     this library only enforces "can the peer send a message at all".
//
//   invoke_tool:<name>
//     Trigger a specific named skill on the agent. <name> is
//     [a-z0-9-]{1,40}. Each receiver's owner grants per tool.
//
//   read_memory:<wing>
//   read_memory:<wing>/<room>
//     List/search/read drawers in a memory wing (or a single room
//     within a wing). Wing/room are [a-z][a-z0-9-]{0,30}.
//
// Capability strings are stored verbatim in your ACL store. The match
// endpoint is responsible for fuzzy-matching e.g. read_memory:work →
// read_memory:work/projects (a wing-wide grant covers room queries).

export const CAP_PATTERN = /^(message|invoke_tool:[a-z0-9-]{1,40}|read_memory:[a-z][a-z0-9-]{0,30}(\/[a-z][a-z0-9-]{0,30})?)$/;

/**
 * Parse a capability string into a structured form.
 * Returns { kind: 'message' } | { kind: 'invoke_tool', name } |
 *         { kind: 'read_memory', wing, room? } | null on parse failure.
 */
export function parseCapability(s) {
  if (!CAP_PATTERN.test(s)) return null;
  if (s === 'message') return { kind: 'message' };
  if (s.startsWith('invoke_tool:')) {
    return { kind: 'invoke_tool', name: s.slice('invoke_tool:'.length) };
  }
  if (s.startsWith('read_memory:')) {
    const ref = s.slice('read_memory:'.length);
    const [wing, room] = ref.split('/');
    return room ? { kind: 'read_memory', wing, room } : { kind: 'read_memory', wing };
  }
  return null;
}

/**
 * Infer the capability that an inbound HTTP request maps to.
 *
 * Default route → capability bindings:
 *   POST /api/a2a/message                                      → message
 *   POST /api/a2a/invoke_tool   {tool: 'sendgrid'}             → invoke_tool:sendgrid
 *   POST /api/a2a/read_memory   {wing, room?}                  → read_memory:wing[/room]
 *   POST /api/a2a/list_drawers  {wing, room?}                  → read_memory:wing[/room]
 *   POST /api/a2a/search        {wing, room?}                  → read_memory:wing[/room]
 *
 * Returns the capability string, or null for unknown shapes (caller
 * should reject with 400).
 *
 * @param {object} req — Express-style request with method, path, body
 * @param {object} [opts]
 *   @param {string} [opts.basePath] — strip from req.path before matching (e.g. '/api/a2a')
 */
export function inferCapability(req, opts = {}) {
  if (req.method !== 'POST') return null;
  const basePath = opts.basePath ?? '/api/a2a';
  const path = req.path.startsWith(basePath) ? req.path.slice(basePath.length) : req.path;

  if (path === '/message') return 'message';

  if (path === '/invoke_tool') {
    const tool = req.body?.tool;
    if (typeof tool === 'string' && /^[a-z0-9-]{1,40}$/.test(tool)) {
      return `invoke_tool:${tool}`;
    }
    return null;
  }

  if (path === '/read_memory' || path === '/list_drawers' || path === '/search') {
    const wing = req.body?.wing;
    const room = req.body?.room;
    if (typeof wing !== 'string') return null;
    if (typeof room === 'string' && room.length > 0) return `read_memory:${wing}/${room}`;
    return `read_memory:${wing}`;
  }

  return null;
}
