// A minimal MCP server over stdio: newline-delimited JSON-RPC 2.0.
//
// Written by hand instead of pulling in the official SDK, which brings 17
// dependencies (Express, Hono, and more) for a server that only needs four
// methods. A security tool should be easy to audit end to end.
//
// stdout carries protocol messages only. Anything human goes to stderr.
import path from 'node:path';
import readline from 'node:readline';
import { scan, ScanError } from '../scan.js';
import { ConfigError } from '../config.js';
import { ALL_RULES, getRule } from '../rules/index.js';
import { VERSION } from '../version.js';

const SUPPORTED_PROTOCOLS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];

const INSTRUCTIONS = `rattlecheck finds security holes in Supabase projects: tables anyone can read, functions anyone can call with full database powers, and policies that let anyone change every row.

How to use it:
1. Call scan on the project folder before you deploy, and after any migration that creates or changes tables, policies, functions, or grants.
2. For each finding, put its fix SQL into a NEW migration file. Never edit migrations that already ran. Never run SQL against a production database yourself.
3. Call scan again until the grade is A.
4. If a finding is intentional (a public menu, say), ask the user before adding an allow entry with a reason to rattlecheck.config.json. Never allow a finding just to make it go away.
5. Tell the user what was found in plain words, using each finding's "plain" text.`;

const TOOLS = [
  {
    name: 'scan',
    title: 'Scan a Supabase project',
    description:
      'Replays the project\'s supabase/migrations and reports every open door: tables without row-level security, SECURITY DEFINER functions anyone can call, unpinned search paths, triggers that break user writes, and always-true policies. Returns a grade (A to F), each finding in plain English, and the SQL to fix it. Read-only. With live=true it also asks the running project, read-only and only after proving the user owns it, how many rows each table hands to the public key.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Project folder that contains supabase/migrations. Defaults to the current folder.' },
        live: { type: 'boolean', description: 'Also check the running project (read-only). Requires the project URL and keys in the local .env and proof of ownership.', default: false },
      },
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
  },
  {
    name: 'explain_rule',
    title: 'Explain a rattlecheck rule',
    description: 'Explains one rule (for example RC002): what it catches, why it matters, and which security standards it maps to.',
    inputSchema: { type: 'object', properties: { id: { type: 'string', description: 'Rule id, like RC001' } }, required: ['id'], additionalProperties: false },
    annotations: { readOnlyHint: true },
  },
  {
    name: 'list_rules',
    title: 'List rattlecheck rules',
    description: 'Lists every rule rattlecheck checks, with severity.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
    annotations: { readOnlyHint: true },
  },
];

function summarize(report) {
  const lines = [`Grade ${report.grade.letter} (${report.grade.label}). ${report.doors.checked} doors checked, ${report.doors.open} open.`];
  for (const f of report.findings) {
    lines.push('', `[${f.severity.toUpperCase()}] ${f.rule} ${f.name}${f.detail ? ` (${f.detail})` : ''}`, f.plain, `What to do: ${f.todo}`, `Location: ${f.file ?? 'live project'}${f.line ? `:${f.line}` : ''}`, 'Fix SQL (put in a NEW migration):', f.fix);
  }
  if (!report.coverage.ok) lines.push('', 'WARNING: migration files were found but nothing could be parsed. Do not trust this result.');
  for (const w of report.configWarnings) lines.push('', `Config: ${w}`);
  return lines.join('\n');
}

export async function callTool(name, args = {}, { cwd = process.cwd(), env = process.env } = {}) {
  if (name === 'list_rules') {
    const rules = ALL_RULES.map((r) => ({ id: r.id, severity: r.severity, title: r.title, live: Boolean(r.live) }));
    return { content: [{ type: 'text', text: rules.map((r) => `${r.id} ${r.severity} ${r.title}`).join('\n') }], structuredContent: { rules } };
  }
  if (name === 'explain_rule') {
    const r = getRule(args.id);
    if (!r) return { content: [{ type: 'text', text: `No rule called ${args.id}.` }], isError: true };
    const data = { id: r.id, severity: r.severity, title: r.title, summary: r.summary, standards: r.standards };
    return { content: [{ type: 'text', text: `${r.id} ${r.title}\n\n${r.summary}\n\nStandards: ${JSON.stringify(r.standards)}` }], structuredContent: data };
  }
  if (name === 'scan') {
    if (args.path !== undefined && typeof args.path !== 'string') return { content: [{ type: 'text', text: '"path" must be a string.' }], isError: true };
    if (args.live !== undefined && typeof args.live !== 'boolean') return { content: [{ type: 'text', text: '"live" must be true or false.' }], isError: true };
    try {
      const report = await scan({ root: path.resolve(cwd, args.path ?? '.'), live: args.live === true, env });
      return { content: [{ type: 'text', text: summarize(report) }], structuredContent: report };
    } catch (e) {
      const known = e instanceof ScanError || e instanceof ConfigError;
      return { content: [{ type: 'text', text: known ? e.message : `rattlecheck hit an unexpected error: ${e.message}` }], isError: true };
    }
  }
  return null;
}

export async function handleMessage(msg, ctx = {}) {
  if (!msg || typeof msg !== 'object' || Array.isArray(msg)) {
    return { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid request' } };
  }
  const { id, method, params } = msg;
  const reply = (result) => ({ jsonrpc: '2.0', id, result });
  const fail = (code, message) => ({ jsonrpc: '2.0', id, error: { code, message } });

  // A response from the client (to a request we never send) or a notification: no reply.
  if (typeof method !== 'string') {
    if (id !== undefined && ('result' in msg || 'error' in msg)) return null;
    return { jsonrpc: '2.0', id: id ?? null, error: { code: -32600, message: 'Invalid request' } };
  }
  if (id === undefined) return null; // notifications/initialized, notifications/cancelled, ...

  if (method === 'initialize') {
    const asked = params?.protocolVersion;
    return reply({
      protocolVersion: SUPPORTED_PROTOCOLS.includes(asked) ? asked : SUPPORTED_PROTOCOLS[0],
      capabilities: { tools: { listChanged: false } },
      serverInfo: { name: 'rattlecheck', title: 'rattlecheck', version: VERSION },
      instructions: INSTRUCTIONS,
    });
  }
  if (method === 'ping') return reply({});
  if (method === 'tools/list') return reply({ tools: TOOLS });
  if (method === 'tools/call') {
    const result = await callTool(params?.name, params?.arguments ?? {}, ctx);
    if (!result) return fail(-32602, `Unknown tool: ${params?.name}`);
    return reply(result);
  }
  return fail(-32601, `Method not found: ${method}`);
}

export function runMcpServer({ input = process.stdin, output = process.stdout } = {}) {
  const rl = readline.createInterface({ input, crlfDelay: Infinity });
  rl.on('line', async (line) => {
    if (!line.trim()) return;
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      output.write(`${JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } })}\n`);
      return;
    }
    const one = async (m) => {
      try {
        return await handleMessage(m);
      } catch (e) {
        const id = m && typeof m === 'object' && m.id !== undefined ? m.id : null;
        return { jsonrpc: '2.0', id, error: { code: -32603, message: e.message } };
      }
    };
    if (Array.isArray(msg)) {
      // JSON-RPC batch (required by protocol 2025-03-26).
      if (msg.length === 0) {
        output.write(`${JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid request' } })}\n`);
        return;
      }
      const replies = (await Promise.all(msg.map(one))).filter(Boolean);
      if (replies.length) output.write(`${JSON.stringify(replies)}\n`);
      return;
    }
    const res = await one(msg);
    if (res) output.write(`${JSON.stringify(res)}\n`);
  });
  return new Promise((resolve) => rl.on('close', resolve));
}
