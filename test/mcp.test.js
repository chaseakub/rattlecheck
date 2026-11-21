import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan } from '../src/scan.js';

const BIN = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'rattlecheck.js');

function project(sql) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rattlecheck-mcp-'));
  fs.mkdirSync(path.join(root, 'supabase', 'migrations'), { recursive: true });
  fs.writeFileSync(path.join(root, 'supabase', 'migrations', '0001.sql'), sql);
  return root;
}

// Talks to the real server process over stdio, the way an agent does.
function session() {
  const child = spawn(process.execPath, [BIN, 'mcp'], { stdio: ['pipe', 'pipe', 'pipe'] });
  let buf = '';
  const waiting = new Map();
  child.stdout.on('data', (d) => {
    buf += d;
    let nl;
    while ((nl = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + 1);
      const msg = JSON.parse(line);
      waiting.get(msg.id)?.(msg);
      waiting.delete(msg.id);
    }
  });
  let next = 1;
  return {
    request(method, params) {
      const id = next++;
      child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
      return new Promise((resolve) => waiting.set(id, resolve));
    },
    notify(method) {
      child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method })}\n`);
    },
    close() {
      child.stdin.end();
      return new Promise((r) => child.on('close', r));
    },
  };
}

test('MCP: initialize, list tools, scan matches the CLI report', async () => {
  const root = project(`create table public.customers (id uuid, email text);`);
  const s = session();
  try {
    const init = await s.request('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '0' } });
    assert.equal(init.result.protocolVersion, '2025-06-18');
    assert.equal(init.result.serverInfo.name, 'rattlecheck');
    assert.match(init.result.instructions, /NEW migration/);
    s.notify('notifications/initialized');

    const list = await s.request('tools/list', {});
    assert.deepEqual(list.result.tools.map((t) => t.name).sort(), ['explain_rule', 'list_rules', 'scan']);

    const res = await s.request('tools/call', { name: 'scan', arguments: { path: root } });
    assert.equal(res.result.isError, undefined);
    const viaMcp = res.result.structuredContent;
    const direct = await scan({ root, env: {} });
    assert.equal(viaMcp.grade.letter, direct.grade.letter);
    assert.deepEqual(viaMcp.findings.map((f) => f.object), direct.findings.map((f) => f.object));
    assert.match(res.result.content[0].text, /Grade F/);
    assert.match(res.result.content[0].text, /Fix SQL/);

    const unknownTool = await s.request('tools/call', { name: 'nope', arguments: {} });
    assert.equal(unknownTool.error.code, -32602);
    const unknownMethod = await s.request('resources/list', {});
    assert.equal(unknownMethod.error.code, -32601);
    const ping = await s.request('ping', {});
    assert.deepEqual(ping.result, {});
  } finally {
    await s.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('MCP: unsupported protocol version gets the newest supported one', async () => {
  const s = session();
  try {
    const init = await s.request('initialize', { protocolVersion: '1999-01-01', capabilities: {} });
    assert.equal(init.result.protocolVersion, '2025-11-25');
  } finally {
    await s.close();
  }
});

test('MCP: scan on a folder without migrations is a tool error, not a crash', async () => {
  const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'rattlecheck-mcp-empty-'));
  const s = session();
  try {
    const res = await s.request('tools/call', { name: 'scan', arguments: { path: empty } });
    assert.equal(res.result.isError, true);
    assert.match(res.result.content[0].text, /No Supabase migrations found/);
  } finally {
    await s.close();
    fs.rmSync(empty, { recursive: true, force: true });
  }
});

test('MCP: a batch gets one array reply, and notifications inside it get none', async () => {
  const child = spawn(process.execPath, [BIN, 'mcp'], { stdio: ['pipe', 'pipe', 'pipe'] });
  const line = new Promise((resolve) => {
    let buf = '';
    child.stdout.on('data', (d) => {
      buf += d;
      const nl = buf.indexOf('\n');
      if (nl !== -1) resolve(buf.slice(0, nl));
    });
  });
  child.stdin.write(`${JSON.stringify([
    { jsonrpc: '2.0', id: 1, method: 'ping' },
    { jsonrpc: '2.0', method: 'notifications/initialized' },
    { jsonrpc: '2.0', id: 2, method: 'tools/list' },
  ])}\n`);
  const reply = JSON.parse(await line);
  child.stdin.end();
  await new Promise((r) => child.on('close', r));
  assert.ok(Array.isArray(reply));
  assert.deepEqual(reply.map((m) => m.id).sort(), [1, 2]);
});

test('MCP: a "null" line does not crash the server', async () => {
  const child = spawn(process.execPath, [BIN, 'mcp'], { stdio: ['pipe', 'pipe', 'pipe'] });
  const line = new Promise((resolve) => {
    let buf = '';
    child.stdout.on('data', (d) => {
      buf += d;
      const nl = buf.indexOf('\n');
      if (nl !== -1) resolve(buf.slice(0, nl));
    });
  });
  child.stdin.write('null\n');
  const reply = JSON.parse(await line);
  child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'ping' })}\n`);
  child.stdin.end();
  const code = await new Promise((r) => child.on('close', r));
  assert.equal(reply.error.code, -32600);
  assert.equal(code, 0);
});
