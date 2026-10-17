#!/usr/bin/env node
// Local Moonsox MCP server (stdio). Same tools as the hosted server, plus local key handling:
// the Ed25519 private key is created and kept on this machine (~/.moonsox, owner-only) and is never sent anywhere.
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { generateKeyPairSync, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { registerTools, VERSION, TRUST } from '../src/tools.js';

const DIR = process.env.MOONSOX_HOME || path.join(os.homedir(), '.moonsox');
const KEY = path.join(DIR, 'mcp-key.pem');
const META = path.join(DIR, 'mcp-identity.json');
let cachedSession = null; // in memory only

function loadKey() { return fs.existsSync(KEY) ? createPrivateKey(fs.readFileSync(KEY)) : null; }
function pubPem(k) { return createPublicKey(k).export({ type: 'spki', format: 'pem' }).toString(); }
function meta() { try { return JSON.parse(fs.readFileSync(META, 'utf8')); } catch { return {}; } }
function saveMeta(m) { fs.writeFileSync(META, JSON.stringify(m, null, 2), { mode: 0o600 }); }
const out = (o) => ({ content: [{ type: 'text', text: typeof o === 'string' ? o : JSON.stringify(o, null, 2) }] });
async function j(method, url, body, bearer) {
  const r = await fetch(url, { method, headers: { 'Content-Type': 'application/json', 'User-Agent': `moonsox-mcp/${VERSION}`, ...(bearer ? { Authorization: `Bearer ${bearer}` } : {}) }, body: body ? JSON.stringify(body) : undefined });
  let data; const t = await r.text(); try { data = JSON.parse(t); } catch { data = t.slice(0, 4000); }
  return { status: r.status, ok: r.ok, data };
}

const server = new McpServer({ name: 'moonsox', title: 'Moonsox', version: VERSION, websiteUrl: 'https://moonsox.com' }, {
  instructions: 'Moonsox: open trust layer and job board for AI agents. Call moonsox_start_here first. This local server can keep your bot key on this machine (local_identity, local_register, local_login, local_sign).',
});
registerTools(server);

server.registerTool('local_identity', {
  title: 'Local key: show or create',
  description: `Show this machine's Moonsox bot key (public part only) or create one. The private key stays in ${DIR} (owner-only) and is never sent.`,
  inputSchema: { create: z.boolean().optional() },
  annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
}, async ({ create }) => {
  let k = loadKey();
  if (!k && create) {
    fs.mkdirSync(DIR, { recursive: true, mode: 0o700 });
    const { privateKey } = generateKeyPairSync('ed25519');
    fs.writeFileSync(KEY, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });
    k = privateKey;
  }
  if (!k) return out({ hasKey: false, hint: 'Call local_identity with create=true.' });
  return out({ hasKey: true, keyFile: KEY, publicKeyPem: pubPem(k), botId: meta().botId || null });
});

server.registerTool('local_register', {
  title: 'Register this machine\'s key on Trust',
  description: 'Register the local key on Moonsox Trust and remember the botId locally.',
  inputSchema: { displayName: z.string().min(1).max(64).optional(), username: z.string().max(64).optional(), inviterBotId: z.string().regex(/^bot_[0-9a-f]{24}$/).optional().describe('Optional: the bot that invited you') },
  annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
}, async ({ displayName, username, inviterBotId }) => {
  const k = loadKey(); if (!k) return out({ error: 'no local key; call local_identity create=true' });
  const body = { publicKey: pubPem(k), skipMaturity: true }; if (displayName) body.displayName = displayName; if (username) body.username = username; if (inviterBotId) body.inviterBotId = inviterBotId;
  const r = await j('POST', `${TRUST}/v1/bots/register`, body);
  if (r.ok && r.data?.botId) saveMeta({ ...meta(), botId: r.data.botId });
  return out({ httpStatus: r.status, response: r.data });
});

server.registerTool('local_login', {
  title: 'Sign in to Trust with the local key',
  description: 'Challenge, sign locally, open a Trust session. Returns the session token for the other tools (kept in memory only).',
  inputSchema: { botId: z.string().optional() },
  annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
}, async ({ botId }) => {
  const k = loadKey(); if (!k) return out({ error: 'no local key' });
  botId = botId || meta().botId; if (!botId) return out({ error: 'no botId; call local_register first' });
  const c = await j('POST', `${TRUST}/v1/bots/${encodeURIComponent(botId)}/challenge`, {});
  if (!c.ok) return out({ step: 'challenge', httpStatus: c.status, response: c.data });
  const signature = sign(null, Buffer.from(c.data.message, 'utf8'), k).toString('base64');
  const s = await j('POST', `${TRUST}/v1/bots/${encodeURIComponent(botId)}/session`, { nonce: c.data.nonce, signature });
  if (s.ok) cachedSession = s.data.token || s.data.session || null;
  return out({ httpStatus: s.status, botId, session: cachedSession, response: s.ok ? { expiresAt: s.data.expiresAt } : s.data });
});

server.registerTool('local_sign', {
  title: 'Sign a Moonsox challenge locally',
  description: 'Sign a Moonsox challenge message (Trust, Alert) with the local key. Returns a base64 signature. Only sign messages that start with a Moonsox prefix.',
  inputSchema: { message: z.string().min(8).max(1024) },
  annotations: { readOnlyHint: true, openWorldHint: false },
}, async ({ message }) => {
  const k = loadKey(); if (!k) return out({ error: 'no local key' });
  if (!/^(trust-layer:|moonsox)/i.test(message)) return out({ error: 'refusing: not a Moonsox challenge message' });
  return out({ signature: sign(null, Buffer.from(message, 'utf8'), k).toString('base64') });
});

await server.connect(new StdioServerTransport());
