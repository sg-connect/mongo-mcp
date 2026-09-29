import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Authenticator, FailureLimiter, hashPassword } from '../src/auth.js';
import { startHttpServer, type RunningHttpServer } from '../src/http.js';
import { ConnectionRegistry } from '../src/security/allowlist.js';
import { createContext, type MongoMcpContext } from '../src/server.js';
import { EXPOSED_TOOLS } from '../src/tools/index.js';
import { conn } from './helpers.js';

const PASSWORD = 'correct horse battery staple';
const auth = new Authenticator({ alice: hashPassword(PASSWORD) });
const basic = (user: string, pass: string): string => `Basic ${Buffer.from(`${user}:${pass}`).toString('base64')}`;
const GOOD = basic('alice', PASSWORD);

describe('Streamable HTTP transport', () => {
  let app: MongoMcpContext;
  let running: RunningHttpServer;

  beforeAll(async () => {
    app = createContext({ registry: new ConnectionRegistry([conn('shop-prod'), conn('shop-stage')]), auditLogPath: null });
    running = await startHttpServer({ ctx: app.ctx, port: 0, auth, log: () => undefined });
  });

  afterAll(async () => {
    await running?.close();
    await app?.close();
  });

  const connect = async (headers: Record<string, string>): Promise<Client> => {
    const client = new Client({ name: 'http-test', version: '0' });
    await client.connect(new StreamableHTTPClientTransport(new URL(running.url), { requestInit: { headers } }));
    return client;
  };

  it('refuses to start without any user accounts', async () => {
    await expect(startHttpServer({ ctx: app.ctx, port: 0, auth: new Authenticator({}), log: () => undefined })).rejects.toThrow(/user account/);
  });

  it('serves an unauthenticated health check that reveals nothing', async () => {
    const res = await fetch(running.url.replace('/mcp', '/healthz'));
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('{"ok":true}');
  });

  it('returns 404 for unknown paths', async () => {
    const res = await fetch(running.url.replace('/mcp', '/admin'), { method: 'POST' });
    expect(res.status).toBe(404);
  });

  it('rejects missing and wrong credentials with 401', async () => {
    const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
    const headers = { 'content-type': 'application/json', accept: 'application/json, text/event-stream' };
    const none = await fetch(running.url, { method: 'POST', headers, body });
    expect(none.status).toBe(401);
    expect(none.headers.get('www-authenticate')).toMatch(/^Basic realm="mongo-mcp"/);
    for (const authorization of [basic('alice', 'wrong password here'), basic('nobody', PASSWORD), `Bearer ${'0'.repeat(64)}`]) {
      const res = await fetch(running.url, { method: 'POST', headers: { ...headers, authorization }, body });
      expect(res.status).toBe(401);
    }
    await expect(connect({})).rejects.toThrow();
  });

  it('locks an IP out after repeated failed logins', async () => {
    const strict = await startHttpServer({ ctx: app.ctx, port: 0, auth, limiter: new FailureLimiter(3), log: () => undefined });
    try {
      const post = (authorization: string): Promise<Response> =>
        fetch(strict.url, {
          method: 'POST',
          headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', authorization },
          body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
        });
      for (let i = 0; i < 3; i++) expect((await post(basic('alice', `guess number ${i}`))).status).toBe(401);
      const locked = await post(GOOD);
      expect(locked.status).toBe(429);
      expect(Number(locked.headers.get('retry-after'))).toBeGreaterThan(0);
    } finally {
      await strict.close();
    }
  });

  it('behind a proxy, refuses requests that did not arrive over HTTPS', async () => {
    const proxied = await startHttpServer({ ctx: app.ctx, port: 0, auth, trustProxy: true, log: () => undefined });
    try {
      const post = (proto: string | undefined): Promise<Response> =>
        fetch(proxied.url, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            accept: 'application/json, text/event-stream',
            authorization: GOOD,
            'x-forwarded-for': '203.0.113.7',
            ...(proto ? { 'x-forwarded-proto': proto } : {}),
          },
          body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
        });
      expect((await post(undefined)).status).toBe(403);
      expect((await post('http')).status).toBe(403);
      expect((await post('https')).status).toBe(200);
    } finally {
      await proxied.close();
    }
  });

  it('rejects browser-originated requests (Origin header) even with a valid token', async () => {
    const res = await fetch(running.url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', authorization: GOOD, origin: 'https://evil.example' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    });
    expect(res.status).toBe(403);
  });

  it('rejects requests whose Host header is not allowlisted (DNS rebinding)', async () => {
    const strict = await startHttpServer({ ctx: app.ctx, port: 0, auth, allowedHosts: ['mongo-mcp.internal:1'], log: () => undefined });
    try {
      const res = await fetch(strict.url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', authorization: GOOD },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
      });
      expect(res.status).toBe(403);
    } finally {
      await strict.close();
    }
  });

  it('rejects oversized bodies', async () => {
    const res = await fetch(running.url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', authorization: GOOD },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: { pad: 'x'.repeat(1024 * 1024 + 10) } }),
    });
    expect(res.status).toBe(413);
  });

  it('serves the full MCP tool surface to an authenticated client', async () => {
    const client = await connect({ authorization: GOOD });
    try {
      const { tools } = await client.listTools();
      expect(tools.map((t) => t.name).sort()).toEqual([...EXPOSED_TOOLS].sort());
      const res = (await client.callTool({ name: 'list-connections', arguments: {} })) as { content: { type: string; text?: string }[] };
      const text = res.content[0]?.text ?? '';
      expect(text).toContain('"shop-prod"');
      expect(text).not.toContain('mongodb');
      const rejected = (await client.callTool({ name: 'find', arguments: { connection: 'nope', database: 'x', collection: 'y' } })) as { isError?: boolean; content: { text?: string }[] };
      expect(rejected.isError).toBe(true);
      expect(rejected.content[0]?.text).toContain('CONNECTION_NOT_ALLOWED');
    } finally {
      await client.close();
    }
  });

  it('handles concurrent clients independently (stateless)', async () => {
    const clients = await Promise.all([1, 2, 3].map(() => connect({ authorization: GOOD })));
    try {
      const results = await Promise.all(clients.map((c) => c.listTools()));
      for (const r of results) expect(r.tools).toHaveLength(EXPOSED_TOOLS.length);
    } finally {
      await Promise.all(clients.map((c) => c.close()));
    }
  });
});
