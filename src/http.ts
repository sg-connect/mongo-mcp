/**
 * Streamable HTTP transport: the only way to reach mongo-mcp. Claude gets a
 * URL plus a username and password; the MongoDB connection strings stay in
 * this process's environment and are never sent to the client.
 *
 * Request gates, in order:
 *   1. path      — only POST/GET/DELETE /mcp and GET /healthz exist
 *   2. HTTPS     — when behind a TLS proxy, plain-HTTP requests are refused
 *   3. Host      — must be on the allowlist (defeats DNS rebinding)
 *   4. Origin    — browsers send it; refused unless explicitly allowed
 *   5. lockout   — an IP with too many failed logins gets 429
 *   6. auth      — `Authorization: Basic`, checked against scrypt hashes
 *   7. body size — ≤ 1 MiB
 *
 * Stateless mode: each request gets a fresh McpServer bound to the shared
 * ToolContext and the authenticated username, so there is no session table to
 * leak or hijack.
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { Authenticator, FailureLimiter } from './auth.js';
import { buildMcpServer } from './server.js';
import type { ToolContext } from './tools/context.js';

export const DEFAULT_HTTP_PORT = 8765;
export const DEFAULT_HTTP_HOST = '127.0.0.1';
export const MCP_PATH = '/mcp';
const MAX_BODY_BYTES = 1024 * 1024;

export interface HttpServerOptions {
  ctx: ToolContext;
  host?: string;
  port?: number;
  /** Accounts allowed to call the server. Required. */
  auth: Authenticator;
  /** Accepted values of the HTTP Host header (host[:port]). Defaults to 127.0.0.1:<port> and localhost:<port>. */
  allowedHosts?: string[];
  /** Accepted Origin header values. Default: none (any Origin header is refused). */
  allowedOrigins?: string[];
  /**
   * Set when a reverse proxy (Caddy) terminates TLS in front of this server:
   * the client IP is taken from the last X-Forwarded-For hop, and requests the
   * proxy did not receive over HTTPS (X-Forwarded-Proto) are refused.
   */
  trustProxy?: boolean;
  limiter?: FailureLimiter;
  log?: (msg: string) => void;
}

export interface RunningHttpServer {
  server: http.Server;
  url: string;
  port: number;
  close(): Promise<void>;
}

function deny(res: http.ServerResponse, status: number, message: string, extraHeaders: Record<string, string> = {}): void {
  res.writeHead(status, { 'content-type': 'application/json', ...extraHeaders });
  res.end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32000, message }, id: null }));
}

async function readJsonBody(req: http.IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    size += buf.length;
    if (size > MAX_BODY_BYTES) throw Object.assign(new Error('request body too large'), { status: 413 });
    chunks.push(buf);
  }
  const text = Buffer.concat(chunks).toString('utf8');
  if (!text) return undefined;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw Object.assign(new Error('invalid JSON body'), { status: 400 });
  }
}

const header = (req: http.IncomingMessage, name: string): string | undefined => {
  const v = req.headers[name];
  return Array.isArray(v) ? v[v.length - 1] : v;
};

export async function startHttpServer(opts: HttpServerOptions): Promise<RunningHttpServer> {
  if (!opts.auth || opts.auth.size === 0) throw new Error('HTTP mode requires at least one user account (MONGO_MCP_USERS_FILE).');
  const host = opts.host ?? DEFAULT_HTTP_HOST;
  const requestedPort = opts.port ?? DEFAULT_HTTP_PORT;
  const log = opts.log ?? ((m: string) => process.stderr.write(`[mongo-mcp] ${m}\n`));
  const limiter = opts.limiter ?? new FailureLimiter();
  const allowedOrigins = new Set((opts.allowedOrigins ?? []).map((o) => o.toLowerCase()));
  // Filled after listen() so an ephemeral port (0) still produces a correct default.
  let allowedHosts = new Set<string>();

  const clientIp = (req: http.IncomingMessage): string => {
    if (opts.trustProxy) {
      const hops = header(req, 'x-forwarded-for')?.split(',').map((s) => s.trim()).filter(Boolean);
      if (hops?.length) return hops[hops.length - 1]!;
    }
    return req.socket.remoteAddress ?? 'unknown';
  };

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://placeholder');

    if (req.method === 'GET' && url.pathname === '/healthz') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"ok":true}');
      return;
    }
    if (url.pathname !== MCP_PATH) return deny(res, 404, 'not found');

    const ip = clientIp(req);
    if (opts.trustProxy && header(req, 'x-forwarded-proto')?.toLowerCase() !== 'https') {
      log(`refused non-HTTPS request from ${ip}`);
      return deny(res, 403, 'https required');
    }
    const hostHeader = (req.headers.host ?? '').toLowerCase();
    if (!allowedHosts.has(hostHeader)) {
      log(`refused request with Host "${hostHeader}" from ${ip}`);
      return deny(res, 403, 'forbidden host');
    }
    const origin = req.headers.origin?.toLowerCase();
    if (origin !== undefined && !allowedOrigins.has(origin)) {
      log(`refused request with Origin "${origin}" from ${ip}`);
      return deny(res, 403, 'forbidden origin');
    }
    const locked = limiter.lockedFor(ip);
    if (locked) return deny(res, 429, 'too many failed logins', { 'retry-after': String(locked) });

    const user = opts.auth.verify(req.headers.authorization);
    if (!user) {
      limiter.fail(ip);
      log(`refused unauthenticated request from ${ip}`);
      return deny(res, 401, 'unauthorized', { 'www-authenticate': 'Basic realm="mongo-mcp", charset="UTF-8"' });
    }
    limiter.succeed(ip);

    let body: unknown;
    if (req.method === 'POST') {
      try {
        body = await readJsonBody(req);
      } catch (err) {
        const e = err as Error & { status?: number };
        return deny(res, e.status ?? 400, e.message);
      }
    }

    const mcp = buildMcpServer(opts.ctx, user);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.on('close', () => {
      void transport.close();
      void mcp.close();
    });
    try {
      await mcp.connect(transport);
      await transport.handleRequest(req, res, body);
    } catch (err) {
      log(`request failed: ${opts.ctx.redactor.error(err)}`);
      if (!res.headersSent) deny(res, 500, 'internal error');
      else res.end();
    }
  });

  server.keepAliveTimeout = 65_000;
  server.requestTimeout = 120_000;

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(requestedPort, host, () => resolve());
  });
  const port = (server.address() as AddressInfo).port;
  allowedHosts = new Set((opts.allowedHosts ?? [`127.0.0.1:${port}`, `localhost:${port}`]).map((h) => h.toLowerCase()));

  const url = `http://${host === '0.0.0.0' || host === '::' ? '127.0.0.1' : host}:${port}${MCP_PATH}`;
  return {
    server,
    url,
    port,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections?.();
        server.close(() => resolve());
      }),
  };
}
