/**
 * Builds the shared ToolContext and MCP server instances.
 *
 * Kept free of transport concerns so the same context can back one
 * server, one McpServer per HTTP request (stateless Streamable HTTP), or the
 * in-memory transport used by tests.
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { AuditLogger } from './audit/logger.js';
import { ClientManager } from './mongodb/client.js';
import type { ConnectionRegistry } from './security/allowlist.js';
import { Redactor } from './security/redact.js';
import type { ToolContext } from './tools/context.js';
import { registerAllTools } from './tools/index.js';

export const SERVER_NAME = 'mongo-mcp';
export const SERVER_VERSION = '0.1.0';

export interface CreateContextOptions {
  registry: ConnectionRegistry;
  auditLogPath: string | null;
  echoAuditToStderr?: boolean;
  clients?: ClientManager;
}

export interface MongoMcpContext {
  ctx: ToolContext;
  close(): Promise<void>;
}

/** Shared, long-lived state: registry, driver clients, redactor, audit log. */
export function createContext(opts: CreateContextOptions): MongoMcpContext {
  let audit: AuditLogger | undefined;
  const clients =
    opts.clients ??
    new ClientManager({
      // A command outside READ_COMMANDS means a bug let something other than a read through. Make it loud.
      onUnexpectedCommand: (e) => {
        process.stderr.write(`[mongo-mcp] SECURITY: unexpected command "${e.commandName}" on ${e.connection}/${e.databaseName}\n`);
        audit?.log({
          ts: new Date().toISOString(),
          user: null,
          tool: 'tripwire',
          operation: e.commandName,
          connection: e.connection,
          database: e.databaseName,
          collection: null,
          production: opts.registry.all().find((c) => c.name === e.connection)?.production ?? null,
          params: null,
          durationMs: 0,
          resultCount: null,
          ok: false,
          rejected: false,
          rejectionCode: null,
          rejectionReason: null,
          error: `SECURITY: unexpected command ${e.commandName}`,
          collscanCheck: null,
        });
      },
    });
  const redactor = new Redactor(clients.secretValues(opts.registry.all()));
  audit = new AuditLogger({ filePath: opts.auditLogPath, redactor, echoToStderr: opts.echoAuditToStderr ?? false });
  const ctx: ToolContext = { registry: opts.registry, clients, audit, redactor };
  return { ctx, close: () => clients.closeAll() };
}

/** A fresh McpServer with every tool registered against `ctx`. Cheap; safe to build per request. */
export function buildMcpServer(ctx: ToolContext, user?: string): McpServer {
  const server = new McpServer(
    { name: SERVER_NAME, version: SERVER_VERSION },
    {
      capabilities: { tools: {} },
      instructions: [
        'mongo-mcp gives read-only, allowlisted access to MongoDB. Start with list-connections, then list-collections, collection-schema and collection-indexes.',
        'Every result is bounded (limit ≤ 100, maxTimeMS ≤ connection max). On production connections, queries that would scan a large collection without an index are rejected: use explain first and lead with indexed fields.',
        'Use Extended JSON for ObjectId/Date values: {"$oid": "..."}, {"$date": "..."}. Prefer a projection to keep payloads small.',
        'There are no write tools and no raw command tool. Do not attempt writes.',
      ].join('\n'),
    },
  );
  registerAllTools(server, user === undefined ? ctx : { ...ctx, user });
  return server;
}

export interface MongoMcpServer {
  server: McpServer;
  ctx: ToolContext;
  close(): Promise<void>;
}

/** Convenience for single-server transports (in-memory tests). */
export function createServer(opts: CreateContextOptions): MongoMcpServer {
  const { ctx, close } = createContext(opts);
  const server = buildMcpServer(ctx);
  return {
    server,
    ctx,
    close: async () => {
      await server.close().catch(() => undefined);
      await close();
    },
  };
}
