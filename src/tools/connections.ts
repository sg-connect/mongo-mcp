import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { describeConnection } from '../mongodb/connections.js';
import { READ_ONLY_ANNOTATIONS, fields, runTool, type ToolContext } from './context.js';

export function registerConnectionTools(server: McpServer, ctx: ToolContext): void {
  server.registerTool(
    'list-connections',
    {
      title: 'List configured connections',
      description:
        'Lists the named MongoDB connections this server is allowed to use, with their allowlisted databases/collections, limits and whether credentials are present. Never returns connection strings.',
      inputSchema: {},
      annotations: READ_ONLY_ANNOTATIONS,
    },
    async () =>
      runTool(ctx, { tool: 'list-connections', operation: 'listConnections', params: {} }, async () => {
        const connections = ctx.registry.all().map((c) => describeConnection(c));
        return { result: { connections }, resultCount: connections.length };
      }),
  );

  server.registerTool(
    'list-databases',
    {
      title: 'List databases',
      description: 'Lists the databases Claude may query on a connection (the configured allowlist, intersected with what actually exists when the user has listDatabases privilege).',
      inputSchema: { connection: fields.connection },
      annotations: READ_ONLY_ANNOTATIONS,
    },
    async ({ connection }) =>
      runTool(ctx, { tool: 'list-databases', operation: 'listDatabases', connection, params: { connection } }, async ({ conn }) => {
        const allowed = [...conn.allowedDatabases].sort();
        try {
          const existing = new Set(await ctx.clients.listDatabaseNames(conn));
          const databases = allowed.filter((d) => existing.has(d));
          const allowedButMissing = allowed.filter((d) => !existing.has(d));
          return { result: { connection: conn.name, databases, allowedButMissing }, resultCount: databases.length };
        } catch (err) {
          // Read-only Atlas users often lack listDatabases; fall back to the allowlist.
          return {
            result: { connection: conn.name, databases: allowed, note: `listDatabases not permitted for this user (${ctx.redactor.error(err)}); showing allowlist.` },
            resultCount: allowed.length,
          };
        }
      }),
  );
}
