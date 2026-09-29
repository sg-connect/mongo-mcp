import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { isCollectionAllowed } from '../security/allowlist.js';
import { READ_ONLY_ANNOTATIONS, fields, runTool, type ToolContext } from './context.js';

export function registerCollectionTools(server: McpServer, ctx: ToolContext): void {
  server.registerTool(
    'list-collections',
    {
      title: 'List collections',
      description: 'Lists the collections Claude may query in a database (existing collections intersected with the allowlist), with type and estimated document count.',
      inputSchema: { connection: fields.connection, database: fields.database },
      annotations: READ_ONLY_ANNOTATIONS,
    },
    async ({ connection, database }) =>
      runTool(ctx, { tool: 'list-collections', operation: 'listCollections', connection, database, params: { connection, database } }, async ({ conn }, h) => {
        const db = await h.db();
        const infos = await db.listCollections({}, { nameOnly: false, authorizedCollections: true, maxTimeMS: conn.maxTimeMS }).toArray();
        const visible = infos.filter((c) => isCollectionAllowed(conn, c.name)).sort((a, b) => a.name.localeCompare(b.name));
        const collections = await Promise.all(
          visible.map(async (c) => ({
            name: c.name,
            type: c.type ?? 'collection',
            estimatedDocumentCount: c.type === 'view' ? null : await db.collection(c.name).estimatedDocumentCount({ maxTimeMS: conn.maxTimeMS }).catch(() => null),
          })),
        );
        const existing = new Set(infos.map((c) => c.name));
        const allowedButMissing = conn.allowedCollections === null ? [] : [...conn.allowedCollections].filter((c) => !existing.has(c)).sort();
        return { result: { connection: conn.name, database, collections, allowedButMissing }, resultCount: collections.length };
      }),
  );
}
