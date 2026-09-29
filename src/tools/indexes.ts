import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { READ_ONLY_ANNOTATIONS, fields, runTool, toEJSON, type ToolContext } from './context.js';

export function registerIndexTools(server: McpServer, ctx: ToolContext): void {
  server.registerTool(
    'collection-indexes',
    {
      title: 'Get indexes',
      description: 'Returns the index definitions of a collection. Check this before querying production so filters and sorts can use an index.',
      inputSchema: { connection: fields.connection, database: fields.database, collection: fields.collection },
      annotations: READ_ONLY_ANNOTATIONS,
    },
    async ({ connection, database, collection }) =>
      runTool(
        ctx,
        { tool: 'collection-indexes', operation: 'listIndexes', connection, database, collection, params: { connection, database, collection } },
        async ({ conn }, h) => {
          const coll = await h.coll();
          const indexes = await coll.indexes({ maxTimeMS: conn.maxTimeMS });
          return { result: { connection: conn.name, database, collection, indexes: indexes.map(toEJSON) }, resultCount: indexes.length };
        },
      ),
  );
}
