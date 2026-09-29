import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { Document } from 'mongodb';
import { guardCollscan } from '../mongodb/inspect.js';
import { effectiveLimits } from '../security/query-policy.js';
import { validateFilter } from '../security/validator.js';
import { READ_ONLY_ANNOTATIONS, fields, fromEJSON, runTool, type ToolContext } from './context.js';

export function registerCountTools(server: McpServer, ctx: ToolContext): void {
  server.registerTool(
    'count',
    {
      title: 'Count documents',
      description:
        'Counts documents matching a filter. With an empty filter the count comes from collection metadata (estimated, instant). With a filter it is exact and subject to the COLLSCAN guard on production.',
      inputSchema: {
        connection: fields.connection,
        database: fields.database,
        collection: fields.collection,
        filter: fields.filter,
        maxTimeMS: fields.maxTimeMS,
        hint: fields.hint,
      },
      annotations: READ_ONLY_ANNOTATIONS,
    },
    async (args) =>
      runTool(ctx, { tool: 'count', operation: 'count', connection: args.connection, database: args.database, collection: args.collection, params: args }, async ({ conn }, h) => {
        const filter = fromEJSON<Document>(validateFilter(args.filter));
        const { maxTimeMS, notes } = effectiveLimits(conn, { maxTimeMS: args.maxTimeMS });
        const coll = await h.coll();

        if (Object.keys(filter).length === 0) {
          const count = await coll.estimatedDocumentCount({ maxTimeMS });
          return { result: { connection: conn.name, database: args.database, collection: args.collection, count, estimated: true, notes: notes.length ? notes : undefined }, resultCount: 1 };
        }

        const collscanCheck = await guardCollscan(conn, coll, { kind: 'count', filter }, maxTimeMS);
        const count = await coll.countDocuments(filter, { maxTimeMS, hint: args.hint as string | Document | undefined });
        return {
          result: { connection: conn.name, database: args.database, collection: args.collection, count, estimated: false, notes: notes.length ? notes : undefined },
          resultCount: 1,
          collscanCheck,
        };
      }),
  );

}
