import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { Document } from 'mongodb';
import { guardCollscan } from '../mongodb/inspect.js';
import { effectiveLimits } from '../security/query-policy.js';
import { validateFilter, validateHint, validateProjection, validateSort } from '../security/validator.js';
import { READ_ONLY_ANNOTATIONS, fields, fromEJSON, runTool, shapeDocuments, type ToolContext } from './context.js';

export function registerFindTools(server: McpServer, ctx: ToolContext): void {
  server.registerTool(
    'find',
    {
      title: 'Find documents',
      description:
        'Runs a bounded read-only find. Results are capped (default 20, max 100) and time-limited. On production connections a queryPlanner explain runs first and full collection scans on large collections are rejected.',
      inputSchema: {
        connection: fields.connection,
        database: fields.database,
        collection: fields.collection,
        filter: fields.filter,
        projection: fields.projection,
        sort: fields.sort,
        limit: fields.limit,
        skip: fields.skip,
        maxTimeMS: fields.maxTimeMS,
        hint: fields.hint,
      },
      annotations: READ_ONLY_ANNOTATIONS,
    },
    async (args) =>
      runTool(ctx, { tool: 'find', operation: 'find', connection: args.connection, database: args.database, collection: args.collection, params: args }, async ({ conn }, h) => {
        const filter = fromEJSON<Document>(validateFilter(args.filter));
        const projection = fromEJSON<Document | undefined>(validateProjection(args.projection));
        const sort = validateSort(args.sort) as Document | undefined;
        const hint = validateHint(args.hint);
        const { limit, skip, maxTimeMS, notes } = effectiveLimits(conn, args);

        const coll = await h.coll();
        const collscanCheck = await guardCollscan(conn, coll, { kind: 'find', filter, sort, hint, limit, skip }, maxTimeMS);

        const docs = await coll.find(filter, { projection, sort, limit, skip, maxTimeMS, hint, batchSize: limit }).toArray();
        const shaped = shapeDocuments(docs);
        return {
          result: {
            connection: conn.name,
            database: args.database,
            collection: args.collection,
            returned: shaped.returned,
            limit,
            skip,
            hasMore: docs.length === limit,
            truncatedForSize: shaped.truncated,
            notes: notes.length ? notes : undefined,
            documents: shaped.documents,
          },
          resultCount: shaped.returned,
          collscanCheck,
        };
      }),
  );

}
