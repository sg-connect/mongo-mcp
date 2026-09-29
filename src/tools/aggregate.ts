import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { Document } from 'mongodb';
import { z } from 'zod';
import { guardCollscan } from '../mongodb/inspect.js';
import { effectiveLimits } from '../security/query-policy.js';
import { validatePipeline } from '../security/validator.js';
import { READ_ONLY_ANNOTATIONS, fields, fromEJSON, runTool, shapeDocuments, type ToolContext } from './context.js';

export function registerAggregateTools(server: McpServer, ctx: ToolContext): void {
  server.registerTool(
    'aggregate',
    {
      title: 'Run aggregation pipeline',
      description:
        'Runs a read-only aggregation pipeline. Stages are checked against an allowlist ($out/$merge/$function etc. are refused, $lookup/$unionWith targets must be allowlisted). A trailing $limit (default 20, max 100) is always appended. On production, full collection scans on large collections are rejected.',
      inputSchema: {
        connection: fields.connection,
        database: fields.database,
        collection: fields.collection,
        pipeline: z.array(z.record(z.string(), z.unknown())).describe('Array of stages, e.g. [{"$match": {...}}, {"$group": {...}}]. Extended JSON is accepted.'),
        limit: fields.limit,
        maxTimeMS: fields.maxTimeMS,
      },
      annotations: READ_ONLY_ANNOTATIONS,
    },
    async (args) =>
      runTool(ctx, { tool: 'aggregate', operation: 'aggregate', connection: args.connection, database: args.database, collection: args.collection, params: args }, async ({ conn }, h) => {
        const validated = validatePipeline(args.pipeline, conn);
        const { limit, maxTimeMS, notes } = effectiveLimits(conn, { limit: args.limit, maxTimeMS: args.maxTimeMS });
        const pipeline = [...fromEJSON<Document[]>(validated), { $limit: limit + 1 }];
        const coll = await h.coll();

        const collscanCheck = await guardCollscan(conn, coll, { kind: 'aggregate', pipeline }, maxTimeMS);

        const rows = await coll.aggregate(pipeline, { maxTimeMS, allowDiskUse: false, batchSize: limit + 1 }).toArray();
        const shaped = shapeDocuments(rows.slice(0, limit));
        return {
          result: {
            connection: conn.name,
            database: args.database,
            collection: args.collection,
            returned: shaped.returned,
            limit,
            hasMore: rows.length > limit,
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
