import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { Document } from 'mongodb';
import { z } from 'zod';
import { guardCollscan } from '../mongodb/inspect.js';
import { inferSchema } from '../mongodb/schema.js';
import { effectiveLimits } from '../security/query-policy.js';
import { validateFilter } from '../security/validator.js';
import { READ_ONLY_ANNOTATIONS, fields, fromEJSON, runTool, type ToolContext } from './context.js';

const scale = z.enum(['bytes', 'KB', 'MB', 'GB']).optional().describe('Unit for sizes. Default MB.');
const SCALE = { bytes: 1, KB: 1024, MB: 1024 ** 2, GB: 1024 ** 3 } as const;
const scaled = (bytes: unknown, unit: keyof typeof SCALE): number | null =>
  typeof bytes === 'number' ? Math.round((bytes / SCALE[unit]) * 100) / 100 : null;

export function registerStatsTools(server: McpServer, ctx: ToolContext): void {
  server.registerTool(
    'collection-schema',
    {
      title: 'Describe collection schema',
      description:
        'Infers a collection\'s shape from a random sample: every field path with its BSON types and how often it appears. Returns no field values. Default sample 50, max 100; optional filter narrows the population first (subject to the COLLSCAN guard on production).',
      inputSchema: {
        connection: fields.connection,
        database: fields.database,
        collection: fields.collection,
        sampleSize: z.number().int().positive().optional().describe('Documents to sample. Default 50, max 100.'),
        filter: fields.filter,
        maxTimeMS: fields.maxTimeMS,
      },
      annotations: READ_ONLY_ANNOTATIONS,
    },
    async (args) =>
      runTool(ctx, { tool: 'collection-schema', operation: 'sample', connection: args.connection, database: args.database, collection: args.collection, params: args }, async ({ conn }, h) => {
        const filter = fromEJSON<Document>(validateFilter(args.filter));
        const { limit: size, maxTimeMS, notes } = effectiveLimits(conn, { limit: args.sampleSize ?? 50, maxTimeMS: args.maxTimeMS });
        const pipeline: Document[] = [];
        if (Object.keys(filter).length) pipeline.push({ $match: filter });
        pipeline.push({ $sample: { size } });
        const coll = await h.coll();

        const collscanCheck = await guardCollscan(conn, coll, { kind: 'aggregate', pipeline }, maxTimeMS);

        // promoteValues: false keeps Int32/Double/Long distinguishable for type reporting.
        const docs = await coll.aggregate(pipeline, { maxTimeMS, allowDiskUse: false, promoteValues: false }).toArray();
        const { fields: schema, truncated } = inferSchema(docs);
        return {
          result: {
            connection: conn.name,
            database: args.database,
            collection: args.collection,
            sampled: docs.length,
            fieldCount: schema.length,
            truncated,
            notes: notes.length ? notes : undefined,
            fields: schema,
          },
          resultCount: schema.length,
          collscanCheck,
        };
      }),
  );

  server.registerTool(
    'collection-storage-size',
    {
      title: 'Collection storage size',
      description: 'Returns the collection\'s document count, data size, storage size on disk and index sizes (from $collStats). Reads metadata only.',
      inputSchema: { connection: fields.connection, database: fields.database, collection: fields.collection, scale },
      annotations: READ_ONLY_ANNOTATIONS,
    },
    async (args) =>
      runTool(ctx, { tool: 'collection-storage-size', operation: 'collStats', connection: args.connection, database: args.database, collection: args.collection, params: args }, async ({ conn }, h) => {
        const unit = args.scale ?? 'MB';
        const coll = await h.coll();
        // One document per shard on a sharded cluster; summed below.
        const rows = await coll.aggregate([{ $collStats: { storageStats: {} } }], { maxTimeMS: conn.maxTimeMS }).toArray();
        const sum = (key: string): number => rows.reduce((n, r) => n + (Number((r.storageStats as Document | undefined)?.[key]) || 0), 0);
        const indexSizes: Record<string, number> = {};
        for (const r of rows) {
          for (const [name, bytes] of Object.entries(((r.storageStats as Document | undefined)?.indexSizes ?? {}) as Record<string, number>)) {
            indexSizes[name] = (indexSizes[name] ?? 0) + Number(bytes);
          }
        }
        const count = sum('count');
        return {
          result: {
            connection: conn.name,
            database: args.database,
            collection: args.collection,
            unit,
            count,
            size: scaled(sum('size'), unit),
            storageSize: scaled(sum('storageSize'), unit),
            totalIndexSize: scaled(sum('totalIndexSize'), unit),
            totalSize: scaled(sum('totalSize') || sum('storageSize') + sum('totalIndexSize'), unit),
            avgObjSizeBytes: count ? Math.round(sum('size') / count) : 0,
            indexSizes: Object.fromEntries(Object.entries(indexSizes).map(([k, v]) => [k, scaled(v, unit)])),
            shards: rows.length > 1 ? rows.map((r) => r.shard).filter(Boolean) : undefined,
          },
          resultCount: 1,
        };
      }),
  );

  server.registerTool(
    'db-stats',
    {
      title: 'Database statistics',
      description:
        'Returns statistics for an allowlisted database: number of collections, views, objects and indexes, and data/storage/index sizes. Totals cover the whole database, including collections that are not on the allowlist (numbers only, no names).',
      inputSchema: { connection: fields.connection, database: fields.database, scale },
      annotations: READ_ONLY_ANNOTATIONS,
    },
    async (args) =>
      runTool(ctx, { tool: 'db-stats', operation: 'dbStats', connection: args.connection, database: args.database, params: args }, async ({ conn }, h) => {
        const unit = args.scale ?? 'MB';
        const db = await h.db();
        const stats = await db.stats(conn.maxTimeMS);
        return {
          result: {
            connection: conn.name,
            database: args.database,
            unit,
            collections: stats.collections,
            views: stats.views,
            objects: stats.objects,
            indexes: stats.indexes,
            avgObjSizeBytes: Math.round(Number(stats.avgObjSize) || 0),
            dataSize: scaled(stats.dataSize, unit),
            storageSize: scaled(stats.storageSize, unit),
            indexSize: scaled(stats.indexSize, unit),
            totalSize: scaled(stats.totalSize ?? Number(stats.storageSize) + Number(stats.indexSize), unit),
            // raw is keyed by shard host; report only how many there are.
            ...(stats.raw ? { shards: Object.keys(stats.raw as Document).length } : {}),
          },
          resultCount: 1,
        };
      }),
  );
}
