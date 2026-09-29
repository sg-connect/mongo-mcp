import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { Document } from 'mongodb';
import { z } from 'zod';
import { explainTarget, type CollscanTarget } from '../mongodb/inspect.js';
import { collectPlanStages, hasCollscan, indexesUsed } from '../security/collscan.js';
import { effectiveLimits } from '../security/query-policy.js';
import { validateFilter, validateHint, validatePipeline, validateSort } from '../security/validator.js';
import { ValidationError } from '../types.js';
import { READ_ONLY_ANNOTATIONS, fields, fromEJSON, runTool, toEJSON, type ToolContext } from './context.js';

export function registerExplainTool(server: McpServer, ctx: ToolContext): void {
  server.registerTool(
    'explain',
    {
      title: 'Explain a query plan',
      description:
        'Returns the query plan for a find, count or aggregate WITHOUT running it (verbosity "queryPlanner", default). "executionStats" does execute the operation under the time limit and reports docs examined. Use this to check for COLLSCAN before querying production.',
      inputSchema: {
        connection: fields.connection,
        database: fields.database,
        collection: fields.collection,
        operation: z.enum(['find', 'count', 'aggregate']),
        filter: fields.filter,
        sort: fields.sort,
        hint: fields.hint,
        limit: fields.limit,
        pipeline: z.array(z.record(z.string(), z.unknown())).optional().describe('For aggregate: the pipeline.'),
        verbosity: z.enum(['queryPlanner', 'executionStats']).optional().describe('Default queryPlanner (does not execute).'),
        maxTimeMS: fields.maxTimeMS,
      },
      annotations: READ_ONLY_ANNOTATIONS,
    },
    async (args) =>
      runTool(ctx, { tool: 'explain', operation: 'explain', connection: args.connection, database: args.database, collection: args.collection, params: args }, async ({ conn }, h) => {
        const { limit, maxTimeMS } = effectiveLimits(conn, { limit: args.limit, maxTimeMS: args.maxTimeMS });
        const verbosity = args.verbosity ?? 'queryPlanner';

        let target: CollscanTarget;
        switch (args.operation) {
          case 'find':
            target = { kind: 'find', filter: fromEJSON(validateFilter(args.filter)), sort: validateSort(args.sort), hint: validateHint(args.hint), limit, skip: 0 };
            break;
          case 'count':
            target = { kind: 'count', filter: fromEJSON(validateFilter(args.filter)) };
            break;
          case 'aggregate':
            if (!args.pipeline) throw new ValidationError('INVALID_INPUT', 'pipeline is required for operation "aggregate".');
            target = { kind: 'aggregate', pipeline: [...fromEJSON<Document[]>(validatePipeline(args.pipeline, conn)), { $limit: limit }] };
            break;
        }

        const coll = await h.coll();
        const explain = await explainTarget(coll, target, maxTimeMS, verbosity);
        const stages = collectPlanStages(explain);
        const collscan = hasCollscan(explain);

        // Trim noisy, host-revealing sections; keep what matters for tuning.
        const { serverInfo: _s, serverParameters: _p, command: _c, ok: _ok, $clusterTime: _ct, operationTime: _ot, ...rest } = explain as Record<string, unknown>;
        return {
          result: {
            connection: conn.name,
            database: args.database,
            collection: args.collection,
            operation: args.operation,
            verbosity,
            summary: {
              collscan,
              wouldBeRejectedOnThisConnection: collscan && conn.rejectCollscan,
              planStages: stages,
              indexesUsed: indexesUsed(explain),
            },
            explain: toEJSON(rest),
          },
          resultCount: 1,
          collscanCheck: { performed: true, collscan, stages },
        };
      }),
  );
}
