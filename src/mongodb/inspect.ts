/**
 * COLLSCAN guard: runs a queryPlanner-level explain() before a potentially
 * expensive operation on connections with `rejectCollscan` enabled, and
 * refuses the operation when the winning plan scans the whole collection and
 * the collection is larger than `collscanMaxDocs`.
 *
 * queryPlanner explains do not execute the query, so this pre-flight is cheap.
 */
import type { Document } from 'mongodb';
import type { ReadCollection } from './readonly.js';
import { collectPlanStages, hasCollscan, indexesUsed } from '../security/collscan.js';
import { ValidationError, type CollscanCheck, type JsonDocument, type ResolvedConnection } from '../types.js';

export type CollscanTarget =
  | { kind: 'find'; filter: JsonDocument; sort?: JsonDocument | undefined; hint?: string | JsonDocument | undefined; limit: number; skip: number }
  | { kind: 'aggregate'; pipeline: JsonDocument[] }
  | { kind: 'count'; filter: JsonDocument };

const isEmpty = (doc: JsonDocument | undefined): boolean => !doc || Object.keys(doc).length === 0;

/** Build the explain() promise for a target without executing the underlying query. */
export function explainTarget(coll: ReadCollection, target: CollscanTarget, maxTimeMS: number, verbosity: 'queryPlanner' | 'executionStats' = 'queryPlanner'): Promise<Document> {
  switch (target.kind) {
    case 'find':
      return coll
        .find(target.filter, { sort: target.sort as Document | undefined, hint: target.hint as Document | string | undefined, limit: target.limit, skip: target.skip, maxTimeMS })
        .explain(verbosity);
    case 'aggregate':
      return coll.aggregate(target.pipeline, { maxTimeMS }).explain(verbosity);
    case 'count':
      return coll.aggregate([{ $match: target.filter }, { $group: { _id: 1, n: { $sum: 1 } } }], { maxTimeMS }).explain(verbosity);
  }
}

/** Decide whether an explain pre-flight is even worth it. Bounded, filter-less finds stop after `limit` docs. */
function skipReason(conn: ResolvedConnection, target: CollscanTarget): string | undefined {
  if (!conn.rejectCollscan) return 'rejectCollscan disabled for this connection';
  if (target.kind === 'find' && isEmpty(target.filter) && isEmpty(target.sort) && target.skip === 0) return 'unfiltered, unsorted find is bounded by limit';
  return undefined;
}

/**
 * Throws COLLSCAN_REJECTED when the operation would scan a large collection without an index.
 * Returns the check result for the audit log otherwise.
 */
export async function guardCollscan(conn: ResolvedConnection, coll: ReadCollection, target: CollscanTarget, maxTimeMS: number): Promise<CollscanCheck> {
  const skipped = skipReason(conn, target);
  if (skipped) return { performed: false, skipped };

  const explain = await explainTarget(coll, target, maxTimeMS);
  const stages = collectPlanStages(explain);
  const collscan = hasCollscan(explain);
  if (!collscan) return { performed: true, collscan: false, stages };

  const estimatedDocs = await coll.estimatedDocumentCount({ maxTimeMS });
  if (estimatedDocs <= conn.collscanMaxDocs) return { performed: true, collscan: true, stages, estimatedDocs };

  const indexes = await coll.indexes({ maxTimeMS }).catch(() => [] as Document[]);
  const indexDesc = indexes.map((ix) => `${ix.name}: ${JSON.stringify(ix.key)}`).join('; ') || '(could not list indexes)';
  const used = indexesUsed(explain);

  throw new ValidationError(
    'COLLSCAN_REJECTED',
    `Rejected: this ${target.kind} would perform a full collection scan (COLLSCAN) on "${coll.dbName}.${coll.collectionName}" ` +
      `(~${estimatedDocs.toLocaleString('en-US')} documents; production limit is ${conn.collscanMaxDocs.toLocaleString('en-US')}). ` +
      `Plan stages: ${stages.join(', ')}${used.length ? `; indexes used: ${used.join(', ')}` : ''}. ` +
      `Available indexes — ${indexDesc}. ` +
      `Rewrite the query so its filter/sort leads with an indexed field, add a narrower filter (e.g. on _id or an indexed date range), or use the "explain" tool to inspect the plan.`,
  );
}
