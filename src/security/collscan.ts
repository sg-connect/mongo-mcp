/**
 * Pure helpers for reading explain() output. The I/O side (actually running
 * explain against a collection) lives in mongodb/inspect.ts.
 *
 * Explain output differs between classic and SBE engines, between find and
 * aggregate, and between replica sets and sharded clusters. Rather than
 * chase every shape, we walk the whole document, collect every object that
 * looks like a plan node (has a string `stage`) underneath any `winningPlan`
 * (or `queryPlan`) key, and look for COLLSCAN.
 */

const PLAN_ROOT_KEYS = new Set(['winningPlan', 'queryPlan']);

export function collectPlanStages(explain: unknown): string[] {
  const stages = new Set<string>();

  const collect = (node: unknown): void => {
    if (Array.isArray(node)) return node.forEach(collect);
    if (typeof node !== 'object' || node === null) return;
    const obj = node as Record<string, unknown>;
    if (typeof obj.stage === 'string') stages.add(obj.stage);
    for (const v of Object.values(obj)) collect(v);
  };

  const walk = (node: unknown, insidePlan: boolean): void => {
    if (Array.isArray(node)) return node.forEach((n) => walk(n, insidePlan));
    if (typeof node !== 'object' || node === null) return;
    const obj = node as Record<string, unknown>;
    if (insidePlan) collect(obj);
    for (const [k, v] of Object.entries(obj)) {
      // Do not descend into rejectedPlans: those were not chosen.
      if (k === 'rejectedPlans') continue;
      walk(v, insidePlan || PLAN_ROOT_KEYS.has(k));
    }
  };

  walk(explain, false);
  return [...stages].sort();
}

export function hasCollscan(explain: unknown): boolean {
  return collectPlanStages(explain).includes('COLLSCAN');
}

/** Index names/keys the winning plan used, for a friendlier rejection message. */
export function indexesUsed(explain: unknown): string[] {
  const names = new Set<string>();
  const walk = (node: unknown): void => {
    if (Array.isArray(node)) return node.forEach(walk);
    if (typeof node !== 'object' || node === null) return;
    const obj = node as Record<string, unknown>;
    if (obj.stage === 'IXSCAN' || obj.stage === 'EXPRESS_IXSCAN' || obj.stage === 'EXPRESS_CLUSTERED_IXSCAN' || obj.stage === 'DISTINCT_SCAN' || obj.stage === 'IDHACK') {
      if (typeof obj.indexName === 'string') names.add(obj.indexName);
      else if (obj.stage === 'IDHACK') names.add('_id_');
    }
    for (const [k, v] of Object.entries(obj)) if (k !== 'rejectedPlans') walk(v);
  };
  walk(explain);
  return [...names].sort();
}
