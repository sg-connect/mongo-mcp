/**
 * Structural validation of everything Claude sends that ends up in a MongoDB command.
 *
 * Strategy: allowlists over denylists. Aggregation stages must be on a known
 * read-only list; a handful of operators that execute server-side JavaScript
 * are refused anywhere in any document; cross-collection stages ($lookup,
 * $unionWith, $graphLookup) must reference allowlisted collections, otherwise
 * they would be a trivial bypass of the collection allowlist.
 */
import { ValidationError, type JsonDocument, type ResolvedConnection } from '../types.js';
import { isCollectionAllowed } from './allowlist.js';
import { MAX_PIPELINE_STAGES, MAX_QUERY_DEPTH } from './query-policy.js';

/** Operators that run arbitrary server-side JavaScript. Refused everywhere, always. */
export const FORBIDDEN_OPERATORS: ReadonlySet<string> = new Set(['$where', '$function', '$accumulator']);

/** Stages that write, or that expose cluster internals unrelated to data investigation. */
export const FORBIDDEN_STAGES: Readonly<Record<string, string>> = {
  $out: 'writes results to a collection',
  $merge: 'writes results to a collection',
  $currentOp: 'exposes server operations',
  $listSessions: 'exposes sessions',
  $listLocalSessions: 'exposes sessions',
  $listSampledQueries: 'exposes sampled queries',
  $listClusterCatalog: 'exposes cluster catalog',
  $changeStream: 'opens a change stream',
  $changeStreamSplitLargeEvent: 'opens a change stream',
  $planCacheStats: 'exposes plan cache internals',
  $querySettings: 'exposes query settings',
  $shardedDataDistribution: 'exposes sharding internals',
  $listSearchIndexes: 'exposes search index definitions',
};

/** Read-only aggregation stages Claude may use. */
export const ALLOWED_STAGES: ReadonlySet<string> = new Set([
  '$addFields',
  '$bucket',
  '$bucketAuto',
  '$collStats',
  '$count',
  '$densify',
  '$documents',
  '$facet',
  '$fill',
  '$geoNear',
  '$graphLookup',
  '$group',
  '$indexStats',
  '$limit',
  '$lookup',
  '$match',
  '$project',
  '$redact',
  '$replaceRoot',
  '$replaceWith',
  '$sample',
  '$search',
  '$searchMeta',
  '$set',
  '$setWindowFields',
  '$skip',
  '$sort',
  '$sortByCount',
  '$unionWith',
  '$unset',
  '$unwind',
  '$vectorSearch',
]);

export const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;

/**
 * Walks any JSON-ish value and throws if a forbidden operator key appears at any depth.
 * Also enforces a depth ceiling so a malicious payload cannot exhaust the stack.
 */
export function assertNoForbiddenOperators(value: unknown, path = '$', depth = 0): void {
  if (depth > MAX_QUERY_DEPTH) throw new ValidationError('QUERY_TOO_DEEP', `Query nesting exceeds ${MAX_QUERY_DEPTH} levels at ${path}.`);
  if (Array.isArray(value)) {
    value.forEach((v, i) => assertNoForbiddenOperators(v, `${path}[${i}]`, depth + 1));
    return;
  }
  if (!isPlainObject(value)) return;
  for (const [key, v] of Object.entries(value)) {
    if (FORBIDDEN_OPERATORS.has(key)) {
      throw new ValidationError('FORBIDDEN_OPERATOR', `Operator ${key} (server-side JavaScript) is not allowed (found at ${path}.${key}).`);
    }
    assertNoForbiddenOperators(v, `${path}.${key}`, depth + 1);
  }
}

function requireObject(value: unknown, what: string): JsonDocument {
  if (value === undefined || value === null) return {};
  if (!isPlainObject(value)) throw new ValidationError('INVALID_INPUT', `${what} must be a JSON object.`);
  return value;
}

/** A find/count filter. */
export function validateFilter(filter: unknown): JsonDocument {
  const f = requireObject(filter, 'filter');
  assertNoForbiddenOperators(f, 'filter');
  return f;
}

export function validateProjection(projection: unknown): JsonDocument | undefined {
  if (projection === undefined || projection === null) return undefined;
  const p = requireObject(projection, 'projection');
  assertNoForbiddenOperators(p, 'projection');
  return Object.keys(p).length ? p : undefined;
}

export function validateSort(sort: unknown): JsonDocument | undefined {
  if (sort === undefined || sort === null) return undefined;
  const s = requireObject(sort, 'sort');
  for (const [k, v] of Object.entries(s)) {
    const ok = v === 1 || v === -1 || v === 'asc' || v === 'desc' || (isPlainObject(v) && Object.keys(v).length === 1 && '$meta' in v);
    if (!ok) throw new ValidationError('INVALID_INPUT', `sort.${k} must be 1, -1, "asc", "desc" or {"$meta": ...}.`);
  }
  return Object.keys(s).length ? s : undefined;
}

export function validateHint(hint: unknown): string | JsonDocument | undefined {
  if (hint === undefined || hint === null) return undefined;
  if (typeof hint === 'string') {
    if (!/^[A-Za-z0-9_.$-]{1,128}$/.test(hint)) throw new ValidationError('INVALID_INPUT', 'hint must be an index name or an index key document.');
    return hint;
  }
  const h = requireObject(hint, 'hint');
  for (const v of Object.values(h)) {
    if (v !== 1 && v !== -1 && typeof v !== 'string') throw new ValidationError('INVALID_INPUT', 'hint key document values must be 1, -1 or an index type string.');
  }
  return Object.keys(h).length ? h : undefined;
}

export function validateFieldName(field: unknown, what = 'field'): string {
  if (typeof field !== 'string' || !/^[^$][^\0]{0,255}$/.test(field)) {
    throw new ValidationError('INVALID_INPUT', `${what} must be a non-empty field path that does not start with "$".`);
  }
  return field;
}

/**
 * Checks a `from`/`coll` reference used by $lookup, $graphLookup, $unionWith.
 * Accepts a collection name or {db, coll}. The target must be allowlisted.
 */
function assertCollectionRef(conn: ResolvedConnection, ref: unknown, path: string): void {
  if (ref === undefined) return; // $lookup without `from` (uses $documents) is fine
  let db: unknown;
  let coll: unknown;
  if (typeof ref === 'string') coll = ref;
  else if (isPlainObject(ref)) ({ db, coll } = ref);
  else throw new ValidationError('INVALID_INPUT', `${path} must be a collection name or {db, coll}.`);

  if (db !== undefined) {
    if (typeof db !== 'string' || !conn.allowedDatabases.has(db)) {
      throw new ValidationError('DATABASE_NOT_ALLOWED', `${path} references database ${JSON.stringify(db)}, which is not allowed on connection "${conn.name}".`);
    }
  }
  if (typeof coll !== 'string' || !isCollectionAllowed(conn, coll)) {
    throw new ValidationError('COLLECTION_NOT_ALLOWED', `${path} references collection ${JSON.stringify(coll)}, which is not allowed on connection "${conn.name}".`);
  }
}

/**
 * Validates an aggregation pipeline (recursively, including sub-pipelines) against `conn`.
 * Returns the same pipeline (typed) when valid.
 */
export function validatePipeline(pipeline: unknown, conn: ResolvedConnection, path = 'pipeline', depth = 0): JsonDocument[] {
  if (!Array.isArray(pipeline)) throw new ValidationError('INVALID_INPUT', `${path} must be an array of stages.`);
  if (pipeline.length > MAX_PIPELINE_STAGES) throw new ValidationError('PIPELINE_TOO_LARGE', `${path} has ${pipeline.length} stages; max is ${MAX_PIPELINE_STAGES}.`);
  if (depth > 4) throw new ValidationError('QUERY_TOO_DEEP', `${path}: sub-pipelines nested too deeply.`);

  return pipeline.map((stage, i) => {
    const p = `${path}[${i}]`;
    if (!isPlainObject(stage)) throw new ValidationError('INVALID_INPUT', `${p} must be an object with exactly one $stage key.`);
    const keys = Object.keys(stage);
    if (keys.length !== 1) throw new ValidationError('INVALID_INPUT', `${p} must have exactly one $stage key (got ${keys.length}).`);
    const name = keys[0]!;
    const body = stage[name];

    if (name in FORBIDDEN_STAGES) throw new ValidationError('FORBIDDEN_STAGE', `Stage ${name} is not allowed: it ${FORBIDDEN_STAGES[name]}.`);
    if (!ALLOWED_STAGES.has(name)) throw new ValidationError('FORBIDDEN_STAGE', `Stage ${name} is not on the read-only allowlist.`);

    assertNoForbiddenOperators(body, `${p}.${name}`);

    switch (name) {
      case '$lookup':
      case '$graphLookup': {
        if (!isPlainObject(body)) throw new ValidationError('INVALID_INPUT', `${p}.${name} must be an object.`);
        assertCollectionRef(conn, body.from, `${p}.${name}.from`);
        if (name === '$lookup' && body.pipeline !== undefined) validatePipeline(body.pipeline, conn, `${p}.$lookup.pipeline`, depth + 1);
        break;
      }
      case '$unionWith': {
        if (typeof body === 'string') assertCollectionRef(conn, body, `${p}.$unionWith`);
        else if (isPlainObject(body)) {
          assertCollectionRef(conn, body.coll, `${p}.$unionWith.coll`);
          if (body.pipeline !== undefined) validatePipeline(body.pipeline, conn, `${p}.$unionWith.pipeline`, depth + 1);
        } else throw new ValidationError('INVALID_INPUT', `${p}.$unionWith must be a collection name or {coll, pipeline}.`);
        break;
      }
      case '$facet': {
        if (!isPlainObject(body)) throw new ValidationError('INVALID_INPUT', `${p}.$facet must be an object of named pipelines.`);
        for (const [facet, sub] of Object.entries(body)) validatePipeline(sub, conn, `${p}.$facet.${facet}`, depth + 1);
        break;
      }
      case '$limit':
      case '$skip': {
        if (typeof body !== 'number' || !Number.isInteger(body) || body < 0) throw new ValidationError('INVALID_INPUT', `${p}.${name} must be a non-negative integer.`);
        break;
      }
      default:
        break;
    }
    return stage;
  });
}
