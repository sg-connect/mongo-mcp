/**
 * Global, non-configurable ceilings plus helpers that clamp per-call values
 * into the window allowed for a given connection.
 *
 * Connection config can tighten these; it can never loosen them past the HARD_* values.
 */
import type { ConnectionConfig, ResolvedConnection } from '../types.js';

export const DEFAULT_LIMIT = 20;
export const HARD_MAX_LIMIT = 100;

export const DEFAULT_MAX_TIME_MS = 10_000;
export const HARD_MAX_TIME_MS = 30_000;

/** Deep skips are O(n) on the server; keep them bounded. */
export const HARD_MAX_SKIP = 10_000;

/** Largest JSON payload (bytes) a single tool call will return to Claude. */
export const MAX_OUTPUT_BYTES = 256 * 1024;

export const DEFAULT_COLLSCAN_MAX_DOCS = 10_000;

export const MAX_PIPELINE_STAGES = 50;
/** Guards the recursive validators against pathological nesting. */
export const MAX_QUERY_DEPTH = 32;

const clampInt = (value: number, min: number, max: number): number =>
  Math.min(max, Math.max(min, Math.trunc(value)));

const isProdName = (name: string): boolean => /(^|[-_.])prod(uction)?($|[-_.])/i.test(name);

/** Apply defaults and hard ceilings to a raw connection config. Pure; does not read env. */
export function resolveConnection(name: string, cfg: ConnectionConfig): ResolvedConnection {
  const production = cfg.production ?? isProdName(name);

  const maxLimit = clampInt(cfg.maxLimit ?? HARD_MAX_LIMIT, 1, HARD_MAX_LIMIT);
  const defaultLimit = clampInt(cfg.defaultLimit ?? DEFAULT_LIMIT, 1, maxLimit);
  const maxTimeMS = clampInt(cfg.maxTimeMS ?? DEFAULT_MAX_TIME_MS, 1, HARD_MAX_TIME_MS);

  const wildcard = cfg.allowedCollections.length === 1 && cfg.allowedCollections[0] === '*';
  const allowedCollections = wildcard && !production ? null : new Set(cfg.allowedCollections.filter((c) => c !== '*'));

  return {
    name,
    uriEnv: cfg.uriEnv,
    description: cfg.description,
    production,
    allowedDatabases: new Set(cfg.allowedDatabases),
    allowedCollections,
    defaultLimit,
    maxLimit,
    maxTimeMS,
    rejectCollscan: cfg.rejectCollscan ?? production,
    collscanMaxDocs: Math.max(0, Math.trunc(cfg.collscanMaxDocs ?? DEFAULT_COLLSCAN_MAX_DOCS)),
    readPreference: cfg.readPreference ?? (production ? 'secondaryPreferred' : 'primary'),
  };
}

export interface EffectiveLimits {
  limit: number;
  skip: number;
  maxTimeMS: number;
  /** Human-readable notes about clamping, surfaced to Claude so it learns the boundaries. */
  notes: string[];
}

/** Turn what Claude asked for into what the policy allows. Never throws; clamps and explains. */
export function effectiveLimits(
  conn: ResolvedConnection,
  requested: { limit?: number | undefined; skip?: number | undefined; maxTimeMS?: number | undefined },
): EffectiveLimits {
  const notes: string[] = [];

  let limit = conn.defaultLimit;
  if (requested.limit !== undefined) {
    limit = clampInt(requested.limit, 1, conn.maxLimit);
    if (limit !== requested.limit) notes.push(`limit clamped from ${requested.limit} to ${limit} (max ${conn.maxLimit})`);
  }

  let skip = 0;
  if (requested.skip !== undefined) {
    skip = clampInt(requested.skip, 0, HARD_MAX_SKIP);
    if (skip !== requested.skip) notes.push(`skip clamped from ${requested.skip} to ${skip} (max ${HARD_MAX_SKIP})`);
  }

  let maxTimeMS = conn.maxTimeMS;
  if (requested.maxTimeMS !== undefined) {
    maxTimeMS = clampInt(requested.maxTimeMS, 1, conn.maxTimeMS);
    if (maxTimeMS !== requested.maxTimeMS) {
      notes.push(`maxTimeMS clamped from ${requested.maxTimeMS} to ${maxTimeMS} (connection max ${conn.maxTimeMS})`);
    }
  }

  return { limit, skip, maxTimeMS, notes };
}
