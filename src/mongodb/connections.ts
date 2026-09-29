/**
 * Safe, Claude-facing descriptions of configured connections.
 * Deliberately excludes uriEnv values and the URI itself.
 */
import type { ResolvedConnection } from '../types.js';

export interface ConnectionSummary {
  name: string;
  description: string | undefined;
  production: boolean;
  credentialsConfigured: boolean;
  allowedDatabases: string[];
  allowedCollections: string[] | '*';
  limits: { defaultLimit: number; maxLimit: number; maxTimeMS: number };
  rejectCollscan: boolean;
  collscanMaxDocs: number;
  readPreference: string;
}

export function describeConnection(conn: ResolvedConnection, env: NodeJS.ProcessEnv = process.env): ConnectionSummary {
  return {
    name: conn.name,
    description: conn.description,
    production: conn.production,
    credentialsConfigured: typeof env[conn.uriEnv] === 'string' && env[conn.uriEnv]!.length > 0,
    allowedDatabases: [...conn.allowedDatabases].sort(),
    allowedCollections: conn.allowedCollections === null ? '*' : [...conn.allowedCollections].sort(),
    limits: { defaultLimit: conn.defaultLimit, maxLimit: conn.maxLimit, maxTimeMS: conn.maxTimeMS },
    rejectCollscan: conn.rejectCollscan,
    collscanMaxDocs: conn.collscanMaxDocs,
    readPreference: conn.readPreference,
  };
}
