/**
 * Shared types for mongo-mcp.
 *
 * Everything user-controlled (Claude-controlled) flows through these types and
 * is validated by the security layer before it reaches the MongoDB driver.
 */

export type ReadPreferenceName =
  | 'primary'
  | 'primaryPreferred'
  | 'secondary'
  | 'secondaryPreferred'
  | 'nearest';

/** Shape of one entry in config/connections.json (before defaults are applied). */
export interface ConnectionConfig {
  /** Name of the environment variable that holds the MongoDB URI. The URI itself is never stored in config. */
  uriEnv: string;
  /** Human description shown to Claude via list-connections. */
  description?: string;
  /** Production connections get stricter policies (COLLSCAN rejection, no wildcards). Defaults to true when the name contains "prod". */
  production?: boolean;
  /** Databases Claude may touch on this connection. Required, non-empty. */
  allowedDatabases: string[];
  /** Collections Claude may touch (applies to every allowed database). ["*"] is honoured on non-production connections only. */
  allowedCollections: string[];
  /** Result limit applied when Claude does not pass one. Default 20. */
  defaultLimit?: number;
  /** Largest result limit Claude may request; clamped to the global hard max (100). */
  maxLimit?: number;
  /** Server-side time budget per operation. Default 10 000 ms; clamped to the global hard max (30 000). */
  maxTimeMS?: number;
  /** Run explain() first and reject obvious full collection scans. Defaults to the value of `production`. */
  rejectCollscan?: boolean;
  /** A COLLSCAN is tolerated if the collection has at most this many documents (estimated). Default 10 000. */
  collscanMaxDocs?: number;
  /** Driver read preference. Default secondaryPreferred for production, primary otherwise. */
  readPreference?: ReadPreferenceName;
}

/** A connection after defaults and clamping have been applied. Safe to hand to tools. */
export interface ResolvedConnection {
  name: string;
  uriEnv: string;
  description: string | undefined;
  production: boolean;
  allowedDatabases: ReadonlySet<string>;
  /** `null` means wildcard (only possible on non-production connections). */
  allowedCollections: ReadonlySet<string> | null;
  defaultLimit: number;
  maxLimit: number;
  maxTimeMS: number;
  rejectCollscan: boolean;
  collscanMaxDocs: number;
  readPreference: ReadPreferenceName;
}

export type ConnectionsConfig = Record<string, ConnectionConfig>;

/** A JSON-ish document as received from the MCP client (may contain Extended JSON like {"$oid": "..."}). */
export type JsonDocument = Record<string, unknown>;

export type ValidationCode =
  | 'CONNECTION_NOT_ALLOWED'
  | 'DATABASE_NOT_ALLOWED'
  | 'COLLECTION_NOT_ALLOWED'
  | 'ENV_MISSING'
  | 'INVALID_INPUT'
  | 'FORBIDDEN_OPERATOR'
  | 'FORBIDDEN_STAGE'
  | 'PIPELINE_TOO_LARGE'
  | 'QUERY_TOO_DEEP'
  | 'COLLSCAN_REJECTED';

/** Thrown by the security layer. Always safe to show to Claude: contains no secrets. */
export class ValidationError extends Error {
  readonly code: ValidationCode;
  constructor(code: ValidationCode, message: string) {
    super(message);
    this.name = 'ValidationError';
    this.code = code;
  }
}

/** One line in the audit log. Never contains URIs or credentials (see security/redact.ts). */
export interface AuditRecord {
  ts: string;
  /** Authenticated HTTP user; null for in-process callers (tests). */
  user: string | null;
  tool: string;
  operation: string;
  connection: string | null;
  database: string | null;
  collection: string | null;
  production: boolean | null;
  params: unknown;
  durationMs: number;
  resultCount: number | null;
  ok: boolean;
  rejected: boolean;
  rejectionCode: ValidationCode | null;
  rejectionReason: string | null;
  error: string | null;
  collscanCheck: CollscanCheck | null;
}

export interface CollscanCheck {
  /** Whether an explain() was actually run. */
  performed: boolean;
  /** Why it was skipped, when it was. */
  skipped?: string;
  collscan?: boolean;
  /** Plan stage names found under the winning plan(s). */
  stages?: string[];
  estimatedDocs?: number;
}
