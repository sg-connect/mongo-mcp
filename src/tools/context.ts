/**
 * Everything a tool needs, plus `runTool`: the single choke point through which
 * every tool call passes. It resolves and validates the scope (connection →
 * database → collection), times the operation, writes the audit record, and
 * converts errors into safe MCP tool results.
 */
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { BSON, type Document } from 'mongodb';
import { z } from 'zod';
import { AuditLogger } from '../audit/logger.js';
import { ClientManager } from '../mongodb/client.js';
import type { ReadCollection, ReadDb } from '../mongodb/readonly.js';
import { ConnectionRegistry, requireCollection, requireDatabase } from '../security/allowlist.js';
import { MAX_OUTPUT_BYTES } from '../security/query-policy.js';
import { Redactor } from '../security/redact.js';
import { ValidationError, type AuditRecord, type CollscanCheck, type JsonDocument, type ResolvedConnection } from '../types.js';

export interface ToolContext {
  registry: ConnectionRegistry;
  clients: ClientManager;
  audit: AuditLogger;
  redactor: Redactor;
  /** Who is calling, set per HTTP request after authentication. */
  user?: string;
}

/** Zod fragments shared by tools, with descriptions that teach Claude the boundaries. */
export const fields = {
  connection: z.string().describe('Named connection from list-connections (e.g. "shop-prod").'),
  database: z.string().describe('Database name. Must be on the connection allowlist.'),
  collection: z.string().describe('Collection name. Must be on the connection allowlist.'),
  document: z.record(z.string(), z.unknown()),
  filter: z
    .record(z.string(), z.unknown())
    .optional()
    .describe('MongoDB query filter. Use Extended JSON for special types: {"_id": {"$oid": "..."}}, {"createdAt": {"$gte": {"$date": "2026-01-01T00:00:00Z"}}}. $where is refused.'),
  projection: z.record(z.string(), z.unknown()).optional().describe('Projection, e.g. {"name": 1, "status": 1}. Prefer projecting to keep results small.'),
  sort: z.record(z.string(), z.unknown()).optional().describe('Sort spec, e.g. {"createdAt": -1}. On production, sorting on an unindexed field is rejected as a COLLSCAN.'),
  limit: z.number().int().positive().optional().describe('Max documents to return. Default 20, hard max 100 (larger values are clamped).'),
  skip: z.number().int().nonnegative().optional().describe('Documents to skip. Max 10 000.'),
  maxTimeMS: z.number().int().positive().optional().describe('Server-side time budget. Default 10 000 ms; cannot exceed the connection maximum.'),
  hint: z.union([z.string(), z.record(z.string(), z.unknown())]).optional().describe('Index name or key document to force an index.'),
} as const;

export const READ_ONLY_ANNOTATIONS = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false } as const;

/** Extended JSON ({"$oid": ...}, {"$date": ...}) → BSON values the driver understands. */
export function fromEJSON<T = Document>(value: unknown): T {
  if (value === undefined || value === null) return value as T;
  return BSON.EJSON.deserialize(value as Document, { relaxed: true }) as T;
}

/** BSON → relaxed Extended JSON so ObjectId/Date survive the trip to Claude in a copy-pasteable form. */
export function toEJSON(value: unknown): unknown {
  return BSON.EJSON.serialize(value as Document, { relaxed: true });
}

export interface ShapedDocuments {
  documents: unknown[];
  returned: number;
  truncated: boolean;
  approxBytes: number;
}

/** Serialise documents until the output byte budget is reached. */
export function shapeDocuments(docs: Document[], budget = MAX_OUTPUT_BYTES): ShapedDocuments {
  const out: unknown[] = [];
  let bytes = 2;
  for (const doc of docs) {
    const ej = toEJSON(doc);
    const size = Buffer.byteLength(JSON.stringify(ej));
    if (out.length > 0 && bytes + size > budget) return { documents: out, returned: out.length, truncated: true, approxBytes: bytes };
    out.push(ej);
    bytes += size + 1;
  }
  return { documents: out, returned: out.length, truncated: false, approxBytes: bytes };
}

export interface Scope {
  conn: ResolvedConnection;
  database: string | null;
  collection: string | null;
}

export interface ToolOutcome {
  /** JSON-serialisable payload returned to Claude. */
  result: unknown;
  resultCount?: number;
  collscanCheck?: CollscanCheck;
}

export interface RunToolInput {
  tool: string;
  operation: string;
  connection?: string | undefined;
  database?: string | undefined;
  collection?: string | undefined;
  /** Parameters as received (already zod-parsed); logged after redaction. */
  params: unknown;
}

function text(payload: unknown, isError = false): CallToolResult {
  return { content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }], isError };
}

/**
 * Run a tool body inside the security + audit envelope.
 *
 * `body` receives the validated scope and lazily-resolved handles. The
 * handles are read-only facades (mongodb/readonly.ts): they have no write
 * methods to call.
 */
export async function runTool(
  ctx: ToolContext,
  input: RunToolInput,
  body: (scope: Scope, handles: { db: () => Promise<ReadDb>; coll: () => Promise<ReadCollection> }) => Promise<ToolOutcome>,
): Promise<CallToolResult> {
  const started = performance.now();
  const base: Omit<AuditRecord, 'durationMs' | 'resultCount' | 'ok' | 'rejected' | 'rejectionCode' | 'rejectionReason' | 'error' | 'collscanCheck'> = {
    ts: new Date().toISOString(),
    user: ctx.user ?? null,
    tool: input.tool,
    operation: input.operation,
    connection: input.connection ?? null,
    database: input.database ?? null,
    collection: input.collection ?? null,
    production: null,
    params: input.params,
  };
  const finish = (partial: Partial<AuditRecord>): void =>
    ctx.audit.log({
      ...base,
      durationMs: Math.round(performance.now() - started),
      resultCount: null,
      ok: false,
      rejected: false,
      rejectionCode: null,
      rejectionReason: null,
      error: null,
      collscanCheck: null,
      ...partial,
    });

  let scope: Scope | undefined;
  try {
    if (input.connection !== undefined) {
      const conn = ctx.registry.require(input.connection);
      base.production = conn.production;
      const database = input.database !== undefined ? requireDatabase(conn, input.database) : null;
      const collection = input.collection !== undefined ? requireCollection(conn, input.collection) : null;
      if (collection !== null && database === null) throw new ValidationError('INVALID_INPUT', 'database is required when collection is given.');
      scope = { conn, database, collection };
    } else if (input.database !== undefined || input.collection !== undefined) {
      throw new ValidationError('INVALID_INPUT', 'connection is required.');
    } else {
      // Connection-less tools (list-connections). Provide a dummy scope; handles will refuse.
      scope = { conn: undefined as unknown as ResolvedConnection, database: null, collection: null };
    }

    const s = scope;
    const handles = {
      db: async (): Promise<ReadDb> => {
        if (!s.conn || s.database === null) throw new ValidationError('INVALID_INPUT', 'database is required.');
        return ctx.clients.db(s.conn, s.database);
      },
      coll: async (): Promise<ReadCollection> => {
        if (!s.conn || s.database === null || s.collection === null) throw new ValidationError('INVALID_INPUT', 'database and collection are required.');
        return ctx.clients.collection(s.conn, s.database, s.collection);
      },
    };

    const outcome = await body(s, handles);
    finish({ ok: true, resultCount: outcome.resultCount ?? null, collscanCheck: outcome.collscanCheck ?? null });
    return text(ctx.redactor.deep(outcome.result));
  } catch (err) {
    if (err instanceof ValidationError) {
      finish({ rejected: true, rejectionCode: err.code, rejectionReason: err.message });
      return text({ error: err.code, message: err.message, tool: input.tool }, true);
    }
    const message = ctx.redactor.error(err);
    finish({ error: message });
    return text({ error: 'OPERATION_FAILED', message, tool: input.tool }, true);
  }
}
