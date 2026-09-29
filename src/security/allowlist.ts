/**
 * Connection / database / collection allowlists.
 *
 * These are the outermost gate: nothing reaches the driver unless the
 * (connection, database, collection) triple is explicitly allowed by config.
 */
import { ValidationError, type ResolvedConnection } from '../types.js';

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;

function assertPlainName(kind: 'database' | 'collection', value: unknown): string {
  if (typeof value !== 'string' || !NAME_RE.test(value) || value.startsWith('system.')) {
    throw new ValidationError('INVALID_INPUT', `Invalid ${kind} name.`);
  }
  return value;
}

export class ConnectionRegistry {
  private readonly byName: ReadonlyMap<string, ResolvedConnection>;

  constructor(connections: Iterable<ResolvedConnection>) {
    this.byName = new Map([...connections].map((c) => [c.name, c]));
  }

  names(): string[] {
    return [...this.byName.keys()].sort();
  }

  all(): ResolvedConnection[] {
    return this.names().map((n) => this.byName.get(n)!);
  }

  /** Throws CONNECTION_NOT_ALLOWED unless `name` is configured. */
  require(name: unknown): ResolvedConnection {
    const conn = typeof name === 'string' ? this.byName.get(name) : undefined;
    if (!conn) {
      throw new ValidationError(
        'CONNECTION_NOT_ALLOWED',
        `Unknown connection ${JSON.stringify(String(name))}. Available: ${this.names().join(', ') || '(none configured)'}.`,
      );
    }
    return conn;
  }
}

export function requireDatabase(conn: ResolvedConnection, database: unknown): string {
  const db = assertPlainName('database', database);
  if (!conn.allowedDatabases.has(db)) {
    throw new ValidationError(
      'DATABASE_NOT_ALLOWED',
      `Database "${db}" is not allowed on connection "${conn.name}". Allowed: ${[...conn.allowedDatabases].join(', ')}.`,
    );
  }
  return db;
}

export function isCollectionAllowed(conn: ResolvedConnection, collection: string): boolean {
  if (collection.startsWith('system.')) return false;
  return conn.allowedCollections === null || conn.allowedCollections.has(collection);
}

export function requireCollection(conn: ResolvedConnection, collection: unknown): string {
  const coll = assertPlainName('collection', collection);
  if (!isCollectionAllowed(conn, coll)) {
    const allowed = conn.allowedCollections === null ? '*' : [...conn.allowedCollections].join(', ');
    throw new ValidationError(
      'COLLECTION_NOT_ALLOWED',
      `Collection "${coll}" is not allowed on connection "${conn.name}". Allowed: ${allowed}.`,
    );
  }
  return coll;
}
