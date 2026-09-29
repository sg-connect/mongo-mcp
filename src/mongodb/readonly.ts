/**
 * Read-only facades over the driver's Db and Collection.
 *
 * The database user behind a connection may be allowed to write. These
 * facades are why that does not matter to the tools: they are handed objects
 * that only have read methods, so a write is a compile error, and a stray
 * `$out`/`$merge` is refused here even if the validator above ever missed one.
 *
 * The command tripwire in client.ts is the last line: it reports any command
 * the driver sends that is not on READ_COMMANDS.
 */
import type { AggregateOptions, Collection, CountDocumentsOptions, Db, Document, EstimatedDocumentCountOptions, FindOptions } from 'mongodb';
import { ValidationError } from '../types.js';

/** Every command this server is expected to send, including the driver's own handshake/session commands. */
export const READ_COMMANDS: ReadonlySet<string> = new Set([
  'find',
  'getMore',
  'killCursors',
  'aggregate',
  'count',
  'explain',
  'listIndexes',
  'listCollections',
  'listDatabases',
  'dbStats',
  'hello',
  'isMaster',
  'ismaster',
  'ping',
  'buildInfo',
  'endSessions',
  'saslStart',
  'saslContinue',
  'authenticate',
  'getnonce',
]);

const WRITE_STAGES = new Set(['$out', '$merge']);

/** Independent of validator.ts on purpose: a second, simpler check on the final pipeline. */
export function assertNoWriteStages(pipeline: Document[]): void {
  for (const stage of pipeline) {
    for (const key of Object.keys(stage)) {
      if (WRITE_STAGES.has(key)) throw new ValidationError('FORBIDDEN_STAGE', `Stage ${key} writes data and is never allowed.`);
    }
  }
}

export interface ReadCollection {
  readonly dbName: string;
  readonly collectionName: string;
  find: Collection<Document>['find'];
  aggregate(pipeline: Document[], options?: AggregateOptions): ReturnType<Collection<Document>['aggregate']>;
  countDocuments(filter?: Document, options?: CountDocumentsOptions): Promise<number>;
  estimatedDocumentCount(options?: EstimatedDocumentCountOptions): Promise<number>;
  indexes(options?: { maxTimeMS?: number }): Promise<Document[]>;
}

export interface ReadDb {
  readonly databaseName: string;
  listCollections(filter: Document, options: { nameOnly: false; authorizedCollections: boolean; maxTimeMS: number }): ReturnType<Db['listCollections']>;
  collection(name: string): ReadCollection;
  /** dbStats with a fixed command document. */
  stats(maxTimeMS: number): Promise<Document>;
}

export function readOnlyCollection(coll: Collection<Document>): ReadCollection {
  return Object.freeze({
    dbName: coll.dbName,
    collectionName: coll.collectionName,
    find: ((filter?: Document, options?: FindOptions) => coll.find(filter ?? {}, options)) as Collection<Document>['find'],
    aggregate: (pipeline: Document[], options?: AggregateOptions) => {
      assertNoWriteStages(pipeline);
      return coll.aggregate(pipeline, options);
    },
    countDocuments: (filter?: Document, options?: CountDocumentsOptions) => coll.countDocuments(filter ?? {}, options),
    estimatedDocumentCount: (options?: EstimatedDocumentCountOptions) => coll.estimatedDocumentCount(options),
    indexes: (options?: { maxTimeMS?: number }) => coll.indexes(options) as Promise<Document[]>,
  });
}

export function readOnlyDb(db: Db): ReadDb {
  return Object.freeze({
    databaseName: db.databaseName,
    listCollections: (filter: Document, options: { nameOnly: false; authorizedCollections: boolean; maxTimeMS: number }) => db.listCollections(filter, options),
    collection: (name: string) => readOnlyCollection(db.collection(name)),
    stats: (maxTimeMS: number) => db.command({ dbStats: 1, scale: 1, maxTimeMS }),
  });
}
