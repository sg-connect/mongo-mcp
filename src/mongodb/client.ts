/**
 * Lazily creates and caches one MongoClient per connection.
 *
 * The URI is read from the environment at connect time and never stored on
 * any object that could be serialised. Read preference / concern come from
 * the resolved connection. The raw MongoClient never leaves this class:
 * callers get read-only facades (readonly.ts) and a few fixed admin reads.
 *
 * The database user may have write privileges. Every command the driver sends
 * is checked against READ_COMMANDS; anything else is reported through
 * `onUnexpectedCommand` (the server logs it as a security event).
 */
import { MongoClient, ReadPreference, type CommandStartedEvent } from 'mongodb';
import { ValidationError, type ResolvedConnection } from '../types.js';
import { READ_COMMANDS, readOnlyCollection, readOnlyDb, type ReadCollection, type ReadDb } from './readonly.js';

export interface UnexpectedCommand {
  connection: string;
  commandName: string;
  databaseName: string;
}

export interface ClientManagerOptions {
  serverSelectionTimeoutMS?: number;
  connectTimeoutMS?: number;
  env?: NodeJS.ProcessEnv;
  onUnexpectedCommand?: (event: UnexpectedCommand) => void;
}

const defaultTripwire = (e: UnexpectedCommand): void => {
  process.stderr.write(`[mongo-mcp] SECURITY: unexpected command "${e.commandName}" on ${e.connection}/${e.databaseName}\n`);
};

export class ClientManager {
  private readonly clients = new Map<string, Promise<MongoClient>>();
  private readonly opts: Required<ClientManagerOptions>;

  constructor(opts: ClientManagerOptions = {}) {
    this.opts = {
      serverSelectionTimeoutMS: opts.serverSelectionTimeoutMS ?? 10_000,
      connectTimeoutMS: opts.connectTimeoutMS ?? 10_000,
      env: opts.env ?? process.env,
      onUnexpectedCommand: opts.onUnexpectedCommand ?? defaultTripwire,
    };
  }

  /** All URI values currently configured — used only to seed the redactor. */
  secretValues(conns: Iterable<ResolvedConnection>): string[] {
    const out: string[] = [];
    for (const c of conns) {
      const v = this.opts.env[c.uriEnv];
      if (v) out.push(v);
    }
    return out;
  }

  private async client(conn: ResolvedConnection): Promise<MongoClient> {
    let pending = this.clients.get(conn.name);
    if (!pending) {
      pending = this.connect(conn);
      this.clients.set(conn.name, pending);
      pending.catch(() => this.clients.delete(conn.name));
    }
    return pending;
  }

  private async connect(conn: ResolvedConnection): Promise<MongoClient> {
    const uri = this.opts.env[conn.uriEnv];
    if (!uri) {
      throw new ValidationError('ENV_MISSING', `Connection "${conn.name}" has no credentials: environment variable ${conn.uriEnv} is not set.`);
    }
    const client = new MongoClient(uri, {
      appName: 'mongo-mcp',
      maxPoolSize: 4,
      minPoolSize: 0,
      serverSelectionTimeoutMS: this.opts.serverSelectionTimeoutMS,
      connectTimeoutMS: this.opts.connectTimeoutMS,
      readPreference: ReadPreference.fromString(conn.readPreference),
      readConcern: { level: 'local' },
      retryWrites: false,
      monitorCommands: true,
    });
    client.on('commandStarted', (e: CommandStartedEvent) => {
      if (!READ_COMMANDS.has(e.commandName)) this.opts.onUnexpectedCommand({ connection: conn.name, commandName: e.commandName, databaseName: e.databaseName });
    });
    await client.connect();
    return client;
  }

  async db(conn: ResolvedConnection, database: string): Promise<ReadDb> {
    return readOnlyDb((await this.client(conn)).db(database));
  }

  async collection(conn: ResolvedConnection, database: string, collection: string): Promise<ReadCollection> {
    return readOnlyCollection((await this.client(conn)).db(database).collection(collection));
  }

  /** `hello` on admin, for --check. */
  async hello(conn: ResolvedConnection): Promise<{ setName?: string; maxWireVersion?: number }> {
    return (await this.client(conn)).db('admin').command({ hello: 1 });
  }

  /** Names of databases the user can see. Throws when the user lacks listDatabases. */
  async listDatabaseNames(conn: ResolvedConnection): Promise<string[]> {
    const res = await (await this.client(conn)).db('admin').command({ listDatabases: 1, nameOnly: true, authorizedDatabases: true });
    return (res.databases as { name: string }[]).map((d) => d.name);
  }

  async closeAll(): Promise<void> {
    const pending = [...this.clients.values()];
    this.clients.clear();
    await Promise.allSettled(pending.map(async (p) => (await p).close()));
  }
}
