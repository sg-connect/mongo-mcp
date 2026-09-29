/**
 * End-to-end: drives the real MCP server over an in-memory transport against a
 * local mongod. Skipped automatically when no server is reachable.
 *
 *   MONGO_MCP_TEST_URI=mongodb://127.0.0.1:27017 npm test
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { MongoClient, ObjectId } from 'mongodb';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ClientManager, type UnexpectedCommand } from '../src/mongodb/client.js';
import { ConnectionRegistry } from '../src/security/allowlist.js';
import { createServer, type MongoMcpServer } from '../src/server.js';
import { EXPOSED_TOOLS } from '../src/tools/index.js';
import { conn } from './helpers.js';

const URI = process.env.MONGO_MCP_TEST_URI ?? 'mongodb://127.0.0.1:27017/?appName=mongo-mcp-test';
const DB = 'mongo_mcp_test';

async function reachable(): Promise<boolean> {
  const probe = new MongoClient(URI, { serverSelectionTimeoutMS: 1_500 });
  try {
    await probe.connect();
    await probe.db('admin').command({ ping: 1 });
    return true;
  } catch {
    return false;
  } finally {
    await probe.close().catch(() => undefined);
  }
}

const canRun = await reachable();

interface ToolResult {
  isError: boolean;
  payload: Record<string, unknown>;
}

describe.skipIf(!canRun)('mongo-mcp end-to-end against local mongod', () => {
  let admin: MongoClient;
  let app: MongoMcpServer;
  let client: Client;
  let auditPath: string;
  const customerId = new ObjectId();
  const orderIds: ObjectId[] = [];
  const unexpected: UnexpectedCommand[] = [];
  let clients: ClientManager;

  const call = async (name: string, args: Record<string, unknown> = {}): Promise<ToolResult> => {
    const res = (await client.callTool({ name, arguments: args })) as { isError?: boolean; content: { type: string; text?: string }[] };
    const text = res.content.find((c) => c.type === 'text')?.text ?? '{}';
    return { isError: !!res.isError, payload: JSON.parse(text) as Record<string, unknown> };
  };

  beforeAll(async () => {
    admin = new MongoClient(URI);
    await admin.connect();
    const db = admin.db(DB);
    await db.dropDatabase();
    await db.collection('customers').insertMany([{ _id: customerId, name: 'Acme' }, { name: 'Globex' }]);
    const docs = Array.from({ length: 60 }, (_, i) => ({
      _id: new ObjectId(),
      customerId,
      name: `Order ${i}`,
      status: i % 3 === 0 ? 'active' : 'paused',
      budget: (i + 1) * 100,
      createdAt: new Date(2026, 0, 1 + i),
    }));
    orderIds.push(...docs.map((d) => d._id));
    await db.collection('orders').insertMany(docs);
    await db.collection('secrets').insertOne({ apiKey: 'should-never-be-readable-on-prod' });

    process.env.MONGO_MCP_TEST_URI = URI;
    auditPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'mongo-mcp-')), 'audit.jsonl');

    const registry = new ConnectionRegistry([
      conn('test-dev', { production: false, allowedDatabases: [DB], allowedCollections: ['*'] }),
      conn('test-prod', { production: true, allowedDatabases: [DB], allowedCollections: ['orders', 'customers'], collscanMaxDocs: 0 }),
      conn('no-creds', { uriEnv: 'MONGO_MCP_DOES_NOT_EXIST_URI', allowedDatabases: [DB], allowedCollections: ['orders'] }),
    ]);
    clients = new ClientManager({ serverSelectionTimeoutMS: 3_000, onUnexpectedCommand: (e) => unexpected.push(e) });
    app = createServer({ registry, auditLogPath: auditPath, clients });

    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await app.server.connect(serverTransport);
    client = new Client({ name: 'mongo-mcp-tests', version: '0.0.0' });
    await client.connect(clientTransport);
  });

  afterAll(async () => {
    await client?.close().catch(() => undefined);
    await app?.close().catch(() => undefined);
    await admin?.db(DB).dropDatabase().catch(() => undefined);
    await admin?.close().catch(() => undefined);
  });

  it('exposes exactly the read-only tool set and nothing that can write', async () => {
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name).sort();
    expect(names).toEqual([...EXPOSED_TOOLS].sort());
    for (const n of names) {
      expect(n).not.toMatch(/insert|update|replace|delete|remove|bulk|drop|rename|create|command|eval|shell|run|exec/i);
    }
    for (const t of tools) {
      expect(t.annotations?.readOnlyHint).toBe(true);
      expect(t.annotations?.destructiveHint).toBe(false);
    }
  });

  it('list-connections never reveals the URI or host', async () => {
    const r = await call('list-connections');
    expect(r.isError).toBe(false);
    const text = JSON.stringify(r.payload);
    expect(text).not.toContain('mongodb://');
    expect(text).not.toContain('127.0.0.1');
    expect(text).not.toContain('MONGO_MCP_TEST_URI');
    const conns = r.payload.connections as { name: string; credentialsConfigured: boolean; production: boolean; allowedCollections: unknown }[];
    expect(conns.find((c) => c.name === 'test-prod')).toMatchObject({ production: true, credentialsConfigured: true, allowedCollections: ['customers', 'orders'] });
    expect(conns.find((c) => c.name === 'test-dev')).toMatchObject({ allowedCollections: '*' });
    expect(conns.find((c) => c.name === 'no-creds')).toMatchObject({ credentialsConfigured: false });
  });

  it('rejects unknown connections, disallowed databases and disallowed collections', async () => {
    expect((await call('list-databases', { connection: 'shop-prod' })).payload.error).toBe('CONNECTION_NOT_ALLOWED');
    expect((await call('list-collections', { connection: 'test-prod', database: 'admin' })).payload.error).toBe('DATABASE_NOT_ALLOWED');
    const secrets = await call('find', { connection: 'test-prod', database: DB, collection: 'secrets' });
    expect(secrets.isError).toBe(true);
    expect(secrets.payload.error).toBe('COLLECTION_NOT_ALLOWED');
    expect(JSON.stringify(secrets.payload)).not.toContain('should-never-be-readable');
  });

  it('reports missing credentials without leaking anything', async () => {
    const r = await call('list-collections', { connection: 'no-creds', database: DB });
    expect(r.payload.error).toBe('ENV_MISSING');
    expect(String(r.payload.message)).toContain('MONGO_MCP_DOES_NOT_EXIST_URI');
  });

  it('list-databases / list-collections / collection-indexes work and respect the allowlist', async () => {
    const dbs = await call('list-databases', { connection: 'test-prod' });
    expect(dbs.payload.databases).toEqual([DB]);

    const colls = await call('list-collections', { connection: 'test-prod', database: DB });
    const names = (colls.payload.collections as { name: string }[]).map((c) => c.name);
    expect(names).toEqual(['customers', 'orders']); // "secrets" filtered out

    const dev = await call('list-collections', { connection: 'test-dev', database: DB });
    expect((dev.payload.collections as { name: string }[]).map((c) => c.name)).toContain('secrets');

    const idx = await call('collection-indexes', { connection: 'test-prod', database: DB, collection: 'orders' });
    expect((idx.payload.indexes as { name: string }[]).map((i) => i.name)).toEqual(['_id_']);
  });

  it('find returns bounded, Extended-JSON documents and honours filters/projection/sort', async () => {
    const r = await call('find', {
      connection: 'test-dev',
      database: DB,
      collection: 'orders',
      filter: { status: 'active', createdAt: { $gte: { $date: '2026-01-10T00:00:00Z' } } },
      projection: { name: 1, budget: 1, createdAt: 1 },
      sort: { budget: -1 },
      limit: 5,
    });
    expect(r.isError).toBe(false);
    expect(r.payload.returned).toBe(5);
    expect(r.payload.hasMore).toBe(true);
    const docs = r.payload.documents as { _id: { $oid: string }; budget: number; createdAt: { $date: string }; status?: string }[];
    expect(docs[0]!._id.$oid).toMatch(/^[0-9a-f]{24}$/);
    expect(docs[0]!.createdAt.$date).toMatch(/^2026-/);
    expect(docs[0]!.status).toBeUndefined(); // projected away
    expect(docs.map((d) => d.budget)).toEqual([...docs.map((d) => d.budget)].sort((a, b) => b - a));
  });

  it('enforces the maximum limit and maxTimeMS by clamping', async () => {
    const r = await call('find', { connection: 'test-dev', database: DB, collection: 'orders', limit: 5000, maxTimeMS: 999_999 });
    expect(r.payload.limit).toBe(60 > 100 ? 100 : 100);
    expect(r.payload.returned).toBe(60);
    expect(r.payload.notes).toEqual(expect.arrayContaining([expect.stringMatching(/limit clamped from 5000 to 100/), expect.stringMatching(/maxTimeMS clamped/)]));
  });

  it('find resolves Extended JSON ObjectIds', async () => {
    const r = await call('find', { connection: 'test-prod', database: DB, collection: 'orders', filter: { _id: { $oid: orderIds[7]!.toHexString() } }, limit: 1 });
    expect(r.isError).toBe(false);
    expect(r.payload.returned).toBe(1);
    expect((r.payload.documents as { name: string }[])[0]!.name).toBe('Order 7');
  });

  it('refuses server-side JavaScript in filters', async () => {
    const r = await call('find', { connection: 'test-dev', database: DB, collection: 'orders', filter: { $where: 'this.budget > 1' } });
    expect(r.isError).toBe(true);
    expect(r.payload.error).toBe('FORBIDDEN_OPERATOR');
  });

  it('refuses $out and $merge end-to-end, so writes cannot happen through aggregate', async () => {
    const out = await call('aggregate', { connection: 'test-dev', database: DB, collection: 'orders', pipeline: [{ $match: {} }, { $out: 'stolen' }] });
    expect(out.payload.error).toBe('FORBIDDEN_STAGE');
    const merge = await call('aggregate', { connection: 'test-dev', database: DB, collection: 'orders', pipeline: [{ $merge: { into: 'customers' } }] });
    expect(merge.payload.error).toBe('FORBIDDEN_STAGE');
    const names = (await admin.db(DB).listCollections().toArray()).map((c) => c.name);
    expect(names).not.toContain('stolen');
    expect(await admin.db(DB).collection('customers').countDocuments()).toBe(2);
  });

  it('refuses $lookup into a collection outside the allowlist', async () => {
    const r = await call('aggregate', {
      connection: 'test-prod',
      database: DB,
      collection: 'orders',
      pipeline: [{ $match: { status: 'active' } }, { $lookup: { from: 'secrets', pipeline: [], as: 's' } }],
    });
    expect(r.payload.error).toBe('COLLECTION_NOT_ALLOWED');
  });

  it('aggregate runs read-only pipelines with a trailing limit', async () => {
    const r = await call('aggregate', {
      connection: 'test-dev',
      database: DB,
      collection: 'orders',
      pipeline: [
        { $lookup: { from: 'customers', localField: 'customerId', foreignField: '_id', as: 'customer' } },
        { $unwind: '$customer' },
        { $group: { _id: { customer: '$customer.name', status: '$status' }, total: { $sum: '$budget' }, n: { $sum: 1 } } },
        { $sort: { total: -1 } },
      ],
    });
    expect(r.isError).toBe(false);
    expect(r.payload.returned).toBe(2);
    expect(r.payload.hasMore).toBe(false);
  });

  describe('production policies', () => {
    it('rejects a filtered find that would COLLSCAN, and explains why', async () => {
      const r = await call('find', { connection: 'test-prod', database: DB, collection: 'orders', filter: { status: 'active' } });
      expect(r.isError).toBe(true);
      expect(r.payload.error).toBe('COLLSCAN_REJECTED');
      expect(String(r.payload.message)).toMatch(/full collection scan/);
      expect(String(r.payload.message)).toMatch(/_id_/); // lists available indexes
    });

    it('rejects a sort on an unindexed field even with an empty filter', async () => {
      const r = await call('find', { connection: 'test-prod', database: DB, collection: 'orders', sort: { budget: -1 } });
      expect(r.payload.error).toBe('COLLSCAN_REJECTED');
    });

    it('allows bounded unfiltered finds and _id lookups', async () => {
      const all = await call('find', { connection: 'test-prod', database: DB, collection: 'orders', limit: 3 });
      expect(all.isError).toBe(false);
      expect(all.payload.returned).toBe(3);
      const byId = await call('find', { connection: 'test-prod', database: DB, collection: 'orders', filter: { _id: { $oid: orderIds[0]!.toHexString() } } });
      expect(byId.isError).toBe(false);
      expect(byId.payload.returned).toBe(1);
    });

    it('count with an empty filter is served from metadata; filtered count is guarded', async () => {
      const est = await call('count', { connection: 'test-prod', database: DB, collection: 'orders' });
      expect(est.payload).toMatchObject({ count: 60, estimated: true });
      const exact = await call('count', { connection: 'test-prod', database: DB, collection: 'orders', filter: { status: 'active' } });
      expect(exact.payload.error).toBe('COLLSCAN_REJECTED');
    });

    it('explain reports the plan without executing and flags the would-be rejection', async () => {
      const r = await call('explain', { connection: 'test-prod', database: DB, collection: 'orders', operation: 'find', filter: { status: 'active' } });
      expect(r.isError).toBe(false);
      expect(r.payload.summary).toMatchObject({ collscan: true, wouldBeRejectedOnThisConnection: true });
      expect(JSON.stringify(r.payload)).not.toContain('serverInfo');
    });

    it('accepts the same queries once an index exists', async () => {
      await admin.db(DB).collection('orders').createIndex({ status: 1, budget: -1 });
      const find = await call('find', { connection: 'test-prod', database: DB, collection: 'orders', filter: { status: 'active' }, sort: { budget: -1 }, limit: 4 });
      expect(find.isError).toBe(false);
      expect(find.payload.returned).toBe(4);
      const count = await call('count', { connection: 'test-prod', database: DB, collection: 'orders', filter: { status: 'active' } });
      expect(count.payload).toMatchObject({ count: 20, estimated: false });
      const grouped = await call('aggregate', { connection: 'test-prod', database: DB, collection: 'orders', pipeline: [{ $match: { status: { $in: ['active', 'paused'] } } }, { $group: { _id: '$status' } }] });
      expect(grouped.isError).toBe(false);
      expect((grouped.payload.documents as { _id: string }[]).map((d) => d._id).sort()).toEqual(['active', 'paused']);
      const explain = await call('explain', { connection: 'test-prod', database: DB, collection: 'orders', operation: 'find', filter: { status: 'active' } });
      expect((explain.payload.summary as { collscan: boolean; indexesUsed: string[] }).collscan).toBe(false);
      expect((explain.payload.summary as { indexesUsed: string[] }).indexesUsed).toEqual(['status_1_budget_-1']);
    });
  });

  it('collection-schema reports field paths and types without any values', async () => {
    const r = await call('collection-schema', { connection: 'test-dev', database: DB, collection: 'orders', sampleSize: 20 });
    expect(r.isError).toBe(false);
    expect(r.payload.sampled).toBe(20);
    const byPath = Object.fromEntries((r.payload.fields as { path: string; types: Record<string, number>; presence: number }[]).map((f) => [f.path, f]));
    expect(Object.keys(byPath).sort()).toEqual(['_id', 'budget', 'createdAt', 'customerId', 'name', 'status']);
    expect(byPath._id!.types).toEqual({ objectId: 20 });
    expect(byPath.createdAt!.types).toEqual({ date: 20 });
    expect(byPath.budget!.types).toEqual({ int: 20 });
    expect(byPath.status!.presence).toBe(1);
    expect(JSON.stringify(r.payload)).not.toMatch(/Order \d|active|paused/);
  });

  it('collection-schema respects the allowlist and the COLLSCAN guard', async () => {
    expect((await call('collection-schema', { connection: 'test-prod', database: DB, collection: 'secrets' })).payload.error).toBe('COLLECTION_NOT_ALLOWED');
    expect((await call('collection-schema', { connection: 'test-prod', database: DB, collection: 'customers', filter: { name: 'Acme' } })).payload.error).toBe('COLLSCAN_REJECTED');
  });

  it('collection-storage-size and db-stats return sizes, not data', async () => {
    const size = await call('collection-storage-size', { connection: 'test-prod', database: DB, collection: 'orders', scale: 'bytes' });
    expect(size.isError).toBe(false);
    expect(size.payload).toMatchObject({ count: 60, unit: 'bytes' });
    expect(size.payload.size).toBeGreaterThan(0);
    expect(Object.keys(size.payload.indexSizes as object)).toContain('_id_');
    expect((await call('collection-storage-size', { connection: 'test-prod', database: DB, collection: 'secrets' })).payload.error).toBe('COLLECTION_NOT_ALLOWED');

    const stats = await call('db-stats', { connection: 'test-prod', database: DB });
    expect(stats.isError).toBe(false);
    expect(stats.payload.collections).toBeGreaterThanOrEqual(3);
    expect(stats.payload.objects).toBeGreaterThanOrEqual(63);
    expect(JSON.stringify(stats.payload)).not.toContain('secrets');
    expect((await call('db-stats', { connection: 'test-prod', database: 'admin' })).payload.error).toBe('DATABASE_NOT_ALLOWED');
  });

  describe('with a database user that CAN write', () => {
    // The local mongod runs without auth, so this connection has full write privileges —
    // the same situation as a read-write Atlas user configured on the VM.
    const snapshot = async (): Promise<string> => {
      const db = admin.db(DB);
      const names = (await db.listCollections({}, { nameOnly: true }).toArray()).map((c) => c.name).sort();
      const parts: string[] = [];
      for (const n of names) {
        const docs = await db.collection(n).find({}, { sort: { _id: 1 } }).toArray();
        const indexes = (await db.collection(n).indexes()).map((i) => i.name).sort();
        parts.push(`${n}:${JSON.stringify(docs)}:${indexes.join(',')}`);
      }
      const dbs = (await admin.db('admin').command({ listDatabases: 1, nameOnly: true })).databases.map((d: { name: string }) => d.name).sort();
      return JSON.stringify({ parts, dbs });
    };

    const base = { connection: 'test-dev', database: DB, collection: 'orders' };
    const hostile: [string, Record<string, unknown>][] = [
      ['aggregate', { ...base, pipeline: [{ $out: 'stolen' }] }],
      ['aggregate', { ...base, pipeline: [{ $match: {} }, { $merge: { into: 'orders', whenMatched: 'replace' } }] }],
      ['aggregate', { ...base, pipeline: [{ $out: { db: 'other_db', coll: 'x' } }] }],
      ['aggregate', { ...base, pipeline: [{ $facet: { a: [{ $out: 'x' }] } }] }],
      ['aggregate', { ...base, pipeline: [{ $lookup: { from: 'customers', pipeline: [{ $merge: 'customers' }], as: 'b' } }] }],
      ['aggregate', { ...base, pipeline: [{ $unionWith: { coll: 'customers', pipeline: [{ $out: 'x' }] } }] }],
      ['aggregate', { ...base, pipeline: [{ $set: { x: { $function: { body: 'function(){db.orders.drop()}', args: [], lang: 'js' } } } }] }],
      ['aggregate', { ...base, pipeline: [{ $group: { _id: null, x: { $accumulator: { init: 'function(){}', accumulate: 'function(){}', accumulateArgs: [], merge: 'function(){}', lang: 'js' } } } }] }],
      ['aggregate', { ...base, pipeline: [{ $currentOp: {} }] }],
      ['aggregate', { ...base, pipeline: [{ $documents: [{ a: 1 }] }, { $merge: 'orders' }] }],
      ['find', { ...base, filter: { $where: 'db.orders.drop() || true' } }],
      ['find', { ...base, filter: { $expr: { $function: { body: 'function(){return true}', args: [], lang: 'js' } } } }],
      ['count', { ...base, filter: { $where: 'true' } }],
      ['explain', { ...base, operation: 'aggregate', pipeline: [{ $out: 'x' }] }],
      ['explain', { ...base, operation: 'aggregate', verbosity: 'executionStats', pipeline: [{ $merge: 'x' }] }],
      ['collection-schema', { ...base, filter: { $where: 'true' } }],
    ];

    it('refuses every write-shaped request and leaves the database byte-for-byte unchanged', async () => {
      const before = await snapshot();
      for (const [tool, args] of hostile) {
        const r = await call(tool, args);
        expect(r.isError, `${tool} ${JSON.stringify(args)}`).toBe(true);
        expect(['FORBIDDEN_STAGE', 'FORBIDDEN_OPERATOR', 'INVALID_INPUT']).toContain(r.payload.error);
      }
      expect(await snapshot()).toBe(before);
    });

    it('sent no command outside the read allowlist during the whole suite', () => {
      expect(unexpected).toEqual([]);
    });

    it('the tripwire does fire when a write reaches the driver', async () => {
      const seen: UnexpectedCommand[] = [];
      const probe = new ClientManager({ serverSelectionTimeoutMS: 3_000, onUnexpectedCommand: (e) => seen.push(e) });
      try {
        // Bypass the facade on purpose, as a bug would.
        const raw = await (probe as unknown as { client(c: unknown): Promise<MongoClient> }).client(conn('test-dev', { production: false, allowedDatabases: [DB], allowedCollections: ['*'] }));
        await raw.db(DB).collection('tripwire').insertOne({ a: 1 });
        expect(seen.map((e) => e.commandName)).toContain('insert');
      } finally {
        await admin.db(DB).collection('tripwire').drop().catch(() => undefined);
        await probe.closeAll();
      }
    });
  });

  it('writes a redacted audit trail covering successes and rejections', async () => {
    const lines = fs.readFileSync(auditPath, 'utf8').trim().split('\n').map((l) => JSON.parse(l) as Record<string, unknown>);
    expect(lines.length).toBeGreaterThan(20);
    const all = fs.readFileSync(auditPath, 'utf8');
    expect(all).not.toContain('mongodb://');
    expect(all).not.toContain('127.0.0.1');
    const rejected = lines.filter((l) => l.rejected === true);
    const codes = new Set(rejected.map((l) => l.rejectionCode));
    for (const c of ['CONNECTION_NOT_ALLOWED', 'DATABASE_NOT_ALLOWED', 'COLLECTION_NOT_ALLOWED', 'FORBIDDEN_STAGE', 'FORBIDDEN_OPERATOR', 'COLLSCAN_REJECTED', 'ENV_MISSING']) {
      expect(codes.has(c), `audit should contain a ${c} rejection`).toBe(true);
    }
    const ok = lines.find((l) => l.tool === 'find' && l.ok === true) as Record<string, unknown>;
    expect(ok).toMatchObject({ connection: expect.any(String), database: DB, collection: 'orders', operation: 'find' });
    expect(typeof ok.durationMs).toBe('number');
    expect(typeof ok.resultCount).toBe('number');
    expect(ok.params).toBeTruthy();
  });
});
