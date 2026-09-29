import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { describe, expect, it } from 'vitest';
import { Authenticator, FailureLimiter, MIN_PASSWORD_LENGTH, hashPassword, parseBasic, parseUsers } from '../src/auth.js';
import { startHttpServer } from '../src/http.js';
import { ConnectionRegistry } from '../src/security/allowlist.js';
import { createContext } from '../src/server.js';
import { conn } from './helpers.js';

const basic = (user: string, pass: string): string => `Basic ${Buffer.from(`${user}:${pass}`).toString('base64')}`;

describe('password hashing', () => {
  it('produces salted scrypt hashes that never contain the password', () => {
    const a = hashPassword('a long enough password');
    const b = hashPassword('a long enough password');
    expect(a).toMatch(/^scrypt\$16384\$8\$1\$/);
    expect(a).not.toBe(b);
    expect(a).not.toContain('password');
  });

  it(`rejects passwords shorter than ${MIN_PASSWORD_LENGTH} characters`, () => {
    expect(() => hashPassword('short')).toThrow(/at least/);
  });
});

describe('users file', () => {
  it('accepts hashes and ignores $comment', () => {
    const users = parseUsers({ $comment: 'x', alice: hashPassword('a long enough password') });
    expect(Object.keys(users)).toEqual(['alice']);
  });

  it('refuses plain-text passwords, bad usernames and empty files', () => {
    expect(() => parseUsers({ alice: 'hunter2hunter2hunter2' })).toThrow(/never a plain password/);
    expect(() => parseUsers({ 'Alice Smith': hashPassword('a long enough password') })).toThrow(/usernames/);
    expect(() => parseUsers({})).toThrow(/no accounts/);
  });
});

describe('Basic header parsing', () => {
  it('splits on the first colon so passwords may contain colons', () => {
    expect(parseBasic(basic('alice', 'pa:ss:word'))).toEqual({ username: 'alice', password: 'pa:ss:word' });
  });

  it('rejects other schemes and malformed values', () => {
    expect(parseBasic(undefined)).toBeUndefined();
    expect(parseBasic('Bearer abc')).toBeUndefined();
    expect(parseBasic(`Basic ${Buffer.from('nocolon').toString('base64')}`)).toBeUndefined();
    expect(parseBasic(`Basic ${Buffer.from(':empty-user').toString('base64')}`)).toBeUndefined();
  });
});

describe('Authenticator', () => {
  const auth = new Authenticator({ alice: hashPassword('correct horse battery staple'), bob: hashPassword('another long password!') });

  it('returns the username for valid credentials only', () => {
    expect(auth.verify(basic('alice', 'correct horse battery staple'))).toBe('alice');
    expect(auth.verify(basic('bob', 'another long password!'))).toBe('bob');
    expect(auth.verify(basic('alice', 'another long password!'))).toBeUndefined();
    expect(auth.verify(basic('ghost', 'correct horse battery staple'))).toBeUndefined();
  });

  it('does not let a cached success leak to another password', () => {
    expect(auth.verify(basic('alice', 'correct horse battery staple'))).toBe('alice');
    expect(auth.verify(basic('alice', 'correct horse battery stapl'))).toBeUndefined();
  });
});

describe('FailureLimiter', () => {
  it('locks after maxFailures inside the window and unlocks after lockMs', () => {
    const l = new FailureLimiter(3, 60_000, 120_000);
    l.fail('1.2.3.4', 0);
    l.fail('1.2.3.4', 1);
    expect(l.lockedFor('1.2.3.4', 2)).toBe(0);
    l.fail('1.2.3.4', 3);
    expect(l.lockedFor('1.2.3.4', 4)).toBeGreaterThan(0);
    expect(l.lockedFor('5.6.7.8', 4)).toBe(0);
    expect(l.lockedFor('1.2.3.4', 3 + 120_001)).toBe(0);
  });

  it('forgets failures after a success and after the window passes', () => {
    const l = new FailureLimiter(2, 1_000, 60_000);
    l.fail('ip', 0);
    l.succeed('ip');
    l.fail('ip', 10);
    expect(l.lockedFor('ip', 11)).toBe(0);
    l.fail('ip', 5_000);
    expect(l.lockedFor('ip', 5_001)).toBe(0);
  });
});

describe('audit attribution', () => {
  it('records the authenticated username on every tool call', async () => {
    const auditPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'mongo-mcp-')), 'audit.jsonl');
    const app = createContext({ registry: new ConnectionRegistry([conn('shop-stage', { production: false })]), auditLogPath: auditPath });
    const running = await startHttpServer({ ctx: app.ctx, port: 0, auth: new Authenticator({ bob: hashPassword('another long password!') }), log: () => undefined });
    const client = new Client({ name: 'audit-test', version: '0' });
    try {
      await client.connect(new StreamableHTTPClientTransport(new URL(running.url), { requestInit: { headers: { authorization: basic('bob', 'another long password!') } } }));
      await client.callTool({ name: 'list-connections', arguments: {} });
      const records = fs.readFileSync(auditPath, 'utf8').trim().split('\n').map((l) => JSON.parse(l) as { user: string; tool: string });
      expect(records.at(-1)).toMatchObject({ user: 'bob', tool: 'list-connections' });
    } finally {
      await client.close();
      await running.close();
      await app.close();
    }
  });
});
