/**
 * Username/password authentication for the HTTP endpoint (HTTP Basic, behind TLS).
 *
 * Passwords are never stored: config/users.json maps each username to an
 * scrypt hash produced by `mongo-mcp --hash-password`. Every person gets
 * their own account so the audit log says who ran what.
 *
 *   { "alice": "scrypt$16384$8$1$<salt b64>$<hash b64>" }
 *
 * Unknown usernames are verified against a dummy hash so response timing does
 * not reveal which accounts exist. Successful verifications are cached for a
 * few minutes (keyed by a hash of the credentials) because stateless MCP
 * authenticates every request and scrypt is deliberately slow.
 */
import { createHash, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import fs from 'node:fs';
import { z } from 'zod';

const SCRYPT = { N: 16384, r: 8, p: 1, keyLen: 32 } as const;
export const MIN_PASSWORD_LENGTH = 16;
const USERNAME_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const HASH_RE = /^scrypt\$(\d+)\$(\d+)\$(\d+)\$([A-Za-z0-9+/=]+)\$([A-Za-z0-9+/=]+)$/;
const CACHE_TTL_MS = 5 * 60_000;
const CACHE_MAX = 256;

export function hashPassword(password: string): string {
  if (password.length < MIN_PASSWORD_LENGTH) throw new Error(`password must be at least ${MIN_PASSWORD_LENGTH} characters`);
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, SCRYPT.keyLen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p });
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64')}$${hash.toString('base64')}`;
}

function verifyHash(password: string, stored: string): boolean {
  const m = HASH_RE.exec(stored);
  if (!m) return false;
  const [, n, r, p, salt, hash] = m;
  const expected = Buffer.from(hash!, 'base64');
  const actual = scryptSync(password, Buffer.from(salt!, 'base64'), expected.length, { N: Number(n), r: Number(r), p: Number(p), maxmem: 64 * 1024 * 1024 });
  return timingSafeEqual(actual, expected);
}

const usersSchema = z.record(z.string(), z.string().regex(HASH_RE, 'value must be a hash from `mongo-mcp --hash-password`, never a plain password'));

export function parseUsers(raw: unknown): Record<string, string> {
  const data = raw && typeof raw === 'object' ? { ...(raw as Record<string, unknown>) } : raw;
  if (data && typeof data === 'object') delete (data as Record<string, unknown>).$comment;
  const result = usersSchema.safeParse(data);
  if (!result.success) {
    const issues = result.error.issues.map((i) => `  ${i.path.join('.') || '(root)'}: ${i.message}`).join('\n');
    throw new Error(`Invalid users file:\n${issues}`);
  }
  const bad = Object.keys(result.data).filter((u) => !USERNAME_RE.test(u));
  if (bad.length) throw new Error(`Invalid users file: usernames must be lowercase letters, digits, . _ - (got ${bad.map((u) => JSON.stringify(u)).join(', ')})`);
  if (Object.keys(result.data).length === 0) throw new Error('Users file has no accounts.');
  return result.data;
}

export function loadUsersFile(file: string): Record<string, string> {
  if (!fs.existsSync(file)) throw new Error(`Users file not found: ${file}. Create it with \`mongo-mcp --hash-password <username>\`.`);
  return parseUsers(JSON.parse(fs.readFileSync(file, 'utf8')) as unknown);
}

/** Parses `Authorization: Basic <base64(user:pass)>`. */
export function parseBasic(header: string | undefined): { username: string; password: string } | undefined {
  const m = header ? /^Basic\s+([A-Za-z0-9+/=]+)$/i.exec(header) : null;
  if (!m) return undefined;
  const decoded = Buffer.from(m[1]!, 'base64').toString('utf8');
  const i = decoded.indexOf(':');
  if (i <= 0) return undefined;
  return { username: decoded.slice(0, i), password: decoded.slice(i + 1) };
}

export class Authenticator {
  private readonly users: ReadonlyMap<string, string>;
  private readonly dummy = hashPassword(randomBytes(24).toString('base64'));
  private readonly cache = new Map<string, { username: string; expires: number }>();

  constructor(users: Record<string, string>) {
    this.users = new Map(Object.entries(users));
  }

  get size(): number {
    return this.users.size;
  }

  /** Returns the username when the header carries valid credentials. */
  verify(header: string | undefined, now = Date.now()): string | undefined {
    const creds = parseBasic(header);
    if (!creds) return undefined;
    const key = createHash('sha256').update(`${creds.username}\0${creds.password}`).digest('base64');
    const hit = this.cache.get(key);
    if (hit && hit.expires > now) return hit.username;

    const stored = this.users.get(creds.username);
    const ok = verifyHash(creds.password, stored ?? this.dummy) && stored !== undefined;
    if (!ok) return undefined;

    if (this.cache.size >= CACHE_MAX) this.cache.delete(this.cache.keys().next().value!);
    this.cache.set(key, { username: creds.username, expires: now + CACHE_TTL_MS });
    return creds.username;
  }
}

/**
 * Per-client-IP lockout: after `maxFailures` failed logins inside `windowMs`,
 * that IP gets 429 for `lockMs`. Keeps online guessing slow even though each
 * attempt already costs an scrypt.
 */
export class FailureLimiter {
  private readonly entries = new Map<string, { failures: number; windowStart: number; lockedUntil: number }>();

  constructor(
    private readonly maxFailures = 10,
    private readonly windowMs = 5 * 60_000,
    private readonly lockMs = 15 * 60_000,
  ) {}

  lockedFor(ip: string, now = Date.now()): number {
    const e = this.entries.get(ip);
    return e && e.lockedUntil > now ? Math.ceil((e.lockedUntil - now) / 1000) : 0;
  }

  fail(ip: string, now = Date.now()): void {
    let e = this.entries.get(ip);
    if (!e || now - e.windowStart > this.windowMs) {
      e = { failures: 0, windowStart: now, lockedUntil: 0 };
      this.entries.set(ip, e);
    }
    e.failures++;
    if (e.failures >= this.maxFailures) e.lockedUntil = now + this.lockMs;
    if (this.entries.size > 10_000) this.prune(now);
  }

  succeed(ip: string): void {
    this.entries.delete(ip);
  }

  private prune(now: number): void {
    for (const [ip, e] of this.entries) if (e.lockedUntil <= now && now - e.windowStart > this.windowMs) this.entries.delete(ip);
  }
}
