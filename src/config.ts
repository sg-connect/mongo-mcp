/**
 * Locates and loads connections.json plus an optional .env file.
 *
 * Resolution order (first hit wins):
 *   connections: $MONGO_MCP_CONFIG → ~/.config/mongo-mcp/connections.json → <package>/config/connections.json
 *   env files:   $MONGO_MCP_ENV_FILE, else <package>/.env, .env.sandbox and .env.production (all that exist)
 *   users:       $MONGO_MCP_USERS_FILE → <package>/config/users.json
 *
 * The .env loader never overrides variables already present in the process
 * environment, so values set by Docker / the VM take precedence.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import type { ConnectionsConfig } from './types.js';
import { resolveConnection } from './security/query-policy.js';
import { ConnectionRegistry } from './security/allowlist.js';

export const PACKAGE_ROOT = fileURLToPath(new URL('..', import.meta.url));
const USER_CONFIG_DIR = path.join(os.homedir(), '.config', 'mongo-mcp');

const nameList = z.array(z.string().min(1)).min(1);

const connectionSchema = z
  .object({
    uriEnv: z.string().regex(/^[A-Z][A-Z0-9_]*$/, 'uriEnv must be an environment variable NAME (e.g. PRODUCTION_CLUSTER0_URI), not a URI'),
    description: z.string().max(500).optional(),
    production: z.boolean().optional(),
    allowedDatabases: nameList,
    allowedCollections: nameList,
    defaultLimit: z.number().int().positive().optional(),
    maxLimit: z.number().int().positive().optional(),
    maxTimeMS: z.number().int().positive().optional(),
    rejectCollscan: z.boolean().optional(),
    collscanMaxDocs: z.number().int().nonnegative().optional(),
    readPreference: z.enum(['primary', 'primaryPreferred', 'secondary', 'secondaryPreferred', 'nearest']).optional(),
  })
  .strict();

const configSchema = z.record(z.string().regex(/^[a-z0-9][a-z0-9_-]{0,63}$/i, 'connection names: letters, digits, - and _'), connectionSchema);

export function parseConnectionsConfig(raw: unknown): ConnectionsConfig {
  const data = raw && typeof raw === 'object' ? { ...(raw as Record<string, unknown>) } : raw;
  if (data && typeof data === 'object') delete (data as Record<string, unknown>).$comment;
  const result = configSchema.safeParse(data);
  if (!result.success) {
    const issues = result.error.issues.map((i) => `  ${i.path.join('.') || '(root)'}: ${i.message}`).join('\n');
    throw new Error(`Invalid connections config:\n${issues}`);
  }
  for (const [name, conn] of Object.entries(result.data)) {
    if (/mongodb(\+srv)?:\/\//i.test(conn.uriEnv)) throw new Error(`Connection "${name}": uriEnv contains a URI. Put the URI in the environment and reference its NAME here.`);
  }
  return result.data;
}

export function locateConfigFile(explicit?: string): string | undefined {
  const candidates = [
    explicit,
    process.env.MONGO_MCP_CONFIG,
    path.join(USER_CONFIG_DIR, 'connections.json'),
    path.join(PACKAGE_ROOT, 'config', 'connections.json'),
  ].filter((p): p is string => !!p);
  return candidates.find((p) => fs.existsSync(p));
}

export function loadRegistry(configPath?: string): { registry: ConnectionRegistry; configPath: string } {
  const found = locateConfigFile(configPath);
  if (!found) {
    throw new Error(
      'No connections config found. Create config/connections.json (see config/connections.example.json) or set MONGO_MCP_CONFIG.',
    );
  }
  const raw = JSON.parse(fs.readFileSync(found, 'utf8')) as unknown;
  const cfg = parseConnectionsConfig(raw);
  const resolved = Object.entries(cfg).map(([name, c]) => resolveConnection(name, c));
  return { registry: new ConnectionRegistry(resolved), configPath: found };
}

/** Minimal .env parser: KEY=VALUE, optional quotes, # comments. Existing env wins. */
export function applyEnvFile(file: string): string[] {
  const applied: string[] = [];
  const text = fs.readFileSync(file, 'utf8');
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!m) continue;
    const key = m[1]!;
    let value = m[2]!.trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    else value = value.replace(/\s+#.*$/, '');
    if (process.env[key] === undefined) {
      process.env[key] = value;
      applied.push(key);
    }
  }
  return applied;
}

/** The explicit file (or $MONGO_MCP_ENV_FILE) alone, else every package-root file in ENV_FILES that exists. */
export const ENV_FILES = ['.env', '.env.sandbox', '.env.production'] as const;

export function loadEnvFiles(explicit?: string): string[] {
  const chosen = explicit ?? process.env.MONGO_MCP_ENV_FILE;
  const files = chosen ? [chosen] : ENV_FILES.map((f) => path.join(PACKAGE_ROOT, f));
  const found = files.filter((p) => fs.existsSync(p));
  for (const f of found) applyEnvFile(f);
  return found;
}

export function defaultUsersFilePath(): string {
  return process.env.MONGO_MCP_USERS_FILE || path.join(PACKAGE_ROOT, 'config', 'users.json');
}

export function defaultAuditLogPath(): string {
  return process.env.MONGO_MCP_AUDIT_LOG || path.join(os.homedir(), '.mongo-mcp', 'audit.jsonl');
}
