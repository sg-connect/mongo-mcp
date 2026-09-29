import { resolveConnection } from '../src/security/query-policy.js';
import type { ConnectionConfig, ResolvedConnection } from '../src/types.js';

export function conn(name: string, overrides: Partial<ConnectionConfig> = {}): ResolvedConnection {
  return resolveConnection(name, {
    uriEnv: 'MONGO_MCP_TEST_URI',
    allowedDatabases: ['shop'],
    allowedCollections: ['orders', 'customers', 'products'],
    ...overrides,
  });
}
