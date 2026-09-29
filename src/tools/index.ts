import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { ToolContext } from './context.js';
import { registerAggregateTools } from './aggregate.js';
import { registerCollectionTools } from './collections.js';
import { registerConnectionTools } from './connections.js';
import { registerCountTools } from './count.js';
import { registerExplainTool } from './explain.js';
import { registerFindTools } from './find.js';
import { registerIndexTools } from './indexes.js';
import { registerStatsTools } from './stats.js';

/**
 * The complete, closed set of tools this server exposes. Adding a tool here is
 * a security-relevant change: see CLAUDE.md.
 */
export const EXPOSED_TOOLS = [
  'list-connections',
  'list-databases',
  'list-collections',
  'collection-indexes',
  'collection-schema',
  'collection-storage-size',
  'db-stats',
  'find',
  'count',
  'aggregate',
  'explain',
] as const;

export function registerAllTools(server: McpServer, ctx: ToolContext): void {
  registerConnectionTools(server, ctx);
  registerCollectionTools(server, ctx);
  registerIndexTools(server, ctx);
  registerStatsTools(server, ctx);
  registerFindTools(server, ctx);
  registerCountTools(server, ctx);
  registerAggregateTools(server, ctx);
  registerExplainTool(server, ctx);
}
