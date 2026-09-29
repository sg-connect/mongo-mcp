import { describe, expect, it } from 'vitest';
import { collectPlanStages, hasCollscan, indexesUsed } from '../src/security/collscan.js';

// Shapes captured from real explain() outputs (trimmed).
const classicFindCollscan = {
  queryPlanner: {
    namespace: 'shop.orders',
    winningPlan: { stage: 'LIMIT', limitAmount: 20, inputStage: { stage: 'COLLSCAN', filter: { status: { $eq: 'active' } }, direction: 'forward' } },
    rejectedPlans: [],
  },
};

const sbeFindIxscan = {
  queryPlanner: {
    winningPlan: {
      queryPlan: { stage: 'FETCH', inputStage: { stage: 'IXSCAN', indexName: 'status_1', keyPattern: { status: 1 } } },
      slotBasedPlan: { stages: 'irrelevant text' },
    },
    rejectedPlans: [{ queryPlan: { stage: 'COLLSCAN' } }],
  },
};

const aggregateWithCursor = {
  stages: [
    { $cursor: { queryPlanner: { winningPlan: { stage: 'COLLSCAN', direction: 'forward' } } } },
    { $group: { _id: '$customer' } },
  ],
};

const shardedFind = {
  queryPlanner: {
    winningPlan: {
      stage: 'SHARD_MERGE',
      shards: [
        { shardName: 'shard0', winningPlan: { stage: 'FETCH', inputStage: { stage: 'IXSCAN', indexName: '_id_' } } },
        { shardName: 'shard1', winningPlan: { stage: 'COLLSCAN' } },
      ],
    },
  },
};

describe('explain plan walker', () => {
  it('detects COLLSCAN in a classic find plan', () => {
    expect(hasCollscan(classicFindCollscan)).toBe(true);
    expect(collectPlanStages(classicFindCollscan)).toEqual(['COLLSCAN', 'LIMIT']);
  });

  it('does not count rejected plans', () => {
    expect(hasCollscan(sbeFindIxscan)).toBe(false);
    expect(collectPlanStages(sbeFindIxscan)).toEqual(['FETCH', 'IXSCAN']);
    expect(indexesUsed(sbeFindIxscan)).toEqual(['status_1']);
  });

  it('finds the $cursor stage inside aggregate explains', () => {
    expect(hasCollscan(aggregateWithCursor)).toBe(true);
  });

  it('inspects every shard of a sharded plan', () => {
    expect(hasCollscan(shardedFind)).toBe(true);
    expect(indexesUsed(shardedFind)).toEqual(['_id_']);
  });

  it('is quiet on empty/irrelevant input', () => {
    expect(hasCollscan({})).toBe(false);
    expect(hasCollscan(null)).toBe(false);
    expect(collectPlanStages({ ok: 1, serverInfo: { host: 'x' } })).toEqual([]);
  });
});
