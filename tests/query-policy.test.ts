import { describe, expect, it } from 'vitest';
import { DEFAULT_LIMIT, DEFAULT_MAX_TIME_MS, HARD_MAX_LIMIT, HARD_MAX_SKIP, HARD_MAX_TIME_MS, effectiveLimits, resolveConnection } from '../src/security/query-policy.js';
import { conn } from './helpers.js';

describe('resolveConnection', () => {
  it('applies defaults', () => {
    const c = conn('shop-stage', { production: false });
    expect(c.defaultLimit).toBe(DEFAULT_LIMIT);
    expect(c.maxLimit).toBe(HARD_MAX_LIMIT);
    expect(c.maxTimeMS).toBe(DEFAULT_MAX_TIME_MS);
    expect(c.rejectCollscan).toBe(false);
    expect(c.readPreference).toBe('primary');
  });

  it('infers production from the name and turns on strict defaults', () => {
    const c = conn('shop-prod');
    expect(c.production).toBe(true);
    expect(c.rejectCollscan).toBe(true);
    expect(c.readPreference).toBe('secondaryPreferred');
    expect(conn('shop-production').production).toBe(true);
    expect(conn('prod_reporting').production).toBe(true);
    expect(conn('product-catalog-stage').production).toBe(false);
  });

  it('never lets config exceed the hard ceilings', () => {
    const c = resolveConnection('x', { uriEnv: 'E', allowedDatabases: ['d'], allowedCollections: ['c'], maxLimit: 10_000, defaultLimit: 5_000, maxTimeMS: 600_000 });
    expect(c.maxLimit).toBe(HARD_MAX_LIMIT);
    expect(c.defaultLimit).toBe(HARD_MAX_LIMIT);
    expect(c.maxTimeMS).toBe(HARD_MAX_TIME_MS);
  });

  it('lets config tighten limits', () => {
    const c = conn('tight', { maxLimit: 10, defaultLimit: 50, maxTimeMS: 2_000 });
    expect(c.maxLimit).toBe(10);
    expect(c.defaultLimit).toBe(10); // clamped to maxLimit
    expect(c.maxTimeMS).toBe(2_000);
  });
});

describe('effectiveLimits', () => {
  const c = conn('shop-prod');

  it('uses the default limit when none is requested', () => {
    expect(effectiveLimits(c, {})).toMatchObject({ limit: DEFAULT_LIMIT, skip: 0, maxTimeMS: DEFAULT_MAX_TIME_MS, notes: [] });
  });

  it('enforces the maximum limit', () => {
    const r = effectiveLimits(c, { limit: 5_000 });
    expect(r.limit).toBe(HARD_MAX_LIMIT);
    expect(r.notes[0]).toMatch(/limit clamped from 5000 to 100/);
    expect(effectiveLimits(c, { limit: 0 }).limit).toBe(1);
    expect(effectiveLimits(c, { limit: -7 }).limit).toBe(1);
    expect(effectiveLimits(c, { limit: 42 }).limit).toBe(42);
  });

  it('enforces maxTimeMS', () => {
    const r = effectiveLimits(c, { maxTimeMS: 999_999 });
    expect(r.maxTimeMS).toBe(c.maxTimeMS);
    expect(r.notes[0]).toMatch(/maxTimeMS clamped/);
    expect(effectiveLimits(c, { maxTimeMS: 500 }).maxTimeMS).toBe(500);
  });

  it('bounds skip', () => {
    expect(effectiveLimits(c, { skip: 1_000_000 }).skip).toBe(HARD_MAX_SKIP);
    expect(effectiveLimits(c, { skip: -1 }).skip).toBe(0);
  });
});
