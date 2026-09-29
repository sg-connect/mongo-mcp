import { describe, expect, it } from 'vitest';
import { assertNoForbiddenOperators, validateFilter, validateHint, validatePipeline, validateProjection, validateSort } from '../src/security/validator.js';
import { ValidationError } from '../src/types.js';
import { conn } from './helpers.js';

const c = conn('shop-prod');

describe('find filters', () => {
  it('accepts ordinary filters, including Extended JSON and $expr', () => {
    expect(validateFilter({ status: 'active' })).toEqual({ status: 'active' });
    expect(validateFilter({ _id: { $oid: '65f1c0a3e4b0f7d2c8a1b2c3' } })).toBeTruthy();
    expect(validateFilter({ $and: [{ a: { $gt: 1 } }, { b: { $in: [1, 2] } }] })).toBeTruthy();
    expect(validateFilter({ $expr: { $gt: ['$spent', '$budget'] } })).toBeTruthy();
    expect(validateFilter(undefined)).toEqual({});
  });

  it('rejects server-side JavaScript anywhere in the document', () => {
    expect(() => validateFilter({ $where: 'this.a > 1' })).toThrow(/\$where/);
    expect(() => validateFilter({ $and: [{ a: 1 }, { $where: 'sleep(1000)' }] })).toThrow(ValidationError);
    expect(() => validateFilter({ $expr: { $function: { body: 'x', args: [], lang: 'js' } } })).toThrow(/\$function/);
    expect(() => validateProjection({ total: { $function: { body: 'x', args: [], lang: 'js' } } })).toThrow(/\$function/);
  });

  it('rejects non-object filters', () => {
    expect(() => validateFilter('status: active')).toThrow(ValidationError);
    expect(() => validateFilter([{ a: 1 }])).toThrow(ValidationError);
  });

  it('caps nesting depth', () => {
    let deep: Record<string, unknown> = { leaf: 1 };
    for (let i = 0; i < 40; i++) deep = { $and: [deep] };
    expect(() => assertNoForbiddenOperators(deep)).toThrow(/nesting/);
  });
});

describe('sort / hint / projection', () => {
  it('validates sort values', () => {
    expect(validateSort({ createdAt: -1, name: 1 })).toEqual({ createdAt: -1, name: 1 });
    expect(validateSort({ score: { $meta: 'textScore' } })).toBeTruthy();
    expect(() => validateSort({ createdAt: 'down' })).toThrow(ValidationError);
    expect(validateSort({})).toBeUndefined();
  });

  it('validates hints', () => {
    expect(validateHint('customer_1_createdAt_-1')).toBe('customer_1_createdAt_-1');
    expect(validateHint({ customer: 1 })).toEqual({ customer: 1 });
    expect(() => validateHint('$natural; drop')).toThrow(ValidationError);
    expect(() => validateHint({ customer: { $function: 1 } })).toThrow(ValidationError);
  });
});

describe('aggregation pipelines', () => {
  it('accepts read-only pipelines', () => {
    const pipeline = [
      { $match: { status: 'active' } },
      { $lookup: { from: 'customers', localField: 'customerId', foreignField: '_id', as: 'customer' } },
      { $unwind: '$customer' },
      { $group: { _id: '$customer.name', n: { $sum: 1 } } },
      { $sort: { n: -1 } },
      { $limit: 10 },
    ];
    expect(validatePipeline(pipeline, c)).toHaveLength(6);
  });

  it('rejects $out', () => {
    expect(() => validatePipeline([{ $match: {} }, { $out: 'stolen' }], c)).toThrow(/\$out is not allowed/);
    expect(() => validatePipeline([{ $out: { db: 'shop', coll: 'x' } }], c)).toThrow(ValidationError);
  });

  it('rejects $merge', () => {
    expect(() => validatePipeline([{ $match: {} }, { $merge: { into: 'orders' } }], c)).toThrow(/\$merge is not allowed/);
  });

  it('rejects $out/$merge hidden in sub-pipelines', () => {
    expect(() => validatePipeline([{ $facet: { a: [{ $out: 'x' }] } }], c)).toThrow(/\$out/);
    expect(() => validatePipeline([{ $lookup: { from: 'customers', pipeline: [{ $merge: { into: 'x' } }], as: 'b' } }], c)).toThrow(/\$merge/);
    expect(() => validatePipeline([{ $unionWith: { coll: 'customers', pipeline: [{ $out: 'x' }] } }], c)).toThrow(/\$out/);
  });

  it('rejects server-side JavaScript stages and operators', () => {
    expect(() => validatePipeline([{ $group: { _id: null, v: { $accumulator: { init: 'x', accumulate: 'y', accumulateArgs: [], merge: 'z', lang: 'js' } } } }], c)).toThrow(/\$accumulator/);
    expect(() => validatePipeline([{ $addFields: { v: { $function: { body: 'x', args: [], lang: 'js' } } } }], c)).toThrow(/\$function/);
    expect(() => validatePipeline([{ $match: { $where: '1' } }], c)).toThrow(/\$where/);
  });

  it('rejects admin / introspection stages and anything not on the allowlist', () => {
    for (const stage of ['$currentOp', '$listSessions', '$listLocalSessions', '$planCacheStats', '$changeStream', '$querySettings']) {
      expect(() => validatePipeline([{ [stage]: {} }], c)).toThrow(ValidationError);
    }
    expect(() => validatePipeline([{ $madeUpStage: {} }], c)).toThrow(/not on the read-only allowlist/);
  });

  it('enforces the collection allowlist on $lookup / $graphLookup / $unionWith', () => {
    expect(() => validatePipeline([{ $lookup: { from: 'users', localField: 'a', foreignField: 'b', as: 'u' } }], c)).toThrow(/references collection "users"/);
    expect(() => validatePipeline([{ $graphLookup: { from: 'secrets', startWith: '$a', connectFromField: 'a', connectToField: 'b', as: 'x' } }], c)).toThrow(/COLLECTION_NOT_ALLOWED|not allowed/);
    expect(() => validatePipeline([{ $unionWith: 'users' }], c)).toThrow(/not allowed/);
    expect(() => validatePipeline([{ $unionWith: { coll: 'users' } }], c)).toThrow(/not allowed/);
    expect(() => validatePipeline([{ $lookup: { from: { db: 'admin', coll: 'system.users' }, pipeline: [], as: 'x' } }], c)).toThrow(/database "admin"/);
    // allowed target passes
    expect(validatePipeline([{ $unionWith: 'products' }], c)).toHaveLength(1);
  });

  it('rejects malformed stages', () => {
    expect(() => validatePipeline({ $match: {} }, c)).toThrow(/must be an array/);
    expect(() => validatePipeline([{ $match: {}, $limit: 1 }], c)).toThrow(/exactly one/);
    expect(() => validatePipeline(['$match'], c)).toThrow(ValidationError);
    expect(() => validatePipeline([{ $limit: -1 }], c)).toThrow(ValidationError);
    expect(() => validatePipeline([{ $limit: 'all' }], c)).toThrow(ValidationError);
  });

  it('caps pipeline length', () => {
    const huge = Array.from({ length: 51 }, () => ({ $match: {} }));
    expect(() => validatePipeline(huge, c)).toThrow(/max is 50/);
  });
});
