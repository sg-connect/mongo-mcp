import { describe, expect, it } from 'vitest';
import { ConnectionRegistry, requireCollection, requireDatabase } from '../src/security/allowlist.js';
import { ValidationError } from '../src/types.js';
import { conn } from './helpers.js';

describe('connection allowlist', () => {
  const registry = new ConnectionRegistry([conn('shop-prod'), conn('shop-stage')]);

  it('resolves configured connections', () => {
    expect(registry.require('shop-prod').name).toBe('shop-prod');
    expect(registry.names()).toEqual(['shop-prod', 'shop-stage']);
  });

  it('rejects unknown connections', () => {
    expect(() => registry.require('unknown-prod')).toThrowError(ValidationError);
    expect(() => registry.require('unknown-prod')).toThrow(/Unknown connection "unknown-prod"/);
    expect(() => registry.require(undefined)).toThrow(ValidationError);
    expect(() => registry.require({ toString: () => 'shop-prod' })).toThrow(ValidationError);
  });
});

describe('database allowlist', () => {
  const c = conn('shop-prod');

  it('accepts allowed databases', () => {
    expect(requireDatabase(c, 'shop')).toBe('shop');
  });

  it('rejects databases not on the allowlist', () => {
    expect(() => requireDatabase(c, 'admin')).toThrow(/not allowed on connection "shop-prod"/);
    expect(() => requireDatabase(c, 'local')).toThrow(ValidationError);
    expect(() => requireDatabase(c, 'config')).toThrow(ValidationError);
  });

  it('rejects malformed names', () => {
    expect(() => requireDatabase(c, '')).toThrow(ValidationError);
    expect(() => requireDatabase(c, 'shop$')).toThrow(ValidationError);
    expect(() => requireDatabase(c, 'a/b')).toThrow(ValidationError);
    expect(() => requireDatabase(c, 42)).toThrow(ValidationError);
  });
});

describe('collection allowlist', () => {
  const c = conn('shop-prod');

  it('accepts allowed collections', () => {
    expect(requireCollection(c, 'orders')).toBe('orders');
  });

  it('rejects collections not on the allowlist', () => {
    expect(() => requireCollection(c, 'users')).toThrow(/Collection "users" is not allowed/);
    expect(() => requireCollection(c, 'system.users')).toThrow(ValidationError);
    expect(() => requireCollection(c, 'system.js')).toThrow(ValidationError);
  });

  it('wildcard is honoured only for non-production connections', () => {
    const dev = conn('local', { production: false, allowedCollections: ['*'] });
    expect(requireCollection(dev, 'anything')).toBe('anything');
    expect(() => requireCollection(dev, 'system.profile')).toThrow(ValidationError);

    const prod = conn('shop-prod', { production: true, allowedCollections: ['*'] });
    expect(() => requireCollection(prod, 'anything')).toThrow(/not allowed/);
  });
});
