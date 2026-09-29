/**
 * Infers a collection's shape from sampled documents: field paths, BSON
 * types and how often each appears. Returns no field values, so a schema
 * look is safe on collections whose contents Claude should not read.
 */
import { Binary, Decimal128, Double, Int32, Long, ObjectId, Timestamp, UUID, type Document } from 'mongodb';

export interface FieldSchema {
  path: string;
  /** BSON type name → number of sampled documents where the field had that type. */
  types: Record<string, number>;
  /** Share of sampled documents that contain the field (0–1). */
  presence: number;
}

const MAX_DEPTH = 8;
const MAX_FIELDS = 500;

export function bsonType(value: unknown): string {
  if (value === null) return 'null';
  if (value === undefined) return 'undefined';
  if (Array.isArray(value)) return 'array';
  if (value instanceof Date) return 'date';
  if (value instanceof ObjectId) return 'objectId';
  if (value instanceof UUID) return 'uuid';
  if (value instanceof Binary) return 'binData';
  if (value instanceof Decimal128) return 'decimal';
  if (value instanceof Long) return 'long';
  if (value instanceof Int32) return 'int';
  if (value instanceof Double) return 'double';
  if (value instanceof Timestamp) return 'timestamp';
  if (value instanceof RegExp) return 'regex';
  switch (typeof value) {
    case 'string':
      return 'string';
    case 'boolean':
      return 'bool';
    case 'number':
      return Number.isInteger(value) ? 'int' : 'double';
    case 'bigint':
      return 'long';
    case 'object':
      return (value as { _bsontype?: string })._bsontype?.toLowerCase() ?? 'object';
    default:
      return typeof value;
  }
}

const isPlainObject = (v: unknown): v is Document => bsonType(v) === 'object';

export function inferSchema(docs: Document[]): { fields: FieldSchema[]; truncated: boolean } {
  const seen = new Map<string, { types: Map<string, number>; docs: number }>();
  let truncated = false;

  for (const doc of docs) {
    const inThisDoc = new Set<string>();
    const walk = (obj: Document, prefix: string, depth: number): void => {
      for (const [key, value] of Object.entries(obj)) {
        const path = prefix ? `${prefix}.${key}` : key;
        let entry = seen.get(path);
        if (!entry) {
          if (seen.size >= MAX_FIELDS) {
            truncated = true;
            continue;
          }
          entry = { types: new Map(), docs: 0 };
          seen.set(path, entry);
        }
        const type = bsonType(value);
        if (!inThisDoc.has(`${path}\0${type}`)) {
          entry.types.set(type, (entry.types.get(type) ?? 0) + 1);
          inThisDoc.add(`${path}\0${type}`);
        }
        if (!inThisDoc.has(path)) {
          entry.docs++;
          inThisDoc.add(path);
        }
        if (depth >= MAX_DEPTH) continue;
        if (isPlainObject(value)) walk(value, path, depth + 1);
        else if (Array.isArray(value)) {
          // Array elements are described under "<path>[]".
          for (const el of value) {
            if (isPlainObject(el)) walk(el, `${path}[]`, depth + 1);
          }
        }
      }
    };
    walk(doc, '', 0);
  }

  const n = docs.length || 1;
  const fields = [...seen.entries()]
    .map(([path, e]) => ({ path, types: Object.fromEntries([...e.types.entries()].sort((a, b) => b[1] - a[1])), presence: Math.round((e.docs / n) * 1000) / 1000 }))
    .sort((a, b) => a.path.localeCompare(b.path));
  return { fields, truncated };
}
