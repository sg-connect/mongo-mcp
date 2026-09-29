/**
 * Scrubs anything that could leak credentials before it is logged or returned to Claude.
 *
 * Two layers:
 *  1. pattern-based: any mongodb:// or mongodb+srv:// URI, and user:pass@ fragments
 *  2. value-based: the literal values of every configured *_URI env var
 */

const URI_RE = /mongodb(?:\+srv)?:\/\/[^\s"'`<>]+/gi;
const USERINFO_RE = /\/\/[^\s/@"'`]+:[^\s/@"'`]+@/g;

export const REDACTED = '[REDACTED]';

export class Redactor {
  private readonly secrets: string[];

  constructor(secrets: Iterable<string> = []) {
    // Longest first so a secret that contains another is scrubbed whole.
    this.secrets = [...new Set([...secrets].filter((s) => s.length >= 8))].sort((a, b) => b.length - a.length);
  }

  string(input: string): string {
    let out = input;
    for (const s of this.secrets) out = out.split(s).join(REDACTED);
    out = out.replace(URI_RE, REDACTED).replace(USERINFO_RE, `//${REDACTED}@`);
    return out;
  }

  /** Deep-copies `value`, scrubbing every string leaf. Cycles are cut. */
  deep<T>(value: T, seen = new WeakSet<object>()): T {
    if (typeof value === 'string') return this.string(value) as T;
    if (value === null || typeof value !== 'object') return value;
    if (seen.has(value)) return '[Circular]' as T;
    seen.add(value);
    if (Array.isArray(value)) return value.map((v) => this.deep(v, seen)) as T;
    if (value instanceof Date) return value;
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[this.string(k)] = this.deep(v, seen);
    return out as T;
  }

  /** Error → safe single-line message. Never includes the stack. */
  error(err: unknown): string {
    if (err instanceof Error) return this.string(`${err.name}: ${err.message}`);
    return this.string(String(err));
  }
}
