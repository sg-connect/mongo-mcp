import { describe, expect, it } from 'vitest';
import { REDACTED, Redactor } from '../src/security/redact.js';

const uri = 'mongodb+srv://fake_user:NotARealPassword@cluster.example.invalid/?retryWrites=false';

describe('Redactor', () => {
  const r = new Redactor([uri]);

  it('scrubs configured secret values', () => {
    expect(r.string(`failed to connect using ${uri} after 3 tries`)).toBe(`failed to connect using ${REDACTED} after 3 tries`);
  });

  it('scrubs any mongodb URI, even unknown ones', () => {
    expect(r.string('uri=mongodb://alice:pw@db.example.invalid:27017/admin')).toBe(`uri=${REDACTED}`);
    expect(new Redactor().string('see mongodb+srv://x:y@z.net')).toBe(`see ${REDACTED}`);
  });

  it('scrubs user:password@ fragments', () => {
    expect(r.string('https://bob:hunter22@example.com/x')).toBe(`https://${REDACTED}@example.com/x`);
  });

  it('scrubs deep inside objects and arrays, including keys', () => {
    const out = r.deep({ a: [uri, { nested: `x ${uri} y` }], [uri]: 1, n: 5, d: null });
    expect(JSON.stringify(out)).not.toContain('NotARealPassword');
    expect(JSON.stringify(out)).not.toContain('mongodb+srv');
    expect((out as { n: number }).n).toBe(5);
  });

  it('formats errors without stacks or secrets', () => {
    const err = new Error(`connect ECONNREFUSED ${uri}`);
    const msg = r.error(err);
    expect(msg).toBe(`Error: connect ECONNREFUSED ${REDACTED}`);
    expect(msg).not.toContain('at ');
  });
});
