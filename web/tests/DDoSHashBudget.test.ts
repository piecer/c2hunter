import { createHash } from 'node:crypto';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

beforeEach(() => { vi.resetModules(); });
afterEach(() => { vi.restoreAllMocks(); });
const nativeDigest = (text: string) => createHash('sha256').update(text, 'utf8').digest('hex');

it.each(['', 'abc', '한글 / 🌐', '\ud800', '\udfff', ...[55, 56, 63, 64, 65, 127, 128, 1024, 1025].map(size => 'a'.repeat(size))])('preserves native UTF-8 SHA-256 for %j', async text => {
  const { sha256 } = await import('../src/ddosReportContract');
  expect(sha256(text)).toBe(nativeDigest(text));
  expect(sha256(text)).toBe(nativeDigest(text));
});

it('hashes each of 512 short immutable inputs only once across repeated validation', async () => {
  const { sha256 } = await import('../src/ddosReportContract');
  const encode = vi.spyOn(TextEncoder.prototype, 'encode');
  const inputs = Array.from({ length: 512 }, (_, index) => `source-identity-${index}`);
  for (const text of inputs) expect(sha256(text)).toBe(nativeDigest(text));
  for (const text of inputs) expect(sha256(text)).toBe(nativeDigest(text));
  expect(encode).toHaveBeenCalledTimes(inputs.length);
});

it('evicts the least recently used input at the entry cap without stale digests', async () => {
  const { sha256 } = await import('../src/ddosReportContract');
  const encode = vi.spyOn(TextEncoder.prototype, 'encode');
  for (let index = 0; index < 512; index++) sha256(`bounded-${index}`);
  expect(sha256('bounded-0')).toBe(nativeDigest('bounded-0'));
  sha256('overflow');
  encode.mockClear();
  expect(sha256('bounded-0')).toBe(nativeDigest('bounded-0'));
  expect(sha256('bounded-1')).toBe(nativeDigest('bounded-1'));
  expect(encode).toHaveBeenCalledTimes(1);
});

it('bounds retained text by UTF-16 length without refusing longer input', async () => {
  const { sha256 } = await import('../src/ddosReportContract');
  const encode = vi.spyOn(TextEncoder.prototype, 'encode');
  const boundary = '🌐'.repeat(512);
  expect(boundary.length).toBe(1024);
  expect(sha256(boundary)).toBe(nativeDigest(boundary));
  expect(sha256(boundary)).toBe(nativeDigest(boundary));
  expect(encode).toHaveBeenCalledTimes(1);
  encode.mockClear();
  for (const text of [boundary + 'x', 'x'.repeat(65536)]) {
    expect(sha256(text)).toBe(nativeDigest(text));
    expect(sha256(text)).toBe(nativeDigest(text));
  }
  expect(encode).toHaveBeenCalledTimes(4);
});

it('does not reuse a digest when immutable input content changes', async () => {
  const { sha256 } = await import('../src/ddosReportContract');
  const encode = vi.spyOn(TextEncoder.prototype, 'encode');
  const original = '{"target":"10.0.1.1"}';
  const changed = '{"target":"10.0.1.2"}';
  expect(sha256(original)).toBe(nativeDigest(original));
  expect(sha256(changed)).toBe(nativeDigest(changed));
  expect(sha256(original)).toBe(nativeDigest(original));
  expect(sha256(changed)).not.toBe(sha256(original));
  expect(encode).toHaveBeenCalledTimes(2);
});

it('never retains mutable string-like objects if a runtime caller bypasses the type', async () => {
  const { sha256 } = await import('../src/ddosReportContract');
  const encode = vi.spyOn(TextEncoder.prototype, 'encode');
  let value = 'before';
  const mutable = { length: 6, toString: () => value } as unknown as string;
  expect(sha256(mutable)).toBe(nativeDigest(value));
  value = 'after';
  expect(sha256(mutable)).toBe(nativeDigest(value));
  expect(sha256(mutable)).toBe(nativeDigest(value));
  expect(encode).toHaveBeenCalledTimes(3);
});
