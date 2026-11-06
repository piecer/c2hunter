import { afterEach, expect, it, vi } from 'vitest';
import { api } from '../src/api';
import { captureRequest, investigationApi } from '../src/investigationApi';
import { parseInvestigation } from '../src/investigationContract';
import { InvestigationOwner } from '../src/investigationLifecycle';
import { INVESTIGATION_RESPONSE_LIMIT, readBoundedJSON } from '../src/investigationTransport';
import { fixture } from './investigationFixtures';

afterEach(() => vi.useRealTimers());
it('counts streamed UTF-8 bytes and cancels oversize before JSON.parse', async () => {
  const cancel = vi.fn();
  let reads = 0;
  const response = new Response(new ReadableStream({ pull(controller) {
    reads += 1; controller.enqueue(new Uint8Array(65536));
  }, cancel }), { headers: { 'content-length': '1' } });
  const parse = vi.spyOn(JSON, 'parse');
  const failure = await readBoundedJSON(response).catch(error => error);
  const callsBeforeAssertions = [...parse.mock.calls];
  parse.mockRestore();
  expect(failure).toBeInstanceOf(Error);
  expect((failure as Error).message).toContain('byte limit');
  expect(cancel).toHaveBeenCalledOnce();
  // Vitest itself parses source maps while recording Error stacks. Those are
  // not response decoding. The stream's distinctive NUL payload must never parse.
  expect(callsBeforeAssertions.filter(([text]) => text.startsWith('\u0000'))).toHaveLength(0);
  const positive = vi.spyOn(JSON, 'parse');
  await expect(readBoundedJSON(new Response('{"bounded":true}'))).resolves.toEqual({ bounded: true });
  expect(positive).toHaveBeenCalledWith('{"bounded":true}');
  expect(reads).toBeLessThanOrEqual(6);
});
it('does not expose malformed response excerpts through parser errors', async () => {
  const failure = await readBoundedJSON(new Response('private-provider-secret invalid json')).catch(error => error);
  expect((failure as Error).message).toBe('Invalid investigation JSON');
});
it('rejects oversized Content-Length without consuming the body', async () => {
  const response = new Response('null', { headers: { 'content-length': String(INVESTIGATION_RESPONSE_LIMIT + 1) } });
  await expect(readBoundedJSON(response)).rejects.toThrow('byte limit');
});
it('retains auth header and the existing 401 invalidation event even for malformed errors', async () => {
  localStorage.setItem('c2hunter-token', 'test-token');
  const invalid = vi.fn(); window.addEventListener('c2hunter-auth-invalid', invalid);
  const fetch = vi.fn<typeof globalThis.fetch>(async () => new Response('not JSON', { status: 401 })); vi.stubGlobal('fetch', fetch);
  await expect(api.boundedRequest('/ai-investigations/capabilities')).rejects.toThrow();
  expect(new Headers(fetch.mock.calls[0][1]?.headers).get('authorization')).toBe('Bearer test-token');
  expect(localStorage.getItem('c2hunter-token')).toBeNull(); expect(invalid).toHaveBeenCalledOnce();
  window.removeEventListener('c2hunter-auth-invalid', invalid);
});
it('enforces evidence route scope/source identity and encodes literal job IDs', async () => {
  const run = parseInvestigation('InvestigationRun', fixture('run_completed'));
  const evidence = parseInvestigation('Evidence', fixture('evidence_protocol'));
  const fetch = vi.fn<typeof globalThis.fetch>(async () => Response.json(evidence)); vi.stubGlobal('fetch', fetch);
  await investigationApi.evidence('job', run, evidence.evidence_id, new AbortController().signal);
  evidence.scope.target_ip = '10.0.0.9';
  await expect(investigationApi.evidence('job', run, evidence.evidence_id, new AbortController().signal)).rejects.toThrow('identity mismatch');
  await expect(investigationApi.history('job/with:literal', null, new AbortController().signal)).rejects.toThrow();
  expect(fetch.mock.calls.at(-1)?.[0]).toContain('/analysis-jobs/job%2Fwith%3Aliteral/');
});
it('can capture a stable request in HTTP contexts without randomUUID', () => {
  const run = parseInvestigation('InvestigationRun', fixture('run_queued'));
  vi.stubGlobal('crypto', { getRandomValues: crypto.getRandomValues.bind(crypto) });
  const first = JSON.parse(captureRequest(run.scope, 'Explain facts', 'en', run.request.expected_source_sha256, false));
  const second = JSON.parse(captureRequest(run.scope, 'Explain facts', 'en', run.request.expected_source_sha256, false));
  expect(first.idempotency_key).toMatch(/^[0-9a-f]{32}$/);
  expect(second.idempotency_key).not.toBe(first.idempotency_key);
});
it('retires callbacks and all owned deadline timers even when transport ignores AbortSignal', async () => {
  vi.useFakeTimers();
  const owner = new InvestigationOwner(); const success = vi.fn(); const failure = vi.fn();
  let resolve!: (value: string) => void; let signal!: AbortSignal;
  const pending = owner.request(value => { signal = value; return new Promise<string>(done => { resolve = done; }); }, success, failure);
  owner.cancel();
  expect(signal.aborted).toBe(true); expect(vi.getTimerCount()).toBe(0);
  resolve('stale'); await pending;
  expect(success).not.toHaveBeenCalled(); expect(failure).not.toHaveBeenCalled();
});
