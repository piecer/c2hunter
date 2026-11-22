import { expect, it, vi } from 'vitest';
import { readInterpretationRuns } from '../src/interpretationRuns';
const other = { id: 'other', analysis_kind: 'C2', status: 'COMPLETED', language: 'en' };
it('publishes the first history page with one automatic request even for a huge absent-kind history', async () => {
  const fetcher = vi.fn(async () => Response.json({ items: Array.from({ length: 50 }, (_, i) => ({ ...other, id: `other-${i}` })), current_page: 1, page_size: 50, total: 1000000 }));
  vi.stubGlobal('fetch', fetcher);
  const result = await readInterpretationRuns('job', 'DDOS_ATTACK', new AbortController().signal);
  expect(fetcher).toHaveBeenCalledTimes(1);
  expect(result.items).toHaveLength(50);
  expect(result).toMatchObject({ discovery: 'incomplete', nextPage: 2 });
});
it.each([
  {}, { current_page: 1, page_size: 50, total: 1 },
  { current_page: 2, page_size: 50, total: 0 },
  { current_page: 1, page_size: 201, total: 0 },
  { current_page: 1, page_size: 50, total: -1 },
])('does not turn unknown/malformed/truncated pagination into absence readiness: %j', async meta => {
  vi.stubGlobal('fetch', vi.fn(async () => Response.json({ items: [], ...meta })));
  expect(await readInterpretationRuns('job', 'DDOS_ATTACK', new AbortController().signal)).toMatchObject({ discovery: 'unknown' });
});
it('proves absence only with complete valid current_page metadata', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => Response.json({ items: [], current_page: 1, page_size: 50, total: 0 })));
  expect(await readInterpretationRuns('job', 'DDOS_ATTACK', new AbortController().signal)).toMatchObject({ discovery: 'resolved' });
});
