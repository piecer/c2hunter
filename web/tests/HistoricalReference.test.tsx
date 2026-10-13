import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Link, MemoryRouter } from 'react-router-dom';
import type { ReactNode } from 'react';
import { expect, it, vi } from 'vitest';
import App from '../src/App';
import { historicalReasons } from '../src/historicalReferenceReasons';

// Real deterministic controller builder/public projections, not a model response.
const wire = execFileSync(process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python'), ['tests/historical_reference_fixture.py'], { encoding: 'utf8', timeout: 30000 });
const fixture = JSON.parse(wire).with_reference;
const emptyFixture = JSON.parse(wire).empty;
const jobId = fixture.run.analysis_job_id;
const scopeId = fixture.scope.config.scope_id;
const job = { id: jobId, name: 'Historical UI fixture', status: 'COMPLETED', analysis: { module: 'c2' }, sensor_ids: [], internal_networks: [] };

function setup(handler?: (path: string, init?: RequestInit) => Response | Promise<Response>, client = new QueryClient({ defaultOptions: { queries: { retry: false } } }), navigation?: ReactNode) {
  localStorage.setItem('c2hunter-token', 'test-token');
  localStorage.setItem('c2hunter-report-language', 'en');
  const posts: Record<string, unknown>[] = [];
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input).replace('/api/v1', '');
    if (init?.method === 'POST' && path === `/analysis-jobs/${jobId}/ai-runs`) posts.push(JSON.parse(String(init.body)));
    if (handler) {
      const response = await handler(path, init);
      if (response.status !== 599) return response;
    }
    if (path === `/analysis-jobs/${jobId}`) return Response.json(job);
    if (path === '/ai-capabilities') return Response.json({ available: true, remote: false });
    if (path === '/historical-baselines/scopes') return Response.json({ items: [fixture.scope], total: 1, offset: 0, limit: 20, next_offset: null });
    if (path === `/historical-baselines/scopes/${scopeId}/preview`) return Response.json(fixture.preview);
    return Response.json({ items: [], total: 0 });
  });
  vi.stubGlobal('fetch', fetcher);
  const view = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[`/analyses/${jobId}`]}>{navigation}<App/></MemoryRouter></QueryClientProvider>);
  return { ...view, posts, fetcher, client, user: userEvent.setup() };
}

it.each(['scope', 'opt-out'])('ignores a late previous preview after %s ownership changes', async change => {
  let release!: (response: Response) => void;
  const late = new Promise<Response>(resolve => { release = resolve; });
  const { user } = setup(path => path.endsWith('/preview') ? late : fallback());
  await optIn(user);
  await user.click(screen.getByRole('button', { name: 'Preview reference' }));
  if (change === 'scope') await user.selectOptions(screen.getByLabelText('Historical scope'), '');
  else {
    await user.click(screen.getByRole('checkbox', { name: /Use historical reference/ }));
    await user.click(screen.getByRole('checkbox', { name: /Use historical reference/ }));
  }
  await act(async () => { release(Response.json(fixture.preview)); });
  expect(screen.getByRole('button', { name: 'Run AI analysis' })).toBeDisabled();
  expect(screen.queryByText(/Reference pinned/)).not.toBeInTheDocument();
});

it.each(['source_job_id', 'scope_id', 'scope_revision', 'source_binding_sha256'])('refuses a preview with a mismatched or malformed %s', async field => {
  const { user, posts } = setup(path => path.endsWith('/preview') ? Response.json({ ...fixture.preview, [field]: field === 'scope_revision' ? 99 : 'invalid-owner' }) : fallback());
  await optIn(user);
  await user.click(screen.getByRole('button', { name: 'Preview reference' }));
  expect(await screen.findByRole('alert')).toHaveTextContent(/preview|미리보기/i);
  expect(screen.getByRole('button', { name: 'Run AI analysis' })).toBeDisabled();
  expect(posts).toHaveLength(0);
});

it('pins an empty generation as null, preserves remote consent, and drops history when shadow is disabled', async () => {
  const { user, posts } = setup(path => {
    if (path === '/ai-capabilities') return Response.json({ available: true, remote: true, destination: 'model.example', provider: 'test' });
    if (path.endsWith('/scopes')) return Response.json({ items: [emptyFixture.scope] });
    if (path.endsWith('/preview')) return Response.json(emptyFixture.preview);
    return fallback();
  });
  await optIn(user);
  await user.click(screen.getByRole('button', { name: 'Preview reference' }));
  await screen.findByText(/Reference pinned/);
  expect(screen.getByRole('button', { name: 'Run AI analysis' })).toBeDisabled();
  await user.click(screen.getByRole('checkbox', { name: /I consent/ }));
  await user.click(screen.getByRole('button', { name: 'Run AI analysis' }));
  await waitFor(() => expect(posts).toHaveLength(1));
  expect(posts[0].baseline_reference).toEqual(emptyFixture.payload.baseline_reference);
  expect(posts[0].allow_remote).toBe(true);
  await user.click(screen.getByRole('checkbox', { name: /behavioral discovery/ }));
  await user.click(screen.getByRole('button', { name: 'Run AI analysis' }));
  await waitFor(() => expect(posts).toHaveLength(2));
  expect(posts[1]).toEqual({ idempotency_key: expect.any(String), candidate_limit: 5, language: 'en', allow_remote: true });
  await user.click(screen.getByRole('checkbox', { name: /behavioral discovery/ }));
  expect(screen.getByRole('checkbox', { name: /Use historical reference/ })).not.toBeChecked();
});

const fallback = () => new Response(null, { status: 599 });

it('renders the saved producer reference separately from AI, with lazy bounded comparisons and full source provenance', async () => {
  const { user, fetcher } = setup(path => {
    if (path === `/analysis-jobs/${jobId}/ai-runs`) return Response.json({ items: [fixture.run] });
    if (path === `/ai-runs/${fixture.run.id}`) return Response.json(fixture.run);
    if (path === `/ai-runs/${fixture.run.id}/baseline-comparisons?offset=0&limit=20`) return Response.json(fixture.comparisons);
    if (path === `/ai-runs/${fixture.run.id}/baseline-sources?offset=0&limit=20`) return Response.json(fixture.sources);
    return fallback();
  });
  const saved = await screen.findByRole('region', { name: 'Saved historical reference' });
  expect(within(saved).getByText(scopeId)).toBeInTheDocument();
  expect(within(saved).getByText(fixture.run.baseline_summary.generation_id)).toBeInTheDocument();
  expect(within(saved).getByText(/UNREVIEWED/)).toBeInTheDocument();
  expect(within(saved).getByText(/not an AI verdict/)).toBeInTheDocument();
  expect(within(saved).getByText('TARGET_REVIEW_REQUIRED')).toBeInTheDocument();
  expect(fetcher.mock.calls.some(([path]) => /baseline-(comparisons|sources)/.test(String(path)))).toBe(false);
  expect(within(saved).queryByRole('table')).not.toBeInTheDocument();
  await user.click(within(saved).getByRole('button', { name: 'Inspect frozen reference' }));
  expect(within(saved).getByText(fixture.run.baseline_summary.target_source_binding_sha256)).toBeInTheDocument();
  await user.click(within(saved).getByRole('button', { name: 'View comparisons' }));
  const table = await within(saved).findByRole('table', { name: 'Historical comparisons' });
  expect(await within(table).findByText('203.0.113.9')).toBeInTheDocument();
  expect(within(table).getByText('INCOMPATIBLE')).toBeInTheDocument();
  expect(within(saved).queryByText('recurrence')).not.toBeInTheDocument();
  await user.click(within(table).getByRole('button', { name: /Comparison details/ }));
  expect(within(saved).getByText('recurrence')).toBeInTheDocument();
  expect(within(saved).getAllByText('—').length).toBeGreaterThan(0);
  await user.click(within(saved).getByRole('button', { name: 'View sources' }));
  expect(within(saved).queryByRole('table', { name: 'Historical comparisons' })).not.toBeInTheDocument();
  expect(within(saved).queryByText('recurrence')).not.toBeInTheDocument();
  const sources = await within(saved).findByRole('table', { name: 'Historical sources' });
  expect(await within(sources).findByText(fixture.sources.items[0].source_receipt_id)).toBeInTheDocument();
  await user.click(within(sources).getAllByRole('button', { name: /Source details/ })[0]);
  expect(within(saved).getByText(fixture.sources.items[0].source_binding_sha256)).toBeInTheDocument();
  expect(within(saved).getByText(fixture.sources.items[0].approved_by)).toBeInTheDocument();
  await user.selectOptions(screen.getByLabelText('보고서 언어 / Report language'), 'ko');
  expect(screen.getByRole('region', { name: '저장된 과거 참조' })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: '비교 결과 보기' })).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: '원본 목록 보기' }));
  expect(within(saved).queryByRole('table')).not.toBeInTheDocument();
  expect(within(saved).queryByText(fixture.sources.items[0].source_binding_sha256)).not.toBeInTheDocument();
});
it('uses server next_offset and replaces the mounted source page rather than accumulating it', async () => {
  const { user, fetcher } = setup(path => {
    if (path === `/analysis-jobs/${jobId}/ai-runs`) return Response.json({ items: [fixture.run] });
    if (path === `/ai-runs/${fixture.run.id}`) return Response.json(fixture.run);
    // Navigation fault fixture intentionally returns short pages from real producer rows.
    if (path.endsWith('/baseline-sources?offset=0&limit=20')) return Response.json({ ...fixture.sources, items: fixture.sources.items.slice(0, 1), next_offset: 1 });
    if (path.endsWith('/baseline-sources?offset=1&limit=20')) return Response.json({ ...fixture.sources, offset: 1, items: fixture.sources.items.slice(1), next_offset: null });
    return fallback();
  });
  const saved = await screen.findByRole('region', { name: 'Saved historical reference' });
  await user.click(within(saved).getByRole('button', { name: 'View sources' }));
  await within(saved).findByText(fixture.sources.items[0].source_receipt_id);
  expect(within(saved).queryByText(fixture.sources.items[1].source_receipt_id)).not.toBeInTheDocument();
  await user.click(within(saved).getByRole('button', { name: 'Source details 1' }));
  await user.click(within(saved).getByRole('button', { name: 'Next reference page' }));
  await within(saved).findByText(fixture.sources.items[1].source_receipt_id);
  expect(within(saved).getByText(fixture.sources.items[2].source_receipt_id)).toBeInTheDocument();
  expect(within(saved).queryByText(fixture.sources.items[0].source_receipt_id)).not.toBeInTheDocument();
  expect(within(saved).queryByText(fixture.sources.items[0].source_binding_sha256)).not.toBeInTheDocument();
  expect(within(saved).queryByRole('region', { name: 'Source provenance' })).not.toBeInTheDocument();
  expect(within(saved).getByRole('button', { name: 'Next reference page' })).toBeDisabled();
  expect(fetcher.mock.calls.filter(([path]) => String(path).includes('/baseline-sources')).map(([path]) => String(path))).toEqual([
    `/api/v1/ai-runs/${fixture.run.id}/baseline-sources?offset=0&limit=20`, `/api/v1/ai-runs/${fixture.run.id}/baseline-sources?offset=1&limit=20`,
  ]);
  await user.click(within(saved).getByRole('button', { name: 'Previous reference page' }));
  expect(await within(saved).findByText(fixture.sources.items[0].source_receipt_id)).toBeInTheDocument();
  expect(within(saved).queryByText(fixture.sources.items[1].source_receipt_id)).not.toBeInTheDocument();
});

it.each(['comparisons', 'sources'])('keeps compact summary visible when saved %s require analyst access', async tab => {
  const { user, fetcher } = setup(path => {
    if (path === `/analysis-jobs/${jobId}/ai-runs`) return Response.json({ items: [fixture.run] });
    if (path === `/ai-runs/${fixture.run.id}`) return Response.json(fixture.run);
    if (path.includes(`/baseline-${tab}?`)) return Response.json({ error: { code: 'INSUFFICIENT_ROLE', message: 'ANALYST required' } }, { status: 403 });
    return fallback();
  });
  const saved = await screen.findByRole('region', { name: 'Saved historical reference' });
  const button = within(saved).getByRole('button', { name: tab === 'comparisons' ? 'View comparisons' : 'View sources' });
  await user.click(button);
  expect(await within(saved).findByRole('alert')).toHaveTextContent('Sign in with an ANALYST or ADMIN account');
  expect(within(saved).getByText(scopeId)).toBeInTheDocument();
  await user.click(button);
  await user.click(button);
  await within(saved).findByRole('alert');
  expect(fetcher.mock.calls.filter(([path]) => String(path).includes(`/baseline-${tab}?`))).toHaveLength(1);
});

it('stops polling denied historical assessments and explains the role without hiding summary', async () => {
  vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
  const { fetcher, unmount, client } = setup(path => {
    if (path === `/analysis-jobs/${jobId}/ai-runs`) return Response.json({ items: [fixture.run] });
    if (path === `/ai-runs/${fixture.run.id}`) return Response.json(fixture.run);
    if (path.endsWith('/assessments')) return Response.json({ error: { code: 'INSUFFICIENT_ROLE', message: 'denied' } }, { status: 403 });
    return fallback();
  });
  try {
    await screen.findByRole('region', { name: 'Saved historical reference' });
    expect(await screen.findByRole('alert')).toHaveTextContent('Sign in with an ANALYST or ADMIN account');
    await act(async () => { await vi.advanceTimersByTimeAsync(6000); });
    expect(fetcher.mock.calls.filter(([path]) => String(path).endsWith('/assessments'))).toHaveLength(1);
  } finally { unmount(); client.clear(); vi.useRealTimers(); }
});

it('does not offer selection retry when historical selection access is denied', async () => {
  const { user } = setup(path => {
    if (path === `/analysis-jobs/${jobId}/ai-runs`) return Response.json({ items: [fixture.run] });
    if (path === `/ai-runs/${fixture.run.id}`) return Response.json(fixture.run);
    if (path.includes('/selection?')) return Response.json({ error: { code: 'INSUFFICIENT_ROLE', message: 'denied' } }, { status: 403 });
    return fallback();
  });
  await user.click(await screen.findByRole('button', { name: 'View selection inventory' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Sign in with an ANALYST or ADMIN account');
  expect(screen.queryByRole('button', { name: 'Retry selection' })).not.toBeInTheDocument();
});

it('selects cached saved runs with collapsed details and invalidates the preview owner', async () => {
  // A second persisted-run identity carrying the producer's empty-reference projection.
  const second = { ...emptyFixture.run, id: 'older-saved-run', status: 'COMPLETED' };
  const first = { ...fixture.run, status: 'COMPLETED' };
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(['ai-run', first.id], first);
  client.setQueryData(['ai-run', second.id], second);
  client.setQueryData(['historical-reference-page', first.id, 'sources', 0], fixture.sources);
  client.setQueryData(['historical-reference-page', second.id, 'sources', 0], emptyFixture.sources);
  const { user } = setup(path => path === `/analysis-jobs/${jobId}/ai-runs` ? Response.json({ items: [first, second] }) : fallback(), client);
  const saved = await screen.findByRole('region', { name: 'Saved historical reference' });
  await user.click(within(saved).getByRole('button', { name: 'Inspect frozen reference' }));
  await user.click(within(saved).getByRole('button', { name: 'View sources' }));
  await user.click(await within(saved).findByRole('button', { name: 'Source details 1' }));
  await optIn(user);
  await user.click(screen.getByRole('button', { name: 'Preview reference' }));
  await screen.findByText(/Reference pinned/);
  await user.selectOptions(screen.getByLabelText('Saved AI run'), second.id);
  const next = screen.getByRole('region', { name: 'Saved historical reference' });
  expect(within(next).getByText('None (null)')).toBeInTheDocument();
  expect(within(next).getByRole('button', { name: 'Inspect frozen reference' })).toHaveAttribute('aria-expanded', 'false');
  expect(within(next).getByRole('button', { name: 'View sources' })).toHaveAttribute('aria-expanded', 'false');
  expect(within(next).queryByRole('table')).not.toBeInTheDocument();
  expect(screen.queryByText(/Reference pinned/)).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Run AI analysis' })).toBeDisabled();
  await user.selectOptions(screen.getByLabelText('Saved AI run'), first.id);
  expect(screen.getByRole('button', { name: 'View sources' })).toHaveAttribute('aria-expanded', 'false');
  expect(screen.queryByRole('region', { name: 'Source provenance' })).not.toBeInTheDocument();
});

it('covers every producer reason and reproduces the no-I/O fixture bytes exactly', () => {
  expect(Object.keys(historicalReasons).sort()).toEqual(JSON.parse(wire).reason_codes);
  const again = execFileSync(process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python'), ['tests/historical_reference_fixture.py'], { encoding: 'utf8', timeout: 30000 });
  expect(again).toBe(wire);
}, 35000);

it('reaches all 128 actual producer comparisons while bounding mounted rows and expanded records', async () => {
  const maximum = JSON.parse(wire).maximum;
  const { user } = setup(path => {
    if (path === `/analysis-jobs/${jobId}/ai-runs`) return Response.json({ items: [maximum.run] });
    if (path === `/ai-runs/${maximum.run.id}`) return Response.json(maximum.run);
    if (path.includes('/baseline-comparisons?')) {
      const offset = Number(new URL(path, 'http://test').searchParams.get('offset'));
      return Response.json(maximum.comparison_pages.find((page: { offset: number }) => page.offset === offset));
    }
    return fallback();
  });
  const saved = await screen.findByRole('region', { name: 'Saved historical reference' });
  const before = document.querySelectorAll('*').length;
  await user.click(within(saved).getByRole('button', { name: 'View comparisons' }));
  const visited = new Set<string>();
  let peak = before;
  for (const page of maximum.comparison_pages) {
    const table = await within(saved).findByRole('table', { name: 'Historical comparisons' });
    await within(table).findByText(page.items[0].key.peer_ip);
    expect(within(table).getAllByRole('row')).toHaveLength(page.items.length + 1);
    for (let index = 0; index < page.items.length; index++) {
      await user.click(within(table).getByRole('button', { name: `Comparison details ${index + 1}` }));
      expect(within(saved).getAllByRole('region', { name: 'Comparison evidence' })).toHaveLength(1);
      visited.add(page.items[index].key.peer_ip);
      peak = Math.max(peak, document.querySelectorAll('*').length);
    }
    const next = within(saved).getByRole('button', { name: 'Next reference page' });
    if (page.next_offset === null) expect(next).toBeDisabled();
    else await user.click(next);
  }
  expect(visited.size).toBe(128);
  expect(peak).toBeLessThan(1200);
  await user.click(within(saved).getByRole('button', { name: 'View comparisons' }));
  expect(within(saved).queryByRole('table')).not.toBeInTheDocument();
  expect(document.querySelectorAll('*').length).toBe(before);
}, 20000);

it.each(['artifacts', 'feedback'])('explains denied %s without leaving authorized-looking actions', async kind => {
  // Presentation-only assessment stub; no model is executed or claimed.
  const assessment = { id: 'assessment-fixture', candidate_id: 'rule', external_ip: '203.0.113.9', assessment: {
    candidate: { verdict: 'SUSPICIOUS', confidence: 0.5, summary_en: 'Fixture interpretation only', summary_ko: '픽스처 해석 전용' },
    supporting_factors: [], counter_factors: [], missing_information: [], limitations: [],
  } };
  const { user } = setup(path => {
    if (path === `/analysis-jobs/${jobId}/ai-runs`) return Response.json({ items: [fixture.run] });
    if (path === `/ai-runs/${fixture.run.id}`) return Response.json(fixture.run);
    if (path.endsWith('/assessments')) return Response.json({ items: [assessment] });
    if (path === `/ai-assessments/assessment-fixture/${kind}`) return Response.json({ error: { code: 'INSUFFICIENT_ROLE', message: 'denied' } }, { status: 403 });
    return fallback();
  });
  expect(await screen.findByRole('alert')).toHaveTextContent('Sign in with an ANALYST or ADMIN account');
  if (kind === 'feedback') {
    await user.type(screen.getByLabelText('Analyst note', { selector: 'textarea' }), 'do not send');
    expect(screen.getByRole('button', { name: 'Save confirmed feedback' })).toBeDisabled();
  }
});

it('does not apply a late preview to another already cached job', async () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(['job', jobId], job);
  client.setQueryData(['job', 'next-job'], { ...job, id: 'next-job', name: 'Next fixture job' });
  client.setQueryData(['ai-runs', jobId], { items: [] });
  client.setQueryData(['ai-runs', 'next-job'], { items: [] });
  let release!: (response: Response) => void;
  const late = new Promise<Response>(resolve => { release = resolve; });
  const { user } = setup(path => path.endsWith('/preview') ? late : fallback(), client, <Link to="/analyses/next-job">Switch fixture job</Link>);
  await optIn(user);
  await user.click(screen.getByRole('button', { name: 'Preview reference' }));
  await user.click(screen.getByRole('link', { name: 'Switch fixture job' }));
  expect(await screen.findByRole('heading', { name: 'Next fixture job' })).toBeInTheDocument();
  expect(screen.getByRole('checkbox', { name: /behavioral discovery/ })).not.toBeChecked();
  await optIn(user);
  await act(async () => { release(Response.json(fixture.preview)); });
  expect(screen.getByRole('button', { name: 'Run AI analysis' })).toBeDisabled();
  expect(screen.queryByText(/Reference pinned/)).not.toBeInTheDocument();
});

it('keeps action disabled after a failed explicit preview and translates opt-in controls to Korean', async () => {
  const { user, posts, fetcher } = setup(path => path.endsWith('/preview') ? Response.json({ error: { code: 'BASELINE_STORAGE_UNAVAILABLE', message: 'offline' } }, { status: 503 }) : fallback());
  await optIn(user);
  await user.selectOptions(screen.getByLabelText('보고서 언어 / Report language'), 'ko');
  expect(screen.getByLabelText('과거 참조 범위')).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: '참조 미리보기' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('과거 참조 요청 실패');
  expect(screen.getByRole('button', { name: 'Run AI analysis' })).toBeDisabled();
  expect(fetcher.mock.calls.filter(([path]) => String(path).endsWith('/preview'))).toHaveLength(1);
  expect(posts).toHaveLength(0);
});

async function optIn(user: ReturnType<typeof userEvent.setup>) {
  const panel = await screen.findByRole('region', { name: 'AI C2 분석' });
  await user.click(within(panel).getByRole('checkbox', { name: /behavioral discovery/ }));
  await user.click(within(panel).getByRole('checkbox', { name: /Use historical reference/ }));
  await user.selectOptions(await screen.findByLabelText('Historical scope'), scopeId);
  return panel;
}

it('keeps historical off by default and pins a real preview in the existing create request', async () => {
  const { user, posts, fetcher } = setup();
  const panel = await screen.findByRole('region', { name: 'AI C2 분석' });
  expect(within(panel).queryByRole('checkbox', { name: /Use historical reference/ })).not.toBeInTheDocument();
  await user.click(within(panel).getByRole('button', { name: 'Run AI analysis' }));
  await waitFor(() => expect(posts).toHaveLength(1));
  expect(posts[0]).toEqual({ idempotency_key: expect.any(String), candidate_limit: 5, language: 'en', allow_remote: false });
  expect(fetcher.mock.calls.some(([path]) => String(path).includes('historical-baselines'))).toBe(false);
  await optIn(user);
  expect(screen.getByRole('button', { name: 'Run AI analysis' })).toBeDisabled();
  expect(screen.getByText(/No target quality review is asserted/)).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Preview reference' }));
  expect(await screen.findByText(/Reference pinned/)).toBeInTheDocument();
  const previewCall = fetcher.mock.calls.find(([path]) => String(path).endsWith('/preview'))!;
  expect(JSON.parse(String(previewCall[1]?.body))).toEqual({ source_job_id: jobId, expected_revision: fixture.scope.control_revision, purpose: 'COMPARISON' });
  await user.click(screen.getByRole('button', { name: 'Run AI analysis' }));
  await waitFor(() => expect(posts).toHaveLength(2));
  expect(posts[1]).toEqual({ ...fixture.payload, idempotency_key: expect.any(String), language: 'en' });
});

it.each(['preview', 'create'])('requires an explicit fresh preview after a stale %s without automatic retry or rebasing', async phase => {
  let stale = true;
  const { user, fetcher, posts } = setup((path, init) => {
    if (stale && init?.method === 'POST' && path.endsWith(phase === 'preview' ? '/preview' : '/ai-runs')) return Response.json({ error: { code: 'BASELINE_REVISION_CONFLICT', message: 'conflict' } }, { status: 409 });
    return fallback();
  });
  await optIn(user);
  await user.click(screen.getByRole('button', { name: 'Preview reference' }));
  if (phase === 'create') {
    await screen.findByText(/Reference pinned/);
    await user.click(screen.getByRole('button', { name: 'Run AI analysis' }));
  }
  expect(await screen.findByText(/Stale reference/)).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Run AI analysis' })).toBeDisabled();
  expect(fetcher.mock.calls.filter(([path]) => String(path).endsWith('/preview'))).toHaveLength(1);
  expect(posts).toHaveLength(phase === 'create' ? 1 : 0);
  stale = false;
  await user.click(screen.getByRole('button', { name: 'Reload scopes' }));
  await user.selectOptions(await screen.findByLabelText('Historical scope'), scopeId);
  expect(screen.getByRole('button', { name: 'Run AI analysis' })).toBeDisabled();
  await user.click(screen.getByRole('button', { name: 'Preview reference' }));
  await screen.findByText(/Reference pinned/);
  await waitFor(() => expect(screen.getByRole('button', { name: 'Run AI analysis' })).toBeEnabled());
});

it.each(['scopes', 'preview', 'create'])('explains authenticated analyst denial on %s and does not offer a retry flood', async phase => {
  const { user, fetcher } = setup((path, init) => {
    if ((phase === 'scopes' && path.endsWith('/scopes')) || (phase === 'preview' && path.endsWith('/preview')) || (phase === 'create' && init?.method === 'POST' && path.endsWith('/ai-runs'))) return Response.json({ error: { code: 'BASELINE_AUTH_REQUIRED', message: 'denied' } }, { status: 403 });
    return fallback();
  });
  await screen.findByRole('region', { name: 'AI C2 분석' });
  await user.click(screen.getByRole('checkbox', { name: /behavioral discovery/ }));
  await user.click(screen.getByRole('checkbox', { name: /Use historical reference/ }));
  if (phase !== 'scopes') {
    await user.selectOptions(await screen.findByLabelText('Historical scope'), scopeId);
    await user.click(screen.getByRole('button', { name: 'Preview reference' }));
    if (phase === 'create') {
      await screen.findByText(/Reference pinned/);
      await user.click(screen.getByRole('button', { name: 'Run AI analysis' }));
    }
  }
  const alert = await screen.findByRole('alert');
  expect(alert).toHaveTextContent('Sign in with an ANALYST or ADMIN account');
  expect(screen.getByRole('button', { name: 'Run AI analysis' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Preview reference' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Reload scopes' })).toBeDisabled();
  expect(fetcher.mock.calls.filter(([path, init]) => phase === 'scopes' ? String(path).endsWith('/scopes') : String(path).endsWith(phase === 'preview' ? '/preview' : '/ai-runs') && init?.method === 'POST')).toHaveLength(1);
});
