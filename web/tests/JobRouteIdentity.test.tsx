import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import App from '../src/App';
import { jobApi } from '../src/jobInvestigationApi';
import { parseJobWire } from '../src/jobInvestigationContract';
import { producer } from './jobInvestigationFixtures';

// Frontend transport contract only: opaque IDs here do not claim server admission.
const ids = ['plain-job', 'job/segment?query=yes#fragment%literal'];
// Same real controller producer used by HistoricalReference/MutationOwners tests.
const historical = JSON.parse(execFileSync(process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python'), ['tests/historical_reference_fixture.py'], { encoding: 'utf8', timeout: 30000 })).with_reference;
function mount(id: string, status = 'COMPLETED', module = 'c2', handler?: (path: string, init?: RequestInit) => Response | undefined) {
  localStorage.setItem('c2hunter-token', 'test');
  localStorage.setItem('c2hunter-report-language', 'en');
  const job = { id, name: 'URI route job', status, dataset_id: 'dataset', analysis: { module } };
  const root = `/analysis-jobs/${encodeURIComponent(id)}`;
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input).replace('/api/v1', '');
    const response = handler?.(path, init);
    if (response) return response;
    if (path === root) return Response.json(job);
    if (path === `${root}/cancel`) return Response.json({});
    if (path.startsWith(`${root}/candidates?`)) {
      const query = new URLSearchParams(path.split('?')[1]);
      return Response.json({ items: [], total: 0, page: Number(query.get('page') ?? 1), page_size: Number(query.get('page_size')) });
    }
    if (path === '/ai-capabilities') return Response.json({ available: true, remote: false });
    if (path === `${root}/ai-runs`) return Response.json({ items: [] });
    // Fail closed for a malformed job segment, rather than matching a raw suffix.
    return Response.json({ error: { message: `Unexpected request: ${path}` } }, { status: 404 });
  });
  vi.stubGlobal('fetch', fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[`/analyses/${encodeURIComponent(id)}`]}><App/></MemoryRouter></QueryClientProvider>);
  const paths = () => fetcher.mock.calls.map(([path]) => String(path).replace('/api/v1', ''));
  const posts = () => fetcher.mock.calls.filter(([, init]) => init?.method === 'POST');
  return { client, fetcher, paths, posts, root, job };
}

describe('Job route frontend transport identity', () => {
  it.each(ids)('keeps the parent-analysis link identity for %s', async id => {
    const parentId = `${id}-parent`;
    const parentRoot = `/analysis-jobs/${encodeURIComponent(parentId)}`;
    const { paths, posts } = mount(id, 'COMPLETED', 'c2', path => {
      if (path === `/analysis-jobs/${encodeURIComponent(id)}`) return Response.json({ id, name: 'URI route job', status: 'COMPLETED', parent_job_id: parentId, analysis: { module: 'c2' } });
      if (path === parentRoot) return Response.json({ id: parentId, name: 'Parent analysis', status: 'COMPLETED', analysis: { module: 'c2' } });
      return undefined;
    });
    fireEvent.click(await screen.findByRole('button', { name: 'Work information' }));
    const parent = screen.getByRole('link', { name: parentId });
    expect(parent).toHaveAttribute('href', `/analyses/${encodeURIComponent(parentId)}`);
    fireEvent.click(parent);
    expect(await screen.findByRole('heading', { name: 'Parent analysis' })).toBeVisible();
    expect(paths()).toContain(parentRoot);
    expect(posts()).toHaveLength(0);
  });

  it.each(ids)('preserves the literal export body job_id for %s', async id => {
    const { posts } = mount(id);
    fireEvent.click(await screen.findByRole('button', { name: 'Work information' }));
    expect(posts()).toHaveLength(0);
    fireEvent.click(screen.getByRole('button', { name: 'Download filtered capture' }));
    await waitFor(() => expect(posts()).toHaveLength(1));
    expect(String(posts()[0][0])).toBe('/api/v1/pcap-exports');
    expect(JSON.parse(String(posts()[0][1]?.body))).toMatchObject({ job_id: id });
  });

  it.each(ids)('keeps source-404 job history lazy and read-only for %s', async id => {
    const { posts, paths, root } = mount(id, 'COMPLETED', 'c2', path => path === `/analysis-jobs/${encodeURIComponent(id)}` ? Response.json({ error: { message: 'Source unavailable' } }, { status: 404 }) : undefined);
    const history = vi.spyOn(jobApi, 'history').mockResolvedValue({ items: [], next_cursor: null });
    vi.spyOn(jobApi, 'capabilities').mockResolvedValue(parseJobWire('capabilities', producer.fixtures.capabilities));
    await screen.findByText('Source unavailable');
    expect(paths()).toEqual([root]);
    expect(history).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: /Open experimental/ }));
    await screen.findByRole('region', { name: 'Job investigation history' });
    expect(history.mock.calls[0][0]).toBe(id);
    expect(screen.getByRole('button', { name: /Start experimental/ })).toBeDisabled();
    expect(posts()).toHaveLength(0);
  });

  it.each(ids)('reads and starts AI runs for %s without encoding source-reference bodies', async id => {
    const root = `/analysis-jobs/${encodeURIComponent(id)}`;
    const scopeId = historical.scope.config.scope_id;
    let started = false;
    const run = { ...historical.run, analysis_job_id: id };
    const { posts, paths, client } = mount(id, 'COMPLETED', 'c2', (path, init) => {
      if (path === `${root}/ai-runs`) {
        if (init?.method === 'POST') { started = true; return Response.json(run); }
        return Response.json({ items: started ? [run] : [] });
      }
      if (path === `/ai-runs/${run.id}`) return Response.json(run);
      if (path === `/ai-runs/${run.id}/assessments`) return Response.json({ items: [] });
      if (path === '/historical-baselines/scopes') return Response.json({ items: [historical.scope] });
      if (path === `/historical-baselines/scopes/${scopeId}/preview`) return Response.json({ ...historical.preview, source_job_id: id });
      return undefined;
    });
    fireEvent.click(await screen.findByRole('button', { name: 'AI investigation' }));
    await waitFor(() => expect(paths()).toContain(`${root}/ai-runs`));
    expect(posts()).toHaveLength(0);
    expect(client.getQueryData(['ai-runs', id])).toEqual({ items: [] });
    fireEvent.click(screen.getByRole('checkbox', { name: /behavioral discovery/ }));
    fireEvent.click(screen.getByRole('checkbox', { name: /Use historical reference/ }));
    await waitFor(() => expect(screen.getByLabelText('Historical scope')).toBeEnabled());
    fireEvent.change(screen.getByLabelText('Historical scope'), { target: { value: scopeId } });
    fireEvent.click(screen.getByRole('button', { name: 'Preview reference' }));
    await screen.findByText(/Reference pinned/);
    expect(posts()).toHaveLength(1);
    expect(JSON.parse(String(posts()[0][1]?.body))).toEqual({ source_job_id: id, expected_revision: historical.scope.control_revision, purpose: 'COMPARISON' });
    fireEvent.click(screen.getByRole('button', { name: 'Run AI analysis' }));
    await waitFor(() => expect(posts()).toHaveLength(2));
    expect(String(posts()[1][0])).toBe(`/api/v1${root}/ai-runs`);
    expect(JSON.parse(String(posts()[1][1]?.body))).toEqual({ ...historical.payload, idempotency_key: expect.stringContaining(`web-${id}-`), language: 'en' });
    await waitFor(() => expect(paths()).toContain(`/ai-runs/${run.id}/assessments`));
    expect(paths()).toContain(`/ai-runs/${run.id}`);
    expect(client.getQueryData(['ai-runs', id])).toEqual({ items: [run] });
    expect(posts()).toHaveLength(2);
  });

  it.each(ids.flatMap(id => ['c2', 'ddos_attack'].map(module => ({ id, module }))))('reanalyzes $module $id and routes to the literal created job', async ({ id, module }) => {
    const createdId = `${id}-child`;
    const createdRoot = `/analysis-jobs/${encodeURIComponent(createdId)}`;
    const { posts, root, paths } = mount(id, 'COMPLETED', module, (path, init) => {
      if (path === `/analysis-jobs/${encodeURIComponent(id)}/reanalyze` && init?.method === 'POST') return Response.json({ id: createdId });
      if (path === createdRoot) return Response.json({ id: createdId, name: 'Created analysis', status: 'COMPLETED', analysis: { module: 'c2' } });
      return undefined;
    });
    await screen.findByRole('heading', { name: 'URI route job' });
    if (module === 'c2') fireEvent.click(screen.getByRole('button', { name: 'Work information' }));
    expect(posts()).toHaveLength(0);
    fireEvent.click(screen.getByRole('button', { name: module === 'c2' ? '탐지 가중치로 재분석' : 'DDoS threshold로 재분석' }));
    await waitFor(() => expect(posts()).toHaveLength(1));
    expect(String(posts()[0][0])).toBe(`/api/v1${root}/reanalyze`);
    const body = JSON.parse(String(posts()[0][1]?.body));
    expect(body.idempotency_key).toEqual(expect.any(String));
    if (module === 'c2') expect(Object.values(body.detector_weights)).toEqual(expect.arrayContaining([1]));
    expect(await screen.findByRole('heading', { name: 'Created analysis' })).toBeVisible();
    expect(paths()).toContain(createdRoot);
    expect(posts()).toHaveLength(1);
  });

  it.each(ids)('reads %s as one segment with unchanged lazy 25/200 candidate scopes', async id => {
    const { paths, posts, root, client, job } = mount(id);
    await waitFor(() => expect(paths()).toContain(root));
    await screen.findByRole('heading', { name: '0 retained candidates · Not a safety verdict' });
    expect(paths()).toEqual([root, `${root}/candidates?page=1&page_size=25&minimum_score=0&sort=-score`]);
    expect(client.getQueryData(['job', id])).toEqual(job);
    expect(client.getQueryData(['job-candidates', id, 1])).toMatchObject({ page_size: 25 });
    expect(posts()).toHaveLength(0);
    fireEvent.click(screen.getByRole('button', { name: 'AI investigation' }));
    await waitFor(() => expect(paths()).toContain(`${root}/candidates?page_size=200`));
    expect(posts()).toHaveLength(0);
    fireEvent.click(screen.getByRole('button', { name: 'Results & evidence' }));
    expect(client.getQueryData(['job-ai-known-candidates', id])).toMatchObject({ page_size: 200 });
  });

  it.each(ids)('cancels %s only on an ordinary click with the original body', async id => {
    const { posts, root } = mount(id, 'ANALYZING');
    const cancel = await screen.findByRole('button', { name: 'Cancel analysis' });
    expect(posts()).toHaveLength(0);
    fireEvent.click(cancel);
    await waitFor(() => expect(posts()).toHaveLength(1));
    expect(String(posts()[0][0])).toBe(`/api/v1${root}/cancel`);
    expect(JSON.parse(String(posts()[0][1]?.body))).toEqual({ reason: 'operator requested from web console' });
    expect(await screen.findByText('Cancellation requested')).toBeVisible();
  });
});
