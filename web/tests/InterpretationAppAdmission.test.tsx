import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { readFileSync } from 'node:fs';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, expect, it, vi } from 'vitest';
import App from '../src/App';
const python = process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python');
const network = JSON.parse(execFileSync(python, ['tests/network_report_fixture.py', '--pagination'], { encoding: 'utf8' }))['20'];
const ddos = JSON.parse(readFileSync('tests/fixtures/ddos-report-contract.json', 'utf8'));
const clients: QueryClient[] = [];
afterEach(() => clients.splice(0).forEach(c => c.clear()));
const variants = [{ module: 'network_anomaly', kind: 'NETWORK_ANOMALY', report: network, open: 'Open AI interpretation', submit: 'AI interpretation' }, { module: 'ddos_attack', kind: 'DDOS_ATTACK', report: ddos, open: 'Open DDoS AI interpretation', submit: 'Run DDoS AI interpretation' }];
it.each(variants.flatMap(variant => ['replacement', 'missing', 'invalid', 'query error'].flatMap(loss => ['accepted', 'ambiguous'].map(receipt => ({ ...variant, loss, receipt })))))('$kind retains $receipt admission through $loss and recovery with a lagging list', async ({ module, kind, report, open, submit, loss, receipt }) => {
  localStorage.setItem('c2hunter-token', 'fixture'); localStorage.setItem('c2hunter-report-language', 'en');
  const job = { id: 'owned', status: 'COMPLETED', name: 'Owned job', dataset_id: 'dataset', analysis: { module }, [module]: report };
  const older = { id: 'older', analysis_kind: kind, status: 'COMPLETED', language: 'en', created_at: '2026-11-01T00:00:00Z' };
  const admitted = { ...older, id: 'admitted', status: 'ANALYZING', created_at: '2026-11-02T00:00:00Z' };
  const bodies: string[] = [];
  let release!: (response: Response) => void;
  const pending = new Promise<Response>(resolve => { release = resolve; });
  let jobError = false;
  vi.stubGlobal('fetch', vi.fn(async (input: unknown, init?: RequestInit) => {
    const url = String(input);
    if (init?.method === 'POST') { bodies.push(String(init.body)); return pending; }
    if (url.endsWith('/analysis-jobs/owned')) return jobError ? Response.json({ error: { message: 'Job unavailable' } }, { status: 503 }) : Response.json(job);
    if (url.endsWith('/ai-capabilities')) return Response.json({ available: true, network_interpretation: true, ddos_interpretation: true, remote: false });
    if (url.endsWith('/owned/ai-runs')) return Response.json({ items: [older], current_page: 1, page_size: 50, total: 1 });
    if (url.endsWith('/ai-runs/older')) return Response.json(older);
    if (url.endsWith('/ai-runs/admitted')) return Response.json(admitted);
    return Response.json({ items: [] });
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } }); clients.push(client);
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/analyses/owned']}><App/></MemoryRouter></QueryClientProvider>);
  fireEvent.click(await screen.findByRole('button', { name: open }));
  fireEvent.click(screen.getByRole('button', { name: 'New AI interpretation' }));
  await waitFor(() => expect(screen.getByRole('button', { name: submit })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: submit }));
  await waitFor(() => expect(bodies).toHaveLength(1));
  const originalBody = bodies[0];
  fireEvent.click(screen.getByRole('button', { name: 'View saved run older' }));
  if (loss === 'query error') {
    jobError = true;
    await act(async () => { await client.invalidateQueries({ queryKey: ['job', 'owned'] }); });
  } else {
    const replacement = loss === 'missing' ? undefined : loss === 'invalid' ? { version: 'future' } : { ...structuredClone(report), warnings: [...report.warnings] };
    await act(async () => { client.setQueryData(['job', 'owned'], { ...job, [module]: replacement, ...(loss === 'replacement' ? { dataset_id: 'replacement-dataset' } : {}) }); await new Promise(resolve => setTimeout(resolve, 0)); });
  }
  await waitFor(() => expect(screen.getByText('AI request pending — admission not yet confirmed.')).toBeVisible());
  await act(async () => { release(receipt === 'accepted' ? Response.json(admitted) : Response.json({ status: 'QUEUED' })); });
  await waitFor(() => expect(client.isMutating()).toBe(0));
  jobError = false;
  act(() => { client.setQueryData(['job', 'owned'], job); });
  await waitFor(() => expect(client.getQueryState(['job', 'owned'])?.status).toBe('success'));
  const opener = screen.queryByRole('button', { name: open });
  if (opener) fireEvent.click(opener);
  expect(await screen.findByRole('button', { name: 'View saved run older' })).toHaveAttribute('aria-pressed', 'true');
  const newForm = screen.getByRole('button', { name: 'New AI interpretation' });
  if (newForm.getAttribute('aria-expanded') !== 'true') fireEvent.click(newForm);
  expect(screen.getByRole('button', { name: submit })).toBeDisabled();
  if (receipt === 'accepted') expect(await screen.findByRole('button', { name: 'Cancel AI run' })).toBeVisible();
  else expect(screen.getByText('AI admission unconfirmed. Review the request before trying again.')).toBeVisible();
  expect(bodies).toEqual([originalBody]);
  expect(JSON.parse(originalBody)).toEqual({ idempotency_key: expect.any(String), analysis_kind: kind, language: 'en', allow_remote: false });
});
it.each(variants.flatMap(v => ['known', 'late acknowledgement'].map(origin => ({ ...v, origin }))))('$kind keeps actionable status above repeated parent errors for $origin', async ({ module, kind, report, open, submit, origin }) => {
  localStorage.setItem('c2hunter-token', 'fixture'); localStorage.setItem('c2hunter-report-language', 'en');
  const job = { id: 'owned', status: 'COMPLETED', name: 'Owned job', dataset_id: 'dataset', analysis: { module }, [module]: report };
  const active = { id: 'active', analysis_kind: kind, status: 'ANALYZING', language: 'en', analysis_job_id: 'owned', dataset_id: 'dataset' };
  let jobError = false, statusError = false, reads = 0;
  let release!: (r: Response) => void;
  const pending = new Promise<Response>(resolve => { release = resolve; });
  const posts: string[] = [];
  vi.stubGlobal('fetch', vi.fn(async (input: unknown, init?: RequestInit) => {
    const url = String(input);
    if (init?.method === 'POST') { posts.push(url); return url.endsWith('/cancel') ? Response.json({ ...active, status: 'CANCELLED' }) : pending; }
    if (url.endsWith('/analysis-jobs/owned')) return jobError ? Response.json({}, { status: 503 }) : Response.json(job);
    if (url.endsWith('/ai-capabilities')) return Response.json({ available: true, network_interpretation: true, ddos_interpretation: true, remote: false });
    if (url.endsWith('/owned/ai-runs')) return Response.json({ items: origin === 'known' ? [active] : [], current_page: 1, page_size: 50, total: origin === 'known' ? 1 : 0 });
    if (url.endsWith('/ai-runs/active')) { reads++; return statusError ? Response.json({}, { status: 503 }) : Response.json(active); }
    return Response.json({ items: [] });
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } }); clients.push(client);
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/analyses/owned']}><App/></MemoryRouter></QueryClientProvider>);
  fireEvent.click(await screen.findByRole('button', { name: open }));
  if (origin !== 'known') {
    fireEvent.click(screen.getByRole('button', { name: 'New AI interpretation' }));
    await waitFor(() => expect(screen.getByRole('button', { name: submit })).toBeEnabled());
    fireEvent.click(screen.getByRole('button', { name: submit }));
    await waitFor(() => expect(posts).toHaveLength(1));
  } else await screen.findByRole('button', { name: 'Cancel AI run' });
  jobError = true;
  await act(async () => { await client.invalidateQueries({ queryKey: ['job', 'owned'] }); });
  if (origin !== 'known') await act(async () => { release(Response.json(active)); });
  await waitFor(() => expect(client.isMutating()).toBe(0));
  fireEvent.click(screen.getByRole('button', { name: '다시 시도' }));
  await waitFor(() => expect(client.isFetching()).toBe(0));
  expect(screen.queryByRole('button', { name: open })).not.toBeInTheDocument();
  expect(await screen.findByRole('button', { name: 'Cancel AI run' })).toBeEnabled();
  const before = reads;
  statusError = true;
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Retry status lookup' })); });
  await waitFor(() => expect(reads).toBeGreaterThan(before));
  await waitFor(() => expect(screen.queryByRole('button', { name: 'Cancel AI run' })).not.toBeInTheDocument());
  statusError = false;
  fireEvent.click(screen.getByRole('button', { name: 'Retry status lookup' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Cancel AI run' }));
  await waitFor(() => expect(posts.filter(p => p.endsWith('/cancel'))).toEqual(['/api/v1/ai-runs/active/cancel']));
  expect(posts.filter(p => !p.endsWith('/cancel'))).toHaveLength(origin === 'known' ? 0 : 1);
});
it.each(variants.flatMap(v => ['late valid receipt', 'lost receipt'].map(receipt => ({ ...v, receipt }))))('$kind reconciles $receipt by identity after source loss, then permits B cancellation', async ({ module, kind, report, open, receipt }) => {
  localStorage.setItem('c2hunter-token', 'fixture'); localStorage.setItem('c2hunter-report-language', 'en');
  const job = { id: 'owned', status: 'COMPLETED', name: 'Owned job', dataset_id: 'dataset', analysis: { module }, [module]: report };
  const a = { id: 'A', analysis_kind: kind, status: 'ANALYZING', language: 'en', analysis_job_id: 'owned', dataset_id: 'dataset', created_at: '2026-11-01T00:00:00Z' };
  const b = { ...a, id: 'B', created_at: '2026-11-02T00:00:00Z' };
  let rows = [a], terminal = false, jobError = false;
  let release!: (r: Response) => void;
  const held = new Promise<Response>(resolve => { release = resolve; });
  const posts: string[] = [];
  vi.stubGlobal('fetch', vi.fn(async (input: unknown, init?: RequestInit) => {
    const url = String(input);
    if (init?.method === 'POST') { posts.push(url); return url.endsWith('/A/cancel') ? held : Response.json({ ...b, status: 'CANCELLED' }); }
    if (url.endsWith('/analysis-jobs/owned')) return jobError ? Response.json({}, { status: 503 }) : Response.json(job);
    if (url.endsWith('/ai-capabilities')) return Response.json({ available: true, network_interpretation: true, ddos_interpretation: true, remote: false });
    if (url.endsWith('/owned/ai-runs')) return Response.json({ items: rows, current_page: 1, page_size: 50, total: rows.length });
    return Response.json(url.endsWith('/ai-runs/B') ? b : { ...a, status: terminal ? 'COMPLETED' : 'ANALYZING' });
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } }); clients.push(client);
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/analyses/owned']}><App/></MemoryRouter></QueryClientProvider>);
  fireEvent.click(await screen.findByRole('button', { name: open }));
  fireEvent.click(await screen.findByRole('button', { name: 'Cancel AI run' }));
  await waitFor(() => expect(posts).toEqual(['/api/v1/ai-runs/A/cancel']));
  jobError = true;
  await act(async () => { await client.invalidateQueries({ queryKey: ['job', 'owned'] }); });
  await waitFor(() => expect(screen.queryByRole('button', { name: open.replace('Open', 'Close') })).not.toBeInTheDocument());
  expect(screen.getByRole('button', { name: '다시 시도' })).toBeVisible();
  await act(async () => { release(receipt === 'lost receipt' ? Response.json({}, { status: 503 }) : Response.json({ ...a, status: 'CANCELLED' })); });
  await waitFor(() => expect(client.isMutating()).toBe(0));
  jobError = false;
  act(() => { client.setQueryData(['job', 'owned'], job); });
  await waitFor(() => expect(screen.getByRole('button', { name: open })).toBeVisible());
  await waitFor(() => expect(screen.getByText('AI cancellation unconfirmed — the run may still be active.')).toBeVisible());
  terminal = true;
  fireEvent.click(screen.getByRole('button', { name: 'Reconcile cancellation status' }));
  await waitFor(() => expect(screen.queryByText('AI cancellation unconfirmed — the run may still be active.')).not.toBeInTheDocument());
  if (receipt === 'lost receipt') expect(screen.getByText(/Terminal status observed; original cancellation acknowledgement remains unknown/)).toBeVisible();
  rows = [b, a];
  await act(async () => { await client.invalidateQueries({ queryKey: ['ai-runs', 'owned'] }); });
  await waitFor(() => expect(screen.getByRole('button', { name: 'Cancel AI run' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: 'Cancel AI run' }));
  await waitFor(() => expect(posts).toEqual(['/api/v1/ai-runs/A/cancel', '/api/v1/ai-runs/B/cancel']));
});
it.each(variants.flatMap(v => [false, true].map(sourceError => ({ ...v, sourceError }))))('$kind retries only the captured request and destination, source error=$sourceError', async ({ module, kind, report, open, submit, sourceError }) => {
  localStorage.setItem('c2hunter-token', 'fixture'); localStorage.setItem('c2hunter-report-language', 'en');
  const job = { id: 'owned', status: 'COMPLETED', name: 'Owned job', dataset_id: 'dataset', analysis: { module }, [module]: report };
  const older = { id: 'older', analysis_kind: kind, status: 'COMPLETED', language: 'en' };
  const admitted = { ...older, id: 'admitted', status: 'ANALYZING' };
  let destination = 'https://original.invalid', jobError = false;
  let release!: (r: Response) => void;
  const held = new Promise<Response>(resolve => { release = resolve; });
  const bodies: string[] = [];
  vi.stubGlobal('fetch', vi.fn(async (input: unknown, init?: RequestInit) => {
    const url = String(input);
    if (init?.method === 'POST') { bodies.push(String(init.body)); if (bodies.length === 1) throw new TypeError('Lost receipt'); return held; }
    if (url.endsWith('/analysis-jobs/owned')) return jobError ? Response.json({}, { status: 503 }) : Response.json(job);
    if (url.endsWith('/ai-capabilities')) return Response.json({ available: true, network_interpretation: true, ddos_interpretation: true, remote: true, provider: 'provider', model_name: 'model', destination });
    if (url.endsWith('/owned/ai-runs')) return Response.json({ items: [older], current_page: 1, page_size: 50, total: 1 });
    return Response.json(url.endsWith('/ai-runs/admitted') ? admitted : older);
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } }); clients.push(client);
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/analyses/owned']}><App/></MemoryRouter></QueryClientProvider>);
  fireEvent.click(await screen.findByRole('button', { name: open }));
  fireEvent.click(screen.getByRole('button', { name: 'New AI interpretation' }));
  fireEvent.click(await screen.findByRole('checkbox', { name: /I consent/ }));
  await waitFor(() => expect(screen.getByRole('button', { name: submit })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: submit }));
  await waitFor(() => expect(bodies).toHaveLength(1));
  await waitFor(() => expect(client.isMutating()).toBe(0));
  fireEvent.click(screen.getByRole('button', { name: 'View saved run older' }));
  fireEvent.change(screen.getAllByRole('combobox', { name: /^(보고서 언어|Report language)$/ })[0], { target: { value: 'ko' } });
  if (sourceError) {
    jobError = true;
    await act(async () => { await client.invalidateQueries({ queryKey: ['job', 'owned'] }); });
    await screen.findByRole('button', { name: '다시 시도' });
  }
  destination = 'https://changed.invalid';
  fireEvent.click(await screen.findByRole('button', { name: '동일한 AI 요청 재시도' }));
  expect(await screen.findByText(/원래 모델 대상/)).toBeVisible();
  expect(bodies).toHaveLength(1);
  destination = 'https://original.invalid';
  const retry = screen.getByRole('button', { name: '동일한 AI 요청 재시도' });
  act(() => { retry.click(); retry.click(); });
  await waitFor(() => expect(bodies).toHaveLength(2));
  expect(bodies[1]).toBe(bodies[0]);
  expect(JSON.parse(bodies[1])).toEqual({ idempotency_key: expect.any(String), analysis_kind: kind, language: 'en', allow_remote: true });
  await act(async () => { release(Response.json(admitted)); });
  await waitFor(() => expect(client.isMutating()).toBe(0));
  if (sourceError) { jobError = false; act(() => { client.setQueryData(['job', 'owned'], job); }); }
  const opener = await screen.findByRole('button', { name: kind === 'DDOS_ATTACK' ? /DDoS AI 해석 (열기|닫기)/ : /^AI 해석 (열기|닫기)$/ });
  if (opener.getAttribute('aria-expanded') !== 'true') fireEvent.click(opener);
  expect(await screen.findByRole('button', { name: '저장 실행 보기 older' })).toHaveAttribute('aria-pressed', 'true');
  expect(bodies).toHaveLength(2);
});
