import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import NetworkAIInterpretation from '../src/NetworkAIInterpretation';
import NetworkAnomalyPanel, { type NetworkAnomalyReport } from '../src/NetworkAnomalyPanel';

// Real parser/producer evidence; AI runs are transport fixtures, not model output.
const python = process.env.C2HUNTER_PYTHON ?? process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python');
const reports = JSON.parse(execFileSync(python, ['tests/network_report_fixture.py', '--pagination'], { encoding: 'utf8' })) as Record<string, NetworkAnomalyReport>;
const report = reports['20'];
const interpretation = (summary: string) => ({
  schema_version: 'network-interpretation-v1', kind: 'MODEL_INTERPRETATION', language: 'en', summary,
  possible_causes: [{ hypothesis: 'Compare capture points.', uncertainty: 'Not confirmed.', issue_ids: [report.issues![19].id] }],
  prioritized_checks: [], correlations: [], limitations: ['Single vantage only.'],
});
const a = { id: 'run-a', analysis_kind: 'NETWORK_ANOMALY', status: 'COMPLETED', language: 'en', created_at: '2026-10-01T00:00:00Z', network_interpretation: interpretation('Saved hypothesis A') };
const b = { ...a, id: 'run-b', created_at: '2026-10-02T00:00:00Z', network_interpretation: interpretation('Latest hypothesis B') };
type Run = Omit<typeof a, 'network_interpretation' | 'created_at'> & { created_at?: string; network_interpretation?: ReturnType<typeof interpretation>; error_code?: string };
const clients: QueryClient[] = [];
afterEach(() => { clients.splice(0).forEach(client => client.clear()); });
function setup() {
  localStorage.setItem('c2hunter-report-language', 'en');
  const state = { items: [] as Run[], reflectPost: true, submitResponse: undefined as (() => Response | Promise<Response>) | undefined, readList: undefined as (() => Response | Promise<Response>) | undefined, readA: undefined as (() => Response | Promise<Response>) | undefined, readB: b as Run };
  const requests: { url: string; method: string }[] = [];
  vi.stubGlobal('fetch', vi.fn(async (input: unknown, init?: RequestInit) => {
    const url = String(input), method = init?.method ?? 'GET';
    requests.push({ url, method });
    if (url.endsWith('/ai-capabilities')) return Response.json({ available: true, network_interpretation: true, remote: false });
    if (url.endsWith('/analysis-jobs/reconcile/ai-runs')) {
      if (method === 'POST') {
        if (state.reflectPost) state.items = [a];
        return state.submitResponse?.() ?? Response.json({ ...a, status: 'QUEUED', network_interpretation: undefined });
      }
      return state.readList?.() ?? Response.json({ items: state.items });
    }
    if (url.endsWith('/ai-runs/run-a')) return state.readA?.() ?? Response.json(a);
    if (url.endsWith('/ai-runs/run-b')) return Response.json(state.readB);
    if (url.endsWith('/cancel')) return Response.json({});
    throw new Error(`Unexpected request: ${method} ${url}`);
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  clients.push(client);
  const view = render(<QueryClientProvider client={client}><NetworkAnomalyPanel report={report}><NetworkAIInterpretation jobId="reconcile" completed/></NetworkAnomalyPanel></QueryClientProvider>);
  const refresh = async () => { await act(async () => { await client.invalidateQueries({ queryKey: ['ai-runs', 'reconcile'] }); }); await waitFor(() => expect(client.isFetching()).toBe(0)); };
  const submit = async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Open AI interpretation' }));
    await waitFor(() => expect(screen.getByRole('button', { name: 'AI interpretation' })).toBeEnabled());
    fireEvent.click(screen.getByRole('button', { name: 'AI interpretation' }));
    await screen.findByText('Saved hypothesis A');
    await waitFor(() => expect(client.isMutating()).toBe(0));
  };
  return { ...view, client, state, requests, refresh, submit };
}

function deferredResponse() {
  let resolve!: (response: Response) => void;
  const promise = new Promise<Response>(done => { resolve = done; });
  return { promise, resolve };
}

it('follows the newer same-job active run after POST queued A completes through GET', async () => {
  const { state, submit, refresh, requests } = setup();
  await submit();
  state.readB = { ...b, status: 'ANALYZING', network_interpretation: undefined };
  state.items = [state.readB, a];
  await refresh();
  expect(screen.queryByText('Saved hypothesis A')).not.toBeInTheDocument();
  expect(await screen.findByRole('button', { name: 'Cancel AI run' })).toBeVisible();
  expect(screen.getByRole('button', { name: 'AI interpretation' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Cancel AI run' }));
  await waitFor(() => expect(requests).toContainEqual({ method: 'POST', url: '/api/v1/ai-runs/run-b/cancel' }));
  expect(requests.filter(request => request.method === 'POST' && !request.url.endsWith('/cancel'))).toHaveLength(1);
});

it('does not regress to an older or empty list after observing the newer run', async () => {
  const { state, submit, refresh } = setup();
  await submit();
  state.items = [b, a];
  await refresh();
  expect(screen.getByText('Latest hypothesis B')).toBeVisible();
  for (const stale of [[a], []]) {
    state.items = stale;
    await refresh();
    expect(screen.queryByText('Saved hypothesis A')).not.toBeInTheDocument();
    expect(screen.getByText('Latest hypothesis B')).toBeVisible();
  }
});

it.each(['QUEUED', 'PREPARING', 'VALIDATING', 'COMPLETED', 'FAILED', 'CANCELLED'])('follows newer %s B even when A is absent from the next list', async status => {
  const { state, submit, refresh, requests } = setup();
  state.reflectPost = false;
  await submit();
  state.readB = { ...b, status, error_code: status === 'FAILED' ? 'MODEL_TIMEOUT' : undefined };
  state.items = [{ ...b, analysis_kind: 'C2' }, state.readB];
  await refresh();
  expect(screen.queryByText('Saved hypothesis A')).not.toBeInTheDocument();
  const active = ['QUEUED', 'PREPARING', 'VALIDATING'].includes(status);
  await waitFor(() => expect(screen.getByRole('button', { name: 'AI interpretation' })).toHaveProperty('disabled', active));
  expect(Boolean(screen.queryByRole('button', { name: 'Cancel AI run' }))).toBe(active);
  if (status === 'COMPLETED') expect(screen.getByText('Latest hypothesis B')).toBeVisible();
  else expect(screen.queryByText('Latest hypothesis B')).not.toBeInTheDocument();
  if (status === 'FAILED') expect(screen.getByText(/MODEL_TIMEOUT/)).toBeVisible();
  expect(requests.filter(request => request.method === 'POST')).toHaveLength(1);
});

it('retains the POST-created queued run while an empty list and delayed detail lag behind', async () => {
  const { state, client, requests } = setup();
  const pending = deferredResponse();
  state.reflectPost = false;
  state.readA = () => pending.promise;
  fireEvent.click(screen.getByRole('button', { name: 'Open AI interpretation' }));
  await waitFor(() => expect(screen.getByRole('button', { name: 'AI interpretation' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: 'AI interpretation' }));
  expect(await screen.findByRole('button', { name: 'Cancel AI run' })).toBeVisible();
  expect(screen.getByText('Queued')).toBeVisible();
  expect(screen.getByRole('button', { name: 'AI interpretation' })).toBeDisabled();
  expect(screen.queryByText('No saved AI interpretation runs.')).not.toBeInTheDocument();
  await act(async () => { pending.resolve(Response.json(a)); });
  await screen.findByText('Saved hypothesis A');
  await waitFor(() => expect(client.isFetching()).toBe(0));
  expect(requests.filter(request => request.method === 'POST')).toHaveLength(1);
});

it('retains B and exposes a list failure without enabling another inference', async () => {
  const { state, submit, refresh, requests } = setup();
  await submit();
  state.items = [b, a];
  await refresh();
  state.readList = () => Response.json({ error: { message: 'List temporarily unavailable' } }, { status: 503 });
  await refresh();
  expect(screen.getByText('Latest hypothesis B')).toBeVisible();
  expect(screen.getByText(/status is unconfirmed/)).toBeVisible();
  expect(screen.getByRole('button', { name: 'AI interpretation' })).toBeDisabled();
  expect(screen.queryByText('Saved hypothesis A')).not.toBeInTheDocument();
  state.readList = undefined;
  fireEvent.click(screen.getByRole('button', { name: 'Retry status lookup' }));
  await waitFor(() => expect(screen.getByRole('button', { name: 'AI interpretation' })).toBeEnabled());
  expect(requests.filter(request => request.method === 'POST')).toHaveLength(1);
});

it.each([200, 503])('isolates a late A detail response (%s) after the list selects B', async status => {
  const { state, submit, client, requests } = setup();
  await submit();
  const pending = deferredResponse();
  state.readA = () => pending.promise;
  let oldRead!: Promise<void>;
  act(() => { oldRead = client.refetchQueries({ queryKey: ['ai-run', a.id] }); });
  await waitFor(() => expect(client.isFetching({ queryKey: ['ai-run', a.id] })).toBe(1));
  state.items = [b, a];
  await act(async () => { await client.invalidateQueries({ queryKey: ['ai-runs', 'reconcile'] }); });
  expect(await screen.findByText('Latest hypothesis B')).toBeVisible();
  await act(async () => { pending.resolve(Response.json(status === 200 ? a : { error: { message: 'Old run unavailable' } }, { status })); await oldRead; });
  expect(screen.queryByText('Saved hypothesis A')).not.toBeInTheDocument();
  expect(screen.queryByText(/Old run unavailable/)).not.toBeInTheDocument();
  expect(screen.getByText('Latest hypothesis B')).toBeVisible();
  expect(requests.filter(request => request.method === 'POST')).toHaveLength(1);
});

it('does not let a delayed POST response replace B already observed from the list', async () => {
  const { state, client, refresh } = setup();
  const pending = deferredResponse();
  state.reflectPost = false;
  state.submitResponse = () => pending.promise;
  fireEvent.click(screen.getByRole('button', { name: 'Open AI interpretation' }));
  await waitFor(() => expect(screen.getByRole('button', { name: 'AI interpretation' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: 'AI interpretation' }));
  await waitFor(() => expect(client.isMutating()).toBe(1));
  state.items = [b, a];
  await refresh();
  expect(screen.getByText('Latest hypothesis B')).toBeVisible();
  await act(async () => { pending.resolve(Response.json({ ...a, status: 'QUEUED', network_interpretation: undefined })); });
  await waitFor(() => expect(client.isMutating()).toBe(0));
  expect(screen.getByText('Latest hypothesis B')).toBeVisible();
  expect(screen.queryByText('Saved hypothesis A')).not.toBeInTheDocument();
});

const timestampCases = [
  { name: 'distinct', aTime: '2026-10-01T00:00:00.123Z', bTime: '2026-10-02T00:00:00.123Z' },
  { name: 'tied', aTime: '2026-10-01T00:00:00.123Z', bTime: '2026-10-01T00:00:00.123Z' },
  { name: 'submillisecond', aTime: '2026-10-01T00:00:00.123100Z', bTime: '2026-10-01T00:00:00.123900Z' },
  { name: 'missing', aTime: undefined, bTime: undefined },
];
for (const listState of ['empty', 'stale', 'failed'] as const) {
  it.each(timestampCases)(`retains observed B after ${listState} list and late POST A ($name timestamps)`, async ({ aTime, bTime }) => {
    const { state, client, refresh, requests } = setup();
    const queuedA = { ...a, created_at: aTime, status: 'QUEUED', network_interpretation: undefined };
    const pending = deferredResponse();
    state.reflectPost = false;
    state.submitResponse = () => pending.promise;
    state.readA = () => Response.json({ ...a, created_at: aTime });
    state.readB = { ...b, created_at: bTime, status: 'ANALYZING', network_interpretation: undefined };
    fireEvent.click(screen.getByRole('button', { name: 'Open AI interpretation' }));
    await waitFor(() => expect(screen.getByRole('button', { name: 'AI interpretation' })).toBeEnabled());
    fireEvent.click(screen.getByRole('button', { name: 'AI interpretation' }));
    await waitFor(() => expect(client.isMutating()).toBe(1));
    state.items = [state.readB, queuedA];
    await refresh();
    expect(screen.getByText('Analyzing')).toBeVisible();
    expect(requests).toContainEqual({ method: 'GET', url: '/api/v1/ai-runs/run-b' });
    state.items = listState === 'stale' ? [queuedA] : [];
    if (listState === 'failed') state.readList = () => Response.json({ error: { message: 'List temporarily unavailable' } }, { status: 503 });
    await refresh();
    expect(screen.getByText('Analyzing')).toBeVisible();
    await act(async () => { pending.resolve(Response.json(queuedA)); });
    await waitFor(() => expect(client.isMutating()).toBe(0));
    await waitFor(() => expect(client.isFetching()).toBe(0));
    expect(screen.queryByText('Saved hypothesis A')).not.toBeInTheDocument();
    expect(screen.getByText('Analyzing')).toBeVisible();
    expect(screen.getByRole('button', { name: 'AI interpretation' })).toBeDisabled();
    if (listState === 'failed') expect(screen.getByText(/status is unconfirmed/)).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: 'Cancel AI run' }));
    await waitFor(() => expect(client.isMutating()).toBe(0));
    expect(requests.filter(request => request.url.endsWith('/cancel'))).toEqual([{ method: 'POST', url: '/api/v1/ai-runs/run-b/cancel' }]);
    expect(requests.filter(request => request.method === 'POST' && !request.url.endsWith('/cancel'))).toHaveLength(1);
    expect(requests).not.toContainEqual({ method: 'GET', url: '/api/v1/ai-runs/run-a' });
  });
}

it.each([undefined, a.created_at])('accepts a manual new POST after known completed B without a new observed identity: %s', async created_at => {
  const { state, client, refresh, requests } = setup();
  await waitFor(() => expect(client.isFetching()).toBe(0));
  state.reflectPost = false;
  state.readB = { ...b, created_at };
  state.items = [state.readB];
  await refresh();
  fireEvent.click(screen.getByRole('button', { name: 'Open AI interpretation' }));
  expect(await screen.findByText('Latest hypothesis B')).toBeVisible();
  await waitFor(() => expect(screen.getByRole('button', { name: 'AI interpretation' })).toBeEnabled());
  const pending = deferredResponse();
  const detail = deferredResponse();
  const queuedA = { ...a, created_at, status: 'QUEUED', network_interpretation: undefined };
  state.submitResponse = () => pending.promise;
  state.readA = () => detail.promise;
  fireEvent.click(screen.getByRole('button', { name: 'AI interpretation' }));
  await waitFor(() => expect(client.isMutating()).toBe(1));
  // A refreshed object/status for the same identity is not a newer run.
  state.items = [{ ...state.readB, progress_percent: 100 } as Run];
  await refresh();
  await act(async () => { pending.resolve(Response.json(queuedA)); });
  await waitFor(() => expect(client.isMutating()).toBe(0));
  expect(await screen.findByText('Queued')).toBeVisible();
  expect(screen.queryByText('Latest hypothesis B')).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'AI interpretation' })).toBeDisabled();
  await act(async () => { detail.resolve(Response.json(queuedA)); });
  await waitFor(() => expect(client.isFetching()).toBe(0));
  fireEvent.click(screen.getByRole('button', { name: 'Cancel AI run' }));
  await waitFor(() => expect(client.isMutating()).toBe(0));
  expect(requests.filter(request => request.url.endsWith('/cancel'))).toEqual([{ method: 'POST', url: '/api/v1/ai-runs/run-a/cancel' }]);
  expect(requests.filter(request => request.method === 'POST' && !request.url.endsWith('/cancel'))).toHaveLength(1);
});

it('resets full-text ownership on A to B, preserves ko/en labels and never auto-submits', async () => {
  const { state, submit, refresh, requests } = setup();
  await submit();
  fireEvent.click(screen.getByRole('button', { name: 'View full AI text' }));
  expect(screen.getByRole('article', { name: 'Full AI interpretation' })).toBeVisible();
  state.items = [b, a];
  await refresh();
  expect(screen.queryByRole('article', { name: 'Full AI interpretation' })).not.toBeInTheDocument();
  expect(screen.getByText('Latest hypothesis B')).toBeVisible();
  fireEvent.change(screen.getByRole('combobox'), { target: { value: 'ko' } });
  expect(screen.getByRole('button', { name: 'AI 원문 전체 보기' })).toBeVisible();
  expect(screen.getByText('Latest hypothesis B')).toHaveAttribute('lang', 'en');
  fireEvent.click(screen.getByRole('button', { name: 'AI 원문 전체 보기' }));
  expect(screen.getByRole('article', { name: 'AI 해석 전체 원문' })).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: '분석 범위 상세 및 한계' }));
  expect(screen.queryByRole('article', { name: 'AI 해석 전체 원문' })).not.toBeInTheDocument();
  expect(screen.getByRole('region', { name: '분석 범위' })).toBeVisible();
  await refresh();
  expect(requests.filter(request => request.method === 'POST')).toHaveLength(1);
});

it.each([undefined, a.created_at])('uses authoritative list membership when timestamps are missing or tied: %s', async created_at => {
  const { state, submit, refresh } = setup();
  await submit();
  state.readB = { ...b, created_at };
  state.items = [state.readB, a];
  await refresh();
  expect(screen.getByText('Latest hypothesis B')).toBeVisible();
  state.items = [a];
  await refresh();
  expect(screen.getByText('Latest hypothesis B')).toBeVisible();
});
