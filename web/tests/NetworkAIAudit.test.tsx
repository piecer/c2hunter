import { openAI } from './reportDisclosure';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, useNavigate } from 'react-router-dom';
import { afterEach, expect, it, vi } from 'vitest';
import App from '../src/App';
import type { NetworkAnomalyReport } from '../src/NetworkAnomalyPanel';

// Deterministic report comes from the real parser/producer. AI responses below
// are explicit transport fixtures, not evidence of a live model/controller run.
const python = process.env.C2HUNTER_PYTHON ?? process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python');
const report = (JSON.parse(execFileSync(python, ['tests/network_report_fixture.py'], { encoding: 'utf8' })) as Record<string, NetworkAnomalyReport>).syn_reset;
const issueId = report.issues![0].id;
const queued = { id: 'audit-run', status: 'QUEUED', analysis_kind: 'NETWORK_ANOMALY', language: 'en' };
const completed = {
  ...queued, status: 'COMPLETED', provider: 'saved-provider', model_name: 'saved-model',
  network_interpretation: {
    schema_version: 'network-interpretation-v1', kind: 'MODEL_INTERPRETATION', language: 'en',
    summary: 'Saved English hypothesis, not a deterministic finding.',
    possible_causes: [{ hypothesis: 'Compare capture vantage points.', uncertainty: 'Not proven.', issue_ids: [issueId] }],
    prioritized_checks: [{ priority: 'HIGH', check: 'Inspect receiver capture.', issue_ids: [issueId] }],
    correlations: [{ interpretation: 'Potentially related observations.', issue_ids: [issueId] }], limitations: ['Single vantage only.'],
  },
};
const capability = { network_interpretation: true, available: true, provider: 'ollama', model_name: 'fixture-model', destination: 'http://model.internal:11434', remote: false, reason: null };
function Navigation() {
  const navigate = useNavigate();
  return <button onClick={() => navigate('/analyses/second')}>Open second job</button>;
}
const clients: QueryClient[] = [];
afterEach(() => { clients.splice(0).forEach(client => client.clear()); vi.useRealTimers(); });
async function setup(options: {
  capabilities?: Record<string, unknown>;
  run?: Record<string, unknown>;
  readRun?: () => Response | Promise<Response>;
  submit?: () => Response | Promise<Response>;
  savedReport?: boolean;
} = {}) {
  localStorage.setItem('c2hunter-token', 'fixture-token');
  localStorage.setItem('c2hunter-report-language', 'ko');
  const requests: { url: string; method: string; body?: unknown }[] = [];
  const fetcher = vi.fn(async (input: unknown, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? 'GET';
    requests.push({ url, method, body: init?.body ? JSON.parse(String(init.body)) : undefined });
    if (url === '/api/v1/ai-capabilities') return Response.json(options.capabilities ?? capability);
    if (url === '/api/v1/analysis-jobs/first/ai-runs' && method === 'POST') return options.submit?.() ?? Response.json(queued);
    if (url === '/api/v1/ai-runs/audit-run') return options.readRun?.() ?? Response.json(options.run ?? queued);
    if (url === '/api/v1/analysis-jobs/first/ai-runs') return Response.json({ items: options.run ? [options.run] : [] });
    if (url === '/api/v1/analysis-jobs/first' || url === '/api/v1/analysis-jobs/second') {
      const id = url.split('/').at(-1)!;
      return Response.json({ id, name: `${id} network job`, status: 'COMPLETED', analysis: { module: 'network_anomaly' }, ...(options.savedReport === false ? {} : { network_anomaly: report }) });
    }
    return Response.json({ items: [] });
  });
  vi.stubGlobal('fetch', fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  clients.push(client);
  const view = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/analyses/first']}><Navigation/><App/></MemoryRouter></QueryClientProvider>);
  await openAI();
  if (options.run?.status === 'COMPLETED' && (options.run.network_interpretation as { schema_version?: string; kind?: string } | undefined)?.schema_version === 'network-interpretation-v1' && (options.run.network_interpretation as { kind?: string }).kind === 'MODEL_INTERPRETATION') fireEvent.click(await screen.findByRole('button', { name: 'AI 원문 전체 보기' }));
  return { ...view, client, requests, posts: () => requests.filter(request => request.method === 'POST') };
}

it('shares one persisted language across the actual producer report and AI while preserving citations and source observations', async () => {
  const original = JSON.stringify(report);
  const { posts, unmount } = await setup({ run: completed });
  expect(await screen.findByText(completed.network_interpretation.summary)).toHaveAttribute('lang', 'en');
  expect(screen.getByRole('heading', { name: '이상 징후 관찰됨' })).toBeVisible();
  const ai = screen.getByRole('heading', { name: 'AI 생성 해석 — 분석가 검토 필요' }).closest('article')!;
  expect(within(ai).getAllByText(issueId)).toHaveLength(3);
  expect(screen.getAllByRole('combobox')).toHaveLength(1);
  fireEvent.change(screen.getByRole('combobox'), { target: { value: 'en' } });
  expect(screen.getByRole('heading', { name: 'Anomaly observed' })).toBeVisible();
  expect(within(ai).getByRole('heading', { name: 'Possible causes (AI hypotheses)' })).toBeVisible();
  expect(within(ai).getAllByText(issueId)).toHaveLength(3);
  expect(screen.getByText(completed.network_interpretation.summary)).toHaveAttribute('lang', 'en');
  expect(localStorage.getItem('c2hunter-report-language')).toBe('en');
  expect(JSON.stringify(report)).toBe(original);
  expect(posts()).toEqual([]);
  unmount();
});

it('does not substitute configured model provenance when the saved run omitted it', async () => {
  await setup({ run: { ...completed, provider: undefined, model_name: undefined } });
  const heading = await screen.findByRole('heading', { name: 'AI 생성 해석 — 분석가 검토 필요' });
  const ai = within(heading.closest('article')!);
  expect(ai.getByText('저장된 실행 제공자 / 모델: 보고되지 않음 · 보고되지 않음')).toBeVisible();
  expect(ai.queryByText(/fixture-model/)).not.toBeInTheDocument();
});

it('bounds literal issue references in every AI section without interpreting markup', async () => {
  const refs = Array.from({ length: 25 }, (_, i) => `citation-${i}`);
  refs[0] = '<a href="javascript:alert(1)">literal</a>';
  const source = completed.network_interpretation;
  const run = { ...completed, network_interpretation: {
    ...source,
    possible_causes: [{ ...source.possible_causes[0], issue_ids: refs }],
    prioritized_checks: [{ ...source.prioritized_checks[0], issue_ids: refs }],
    correlations: [{ ...source.correlations[0], issue_ids: refs }],
  } };
  await setup({ run });
  const heading = await screen.findByRole('heading', { name: 'AI 생성 해석 — 분석가 검토 필요' });
  const article = heading.closest('article')!;
  expect(within(article).getAllByText(text => text.startsWith(refs[0]))).toHaveLength(3);
  expect(within(article).getAllByText(/citation-19$/)).toHaveLength(3);
  expect(within(article).queryByText('citation-20')).not.toBeInTheDocument();
  expect(article.querySelector('a')).toBeNull();
});

it('requires a saved report even when the job status is completed', async () => {
  const { client, posts } = await setup({ savedReport: false });
  await screen.findByText(/아직 네트워크 보고서가 없습니다/);
  await waitFor(() => expect(client.isFetching()).toBe(0));
  const start = screen.getByRole('button', { name: 'AI 해석' });
  expect(start).toBeDisabled();
  fireEvent.click(start);
  expect(posts()).toEqual([]);
});

it.each([
  { ...capability, provider: 'future-provider', available: false, reason: 'AI_PROVIDER_UNSUPPORTED' },
  { ...capability, network_interpretation: false },
  { ...capability, remote: true, destination: null },
])('fails closed for unsupported, disabled, or undisclosed remote capabilities: %j', async capabilities => {
  const { client, posts } = await setup({ capabilities });
  await screen.findByRole('button', { name: 'AI 해석' });
  await waitFor(() => expect(client.isFetching()).toBe(0));
  const start = screen.getByRole('button', { name: 'AI 해석' });
  expect(start).toBeDisabled();
  fireEvent.click(start);
  expect(posts()).toEqual([]);
});

it('invalidates remote consent when the disclosed destination changes', async () => {
  const { client, posts } = await setup({ capabilities: { ...capability, remote: true } });
  fireEvent.click(await screen.findByRole('checkbox', { name: /원격 모델/ }));
  await waitFor(() => expect(screen.getByRole('button', { name: 'AI 해석' })).toBeEnabled());
  act(() => { client.setQueryData(['ai-capabilities'], { ...capability, remote: true, destination: 'https://different.invalid' }); });
  await waitFor(() => expect(screen.getByRole('checkbox')).not.toBeChecked());
  expect(screen.getByRole('button', { name: 'AI 해석' })).toBeDisabled();
  expect(posts()).toEqual([]);
});

it.each([
  undefined,
  { ...completed.network_interpretation, schema_version: 'future-schema' },
  { ...completed.network_interpretation, kind: 'UNVALIDATED' },
])('does not present missing or unvalidated completed output as AI findings: %j', async network_interpretation => {
  const { client, posts } = await setup({ run: { ...completed, network_interpretation } });
  await screen.findByText('이 실행의 검증된 해석 결과가 없습니다.');
  await waitFor(() => expect(client.isFetching()).toBe(0));
  expect(screen.queryByText(completed.network_interpretation.summary)).not.toBeInTheDocument();
  expect(screen.getByRole('heading', { name: '이상 징후 관찰됨' })).toBeVisible();
  expect(posts()).toEqual([]);
});

it('does not carry a submitted AI run or its polling into a different job route', async () => {
  const { client, requests } = await setup();
  await waitFor(() => expect(screen.getByRole('button', { name: 'AI 해석' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: 'AI 해석' }));
  await screen.findByRole('button', { name: 'AI 실행 취소' });
  await waitFor(() => expect(client.isFetching()).toBe(0));
  // Move the active observer's polling timer to the controlled clock before
  // navigating, so the assertion really exercises timer cleanup.
  vi.useFakeTimers();
  await act(async () => { await client.refetchQueries({ queryKey: ['ai-run', queued.id] }); });
  fireEvent.click(screen.getByRole('button', { name: 'Open second job' }));
  await act(async () => { await vi.advanceTimersByTimeAsync(100); });
  expect(screen.getByRole('heading', { name: 'second network job' })).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'AI 해석 열기' }));
  expect(screen.getByRole('button', { name: 'AI 해석' })).toBeEnabled();
  expect(screen.queryByRole('button', { name: 'AI 실행 취소' })).not.toBeInTheDocument();
  const reads = requests.filter(request => request.url === '/api/v1/ai-runs/audit-run').length;
  await act(async () => { await vi.advanceTimersByTimeAsync(4100); });
  expect(requests.filter(request => request.url === '/api/v1/ai-runs/audit-run')).toHaveLength(reads);
});

it('ignores late submission completion after navigating to another job', async () => {
  let resolveSubmission!: (response: Response) => void;
  const pending = new Promise<Response>(resolve => { resolveSubmission = resolve; });
  const { posts, client } = await setup({ submit: () => pending });
  await waitFor(() => expect(screen.getByRole('button', { name: 'AI 해석' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: 'AI 해석' }));
  await waitFor(() => expect(posts()).toHaveLength(1));
  fireEvent.click(screen.getByRole('button', { name: 'Open second job' }));
  await screen.findByRole('heading', { name: 'second network job' });
  await act(async () => { resolveSubmission(Response.json(completed)); });
  await waitFor(() => expect(client.isMutating()).toBe(0));
  expect(screen.queryByText(completed.network_interpretation.summary)).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'AI 실행 취소' })).not.toBeInTheDocument();
  expect(posts()).toHaveLength(1);
});

it('removes active polling timers on unmount without sending cancellation or another request', async () => {
  const { client, unmount, requests, posts } = await setup({ run: queued });
  await screen.findByRole('button', { name: 'AI 실행 취소' });
  await waitFor(() => expect(client.isFetching()).toBe(0));
  // Install fake clock, then explicitly refetch to schedule polling on this clock.
  vi.useFakeTimers();
  await act(async () => { await client.refetchQueries({ queryKey: ['ai-run', queued.id] }); });
  const beforeTick = requests.length;
  await act(async () => { await vi.advanceTimersByTimeAsync(2100); });
  expect(requests.length).toBeGreaterThan(beforeTick);
  const count = requests.length;
  unmount();
  await act(async () => { await vi.advanceTimersByTimeAsync(6100); });
  expect(requests).toHaveLength(count);
  expect(posts()).toEqual([]);
});

it('stops polling after a failed status read and never treats that failure as completion', async () => {
  let reads = 0;
  const { client, requests, posts } = await setup({ run: queued, readRun: () => ++reads === 1 ? Response.json(queued) : Response.json({ error: { code: 'UNAVAILABLE', message: 'Status temporarily unavailable' } }, { status: 503 }) });
  await screen.findByRole('button', { name: 'AI 실행 취소' });
  await waitFor(() => expect(client.isFetching()).toBe(0));
  vi.useFakeTimers();
  await act(async () => { await client.refetchQueries({ queryKey: ['ai-run', queued.id] }); await vi.advanceTimersByTimeAsync(10); });
  expect(screen.getByText(/Status temporarily unavailable/)).toBeVisible();
  expect(screen.getByRole('button', { name: 'AI 해석' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'AI 실행 취소' })).toBeDisabled();
  const count = requests.length;
  await act(async () => { await vi.advanceTimersByTimeAsync(6100); });
  expect(requests).toHaveLength(count);
  expect(posts()).toEqual([]);
});
