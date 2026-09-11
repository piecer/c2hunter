import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import App from '../src/App';
import { vi, expect, it } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import NetworkAnomalyPanel from '../src/NetworkAnomalyPanel';
import { useReportLanguage } from '../src/reportLanguageContext';

function LanguageProbe() { return <p>AI context: {useReportLanguage()}</p>; }
it('shares the report language with the adjacent AI interpretation controls', () => {
  localStorage.setItem('c2hunter-report-language', 'ko');
  render(<NetworkAnomalyPanel><LanguageProbe/></NetworkAnomalyPanel>);
  expect(screen.getByText('AI context: ko')).toBeVisible();
  fireEvent.change(screen.getByLabelText('보고서 언어 / Report language'), { target: { value: 'en' } });
  expect(screen.getByText('AI context: en')).toBeVisible();
});

function setup({ status = 'COMPLETED', remote = false, available = true, savedRun, runResponse, failPath, failMethod }: { status?: string; remote?: boolean; available?: boolean; savedRun?: Record<string, unknown>; runResponse?: () => Record<string, unknown>; failPath?: string; failMethod?: string } = {}) {
  localStorage.setItem('c2hunter-token', 'test-token');
  localStorage.setItem('c2hunter-report-language', 'ko');
  const posts: Array<{ url: string; body: Record<string, unknown> }> = [];
  const fetcher = vi.fn(async (input: unknown, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith(failPath ?? '/never') && (!failMethod || failMethod === init?.method)) return Response.json({ error: { code: 'AI_UNAVAILABLE', message: 'Service unavailable' } }, { status: 503 });
    if (url.endsWith('/ai-runs/run-1') && init?.method !== 'POST') return Response.json(runResponse?.() ?? savedRun);
    if (url.endsWith('/network/ai-runs') && init?.method !== 'POST') return Response.json({ items: savedRun ? [savedRun] : [] });
    if (init?.method === 'POST') {
      posts.push({ url, body: JSON.parse(String(init.body)) });
      return Response.json({ id: 'run-1', status: 'QUEUED', analysis_kind: 'NETWORK_ANOMALY', language: 'en', created_at: '2026-09-11T00:00:00Z' });
    }
    if (url.endsWith('/analysis-jobs/network')) return Response.json({ id: 'network', name: 'Network job', status, analysis: { module: 'network_anomaly' }, network_anomaly: { version: 'network-anomaly-v1', summary: {}, flows: [], warnings: [], limitations: [] } });
    if (url.endsWith('/ai-capabilities')) return Response.json({ network_interpretation: true, available, provider: 'ollama', model_name: 'configured-model', destination: 'http://model.internal:11434', remote, reason: available ? null : 'AI_MODEL_UNAVAILABLE' });
    return Response.json({ items: [] });
  });
  vi.stubGlobal('fetch', fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/analyses/network']}><App/></MemoryRouter></QueryClientProvider>);
  return { posts, fetcher, client };
}
it.each(['ANALYZING', 'PARTIALLY_COMPLETED', 'FAILED'])('does not start inference for %s jobs', async status => {
  const { posts, client } = setup({ status });
  await screen.findByRole('button', { name: 'AI 해석' });
  await waitFor(() => expect(client.isFetching()).toBe(0));
  expect(screen.getByRole('button', { name: 'AI 해석' })).toBeDisabled();
  expect(posts).toEqual([]);
});
it('requires explicit consent after disclosure of the remote destination', async () => {
  const { posts } = setup({ remote: true });
  expect(await screen.findByText(/http:\/\/model.internal:11434/)).toBeVisible();
  expect(screen.getByRole('button', { name: 'AI 해석' })).toBeDisabled();
  fireEvent.click(screen.getByRole('checkbox', { name: /원격 모델/ }));
  fireEvent.click(screen.getByRole('button', { name: 'AI 해석' }));
  await waitFor(() => expect(posts).toHaveLength(1));
  expect(posts[0].body.allow_remote).toBe(true);
});
it('truthfully explains disabled or unavailable AI without generating a result', async () => {
  const { posts } = setup({ available: false });
  expect(await screen.findByText(/AI_MODEL_UNAVAILABLE/)).toBeVisible();
  expect(screen.getByRole('button', { name: 'AI 해석' })).toBeDisabled();
  expect(posts).toEqual([]);
});
const queued = { id: 'run-1', status: 'QUEUED', analysis_kind: 'NETWORK_ANOMALY', language: 'en', created_at: '2026-09-11T00:00:00Z' };
const interpreted = { ...queued, status: 'COMPLETED', network_interpretation: { schema_version: 'network-interpretation-v1', kind: 'MODEL_INTERPRETATION', language: 'en', summary: 'Review capture visibility.', possible_causes: [{ hypothesis: 'Capture loss is possible.', issue_ids: ['issue-1'], uncertainty: 'Single vantage cannot confirm loss.' }], prioritized_checks: [{ priority: 'HIGH', check: 'Compare receiver capture.', issue_ids: ['issue-1'] }], correlations: [], limitations: ['No root cause proven.'] } };
it('loads saved interpretation through run GET and changes labels without translating or reinvoking', async () => {
  const { posts, fetcher } = setup({ savedRun: interpreted });
  expect(await screen.findByText('Review capture visibility.')).toBeVisible();
  expect(fetcher.mock.calls.some(([url]) => String(url).endsWith('/ai-runs/run-1'))).toBe(true);
  expect(screen.getByText('Capture loss is possible.')).toBeVisible();
  expect(screen.getByText('Single vantage cannot confirm loss.')).toBeVisible();
  fireEvent.change(screen.getByLabelText('보고서 언어 / Report language'), { target: { value: 'en' } });
  expect(screen.getByRole('heading', { name: 'Possible causes (AI hypotheses)' })).toBeVisible();
  expect(screen.getByText(/not automatically translated/)).toBeVisible();
  expect(screen.getByText('Review capture visibility.')).toHaveAttribute('lang', 'en');
  expect(posts).toEqual([]);
});
it('polls the saved queued run to validated completion without starting inference', async () => {
  let reads = 0;
  const { posts } = setup({ savedRun: queued, runResponse: () => ++reads > 1 ? interpreted : queued });
  expect(await screen.findByRole('button', { name: 'AI 실행 취소' })).toBeVisible();
  expect(screen.getByRole('button', { name: 'AI 해석' })).toBeDisabled();
  expect(await screen.findByText('Review capture visibility.', {}, { timeout: 3500 })).toBeVisible();
  expect(posts).toEqual([]);
});
it('cancels using the existing AI run endpoint and rereads persisted state', async () => {
  const { posts, fetcher } = setup({ savedRun: queued });
  fireEvent.click(await screen.findByRole('button', { name: 'AI 실행 취소' }));
  await waitFor(() => expect(posts[0]?.url).toBe('/api/v1/ai-runs/run-1/cancel'));
  await waitFor(() => expect(fetcher.mock.calls.filter(([url]) => String(url).endsWith('/ai-runs/run-1')).length).toBeGreaterThan(1));
});
it.each(['/ai-capabilities', '/network/ai-runs', '/ai-runs/run-1'])('shows truthful read failures for %s', async failPath => {
  const { posts } = setup({ savedRun: queued, failPath });
  expect(await screen.findByText(/Service unavailable/)).toBeVisible();
  expect(screen.getByRole('button', { name: 'AI 해석' })).toBeDisabled();
  expect(posts).toEqual([]);
});
it('keeps saved model provenance separate from the currently configured destination', async () => {
  setup({ savedRun: { ...interpreted, provider: 'saved-provider', model_name: 'saved-model', completed_at: '2026-09-11T00:01:00Z' } });
  expect(await screen.findByText(/saved-provider · saved-model/)).toBeVisible();
  expect(screen.getByText(/2026-09-11T00:01:00Z/)).toBeVisible();
});
it('bounds untrusted model prose and renders markup as plain text', async () => {
  const { posts } = setup({ savedRun: { ...interpreted, network_interpretation: { ...interpreted.network_interpretation, summary: '<img src=x onerror=alert(1)>', limitations: Array.from({ length: 25 }, (_, i) => `limit-${i}:` + 'x'.repeat(3000)) } } });
  expect(await screen.findByText('<img src=x onerror=alert(1)>')).toBeVisible();
  expect(document.querySelector('.ai-assessment img')).toBeNull();
  expect(screen.queryByText(/^limit-20:/)).not.toBeInTheDocument();
  expect(screen.getByText(/^limit-0:/).textContent?.length).toBe(2001);
  expect(posts).toEqual([]);
});
it.each(['FAILED', 'CANCELLED'])('does not display model output from a %s run', async status => {
  const { client } = setup({ savedRun: { ...interpreted, status, error_code: status === 'FAILED' ? 'MODEL_TIMEOUT' : undefined } });
  await screen.findByRole('button', { name: 'AI 해석' });
  await waitFor(() => expect(client.isFetching()).toBe(0));
  expect(screen.queryByText('Review capture visibility.')).not.toBeInTheDocument();
});
it('shows inference submission errors without implying a generated result', async () => {
  setup({ failPath: '/network/ai-runs', failMethod: 'POST' });
  await waitFor(() => expect(screen.getByRole('button', { name: 'AI 해석' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: 'AI 해석' }));
  expect(await screen.findByText(/Service unavailable/)).toBeVisible();
  expect(screen.queryByRole('heading', { name: /AI 생성 해석/ })).not.toBeInTheDocument();
});
it.each(['ko', 'en'])('manually submits selected %s language via existing AI runs without sending report data', async language => {
  const { posts } = setup();
  await waitFor(() => expect(screen.getByRole('button', { name: 'AI 해석' })).toBeEnabled());
  expect(posts).toEqual([]);
  fireEvent.change(screen.getByLabelText('보고서 언어 / Report language'), { target: { value: language } });
  expect(posts).toEqual([]);
  fireEvent.click(screen.getByRole('button', { name: language === 'ko' ? 'AI 해석' : 'AI interpretation' }));
  await waitFor(() => expect(posts).toHaveLength(1));
  expect(posts[0].url).toBe('/api/v1/analysis-jobs/network/ai-runs');
  expect(posts[0].body).toEqual({ idempotency_key: expect.any(String), analysis_kind: 'NETWORK_ANOMALY', language, allow_remote: false });
  expect(screen.queryByText('Candidate limit')).not.toBeInTheDocument();
});
