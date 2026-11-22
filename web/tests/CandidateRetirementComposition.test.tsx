import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, useNavigate } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import App from '../src/App';
import { captureAuthentication, setAuthentication } from '../src/authentication';
import { candidateDetailHistory } from '../src/candidateDetailHistory';
import CandidateQueuePreview from '../src/CandidateQueuePreview';
import { api } from '../src/api';

const candidate = { id: 'composition-a', job_id: 'job-a', candidate_ip: '203.0.113.9', score: 80, severity: 'HIGH', evidence: [{ type: 'PERIODIC_BEACON', description: 'Retained reason', warnings: ['Limited coverage'] }] };
function Navigation() {
  const navigate = useNavigate();
  return <button onClick={() => navigate(-1)}>Browser Back</button>;
}
function mount(section = 'operations', status = 404) {
  vi.stubGlobal('matchMedia', vi.fn(() => ({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() })));
  localStorage.setItem('c2hunter-token', 'composition');
  const client = new QueryClient({ defaultOptions: { queries: { staleTime: 10_000, retry: 1, refetchOnWindowFocus: false } } });
  let missing = false;
  const requests: { path: string; method: string }[] = [];
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'http://localhost');
    requests.push({ path: url.pathname, method: init?.method ?? 'GET' });
    if (url.pathname === '/api/v1/candidates') return Response.json({ items: [candidate], total: 1, page: 1, page_size: 50 });
    if (url.pathname.includes('/flows')) return Response.json({ items: [{ flow_id: 'flow-a', job_id: 'job-a', timestamp: '2026-11-15T00:00:00Z', source_ip: '10.0.0.1', destination_ip: candidate.candidate_ip, protocol: 'TCP', direction: 'OUTBOUND', has_payload: true }], total: 1, page: 1, page_size: 50 });
    if (missing) return Response.json({ error: { code: status === 404 ? 'CANDIDATE_NOT_FOUND' : 'UNAVAILABLE', message: 'Missing source' } }, { status });
    return Response.json(candidate);
  }));
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[`/candidates/composition-a?detail=${section}${section === 'evidence' ? '&evidence=0' : section === 'flows' ? '&flow_page=1&flow=flow-a' : ''}`]}><App/><Navigation/></MemoryRouter></QueryClientProvider>);
  return { client, requests, remove: () => { missing = true; }, recover: () => { missing = false; } };
}

it.each(['operations', 'evidence', 'flows'])('retires canonical source and old %s history after an ordinary global preview proves deletion inside freshness', async section => {
  const user = userEvent.setup(); const { client, requests, remove, recover } = mount(section);
  if (section === 'evidence') await waitFor(() => expect(document.querySelector('.evidence.detailed')).toHaveTextContent('Retained reason'));
  else await screen.findByRole('button', { name: section === 'flows' ? 'Mark benign flow-a' : 'Delete candidate' });
  const updated = client.getQueryState(['candidate', candidate.id])!.dataUpdatedAt;
  const history = candidateDetailHistory(client, captureAuthentication().epoch);
  const oldEntries = [...history.entries.keys()];
  await user.click(screen.getByRole('button', { name: '메뉴 / Menu' }));
  await user.click(screen.getByRole('link', { name: 'Candidates' }));
  remove();
  await user.click(await screen.findByRole('button', { name: `Preview candidate ${candidate.candidate_ip}` }));
  await screen.findByText(/Selected candidate unavailable in this scope/);
  await user.click(screen.getByRole('button', { name: 'Browser Back' }));
  await user.click(screen.getByRole('button', { name: 'Browser Back' }));
  await screen.findByRole('heading', { name: candidate.candidate_ip });
  expect(Date.now() - updated).toBeLessThan(10_000);
  expect(screen.queryByRole('button', { name: 'Delete candidate' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Mark benign flow-a' })).not.toBeInTheDocument();
  expect(document.querySelector('.evidence.detailed')).toBeNull();
  await waitFor(() => expect(screen.getByText(/Candidate unavailable; retained summary is historical/)).toBeInTheDocument());
  await user.click(screen.getByRole('button', { name: '점수 조정 및 작업' }));
  expect(screen.queryByRole('button', { name: 'Delete candidate' })).not.toBeInTheDocument();
  expect(oldEntries.every(key => history.entries.get(key)?.retired)).toBe(true);
  expect(client.getQueryState(['candidate', candidate.id])?.error).toBeTruthy();
  expect(screen.getByRole('button', { name: '점수 조정 및 작업' })).toBeDisabled();
  recover();
  await user.click(screen.getByRole('button', { name: 'Retry candidate' }));
  await waitFor(() => expect(screen.getByRole('button', { name: '점수 조정 및 작업' })).toBeEnabled());
  expect(screen.queryByRole('button', { name: 'Delete candidate' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Mark benign flow-a' })).not.toBeInTheDocument();
  expect(document.querySelector('.evidence.detailed')).toBeNull();
  await user.click(screen.getByRole('button', { name: '점수 조정 및 작업' }));
  expect(screen.getByRole('button', { name: 'Delete candidate' })).toBeEnabled();
  await user.click(screen.getByRole('button', { name: 'Browser Back' }));
  expect(screen.queryByRole('button', { name: 'Delete candidate' })).not.toBeInTheDocument();
  expect(oldEntries.every(key => history.entries.get(key)?.retired)).toBe(true);
  expect(requests.every(request => request.method === 'GET')).toBe(true);
});

it('keeps canonical operations and history usable after a transient global preview 503', async () => {
  const user = userEvent.setup(); const { client, remove, requests } = mount('operations', 503);
  await screen.findByRole('button', { name: 'Delete candidate' });
  const before = client.getQueryState(['candidate', candidate.id]);
  await user.click(screen.getByRole('button', { name: '메뉴 / Menu' }));
  await user.click(screen.getByRole('link', { name: 'Candidates' }));
  remove();
  await user.click(await screen.findByRole('button', { name: `Preview candidate ${candidate.candidate_ip}` }));
  await screen.findByText(/Candidate preview could not be refreshed/);
  await user.click(screen.getByRole('button', { name: 'Browser Back' }));
  await user.click(screen.getByRole('button', { name: 'Browser Back' }));
  expect(await screen.findByRole('button', { name: 'Delete candidate' })).toBeEnabled();
  expect(client.getQueryState(['candidate', candidate.id])).toEqual(before);
  expect(requests.every(request => request.method === 'GET')).toBe(true);
});

function seededClient() {
  const client = new QueryClient({ defaultOptions: { queries: { staleTime: 10_000, retry: 1, refetchOnWindowFocus: false } } });
  const history = candidateDetailHistory(client, captureAuthentication().epoch);
  const keys = [candidate, { ...candidate, id: 'composition-b', candidate_ip: '203.0.113.10' }].map(source => {
    client.setQueryData(['candidate', source.id], source);
    const key = history.create(); history.bind(key, client.getQueryData<typeof candidate>(['candidate', source.id])!);
    return key;
  });
  return { client, history, keys };
}

it.each([
  { jobId: undefined, status: 404, code: 'CANDIDATE_NOT_FOUND', retired: true },
  { jobId: 'wrong-job', status: 404, code: 'CANDIDATE_NOT_FOUND', retired: false },
  { jobId: 'wrong-job', status: 404, code: 'JOB_NOT_FOUND', retired: false },
  { jobId: undefined, status: 404, code: 'HTTP_ERROR', retired: false },
  { jobId: undefined, status: 403, code: 'FORBIDDEN', retired: false },
  { jobId: undefined, status: 410, code: 'GONE', retired: false },
])('matches the actual global contract without retiring B or another client: $jobId $status $code', async ({ jobId, status, code, retired }) => {
  const { client, history, keys } = seededClient(); const other = seededClient();
  const b = client.getQueryState(['candidate', 'composition-b']);
  const a = other.client.getQueryState(['candidate', candidate.id]);
  vi.stubGlobal('fetch', vi.fn(async () => Response.json({ error: { code } }, { status })));
  render(<QueryClientProvider client={client}><MemoryRouter><CandidateQueuePreview id={candidate.id} jobId={jobId}/></MemoryRouter></QueryClientProvider>);
  await screen.findByRole('alert');
  expect(history.entries.get(keys[0])?.retired).toBe(retired);
  expect(Boolean(client.getQueryState(['candidate', candidate.id])?.error)).toBe(retired);
  expect(history.entries.get(keys[1])?.retired).toBe(false);
  expect(client.getQueryState(['candidate', 'composition-b'])).toEqual(b);
  expect(other.client.getQueryState(['candidate', candidate.id])).toEqual(a);
  expect(other.history.entries.get(other.keys[0])?.retired).toBe(false);
});

// Capture only real rendered callbacks and the registered query function, as in
// the retained C1 lifetime tests. No private cache mutation or hostile callbacks.
function retryListener(button: HTMLElement) {
  const key = Object.keys(button).find(key => key.startsWith('__reactProps$'))!;
  return (button as unknown as Record<string, { onClick: () => void }>)[key].onClick;
}

it.each(['current', 'close', 'selection ABA', 'authentication ABA', 'client replacement'])('fences queued retries and late error bodies after %s', async transition => {
  localStorage.setItem('c2hunter-token', 'composition');
  const first = seededClient(); const second = seededClient();
  let mode: 'error' | 'held' | 'success' = 'error';
  let stream!: ReadableStreamDefaultController<Uint8Array>;
  const fetcher = vi.fn(async (input: RequestInfo | URL) => {
    if (mode === 'held') return new Response(new ReadableStream<Uint8Array>({ start(controller) { stream = controller; } }), { status: 404 });
    return mode === 'error' ? Response.json({ error: { code: 'UNAVAILABLE' } }, { status: 503 }) : Response.json({ ...candidate, id: String(input).split('/').at(-1) });
  });
  vi.stubGlobal('fetch', fetcher);
  const view = (client: QueryClient, id?: string) => <QueryClientProvider client={client}><MemoryRouter>{id && <CandidateQueuePreview id={id}/>}</MemoryRouter></QueryClientProvider>;
  const mounted = render(view(first.client, candidate.id));
  const retry = retryListener(await screen.findByRole('button', { name: 'Retry candidate preview' }));
  const original = first.client.getQueryCache().find({ queryKey: ['candidate-queue-preview'], exact: false })!.options.queryFn as (context: { signal: AbortSignal }) => Promise<unknown>;
  mode = 'held';
  const signal = new AbortController().signal;
  const pending = original({ signal }).catch(error => error);
  await act(async () => { await Promise.resolve(); });
  expect(stream).toBeDefined();
  mode = 'success';
  if (transition === 'close') mounted.rerender(view(first.client));
  if (transition === 'selection ABA') {
    mounted.rerender(view(first.client, 'composition-b'));
    await screen.findByRole('heading', { name: candidate.candidate_ip });
    mounted.rerender(view(first.client, candidate.id));
    await screen.findByRole('heading', { name: candidate.candidate_ip });
  }
  if (transition === 'authentication ABA') {
    act(() => { setAuthentication('other'); setAuthentication('composition'); });
    mounted.rerender(view(first.client, candidate.id));
    await screen.findByRole('heading', { name: candidate.candidate_ip });
  }
  if (transition === 'client replacement') mounted.rerender(view(second.client, candidate.id));
  const before = fetcher.mock.calls.length;
  if (transition !== 'current') {
    await act(async () => { retry(); await original({ signal }).catch(() => undefined); });
    expect(fetcher.mock.calls.length).toBe(before);
  }
  // Fresh source belongs to the live owner, not the old error body's producer.
  const live = transition === 'client replacement' ? second : first;
  const currentSource = { ...candidate, evidence: [{ type: 'NEW', description: 'Fresh source', warnings: [] }] };
  live.client.setQueryData(['candidate', candidate.id], currentSource);
  const history = candidateDetailHistory(live.client, captureAuthentication().epoch);
  const key = history.create(); history.bind(key, live.client.getQueryData<typeof candidate>(['candidate', candidate.id])!);
  await act(async () => { stream.enqueue(new TextEncoder().encode(JSON.stringify({ error: { code: 'CANDIDATE_NOT_FOUND' } }))); stream.close(); await pending; });
  expect(signal.aborted).toBe(false);
  expect(Boolean(live.client.getQueryState(['candidate', candidate.id])?.error)).toBe(transition === 'current');
  expect(history.entries.get(key)?.retired).toBe(transition === 'current');
  if (transition !== 'current') expect(await pending).toEqual(new Error('Retired preview request'));
});

it('cancels only the canonical read retryer so a late ignored-abort success cannot revive retired authority', async () => {
  const { client, history, keys } = seededClient();
  let release!: (response: Response) => void;
  let calls = 0;
  vi.stubGlobal('fetch', vi.fn(async () => {
    calls++;
    if (calls === 1) return new Promise<Response>(resolve => { release = resolve; });
    return Response.json({ error: { code: 'CANDIDATE_NOT_FOUND' } }, { status: 404 });
  }));
  let consumed!: () => void;
  const bodyConsumed = new Promise<void>(resolve => { consumed = resolve; });
  const pending = client.fetchQuery({ queryKey: ['candidate', candidate.id], staleTime: 0, queryFn: async () => {
    try { return await api.get(`/candidates/${candidate.id}`); } finally { consumed(); }
  } }).catch(error => error);
  render(<QueryClientProvider client={client}><MemoryRouter><CandidateQueuePreview id={candidate.id}/></MemoryRouter></QueryClientProvider>);
  await screen.findByRole('alert');
  const retired = client.getQueryState(['candidate', candidate.id]);
  expect(retired?.status).toBe('error');
  await act(async () => { release(Response.json(candidate)); await bodyConsumed; await pending; });
  expect(client.getQueryState(['candidate', candidate.id])).toEqual(retired);
  expect(history.entries.get(keys[0])?.retired).toBe(true);
  expect(history.entries.get(keys[1])?.retired).toBe(false);
  expect(calls).toBe(2);
});
