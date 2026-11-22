import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { StrictMode, useLayoutEffect } from 'react';
import { Link, MemoryRouter, useLocation } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import App from '../src/App';

const candidateA = { id: 'owner-a', job_id: 'owner-job-a', candidate_ip: '203.0.113.9', severity: 'HIGH', score: 80, evidence: [] };
const candidateB = { ...candidateA, id: 'owner-b', job_id: 'owner-job-b', candidate_ip: '203.0.113.10' };
const flowId = 'flow/part?query#fragment%';
const flow = { flow_id: flowId, job_id: candidateA.job_id, timestamp: '2026-11-15T00:00:00Z', source_ip: '10.0.0.1', destination_ip: candidateA.candidate_ip, protocol: 'TCP', direction: 'OUTBOUND', has_payload: true, current_label: { verdict: 'C2' } };
const createdId = 'created/part?query#fragment%';
const createdPath = `/analyses/${encodeURIComponent(createdId)}`;
// JobDetail currently interpolates the decoded route ID into its reads.
const createdReadPaths = [`/api/v1/analysis-jobs/${createdId}`, `/api/v1/analysis-jobs/${encodeURIComponent(createdId)}`];
type OwnerKind = 'candidate' | 'job';
function RouteWitness({ onCommit }: { onCommit: (path: string) => void }) {
  const { pathname } = useLocation();
  useLayoutEffect(() => { onCommit(pathname); }, [pathname, onCommit]);
  return <output aria-label="Current route">{pathname}</output>;
}
function setup(kind: OwnerKind) {
  const routeA = kind === 'candidate' ? '/candidates/owner-a' : '/analyses/owner-job-a';
  const routeB = kind === 'candidate' ? '/candidates/owner-b' : '/analyses/owner-job-b';
  const job = (id: string) => ({ id, name: id, status: 'COMPLETED', analysis_module: 'c2', candidate_count: 0 });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(['candidate', candidateA.id], candidateA);
  client.setQueryData(['candidate', candidateB.id], candidateB);
  client.setQueryData(['job', candidateA.job_id], job(candidateA.job_id));
  client.setQueryData(['job', candidateB.job_id], job(candidateB.job_id));
  let release!: (response: Response) => void;
  const pending = new Promise<Response>(resolve => { release = resolve; });
  const requests: { path: string; method: string; body?: unknown; signal?: AbortSignal | null }[] = [];
  let settled = 0;
  const commits: string[] = [];
  const commitActions: (() => void)[] = [];
  const onCommit = (path: string) => {
    commits.push(path);
    if (path === routeB) commitActions.forEach(callback => callback());
  };
  localStorage.setItem('c2hunter-token', 'token');
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input); const method = init?.method ?? 'GET';
    requests.push({ path, method, body: init?.body ? JSON.parse(String(init.body)) : undefined, signal: init?.signal });
    if (method === 'POST') { const response = await pending; settled++; return response; }
    if (path.includes('/flows?')) return Response.json({ items: [flow], page: 1, page_size: 50, total: 1 });
    if (path.endsWith('/detection-guidance')) return Response.json({ conditions: [], adjustments: [], recommendations: [{ kind: 'MINIMUM_SCORE' }], warnings: [], recommended_reanalysis: { minimum_score: 17 } });
    if (path.endsWith('/payload-preview')) return Response.json({ payload_ascii: 'Owned payload', payload_hex: '00', sample_bytes: 1 });
    if (createdReadPaths.includes(path)) return Response.json(job(createdId));
    return Response.json({ items: [] });
  }));
  render(<StrictMode><QueryClientProvider client={client}><MemoryRouter initialEntries={[routeA]}><App /><Link to={routeA}>Visit owner A</Link><Link to={routeB}>Visit owner B</Link><RouteWitness onCommit={onCommit}/></MemoryRouter></QueryClientProvider></StrictMode>);
  const user = userEvent.setup();
  const openFlow = async () => {
    await user.click(await screen.findByRole('button', { name: kind === 'candidate' ? 'Flow review' : '작업 정보' }));
    if (kind === 'candidate') await user.click(await screen.findByRole('button', { name: `Inspect flow ${flowId}` }));
    await screen.findByRole('button', { name: `Mark C2 ${flowId}` });
  };
  const openGuidance = async () => {
    await openFlow();
    await user.click(screen.getByRole('button', { name: `탐지 조정 가이드 ${flowId}` }));
    return screen.findByRole('button', { name: '추천 설정으로 재분석' });
  };
  const settle = async (body: unknown) => {
    await act(async () => { release(Response.json(body)); });
    await waitFor(() => expect(client.getMutationCache().getAll().every(mutation => mutation.state.status === 'success')).toBe(true));
    expect(settled).toBe(1);
    expect(requests.filter(request => request.method === 'POST').every(request => !request.signal?.aborted)).toBe(true);
  };
  const expectSourceCached = () => {
    expect(client.getQueryData(['candidate', candidateA.id])).toEqual(candidateA);
    expect(client.getQueryData(['candidate', candidateB.id])).toEqual(candidateB);
    const key = kind === 'candidate' ? ['candidate-flows', candidateA.job_id] : ['job-flows', candidateA.job_id];
    expect(client.getQueriesData({ queryKey: key })).toEqual([[expect.any(Array), expect.objectContaining({ items: [flow] })]]);
  };
  return { user, client, requests, routeA, routeB, commits, commitActions, openFlow, openGuidance, settle, expectSourceCached };
}
function clickCallback(element: HTMLElement) {
  const props = Object.entries(element).find(([key]) => key.startsWith('__reactProps$'))?.[1] as { onClick: () => void };
  return props.onClick;
}
function submitCallback(element: HTMLElement) {
  const props = Object.entries(element).find(([key]) => key.startsWith('__reactProps$'))?.[1] as { onSubmit: (event: { preventDefault: () => void }) => void };
  return () => props.onSubmit({ preventDefault() {} });
}

it.each<OwnerKind>(['candidate', 'job'])('%s: a deferred reanalysis cannot steal cached B after ordinary route navigation', async kind => {
  const fixture = setup(kind);
  const { user, requests, routeB, commits, settle } = fixture;
  await user.click(await fixture.openGuidance());
  await waitFor(() => expect(requests.filter(request => request.method === 'POST')).toHaveLength(1));
  await user.click(screen.getByRole('link', { name: 'Visit owner B' }));
  expect(screen.getByLabelText('Current route')).toHaveTextContent(routeB);
  fixture.expectSourceCached();
  await settle({ id: createdId });
  expect(screen.getByLabelText('Current route')).toHaveTextContent(routeB);
  expect(commits).not.toContain(createdPath);
  expect(requests.filter(request => createdReadPaths.some(path => request.path.startsWith(path)))).toHaveLength(0);
  expect(requests.filter(request => request.method === 'POST')).toEqual([expect.objectContaining({ path: '/api/v1/analysis-jobs/owner-job-a/reanalyze', body: { idempotency_key: expect.any(String), minimum_score: 17 } })]);
});

it.each<OwnerKind>(['candidate', 'job'])('%s: A to B to a new A owner never revives the old publication', async kind => {
  const fixture = setup(kind);
  const { user, requests, routeA, commits, settle } = fixture;
  const staleReanalyze = clickCallback(await fixture.openGuidance());
  await act(async () => staleReanalyze());
  await waitFor(() => expect(requests.filter(request => request.method === 'POST')).toHaveLength(1));
  await user.click(screen.getByRole('link', { name: 'Visit owner B' }));
  await user.click(screen.getByRole('link', { name: 'Visit owner A' }));
  await fixture.openGuidance();
  fixture.expectSourceCached();
  await settle({ id: createdId });
  await act(async () => staleReanalyze());
  expect(screen.getByLabelText('Current route')).toHaveTextContent(routeA);
  expect(commits).not.toContain(createdPath);
  expect(requests.filter(request => request.method === 'POST')).toHaveLength(1);
  expect(requests.filter(request => createdReadPaths.some(path => request.path.startsWith(path)))).toHaveLength(0);
});

it.each<OwnerKind>(['candidate', 'job'])('%s: departed callbacks cannot admit reads or writes, including during the destination layout commit', async kind => {
  const fixture = setup(kind);
  const { user, requests, commitActions } = fixture;
  const reanalyze = clickCallback(await fixture.openGuidance());
  const preview = clickCallback(screen.getByRole('button', { name: `Preview payload ${flowId}` }));
  const guidance = clickCallback(screen.getByRole('button', { name: `탐지 조정 가이드 ${flowId}` }));
  await user.click(screen.getByRole('button', { name: `Mark C2 ${flowId}` }));
  await user.type(screen.getByLabelText('Analyst note'), 'Original raw flow identity');
  const submit = submitCallback(screen.getByLabelText('Analyst note').closest('form')!);
  const callbacks = [reanalyze, preview, guidance, submit];
  commitActions.push(...callbacks);
  const beforeDeparture = requests.length;
  await user.click(screen.getByRole('link', { name: 'Visit owner B' }));
  fixture.expectSourceCached();
  expect(requests.slice(beforeDeparture).filter(request => request.method === 'POST' || request.path.includes(`/flows/${encodeURIComponent(flowId)}/`))).toHaveLength(0);
  await user.click(screen.getByRole('link', { name: 'Visit owner A' }));
  await fixture.openFlow();
  const beforeOldCallbacks = requests.length;
  await act(async () => callbacks.forEach(callback => callback()));
  expect(requests).toHaveLength(beforeOldCallbacks);
  // Fresh owner authority remains usable; the old owner was not a global route flag.
  await user.click(screen.getByRole('button', { name: `Mark benign ${flowId}` }));
  await user.type(screen.getByLabelText('Analyst note'), 'Fresh owner');
  await user.click(screen.getByRole('button', { name: 'Save BENIGN label' }));
  await waitFor(() => expect(requests.filter(request => request.method === 'POST')).toHaveLength(1));
  expect(requests.find(request => request.method === 'POST')).toMatchObject({ path: '/api/v1/analysis-jobs/owner-job-a/flow-labels', body: { flow_id: flowId, note: 'Fresh owner' } });
  await fixture.settle({ label: { verdict: 'BENIGN' } });
  await screen.findByText('BENIGN label saved.');
});

it.each<OwnerKind>(['candidate', 'job'])('%s: an admitted C2 label settles after departure without admitting an automatic guidance read', async kind => {
  const fixture = setup(kind);
  const { user, requests, routeB } = fixture;
  await fixture.openFlow();
  await user.click(screen.getByRole('button', { name: `Mark C2 ${flowId}` }));
  await user.type(screen.getByLabelText('Analyst note'), 'Admitted before departure');
  await user.click(screen.getByRole('button', { name: 'Save C2 label' }));
  await waitFor(() => expect(requests.filter(request => request.method === 'POST')).toHaveLength(1));
  await user.click(screen.getByRole('link', { name: 'Visit owner B' }));
  await fixture.settle({ label: { verdict: 'C2' } });
  expect(screen.getByLabelText('Current route')).toHaveTextContent(routeB);
  expect(requests.filter(request => request.path.endsWith('/detection-guidance'))).toHaveLength(0);
  expect(requests.filter(request => request.method === 'POST')).toEqual([expect.objectContaining({ path: '/api/v1/analysis-jobs/owner-job-a/flow-labels', body: expect.objectContaining({ flow_id: flowId, note: 'Admitted before departure' }) })]);
});

it.each<{ kind: OwnerKind; presentation: string }>([
  { kind: 'candidate', presentation: 'mounted' },
  { kind: 'candidate', presentation: 'close' },
  { kind: 'candidate', presentation: 'switch' },
  { kind: 'job', presentation: 'mounted' },
  { kind: 'job', presentation: 'switch' },
])('$kind: StrictMode $presentation owner retains normal pending completion navigation', async ({ kind, presentation }) => {
  const fixture = setup(kind);
  const { user, requests, settle } = fixture;
  await user.click(await fixture.openGuidance());
  await waitFor(() => expect(requests.filter(request => request.method === 'POST')).toHaveLength(1));
  if (presentation === 'close') await user.click(screen.getByRole('button', { name: 'Close candidate detail' }));
  if (presentation === 'switch') await user.click(screen.getByRole('button', { name: kind === 'candidate' ? 'Raw candidate' : '결과·근거' }));
  if (presentation !== 'mounted') expect(screen.getByText(/Creating reanalysis/)).toBeInTheDocument();
  await settle({ id: createdId });
  await waitFor(() => expect(screen.getByLabelText('Current route')).toHaveTextContent(createdPath));
  expect(requests.filter(request => createdReadPaths.includes(request.path))).toHaveLength(1);
  expect(requests.filter(request => request.method === 'POST')).toHaveLength(1);
});
