import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { StrictMode } from 'react';
import { MemoryRouter } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import App from '../src/App';

// Promoted actual-App SHELL-1 reproduction: successful writes invalidate the
// real query; neither the retained row nor the mutation owner is mocked.
it.each([
  { initial: 'C2', target: 'BENIGN' },
  { initial: undefined, target: 'C2' },
])('saved $target label replaces $initial in both list and retained detail', async ({ initial, target }) => {
  const candidate = { id: 'review-candidate', job_id: 'review-job', candidate_ip: '203.0.113.9', severity: 'HIGH', score: 80, evidence: [] };
  const flowId = 'review-flow';
  const baseFlow = { flow_id: flowId, job_id: candidate.job_id, timestamp: '2026-11-15T00:00:00Z', source_ip: '10.0.0.1', destination_ip: candidate.candidate_ip, protocol: 'TCP', direction: 'OUTBOUND', has_payload: true };
  let current = initial;
  let reads = 0;
  const posts: unknown[] = [];
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(['candidate', candidate.id], candidate);
  localStorage.setItem('c2hunter-token', 'fixture');
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path.endsWith('/flow-labels') && init?.method === 'POST') {
      const body = JSON.parse(String(init.body));
      posts.push(body);
      current = body.verdict;
      return Response.json({ label: { verdict: current } });
    }
    if (path.includes('/flows?')) {
      reads++;
      return Response.json({ items: [{ ...baseFlow, current_label: current ? { verdict: current } : undefined }], page: 1, page_size: 50, total: 1 });
    }
    if (path.endsWith('/detection-guidance')) return Response.json({ conditions: [], adjustments: [], recommendations: [], warnings: [], recommended_reanalysis: { minimum_score: 17 } });
    return Response.json({ items: [] });
  }));
  render(<StrictMode><QueryClientProvider client={client}><MemoryRouter initialEntries={['/candidates/review-candidate']}><App /></MemoryRouter></QueryClientProvider></StrictMode>);
  const user = userEvent.setup();
  await user.click(await screen.findByRole('button', { name: 'Flow review' }));
  await user.click(await screen.findByRole('button', { name: `Inspect flow ${flowId}` }));
  await user.click(screen.getByRole('button', { name: `Mark ${target === 'C2' ? 'C2' : 'benign'} ${flowId}` }));
  await user.type(screen.getByLabelText('Analyst note'), 'Authoritative refreshed verdict');
  if (target === 'C2') await user.click(screen.getByLabelText('Create payload signature'));
  await user.click(screen.getByRole('button', { name: `Save ${target} label` }));
  await screen.findByText(`${target} label saved.`);
  await waitFor(() => expect(within(screen.getByRole('table', { name: 'Candidate flows' })).getByText(target, { exact: true })).toBeVisible());
  expect(reads).toBeGreaterThanOrEqual(2);
  expect(posts).toHaveLength(1);
  const beforeReselection = within(screen.getByRole('table', { name: 'Selected candidate flow' })).queryByText(target, { exact: true }) !== null;
  await user.click(screen.getByRole('button', { name: `Inspect flow ${flowId}` }));
  const afterReselection = within(screen.getByRole('table', { name: 'Selected candidate flow' })).queryByText(target, { exact: true }) !== null;
  expect({ beforeReselection, afterReselection }).toEqual({ beforeReselection: true, afterReselection: true });
  const detail = within(screen.getByRole('table', { name: 'Selected candidate flow' }));
  expect(detail.queryByText(initial ?? 'Unreviewed', { exact: true })).not.toBeInTheDocument();
  expect(Boolean(detail.queryByRole('button', { name: `탐지 조정 가이드 ${flowId}` }))).toBe(target === 'C2');
  expect(detail.getByText(`${target} label saved.`)).toBeVisible();
});

const candidate = { id: 'refresh-candidate', job_id: 'refresh-job', candidate_ip: '203.0.113.9', severity: 'HIGH', score: 80, evidence: [] };
const flowId = 'refresh-flow';
const baseFlow = { flow_id: flowId, job_id: candidate.job_id, timestamp: '2026-11-15T00:00:00Z', source_ip: '10.0.0.1', destination_ip: candidate.candidate_ip, protocol: 'TCP', direction: 'OUTBOUND', has_payload: true };
function mountRefresh() {
  let record = { ...baseFlow, current_label: { verdict: 'C2', confidence: 'HIGH', note: 'Original label' } };
  let page = 1;
  const requests: { path: string; method: string; body?: unknown; signal?: AbortSignal | null }[] = [];
  let release!: (response: Response) => void;
  const pending = new Promise<Response>(resolve => { release = resolve; });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(['candidate', candidate.id], candidate);
  localStorage.setItem('c2hunter-token', 'fixture');
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    const method = init?.method ?? 'GET';
    requests.push({ path, method, body: init?.body ? JSON.parse(String(init.body)) : undefined, signal: init?.signal });
    if (method === 'POST') return pending;
    if (path.includes('/flows?')) return Response.json({ items: [record], page, page_size: 50, total: 1 });
    if (path.endsWith('/payload-preview')) return Response.json({ payload_ascii: 'Retained preview', payload_hex: '00', sample_bytes: 1 });
    if (path.endsWith('/detection-guidance')) return Response.json({ conditions: [], adjustments: [], recommendations: [], warnings: [] });
    return Response.json({ items: [] });
  }));
  render(<StrictMode><QueryClientProvider client={client}><MemoryRouter initialEntries={['/candidates/refresh-candidate']}><App /></MemoryRouter></QueryClientProvider></StrictMode>);
  const user = userEvent.setup();
  const inspect = async () => user.click(await screen.findByRole('button', { name: `Inspect flow ${flowId}` }));
  const open = async () => {
    await user.click(await screen.findByRole('button', { name: 'Flow review' }));
    await inspect();
  };
  const refresh = async (changes: Partial<typeof record> = {}, responsePage = 1) => {
    record = { ...record, ...changes };
    page = responsePage;
    await act(async () => { await client.invalidateQueries({ queryKey: ['candidate-flows', candidate.job_id] }); });
  };
  return { user, client, requests, open, inspect, refresh, release: (response: Response) => release(response) };
}
function selectedDetail() { return within(screen.getByRole('table', { name: 'Selected candidate flow' })); }
function savedClick(button: HTMLElement) {
  return (Object.entries(button).find(([key]) => key.startsWith('__reactProps$'))?.[1] as { onClick: () => void }).onClick;
}

it('refreshes the current label without replacing an idle analyst draft or retained preview', async () => {
  const fixture = mountRefresh(); const { user } = fixture;
  await fixture.open();
  await user.click(screen.getByRole('button', { name: `Preview payload ${flowId}` }));
  await screen.findByText('Retained preview');
  await user.click(screen.getByRole('button', { name: `Mark C2 ${flowId}` }));
  await user.type(screen.getByLabelText('Analyst note'), 'Unsaved analyst judgment');
  await user.selectOptions(screen.getByLabelText('Confidence'), 'MEDIUM');
  await user.clear(screen.getByLabelText('Signature name'));
  await user.type(screen.getByLabelText('Signature name'), 'Draft signature');
  const draft = screen.getByLabelText('Analyst note');
  await fixture.refresh({ current_label: { verdict: 'BENIGN', confidence: 'CONFIRMED', note: 'Refreshed server label' } });
  expect(screen.getByLabelText('Analyst note')).toBe(draft);
  expect(draft).toHaveValue('Unsaved analyst judgment');
  expect(screen.getByLabelText('Confidence')).toHaveValue('MEDIUM');
  expect(screen.getByLabelText('Signature name')).toHaveValue('Draft signature');
  expect(screen.getByLabelText('Create payload signature')).toBeChecked();
  expect(screen.getByText('Retained preview')).toBeVisible();
  await fixture.inspect();
  expect(screen.getByLabelText('Analyst note')).toBe(draft);
  expect(screen.getByLabelText('Signature name')).toHaveValue('Draft signature');
  expect(screen.getByText('Retained preview')).toBeVisible();
  expect(fixture.requests.filter(request => request.method === 'POST')).toHaveLength(0);
  expect(selectedDetail().getByText('BENIGN', { exact: true })).toBeVisible();
  expect(selectedDetail().getByText('Refreshed server label')).toBeVisible();
  expect(selectedDetail().queryByText('Original label')).not.toBeInTheDocument();
  expect(selectedDetail().queryByRole('button', { name: `탐지 조정 가이드 ${flowId}` })).not.toBeInTheDocument();
});

it('keeps the admitted label mutation and draft through refresh, reselection and presentation switches', async () => {
  const fixture = mountRefresh(); const { user, client, requests } = fixture;
  await fixture.open();
  await user.click(screen.getByRole('button', { name: `Mark benign ${flowId}` }));
  await user.type(screen.getByLabelText('Analyst note'), 'Already admitted note');
  await user.selectOptions(screen.getByLabelText('Confidence'), 'MEDIUM');
  await user.click(screen.getByRole('button', { name: 'Save BENIGN label' }));
  await waitFor(() => expect(requests.filter(request => request.method === 'POST')).toHaveLength(1));
  const mutation = client.getMutationCache().getAll().find(item => item.state.status === 'pending')!;
  expect(mutation).toBeDefined();
  await fixture.refresh({ current_label: { verdict: 'C2', confidence: 'CONFIRMED', note: 'Concurrent server label' } });
  await fixture.inspect();
  expect(screen.getByRole('button', { name: 'Saving…' })).toBeDisabled();
  expect(screen.getByRole('button', { name: `Discard draft and release ${flowId}` })).toBeDisabled();
  fireEvent.submit(screen.getByLabelText('Analyst note').closest('form')!);
  await user.click(screen.getByRole('button', { name: 'Raw candidate' }));
  expect(screen.getByText(`${flowId} · Saving…`)).toBeVisible();
  await user.click(screen.getByRole('button', { name: 'Flow review' }));
  await fixture.inspect();
  expect(screen.getByLabelText('Analyst note')).toHaveValue('Already admitted note');
  expect(screen.getByLabelText('Confidence')).toHaveValue('MEDIUM');
  expect(client.getMutationCache().getAll().filter(item => item.state.status === 'pending')).toEqual([mutation]);
  expect(requests.filter(request => request.method === 'POST')).toEqual([expect.objectContaining({
    path: '/api/v1/analysis-jobs/refresh-job/flow-labels',
    body: { flow_id: flowId, verdict: 'BENIGN', confidence: 'MEDIUM', note: 'Already admitted note', create_signature: false, signature_description: '' },
  })]);
  expect(requests.filter(request => request.method === 'POST').every(request => !request.signal?.aborted)).toBe(true);
  await act(async () => fixture.release(Response.json({ error: { message: 'Retained write failure' } }, { status: 503 })));
  expect(await screen.findByRole('alert')).toHaveTextContent('Retained write failure');
  expect(mutation.state.status).toBe('error');
  expect(screen.getByLabelText('Analyst note')).toHaveValue('Already admitted note');
  expect(screen.getByRole('button', { name: 'Save BENIGN label' })).toBeEnabled();
  expect(selectedDetail().getByText('Concurrent server label')).toBeVisible();
});

it.each(['page', 'job', 'flow'])('does not reauthorize a retained draft or old callback after a mismatched %s response recovers', async mismatch => {
  const fixture = mountRefresh(); const { user, requests } = fixture;
  await fixture.open();
  const stalePreview = savedClick(screen.getByRole('button', { name: `Preview payload ${flowId}` }));
  await user.click(screen.getByRole('button', { name: `Mark benign ${flowId}` }));
  await user.type(screen.getByLabelText('Analyst note'), 'Draft survives retirement');
  await fixture.refresh({
    ...(mismatch === 'job' ? { job_id: 'wrong-job' } : {}),
    ...(mismatch === 'flow' ? { flow_id: 'wrong-flow' } : {}),
    current_label: { verdict: 'BENIGN', confidence: 'HIGH', note: 'Foreign label' },
  }, mismatch === 'page' ? 2 : 1);
  await waitFor(() => expect(screen.queryByRole('button', { name: `Mark benign ${flowId}` })).not.toBeInTheDocument());
  expect(screen.getByText(`Draft retained for ${flowId}.`)).toBeVisible();
  expect(selectedDetail().queryByText('Foreign label')).not.toBeInTheDocument();
  await fixture.refresh({ ...baseFlow, current_label: { verdict: 'BENIGN', confidence: 'CONFIRMED', note: 'Recovered server label' } });
  expect(screen.queryByRole('button', { name: `Mark benign ${flowId}` })).not.toBeInTheDocument();
  await act(async () => stalePreview());
  expect(requests.filter(request => request.path.endsWith('/payload-preview'))).toHaveLength(0);
  await fixture.inspect();
  expect(screen.getByLabelText('Analyst note')).toHaveValue('Draft survives retirement');
  await act(async () => stalePreview());
  expect(requests.filter(request => request.path.endsWith('/payload-preview'))).toHaveLength(0);
  await user.click(screen.getByRole('button', { name: `Preview payload ${flowId}` }));
  expect(await screen.findByText('Retained preview')).toBeVisible();
  expect(requests.filter(request => request.path.endsWith('/payload-preview'))).toHaveLength(1);
  expect(requests.filter(request => request.method === 'POST')).toHaveLength(0);
  expect(selectedDetail().getByText('BENIGN', { exact: true })).toBeVisible();
  expect(selectedDetail().getByText('Recovered server label')).toBeVisible();
});
