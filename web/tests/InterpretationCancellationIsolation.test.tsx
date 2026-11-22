import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { readFileSync } from 'node:fs';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, expect, it, vi } from 'vitest';
import App from '../src/App';
const python = process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python');
const network = JSON.parse(execFileSync(python, ['tests/network_report_fixture.py', '--pagination'], { encoding: 'utf8' }))['20'];
const ddos = JSON.parse(readFileSync('tests/fixtures/ddos-report-contract.json', 'utf8'));
const clients: QueryClient[] = [];
afterEach(() => clients.splice(0).forEach(c => c.clear()));
const variants = [{ module: 'network_anomaly', kind: 'NETWORK_ANOMALY', report: network, open: 'Open AI interpretation' }, { module: 'ddos_attack', kind: 'DDOS_ATTACK', report: ddos, open: 'Open DDoS AI interpretation' }];
function deferred() { let resolve!: (r: Response) => void; const promise = new Promise<Response>(r => { resolve = r; }); return { promise, resolve }; }
async function setup(variant: typeof variants[number]) {
  const { module, kind, report, open } = variant;
  localStorage.setItem('c2hunter-token', 'fixture'); localStorage.setItem('c2hunter-report-language', 'en');
  const job = { id: 'owned', status: 'COMPLETED', name: 'Owned job', dataset_id: 'dataset', analysis: { module }, [module]: report };
  const a = { id: 'A', analysis_kind: kind, status: 'ANALYZING', language: 'en', analysis_job_id: 'owned', dataset_id: 'dataset', created_at: '2026-11-01T00:00:00Z' };
  const b = { ...a, id: 'B', created_at: '2026-11-02T00:00:00Z' };
  const state = { rows: [a], jobError: false, aUnreadable: false, aRead: undefined as ReturnType<typeof deferred> | undefined };
  const pendingA = deferred(), pendingB = deferred(), posts: string[] = [], reads: string[] = [];
  vi.stubGlobal('fetch', vi.fn(async (input: unknown, init?: RequestInit) => {
    const url = String(input);
    if (init?.method === 'POST') { posts.push(url); return url.endsWith('/A/cancel') ? pendingA.promise : pendingB.promise; }
    reads.push(url);
    if (url.endsWith('/analysis-jobs/owned')) return state.jobError ? Response.json({}, { status: 503 }) : Response.json(job);
    if (url.endsWith('/ai-capabilities')) return Response.json({ available: true, network_interpretation: true, ddos_interpretation: true, remote: false });
    if (url.includes('/owned/ai-runs')) return Response.json({ items: state.rows, current_page: 1, page_size: 50, total: state.rows.length });
    if (url.endsWith('/ai-runs/A')) return state.aRead ? state.aRead.promise : state.aUnreadable ? Response.json({}, { status: 503 }) : Response.json(a);
    return Response.json(state.rows.find(row => url.endsWith(`/ai-runs/${row.id}`)) ?? b);
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } }); clients.push(client);
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/analyses/owned']}><App/></MemoryRouter></QueryClientProvider>);
  fireEvent.click(await screen.findByRole('button', { name: open }));
  await waitFor(() => expect(client.getQueryData(['ai-run', 'A'])).toEqual(a));
  const cancel = () => screen.getByRole('button', { name: /^(Cancel AI run|Requesting cancellation…)$/ });
  act(() => { cancel().click(); cancel().click(); });
  await waitFor(() => expect(posts).toEqual(['/api/v1/ai-runs/A/cancel']));
  state.jobError = true;
  await act(async () => { await client.invalidateQueries({ queryKey: ['job', 'owned'] }); });
  await screen.findByRole('button', { name: '다시 시도' });
  state.aUnreadable = true; state.rows = [b, a]; state.jobError = false;
  fireEvent.click(screen.getByRole('button', { name: '다시 시도' }));
  await screen.findByRole('button', { name: open });
  await waitFor(() => expect(client.getQueryData(['ai-run', 'B'])).toEqual(b));
  return { state, a, b, client, posts, reads, pendingA, pendingB, cancel };
}
it.each(variants)('$kind allows validated B after late A ACK while A cannot be read', async variant => {
  const h = await setup(variant);
  await act(async () => { h.pendingA.resolve(Response.json({ ...h.a, status: 'CANCELLED' })); });
  await screen.findByText('AI cancellation unconfirmed — the run may still be active.');
  expect(h.cancel()).toBeEnabled();
  fireEvent.click(screen.getByRole('button', { name: 'Reconcile cancellation status' }));
  await waitFor(() => expect(h.reads.filter(p => p.endsWith('/ai-runs/A')).length).toBeGreaterThan(1));
  expect(h.cancel()).toBeEnabled();
  act(() => { h.cancel().click(); h.cancel().click(); });
  await waitFor(() => expect(h.posts).toEqual(['/api/v1/ai-runs/A/cancel', '/api/v1/ai-runs/B/cancel']));
  expect(within(screen.getByRole('group', { name: 'Cancellation receipt A' })).getByText('AI cancellation unconfirmed — the run may still be active.')).toBeVisible();
  await act(async () => { h.pendingB.resolve(Response.json({ ...h.b, status: 'CANCELLED' })); });
});

it.each(variants.flatMap(variant => ['failure', 'malformed', 'wrong language', 'valid'].flatMap(reply => ['pending', 'failed'].map(bState => ({ ...variant, reply, bState })))))('$kind late A $reply cannot clear B $bState lock or overwrite either receipt', async variant => {
  const h = await setup(variant);
  expect(h.cancel()).toBeEnabled();
  act(() => { h.cancel().click(); h.cancel().click(); });
  await waitFor(() => expect(h.posts).toHaveLength(2));
  if (variant.bState === 'failed') await act(async () => { h.pendingB.resolve(Response.json({}, { status: 503 })); });
  await act(async () => { h.pendingA.resolve(variant.reply === 'failure' ? Response.json({}, { status: 503 }) : variant.reply === 'malformed' ? Response.json({ status: 'CANCELLED' }) : Response.json({ ...h.a, status: 'CANCELLED', language: variant.reply === 'wrong language' ? 'ko' : 'en' })); });
  const aReceipt = await screen.findByRole('group', { name: 'Cancellation receipt A' });
  expect(within(aReceipt).getByText('AI cancellation unconfirmed — the run may still be active.')).toBeVisible();
  expect(h.cancel()).toBeDisabled();
  h.state.aRead = deferred();
  fireEvent.click(within(aReceipt).getByRole('button', { name: 'Reconcile cancellation status' }));
  expect(h.cancel()).toBeDisabled();
  await act(async () => { h.state.aRead!.resolve(Response.json({ ...h.a, status: 'COMPLETED' })); });
  await waitFor(() => expect(within(aReceipt).queryByRole('button', { name: 'Reconcile cancellation status' })).not.toBeInTheDocument());
  if (variant.reply !== 'valid') expect(within(aReceipt).getByText(/original cancellation acknowledgement remains unknown/)).toBeVisible();
  expect(h.cancel()).toBeDisabled();
  const bReceipt = screen.getByRole('group', { name: 'Cancellation receipt B' });
  expect(within(bReceipt).getByText(variant.bState === 'pending' ? 'AI cancellation pending — stopping is not yet confirmed.' : 'AI cancellation unconfirmed — the run may still be active.')).toBeVisible();
  fireEvent.click(within(aReceipt).getByRole('button', { name: 'Dismiss cancellation receipt' }));
  expect(h.cancel()).toBeDisabled();
  expect(h.posts).toEqual(['/api/v1/ai-runs/A/cancel', '/api/v1/ai-runs/B/cancel']);
  if (variant.bState === 'pending') await act(async () => { h.pendingB.resolve(Response.json({}, { status: 503 })); });
  expect(within(bReceipt).getByText('AI cancellation unconfirmed — the run may still be active.')).toBeVisible();
});
it.each(variants)('$kind refuses capacity honestly without evicting four unresolved receipts', async variant => {
  const h = await setup(variant);
  await act(async () => { h.pendingA.resolve(Response.json({}, { status: 503 })); });
  fireEvent.click(h.cancel());
  await act(async () => { h.pendingB.resolve(Response.json({}, { status: 503 })); });
  for (const [index, id] of ['C', 'D', 'E'].entries()) {
    const next = { ...h.b, id, created_at: `2026-11-0${index + 3}T00:00:00Z` };
    h.state.rows = [next, ...h.state.rows];
    await act(async () => { await h.client.invalidateQueries({ queryKey: ['ai-runs', 'owned'] }); });
    await waitFor(() => expect(h.client.getQueryData(['ai-run', id])).toEqual(next));
    if (id !== 'E') { fireEvent.click(h.cancel()); await waitFor(() => expect(screen.getByRole('group', { name: `Cancellation receipt ${id}` })).toHaveTextContent('AI cancellation unconfirmed')); }
  }
  expect(h.cancel()).toBeDisabled();
  expect(screen.getByText('Cancellation receipt capacity reached (4). Reconcile and dismiss a retained receipt before cancelling another run.')).toBeVisible();
  expect(screen.getAllByRole('group', { name: /^Cancellation receipt / })).toHaveLength(4);
  expect(h.posts).toEqual(['A', 'B', 'C', 'D'].map(id => `/api/v1/ai-runs/${id}/cancel`));
  expect(screen.queryByRole('group', { name: 'Cancellation receipt E' })).not.toBeInTheDocument();
  for (const id of ['A', 'B', 'C', 'D']) expect(within(screen.getByRole('group', { name: `Cancellation receipt ${id}` })).queryByRole('button', { name: 'Dismiss cancellation receipt' })).not.toBeInTheDocument();
  h.state.aRead = deferred();
  const aReceipt = screen.getByRole('group', { name: 'Cancellation receipt A' });
  fireEvent.click(within(aReceipt).getByRole('button', { name: 'Reconcile cancellation status' }));
  await act(async () => { h.state.aRead!.resolve(Response.json({ ...h.a, status: 'COMPLETED' })); });
  expect(h.cancel()).toBeDisabled(); // Reconciliation alone does not silently evict.
  fireEvent.click(within(aReceipt).getByRole('button', { name: 'Dismiss cancellation receipt' }));
  expect(h.cancel()).toBeEnabled();
  fireEvent.click(h.cancel());
  await waitFor(() => expect(h.posts).toEqual(['A', 'B', 'C', 'D', 'E'].map(id => `/api/v1/ai-runs/${id}/cancel`)));
  expect(screen.getAllByRole('group', { name: /^Cancellation receipt / })).toHaveLength(4);
});

it.each(variants)('$kind keeps B controls independent of held A recovery on the source-error owner', async variant => {
  const h = await setup(variant);
  await act(async () => { h.pendingA.resolve(Response.json({}, { status: 503 })); });
  await waitFor(() => expect(screen.getByRole('group', { name: 'Cancellation receipt A' })).toHaveTextContent('AI cancellation unconfirmed'));
  h.state.jobError = true;
  await act(async () => { await h.client.invalidateQueries({ queryKey: ['job', 'owned'] }); });
  await screen.findByRole('button', { name: '다시 시도' });
  h.state.aRead = deferred();
  fireEvent.click(within(screen.getByRole('group', { name: 'Cancellation receipt A' })).getByRole('button', { name: 'Reconcile cancellation status' }));
  expect(h.cancel()).toBeEnabled();
  act(() => { h.cancel().click(); h.cancel().click(); });
  await waitFor(() => expect(h.posts).toHaveLength(2));
  expect(h.cancel()).toBeDisabled();
  await act(async () => { h.pendingB.resolve(Response.json({}, { status: 503 })); });
  await act(async () => { h.state.aRead!.resolve(Response.json({ ...h.a, status: 'COMPLETED' })); });
  expect(within(screen.getByRole('group', { name: 'Cancellation receipt B' })).getByText('AI cancellation unconfirmed — the run may still be active.')).toBeVisible();
  fireEvent.click(within(screen.getByRole('group', { name: 'Cancellation receipt A' })).getByRole('button', { name: 'Dismiss cancellation receipt' }));
  expect(h.cancel()).toBeDisabled();
  expect(h.posts).toEqual(['/api/v1/ai-runs/A/cancel', '/api/v1/ai-runs/B/cancel']);
});
it.each(variants.flatMap(v => ['job', 'authentication'].map(departure => ({ ...v, departure }))))('$kind retires A recovery and B cancellation callbacks on $departure departure', async variant => {
  const h = await setup(variant);
  await act(async () => { h.pendingA.resolve(Response.json({}, { status: 503 })); });
  await waitFor(() => expect(screen.getByRole('group', { name: 'Cancellation receipt A' })).toHaveTextContent('AI cancellation unconfirmed'));
  h.state.aRead = deferred();
  fireEvent.click(within(screen.getByRole('group', { name: 'Cancellation receipt A' })).getByRole('button', { name: 'Reconcile cancellation status' }));
  fireEvent.click(h.cancel());
  await waitFor(() => expect(h.posts).toHaveLength(2));
  const capturedA = h.client.getQueryData(['ai-run', 'A']);
  if (variant.departure === 'job') fireEvent.click(screen.getByRole('link', { name: 'Back to analysis history' }));
  else fireEvent.click(screen.getByRole('button', { name: 'Sign out' }));
  await waitFor(() => expect(screen.queryByRole('group', { name: 'Cancellation receipt B' })).not.toBeInTheDocument());
  const reads = h.reads.length;
  await act(async () => { h.state.aRead!.resolve(Response.json({ ...h.a, status: 'COMPLETED' })); h.pendingB.resolve(Response.json({ ...h.b, status: 'CANCELLED' })); });
  // Sign out intentionally clears the query cache; late reads must not revive it.
  expect(h.client.getQueryData(['ai-run', 'A'])).toEqual(variant.departure === 'authentication' ? undefined : capturedA);
  expect(h.reads).toHaveLength(reads);
  expect(h.posts).toEqual(['/api/v1/ai-runs/A/cancel', '/api/v1/ai-runs/B/cancel']);
});
