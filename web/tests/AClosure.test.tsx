import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import App from '../src/App';
import { ApiError } from '../src/api';

const candidate = { id: 'closure', job_id: 'job-a', candidate_ip: '203.0.113.9', severity: 'HIGH', score: 80, evidence: [] };
const flow = (id = 'flow-a', job = 'job-a') => ({ flow_id: id, job_id: job, timestamp: '2026-11-15T00:00:00Z', source_ip: '10.0.0.1', destination_ip: candidate.candidate_ip, protocol: 'TCP', direction: 'OUTBOUND', has_payload: true, current_label: null as null | { verdict: 'C2' } });
function setup() {
  const state = { candidate: { ...candidate } as typeof candidate & { job_id?: string }, candidateStatus: 200, flowStatus: 200, flows: [flow()], total: 1 };
  let release!: (response: Response) => void;
  const pending = new Promise<Response>(resolve => { release = resolve; });
  // Share the release barrier and bytes, not a native Response stream whose
  // clone finalizers can consume it before a later write on older Node versions.
  const reply = pending.then(async response => ({
    body: response.body === null ? null : await response.arrayBuffer(),
    init: { status: response.status, statusText: response.statusText, headers: new Headers(response.headers) },
  }));
  const requests: { path: string; method: string; body?: unknown }[] = [];
  localStorage.setItem('c2hunter-token', 'token');
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input); const method = init?.method ?? 'GET';
    requests.push({ path, method, body: init?.body ? JSON.parse(String(init.body)) : undefined });
    if (method === 'POST' || method === 'DELETE') {
      const { body, init: responseInit } = await reply;
      return new Response(body, responseInit);
    }
    if (path === '/api/v1/candidates/closure') return Response.json(state.candidateStatus === 200 ? state.candidate : { error: { message: 'Candidate read failed' } }, { status: state.candidateStatus });
    if (path.includes('/flows?')) return Response.json(state.flowStatus === 200 ? { items: state.flows, page: Number(new URL(path, 'http://fixture').searchParams.get('page')), page_size: 1, total: state.total } : { error: { message: 'Flow read failed' } }, { status: state.flowStatus });
    if (path.endsWith('/detection-guidance')) return Response.json({ conditions: [], adjustments: [], recommendations: [{ kind: 'MINIMUM_SCORE' }], warnings: [], recommended_reanalysis: { minimum_score: 17 } });
    if (path.endsWith('/payload-preview')) return Response.json({ payload_ascii: 'Retained payload', payload_hex: '00', sample_bytes: 1 });
    return Response.json({ items: [] });
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/candidates/closure']}><App /></MemoryRouter></QueryClientProvider>);
  const refresh = async (key = 'candidate-flows') => { await act(async () => { await client.invalidateQueries({ queryKey: [key] }); }); };
  return { state, requests, client, release, refresh, user: userEvent.setup() };
}

it.each([200, 204, 503])('gives each deferred write an independent response body and headers: %s', async status => {
  const { release } = setup();
  await screen.findByRole('button', { name: 'Flow review' });
  const firstRequest = fetch('/api/v1/fixture-write', { method: 'POST' });
  const secondRequest = fetch('/api/v1/fixture-write', { method: 'DELETE' });
  let settled = false;
  void firstRequest.then(() => { settled = true; });
  await Promise.resolve();
  expect(settled).toBe(false);
  const body = status === 204 ? null : JSON.stringify({ label: { verdict: 'BENIGN' }, note: '한글' });
  await act(async () => release(new Response(body, { status, headers: { 'content-type': 'application/json', 'x-fixture': 'original' } })));
  const first = await firstRequest;
  const second = await secondRequest;
  expect(first === second).toBe(false);
  expect(await first.text()).toBe(body ?? '');
  first.headers.set('x-fixture', 'changed');
  expect(second.bodyUsed).toBe(false);
  expect(second.headers.get('x-fixture')).toBe('original');
  expect(await second.text()).toBe(body ?? '');
  const later = await fetch('/api/v1/fixture-write', { method: 'POST' });
  expect(later === first).toBe(false);
  expect(later === second).toBe(false);
  expect(later.bodyUsed).toBe(false);
  expect(later.headers.get('x-fixture')).toBe('original');
  expect(await later.text()).toBe(body ?? '');
  for (const response of [first, second, later]) {
    expect(response.status).toBe(status);
    expect(response.headers.get('content-type')).toBe('application/json');
    if (status === 204) expect(response.body).toBeNull();
  }
});

async function draft(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole('button', { name: 'Flow review' }));
  await user.click(await screen.findByRole('button', { name: 'Inspect flow flow-a' }));
  await user.click(screen.getByRole('button', { name: 'Mark C2 flow-a' }));
  await user.type(screen.getByLabelText('Analyst note'), 'Owned draft');
}

it.each(['404', '410', 'source-change', 'source-missing', 'same-page-absence', 'candidate-403', 'candidate-404', 'candidate-410', 'candidate-id', 'candidate-ip'])('retires flow admission, not its pending owner: %s', async reason => {
  const { state, requests, refresh, user, release } = setup();
  await draft(user);
  const retainedForm = screen.getByLabelText('Analyst note').closest('form')!;
  await user.click(screen.getByRole('button', { name: 'Save C2 label' }));
  await waitFor(() => expect(requests.filter(r => r.method === 'POST')).toHaveLength(1));
  if (reason === 'source-change') state.candidate.job_id = 'job-b';
  else if (reason === 'source-missing') state.candidate.job_id = '';
  else if (reason === 'same-page-absence') state.flows = [];
  else if (reason === 'candidate-id') state.candidate.id = 'replacement';
  else if (reason === 'candidate-ip') state.candidate.candidate_ip = '203.0.113.10';
  else if (reason.startsWith('candidate-')) state.candidateStatus = Number(reason.slice(10));
  else state.flowStatus = Number(reason);
  await refresh(reason.startsWith('source-') || reason.startsWith('candidate-') ? 'candidate' : 'candidate-flows');
  await waitFor(() => expect(screen.queryByLabelText('Analyst note')).not.toBeInTheDocument());
  expect(screen.getByText(/flow-a · Saving/)).toBeInTheDocument();
  fireEvent.submit(retainedForm);
  await act(async () => release(Response.json({ label: { verdict: 'C2' } })));
  await screen.findByText('C2 label saved.');
  expect(requests.filter(r => r.method === 'POST')).toHaveLength(1);
  expect(requests.filter(r => r.path.endsWith('/detection-guidance'))).toHaveLength(0);
  expect(requests.find(r => r.method === 'POST')).toMatchObject({ path: '/api/v1/analysis-jobs/job-a/flow-labels', body: { flow_id: 'flow-a', verdict: 'C2', note: 'Owned draft' } });
});

it('keeps a flow draft and action authority through a transient 503', async () => {
  const { state, requests, refresh, user } = setup();
  await draft(user); state.flowStatus = 503; await refresh();
  expect(screen.getByLabelText('Analyst note')).toHaveValue('Owned draft');
  await user.click(screen.getByRole('button', { name: 'Save C2 label' }));
  await waitFor(() => expect(requests.filter(r => r.method === 'POST')).toHaveLength(1));
});

it('retires clean flow owners across twelve pages without cropping underlying flows', async () => {
  const { state, user } = setup(); state.total = 12;
  await user.click(await screen.findByRole('button', { name: 'Flow review' }));
  for (let i = 0; i < 12; i++) {
    await user.click(await screen.findByRole('button', { name: `Inspect flow flow-${i || 'a'}` }));
    expect(screen.getByLabelText('Flow review retention')).toHaveTextContent('1 of 8');
    if (i < 11) { state.flows = [flow(`flow-${i + 1}`)]; await user.click(screen.getByRole('button', { name: 'Next flows' })); }
  }
  expect(screen.getByText('Flows 12–12 of 12')).toBeInTheDocument();
});

it('refuses a ninth pinned owner, preserves pending work and drafts, and releases only an explicitly discarded idle owner', async () => {
  const { state, user, release, requests } = setup(); state.total = 9;
  await draft(user);
  await user.click(screen.getByRole('button', { name: 'Save C2 label' }));
  for (let i = 1; i < 8; i++) {
    state.flows = [flow(`flow-${i}`)]; await user.click(screen.getByRole('button', { name: 'Next flows' }));
    await user.click(await screen.findByRole('button', { name: `Inspect flow flow-${i}` }));
    await user.click(screen.getByRole('button', { name: `Mark benign flow-${i}` }));
    await user.type(screen.getByLabelText('Analyst note'), `draft-${i}`);
  }
  state.flows = [flow('flow-8')]; await user.click(screen.getByRole('button', { name: 'Next flows' }));
  await user.click(await screen.findByRole('button', { name: 'Inspect flow flow-8' }));
  expect(screen.getByLabelText('Flow review retention')).toHaveTextContent('8 of 8');
  expect(screen.getByRole('alert')).toHaveTextContent('8 retained flow reviews');
  expect(screen.queryByRole('button', { name: 'Mark benign flow-8' })).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Discard draft and release flow-a' })).toBeDisabled();
  expect(document.querySelectorAll('[aria-label^="Retained flow review "]')).toHaveLength(8);
  await user.click(screen.getByRole('button', { name: 'Discard draft and release flow-1' }));
  await user.click(screen.getByRole('button', { name: 'Inspect flow flow-8' }));
  expect(screen.getByRole('button', { name: 'Mark benign flow-8' })).toBeInTheDocument();
  expect(screen.getByLabelText('Flow review retention')).toHaveTextContent('8 of 8');
  await act(async () => release(Response.json({ label: { verdict: 'BENIGN' } })));
  await screen.findByText('BENIGN label saved.');
  expect(requests.filter(r => r.method === 'POST')).toHaveLength(1);
  expect(screen.getByLabelText('Flow review retention')).toHaveTextContent('8 of 8');
  await user.click(screen.getByRole('button', { name: 'Acknowledge and release flow-a' }));
  expect(screen.getByLabelText('Flow review retention')).toHaveTextContent('7 of 8');
});

function clickCallback(element: HTMLElement) {
  const props = Object.entries(element).find(([key]) => key.startsWith('__reactProps$'))?.[1] as { onClick: () => void };
  return props.onClick;
}
function submitCallback(element: HTMLElement) {
  const props = Object.entries(element).find(([key]) => key.startsWith('__reactProps$'))?.[1] as { onSubmit: (event: { preventDefault: () => void }) => void };
  return () => props.onSubmit({ preventDefault() {} });
}
it('refuses a retained label callback at cache-known retirement before React notification', async () => {
  const { user, client, requests } = setup();
  await draft(user);
  const submit = submitCallback(screen.getByLabelText('Analyst note').closest('form')!);
  await act(async () => {
    client.getQueryCache().find({ queryKey: ['candidate-flows', 'job-a', candidate.candidate_ip, 1] })!.setState({ error: new ApiError('Gone', 410), status: 'error' });
    submit();
  });
  expect(requests.filter(r => r.method === 'POST')).toHaveLength(0);
});
it('refuses retained DELETE at cache-known retirement before React notification', async () => {
  const { user, client, requests } = setup();
  await user.click(await screen.findByRole('button', { name: '점수 조정 및 작업' }));
  await user.click(screen.getByRole('button', { name: 'Delete candidate' }));
  const remove = clickCallback(screen.getByRole('button', { name: 'Delete permanently' }));
  await act(async () => {
    client.getQueryCache().find({ queryKey: ['candidate', 'closure'] })!.setState({ error: new ApiError('Gone', 410), status: 'error' });
    remove();
  });
  expect(requests.filter(r => r.method === 'DELETE')).toHaveLength(0);
});
it.each([403, 404, 410])('retires delete intent and its captured callback after candidate %s', async status => {
  const { state, user, refresh, requests } = setup();
  await user.click(await screen.findByRole('button', { name: '점수 조정 및 작업' }));
  await user.click(screen.getByRole('button', { name: 'Delete candidate' }));
  const staleDelete = clickCallback(screen.getByRole('button', { name: 'Delete permanently' }));
  state.candidateStatus = status; await refresh('candidate');
  await screen.findByText(/Candidate unavailable; retained summary/);
  await act(async () => staleDelete());
  expect(requests.filter(r => r.method === 'DELETE')).toHaveLength(0);
  expect(screen.queryByRole('dialog', { name: 'Delete candidate permanently' })).not.toBeInTheDocument();
  state.candidateStatus = 200; await refresh('candidate');
  await waitFor(() => expect(screen.queryByText(/Candidate unavailable; retained summary/)).not.toBeInTheDocument());
  expect(screen.queryByRole('region', { name: 'Selected candidate detail' })).not.toBeInTheDocument();
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  await act(async () => staleDelete());
  expect(requests.filter(r => r.method === 'DELETE')).toHaveLength(0);
  await user.click(screen.getByRole('button', { name: '점수 조정 및 작업' }));
  await user.click(screen.getByRole('button', { name: 'Delete candidate' }));
  await user.click(screen.getByRole('button', { name: 'Delete permanently' }));
  await waitFor(() => expect(requests.filter(r => r.method === 'DELETE')).toHaveLength(1));
});
it('keeps already admitted deletion owned and shows its settlement after retirement', async () => {
  const { state, user, refresh, requests, release } = setup();
  await user.click(await screen.findByRole('button', { name: '점수 조정 및 작업' }));
  await user.click(screen.getByRole('button', { name: 'Delete candidate' }));
  await user.click(screen.getByRole('button', { name: 'Delete permanently' }));
  state.candidateStatus = 410; await refresh('candidate');
  await screen.findByText(/Candidate unavailable; retained summary/);
  expect(screen.getByRole('button', { name: 'Deleting…' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled();
  await act(async () => release(new Response(null, { status: 204 })));
  await screen.findByText('Candidate deletion completed for the retired selection.');
  expect(screen.getByRole('heading', { name: candidate.candidate_ip })).toBeInTheDocument();
  expect(requests.filter(r => r.method === 'DELETE')).toHaveLength(1);
});

it.each(['404', '410', 'job-change', 'job-missing', 'candidate-id', 'candidate-ip', 'same-page-absence'])('retires idle drafts and real retained callbacks without a pending-write guard: %s', async reason => {
  const { state, user, refresh, requests } = setup();
  await draft(user);
  const submit = submitCallback(screen.getByLabelText('Analyst note').closest('form')!);
  const preview = clickCallback(screen.getByRole('button', { name: 'Preview payload flow-a' }));
  if (reason === 'job-change') state.candidate.job_id = 'job-b';
  else if (reason === 'job-missing') Reflect.deleteProperty(state.candidate, 'job_id');
  else if (reason === 'candidate-id') state.candidate.id = 'other';
  else if (reason === 'candidate-ip') state.candidate.candidate_ip = '203.0.113.10';
  else if (reason === 'same-page-absence') state.flows = [];
  else state.flowStatus = Number(reason);
  await refresh(reason.startsWith('job-') || reason.startsWith('candidate-') ? 'candidate' : 'candidate-flows');
  await screen.findByText(/Source selection retired; no new actions/);
  await act(async () => { submit(); preview(); });
  expect(requests.filter(r => r.method === 'POST' || r.path.endsWith('/payload-preview'))).toHaveLength(0);
  expect(screen.getByText('Draft retained for flow-a.')).toBeInTheDocument();
});

it('same-page removal requires fresh reselection, while a different page does not retire a draft', async () => {
  const { state, user, refresh, requests } = setup(); state.total = 2;
  await draft(user);
  const oldSubmit = submitCallback(screen.getByLabelText('Analyst note').closest('form')!);
  state.flows = [flow('flow-b')];
  await user.click(screen.getByRole('button', { name: 'Next flows' }));
  await screen.findByRole('button', { name: 'Inspect flow flow-b' });
  expect(screen.queryByText(/Source selection retired/)).not.toBeInTheDocument();
  state.flows = [flow()];
  await user.click(screen.getByRole('button', { name: 'Previous flows' }));
  await user.click(await screen.findByRole('button', { name: 'Inspect flow flow-a' }));
  expect(screen.getByLabelText('Analyst note')).toHaveValue('Owned draft');
  state.flows = []; await refresh();
  await screen.findByText(/Source selection retired/);
  state.flows = [flow()]; await refresh();
  expect(screen.queryByLabelText('Analyst note')).not.toBeInTheDocument();
  await user.click(await screen.findByRole('button', { name: 'Inspect flow flow-a' }));
  await act(async () => oldSubmit());
  expect(requests.filter(r => r.method === 'POST')).toHaveLength(0);
  await user.click(screen.getByRole('button', { name: 'Save C2 label' }));
  await waitFor(() => expect(requests.filter(r => r.method === 'POST')).toHaveLength(1));
});

async function openGuidance(fixture: ReturnType<typeof setup>) {
  fixture.state.flows[0].current_label = { verdict: 'C2' };
  await fixture.user.click(await screen.findByRole('button', { name: 'Flow review' }));
  await fixture.user.click(await screen.findByRole('button', { name: 'Inspect flow flow-a' }));
  await fixture.user.click(screen.getByRole('button', { name: '탐지 조정 가이드 flow-a' }));
  return screen.findByRole('button', { name: '추천 설정으로 재분석' });
}
it.each([404, 410])('rejects retained guided reanalysis after source %s, preserving admitted settlement and original scope', async status => {
  const fixture = setup(); const { state, user, refresh, requests, release } = fixture;
  const button = await openGuidance(fixture);
  const reanalyze = clickCallback(button);
  await user.click(button);
  await waitFor(() => expect(requests.filter(r => r.method === 'POST')).toHaveLength(1));
  state.flowStatus = status; await refresh();
  await screen.findByText(/Source selection retired/);
  await act(async () => reanalyze());
  await act(async () => release(Response.json({ id: 'new-job' })));
  await screen.findByText('Source flow reanalysis created; source selection retired.');
  expect(screen.getByRole('heading', { name: candidate.candidate_ip })).toBeInTheDocument();
  expect(requests.filter(r => r.method === 'POST')).toEqual([expect.objectContaining({ path: '/api/v1/analysis-jobs/job-a/reanalyze', body: expect.objectContaining({ minimum_score: 17 }) })]);
});
it('checks authoritative source at guided reanalysis admission before notification', async () => {
  const fixture = setup(); const { client, requests } = fixture;
  const reanalyze = clickCallback(await openGuidance(fixture));
  await act(async () => {
    client.getQueryCache().find({ queryKey: ['candidate', 'closure'] })!.setState({ data: { ...candidate, job_id: 'replacement' } });
    reanalyze();
  });
  expect(requests.filter(r => r.method === 'POST')).toHaveLength(0);
});

it('retained inspect callbacks cannot replace later pinned owners', async () => {
  const { state, user } = setup(); state.total = 2;
  await draft(user);
  const inspectA = clickCallback(screen.getByRole('button', { name: 'Inspect flow flow-a' }));
  state.flows = [flow('flow-b')]; await user.click(screen.getByRole('button', { name: 'Next flows' }));
  await user.click(await screen.findByRole('button', { name: 'Inspect flow flow-b' }));
  await user.click(screen.getByRole('button', { name: 'Mark benign flow-b' }));
  await user.type(screen.getByLabelText('Analyst note'), 'B draft');
  await act(async () => inspectA());
  expect(document.querySelectorAll('[aria-label^="Retained flow review "]')).toHaveLength(2);
  expect(screen.getByText('Draft retained for flow-b.')).toBeInTheDocument();
});
it('an idle retained release callback cannot discard a just-admitted write before render', async () => {
  const { user, requests, release } = setup(); await draft(user);
  const submit = submitCallback(screen.getByLabelText('Analyst note').closest('form')!);
  const discard = clickCallback(screen.getByRole('button', { name: 'Discard draft and release flow-a' }));
  await act(async () => { submit(); discard(); });
  await waitFor(() => expect(requests.filter(r => r.method === 'POST')).toHaveLength(1));
  expect(screen.getByLabelText('Flow review retention')).toHaveTextContent('1 of 8');
  await act(async () => release(Response.json({ label: { verdict: 'BENIGN' } })));
  await screen.findByText('BENIGN label saved.');
});

it('bounds eight pending owners and settled outcome DOM across twelve pages, requiring explicit acknowledgement', async () => {
  const { state, user, release, requests } = setup(); state.total = 12;
  await user.click(await screen.findByRole('button', { name: 'Flow review' }));
  const baseline = document.querySelectorAll('*').length;
  for (let i = 0; i < 12; i++) {
    const id = i ? `flow-${i}` : 'flow-a';
    if (i) { state.flows = [flow(id)]; await user.click(screen.getByRole('button', { name: 'Next flows' })); }
    const inspect = await screen.findByRole('button', { name: `Inspect flow ${id}` });
    await user.click(inspect);
    if (i >= 8) {
      expect(screen.getByRole('alert')).toHaveTextContent('8 retained flow reviews');
      expect(screen.queryByRole('button', { name: `Mark benign ${id}` })).not.toBeInTheDocument();
      expect(screen.getAllByRole('status')).toHaveLength(8);
      await user.click(screen.getByRole('button', { name: `Acknowledge and release ${i === 8 ? 'flow-a' : `flow-${i - 8}`}` }));
      await user.click(inspect);
    }
    await user.click(screen.getByRole('button', { name: `Mark benign ${id}` }));
    await user.type(screen.getByLabelText('Analyst note'), `note-${i}`);
    await user.click(screen.getByRole('button', { name: 'Save BENIGN label' }));
    await waitFor(() => expect(requests.filter(r => r.method === 'POST')).toHaveLength(i + 1));
    if (i === 7) {
      expect(screen.getByRole('button', { name: 'Discard draft and release flow-a' })).toBeDisabled();
      expect(screen.getByLabelText('Flow review retention')).toHaveTextContent('8 of 8');
      await act(async () => release(Response.json({ label: { verdict: 'BENIGN' } })));
      await waitFor(() => expect(screen.getAllByText('BENIGN label saved.')).toHaveLength(8));
    }
    if (i >= 8) await waitFor(() => expect(screen.getAllByText('BENIGN label saved.')).toHaveLength(8));
    expect(document.querySelectorAll('[aria-label^="Retained flow review "]').length).toBeLessThanOrEqual(8);
    expect(screen.getByRole('table', { name: 'Selected candidate flow' }).querySelectorAll('*').length).toBeLessThanOrEqual(200);
    expect(document.querySelectorAll('*').length).toBeLessThanOrEqual(baseline + 200);
  }
  expect(screen.getByText('Flows 12–12 of 12')).toBeInTheDocument();
  expect(requests.filter(r => r.method === 'POST').map(r => (r.body as { flow_id: string }).flow_id)).toEqual(['flow-a', ...Array.from({ length: 11 }, (_, i) => `flow-${i + 1}`)]);
  expect(requests.filter(r => r.path.includes('/flows?')).every(r => r.path.includes('page_size=50'))).toBe(true);
});

it('transient refresh failure preserves an admitted owner and its original visible settlement', async () => {
  const { state, user, refresh, requests, release } = setup();
  await draft(user); await user.click(screen.getByRole('button', { name: 'Save C2 label' }));
  await waitFor(() => expect(requests.filter(r => r.method === 'POST')).toHaveLength(1));
  state.flowStatus = 503; await refresh();
  expect(screen.getByRole('button', { name: 'Saving…' })).toBeDisabled();
  expect(screen.getByLabelText('Analyst note')).toHaveValue('Owned draft');
  await act(async () => release(Response.json({ label: { verdict: 'C2' } })));
  await screen.findByText('C2 label saved.');
  await waitFor(() => expect(requests.filter(r => r.path.endsWith('/detection-guidance'))).toHaveLength(1));
});
