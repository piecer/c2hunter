import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import AIInvestigationPanel from '../src/AIInvestigationPanel';
import { fixture } from './investigationFixtures';
import type { InvestigationRun } from '../src/investigationTypes';

it('previews then submits once, polls terminal automatically and opens issued evidence', async () => {
  const completed = fixture('run_completed') as InvestigationRun;
  const submitted: RequestInit[] = [];
  let captured: unknown;
  vi.stubGlobal('fetch', vi.fn(async (input: unknown, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith('/capabilities')) return Response.json(fixture('capabilities'));
    if (url.includes('?limit=5')) return Response.json({ items: [], next_cursor: null });
    if (url.endsWith('/source-preview')) return Response.json(fixture('source_preview'));
    if (url.endsWith('/ai-investigations') && init?.method === 'POST') {
      submitted.push(init); captured = JSON.parse(String(init.body));
      return Response.json({ ...(fixture('run_queued') as object), request: captured });
    }
    if (url.includes('/evidence/')) return Response.json(fixture('evidence_protocol'));
    if (url.includes('/steps?')) return Response.json({ items: [fixture('step_tool')], next_cursor: null });
    if (url.endsWith('/' + completed.id)) return Response.json({ ...completed, request: captured });
    throw new Error('Unexpected URL ' + url);
  }));
  render(<AIInvestigationPanel jobId="job" />);
  fireEvent.change(screen.getByLabelText('대상 IP / Target IP'), { target: { value: '2001:db8::1' } });
  await waitFor(() => expect(screen.getByRole('button', { name: '범위 미리보기 / Preview scope' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: '범위 미리보기 / Preview scope' }));
  await screen.findByText('Source ' + (fixture('source_preview') as { source: { source_sha256: string } }).source.source_sha256);
  fireEvent.click(screen.getByRole('button', { name: '조사 시작 / Start investigation' }));
  expect(await screen.findByText('관측된 통신은 추가 검토가 필요합니다.')).toBeVisible();
  expect(submitted).toHaveLength(1);
  expect(JSON.parse(String(submitted[0].body)).allow_remote).toBe(false);
  expect(within(screen.getByRole('region', { name: '관측 사실 / Observed facts' })).getByText('matched_rows')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: new RegExp('근거 보기.*' + (fixture('evidence_protocol') as { evidence_id: string }).evidence_id) }));
  expect(await screen.findByText('updates.example.test')).toBeVisible();
  await act(async () => {});
});

afterEach(() => vi.useRealTimers());
function deferred() {
  let resolve!: (response: Response) => void;
  const promise = new Promise<Response>(done => { resolve = done; });
  return { resolve, promise };
}
// Transport schedules below mutate copies of accepted producer documents, not
// alternative fixture meanings. Contract parity is tested on untouched bytes.
function transport() {
  const completed = fixture('run_completed') as InvestigationRun;
  const state = {
    history: { items: [] as InvestigationRun[], next_cursor: null as string | null },
    capability: () => Response.json(fixture('capabilities')),
    post: (() => Response.json(fixture('run_queued'))) as (init: RequestInit) => Response | Promise<Response>,
    detail: (() => Response.json(completed)) as (url: string, init: RequestInit) => Response | Promise<Response>,
    list: (() => Response.json(state.history)) as (url: string) => Response | Promise<Response>,
    steps: (() => Response.json({ items: [fixture('step_tool')], next_cursor: null })) as (url: string) => Response | Promise<Response>,
    cancel: (() => Response.json(fixture('run_cancelled'))) as (url: string) => Response | Promise<Response>,
  };
  const calls: { url: string; init: RequestInit }[] = [];
  vi.stubGlobal('fetch', vi.fn(async (input: unknown, init: RequestInit = {}) => {
    const url = String(input); calls.push({ url, init });
    if (url.endsWith('/capabilities')) return state.capability();
    if (url.endsWith('/source-preview')) return Response.json(fixture('source_preview'));
    if (url.includes('?limit=5')) return state.list(url);
    if (url.includes('/steps?')) return state.steps(url);
    if (url.includes('/evidence/')) return Response.json(fixture('evidence_protocol'));
    if (url.endsWith('/cancel')) return state.cancel(url);
    if (url.endsWith('/ai-investigations') && init.method === 'POST') return state.post(init);
    return state.detail(url, init);
  }));
  return { state, calls };
}
async function preview() {
  fireEvent.change(screen.getByLabelText('대상 IP / Target IP'), { target: { value: '2001:db8::1' } });
  await waitFor(() => expect(screen.getByRole('button', { name: '범위 미리보기 / Preview scope' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: '범위 미리보기 / Preview scope' }));
  await screen.findByRole('button', { name: '조사 시작 / Start investigation' });
}
const selectHistory = async (status: string) => fireEvent.click(await screen.findByRole('button', { name: new RegExp(`2001:db8::1 · ${status}`) }));

it('retries a timed-out acknowledgment with identical body/key and never auto-POSTs', async () => {
  const { state, calls } = transport();
  state.post = () => new Promise<Response>(() => {});
  const view = render(<AIInvestigationPanel jobId="job"/>);
  await preview();
  vi.useFakeTimers();
  fireEvent.click(screen.getByRole('button', { name: '조사 시작 / Start investigation' }));
  await act(async () => { await vi.advanceTimersByTimeAsync(15001); });
  const posts = () => calls.filter(call => call.init.method === 'POST' && call.url.endsWith('/ai-investigations'));
  expect(posts()).toHaveLength(1);
  expect(posts()[0].init.signal?.aborted).toBe(true);
  expect(screen.getByText(/Admission is unconfirmed/)).toBeVisible();
  await act(async () => { await vi.advanceTimersByTimeAsync(60000); });
  expect(posts()).toHaveLength(1);
  state.post = init => Response.json({ ...(fixture('run_queued') as object), request: JSON.parse(String(init.body)) });
  state.detail = () => new Promise<Response>(() => {});
  fireEvent.click(screen.getByRole('button', { name: '동일 요청 재시도 / Retry captured request' }));
  await act(async () => { await vi.advanceTimersByTimeAsync(0); });
  expect(posts()).toHaveLength(2);
  expect(posts()[1].init.body).toBe(posts()[0].init.body);
  expect(JSON.parse(String(posts()[1].init.body)).idempotency_key).toBeTruthy();
  view.unmount();
  expect(vi.getTimerCount()).toBe(0);
});

it('polls GET on the same open page until terminal without manual refresh', async () => {
  const { state, calls } = transport();
  const queued = fixture('run_queued') as InvestigationRun;
  state.history = { items: [queued], next_cursor: null };
  state.detail = () => Response.json(queued);
  const view = render(<AIInvestigationPanel jobId="job"/>);
  await screen.findByRole('button', { name: /2001:db8::1 · QUEUED/ });
  vi.useFakeTimers();
  fireEvent.click(screen.getByRole('button', { name: /2001:db8::1 · QUEUED/ }));
  await act(async () => { await vi.advanceTimersByTimeAsync(0); });
  const gets = () => calls.filter(call => call.url.endsWith('/' + queued.id));
  expect(gets()).toHaveLength(1);
  await act(async () => { await vi.advanceTimersByTimeAsync(1999); });
  expect(gets()).toHaveLength(1);
  state.detail = () => Response.json(fixture('run_completed'));
  await act(async () => { await vi.advanceTimersByTimeAsync(1); });
  expect(screen.getByText('관측된 통신은 추가 검토가 필요합니다.')).toBeVisible();
  await act(async () => { await vi.advanceTimersByTimeAsync(10000); });
  expect(gets()).toHaveLength(2);
  expect(calls.filter(call => call.init.method === 'POST')).toHaveLength(0);
  view.unmount(); expect(vi.getTimerCount()).toBe(0);
});

it('discards a delayed create acknowledgment after explicit history selection', async () => {
  const { state, calls } = transport();
  const held = deferred();
  let body: unknown;
  state.post = init => { body = JSON.parse(String(init.body)); return held.promise; };
  state.history = { items: [fixture('run_partial') as InvestigationRun], next_cursor: null };
  render(<AIInvestigationPanel jobId="job"/>); await preview();
  fireEvent.click(screen.getByRole('button', { name: '조사 시작 / Start investigation' }));
  await selectHistory('PARTIAL');
  await act(async () => { held.resolve(Response.json({ ...(fixture('run_queued') as object), request: body })); });
  expect(screen.getByRole('region', { name: '선택 조사 / Selected investigation' })).toHaveTextContent('PARTIAL');
  expect(calls.filter(call => call.init.method === 'POST' && call.url.endsWith('/ai-investigations'))).toHaveLength(1);
  expect(calls.filter(call => call.url.endsWith('/cancel'))).toHaveLength(0);
});

it.each([false, true])('requires explicit remote consent (%s) and captures language/question as text', async consent => {
  const { state, calls } = transport();
  state.capability = () => Response.json({ ...(fixture('capabilities') as object), remote_server_allowed: true });
  state.post = init => { const request = JSON.parse(String(init.body)); return Response.json({ ...(fixture('run_queued') as object), language: request.language, request }); };
  state.detail = () => new Promise<Response>(() => {});
  render(<AIInvestigationPanel jobId="job"/>);
  await waitFor(() => expect(screen.getByRole('checkbox')).toBeEnabled());
  expect(screen.getByRole('checkbox')).not.toBeChecked();
  if (consent) fireEvent.click(screen.getByRole('checkbox'));
  fireEvent.change(screen.getByLabelText('언어 / Language'), { target: { value: 'en' } });
  fireEvent.change(screen.getByLabelText('질문 / Question'), { target: { value: '<img src=x onerror=alert(1)> explain evidence' } });
  await preview();
  fireEvent.click(screen.getByRole('button', { name: '조사 시작 / Start investigation' }));
  const run = await screen.findByRole('region', { name: '선택 조사 / Selected investigation' });
  expect(run.querySelector('img')).toBeNull();
  expect(run).toHaveTextContent('<img src=x onerror=alert(1)> explain evidence');
  const request = JSON.parse(String(calls.find(call => call.init.method === 'POST' && call.url.endsWith('/ai-investigations'))!.init.body));
  expect(request.language).toBe('en'); expect(request.allow_remote).toBe(consent);
});

it('rejects a changed source binding and preserves the captured request for explicit action', async () => {
  const { state, calls } = transport();
  state.post = () => Response.json({ error: { code: 'SOURCE_BINDING_CHANGED', message: 'private details' } }, { status: 409 });
  render(<AIInvestigationPanel jobId="job"/>); await preview();
  fireEvent.click(screen.getByRole('button', { name: '조사 시작 / Start investigation' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('SOURCE_BINDING_CHANGED');
  expect(screen.queryByText('private details')).not.toBeInTheDocument();
  expect(calls.filter(call => call.url.endsWith('/ai-investigations') && call.init.method === 'POST')).toHaveLength(1);
  expect(screen.getByLabelText('대상 IP / Target IP')).toBeDisabled();
});

it('keeps history available when capability is forbidden, with actual cursors and non-first selection', async () => {
  const { state, calls } = transport();
  const first = fixture('run_failed') as InvestigationRun;
  const completed = fixture('run_completed') as InvestigationRun;
  state.capability = () => Response.json({ error: { code: 'FORBIDDEN' } }, { status: 403 });
  state.list = url => Response.json(url.includes('&after=') ? { items: [completed], next_cursor: null } : { items: [first], next_cursor: first.id });
  render(<AIInvestigationPanel jobId="job"/>);
  expect(await screen.findByText(/host.docker.internal/)).toBeVisible();
  await selectHistory('FAILED');
  expect(screen.getByRole('region', { name: '선택 조사 / Selected investigation' })).toHaveTextContent('FAILED');
  fireEvent.click(screen.getByRole('button', { name: '다음 이력 / Next history' }));
  await selectHistory('COMPLETED');
  expect(await screen.findByText('관측된 통신은 추가 검토가 필요합니다.')).toBeVisible();
  expect(calls.some(call => call.url.endsWith(`?limit=5&after=${first.id}`))).toBe(true);
  expect(screen.getByRole('button', { name: '범위 미리보기 / Preview scope' })).toBeDisabled();
});

it('displays the static capability reason header without extending the closed DTO', async () => {
  const { state } = transport();
  state.capability = () => Response.json({ ...(fixture('capabilities') as object), availability: 'UNAVAILABLE' }, { headers: { 'x-investigation-unavailable-reason': 'DISPATCH_UNAVAILABLE' } });
  render(<AIInvestigationPanel jobId="job"/>);
  expect(await screen.findByText(/DISPATCH_UNAVAILABLE/)).toBeVisible();
  expect(screen.getByText(/C2HUNTER_AI_INVESTIGATION_INLINE_ENABLED/)).toBeVisible();
});

it('shows 404 history failure rather than claiming an empty history', async () => {
  const { state } = transport();
  state.list = () => Response.json({ error: { code: 'NOT_FOUND' } }, { status: 404 });
  render(<AIInvestigationPanel jobId="job"/>);
  expect(await screen.findByRole('alert')).toHaveTextContent('NOT_FOUND');
  expect(screen.queryByText('저장된 조사 없음 / No saved investigations')).not.toBeInTheDocument();
});

it.each(['run_partial', 'run_failed', 'run_cancelled'])('renders truthful terminal %s without another model request', async name => {
  const { state, calls } = transport();
  const run = fixture(name) as InvestigationRun;
  state.history = { items: [run], next_cursor: null };
  render(<AIInvestigationPanel jobId="job"/>);
  await selectHistory(run.status);
  expect(screen.getByRole('region', { name: '선택 조사 / Selected investigation' })).toHaveTextContent(run.status);
  if (name === 'run_partial') expect(screen.getByText(/Facts only/)).toBeVisible();
  expect(calls.filter(call => call.init.method === 'POST')).toHaveLength(0);
});

it('retires selected-run polling when the user edits the target scope', async () => {
  const { state, calls } = transport();
  const queued = fixture('run_queued') as InvestigationRun;
  state.history = { items: [queued], next_cursor: null };
  state.detail = () => new Promise<Response>(() => {});
  render(<AIInvestigationPanel jobId="job"/>);
  await selectHistory('QUEUED');
  await waitFor(() => expect(calls.some(call => call.url.endsWith('/' + queued.id))).toBe(true));
  fireEvent.change(screen.getByLabelText('대상 IP / Target IP'), { target: { value: '10.0.0.123' } });
  expect(screen.queryByRole('region', { name: '선택 조사 / Selected investigation' })).not.toBeInTheDocument();
  expect(calls.find(call => call.url.endsWith('/' + queued.id))!.init.signal?.aborted).toBe(true);
});

it('aborts old-job reads and ignores late terminal data after job switch', async () => {
  const { state, calls } = transport();
  const queued = fixture('run_queued') as InvestigationRun;
  const held = deferred();
  state.history = { items: [queued], next_cursor: null };
  state.detail = () => held.promise;
  const view = render(<AIInvestigationPanel jobId="job"/>);
  await selectHistory('QUEUED');
  await waitFor(() => expect(calls.some(call => call.url.endsWith('/' + queued.id))).toBe(true));
  state.history = { items: [], next_cursor: null };
  view.rerender(<AIInvestigationPanel jobId="other-job"/>);
  expect(calls.find(call => call.url.endsWith('/' + queued.id))!.init.signal?.aborted).toBe(true);
  await act(async () => { held.resolve(Response.json(fixture('run_completed'))); });
  expect(screen.queryByText('관측된 통신은 추가 검토가 필요합니다.')).not.toBeInTheDocument();
  expect(screen.getByText('Job other-job')).toBeVisible();
});

it('owns polling by selected run and targets irreversible cancel at that exact identity', async () => {
  const { state, calls } = transport();
  const queued = fixture('run_queued') as InvestigationRun;
  const preparing = { ...(fixture('run_preparing') as InvestigationRun), id: 'c'.repeat(64) };
  const held = deferred();
  state.history = { items: [queued, preparing], next_cursor: null };
  state.detail = url => url.endsWith('/' + queued.id) ? held.promise : new Promise<Response>(() => {});
  state.cancel = () => Response.json({ ...preparing, status: 'CANCELLED', revision: preparing.revision + 1 });
  render(<AIInvestigationPanel jobId="job"/>);
  await selectHistory('QUEUED');
  await selectHistory('PREPARING');
  await act(async () => { held.resolve(Response.json(fixture('run_completed'))); });
  expect(screen.queryByText('관측된 통신은 추가 검토가 필요합니다.')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: '조사 취소 / Cancel investigation' }));
  expect(screen.getByRole('group', { name: '취소 확인 / Confirm cancellation' })).toHaveTextContent(preparing.id);
  fireEvent.click(screen.getByRole('button', { name: '이 조사 취소 확인 / Confirm cancel this run' }));
  expect(await screen.findByText(/does not prove worker release/)).toBeVisible();
  expect(calls.filter(call => call.url.endsWith('/cancel')).map(call => call.url)).toEqual([`/api/v1/analysis-jobs/job/ai-investigations/${preparing.id}/cancel`]);
});

it('stops and aborts outstanding polling when cancellation reaches terminal status', async () => {
  const { state, calls } = transport();
  const queued = fixture('run_queued') as InvestigationRun;
  state.history = { items: [queued], next_cursor: null };
  state.detail = () => new Promise<Response>(() => {});
  state.cancel = () => Response.json({ ...queued, status: 'CANCELLED', revision: queued.revision + 1 });
  render(<AIInvestigationPanel jobId="job"/>);
  await selectHistory('QUEUED');
  await waitFor(() => expect(calls.some(call => call.url.endsWith('/' + queued.id))).toBe(true));
  fireEvent.click(screen.getByRole('button', { name: '조사 취소 / Cancel investigation' }));
  fireEvent.click(screen.getByRole('button', { name: '이 조사 취소 확인 / Confirm cancel this run' }));
  await screen.findByText(/does not prove worker release/);
  expect(calls.find(call => call.url.endsWith('/' + queued.id))!.init.signal?.aborted).toBe(true);
});

it('rejects foreign scope evidence and foreign run responses before rendering', async () => {
  const { state } = transport();
  state.history = { items: [fixture('run_queued') as InvestigationRun], next_cursor: null };
  state.detail = () => Response.json({ ...(fixture('run_completed') as object), job_id: 'foreign-job' });
  render(<AIInvestigationPanel jobId="job"/>);
  await selectHistory('QUEUED');
  expect(await screen.findByRole('alert')).toHaveTextContent('contract or identity mismatch');
  expect(screen.queryByText('관측된 통신은 추가 검토가 필요합니다.')).not.toBeInTheDocument();
});

it('renders actual captured provider/model and expandable commitments without weight-identity claims', async () => {
  const { state } = transport();
  const run = fixture('run_completed') as InvestigationRun;
  state.history = { items: [run], next_cursor: null };
  render(<AIInvestigationPanel jobId="job"/>);
  await selectHistory('COMPLETED');
  const identity = screen.getByRole('region', { name: '캡처된 모델 / Captured model' });
  expect(within(identity).getByText(run.execution.model, { exact: true })).toBeVisible();
  expect(identity).toHaveTextContent('not an immutable weight digest');
  fireEvent.click(within(identity).getByText('실행 버전·설정·해시 / Execution versions, settings & hashes'));
  expect(within(identity).getByText(run.execution.model_config_sha256, { exact: true })).toBeVisible();
  expect(identity).toHaveTextContent(run.execution.policy_version);
});

it('reads receipt pages using server sequence cursors and opens their issued evidence', async () => {
  const { state, calls } = transport();
  state.history = { items: [fixture('run_failed') as InvestigationRun], next_cursor: null };
  const first = fixture('step_model') as { sequence: number };
  const last = fixture('step_tool');
  state.steps = url => Response.json(url.includes(`after=${first.sequence}&`) ? { items: [last], next_cursor: null } : { items: [first], next_cursor: first.sequence });
  render(<AIInvestigationPanel jobId="job"/>);
  await selectHistory('FAILED');
  fireEvent.click(screen.getByRole('button', { name: '도구 실행 기록 / Tool receipts' }));
  await waitFor(() => expect(screen.getByRole('button', { name: '다음 / Next receipts' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: '다음 / Next receipts' }));
  const button = await screen.findByRole('button', { name: new RegExp('근거 보기.*' + (fixture('evidence_protocol') as { evidence_id: string }).evidence_id) });
  fireEvent.click(button);
  expect(await screen.findByText('updates.example.test')).toBeVisible();
  expect(calls.some(call => call.url.endsWith(`/steps?after=${first.sequence}&limit=10`))).toBe(true);
});
