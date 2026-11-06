import { act, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import AIInvestigationPanel from '../src/AIInvestigationPanel';
import type { InvestigationRun } from '../src/investigationTypes';
import { fixture } from './investigationFixtures';

const selected = () => screen.getByRole('region', { name: '선택 조사 / Selected investigation' });
const retry = () => screen.getByRole('button', { name: '상태 다시 읽기 / Retry status read' });
function held() {
  let resolve!: (response: Response) => void;
  return { promise: new Promise<Response>(done => { resolve = done; }), resolve: (response: Response) => resolve(response) };
}
async function coldHistory(revision = 0) {
  const queued = { ...fixture('run_queued') as InvestigationRun, revision };
  const calls: { url: string; init: RequestInit }[] = [];
  const state = {
    get: (): Response | Promise<Response> => Promise.reject(new Error('temporary read failure')),
    cancel: (): Response | Promise<Response> => Response.json({ ...queued, status: 'CANCELLED', revision: queued.revision + 1, reason: 'USER_CANCELLED' }),
  };
  vi.stubGlobal('fetch', vi.fn(async (input: unknown, init: RequestInit = {}) => {
    const url = String(input); calls.push({ url, init });
    if (url.endsWith('/capabilities')) return Response.json(fixture('capabilities'));
    if (url.includes('?limit=5')) return Response.json({ items: [queued], next_cursor: null });
    if (url.endsWith('/cancel')) return state.cancel();
    if (url.endsWith('/' + queued.id) && !init.method) return state.get();
    throw new Error('Unexpected request');
  }));
  const view = render(<AIInvestigationPanel jobId="job"/>);
  fireEvent.click(await screen.findByRole('button', { name: /2001:db8::1 · QUEUED/ }));
  await screen.findByRole('button', { name: '상태 다시 읽기 / Retry status read' });
  expect(selected()).toHaveTextContent('status unconfirmed');
  return { queued, state, calls, view };
}
function confirmCancellation(run: InvestigationRun) {
  fireEvent.click(screen.getByRole('button', { name: '조사 취소 / Cancel investigation' }));
  const confirmation = screen.getByRole('group', { name: '취소 확인 / Confirm cancellation' });
  expect(confirmation).toHaveTextContent(`Job job · IP ${run.target_ip} · Run ${run.id}`);
  fireEvent.click(within(confirmation).getByRole('button', { name: '이 조사 취소 확인 / Confirm cancel this run' }));
}
afterEach(() => vi.useRealTimers());

it('confirmed cold-history cancellation retires obsolete polling uncertainty, not the worker-release disclaimer', async () => {
  const { queued, calls, view } = await coldHistory();
  expect(calls.filter(call => call.init.method === 'POST')).toHaveLength(0);
  confirmCancellation(queued);
  await screen.findByText(/does not prove worker release/);
  expect(selected()).toHaveTextContent('CANCELLED');
  expect(selected()).not.toHaveTextContent('status unconfirmed');
  expect(screen.queryByRole('button', { name: '상태 다시 읽기 / Retry status read' })).not.toBeInTheDocument();
  expect(screen.queryByText('temporary read failure')).not.toBeInTheDocument();
  expect(calls.filter(call => call.init.method === 'POST').map(call => call.url)).toEqual([
    `/api/v1/analysis-jobs/job/ai-investigations/${queued.id}/cancel`,
  ]);
  vi.useFakeTimers(); const count = calls.length;
  await act(async () => vi.advanceTimersByTimeAsync(10000));
  expect(calls).toHaveLength(count);
  view.unmount(); expect(vi.getTimerCount()).toBe(0);
});

it('GET-only recovery keeps uncertainty while pending and failed, clearing it only on accepted status', async () => {
  const { queued, state, calls, view } = await coldHistory();
  const pending = held(); state.get = () => pending.promise;
  fireEvent.click(retry());
  expect(selected()).toHaveTextContent('status unconfirmed');
  await act(async () => pending.resolve(new Response('unavailable', { status: 503 })));
  expect(selected()).toHaveTextContent('status unconfirmed');
  state.get = () => Response.json(queued);
  fireEvent.click(retry()); await act(async () => {});
  expect(selected()).not.toHaveTextContent('status unconfirmed');
  expect(calls.filter(call => call.url.endsWith('/' + queued.id))).toHaveLength(3);
  expect(calls.filter(call => call.init.method === 'POST')).toHaveLength(0);
  view.unmount();
});

it.each(['failed', 'foreign-owner', 'stale-revision'])('a %s cancellation response does not clear current polling uncertainty', async fault => {
  const { queued, state, calls } = await coldHistory(2);
  state.cancel = () => fault === 'failed' ? Promise.reject(new Error('cancel failed')) : Response.json({
    ...queued, status: 'CANCELLED', revision: fault === 'stale-revision' ? queued.revision - 1 : queued.revision + 1,
    owner_id: fault === 'foreign-owner' ? 'other-owner' : queued.owner_id,
  });
  confirmCancellation(queued);
  await screen.findByText(/cancellation unconfirmed/);
  expect(selected()).toHaveTextContent('QUEUED');
  expect(selected()).toHaveTextContent('status unconfirmed');
  expect(retry()).toBeEnabled();
  expect(calls.filter(call => call.init.method === 'POST')).toHaveLength(1);
});

it('a late cancellation valid at dispatch but older than displayed state cannot retire newer uncertainty', async () => {
  const { queued, state, calls, view } = await coldHistory();
  const pending = held(); state.cancel = () => pending.promise;
  confirmCancellation(queued);
  vi.useFakeTimers();
  state.get = () => Response.json({ ...queued, revision: queued.revision + 2 });
  fireEvent.click(retry()); await act(async () => vi.advanceTimersByTimeAsync(0));
  expect(selected()).not.toHaveTextContent('status unconfirmed');
  state.get = () => Promise.reject(new Error('newer read failure'));
  await act(async () => vi.advanceTimersByTimeAsync(2000));
  expect(selected()).toHaveTextContent('newer read failure');
  await act(async () => pending.resolve(Response.json({ ...queued, status: 'CANCELLED', revision: queued.revision + 1, reason: 'USER_CANCELLED' })));
  expect(selected()).toHaveTextContent('QUEUED');
  expect(selected()).toHaveTextContent('newer read failure');
  expect(selected()).toHaveTextContent('status unconfirmed');
  expect(retry()).toBeEnabled();
  expect(calls.filter(call => call.init.method === 'POST')).toHaveLength(1);
  view.unmount(); expect(vi.getTimerCount()).toBe(0);
});

it('a retired cancellation owner cannot clear a newly mounted selection uncertainty', async () => {
  const first = await coldHistory(); const pending = held(); first.state.cancel = () => pending.promise;
  confirmCancellation(first.queued); first.view.unmount();
  const current = await coldHistory();
  await act(async () => pending.resolve(Response.json({ ...first.queued, status: 'CANCELLED', revision: first.queued.revision + 1 })));
  expect(selected()).toHaveTextContent('QUEUED');
  expect(selected()).toHaveTextContent('status unconfirmed');
  expect(retry()).toBeEnabled();
  expect(current.calls.filter(call => call.init.method === 'POST')).toHaveLength(0);
  current.view.unmount();
});
