import { act, fireEvent, screen, within } from '@testing-library/react';
import { render } from './investigationDisplayRender';
import { afterEach, expect, it, vi } from 'vitest';
import AIInvestigationPanel from '../src/AIInvestigationPanel';
import JobInvestigationPanel from '../src/JobInvestigationPanel';
import { validatedIPSnapshot } from '../src/investigationSnapshot';
import { fixture } from './investigationFixtures';
import { producer } from './jobInvestigationFixtures';
import { parseJobWire } from '../src/jobInvestigationContract';
import type { InvestigationRun } from '../src/investigationTypes';
import { ReportLanguageContext } from '../src/reportLanguageContext';

const acknowledge = 'Acknowledge observed terminal outcome';
afterEach(() => vi.useRealTimers());
async function mount(kind: 'IP' | 'Job') {
  const ip = kind === 'IP';
  const queued = { ...(ip ? fixture('run_queued') as InvestigationRun : parseJobWire('run', producer.fixtures.run_queued)), revision: 2 };
  const cancelled = { ...queued, status: 'CANCELLED', revision: 3 };
  const other = { ...queued, id: 'f'.repeat(64) };
  const state = { history: queued as unknown };
  const calls: { url: string; init: RequestInit }[] = [];
  let resolve!: (r: Response) => void, reject!: (e: Error) => void;
  const held = new Promise<Response>((yes, no) => { resolve = yes; reject = no; });
  vi.stubGlobal('fetch', vi.fn(async (input: unknown, init: RequestInit = {}) => {
    const url = String(input); calls.push({ url, init });
    if (url.endsWith('/capabilities')) return new Response('{}', { status: 503 });
    if (url.includes('?limit=')) return Response.json({ items: [state.history], next_cursor: null });
    if (url.endsWith('/cancel')) return held;
    return new Promise<Response>(() => {});
  }));
  const panel = () => ip ? <AIInvestigationPanel jobId="job"/> : <JobInvestigationPanel jobId="job"/>;
  const view = render(<ReportLanguageContext.Provider value="en">{panel()}</ReportLanguageContext.Provider>);
  fireEvent.click(await screen.findByRole('button', { name: ip ? /2001:db8::1 · QUEUED/ : /View saved run QUEUED/ }));
  const region = () => screen.getByRole('region', { name: ip ? 'Selected investigation' : 'Saved job investigation' });
  const cancel = () => {
    fireEvent.click(screen.getByRole('button', { name: ip ? 'Cancel investigation' : 'Request cancellation of this run' }));
    if (ip) fireEvent.click(screen.getByRole('button', { name: 'Confirm cancel this run' }));
  };
  const refresh = async (value: unknown) => {
    state.history = value;
    await act(async () => fireEvent.click(screen.getByRole('button', { name: ip ? 'Retry history read' : 'First history / Refresh' })));
    const button = screen.queryByRole('button', { name: ip ? /2001:db8::1 ·/ : /View saved run/ });
    if (button) await act(async () => fireEvent.click(button));
  };
  return { queued, cancelled, other, state, calls, resolve, reject, view, panel, region, cancel, refresh };
}

it.each(['QUEUED', 'CANCELLED'] as const)('IP %s snapshot equality is semantic across distinct wire bodies, not nested object identity', status => {
  const previous = { ...fixture('run_queued') as InvestigationRun, status };
  const next = JSON.parse(JSON.stringify(previous)) as InvestigationRun;
  expect(validatedIPSnapshot(next, previous)).toEqual(previous);
  expect(() => validatedIPSnapshot({ ...next, reason: 'changed at equal revision' }, previous)).toThrow();
  expect(() => validatedIPSnapshot({ ...next, progress: { ...next.progress, model_calls: 1 } }, previous)).toThrow();
  if (status === 'CANCELLED') expect(() => validatedIPSnapshot({ ...next, status: 'QUEUED', revision: next.revision + 1 }, previous)).toThrow();
});

for (const kind of ['IP', 'Job'] as const) {
  it.each(['failed', 'timed-out'] as const)(`N3 ${kind} lost ACK (%s) permits explicit observed-terminal reconciliation, not premature or automatic release`, async failure => {
    const f = await mount(kind);
    vi.useFakeTimers();
    f.cancel();
    const first = f.calls.find(c => c.url.endsWith('/cancel'))!;
    await f.refresh(f.cancelled);
    expect(f.region()).toHaveTextContent('CANCELLED');
    expect(screen.getByText('Cancellation acknowledgment pending')).toBeVisible();
    expect(screen.queryByRole('button', { name: /Acknowledge/ })).not.toBeInTheDocument();
    expect(first.init.signal?.aborted).toBe(false);
    if (failure === 'failed') await act(async () => f.reject(new Error('ACK lost after apply')));
    else await act(async () => vi.advanceTimersByTimeAsync(15000));
    const receipt = screen.getByRole('region', { name: 'Cancellation receipt' });
    expect(receipt).toHaveTextContent('cancellation unconfirmed');
    const ack = within(receipt).getByRole('button', { name: acknowledge });
    expect(receipt).toHaveTextContent('Original cancellation acknowledgment remains unknown');
    expect(receipt).toHaveTextContent('client');
    expect(receipt).toHaveTextContent('physical worker release is not established');
    // The slot is still held until the explicit action, even though history is terminal.
    const staleAck = (Object.entries(ack).find(([key]) => key.startsWith('__reactProps$'))![1] as { onClick: () => void }).onClick;
    await f.refresh(f.other);
    expect(screen.getByRole('button', { name: kind === 'IP' ? 'Cancel investigation' : 'Request cancellation of this run' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: acknowledge }));
    expect(screen.getByRole('button', { name: kind === 'IP' ? 'Cancel investigation' : 'Request cancellation of this run' })).toBeEnabled();
    f.cancel();
    expect(f.calls.filter(c => c.url.endsWith('/cancel')).map(c => c.url)).toEqual([
      `/api/v1/analysis-jobs/job/${kind === 'IP' ? 'ai-investigations' : 'ai-job-investigations'}/${f.queued.id}/cancel`,
      `/api/v1/analysis-jobs/job/${kind === 'IP' ? 'ai-investigations' : 'ai-job-investigations'}/${f.other.id}/cancel`,
    ]);
    // An expired original response and a detached acknowledgment cannot release B.
    await act(async () => { staleAck(); f.resolve(Response.json(f.cancelled)); });
    expect(f.region()).toHaveTextContent(f.other.id);
    expect(f.region()).not.toHaveTextContent('CANCELLED');
    await f.refresh({ ...f.queued, id: 'e'.repeat(64) });
    expect(screen.getByRole('button', { name: kind === 'IP' ? 'Cancel investigation' : 'Request cancellation of this run' })).toBeDisabled();
    expect(screen.getByRole('button', { name: new RegExp('Return to active.*' + f.other.id) })).toBeVisible();
    expect(f.calls.filter(c => c.init.method === 'POST')).toHaveLength(2);
    f.view.unmount(); expect(vi.getTimerCount()).toBe(0);
  });

  it(`N3 ${kind} rejects invalid terminal history after ACK loss and retains unknown-ACK qualification after explicit reconciliation`, async () => {
    const f = await mount(kind);
    f.cancel(); await act(async () => f.reject(new Error('ACK lost after apply')));
    for (const invalid of [
      { ...f.cancelled, revision: 1 },
      { ...f.cancelled, revision: 2 },
      { ...f.cancelled, owner_id: 'foreign' },
      { ...f.cancelled, request: { ...f.queued.request, question: 'foreign request' } },
      { ...f.cancelled, execution: { ...f.queued.execution, model_tag: 'foreign' } },
      { ...f.cancelled, revision: 'malformed' },
    ]) {
      await f.refresh(invalid);
      expect(f.region()).not.toHaveTextContent('CANCELLED');
      expect(screen.getByRole('region', { name: 'Cancellation receipt' })).toHaveTextContent('cancellation unconfirmed');
      expect(screen.queryByRole('button', { name: /Acknowledge/ })).not.toBeInTheDocument();
    }
    await f.refresh(f.cancelled);
    const ack = screen.getByRole('button', { name: acknowledge });
    f.view.rerender(<ReportLanguageContext.Provider value="ko">{f.panel()}</ReportLanguageContext.Provider>);
    expect(screen.getByRole('button', { name: '관측된 종료 상태 확인' })).toBeEnabled();
    expect(screen.getByRole('region', { name: '취소 영수증' })).toHaveTextContent('원래 취소 수락 응답은 여전히 미확인입니다');
    f.view.rerender(<ReportLanguageContext.Provider value="en">{f.panel()}</ReportLanguageContext.Provider>);
    fireEvent.click(screen.getByRole('button', { name: acknowledge }));
    expect(ack).not.toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Cancellation receipt' })).toHaveTextContent('Original cancellation acknowledgment remains unknown');
    expect(screen.queryByRole('button', { name: 'Acknowledge retained outcome' })).not.toBeInTheDocument();
    expect(f.calls.filter(c => c.init.method === 'POST')).toHaveLength(1);
  });
}
