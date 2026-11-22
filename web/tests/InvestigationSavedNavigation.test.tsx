import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { render } from './investigationDisplayRender';
import { beforeEach, expect, it, vi } from 'vitest';
import { InvestigationEvidence } from '../src/InvestigationResult';
import AIInvestigationPanel from '../src/AIInvestigationPanel';
import JobInvestigationPanel from '../src/JobInvestigationPanel';
import { investigationApi } from '../src/investigationApi';
import { jobApi } from '../src/jobInvestigationApi';
import { savedNavigation } from './investigationSavedNavigationFixtures';
import { fixture } from './investigationFixtures';
import { producer } from './jobInvestigationFixtures';
import { parseJobWire } from '../src/jobInvestigationContract';
import { ReportLanguageContext } from '../src/reportLanguageContext';
import type { InvestigationRun } from '../src/investigationTypes';

beforeEach(() => { sessionStorage.clear(); });

it('opens saved IP history before a lazy new-request form even without capability', async () => {
  vi.spyOn(investigationApi, 'capabilities').mockRejectedValue(new Error('Unavailable'));
  vi.spyOn(investigationApi, 'history').mockResolvedValue({ items: [fixture('run_completed') as InvestigationRun], next_cursor: null });
  const create = vi.spyOn(investigationApi, 'create');
  const view = render(<AIInvestigationPanel jobId="job"/>);
  const saved = await screen.findByRole('button', { name: /2001:db8::1 · COMPLETED/ });
  expect(view.container.querySelector('form')).toBeNull();
  fireEvent.click(saved);
  expect(await screen.findByText('관측된 통신은 추가 검토가 필요합니다.')).toBeVisible();
  expect(create).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: /New investigation request/ }));
  expect(screen.getByRole('button', { name: /Preview scope/ })).toBeDisabled();
  const history = screen.getByRole('region', { name: /Investigation history/ });
  expect(history.compareDocumentPosition(view.container.querySelector('form')!) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  expect(within(history).getByText((fixture('run_completed') as InvestigationRun).id, { exact: false })).toBeVisible();
});

it('opens saved job history without source or capability before a lazy new-request form', async () => {
  vi.spyOn(jobApi, 'capabilities').mockRejectedValue(new Error('Unavailable'));
  const run = parseJobWire('run', producer.fixtures.run_completed);
  vi.spyOn(jobApi, 'history').mockResolvedValue({ items: [run], next_cursor: null });
  const create = vi.spyOn(jobApi, 'create');
  const view = render(<JobInvestigationPanel jobId="job" sourceAvailable={false}/>);
  const saved = await screen.findByRole('button', { name: /View saved run/ });
  expect(view.container.querySelector('form')).toBeNull();
  fireEvent.click(saved);
  expect(screen.getByRole('region', { name: 'Saved job investigation' })).toHaveTextContent('whole-job conclusion: NOT_ESTABLISHED');
  expect(create).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: /New investigation request/ }));
  expect(screen.getByRole('button', { name: /Start experimental/ })).toBeDisabled();
  const history = screen.getByRole('region', { name: 'Job investigation history' });
  expect(history.compareDocumentPosition(view.container.querySelector('form')!) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: Error) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

it('retains IP admission through history, hidden form and endpoint selection without publishing into that history', async () => {
  const held = deferred<InvestigationRun>();
  vi.spyOn(investigationApi, 'capabilities').mockResolvedValue({ document: fixture('capabilities') as Awaited<ReturnType<typeof investigationApi.capabilities>>['document'], unavailableReason: null });
  vi.spyOn(investigationApi, 'preview').mockResolvedValue(fixture('source_preview') as Awaited<ReturnType<typeof investigationApi.preview>>);
  const old = { ...(fixture('run_partial') as InvestigationRun), id: 'e'.repeat(64) };
  vi.spyOn(investigationApi, 'history').mockResolvedValue({ items: [old], next_cursor: null });
  const create = vi.spyOn(investigationApi, 'create').mockReturnValue(held.promise);
  const view = render(<AIInvestigationPanel jobId="job"/>);
  fireEvent.click(screen.getByRole('button', { name: /New investigation request/ }));
  fireEvent.change(screen.getByLabelText(/Target IP/), { target: { value: '2001:db8::1' } });
  await waitFor(() => expect(screen.getByRole('button', { name: /Preview scope/ })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: /Preview scope/ }));
  fireEvent.click(await screen.findByRole('button', { name: /Start investigation/ }));
  const body = create.mock.calls[0][1];
  fireEvent.click(screen.getByRole('button', { name: /New investigation request/ }));
  fireEvent.click(await screen.findByRole('button', { name: /2001:db8::1 · PARTIAL/ }));
  expect(screen.getByText(/Awaiting admission acknowledgment/)).toBeVisible();
  expect(create.mock.calls[0][2]?.aborted).toBe(false);
  view.rerender(<AIInvestigationPanel jobId="job" visible={false} selection={{ ip: '10.0.0.8', sequence: 2 }}/>);
  expect(screen.getByText(/Awaiting admission acknowledgment/)).toBeVisible();
  await act(async () => { held.resolve({ ...(fixture('run_completed') as InvestigationRun), request: JSON.parse(body) }); });
  view.rerender(<AIInvestigationPanel jobId="job" selection={{ ip: '10.0.0.8', sequence: 2 }}/>);
  expect(screen.getByRole('region', { name: /Selected investigation/ })).toHaveTextContent('PARTIAL');
  fireEvent.click(screen.getByRole('button', { name: /Return to active investigation/ }));
  expect(screen.getByRole('region', { name: /Selected investigation/ })).toHaveTextContent('COMPLETED');
  fireEvent.click(screen.getByRole('button', { name: 'Acknowledge retained outcome' }));
  fireEvent.click(screen.getByRole('button', { name: 'Apply deferred target' }));
  expect(screen.getByLabelText('Target IP')).toHaveValue('10.0.0.8');
  expect(screen.queryByText(/Selection deferred/)).not.toBeInTheDocument();
  expect(create).toHaveBeenCalledTimes(1);
});

it('retains job admission through saved history and hide, then recovers the exact uncertain intent', async () => {
  const held = deferred<ReturnType<typeof parseJobWire<'run'>>>();
  vi.spyOn(jobApi, 'capabilities').mockResolvedValue(parseJobWire('capabilities', producer.fixtures.capabilities));
  const old = parseJobWire('run', producer.fixtures.run_completed);
  vi.spyOn(jobApi, 'history').mockResolvedValue({ items: [old], next_cursor: null });
  const create = vi.spyOn(jobApi, 'create').mockReturnValue(held.promise);
  const view = render(<JobInvestigationPanel jobId="job"/>);
  fireEvent.click(screen.getByRole('button', { name: /New investigation request/ }));
  await waitFor(() => expect(screen.getByRole('button', { name: /Start experimental/ })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: /Start experimental/ }));
  const body = create.mock.calls[0][1];
  fireEvent.click(await screen.findByRole('button', { name: /View saved run/ }));
  expect(screen.getByRole('button', { name: /Retry exact/ })).toBeDisabled();
  expect(create.mock.calls[0][2]?.aborted).toBe(false);
  view.rerender(<JobInvestigationPanel jobId="job" visible={false}/>);
  expect(screen.getByRole('region', { name: 'Unconfirmed admission' })).toBeVisible();
  await act(async () => { held.reject(new Error('Admission response lost')); });
  fireEvent.click(screen.getByRole('button', { name: /Recover admission/ }));
  fireEvent.click(screen.getByRole('button', { name: /Retry exact/ }));
  expect(create).toHaveBeenCalledTimes(2);
  expect(create.mock.calls[1][1]).toBe(body);
  expect(JSON.parse(body).expected_source_sha256).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Close recovery' }));
  expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
  expect(screen.getByRole('region', { name: 'Unconfirmed admission' })).toBeVisible();
});

it('retains IP cancellation receipt while browsing another saved run and returning', async () => {
  const queued = fixture('run_queued') as InvestigationRun;
  const old = { ...(fixture('run_partial') as InvestigationRun), id: 'd'.repeat(64) };
  const held = deferred<InvestigationRun>();
  vi.spyOn(investigationApi, 'capabilities').mockRejectedValue(new Error('Unavailable'));
  vi.spyOn(investigationApi, 'history').mockResolvedValue({ items: [queued, old], next_cursor: null });
  vi.spyOn(investigationApi, 'run').mockImplementation(() => new Promise(() => {}));
  const cancel = vi.spyOn(investigationApi, 'cancel').mockReturnValue(held.promise);
  render(<AIInvestigationPanel jobId="job"/>);
  fireEvent.click(await screen.findByRole('button', { name: /2001:db8::1 · QUEUED/ }));
  fireEvent.click(screen.getByRole('button', { name: /Cancel investigation/ }));
  fireEvent.click(screen.getByRole('button', { name: /Confirm cancel this run/ }));
  fireEvent.click(screen.getByRole('button', { name: /2001:db8::1 · PARTIAL/ }));
  expect(cancel.mock.calls[0][2]?.aborted).toBe(false);
  expect(screen.getByText(/Cancellation acknowledgment pending/)).toBeVisible();
  await act(async () => { held.reject(new Error('cancel receipt lost')); });
  expect(screen.getByText(/cancellation unconfirmed/)).toBeVisible();
  expect(screen.getByRole('region', { name: /Selected investigation/ })).toHaveTextContent('PARTIAL');
  fireEvent.click(screen.getByRole('button', { name: /Return to active investigation/ }));
  expect(screen.getByRole('region', { name: /Selected investigation/ })).toHaveTextContent('QUEUED');
  expect(screen.getByText(/cancellation unconfirmed/)).toBeVisible();
  expect(cancel).toHaveBeenCalledTimes(1);
  expect(cancel.mock.calls[0][1].id).toBe(queued.id);
});

it('retains job cancellation settlement outside selected history without releasing admission intent', async () => {
  const queued = parseJobWire('run', producer.fixtures.run_queued);
  const old = { ...parseJobWire('run', producer.fixtures.run_completed), id: 'f'.repeat(64) };
  const held = deferred<typeof queued>();
  vi.spyOn(jobApi, 'capabilities').mockResolvedValue(parseJobWire('capabilities', producer.fixtures.capabilities));
  vi.spyOn(jobApi, 'history').mockResolvedValue({ items: [queued, old], next_cursor: null });
  const cancel = vi.spyOn(jobApi, 'cancel').mockReturnValue(held.promise);
  render(<JobInvestigationPanel jobId="job"/>);
  fireEvent.click(await screen.findByRole('button', { name: /View saved run QUEUED/ }));
  fireEvent.click(screen.getByRole('button', { name: /Request cancellation/ }));
  fireEvent.click(screen.getByRole('button', { name: /View saved run COMPLETED/ }));
  expect(cancel.mock.calls[0][2]?.aborted).toBe(false);
  expect(screen.getByText(/Cancellation acknowledgment pending/)).toBeVisible();
  await act(async () => { held.resolve({ ...queued, status: 'CANCELLED', revision: queued.revision + 1 }); });
  expect(screen.getByRole('region', { name: 'Saved job investigation' })).toHaveTextContent('COMPLETED');
  fireEvent.click(screen.getByRole('button', { name: /Return to active investigation/ }));
  expect(screen.getByRole('region', { name: 'Saved job investigation' })).toHaveTextContent('CANCELLED');
  expect(cancel).toHaveBeenCalledTimes(1);
});

it('bounds job overview to three model claims and keeps every claim reachable through peer detail', async () => {
  const max = savedNavigation.job;
  vi.spyOn(jobApi, 'capabilities').mockRejectedValue(new Error('Unavailable'));
  vi.spyOn(jobApi, 'history').mockResolvedValue({ items: [max], next_cursor: null });
  render(<JobInvestigationPanel jobId="job"/>);
  fireEvent.click(await screen.findByRole('button', { name: /View saved run/ }));
  const summary = screen.getByRole('region', { name: 'Saved job investigation' });
  const result = max.result;
  if (!result || result.kind !== 'RESULT') throw new Error('Producer result absent');
  const claims = result.assessments.flatMap(a => [...a.support, ...a.counterevidence]);
  expect(claims.length).toBeGreaterThan(3);
  expect(summary.querySelectorAll('[data-investigation-claim]')).toHaveLength(3);
  expect(summary.querySelector('pre')).toBeNull();
  expect(document.querySelectorAll('*').length).toBeLessThanOrEqual(1200);
  fireEvent.click(screen.getByRole('button', { name: 'Peer details ' + result.assessments[0].peer_id }));
  const detail = screen.getByRole('region', { name: 'Peer assessment detail' });
  for (const claim of result.assessments[0].support) expect(detail).toHaveTextContent(claim.text);
});

it('IP saved summary mounts at most three claims and lazily opens execution commitments', async () => {
  const saved = fixture('run_completed') as InvestigationRun;
  vi.spyOn(investigationApi, 'capabilities').mockRejectedValue(new Error('Unavailable'));
  vi.spyOn(investigationApi, 'history').mockResolvedValue({ items: [saved], next_cursor: null });
  render(<AIInvestigationPanel jobId="job"/>);
  fireEvent.click(await screen.findByRole('button', { name: /2001:db8::1 · COMPLETED/ }));
  expect(screen.queryByRole('region', { name: /Captured model/ })).not.toBeInTheDocument();
  expect(document.querySelectorAll('[data-investigation-claim]').length).toBeLessThanOrEqual(3);
  expect(screen.queryByRole('region', { name: /Observed facts/ })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: /Observed facts/ }));
  expect(screen.getByRole('region', { name: /Observed facts/ })).toHaveTextContent('matched_rows');
  fireEvent.click(screen.getByRole('button', { name: /Execution and source details/ }));
  expect(screen.getByRole('region', { name: /Captured model/ })).toHaveTextContent(saved.execution.model);
});

it('display locale changes IP labels without changing the captured request or source prose', async () => {
  const held = deferred<InvestigationRun>();
  vi.spyOn(investigationApi, 'capabilities').mockResolvedValue({ document: fixture('capabilities') as Awaited<ReturnType<typeof investigationApi.capabilities>>['document'], unavailableReason: null });
  vi.spyOn(investigationApi, 'preview').mockResolvedValue(fixture('source_preview') as Awaited<ReturnType<typeof investigationApi.preview>>);
  vi.spyOn(investigationApi, 'history').mockResolvedValue({ items: [], next_cursor: null });
  const create = vi.spyOn(investigationApi, 'create').mockReturnValue(held.promise);
  const view = render(<ReportLanguageContext.Provider value="en"><AIInvestigationPanel jobId="job"/></ReportLanguageContext.Provider>);
  fireEvent.click(screen.getByRole('button', { name: 'New investigation request' }));
  fireEvent.change(screen.getByLabelText('Target IP'), { target: { value: '2001:db8::1' } });
  await waitFor(() => expect(screen.getByRole('button', { name: 'Preview scope' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: 'Preview scope' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Start investigation' }));
  const body = create.mock.calls[0][1];
  expect(JSON.parse(body).language).toBe('en');
  view.rerender(<ReportLanguageContext.Provider value="ko"><AIInvestigationPanel jobId="job"/></ReportLanguageContext.Provider>);
  expect(screen.getByRole('button', { name: '새 조사 요청' })).toBeVisible();
  expect(screen.getByLabelText('대상 IP')).toBeDisabled();
  await act(async () => { held.reject(new Error('Unconfirmed')); });
  fireEvent.click(screen.getByRole('button', { name: '동일 요청 재시도' }));
  expect(create.mock.calls[1][1]).toBe(body);
});

it('IP metric citations open the exact evidence page, Escape restores the invoker, and arrows do not read', async () => {
  const saved = savedNavigation.ip;
  if (!saved.result || 'kind' in saved.result) throw new Error('Producer result absent');
  const evidence = savedNavigation.ipEvidence[saved.result.facts.at(-1)!.ref.split(':')[0]];
  vi.spyOn(investigationApi, 'capabilities').mockRejectedValue(new Error('Unavailable'));
  vi.spyOn(investigationApi, 'history').mockResolvedValue({ items: [saved], next_cursor: null });
  const read = vi.spyOn(investigationApi, 'evidence').mockResolvedValue(evidence);
  render(<AIInvestigationPanel jobId="job"/>);
  fireEvent.click(await screen.findByRole('button', { name: /2001:db8::1 · COMPLETED/ }));
  const factsButton = screen.getByRole('button', { name: 'Observed facts' });
  factsButton.focus(); fireEvent.keyDown(factsButton, { key: 'ArrowRight' });
  expect(read).not.toHaveBeenCalled();
  fireEvent.click(factsButton);
  const facts = screen.getByRole('region', { name: 'Observed facts' });
  const metric = saved.result && !('kind' in saved.result) ? saved.result.facts.at(-1)! : undefined;
  if (!metric) throw new Error('Producer facts absent');
  while (!within(facts).queryByRole('button', { name: metric.ref })) fireEvent.click(within(facts).getByRole('button', { name: /Next facts/ }));
  const invoker = within(facts).getByRole('button', { name: metric.ref });
  invoker.focus(); fireEvent.click(invoker);
  const detail = await screen.findByRole('region', { name: 'Selected evidence' });
  await waitFor(() => expect(within(detail).getByText(metric.ref, { exact: true })).toBeVisible());
  expect(read).toHaveBeenCalledTimes(1);
  expect(read.mock.calls[0][1].id).toBe(saved.id);
  expect(read.mock.calls[0][2]).toBe(metric.ref.split(':')[0]);
  expect(detail).toContainElement(document.activeElement as HTMLElement);
  fireEvent.keyDown(detail, { key: 'Escape' });
  expect(screen.queryByRole('region', { name: 'Selected evidence' })).not.toBeInTheDocument();
  expect(invoker).toHaveFocus();
});

it('job evidence detail supports Escape and focus restoration on its actual shared-evidence consumer', async () => {
  const saved = parseJobWire('run', producer.fixtures.run_completed);
  const evidence = parseJobWire('evidence', producer.fixtures.evidence_protocol);
  vi.spyOn(jobApi, 'capabilities').mockRejectedValue(new Error('Unavailable'));
  vi.spyOn(jobApi, 'history').mockResolvedValue({ items: [saved], next_cursor: null });
  const read = vi.spyOn(jobApi, 'evidence').mockResolvedValue(evidence);
  render(<JobInvestigationPanel jobId="job"/>);
  fireEvent.click(await screen.findByRole('button', { name: /View saved run/ }));
  fireEvent.click(screen.getByRole('button', { name: 'Peer details ' + saved.selection.peer_ids[0] }));
  const invoker = screen.getByRole('button', { name: 'Evidence ' + evidence.evidence_id });
  invoker.focus(); fireEvent.click(invoker);
  const detail = await screen.findByRole('region', { name: 'Selected evidence' });
  await within(detail).findByRole('region', { name: 'Evidence details' });
  expect(detail).toContainElement(document.activeElement as HTMLElement);
  fireEvent.keyDown(detail, { key: 'Escape' });
  expect(screen.queryByRole('region', { name: 'Evidence details' })).not.toBeInTheDocument();
  expect(invoker).toHaveFocus();
  expect(read.mock.calls[0][1].id).toBe(saved.id);
});

it('Korean job labels and accessible citations share display locale while request language stays independent', async () => {
  const saved = parseJobWire('run', producer.fixtures.run_completed);
  vi.spyOn(jobApi, 'capabilities').mockResolvedValue(parseJobWire('capabilities', producer.fixtures.capabilities));
  vi.spyOn(jobApi, 'history').mockResolvedValue({ items: [saved], next_cursor: null });
  const read = vi.spyOn(jobApi, 'evidence').mockResolvedValue(parseJobWire('evidence', producer.fixtures.evidence_protocol));
  const create = vi.spyOn(jobApi, 'create');
  const view = render(<ReportLanguageContext.Provider value="ko"><JobInvestigationPanel jobId="job"/></ReportLanguageContext.Provider>);
  fireEvent.click(await screen.findByRole('button', { name: /저장된 조사 보기/ }));
  expect(screen.getByRole('region', { name: '저장된 작업 조사' })).toHaveTextContent('NOT_ESTABLISHED');
  fireEvent.click(screen.getByRole('button', { name: '피어 상세 ' + saved.selection.peer_ids[0] }));
  fireEvent.click(screen.getByRole('button', { name: '근거 ' + parseJobWire('evidence', producer.fixtures.evidence_protocol).evidence_id }));
  await screen.findByRole('region', { name: '근거 상세' });
  fireEvent.click(screen.getByRole('button', { name: '근거 닫기' }));
  fireEvent.click(screen.getByRole('button', { name: '새 조사 요청' }));
  expect(screen.getByLabelText('새 요청 보고서 언어')).toHaveValue('ko');
  view.rerender(<ReportLanguageContext.Provider value="en"><JobInvestigationPanel jobId="job"/></ReportLanguageContext.Provider>);
  expect(screen.getByLabelText('New request report language')).toHaveValue('ko');
  expect(screen.getByRole('region', { name: 'Saved job investigation' })).toHaveTextContent('관측 자료 확인');
  expect(read).toHaveBeenCalledTimes(1);
  expect(create).not.toHaveBeenCalled();
});

it('Korean shared evidence paginates using localized accessible labels without changing facts', () => {
  const evidence = Object.values(savedNavigation.ipEvidence).find(value => value.metrics.length > 4)!;
  render(<ReportLanguageContext.Provider value="ko"><InvestigationEvidence evidence={evidence}/></ReportLanguageContext.Provider>);
  fireEvent.click(screen.getByRole('button', { name: '다음 관측 사실' }));
  expect(screen.getByText(evidence.metrics[4].ref, { exact: true })).toBeVisible();
  expect(screen.getByLabelText('관측 사실 페이지')).toBeVisible();
});
