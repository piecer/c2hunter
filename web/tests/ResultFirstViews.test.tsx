import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, useNavigate } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import App from '../src/App';
import { api } from '../src/api';
import { jobApi } from '../src/jobInvestigationApi';
import { parseJobWire } from '../src/jobInvestigationContract';
import { producer } from './jobInvestigationFixtures';
import { investigationApi } from '../src/investigationApi';
import { fixture } from './investigationFixtures';
import type { InvestigationRun, SourcePreview } from '../src/investigationTypes';

const job = { id: 'result-job', name: 'Retained C2 result', status: 'COMPLETED', dataset_id: 'dataset', analysis: { module: 'c2' }, candidate_count: 51, warnings: ['Retained evidence is incomplete'], packet_count: 100, flow_count: 70 };
const candidates = Array.from({ length: 51 }, (_, index) => ({ id: `candidate-${index + 1}`, candidate_ip: `203.0.113.${index + 1}`, score: 60, severity: 'MEDIUM' }));
function RouteControls() { const navigate = useNavigate(); return <><button onClick={() => navigate('/analyses/other-job')}>Go B</button><button onClick={() => navigate('/analyses/result-job')}>Go A</button></>; }
function mount(overrides: Record<string, unknown> = {}, total: number | undefined = 51) {
  localStorage.setItem('c2hunter-token', 'test');
  const get = vi.spyOn(api, 'get').mockImplementation(async path => {
    if (path === '/analysis-jobs/other-job') return { ...job, id: 'other-job', name: 'Cached B' };
    if (path === '/analysis-jobs/result-job') { if (overrides.sourceMissing) throw new Error('404 source unavailable'); return { ...job, ...overrides }; }
    if (path.includes('/candidates?')) {
      const query = new URLSearchParams(path.split('?')[1]);
      const page = Number(query.get('page') ?? 1), size = Number(query.get('page_size') ?? 200);
      return { items: candidates.slice(0, total).slice((page - 1) * size, page * size), page, page_size: size, total, workflow_counts: { needs_review: 40, in_review: 8, action_required: 3, done: 0 } };
    }
    if (path === '/ai-capabilities') return { available: false };
    return { items: [] };
  });
  const bounded = vi.spyOn(api, 'boundedRequest').mockRejectedValue(new Error('Optional service unavailable'));
  const post = vi.spyOn(api, 'post');
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/analyses/result-job']}><App/><RouteControls/></MemoryRouter></QueryClientProvider>);
  return { get, bounded, post, client, ...view };
}

it('opens C2 results before optional work, with no optional DOM or queries', async () => {
  const { get, bounded, post, container } = mount();
  const table = await screen.findByRole('table', { name: 'Analysis candidates' });
  expect(screen.getByText('Retained evidence is incomplete')).toBeVisible();
  for (const name of ['Source and parsing', 'State transitions', 'AI C2 분석', '가중치 조정 후 재분석']) expect(screen.queryByRole('heading', { name })).not.toBeInTheDocument();
  expect(container.querySelector('#ip-investigation')).toBeNull();
  expect(get.mock.calls.map(([path]) => path).filter(path => /ai-|flows|pcaps|investigation/.test(path))).toEqual([]);
  expect(bounded).not.toHaveBeenCalled(); expect(post).not.toHaveBeenCalled();
  const navigation = screen.getByRole('navigation', { name: '분석 목적' });
  expect(navigation.compareDocumentPosition(table) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  fireEvent.click(within(navigation).getByRole('button', { name: '작업 정보' }));
  expect(await screen.findByRole('heading', { name: 'Source and parsing' })).toBeVisible();
  expect(screen.queryByRole('table', { name: 'Analysis candidates' })).not.toBeInTheDocument();
  expect(screen.getByText('Retained evidence is incomplete')).toBeVisible();
  expect(post).not.toHaveBeenCalled();
});
it('keeps completed lifecycle and full identifiers in work, not above the result', async () => {
  mount({ source_type: 'PCAP_UPLOAD', processing: { phase: 'COMPLETED' }, description: 'Full analyst note' });
  await screen.findByRole('table', { name: 'Analysis candidates' });
  expect(screen.queryByRole('region', { name: 'PCAP 분석 처리 단계' })).not.toBeInTheDocument();
  expect(screen.queryByText('Job result-job · Dataset dataset')).not.toBeInTheDocument();
  expect(screen.queryByText('Full analyst note')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: '작업 정보' }));
  expect(screen.getByRole('region', { name: 'PCAP 분석 처리 단계' })).toBeVisible();
  expect(screen.getByText('Job result-job · Dataset dataset')).toBeVisible();
  expect(screen.getByText('Full analyst note')).toBeVisible();
});
it('reads all 51 scoped candidates in 25-row server pages without inventing page aggregates', async () => {
  const { get, container } = mount();
  const table = await screen.findByRole('table', { name: 'Analysis candidates' });
  expect(within(table).getAllByRole('row')).toHaveLength(26);
  expect(screen.getByText('탐지 후보 51건 · 검토 필요')).toBeVisible();
  expect(screen.getByText(/최소 점수 0 · 제외 후보 미포함/)).toBeVisible();
  expect(within(screen.getByRole('region', { name: 'Candidate 처리 현황' })).getByText('40')).toBeVisible();
  expect(screen.getByText('후보 1–25 / 전체 51')).toBeVisible();
  expect(document.querySelectorAll('*').length).toBeLessThan(1200);
  fireEvent.click(screen.getByRole('button', { name: '다음 후보' }));
  expect(await screen.findByRole('link', { name: '203.0.113.50' })).toBeVisible();
  expect(screen.queryByRole('link', { name: '203.0.113.1' })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: '다음 후보' }));
  expect(await screen.findByRole('link', { name: '203.0.113.51' })).toBeVisible();
  expect(screen.getByRole('button', { name: '다음 후보' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: '이전 후보' }));
  expect(await screen.findByRole('link', { name: '203.0.113.26' })).toBeVisible();
  expect(get.mock.calls.filter(([path]) => path.includes('/candidates?')).map(([path]) => new URLSearchParams(path.split('?')[1]).get('page_size'))).toEqual(['25', '25', '25', '25']);
  expect(container.querySelectorAll('tbody tr')).toHaveLength(25);
});
it.each([
  ['COMPLETED', '보존된 탐지 후보 0건 · 안전 판정 아님'],
  ['FAILED', '분석 실패 · 최종 결론 없음'],
  ['CANCELLED', '분석 취소 · 최종 결론 없음'],
  ['PARTIALLY_COMPLETED', '부분 완료 · 관측 범위 제한'],
  ['ANALYZING', '분석 진행 중 · 최종 결론 대기'],
])('keeps %s distinct from a benign verdict when no candidates are retained', async (status, heading) => {
  mount({ status, candidate_count: 0, transitions: [{ to_status: status, occurred_at: '2026-01-01T00:00:00Z', reason: 'source coverage unavailable' }] }, 0);
  expect(await screen.findByRole('heading', { name: heading })).toBeVisible();
  expect(screen.getByText('Retained evidence is incomplete')).toBeVisible();
  if (status === 'FAILED' || status === 'CANCELLED') expect(screen.getByText('source coverage unavailable')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'AI 조사' }));
  expect(screen.getByRole('heading', { name: heading })).toBeVisible();
});


it('keeps a pending IP admission through purpose switches and retries its exact captured body', async () => {
  mount();
  vi.spyOn(investigationApi, 'capabilities').mockResolvedValue({ document: { availability: 'CONFIGURED_NOT_PROBED', remote_server_allowed: false }, unavailableReason: null } as Awaited<ReturnType<typeof investigationApi.capabilities>>);
  vi.spyOn(investigationApi, 'history').mockResolvedValue({ items: [], next_cursor: null });
  vi.spyOn(investigationApi, 'preview').mockResolvedValue(fixture('source_preview') as SourcePreview);
  let reject!: (error: Error) => void;
  const create = vi.spyOn(investigationApi, 'create').mockImplementation(() => new Promise((_, fail) => { reject = fail; }));
  fireEvent.click(await screen.findByRole('button', { name: 'AI 조사' }));
  fireEvent.click(screen.getByRole('button', { name: /Open IP investigation/ }));
  fireEvent.change(screen.getByLabelText('대상 IP / Target IP'), { target: { value: '2001:db8::1' } });
  await waitFor(() => expect(screen.getByRole('button', { name: /Preview scope/ })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: /Preview scope/ }));
  fireEvent.click(await screen.findByRole('button', { name: /Start investigation/ }));
  expect(create).toHaveBeenCalledTimes(1);
  const body = create.mock.calls[0][1];
  fireEvent.click(screen.getByRole('button', { name: '결과·근거' }));
  expect(screen.queryByLabelText('대상 IP / Target IP')).not.toBeInTheDocument();
  expect(screen.getByText(/Awaiting admission acknowledgment/)).toBeVisible();
  await act(async () => reject(new Error('Unconfirmed admission')));
  expect(screen.getByText(/Admission is unconfirmed/)).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: '작업 정보' }));
  fireEvent.click(screen.getByRole('button', { name: 'AI 조사' }));
  expect(screen.getByLabelText('대상 IP / Target IP')).toHaveValue('2001:db8::1');
  expect(create).toHaveBeenCalledTimes(1);
  fireEvent.click(screen.getByRole('button', { name: /Retry captured request/ }));
  expect(create).toHaveBeenCalledTimes(2);
  expect(create.mock.calls[1][1]).toBe(body);
});


it('retains experimental job intent and its warning outside the AI purpose region', async () => {
  sessionStorage.clear();
  mount();
  vi.spyOn(jobApi, 'capabilities').mockResolvedValue(parseJobWire('capabilities', producer.fixtures.capabilities));
  vi.spyOn(jobApi, 'history').mockResolvedValue({ items: [], next_cursor: null });
  let reject!: (error: Error) => void;
  const create = vi.spyOn(jobApi, 'create').mockImplementation(() => new Promise((_, fail) => { reject = fail; }));
  fireEvent.click(await screen.findByRole('button', { name: 'AI 조사' }));
  fireEvent.click(screen.getByRole('button', { name: /Open experimental/ }));
  await waitFor(() => expect(screen.getByRole('button', { name: /Start experimental/ })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: /Start experimental/ }));
  const body = create.mock.calls[0][1];
  fireEvent.click(screen.getByRole('button', { name: '작업 정보' }));
  expect(screen.queryByRole('textbox', { name: /Question/ })).not.toBeInTheDocument();
  expect(screen.getByRole('region', { name: 'Unconfirmed admission' })).toBeVisible();
  await act(async () => reject(new Error('Admission unknown')));
  expect(screen.getByText('Admission unknown')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'AI 조사' }));
  fireEvent.click(screen.getByRole('button', { name: /Retry exact/ }));
  expect(create).toHaveBeenCalledTimes(2);
  expect(create.mock.calls[1][1]).toBe(body);
});


it.each(['ip', 'job'])('keeps the %s run controller polling with only a compact status after leaving AI', async kind => {
  mount();
  const ipRun = { ...(fixture('run_queued') as InvestigationRun), job_id: 'result-job' };
  const jobRun = { ...parseJobWire('run', producer.fixtures.run_queued), job_id: 'result-job' };
  vi.spyOn(investigationApi, 'capabilities').mockRejectedValue(new Error('Unavailable'));
  vi.spyOn(investigationApi, 'history').mockResolvedValue({ items: [ipRun], next_cursor: null });
  const ipRead = vi.spyOn(investigationApi, 'run').mockResolvedValue(ipRun);
  vi.spyOn(jobApi, 'capabilities').mockResolvedValue(parseJobWire('capabilities', producer.fixtures.capabilities));
  vi.spyOn(jobApi, 'history').mockResolvedValue({ items: [jobRun], next_cursor: null });
  const jobRead = vi.spyOn(jobApi, 'run').mockResolvedValue(jobRun);
  fireEvent.click(await screen.findByRole('button', { name: 'AI 조사' }));
  fireEvent.click(screen.getByRole('button', { name: kind === 'ip' ? /Open IP investigation/ : /Open experimental/ }));
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
  try {
    await act(async () => {});
    fireEvent.click(screen.getByRole('button', { name: kind === 'ip' ? /2001:db8::1 · QUEUED/ : /View saved run/ }));
    await act(async () => {});
    fireEvent.click(screen.getByRole('button', { name: '결과·근거' }));
    expect(screen.queryByRole('textbox', { name: /Question/ })).not.toBeInTheDocument();
    expect(screen.getByText(/QUEUED/)).toBeVisible();
    const reads = kind === 'ip' ? ipRead : jobRead;
    const before = reads.mock.calls.length;
    await act(async () => { await vi.advanceTimersByTimeAsync(2100); });
    expect(reads.mock.calls.length).toBeGreaterThan(before);
  } finally { vi.useRealTimers(); }
});


it('resets purpose, page and optional reads across cached job A to B to A', async () => {
  const { client, get } = mount();
  client.setQueryData(['job', 'other-job'], { ...job, id: 'other-job', name: 'Cached B' });
  await screen.findByRole('table', { name: 'Analysis candidates' });
  fireEvent.click(screen.getByRole('button', { name: '다음 후보' }));
  await screen.findByRole('link', { name: '203.0.113.26' });
  fireEvent.click(screen.getByRole('button', { name: 'AI 조사' }));
  await screen.findByRole('heading', { name: 'AI C2 분석' });
  get.mockClear();
  fireEvent.click(screen.getByRole('button', { name: 'Go B' }));
  expect(await screen.findByRole('link', { name: '203.0.113.1' })).toBeVisible();
  expect(screen.getByRole('button', { name: '결과·근거' })).toHaveAttribute('aria-pressed', 'true');
  expect(get.mock.calls.some(([path]) => path.includes('/other-job/') && /ai-|page=2/.test(path))).toBe(false);
  fireEvent.click(screen.getByRole('button', { name: 'Go A' }));
  expect(await screen.findByRole('link', { name: '203.0.113.1' })).toBeVisible();
  expect(screen.queryByRole('heading', { name: 'AI C2 분석' })).not.toBeInTheDocument();
});


it('keeps job history available when the source is missing initially', async () => {
  mount({ sourceMissing: true });
  const history = vi.spyOn(jobApi, 'history').mockResolvedValue({ items: [], next_cursor: null });
  vi.spyOn(jobApi, 'capabilities').mockResolvedValue(parseJobWire('capabilities', producer.fixtures.capabilities));
  fireEvent.click(await screen.findByRole('button', { name: /Open experimental/ }));
  expect(await screen.findByRole('region', { name: 'Job investigation history' })).toBeVisible();
  expect(screen.getByRole('button', { name: /Start experimental/ })).toBeDisabled();
  expect(history).toHaveBeenCalled();
});

it('does not retire active job intent on a source read error and still allows exact recovery', async () => {
  sessionStorage.clear();
  const { client, get } = mount();
  vi.spyOn(jobApi, 'capabilities').mockResolvedValue(parseJobWire('capabilities', producer.fixtures.capabilities));
  vi.spyOn(jobApi, 'history').mockResolvedValue({ items: [], next_cursor: null });
  let reject!: (error: Error) => void;
  const create = vi.spyOn(jobApi, 'create').mockImplementation(() => new Promise((_, fail) => { reject = fail; }));
  fireEvent.click(await screen.findByRole('button', { name: 'AI 조사' }));
  fireEvent.click(screen.getByRole('button', { name: /Open experimental/ }));
  await waitFor(() => expect(screen.getByRole('button', { name: /Start experimental/ })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: /Start experimental/ }));
  const body = create.mock.calls[0][1];
  get.mockRejectedValue(new Error('404 source unavailable'));
  await act(async () => { await client.invalidateQueries({ queryKey: ['job', 'result-job'] }); });
  expect(screen.getByRole('region', { name: 'Job investigation history' })).toBeVisible();
  await act(async () => reject(new Error('Admission still unknown')));
  expect(screen.getByText('Admission still unknown')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: /Retry exact/ }));
  expect(create.mock.calls[1][1]).toBe(body);
});


it('keeps an export owner across work switches, but cancels once on route disposal', async () => {
  const { post } = mount();
  let resolve!: (value: unknown) => void;
  post.mockImplementation(() => new Promise(done => { resolve = done; }));
  fireEvent.click(await screen.findByRole('button', { name: '작업 정보' }));
  fireEvent.click(screen.getByRole('button', { name: 'Download filtered capture' }));
  fireEvent.click(screen.getByRole('button', { name: '결과·근거' }));
  expect(screen.queryByRole('heading', { name: 'All analysis flows' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Add filter' })).not.toBeInTheDocument();
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
  try {
    await act(async () => resolve({ id: 'export-one', status: 'QUEUED' }));
    expect(post.mock.calls.map(([path]) => path)).toEqual(['/pcap-exports']);
    expect(screen.getByText('Filtered capture queued.')).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: '작업 정보' }));
    expect(screen.getByRole('button', { name: /Preparing capture/ })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Go B' }));
    post.mockResolvedValue({});
    await act(async () => { await vi.advanceTimersByTimeAsync(1100); });
    expect(post.mock.calls.filter(([path]) => path === '/pcap-exports/export-one/cancel')).toHaveLength(1);
  } finally { vi.useRealTimers(); }
});

it('retains controlled reanalysis weights and pending errors across work switches', async () => {
  const { post } = mount();
  let reject!: (error: Error) => void;
  post.mockImplementation(() => new Promise((_, fail) => { reject = fail; }));
  fireEvent.click(await screen.findByRole('button', { name: '작업 정보' }));
  const weights = screen.getAllByRole('spinbutton');
  fireEvent.change(weights[0], { target: { value: '1.7' } });
  fireEvent.click(screen.getByRole('button', { name: '결과·근거' }));
  fireEvent.click(screen.getByRole('button', { name: '작업 정보' }));
  expect(screen.getAllByRole('spinbutton')[0]).toHaveValue(1.7);
  fireEvent.click(screen.getByRole('button', { name: '탐지 가중치로 재분석' }));
  fireEvent.click(screen.getByRole('button', { name: '결과·근거' }));
  expect(screen.getByText('재분석 생성 중…')).toBeVisible();
  expect(screen.queryByRole('spinbutton')).not.toBeInTheDocument();
  await waitFor(() => expect(post).toHaveBeenCalledTimes(1));
  await act(async () => reject(new Error('Reanalysis rejected')));
  expect(await screen.findByText('Reanalysis rejected')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: '작업 정보' }));
  expect(screen.getAllByRole('spinbutton')[0]).toHaveValue(1.7);
  expect(await screen.findByText('Reanalysis rejected')).toBeVisible();
  expect(post).toHaveBeenCalledTimes(1);
});


it('retains the flow mutation owner while unmounting its review form', async () => {
  const { get, post } = mount();
  const original = get.getMockImplementation()!;
  get.mockImplementation(async path => path.includes('/flows?') ? { items: [{ flow_id: 'flow-one', job_id: job.id, timestamp: '', source_ip: '10.0.0.1', destination_ip: '203.0.113.1', protocol: 'TCP', direction: 'OUTBOUND', has_payload: false }] } : original(path));
  let reject!: (error: Error) => void;
  post.mockImplementation(() => new Promise((_, fail) => { reject = fail; }));
  fireEvent.click(await screen.findByRole('button', { name: '작업 정보' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Mark benign flow-one' }));
  fireEvent.change(screen.getByLabelText('Analyst note'), { target: { value: 'Preserved draft' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save BENIGN label' }));
  await waitFor(() => expect(post).toHaveBeenCalledTimes(1));
  fireEvent.click(screen.getByRole('button', { name: '결과·근거' }));
  expect(screen.queryByLabelText('Analyst note')).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Mark benign flow-one' })).not.toBeInTheDocument();
  expect(screen.getByText(/flow-one.*Saving/)).toBeVisible();
  await act(async () => reject(new Error('Label write failed')));
  expect(await screen.findByText('Label write failed')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: '작업 정보' }));
  expect(screen.getByLabelText('Analyst note')).toHaveValue('Preserved draft');
  expect(screen.getByText('Label write failed')).toBeVisible();
  expect(post).toHaveBeenCalledTimes(1);
});


it('preserves on-demand known-candidate links outside the visible result page without inventing membership', async () => {
  const { get } = mount();
  const original = get.getMockImplementation()!;
  const run = { id: 'shadow-run', status: 'COMPLETED', discovery_mode: 'shadow', candidate_count: 2 };
  const assessment = (id: string, ip: string) => ({ id, candidate_id: id, external_ip: ip, discovery_origin: 'BEHAVIOR', assessment: { candidate: { verdict: 'INCONCLUSIVE', confidence: 0, summary_ko: '가설', summary_en: 'Hypothesis' }, supporting_factors: [], counter_factors: [], missing_information: [], limitations: [] } });
  get.mockImplementation(async path => path.endsWith('/ai-runs') ? { items: [run] } : path === '/ai-runs/shadow-run' ? run : path.endsWith('/assessments') ? { items: [assessment('candidate-51', '203.0.113.51'), assessment('unknown-id', '198.51.100.1')] } : original(path));
  await screen.findByRole('table', { name: 'Analysis candidates' });
  expect(get.mock.calls.some(([path]) => path.includes('page_size=200'))).toBe(false);
  fireEvent.click(screen.getByRole('button', { name: 'AI 조사' }));
  expect(await screen.findByRole('link', { name: '203.0.113.51' })).toHaveAttribute('href', '/candidates/candidate-51');
  expect(screen.queryByRole('link', { name: '198.51.100.1' })).not.toBeInTheDocument();
  expect(get.mock.calls.filter(([path]) => path === '/analysis-jobs/result-job/candidates?page_size=200')).toHaveLength(1);
});


it('uses one report language for the C2 first view and keeps unknown metrics distinct from zero', async () => {
  localStorage.setItem('c2hunter-report-language', 'en');
  const { get, post, bounded } = mount({ packet_count: undefined, flow_count: undefined, sensor_ids: undefined, candidate_count: 999 });
  const summary = await screen.findByRole('region', { name: 'C2 result summary' });
  expect(within(summary).getByRole('heading', { name: '51 detected candidates · Review required' })).toBeVisible();
  const facts = within(summary).getByRole('list', { name: 'Key facts' });
  expect(within(facts).getAllByRole('listitem')).toHaveLength(4);
  expect(within(facts).getAllByText('Unknown')).toHaveLength(3);
  expect(within(facts).queryByText('999')).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Results & evidence' })).toHaveAttribute('aria-pressed', 'true');
  const calls = get.mock.calls.length;
  fireEvent.change(screen.getByLabelText('보고서 언어 / Report language'), { target: { value: 'ko' } });
  expect(screen.getByRole('heading', { name: '탐지 후보 51건 · 검토 필요' })).toBeVisible();
  expect(screen.getByRole('button', { name: '결과·근거' })).toBeVisible();
  expect(get).toHaveBeenCalledTimes(calls);
  expect(post).not.toHaveBeenCalled(); expect(bounded).not.toHaveBeenCalled();
});

it('makes the next-check action return to results and focus its candidate heading', async () => {
  mount();
  await screen.findByRole('table', { name: 'Analysis candidates' });
  fireEvent.click(screen.getByRole('button', { name: '작업 정보' }));
  fireEvent.click(screen.getByRole('button', { name: '후보 검토로 이동' }));
  expect(screen.getByRole('heading', { name: '탐지 후보' })).toHaveFocus();
  expect(screen.getByRole('table', { name: 'Analysis candidates' })).toBeVisible();
});
