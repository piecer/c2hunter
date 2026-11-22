import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Link, MemoryRouter } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import App from '../src/App';

const candidate = {
  id: 'selection-a', job_id: 'job-a', candidate_ip: '203.0.113.9', score: 80, severity: 'HIGH',
  workflow_status: 'NEEDS_REVIEW', hosts: ['10.0.0.5'], sensors: ['sensor-a'],
  traffic_buckets: [{ start: '2026-11-15T00:00:00Z', flows: 5, packets: 20, bytes: 2048 }],
  evidence: Array.from({ length: 5 }, (_, i) => ({ type: 'PERIODIC_BEACON', description: `Reason ${i + 1}`, raw_score: i,
    warnings: i === 4 ? ['Retained evidence coverage is incomplete'] : [],
    metrics: { sample_count: 7, period_seconds: 30, observations: Array.from({ length: 100 }, (_, j) => `observation-${j}`) },
  })),
};
function renderCandidate(handler?: (path: string, init?: RequestInit) => Promise<Response>) {
  localStorage.setItem('c2hunter-token', 'token');
  const requests: { path: string; method: string }[] = [];
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    requests.push({ path, method: init?.method ?? 'GET' });
    if (handler) return handler(path, init);
    return Response.json(path === '/api/v1/candidates/selection-a' ? candidate : { items: [] });
  }));
  const view = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/candidates/selection-a']}><App /><Link to="/candidates/selection-a">Test candidate A</Link><Link to="/candidates/selection-b">Test candidate B</Link></MemoryRouter></QueryClientProvider>);
  return { requests, client, ...view };
}

it('preserves literal reserved-character route IDs in encoded candidate and transitive API paths', async () => {
  const user = userEvent.setup();
  const candidateId = 'candidate/part?query#fragment%';
  const jobId = 'job/part?query#fragment%';
  const flowId = 'flow/part?query#fragment%';
  const runId = 'run/part?query#fragment%';
  const candidatePath = `/api/v1/candidates/${encodeURIComponent(candidateId)}`;
  const jobPath = `/api/v1/analysis-jobs/${encodeURIComponent(jobId)}`;
  const flowPath = `${jobPath}/flows/${encodeURIComponent(flowId)}`;
  const record = { ...candidate, id: candidateId, job_id: jobId, current_verdict: { verdict: 'CONFIRMED_C2' } };
  const flow = { flow_id: flowId, job_id: jobId, timestamp: '2026-11-15T00:00:00Z', source_ip: '10.0.0.1', destination_ip: candidate.candidate_ip, protocol: 'TCP', direction: 'OUTBOUND', has_payload: true, current_label: { verdict: 'C2' } };
  const requests: { path: string; method: string; body?: unknown }[] = [];
  localStorage.setItem('c2hunter-token', 'token');
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input); const method = init?.method ?? 'GET';
    requests.push({ path, method, body: init?.body ? JSON.parse(String(init.body)) : undefined });
    if (path === candidatePath && method === 'DELETE') return new Response(null, { status: 204 });
    if (path === candidatePath) return Response.json(record);
    if (path === `${jobPath}/ai-runs`) return Response.json({ items: [{ id: runId, status: 'COMPLETED' }] });
    if (path === `/api/v1/ai-runs/${encodeURIComponent(runId)}/assessments`) return Response.json({ items: [] });
    if (path.startsWith(`${jobPath}/flows?`)) return Response.json({ items: [flow], total: 1, page: 1, page_size: 50 });
    if (path === `${flowPath}/payload-preview`) return Response.json({ payload_ascii: 'reserved-route-payload', payload_hex: '00', sample_bytes: 1 });
    if (path === `${flowPath}/detection-guidance`) return Response.json({ conditions: [], adjustments: [], recommendations: [], warnings: [] });
    if (path === `${jobPath}/flow-labels`) return Response.json({ label: { verdict: 'BENIGN' } });
    if (path === '/api/v1/pcap-exports') return Response.json({ id: 'export-raw-id', status: 'FAILED', error: 'Fixture no matching packets' });
    if (method === 'POST' && (path.startsWith(`${candidatePath}/`) || path === `${jobPath}/reanalyze`)) return Response.json({});
    if (path.startsWith('/api/v1/candidates?')) return Response.json({ items: [] });
    return Response.json({ error: { message: `Unexpected encoded route: ${path}` } }, { status: 404 });
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[`/candidates/${encodeURIComponent(candidateId)}`]}><App /></MemoryRouter></QueryClientProvider>);
  await screen.findByRole('heading', { name: candidate.candidate_ip });
  expect(screen.getByRole('link', { name: 'View source analysis' })).toHaveAttribute('href', `/analyses/${encodeURIComponent(jobId)}`);
  await user.click(screen.getByRole('button', { name: 'AI assessment' }));
  await screen.findByText('최신 Run에 이 후보의 AI 판정이 없습니다.');
  expect(requests.some(request => request.path === `/api/v1/ai-runs/${encodeURIComponent(runId)}/assessments`)).toBe(true);
  await user.click(screen.getByRole('button', { name: '판정 및 외부 검증' }));
  await user.type(screen.getByLabelText('Verdict note'), 'Literal route ownership');
  await user.click(screen.getByRole('button', { name: '판정 저장' }));
  await screen.findByText('Candidate verdict recorded');
  await user.click(screen.getByRole('button', { name: '외부 TI 다시 조회' }));
  await screen.findByText('Threat intelligence lookup completed');
  await user.click(screen.getByRole('button', { name: 'MISP로 전송' }));
  await screen.findByText('MISP ip-src attribute exported');
  await user.type(screen.getByLabelText('조치 내용'), 'Literal action route');
  await user.click(screen.getByRole('button', { name: '조치 완료' }));
  await screen.findByText('후속 대응 조치 상태가 저장되었습니다');
  await user.click(screen.getByRole('button', { name: 'Flow review' }));
  await user.click(await screen.findByRole('button', { name: `Inspect flow ${flowId}` }));
  await user.click(screen.getByRole('button', { name: `Preview payload ${flowId}` }));
  await screen.findByText('reserved-route-payload');
  await user.click(screen.getByRole('button', { name: `탐지 조정 가이드 ${flowId}` }));
  await screen.findByRole('heading', { name: '탐지 조정 가이드' });
  await user.click(screen.getByRole('button', { name: `Mark benign ${flowId}` }));
  await user.type(screen.getByLabelText('Analyst note'), 'Literal flow id');
  await user.click(screen.getByRole('button', { name: 'Save BENIGN label' }));
  await screen.findByText('BENIGN label saved.');
  expect(requests.find(request => request.path === `${jobPath}/flow-labels`)?.body).toMatchObject({ flow_id: flowId });
  await user.click(screen.getByRole('button', { name: '점수 조정 및 작업' }));
  await user.click(screen.getByRole('button', { name: 'Reanalyze' }));
  await screen.findByText('Reanalysis created');
  await user.click(screen.getByRole('button', { name: 'Export candidate PCAP' }));
  await screen.findByText(/Fixture no matching packets/);
  expect(requests.find(request => request.path === '/api/v1/pcap-exports')?.body).toEqual({ job_id: jobId, candidate_id: candidateId });
  await user.click(screen.getByRole('button', { name: 'Delete candidate' }));
  await user.click(screen.getByRole('button', { name: 'Delete permanently' }));
  await waitFor(() => expect(requests.some(request => request.path === candidatePath && request.method === 'DELETE')).toBe(true));
  for (const suffix of ['verdicts', 'actions', 'threat-intelligence/lookups', 'misp-exports']) expect(requests.some(request => request.path === `${candidatePath}/${suffix}` && request.method === 'POST')).toBe(true);
});

it('keeps the complete retained candidate record reachable without mounting it initially', async () => {
  const user = userEvent.setup();
  const full = { ...candidate, distinct_internal_hosts: 73, producer_metadata: { exact_fraction: 0.123456789, absent_measurement: null } };
  renderCandidate(async () => Response.json(full));
  await screen.findByRole('heading', { name: candidate.candidate_ip });
  expect(screen.queryByText(/exact_fraction/)).not.toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Raw candidate' }));
  expect(JSON.parse(screen.getByLabelText('Retained candidate JSON').textContent!)).toEqual(full);
  await user.click(screen.getByRole('button', { name: 'Close candidate detail' }));
  expect(screen.queryByLabelText('Retained candidate JSON')).not.toBeInTheDocument();
});

it('preserves an optional AI read failure after the detail is closed', async () => {
  const user = userEvent.setup();
  renderCandidate(async path => path.endsWith('/ai-runs') ? Response.json({ error: { message: 'AI read unavailable' } }, { status: 503 }) : Response.json(candidate));
  await user.click(await screen.findByRole('button', { name: 'AI assessment' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('AI read unavailable');
  await user.click(screen.getByRole('button', { name: 'Close candidate detail' }));
  expect(screen.getByRole('alert')).toHaveTextContent('AI read unavailable');
  expect(screen.queryByRole('heading', { name: 'AI C2 판정' })).not.toBeInTheDocument();
});

it('retires a deleted candidate selection without retiring a pending decision owner', async () => {
  const user = userEvent.setup();
  let missing = false;
  let release!: (response: Response) => void;
  const pending = new Promise<Response>(resolve => { release = resolve; });
  const { client } = renderCandidate(async (_path, init) => init?.method === 'POST' ? pending : missing ? Response.json({ error: { message: 'Candidate deleted' } }, { status: 404 }) : Response.json(candidate));
  await user.click(await screen.findByRole('button', { name: '판정 및 외부 검증' }));
  await user.type(screen.getByLabelText('Verdict note'), 'Decision already submitted');
  await user.click(screen.getByRole('button', { name: '판정 저장' }));
  await user.click(screen.getByRole('button', { name: '근거 1 · 주기적 비콘' }));
  missing = true;
  await act(async () => { await client.invalidateQueries({ queryKey: ['candidate', 'selection-a'] }); });
  await screen.findByText(/Candidate deleted/);
  expect(document.querySelector('.evidence.detailed')).toBeNull();
  expect(screen.getByRole('button', { name: '판정 및 외부 검증' })).toBeDisabled();
  expect(screen.getByRole('status')).toHaveTextContent('Candidate validation operation pending');
  await act(async () => release(Response.json({ error: { message: 'Decision rejected after deletion' } }, { status: 404 })));
  expect(await screen.findByText('Decision rejected after deletion')).toBeInTheDocument();
});

it('invalidates replaced evidence instead of reusing its expanded metric subtree', async () => {
  const user = userEvent.setup();
  const { client } = renderCandidate();
  await user.click(await screen.findByRole('button', { name: '근거 1 · 주기적 비콘' }));
  await user.click(screen.getByText('상세 지표 1개 더 보기'));
  await screen.findByText('observation-0');
  await act(async () => { client.setQueryData(['candidate', 'selection-a'], { ...candidate, evidence: [{ ...candidate.evidence[0], description: 'Replacement evidence', metrics: { missing: null } }] }); });
  await waitFor(() => expect(document.querySelector('.evidence.detailed')).toBeNull());
  expect(screen.getByText('Selected evidence is no longer available. Select the retained evidence again.')).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: '근거 1 · 주기적 비콘' }));
  expect(document.querySelector('.evidence.detailed')).toHaveTextContent('Replacement evidence');
  expect(screen.queryByText('observation-0')).not.toBeInTheDocument();
});

it('keeps nested mutation owners alive when a candidate refresh fails', async () => {
  const user = userEvent.setup();
  let failedRead = false;
  let release!: (response: Response) => void;
  const pending = new Promise<Response>(resolve => { release = resolve; });
  const { client } = renderCandidate(async (path, init) => {
    if (init?.method === 'POST') return pending;
    if (failedRead) return Response.json({ error: { message: 'Candidate refresh unavailable' } }, { status: 503 });
    return Response.json(path.endsWith('/selection-a') ? candidate : { items: [] });
  });
  await user.click(await screen.findByRole('button', { name: '판정 및 외부 검증' }));
  await user.type(screen.getByLabelText('Verdict note'), 'Pending decision');
  await user.click(screen.getByRole('button', { name: '판정 저장' }));
  await user.click(screen.getByRole('button', { name: 'Close candidate detail' }));
  failedRead = true;
  await act(async () => { await client.invalidateQueries({ queryKey: ['candidate', 'selection-a'] }); });
  expect(await screen.findByRole('alert')).toHaveTextContent('Candidate refresh unavailable');
  expect(screen.getByRole('status')).toHaveTextContent('Candidate validation operation pending');
  await act(async () => release(Response.json({ error: { message: 'Decision uncertain' } }, { status: 503 })));
  expect(await screen.findByText('Decision uncertain')).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: '판정 및 외부 검증' }));
  expect(screen.getByLabelText('Verdict note')).toHaveValue('Pending decision');
});

it('keeps unreported counts distinct from zero and preserves stored TI coverage in the initial summary', async () => {
  const user = userEvent.setup();
  renderCandidate(async path => Response.json(path.endsWith('/selection-a') ? { ...candidate, threat_intelligence: { status: 'PARTIAL', origin: 'AUTO', summary: {}, providers: { virustotal: { status: 'OK' }, misp: { status: 'ERROR', error: 'TI provider unavailable' } } } } : { items: [] }));
  const summary = await screen.findByRole('region', { name: 'Candidate result summary' });
  expect(within(summary).getAllByText('기록 없음')).toHaveLength(2);
  expect(within(summary).getByText('자동 조회 부분 완료')).toBeInTheDocument();
  expect(within(summary).queryByText('미조회')).not.toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: '판정 및 외부 검증' }));
  expect(screen.queryByText('악성 0')).not.toBeInTheDocument();
  expect(screen.getByText('악성 기록 없음')).toBeInTheDocument();
  expect(screen.getByText('TI provider unavailable')).toBeInTheDocument();
});

it('resets selected evidence and lazy metrics across cached A → B → A', async () => {
  const user = userEvent.setup();
  const other = { ...candidate, id: 'selection-b', candidate_ip: '203.0.113.10' };
  const { client } = renderCandidate(async path => Response.json(path.endsWith('/selection-b') ? other : candidate));
  await screen.findByRole('heading', { name: candidate.candidate_ip });
  client.setQueryData(['candidate', 'selection-b'], other);
  await user.click(screen.getByRole('button', { name: '근거 1 · 주기적 비콘' }));
  await user.click(screen.getByText('상세 지표 1개 더 보기'));
  expect(await screen.findByText('observation-0')).toBeInTheDocument();
  await user.click(screen.getByRole('link', { name: 'Test candidate B' }));
  await screen.findByRole('heading', { name: other.candidate_ip });
  expect(document.querySelector('.evidence.detailed')).toBeNull();
  await user.click(screen.getByRole('link', { name: 'Test candidate A' }));
  await screen.findByRole('heading', { name: candidate.candidate_ip });
  expect(document.querySelector('.evidence.detailed')).toBeNull();
  await user.click(screen.getByRole('button', { name: '근거 1 · 주기적 비콘' }));
  expect(screen.getByText('상세 지표 1개 더 보기').closest('details')!.children).toHaveLength(1);
});

it.each(['verdict', 'TI', 'MISP', 'action'])('retains a deferred %s write, draft and failure through repeated presentation closes', async kind => {
  const user = userEvent.setup();
  let release!: (response: Response) => void;
  const pending = new Promise<Response>(resolve => { release = resolve; });
  const { requests } = renderCandidate(async (path, init) => init?.method === 'POST' ? pending : Response.json(path.endsWith('/selection-a') ? { ...candidate, current_verdict: { verdict: 'CONFIRMED_C2' }, action_status: 'PENDING' } : { items: [] }));
  await user.click(await screen.findByRole('button', { name: '판정 및 외부 검증' }));
  await user.type(screen.getByLabelText('Verdict note'), 'Retained verdict draft');
  await user.type(screen.getByLabelText('MISP event ID'), 'event-123');
  await user.type(screen.getByLabelText('조치 내용'), 'Retained action draft');
  const submitName = kind === 'verdict' ? '판정 저장' : kind === 'TI' ? '외부 TI 다시 조회' : kind === 'MISP' ? 'MISP로 전송' : '조치 완료';
  await user.click(screen.getByRole('button', { name: submitName }));
  for (let i = 0; i < 2; i++) {
    await user.click(screen.getByRole('button', { name: 'Close candidate detail' }));
    expect(screen.getByRole('status')).toHaveTextContent('Candidate validation operation pending');
    expect(screen.queryByLabelText('Verdict note')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: '판정 및 외부 검증' }));
    expect(screen.getByLabelText('Verdict note')).toHaveValue('Retained verdict draft');
    const pendingName = kind === 'verdict' ? '저장 중…' : kind === 'TI' ? '조회 중…' : kind === 'MISP' ? '전송 중…' : '조치 완료';
    expect(screen.getByRole('button', { name: pendingName })).toBeDisabled();
  }
  await user.click(screen.getByRole('button', { name: 'Close candidate detail' }));
  await act(async () => release(Response.json({ error: { message: `${kind} write failed` } }, { status: 503 })));
  expect(await screen.findByRole('alert')).toHaveTextContent(`${kind} write failed`);
  await user.click(screen.getByRole('button', { name: '판정 및 외부 검증' }));
  expect(screen.getByRole('alert')).toHaveTextContent(`${kind} write failed`);
  expect(screen.getByLabelText('MISP event ID')).toHaveValue('event-123');
  expect(requests.filter(request => request.method === 'POST')).toHaveLength(1);
});

it('shows a pending export on presentation close without cancelling until route departure', async () => {
  const user = userEvent.setup();
  let release!: (response: Response) => void;
  const pending = new Promise<Response>(resolve => { release = resolve; });
  const { requests } = renderCandidate(async (path, init) => {
    if (path === '/api/v1/pcap-exports' && init?.method === 'POST') return pending;
    if (path.endsWith('/cancel')) return Response.json({ status: 'CANCELLED' });
    return Response.json(path.endsWith('/selection-b') ? { ...candidate, id: 'selection-b' } : candidate);
  });
  await user.click(await screen.findByRole('button', { name: '점수 조정 및 작업' }));
  await user.click(screen.getByRole('button', { name: 'Export candidate PCAP' }));
  await user.click(screen.getByRole('button', { name: 'Close candidate detail' }));
  expect(screen.getByRole('status')).toHaveTextContent('Candidate operation pending');
  await user.click(screen.getByRole('button', { name: '점수 조정 및 작업' }));
  expect(screen.getByRole('button', { name: 'Requesting export…' })).toBeDisabled();
  expect(requests.filter(request => request.path.endsWith('/cancel'))).toHaveLength(0);
  await user.click(screen.getByRole('link', { name: 'Test candidate B' }));
  await act(async () => release(Response.json({ id: 'export-a', status: 'PENDING' })));
  await waitFor(() => expect(requests.filter(request => request.path.endsWith('/cancel'))).toHaveLength(1));
  expect(requests.filter(request => request.path === '/api/v1/pcap-exports')).toHaveLength(1);
  expect(screen.queryByText(/Candidate operation pending/)).not.toBeInTheDocument();
});

it('pages traffic buckets without dropping the last retained bucket', async () => {
  const user = userEvent.setup();
  renderCandidate(async path => Response.json(path.endsWith('/selection-a') ? { ...candidate, traffic_buckets: Array.from({ length: 600 }, (_, i) => ({ start: new Date(Date.UTC(2026, 10, 15, 0, i)).toISOString(), flows: i, packets: 1, bytes: 1 })) } : { items: [] }));
  await user.click(await screen.findByRole('button', { name: 'Traffic buckets' }));
  const table = screen.getByRole('table', { name: 'Candidate traffic buckets' });
  expect(within(table).getAllByRole('row')).toHaveLength(51);
  for (let page = 0; page < 11; page++) await user.click(screen.getByRole('button', { name: 'Next traffic buckets' }));
  expect(screen.getByText('Buckets 551–600 of 600')).toBeInTheDocument();
  expect(within(table).getByText('599')).toBeInTheDocument();
});

it('focuses the selected nonmodal detail and returns focus on Escape', async () => {
  const user = userEvent.setup();
  renderCandidate();
  const opener = await screen.findByRole('button', { name: '근거 1 · 주기적 비콘' });
  await user.click(opener);
  const detail = screen.getByRole('region', { name: 'Selected candidate detail' });
  expect(within(detail).getByRole('heading', { name: 'Selected candidate detail' })).toHaveFocus();
  expect(detail).not.toHaveAttribute('aria-modal');
  await user.keyboard('{Escape}');
  expect(screen.queryByRole('region', { name: 'Selected candidate detail' })).not.toBeInTheDocument();
  expect(opener).toHaveFocus();
  expect(document.querySelector('.evidence.detailed')).toBeNull();
});

it('selects one flow while its deferred label owner survives purpose switches and page changes', async () => {
  const user = userEvent.setup();
  let release!: (response: Response) => void;
  const pending = new Promise<Response>(resolve => { release = resolve; });
  const flow = (id: string) => ({ flow_id: id, job_id: 'job-a', timestamp: '2026-11-15T00:00:00Z', source_ip: '10.0.0.1', destination_ip: '203.0.113.9', protocol: 'TCP', direction: 'OUTBOUND', has_payload: true });
  const { requests } = renderCandidate(async (path, init) => {
    if (init?.method === 'POST') return pending;
    if (path.includes('/flows?')) return Response.json({ items: [flow(path.includes('page=2') ? 'flow-b' : 'flow-a')], page: path.includes('page=2') ? 2 : 1, page_size: 1, total: 2 });
    return Response.json(path.endsWith('/selection-a') ? candidate : { items: [] });
  });
  await user.click(await screen.findByRole('button', { name: 'Flow review' }));
  expect(screen.queryByRole('button', { name: 'Mark C2 flow-a' })).not.toBeInTheDocument();
  await user.click(await screen.findByRole('button', { name: 'Inspect flow flow-a' }));
  await user.click(screen.getByRole('button', { name: 'Mark benign flow-a' }));
  await user.type(screen.getByLabelText('Analyst note'), 'Keep this pending label');
  await user.click(screen.getByRole('button', { name: 'Save BENIGN label' }));
  await user.click(screen.getByRole('button', { name: 'Network context' }));
  expect(screen.getByRole('status')).toHaveTextContent('flow-a · Saving…');
  expect(screen.queryByLabelText('Analyst note')).not.toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Flow review' }));
  await user.click(screen.getByRole('button', { name: 'Inspect flow flow-a' }));
  expect(screen.getByRole('button', { name: 'Saving…' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Mark C2 flow-a' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Mark benign flow-a' })).toBeDisabled();
  await user.click(screen.getByRole('button', { name: 'Next flows' }));
  await user.click(await screen.findByRole('button', { name: 'Inspect flow flow-b' }));
  expect(screen.queryByRole('button', { name: 'Mark C2 flow-a' })).not.toBeInTheDocument();
  expect(screen.getByRole('status')).toHaveTextContent('flow-a · Saving…');
  release(Response.json({ error: { message: 'label write failed' } }, { status: 503 }));
  expect(await screen.findByRole('alert')).toHaveTextContent('label write failed');
  await user.click(screen.getByRole('button', { name: 'Previous flows' }));
  await user.click(await screen.findByRole('button', { name: 'Inspect flow flow-a' }));
  expect(screen.getByLabelText('Analyst note')).toHaveValue('Keep this pending label');
  expect(requests.filter(request => request.method === 'POST')).toHaveLength(1);
});

it('materializes metrics only while open and pages every retained array value', async () => {
  const user = userEvent.setup();
  renderCandidate();
  await user.click(await screen.findByRole('button', { name: '근거 1 · 주기적 비콘' }));
  const disclosure = screen.getByText('상세 지표 1개 더 보기').closest('details')!;
  expect(disclosure.children).toHaveLength(1);
  await user.click(within(disclosure).getByText('상세 지표 1개 더 보기'));
  expect(await screen.findByText('observation-0')).toBeInTheDocument();
  expect(screen.queryByText('observation-99')).not.toBeInTheDocument();
  for (let page = 1; page < 5; page++) await user.click(screen.getByRole('button', { name: 'Next metric values' }));
  expect(screen.getByText('observation-99')).toBeInTheDocument();
  expect(screen.getByText('Values 81–100 of 100')).toBeInTheDocument();
  await user.click(within(disclosure).getByText('상세 지표 1개 더 보기'));
  await waitFor(() => expect(disclosure.children).toHaveLength(1));
  expect(screen.queryByText('observation-99')).not.toBeInTheDocument();
});

it('opens the candidate with its result, limitations and brief chart, then selects only one retained evidence', async () => {
  const user = userEvent.setup();
  const { requests } = renderCandidate();
  await screen.findByRole('heading', { name: '203.0.113.9' });
  expect(screen.queryByRole('table', { name: 'Candidate traffic buckets' })).not.toBeInTheDocument();
  expect(screen.queryByRole('heading', { name: 'Network context' })).not.toBeInTheDocument();
  expect(screen.queryByLabelText('Verdict note')).not.toBeInTheDocument();
  expect(screen.queryByRole('heading', { name: 'Flow review' })).not.toBeInTheDocument();
  expect(screen.getByRole('img', { name: 'Traffic over time' })).toBeInTheDocument();
  const summary = screen.getByRole('region', { name: 'Candidate result summary' });
  expect(within(summary).getAllByRole('listitem')).toHaveLength(3);
  expect(within(summary).getByText('미분석')).toBeInTheDocument();
  expect(screen.getByText('Retained evidence coverage is incomplete')).toBeInTheDocument();
  expect(requests.map(request => request.path)).toEqual(['/api/v1/candidates/selection-a']);
  await user.click(screen.getByRole('button', { name: '근거 1 · 주기적 비콘' }));
  expect(screen.getByText('원시 점수')).toBeInTheDocument();
  expect(document.querySelectorAll('.evidence.detailed')).toHaveLength(1);
  await user.selectOptions(screen.getByLabelText('Evidence selection'), '4');
  expect(document.querySelectorAll('.evidence.detailed')).toHaveLength(1);
  expect(document.querySelector('.evidence.detailed')).toHaveTextContent('Reason 5');
  await user.click(screen.getByRole('button', { name: 'Traffic buckets' }));
  expect(screen.getByRole('table', { name: 'Candidate traffic buckets' })).toBeInTheDocument();
  expect(document.querySelectorAll('.evidence.detailed')).toHaveLength(0);
  expect(requests.every(request => request.method === 'GET')).toBe(true);
});
