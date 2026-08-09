import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import App from '../src/App';

const responses: Record<string, unknown> = {
  '/api/v1/dashboard': {
    generated_at: '2026-07-20T10:10:00Z',
    fleet: { total: 3, online: 2, offline: 1, degraded: 0, dropped_packets: 6 },
    analyses: { total: 4, active: 1, completed_24h: 2, failed_24h: 1, partially_completed_24h: 1, by_status: { WAITING_FOR_SENSOR: 0, CAPTURING: 0, UPLOADING: 0, INGESTING: 0, ANALYZING: 1 } },
    candidates: { total: 5, critical: 1, high: 1, medium: 2, low: 1, new_24h: 3 },
    candidate_trend: [{ hour: '07:00', count: 0 }, { hour: '08:00', count: 1 }, { hour: '09:00', count: 0 }, { hour: '10:00', count: 2 }],
    priority_candidates: [{ id: 'candidate-1', job_id: 'job-1', candidate_ip: '203.0.113.9', score: 91, severity: 'CRITICAL', last_seen: '2026-07-20T10:05:00Z', evidence_count: 2 }],
    recent_analyses: [{ id: 'job-1', name: 'Investigation', status: 'COMPLETED', created_at: '2026-07-20T10:00:00Z', candidate_count: 2, packet_count: 100, flow_count: 50 }],
    sensor_quality: [{ sensor_id: 'sensor-b', name: 'Sensor B', status: 'OFFLINE', received_packets: 94, dropped_packets: 6, drop_rate_percent: 6, last_heartbeat_at: '2026-07-20T09:00:00Z', last_error: 'capture stopped' }],
    attention: [
      { kind: 'OFFLINE_SENSOR', severity: 'HIGH', title: 'Sensor B 오프라인', detail: '마지막 heartbeat를 확인하세요.', href: '/sensors/sensor-b' },
      { kind: 'CRITICAL_CANDIDATE', severity: 'CRITICAL', title: '203.0.113.9 조사 필요', detail: '점수 91 · CRITICAL', href: '/candidates/candidate-1' },
    ],
  },
  '/api/v1/analysis-jobs': { items: [{ id: 'job-1', name: 'Investigation', description: 'Initial note', status: 'COMPLETED', source_type: 'PCAP_UPLOAD', source: { filename: 'capture.pcap', size_bytes: 2048 }, created_at: '2026-07-20T10:10:00Z', start_time: '2026-07-20T10:00:00Z', end_time: '2026-07-20T10:05:00Z', packet_count: 100, flow_count: 50, candidate_count: 2 }] },
  '/api/v1/sensors': { items: [{ sensor_id: 'sensor-a', name: 'Sensor A', status: 'ONLINE', last_heartbeat: '2026-07-20T10:00:00Z', interfaces: [{ name: 'eth0', direction: 'INBOUND' }], version: '0.1.0', cpu_percent: 10, memory_percent: 20, disk_percent: 30, received_packets: 1000, dropped_packets: 2 }, { sensor_id: 'sensor-b', name: 'Sensor B', status: 'ONLINE', interfaces: [{ name: 'eth1', direction: 'OUTBOUND' }] }] },
  '/api/v1/analysis-jobs/job-1': { id: 'job-1', dataset_id: 'dataset-1', name: 'Investigation', status: 'ANALYZING', sensor_ids: ['sensor-a'], internal_networks: ['10.0.0.0/8'], capture: { max_packets: 2000, directions: ['OUTBOUND'] }, analysis: { profile: 'ddos_botnet', minimum_candidate_score: 60 }, transitions: [{ to_status: 'CREATED', occurred_at: '2026-07-20T10:00:00Z', reason: 'analysis requested' }], packet_count: 100, flow_count: 50, candidate_count: 1 },
  '/api/v1/analysis-jobs/job-1/candidates?page_size=200': { items: [{ id: 'candidate-1', job_id: 'job-1', candidate_ip: '203.0.113.9', score: 80, severity: 'HIGH', hosts: ['10.0.0.5'], sensors: ['sensor-a'], first_seen: '2026-07-20T10:00:00Z', last_seen: '2026-07-20T10:05:00Z', evidence: [{ type: 'PERIODIC_BEACON', detector: 'periodic_beacon', contribution: 15, description: 'Periodic traffic' }] }] },
  '/api/v1/candidates': { items: [{ id: 'candidate-1', job_id: 'job-1', candidate_ip: '203.0.113.9', score: 80, severity: 'HIGH', hosts: ['10.0.0.5'], sensors: ['sensor-a'], first_seen: '2026-07-20T10:00:00Z', last_seen: '2026-07-20T10:05:00Z', evidence: [{ type: 'PERIODIC_BEACON', detector: 'periodic_beacon', contribution: 15, description: 'Periodic traffic' }] }] },
  '/api/v1/candidates/candidate-1': { id: 'candidate-1', job_id: 'job-1', candidate_ip: '203.0.113.9', score: 80, severity: 'HIGH', hosts: ['10.0.0.5'], sensors: ['sensor-a'], protocols: ['TCP'], ports: [443], domains: ['c2.example'], first_seen: '2026-07-20T10:00:00Z', last_seen: '2026-07-20T10:05:00Z', flow_count: 5, packet_count: 20, byte_count: 2048, traffic_buckets: [{ start: '2026-07-20T10:00:00Z', flows: 5, packets: 20, bytes: 2048 }], evidence: [{ type: 'PERIODIC_BEACON', detector: 'periodic_beacon', version: '1.0.0', raw_score: 15, contribution: 15, confidence: 0.9, description: 'Periodic traffic', hosts: ['10.0.0.5'], sensors: ['sensor-a'], metrics: { sample_count: 7, period_seconds: 30 } }], adjustments: [{ kind: 'SINGLE_HOST', points: -20, explanation: 'Single internal host observed' }] },
  '/api/v1/analysis-jobs/job-1/flows?candidate_ip=203.0.113.9&page=1&page_size=50': { items: [{ flow_id: '0123456789abcdef01234567', job_id: 'job-1', sensor_id: 'sensor-a', timestamp: '2026-07-20T10:00:00Z', source_ip: '10.0.0.5', destination_ip: '203.0.113.9', source_port: 51000, destination_port: 443, internal_ip: '10.0.0.5', external_ip: '203.0.113.9', service_port: 443, protocol: 'TCP', direction: 'OUTBOUND', packet_count: 2, total_bytes: 128, payload_hash: '8a62e967fcd6dfa5d75308c37808b4668a7faf1cdb06e09ac0a7161827603887', payload_prefix_hash: '8a62e967fcd6dfa5d75308c37808b4668a7faf1cdb06e09ac0a7161827603887', payload_length: 6, payload_entropy: 2.585, payload_printable_ratio: 1, payload_simhash: 'e627bf19152d67b3', payload_feature_version: '1', has_payload: true, current_label: null }], page: 1, page_size: 50, total: 1 },
  '/api/v1/analysis-jobs/job-1/flows/0123456789abcdef01234567/payload-preview': { flow_id: '0123456789abcdef01234567', payload_hex: '626561636f6e', payload_ascii: 'beacon', sample_bytes: 6, payload_length: 6, truncated: false, payload_hash: '8a62e967fcd6dfa5d75308c37808b4668a7faf1cdb06e09ac0a7161827603887' },
  '/api/v1/payload-signatures?page_size=200': { items: [{ id: 'signature-1', name: 'TCP beacon payload', description: 'Confirmed implant beacon', version: 1, enabled: true, source_job_id: 'job-1', source_flow_id: '0123456789abcdef01234567', source_label_id: 'label-1', protocol: 'TCP', direction: 'OUTBOUND', service_port: 443, payload_hash: '8a62e967fcd6dfa5d75308c37808b4668a7faf1cdb06e09ac0a7161827603887', payload_prefix_hash: '8a62e967fcd6dfa5d75308c37808b4668a7faf1cdb06e09ac0a7161827603887', payload_length: 6, payload_entropy: 2.585, payload_printable_ratio: 1, payload_simhash: 'e627bf19152d67b3', payload_feature_version: '1', length_tolerance_ratio: 0.15, entropy_tolerance: 0.75, simhash_max_distance: 8, created_by: 'analyst', created_at: '2026-07-20T10:06:00Z', updated_at: '2026-07-20T10:06:00Z' }] },
  '/api/v1/allowlist': { items: [] },
};
responses['/api/v1/analysis-jobs/job-1/flows?page=1&page_size=50&include_filter=%7B%22has_payload%22%3Atrue%7D'] =
  responses['/api/v1/analysis-jobs/job-1/flows?candidate_ip=203.0.113.9&page=1&page_size=50'];
responses['/api/v1/candidates?page=1&page_size=50&minimum_score=0&sort=-score'] =
  responses['/api/v1/candidates'];
responses['/api/v1/sensor-pcaps?analysis_job_id=job-1&page_size=200'] = { items: [], total: 0, page: 1, page_size: 200 };
responses['/api/v1/analysis-jobs/job-1/ai-runs'] = {
  items: [{ id: 'ai-run-1', analysis_job_id: 'job-1', status: 'COMPLETED', candidate_count: 1, created_at: '2026-07-20T10:11:00Z' }],
  total: 1,
};
responses['/api/v1/ai-runs/ai-run-1/assessments'] = {
  items: [{
    id: 'assessment-1', candidate_id: 'candidate-1', external_ip: '203.0.113.9',
    assessment: {
      candidate: { external_ip: '203.0.113.9', verdict: 'SUSPICIOUS', confidence: 0.75, summary_ko: '주기 통신 근거를 검토해야 합니다.', summary_en: 'Review periodic traffic evidence.' },
      supporting_factors: [{ title: 'Periodic traffic', evidence_ids: ['E-C2H-candidate-1-01'], explanation: 'Repeated timing', strength: 'HIGH' }],
      counter_factors: [], missing_information: ['Local reputation'], recommended_actions: [], stable_detection_features: [], limitations: [],
    },
  }],
  total: 1,
};

function renderAt(route: string, handler?: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>) {
  localStorage.setItem('c2hunter-token', 'token');
  vi.stubGlobal('fetch', vi.fn(handler ?? (async (input: RequestInfo | URL) => {
    const path = String(input);
    return new Response(JSON.stringify(responses[path]), { status: responses[path] ? 200 : 404, headers: { 'content-type': 'application/json' } });
  })));
  return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={[route]}><App /></MemoryRouter></QueryClientProvider>);
}

describe('C2Hunter UI', () => {
  it('shows dashboard priorities, threat posture, and recent activity', async () => {
    renderAt('/');
    expect(await screen.findByRole('heading', { name: 'Dashboard' })).toBeInTheDocument();
    expect(await screen.findByText('온라인 센서')).toBeInTheDocument();
    expect(screen.getByText('High / Critical 후보')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: '지금 확인할 항목' })).toBeInTheDocument();
    const priorityHeading = screen.getByRole('heading', { name: '우선 조사 후보' });
    expect(priorityHeading).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: '최근 분석' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: '후보 심각도' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: '분석 파이프라인' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: '센서 수집 품질' })).toBeInTheDocument();
    expect(screen.getByText((_, element) => element?.tagName === 'SMALL' && element.textContent?.includes('드롭률 6.00%') === true)).toBeInTheDocument();
    expect(within(priorityHeading.closest('article') as HTMLElement).getByRole('link', { name: /203\.0\.113\.9/ })).toHaveAttribute('href', '/candidates/candidate-1');
    expect(screen.getByRole('link', { name: /Investigation/ })).toHaveAttribute('href', '/analyses/job-1');
    expect(screen.getByText('Sensor B 오프라인')).toBeInTheDocument();
  });

  it('shows sensor status and direction with an accessible table', async () => {
    renderAt('/sensors');
    expect(await screen.findByRole('link', { name: 'Sensor A' })).toBeInTheDocument();
    expect(screen.getByText('INBOUND')).toBeInTheDocument();
    expect(screen.getByRole('table', { name: 'Sensors' })).toBeInTheDocument();
  });

  it('renders raw Controller candidates without assuming optional arrays exist', async () => {
    renderAt('/candidates');
    expect(await screen.findByRole('table', { name: 'C2 candidates' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: '203.0.113.9' })).toBeInTheDocument();
    expect(screen.getByText('Unknown')).toBeInTheDocument();
    expect(screen.getByText('주기적 비콘')).toBeInTheDocument();
  });

  it('filters, sorts, and paginates candidates through the Controller API', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path.includes('page=2')) {
        return new Response(JSON.stringify({ items: [{ id: 'candidate-2', job_id: 'job-1', candidate_ip: '198.51.100.7', score: 64, severity: 'MEDIUM' }], page: 2, page_size: 50, total: 51 }), { status: 200 });
      }
      return new Response(JSON.stringify({ items: responses['/api/v1/candidates'] && (responses['/api/v1/candidates'] as { items: unknown[] }).items, page: 1, page_size: 50, total: 51 }), { status: 200 });
    });
    localStorage.setItem('c2hunter-token', 'token');
    vi.stubGlobal('fetch', fetchMock);
    const user = userEvent.setup();
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={['/candidates']}><App /></MemoryRouter></QueryClientProvider>);

    expect(await screen.findByRole('link', { name: '203.0.113.9' })).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText('Severity'), 'HIGH');
    await user.selectOptions(screen.getByLabelText('Verdict'), 'CONFIRMED_C2');
    await user.clear(screen.getByLabelText('Minimum score'));
    await user.type(screen.getByLabelText('Minimum score'), '70');
    await user.click(screen.getByLabelText('Include suppressed candidates'));
    await user.selectOptions(screen.getByLabelText('Sort candidates'), 'candidate_ip');
    await user.click(screen.getByRole('button', { name: 'Apply filters' }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/v1/candidates?page=1&page_size=50&minimum_score=70&sort=candidate_ip&severity=HIGH&verdict=CONFIRMED_C2&include_suppressed=true', expect.anything()));
    await user.click(screen.getByRole('button', { name: 'Next candidates' }));
    expect(await screen.findByRole('link', { name: '198.51.100.7' })).toBeInTheDocument();
    expect(screen.getByText('Candidates 51–51 of 51')).toBeInTheDocument();
  });

  it('marks the current navigation destination', async () => {
    renderAt('/candidates');
    expect(await screen.findByRole('link', { name: 'Candidates' })).toHaveAttribute('aria-current', 'page');
    expect(screen.getByRole('link', { name: 'Dashboard' })).not.toHaveAttribute('aria-current');
  });

  it('shows detector settings, state history, and candidates on analysis detail', async () => {
    renderAt('/analyses/job-1');
    expect(await screen.findByRole('heading', { name: '탐지 설정' })).toBeInTheDocument();
    expect(screen.getByText('최소 후보 점수')).toBeInTheDocument();
    expect(screen.getByText('ddos_botnet')).toBeInTheDocument();
    expect(await screen.findByRole('table', { name: 'Analysis candidates' })).toBeInTheDocument();
    expect(await screen.findByRole('table', { name: 'Analysis flows' })).toBeInTheDocument();
    expect(screen.getByText('analysis requested')).toBeInTheDocument();
  });

  it('shows AI run status and evidence-linked candidate assessment', async () => {
    renderAt('/analyses/job-1');

    const region = await screen.findByRole('region', { name: 'AI C2 분석' });
    expect(await within(region).findByText('COMPLETED')).toBeInTheDocument();
    expect(await within(region).findByText('SUSPICIOUS')).toBeInTheDocument();
    expect(within(region).getByText('신뢰도 75%')).toBeInTheDocument();
    expect(within(region).getByText('주기 통신 근거를 검토해야 합니다.')).toBeInTheDocument();
    expect(within(region).getByText('E-C2H-candidate-1-01')).toBeInTheDocument();
    expect(within(region).getByRole('link', { name: '203.0.113.9' })).toHaveAttribute(
      'href',
      '/candidates/candidate-1',
    );
  });

  it('shows the latest validated AI assessment on candidate detail', async () => {
    renderAt('/candidates/candidate-1');

    const region = await screen.findByRole('region', { name: 'AI C2 판정' });
    expect(await within(region).findByText('SUSPICIOUS')).toBeInTheDocument();
    expect(within(region).getByText('신뢰도 75%')).toBeInTheDocument();
    expect(within(region).getByText('E-C2H-candidate-1-01')).toBeInTheDocument();
  });

  it('presents nested capture and detection configuration without exposed raw JSON', async () => {
    const detailed = {
      ...(responses['/api/v1/analysis-jobs/job-1'] as Record<string, unknown>),
      capture: {
        max_packets: 2000,
        directions: ['OUTBOUND', 'INBOUND'],
        store_pcap: true,
        limits: { max_duration_seconds: 300, idle_timeout_seconds: 30 },
      },
      analysis: {
        profile: 'ddos_botnet',
        minimum_candidate_score: 60,
        minimum_distinct_clients: 3,
        periodicity_min_samples: 5,
        ml_anomaly_enabled: true,
        detector_weights: { periodic_beacon: 1.5, common_destination: 0.25, dns_tunnel: 0 },
        custom_policy: { mode: 'strict', tags: ['production', 'edge'] },
      },
    };
    renderAt('/analyses/job-1', async (input: RequestInfo | URL) => {
      const path = String(input);
      return new Response(JSON.stringify(path === '/api/v1/analysis-jobs/job-1' ? detailed : responses[path] ?? { items: [] }), { status: 200 });
    });

    const detection = await screen.findByRole('region', { name: '탐지 설정 요약' });
    expect(within(detection).getByText('최소 후보 점수')).toBeInTheDocument();
    expect(within(detection).getByText('60점 이상')).toBeInTheDocument();
    expect(within(detection).getByText('1.5×')).toBeInTheDocument();
    expect(within(detection).getByText('강화')).toBeInTheDocument();
    expect(within(detection).getByText('비활성')).toBeInTheDocument();
    expect(within(detection).getByText('Strict')).toBeInTheDocument();
    expect(within(detection).getByText('Production')).toBeInTheDocument();

    const scope = screen.getByRole('region', { name: '분석 범위' });
    expect(within(scope).getByText('sensor-a')).toBeInTheDocument();
    expect(within(scope).queryByText('Sensor-A')).not.toBeInTheDocument();
    expect(within(scope).getByText('OUTBOUND')).toBeInTheDocument();
    expect(within(scope).getByText('INBOUND')).toBeInTheDocument();
    expect(within(scope).getByText('PCAP 저장')).toBeInTheDocument();
    expect(within(scope).getByText('사용')).toBeInTheDocument();

    const raw = screen.getByText('원본 설정 보기').closest('details');
    expect(raw).not.toHaveAttribute('open');
    expect(document.body).not.toHaveTextContent('{"periodic_beacon":1.5');
  });

  it('reanalyzes the same dataset with tuned detector weights', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path === '/api/v1/analysis-jobs/job-1') return new Response(JSON.stringify({ ...(responses[path] as Record<string, unknown>), status: 'COMPLETED' }), { status: 200 });
      if (path === '/api/v1/analysis-jobs/job-1/reanalyze' && init?.method === 'POST') return new Response(JSON.stringify({ id: 'job-tuned', status: 'CREATED' }), { status: 201 });
      if (path === '/api/v1/analysis-jobs/job-tuned') return new Response(JSON.stringify({ id: 'job-tuned', name: 'Tuned analysis', status: 'CREATED' }), { status: 200 });
      return new Response(JSON.stringify(responses[path] ?? { items: [] }), { status: 200 });
    });
    localStorage.setItem('c2hunter-token', 'token');
    vi.stubGlobal('fetch', fetchMock);
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={['/analyses/job-1']}><App /></MemoryRouter></QueryClientProvider>);
    const user = userEvent.setup();

    expect(await screen.findByRole('heading', { name: '가중치 조정 후 재분석' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: '대형 서비스 노이즈 줄이기' }));
    await user.click(screen.getByRole('button', { name: '탐지 가중치로 재분석' }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/v1/analysis-jobs/job-1/reanalyze', expect.objectContaining({ method: 'POST' })));
    const call = fetchMock.mock.calls.find(([url, init]) => url === '/api/v1/analysis-jobs/job-1/reanalyze' && init?.method === 'POST');
    expect(JSON.parse(String(call?.[1]?.body))).toEqual(expect.objectContaining({
      idempotency_key: expect.any(String),
      detector_weights: expect.objectContaining({ common_destination: 0.25, analyst_payload_signature: 1 }),
    }));
  });

  it('resets reanalysis weights when navigating between completed jobs', async () => {
    const jobs = [
      { id: 'job-1', name: 'First investigation', status: 'COMPLETED' },
      { id: 'job-2', name: 'Second investigation', status: 'COMPLETED' },
    ];
    const secondJob = { ...jobs[1], dataset_id: 'dataset-2', analysis: { detector_weights: { common_destination: 1.75 } } };
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path === '/api/v1/analysis-jobs/job-1') {
        return new Response(JSON.stringify({ ...jobs[0], dataset_id: 'dataset-1', parent_job_id: 'job-2', analysis: { detector_weights: { common_destination: 1 } } }), { status: 200 });
      }
      if (path === '/api/v1/analysis-jobs/job-2') {
        return new Response(JSON.stringify(secondJob), { status: 200 });
      }
      return new Response(JSON.stringify({ items: [] }), { status: 200 });
    });
    localStorage.setItem('c2hunter-token', 'token');
    vi.stubGlobal('fetch', fetchMock);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    client.setQueryData(['job', 'job-2'], secondJob);
    render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/analyses/job-1']}><App /></MemoryRouter></QueryClientProvider>);
    const user = userEvent.setup();

    const firstWeight = await screen.findByLabelText(/공통 목적지/);
    await user.clear(firstWeight);
    await user.type(firstWeight, '0.25');
    await user.click(screen.getByRole('link', { name: 'job-2' }));

    expect(await screen.findByLabelText(/공통 목적지/)).toHaveValue(1.75);
  });

  it('lets an analyst browse flows that were never promoted to candidates', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path.includes('/flows?')) {
        return new Response(JSON.stringify(responses['/api/v1/analysis-jobs/job-1/flows?page=1&page_size=50&include_filter=%7B%22has_payload%22%3Atrue%7D']), { status: 200, headers: { 'content-type': 'application/json' } });
      }
      return new Response(JSON.stringify(responses[path]), { status: responses[path] ? 200 : 404, headers: { 'content-type': 'application/json' } });
    });
    renderAt('/analyses/job-1');
    vi.stubGlobal('fetch', fetchMock);
    const user = userEvent.setup();

    expect(await screen.findByRole('table', { name: 'Analysis flows' })).toBeInTheDocument();
    expect(screen.getByText('No filter-out patterns configured')).toBeInTheDocument();
    expect(screen.getByText('Filters applied')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Add filter out' }));
    expect(screen.getByText('Unapplied changes')).toBeInTheDocument();
    expect(screen.getAllByText('Advanced conditions')).toHaveLength(2);
    await user.type(screen.getByLabelText('Filter out 1 endpoint IP or CIDR'), '198.51.100.0/24');
    await user.type(screen.getByLabelText('Filter out 1 external service port'), '443');
    await user.type(screen.getByLabelText('Filter out 1 source port'), '51000');
    await user.type(screen.getByLabelText('Filter out 1 destination port'), '443');
    await user.click(screen.getByRole('button', { name: 'Apply filters' }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/analysis-jobs/job-1/flows?page=1&page_size=50&include_filter=%7B%22has_payload%22%3Atrue%7D&exclude_filter=%7B%22candidate_ip%22%3A%22198.51.100.0%2F24%22%2C%22port%22%3A443%2C%22source_port%22%3A51000%2C%22destination_port%22%3A443%7D',
      expect.any(Object),
    ));
  });

  it('renders an error state with retry when a request fails', async () => {
    localStorage.setItem('c2hunter-token', 'token');
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: { message: 'Storage unavailable' } }), { status: 503, headers: { 'content-type': 'application/json' } })));
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={['/']}><App /></MemoryRouter></QueryClientProvider>);
    expect(await screen.findByRole('alert')).toHaveTextContent('Storage unavailable');
    expect(screen.getByRole('button', { name: '다시 시도' })).toBeInTheDocument();
  });

  it('submits every required Controller analysis field', async () => {
    vi.stubGlobal('crypto', {});
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path === '/api/v1/analysis-jobs' && init?.method === 'POST') {
        return new Response(JSON.stringify({ id: 'job-new', name: 'Web analysis', status: 'CREATED' }), { status: 201 });
      }
      return new Response(JSON.stringify(responses[path]), { status: responses[path] ? 200 : 404 });
    });
    renderAt('/analyses/new');
    vi.stubGlobal('fetch', fetchMock);
    const user = userEvent.setup();
    await screen.findByLabelText('Sensor A');
    await user.type(screen.getByLabelText('Analysis name'), 'Web analysis');
    await user.click(screen.getByLabelText('Sensor A'));
    await user.click(screen.getByRole('button', { name: '대형 서비스 노이즈 줄이기' }));
    await user.click(screen.getByRole('button', { name: 'Start analysis' }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/v1/analysis-jobs', expect.objectContaining({ method: 'POST' })));
    const call = fetchMock.mock.calls.find(([url, init]) => url === '/api/v1/analysis-jobs' && init?.method === 'POST');
    const body = JSON.parse(String(call?.[1]?.body));
    expect(body).toEqual(expect.objectContaining({
      name: 'Web analysis', sensor_ids: ['sensor-a'], mode: 'LIVE', internal_networks: ['10.0.0.0/8'],
      idempotency_key: expect.any(String), start_time: expect.any(String), end_time: expect.any(String),
      analysis: expect.objectContaining({
        minimum_candidate_score: 50,
        minimum_distinct_clients: 3,
        detector_weights: expect.objectContaining({
          common_destination: 0.25,
          protocol_similarity: 0.5,
          analyst_payload_signature: 1,
        }),
      }),
    }));
    expect(new Date(body.end_time).getTime()).toBeGreaterThan(new Date(body.start_time).getTime());
  });

  it('uses the server default when analysis starts before presets load', async () => {
    const pendingPresets = new Promise<Response>(() => undefined);
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path === '/api/v1/detector-weight-presets') return pendingPresets;
      if (path === '/api/v1/analysis-jobs' && init?.method === 'POST') {
        return new Response(JSON.stringify({ error: { message: 'stop after request capture' } }), { status: 503 });
      }
      return new Response(JSON.stringify(responses[path] ?? { items: [] }), { status: 200 });
    });
    localStorage.setItem('c2hunter-token', 'token');
    vi.stubGlobal('fetch', fetchMock);
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={['/analyses/new']}><App /></MemoryRouter></QueryClientProvider>);
    const user = userEvent.setup();

    await screen.findByLabelText('Sensor A');
    await user.type(screen.getByLabelText('Analysis name'), 'Server default');
    await user.click(screen.getByLabelText('Sensor A'));
    await user.click(screen.getByRole('button', { name: 'Start analysis' }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/v1/analysis-jobs', expect.objectContaining({ method: 'POST' })));
    const call = fetchMock.mock.calls.find(([url, init]) => url === '/api/v1/analysis-jobs' && init?.method === 'POST');
    const body = JSON.parse(String(call?.[1]?.body));
    expect(body.analysis).not.toHaveProperty('detector_weights');
  });

  it('loads, reuses, and saves detector weight presets as defaults', async () => {
    const presetWeights = { common_destination: 0.25, periodic_beacon: 1.5 };
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path === '/api/v1/detector-weight-presets' && init?.method === 'POST') {
        return new Response(JSON.stringify({ id: 'preset-new', name: 'Case preset', detector_weights: presetWeights, is_default: true }), { status: 201 });
      }
      if (path === '/api/v1/detector-weight-presets') {
        return new Response(JSON.stringify({ items: [{ id: 'preset-default', name: 'Quiet shared services', detector_weights: presetWeights, is_default: true }] }), { status: 200 });
      }
      return new Response(JSON.stringify(responses[path] ?? { items: [] }), { status: 200 });
    });
    localStorage.setItem('c2hunter-token', 'token');
    vi.stubGlobal('fetch', fetchMock);
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={['/analyses/new']}><App /></MemoryRouter></QueryClientProvider>);
    const user = userEvent.setup();

    await waitFor(() => expect(screen.getByLabelText(/공통 목적지/)).toHaveValue(0.25));
    expect(screen.getByLabelText('저장된 탐지 가중치 프리셋')).toHaveValue('preset-default');
    await user.type(screen.getByLabelText('새 프리셋 이름'), 'Case preset');
    await user.click(screen.getByLabelText('기본 프리셋으로 저장'));
    await user.click(screen.getByRole('button', { name: '현재 가중치 저장' }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/v1/detector-weight-presets', expect.objectContaining({ method: 'POST' })));
    const call = fetchMock.mock.calls.find(([url, init]) => url === '/api/v1/detector-weight-presets' && init?.method === 'POST');
    expect(JSON.parse(String(call?.[1]?.body))).toEqual(expect.objectContaining({
      name: 'Case preset',
      set_as_default: true,
      detector_weights: expect.objectContaining({ common_destination: 0.25, periodic_beacon: 1.5 }),
    }));
  });

  it('uses the candidate job id and required bodies for candidate actions', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (init?.method === 'POST') return new Response(JSON.stringify({ id: 'created', status: 'CREATED' }), { status: 201 });
      return new Response(JSON.stringify(responses[path]), { status: responses[path] ? 200 : 404 });
    });
    renderAt('/candidates/candidate-1');
    vi.stubGlobal('fetch', fetchMock);
    const user = userEvent.setup();
    await screen.findByRole('heading', { name: '203.0.113.9' });
    await user.click(screen.getByRole('button', { name: 'Export candidate PCAP' }));
    await user.click(screen.getByRole('button', { name: 'Reanalyze' }));

    expect(screen.getByRole('heading', { name: '탐지 근거' })).toBeInTheDocument();
    expect(screen.getByText('주기적 비콘')).toBeInTheDocument();
    expect(screen.getByText('주기 통신 탐지기 · v1.0.0')).toBeInTheDocument();
    expect(screen.getByText('표본 수')).toBeInTheDocument();
    expect(screen.getByRole('table', { name: 'Candidate traffic buckets' })).toBeInTheDocument();

    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/v1/analysis-jobs/job-1/reanalyze', expect.objectContaining({ method: 'POST' })));
    const exportCall = fetchMock.mock.calls.find(([url]) => url === '/api/v1/pcap-exports');
    expect(JSON.parse(String(exportCall?.[1]?.body))).toEqual({ job_id: 'job-1', candidate_id: 'candidate-1' });
    const reanalyzeCall = fetchMock.mock.calls.find(([url]) => url === '/api/v1/analysis-jobs/job-1/reanalyze');
    expect(JSON.parse(String(reanalyzeCall?.[1]?.body))).toEqual({ idempotency_key: expect.any(String) });
  });

  it('records verdicts, looks up TI, and exports confirmed candidates to MISP', async () => {
    const original = responses['/api/v1/candidates/candidate-1'] as Record<string, unknown>;
    let candidate = { ...original };
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path === '/api/v1/candidates/candidate-1/verdicts' && init?.method === 'POST') {
        const verdict = { verdict: 'CONFIRMED_C2', confidence: 'HIGH', note: 'Beacon verified', created_by: 'analyst', created_at: '2026-07-20T11:00:00Z' };
        candidate = { ...candidate, current_verdict: verdict, verdict_history: [verdict] };
        return new Response(JSON.stringify(candidate), { status: 201 });
      }
      if (path === '/api/v1/candidates/candidate-1/threat-intelligence/lookups' && init?.method === 'POST') {
        const threatIntelligence = { fetched_at: '2026-07-20T11:01:00Z', summary: { malicious: 8, suspicious: 2, harmless: 12, abuse_confidence_score: 91 }, providers: { virustotal: { status: 'OK', malicious: 8, suspicious: 2, harmless: 12, reputation: -20 }, abuseipdb: { status: 'OK', abuse_confidence_score: 91, total_reports: 13, country_code: 'US', isp: 'Example ISP' } } };
        candidate = { ...candidate, threat_intelligence: threatIntelligence };
        return new Response(JSON.stringify(threatIntelligence), { status: 200 });
      }
      if (path === '/api/v1/candidates/candidate-1/misp-exports' && init?.method === 'POST') {
        const result = { status: 'EXPORTED', event_id: '42', attribute_id: '9001', created_at: '2026-07-20T11:02:00Z' };
        candidate = { ...candidate, misp_exports: [result] };
        return new Response(JSON.stringify(result), { status: 201 });
      }
      if (path === '/api/v1/candidates/candidate-1') return new Response(JSON.stringify(candidate), { status: 200 });
      return new Response(JSON.stringify(responses[path]), { status: responses[path] ? 200 : 404 });
    });
    renderAt('/candidates/candidate-1', fetchMock);
    const user = userEvent.setup();

    expect(await screen.findByRole('heading', { name: '판정 및 외부 검증' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'MISP로 전송' })).toBeDisabled();
    await user.selectOptions(screen.getByLabelText('Candidate verdict'), 'CONFIRMED_C2');
    await user.selectOptions(screen.getByLabelText('Verdict confidence'), 'HIGH');
    await user.type(screen.getByLabelText('Verdict note'), 'Beacon verified');
    await user.click(screen.getByRole('button', { name: '판정 저장' }));
    await waitFor(() => expect(screen.getByText('확정 C2')).toBeInTheDocument());

    await user.click(screen.getByRole('button', { name: '외부 TI 조회' }));
    expect(await screen.findByText('악성 8')).toBeInTheDocument();
    expect(screen.getByText('Abuse 신뢰도 91%')).toBeInTheDocument();

    await user.type(screen.getByLabelText('MISP event ID'), '42');
    await user.click(screen.getByRole('button', { name: 'MISP로 전송' }));
    expect(await screen.findByText(/Event 42/)).toBeInTheDocument();

    const verdictCall = fetchMock.mock.calls.find(([url]) => url === '/api/v1/candidates/candidate-1/verdicts');
    expect(JSON.parse(String(verdictCall?.[1]?.body))).toEqual({ verdict: 'CONFIRMED_C2', confidence: 'HIGH', note: 'Beacon verified' });
    const mispCall = fetchMock.mock.calls.find(([url]) => url === '/api/v1/candidates/candidate-1/misp-exports');
    expect(JSON.parse(String(mispCall?.[1]?.body))).toEqual({ event_id: '42' });
  });

  it('requires confirmation before permanently deleting a candidate', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path === '/api/v1/candidates/candidate-1' && init?.method === 'DELETE') return new Response(null, { status: 204 });
      return new Response(JSON.stringify(responses[path]), { status: responses[path] ? 200 : 404 });
    });
    renderAt('/candidates/candidate-1');
    vi.stubGlobal('fetch', fetchMock);
    const user = userEvent.setup();
    await screen.findByRole('heading', { name: '203.0.113.9' });

    await user.click(screen.getByRole('button', { name: 'Delete candidate' }));
    expect(screen.getByRole('dialog', { name: 'Delete candidate permanently' })).toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalledWith('/api/v1/candidates/candidate-1', expect.objectContaining({ method: 'DELETE' }));
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('dialog', { name: 'Delete candidate permanently' })).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Delete candidate' }));
    await user.click(screen.getByRole('button', { name: 'Delete permanently' }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/v1/candidates/candidate-1', expect.objectContaining({ method: 'DELETE' })));
  });

  it('summarizes long detector metrics and reveals structured details on demand', async () => {
    const original = responses['/api/v1/candidates/candidate-1'] as Record<string, unknown>;
    responses['/api/v1/candidates/candidate-1'] = {
      ...original,
      evidence: [{
        type: 'PERIODIC_BEACON',
        detector: 'periodic_beacon',
        contribution: 15,
        description: 'Nested metric fixture',
        metrics: {
          sample_count: 7,
          period_seconds: 30,
          jitter_ratio: 0.12,
          confidence_score: 0.91,
          timing_window: { minimum_seconds: 25, maximum_seconds: 35 },
          phases: ['warmup', 'steady_state', 'confirmation', 'retained'],
        },
      }],
    };

    try {
      renderAt('/candidates/candidate-1');
      await screen.findByRole('heading', { name: '탐지 근거' });
      expect(screen.getByTitle('sample_count')).toBeVisible();
      const disclosureLabel = screen.getByText('상세 지표 2개 더 보기');
      const disclosure = disclosureLabel.closest('details');
      expect(disclosure).not.toHaveAttribute('open');
      expect(screen.getByText('Timing Window')).not.toBeVisible();

      await userEvent.click(disclosureLabel);
      expect(disclosure).toHaveAttribute('open');
      expect(screen.getByText('Timing Window')).toBeVisible();
      expect(screen.getByText('Minimum Seconds')).toBeInTheDocument();
      expect(screen.getByText('25초')).toBeInTheDocument();
      expect(screen.getByText('Warmup')).toBeInTheDocument();
      expect(document.body).not.toHaveTextContent('{"minimum_seconds":25');
    } finally {
      responses['/api/v1/candidates/candidate-1'] = original;
    }
  });

  it('renders score adjustments safely when the Controller returns a non-string kind', async () => {
    const original = responses['/api/v1/candidates/candidate-1'] as Record<string, unknown>;
    responses['/api/v1/candidates/candidate-1'] = {
      ...original,
      adjustments: [{ kind: 7, points: -5, explanation: 'Imported adjustment' }],
    };

    try {
      renderAt('/candidates/candidate-1');
      expect(await screen.findByText('점수 조정 · Imported adjustment')).toBeInTheDocument();
    } finally {
      responses['/api/v1/candidates/candidate-1'] = original;
    }
  });

  it('previews a candidate flow and creates an analyst-guided C2 signature', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path === '/api/v1/analysis-jobs/job-1/flow-labels' && init?.method === 'POST') {
        return new Response(JSON.stringify({
          label: { id: 'label-new', verdict: 'C2', confidence: 'HIGH', note: 'Confirmed from malware trace', created_at: '2026-07-20T10:07:00Z' },
          signature: { ...(responses['/api/v1/payload-signatures?page_size=200'] as { items: unknown[] }).items[0] as object },
        }), { status: 201, headers: { 'content-type': 'application/json' } });
      }
      if (path === '/api/v1/analysis-jobs/job-1/flows/0123456789abcdef01234567/detection-guidance') {
        return new Response(JSON.stringify({
          flow_id: '0123456789abcdef01234567',
          candidate_ip: '203.0.113.9',
          initially_detected: false,
          suppressed_by_policy: false,
          current_score: 5,
          minimum_candidate_score: 20,
          score_gap: 15,
          conditions: [{ evidence_type: 'PERIODIC_BEACON', detector: 'periodic_beacon', contribution: 15, weighted_contribution: 15, description: '허용 jitter 범위 내 주기 통신', metrics: { sample_count: 5 } }],
          adjustments: [{ kind: 'SINGLE_HOST', points: -10, explanation: '단일 호스트 관측 감점' }],
          recommendations: [{ id: 'weight-periodic_beacon-2.00', kind: 'DETECTOR_WEIGHT', detector: 'periodic_beacon', current_value: 1, recommended_value: 2, projected_score: 20, score_gain: 15, rationale: '주기 통신 탐지기 가중치를 2로 조정하면 후보 임계점에 도달합니다.', risk: 'MEDIUM', risk_note: '같은 탐지 조건을 만족하는 정상 통신 점수도 함께 증가합니다.', reanalysis: { minimum_candidate_score: 20, detector_weights: { periodic_beacon: 2 } } }],
          recommended_reanalysis: { minimum_candidate_score: 20, detector_weights: { periodic_beacon: 2 } },
          warnings: ['추천값은 동일 데이터셋의 점수 변화만 계산하며 별도 데이터의 오탐률을 예측하지 않습니다.'],
        }), { status: 200, headers: { 'content-type': 'application/json' } });
      }
      if (path === '/api/v1/analysis-jobs/job-1/reanalyze' && init?.method === 'POST') {
        return new Response(JSON.stringify({ id: 'job-guided', name: 'Guided reanalysis', status: 'COMPLETED' }), { status: 201, headers: { 'content-type': 'application/json' } });
      }
      return new Response(JSON.stringify(responses[path]), { status: responses[path] ? 200 : 404, headers: { 'content-type': 'application/json' } });
    });
    renderAt('/candidates/candidate-1');
    vi.stubGlobal('fetch', fetchMock);
    const user = userEvent.setup();

    expect(await screen.findByRole('table', { name: 'Candidate flows' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Preview payload 0123456789abcdef01234567' }));
    expect(await screen.findByText('beacon')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Mark C2 0123456789abcdef01234567' }));
    await user.type(screen.getByLabelText('Analyst note'), 'Confirmed from malware trace');
    await user.click(screen.getByRole('button', { name: 'Save C2 label' }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/v1/analysis-jobs/job-1/flow-labels', expect.objectContaining({ method: 'POST' })));
    const call = fetchMock.mock.calls.find(([url, init]) => url === '/api/v1/analysis-jobs/job-1/flow-labels' && init?.method === 'POST');
    expect(JSON.parse(String(call?.[1]?.body))).toEqual({
      flow_id: '0123456789abcdef01234567',
      verdict: 'C2',
      confidence: 'HIGH',
      note: 'Confirmed from malware trace',
      create_signature: true,
      signature_name: 'TCP 203.0.113.9 payload',
      signature_description: 'Confirmed from malware trace',
    });
    const guideHeading = await screen.findByRole('heading', { name: '탐지 조정 가이드' });
    const guide = guideHeading.closest('section');
    expect(guide).not.toBeNull();
    expect(within(guide as HTMLElement).getByText('주기적 비콘')).toBeInTheDocument();
    expect(within(guide as HTMLElement).getByText('현재 5점 · 후보 기준 20점 · 15점 부족')).toBeInTheDocument();
    expect(within(guide as HTMLElement).getByText('주기 통신 탐지기 가중치를 2로 조정하면 후보 임계점에 도달합니다.')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: '추천 설정으로 재분석' }));
    const reanalysisCall = await waitFor(() => {
      const found = fetchMock.mock.calls.find(([url, init]) => url === '/api/v1/analysis-jobs/job-1/reanalyze' && init?.method === 'POST' && String(init.body).includes('periodic_beacon'));
      expect(found).toBeDefined();
      return found;
    });
    expect(JSON.parse(String(reanalysisCall?.[1]?.body))).toEqual({
      idempotency_key: expect.any(String),
      minimum_candidate_score: 20,
      detector_weights: { periodic_beacon: 2 },
    });
  });

  it('lists and disables a versioned payload signature', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path === '/api/v1/payload-signatures/signature-1' && init?.method === 'PATCH') {
        const signature = (responses['/api/v1/payload-signatures?page_size=200'] as { items: Record<string, unknown>[] }).items[0];
        return new Response(JSON.stringify({ ...signature, enabled: false, version: 2 }), { status: 200, headers: { 'content-type': 'application/json' } });
      }
      return new Response(JSON.stringify(responses[path]), { status: responses[path] ? 200 : 404, headers: { 'content-type': 'application/json' } });
    });
    renderAt('/payload-signatures');
    vi.stubGlobal('fetch', fetchMock);

    expect(await screen.findByRole('table', { name: 'Payload signatures' })).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Disable TCP beacon payload' }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/v1/payload-signatures/signature-1', expect.objectContaining({ method: 'PATCH' })));
    const call = fetchMock.mock.calls.find(([url, init]) => url === '/api/v1/payload-signatures/signature-1' && init?.method === 'PATCH');
    expect(JSON.parse(String(call?.[1]?.body))).toEqual({ enabled: false });
  });

  it('registers a trusted DNS policy without sending a blank expiration', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path === '/api/v1/allowlist' && init?.method === 'POST') {
        return new Response(JSON.stringify({ id: 'allow-1' }), { status: 201, headers: { 'content-type': 'application/json' } });
      }
      return new Response(JSON.stringify(responses[path]), { status: responses[path] ? 200 : 404, headers: { 'content-type': 'application/json' } });
    });
    renderAt('/allowlist');
    vi.stubGlobal('fetch', fetchMock);
    const user = userEvent.setup();

    expect(await screen.findByText(/Trusted DNS\/NTP policies reduce score only/)).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText('Type'), 'TRUSTED_DNS');
    await user.type(screen.getByLabelText('Value'), '1.1.1.1');
    await user.type(screen.getByLabelText('Description'), 'Corporate resolver');
    await user.click(screen.getByRole('button', { name: 'Add entry' }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/v1/allowlist', expect.objectContaining({ method: 'POST' })));
    const call = fetchMock.mock.calls.find(([url, init]) => url === '/api/v1/allowlist' && init?.method === 'POST');
    expect(JSON.parse(String(call?.[1]?.body))).toEqual({
      type: 'TRUSTED_DNS',
      value: '1.1.1.1',
      description: 'Corporate resolver',
      enabled: true,
    });
  });

  it('sends the Controller cancel request body', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (init?.method === 'POST') return new Response(JSON.stringify({ status: 'CANCELLED' }), { status: 200 });
      return new Response(JSON.stringify(responses[path]), { status: responses[path] ? 200 : 404 });
    });
    renderAt('/analyses/job-1');
    vi.stubGlobal('fetch', fetchMock);
    await screen.findByRole('heading', { name: 'Investigation' });
    await userEvent.click(screen.getByRole('button', { name: 'Cancel analysis' }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/v1/analysis-jobs/job-1/cancel', expect.objectContaining({ method: 'POST' })));
    const call = fetchMock.mock.calls.find(([url]) => url === '/api/v1/analysis-jobs/job-1/cancel');
    expect(JSON.parse(String(call?.[1]?.body))).toEqual({ reason: 'operator requested from web console' });
  });

  it('lists analysis history and sends metadata updates and confirmed deletion', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path.startsWith('/api/v1/analysis-jobs?')) return new Response(JSON.stringify(responses['/api/v1/analysis-jobs']), { status: 200 });
      if (path === '/api/v1/analysis-jobs/job-1' && init?.method === 'PATCH') return new Response(JSON.stringify({ id: 'job-1', name: 'Renamed investigation', status: 'COMPLETED' }), { status: 200 });
      if (path === '/api/v1/analysis-jobs/job-1' && init?.method === 'DELETE') return new Response(null, { status: 204 });
      return new Response(JSON.stringify(responses[path]), { status: responses[path] ? 200 : 404 });
    });
    localStorage.setItem('c2hunter-token', 'token');
    vi.stubGlobal('fetch', fetchMock);
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={['/analyses']}><App /></MemoryRouter></QueryClientProvider>);
    const user = userEvent.setup();

    expect(await screen.findByRole('table', { name: 'Analysis history' })).toBeInTheDocument();
    expect(screen.getByText('capture.pcap · 2.0 KiB')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Edit Investigation' }));
    await user.clear(screen.getByLabelText('Analysis name'));
    await user.type(screen.getByLabelText('Analysis name'), 'Renamed investigation');
    await user.clear(screen.getByLabelText('Analyst note'));
    await user.type(screen.getByLabelText('Analyst note'), 'Reviewed evidence');
    await user.click(screen.getByRole('button', { name: 'Save changes' }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/v1/analysis-jobs/job-1', expect.objectContaining({ method: 'PATCH' })));
    const patchCall = fetchMock.mock.calls.find(([url, init]) => url === '/api/v1/analysis-jobs/job-1' && init?.method === 'PATCH');
    expect(JSON.parse(String(patchCall?.[1]?.body))).toEqual({ name: 'Renamed investigation', description: 'Reviewed evidence' });

    await user.click(screen.getByRole('button', { name: 'Delete Investigation' }));
    expect(screen.getByRole('dialog', { name: 'Delete analysis' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Delete permanently' }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/v1/analysis-jobs/job-1', expect.objectContaining({ method: 'DELETE' })));
  });

  it('accepts a PCAP at the 500 MiB boundary and sends it as the binary request body', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path.startsWith('/api/v1/pcap-analysis-jobs?') && init?.method === 'POST') return new Response(JSON.stringify({ id: 'upload-job', name: 'Offline case', status: 'COMPLETED' }), { status: 201 });
      if (path === '/api/v1/analysis-jobs/upload-job') return new Response(JSON.stringify({ id: 'upload-job', name: 'Offline case', status: 'COMPLETED' }), { status: 200 });
      return new Response(JSON.stringify({ error: { message: 'missing fixture' } }), { status: 404 });
    });
    localStorage.setItem('c2hunter-token', 'token');
    vi.stubGlobal('fetch', fetchMock);
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={['/analyses/upload']}><App /></MemoryRouter></QueryClientProvider>);
    const user = userEvent.setup();
    const file = new File([new Uint8Array([0xd4, 0xc3, 0xb2, 0xa1])], 'sample.pcap', { type: 'application/vnd.tcpdump.pcap' });
    Object.defineProperty(file, 'size', { value: 500 * 1024 * 1024 });
    await user.type(screen.getByLabelText('Analysis name'), 'Offline case');
    await user.upload(screen.getByLabelText('Capture file'), file);
    await user.click(screen.getByRole('button', { name: '대형 서비스 노이즈 줄이기' }));
    expect(screen.getByRole('status')).toHaveTextContent('500.0 MiB');
    fireEvent.submit(screen.getByRole('button', { name: 'Upload and analyze' }).closest('form')!);

    await waitFor(() => expect(fetchMock.mock.calls.some(([url, init]) => String(url).startsWith('/api/v1/pcap-analysis-jobs?') && init?.method === 'POST')).toBe(true));
    const uploadCall = fetchMock.mock.calls.find(([url]) => String(url).startsWith('/api/v1/pcap-analysis-jobs?'));
    const url = new URL(String(uploadCall?.[0]), 'http://localhost');
    expect(url.searchParams.get('name')).toBe('Offline case');
    expect(url.searchParams.get('filename')).toBe('sample.pcap');
    expect(JSON.parse(String(url.searchParams.get('detector_weights')))).toEqual(expect.objectContaining({
      common_destination: 0.25,
      protocol_similarity: 0.5,
      analyst_payload_signature: 1,
    }));
    expect(uploadCall?.[1]?.body).toBe(file);
    expect(uploadCall?.[1]?.headers).toEqual(expect.objectContaining({ 'content-type': 'application/vnd.tcpdump.pcap' }));
  });

  it('uses the server default for PCAP upload when weights are untouched', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path.startsWith('/api/v1/pcap-analysis-jobs?') && init?.method === 'POST') {
        return new Response(JSON.stringify({ id: 'upload-job', status: 'CREATED' }), { status: 201 });
      }
      return new Response(JSON.stringify({ items: [] }), { status: 200 });
    });
    localStorage.setItem('c2hunter-token', 'token');
    vi.stubGlobal('fetch', fetchMock);
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={['/analyses/upload']}><App /></MemoryRouter></QueryClientProvider>);
    const user = userEvent.setup();
    const file = new File([new Uint8Array([0xd4, 0xc3, 0xb2, 0xa1])], 'sample.pcap', { type: 'application/vnd.tcpdump.pcap' });

    await user.type(screen.getByLabelText('Analysis name'), 'Server default PCAP');
    await user.upload(screen.getByLabelText('Capture file'), file);
    fireEvent.submit(screen.getByRole('button', { name: 'Upload and analyze' }).closest('form')!);

    await waitFor(() => expect(fetchMock.mock.calls.some(([url, init]) => String(url).startsWith('/api/v1/pcap-analysis-jobs?') && init?.method === 'POST')).toBe(true));
    const uploadCall = fetchMock.mock.calls.find(([url]) => String(url).startsWith('/api/v1/pcap-analysis-jobs?'));
    const url = new URL(String(uploadCall?.[0]), 'http://localhost');
    expect(url.searchParams.has('detector_weights')).toBe(false);
  });

  it('rejects a PCAP larger than 500 MiB before upload', async () => {
    const fetchMock = vi.fn();
    localStorage.setItem('c2hunter-token', 'token');
    vi.stubGlobal('fetch', fetchMock);
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={['/analyses/upload']}><App /></MemoryRouter></QueryClientProvider>);
    const file = new File([new Uint8Array([0xd4, 0xc3, 0xb2, 0xa1])], 'too-large.pcap', { type: 'application/vnd.tcpdump.pcap' });
    Object.defineProperty(file, 'size', { value: 500 * 1024 * 1024 + 1 });

    await userEvent.upload(screen.getByLabelText('Capture file'), file);

    expect(screen.getByRole('alert')).toHaveTextContent('PCAP files must be 500 MiB or smaller.');
    expect(fetchMock.mock.calls.some(([url, init]) => String(url).startsWith('/api/v1/pcap-analysis-jobs?') && init?.method === 'POST')).toBe(false);
  });
});
