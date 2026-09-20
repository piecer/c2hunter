import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import App from '../src/App';
import DDoSAttackPanel, { type DDoSAttackReport } from '../src/DDoSAttackPanel';

const python = process.env.C2HUNTER_TEST_PYTHON ?? (existsSync('../.venv/bin/python') ? resolve('../.venv/bin/python') : 'python3');
const produce = () => execFileSync(python, ['tests/ddos_report_fixture.py'], { encoding: 'utf8' });
const report = JSON.parse(produce()) as DDoSAttackReport;
const contractBytes = readFileSync('tests/fixtures/ddos-report-contract.json', 'utf8');
const scenarioBytes = readFileSync('tests/fixtures/ddos-report-scenarios.json', 'utf8');
const produceScenarios = () => execFileSync(python, ['tests/ddos_report_scenarios.py'], { encoding: 'utf8' });
const scenarios = JSON.parse(scenarioBytes) as Record<string, DDoSAttackReport>;
const identityMetricKeys = [
  'hop_limit_min', 'hop_limit_max', 'network_identity_observed_records',
  'network_identity_anomaly_records', 'ip_id_observed_count', 'ip_id_distinct_count',
  'ip_id_monotonic_ratio', 'network_identity_values_truncated',
];
const asV1 = (source: DDoSAttackReport): DDoSAttackReport => {
  const legacy = structuredClone(source);
  legacy.version = 'ddos-attack-report-v1';
  legacy.catalog_version = 'ddos-taxonomy-v1';
  for (const finding of legacy.findings) {
    delete finding.classification;
    delete finding.common_patterns;
    delete finding.signature_candidates;
    for (const key of identityMetricKeys) delete finding.metrics[key];
  }
  return legacy;
};

it('freezes deterministic bytes from the real DDoS producer', () => {
  expect(produce()).toBe(contractBytes);
  expect(produce()).toBe(contractBytes);
  expect(report.version).toBe('ddos-attack-report-v2');
});

it('round-trips every attack family role and coverage outcome through the strict UI parser', () => {
  expect(produceScenarios()).toBe(scenarioBytes);
  const expected = {
    tcp_syn_inbound: 'TCP_SYN_FLOOD', tcp_ack_inbound: 'TCP_ACK_FLOOD',
    tcp_rst_inbound: 'TCP_RST_FLOOD', udp_outbound_participant: 'UDP_FLOOD',
    possible_reflection: 'POSSIBLE_REFLECTION_AMPLIFICATION', icmp_echo: 'ICMP_ECHO_FLOOD',
    icmp_generic: 'ICMP_FLOOD', multi_vector: 'MULTI_VECTOR',
  } as const;
  for (const [name, attackType] of Object.entries(expected)) {
    expect(scenarios[name].findings.some(item => item.attack_type === attackType)).toBe(true);
  }
  expect(scenarios.udp_outbound_participant.findings[0].attack_role).toBe('PARTICIPANT_SIDE_OUTBOUND');
  expect(scenarios.no_clear_attack.verdict).toBe('no_clear_attack');
  expect(scenarios.insufficient_evidence.verdict).toBe('insufficient_evidence');
  for (const [name, scenario] of Object.entries(scenarios)) {
    const { unmount } = render(<DDoSAttackPanel report={scenario}/>);
    expect(screen.queryByRole('alert'), name).not.toBeInTheDocument();
    unmount();
  }
});

it('accepts a producer-valid mixed-authenticity multi-vector classification', () => {
  const mixed = structuredClone(scenarios.multi_vector);
  const finding = mixed.findings.find(item => item.attack_type === 'MULTI_VECTOR')!;
  finding.classification!.source_authenticity = 'MIXED';
  finding.classification!.confidence = 'medium';
  finding.uncertainty_codes.push('SOURCE_SPOOFING_NOT_CONFIRMED');

  render(<DDoSAttackPanel report={mixed}/>);
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

it('keeps accepting stored v1 reports without v2-only fields', () => {
  render(<DDoSAttackPanel report={asV1(report)}/>);
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  expect(screen.getAllByText('TCP SYN 플러드')).toHaveLength(2);
});

it('renders v2 delivery source authenticity patterns and review-only signatures', () => {
  render(<DDoSAttackPanel report={scenarios.possible_reflection}/>);
  const glance = screen.getByRole('region', { name: 'DDoS 한눈에 보기' });
  expect(within(glance).getByText(/반사·증폭 전달/)).toBeVisible();
  expect(within(glance).getByText(/reflector 집합/)).toBeVisible();
  expect(within(glance).getByText(/Spoofing 미확인/)).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: /상세 근거 보기/ }));
  const evidence = screen.getByRole('region', { name: 'DDoS 발견 근거' });
  expect(within(evidence).getByText('공통 패턴')).toBeVisible();
  expect(within(evidence).getByText(/반사 서비스 집중 패턴/)).toBeVisible();
  expect(within(evidence).getByText('시그니처 후보')).toBeVisible();
  expect(within(evidence).getByText(/반사 프로파일 후보/)).toBeVisible();
  expect(within(evidence).getByText(/후보일 뿐이며 적용 전 검토와 운영자 승인이 필요/)).toBeVisible();
  expect(within(evidence).getByText(/source spoofing은 확인되지 않았습니다/)).toBeVisible();
});

it('fails closed on malformed or attribution-overclaiming v2 fields', () => {
  const mutations: Array<(value: DDoSAttackReport) => void> = [
    value => { value.findings[0].classification!.source_authenticity = 'SPOOFING_CONFIRMED'; },
    value => { value.findings[0].classification!.source_population = 'BOTNET_CONFIRMED'; },
    value => { value.findings[0].classification!.delivery_mechanism = 'REFLECTION_AMPLIFICATION'; },
    value => { value.findings[0].classification!.source_population = 'REFLECTOR_SET'; },
    value => { value.findings[0].classification!.source_authenticity = 'SOURCE_CONSISTENT'; },
    value => { value.findings[0].common_patterns![0].type = 'RAW_PATTERN'; },
    value => { value.findings[0].signature_candidates![0].kind = 'AUTO_BLOCK_RULE'; },
    value => { value.findings[0].signature_candidates![0].requires_human_approval = false; },
    value => { value.findings[0].signature_candidates![0].false_positive_codes = []; },
  ];
  for (const mutate of mutations) {
    const poisoned = structuredClone(report);
    mutate(poisoned);
    const { unmount } = render(<DDoSAttackPanel report={poisoned}/>);
    expect(screen.getByRole('alert')).toHaveTextContent('지원되지 않는 DDoS 보고서');
    expect(document.body).not.toHaveTextContent('CONFIRMED');
    expect(document.body).not.toHaveTextContent('AUTO_BLOCK_RULE');
    unmount();
  }
});

it('keeps a qualified likely finding when a sparse nonfinding target adds a sample warning', () => {
  const value = structuredClone(report);
  value.warnings = ['SAMPLE_WINDOW_SHORT'];
  Object.assign(value.findings[0].metrics, { baseline_packets_per_second: 1, baseline_ratio: 5, robust_z_score: null, response_ratio: 0 });
  value.findings[0].uncertainty_codes = [];
  Object.assign(value.findings[0], { likelihood: 'LIKELY', severity: 'HIGH', confidence: 'high' });
  Object.assign(value, { verdict: 'attack_likely', confidence: 'high' });
  render(<DDoSAttackPanel report={value}/>);
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  expect(screen.getAllByText('TCP SYN 플러드')).toHaveLength(2);
});

it('accepts the closed unknown-payload qualifier for legacy ACK aggregates', () => {
  const value = structuredClone(report);
  value.findings[0].uncertainty_codes.push('TCP_PAYLOAD_VISIBILITY_UNKNOWN');
  render(<DDoSAttackPanel report={value}/>);
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

it('shows one DDoS verdict type defensive objective and priority response first in Korean and English', () => {
  render(<DDoSAttackPanel report={report}/>);
  const glance = screen.getByRole('region', { name: 'DDoS 한눈에 보기' });
  expect(within(glance).getByRole('heading', { name: '의심스러운 DDoS 형태 관찰' })).toBeVisible();
  expect(within(glance).getByText('TCP SYN 플러드')).toBeVisible();
  expect(within(glance).getByText(/연결 상태 자원 고갈/)).toBeVisible();
  expect(within(glance).getByText(/SYN 프록시 또는 SYN 쿠키/)).toBeVisible();
  expect(screen.queryByText('AI C2 분석')).not.toBeInTheDocument();

  fireEvent.change(screen.getByRole('combobox', { name: '보고서 언어 / Report language' }), { target: { value: 'en' } });
  expect(screen.getByRole('heading', { name: 'Suspicious DDoS-shaped traffic observed' })).toBeVisible();
  const englishGlance = screen.getByRole('region', { name: 'DDoS at a glance' });
  expect(within(englishGlance).getByText('TCP SYN flood')).toBeVisible();
  expect(within(englishGlance).getByText(/connection-state resource exhaustion/i)).toBeVisible();
});

it('lazily exposes facts uncertainty and coverage while keeping all actions human-approved', () => {
  const { container } = render(<DDoSAttackPanel report={report}/>);
  expect(screen.queryByRole('region', { name: 'DDoS 발견 근거' })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: /상세 근거 보기/ }));
  const evidence = screen.getByRole('region', { name: 'DDoS 발견 근거' });
  expect(within(evidence).getByText(/1,200/)).toBeVisible();
  expect(within(evidence).getAllByText(/기준선/).length).toBeGreaterThan(0);
  expect(within(evidence).getAllByText(/운영자 승인 필요/).length).toBeGreaterThan(3);
  expect(within(evidence).getAllByText(/로컬 적용 범위/).length).toBeGreaterThan(0);
  expect(within(evidence).getAllByText(/rollback|검증|확인/).length).toBeGreaterThan(0);
  fireEvent.click(screen.getByRole('button', { name: /분석 범위와 한계/ }));
  expect(screen.getByRole('region', { name: 'DDoS 분석 범위' })).toBeVisible();
  expect(screen.queryByRole('region', { name: 'DDoS 발견 근거' })).not.toBeInTheDocument();
  expect(container.querySelectorAll('*').length).toBeLessThan(500);
});

it('fails closed on unknown attack and recommendation codes without reflecting them', () => {
  const poisoned = structuredClone(report);
  poisoned.findings[0].attack_type = 'RAW_POISON';
  poisoned.recommendations[0].code = 'ACTION_POISON';
  render(<DDoSAttackPanel report={poisoned}/>);
  expect(screen.getByRole('alert')).toHaveTextContent('지원되지 않는 DDoS 보고서');
  expect(document.body).not.toHaveTextContent('RAW_POISON');
  expect(document.body).not.toHaveTextContent('ACTION_POISON');
});

it.each([1, null, true, {}, []].map(code => ({ code })))('rejects non-string evidence codes without throwing: $code', ({ code }) => {
  const value = structuredClone(report);
  value.findings[0].evidence_codes = [code] as string[];
  render(<DDoSAttackPanel report={value}/>);
  expect(screen.getByRole('alert')).toHaveTextContent('지원되지 않는 DDoS 보고서');
});

it('atomically rejects malformed arrays, closed fields, and broken action relationships', () => {
  for (const mutate of [
    (value: DDoSAttackReport) => { value.findings[0].severity = 'SEVERITY_POISON'; },
    (value: DDoSAttackReport) => { value.findings[0].protocol = 'PROTOCOL_POISON'; },
    (value: DDoSAttackReport) => { value.findings[0].recommendation_codes = ['ACTION_POISON']; },
    (value: DDoSAttackReport) => { value.recommendations = value.recommendations.slice(1); },
    (value: DDoSAttackReport) => { value.warnings = {} as string[]; },
    (value: DDoSAttackReport) => { value.findings[0].metrics = {}; value.findings[0].evidence_codes = []; },
    (value: DDoSAttackReport) => { value.verdict = 'insufficient_evidence'; value.confidence = 'unknown'; },
    (value: DDoSAttackReport) => { value.findings[0].target.ip = '999.999.999.999'; },
    (value: DDoSAttackReport) => { delete (value.findings[0].target as { port?: number | null }).port; },
    (value: DDoSAttackReport) => { value.findings[0].metrics.packet_count = 1.5; },
    (value: DDoSAttackReport) => { value.findings[0].metrics.duration_seconds = 315_537_897_601; },
    (value: DDoSAttackReport) => { value.findings[0].severity = 'LOW'; },
    (value: DDoSAttackReport) => { value.findings[0].severity = 'CRITICAL'; },
    (value: DDoSAttackReport) => { value.findings[0].objective = 'UNKNOWN'; },
    (value: DDoSAttackReport) => { value.findings[0].attack_role = 'UNKNOWN'; },
    (value: DDoSAttackReport) => {
      Object.assign(value.findings[0], { likelihood: 'LIKELY', severity: 'HIGH', confidence: 'high' });
      Object.assign(value, { verdict: 'attack_likely', confidence: 'high' });
    },
    (value: DDoSAttackReport) => { value.findings[0].metrics.packet_count = null; },
    (value: DDoSAttackReport) => { value.findings[0].metrics.measurement_precision = null; },
    (value: DDoSAttackReport) => { value.findings[0].uncertainty_codes = []; },
    (value: DDoSAttackReport) => { value.summary.packet_count = 0; },
    (value: DDoSAttackReport) => { value.summary.target_count = 0; },
    (value: DDoSAttackReport) => { value.findings[0].target.ip = '10.0.0.11'; },
    (value: DDoSAttackReport) => { value.findings[0].evidence_codes.push('VOLUME_GATE_MET'); },
    (value: DDoSAttackReport) => { value.warnings = Array(17).fill('BASELINE_UNAVAILABLE'); },
    (value: DDoSAttackReport) => { value.limitations = []; },
    (value: DDoSAttackReport) => { value.limitations = Array(9).fill(value.limitations[0]); },
  ]) {
    const poisoned = structuredClone(report);
    mutate(poisoned);
    const { unmount } = render(<DDoSAttackPanel report={poisoned}/>);
    expect(screen.getByRole('alert')).toHaveTextContent('지원되지 않는 DDoS 보고서');
    expect(document.body).not.toHaveTextContent('POISON');
    unmount();
  }
});

it('rejects family-derived uncertainty, confidence, and summary mutations', () => {
  const mutations: Array<[string, (value: DDoSAttackReport) => void]> = [
    ['multi_vector', value => { value.findings[0].confidence = 'high'; }],
    ['tcp_ack_inbound', value => { value.findings[0].uncertainty_codes = value.findings[0].uncertainty_codes.filter(code => code !== 'ACK_TRAFFIC_MAY_BE_LEGITIMATE'); }],
    ['tcp_rst_inbound', value => { value.findings[0].uncertainty_codes = value.findings[0].uncertainty_codes.filter(code => code !== 'RESETS_MAY_BE_DEFENSIVE_RESPONSES'); }],
    ['possible_reflection', value => { value.findings[0].uncertainty_codes = value.findings[0].uncertainty_codes.filter(code => code !== 'AMPLIFICATION_RATIO_UNOBSERVED'); }],
    ['multi_vector', value => { value.findings[0].uncertainty_codes = []; }],
    ['tcp_syn_inbound', value => { value.summary.scanned_records = 0; }],
    ['tcp_syn_inbound', value => { value.findings[0].metrics.distinct_sources = 0; }],
  ];
  for (const [scenario, mutate] of mutations) {
    const poisoned = structuredClone(scenarios[scenario]);
    mutate(poisoned);
    const { unmount } = render(<DDoSAttackPanel report={poisoned}/>);
    expect(screen.getByRole('alert')).toHaveTextContent('지원되지 않는 DDoS 보고서');
    unmount();
  }
});

it.each([0, 1, 999])('rejects measured v1 reflection amplification ratio %s', ratio => {
  const value = structuredClone(scenarios.possible_reflection);
  expect(value.findings[0].metrics.amplification_ratio).toBeNull();
  value.findings[0].metrics.amplification_ratio = ratio;
  render(<DDoSAttackPanel report={value}/>);
  expect(screen.getByRole('alert')).toHaveTextContent('지원되지 않는 DDoS 보고서');
});

it('rejects impossible multi-vector component cardinality', () => {
  for (const mutate of [
    (value: DDoSAttackReport) => { value.findings[0].metrics.component_finding_count = 0; },
    (value: DDoSAttackReport) => { value.findings[0].metrics.component_types = []; },
    (value: DDoSAttackReport) => { value.findings[0].metrics.component_types = ['MULTI_VECTOR', 'MULTI_VECTOR']; },
    (value: DDoSAttackReport) => { value.findings[0].metrics.component_types = ['TCP_SYN_FLOOD']; },
  ]) {
    const poisoned = structuredClone(scenarios.multi_vector);
    mutate(poisoned);
    const { unmount } = render(<DDoSAttackPanel report={poisoned}/>);
    expect(screen.getByRole('alert')).toHaveTextContent('지원되지 않는 DDoS 보고서');
    unmount();
  }
});

it('accepts the analyzer maximum multi-vector component count', () => {
  const maximum = structuredClone(scenarios.multi_vector);
  maximum.findings[0].metrics.component_finding_count = 4096;
  render(<DDoSAttackPanel report={maximum}/>);
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

it('preserves finite measured numeric facts without three-digit rounding', () => {
  const precise = structuredClone(report);
  precise.findings[0].metrics.average_packets_per_second = 1.23456789;
  render(<DDoSAttackPanel report={precise}/>);
  fireEvent.click(screen.getByRole('button', { name: /상세 근거 보기/ }));
  expect(screen.getByText('1.23456789')).toBeVisible();
});

it('keeps the maximum report paged under a global DOM ceiling with one evidence owner', () => {
  const maximum = structuredClone(report);
  maximum.findings = Array.from({ length: 100 }, (_, index) => {
    const item = structuredClone(report.findings[0]);
    item.target.ip = `10.0.1.${index + 1}`;
    const identity = `${item.attack_role}|${item.target.ip}|${item.target.port}|${item.protocol}|${item.attack_type}`;
    item.id = `ddos-${createHash('sha256').update(identity).digest('hex').slice(0, 16)}`;
    return item;
  });
  maximum.primary_finding_id = maximum.findings[0].id;
  maximum.summary.target_count = 100;
  maximum.summary.finding_count = 100;
  maximum.summary.displayed_finding_count = 100;
  maximum.summary.packet_count = Number(report.findings[0].metrics.packet_count) * 100;
  maximum.summary.byte_count = Number(report.findings[0].metrics.byte_count) * 100;
  maximum.omitted_finding_count = 0;
  render(<DDoSAttackPanel report={maximum}/>);
  expect(document.querySelectorAll('*').length).toBeLessThan(500);
  fireEvent.click(screen.getAllByRole('button', { name: /상세 근거 보기/ })[0]);
  expect(screen.getAllByRole('region', { name: 'DDoS 발견 근거' })).toHaveLength(1);
  fireEvent.click(screen.getByRole('button', { name: '다음' }));
  expect(screen.queryByRole('region', { name: 'DDoS 발견 근거' })).not.toBeInTheDocument();
  expect(document.querySelectorAll('*').length).toBeLessThan(500);
});

it('submits the dedicated DDoS module and thresholds from the live analysis form', async () => {
  let submitted: Record<string, unknown> | undefined;
  localStorage.setItem('c2hunter-token', 'test-token');
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    if (String(input) === '/api/v1/sensors') return new Response(JSON.stringify({ items: [{ sensor_id: 's1', name: 'Sensor' }] }));
    if (String(input) === '/api/v1/analysis-jobs' && init?.method === 'POST') {
      submitted = JSON.parse(String(init.body));
      return new Response(JSON.stringify({ id: 'ddos-job', status: 'CREATED' }));
    }
    return new Response(JSON.stringify({ items: [] }));
  }));
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={['/analyses/new']}><App/></MemoryRouter></QueryClientProvider>);
  fireEvent.change(screen.getByLabelText('Analysis name'), { target: { value: 'DDoS investigation' } });
  fireEvent.change(screen.getByLabelText('Analysis module'), { target: { value: 'ddos_attack' } });
  expect(screen.getByRole('heading', { name: 'DDoS attack traffic analysis' })).toBeVisible();
  await userEvent.click(await screen.findByLabelText('Sensor'));
  fireEvent.change(screen.getByLabelText('Minimum observed sources'), { target: { value: '30' } });
  fireEvent.submit(screen.getByLabelText('Analysis name').closest('form')!);
  await waitFor(() => expect(submitted).toBeDefined());
  expect(submitted?.analysis).toMatchObject({ module: 'ddos_attack', ddos_min_source_count: 30 });
  expect(Object.keys(submitted?.analysis as Record<string, unknown>).filter(key => key.startsWith('ddos_'))).toHaveLength(15);
  expect(JSON.stringify(submitted)).not.toContain('detector_weights');
});

it('shows DDoS findings and verdict in analysis history instead of zero C2 candidates', async () => {
  localStorage.setItem('c2hunter-token', 'test-token');
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    if (String(input).startsWith('/api/v1/analysis-jobs?')) return Response.json({ items: [{
      id: 'ddos-history', name: 'DDoS history', status: 'COMPLETED', analysis: { module: 'ddos_attack' },
      source_type: 'PCAP_UPLOAD', source: { filename: 'attack.pcap', size_bytes: 2048 },
      ddos_attack_summary: { verdict: 'suspicious_traffic', confidence: 'medium', finding_count: 3 },
    }] });
    return Response.json({ items: [] });
  }));
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={['/analyses']}><App/></MemoryRouter></QueryClientProvider>);
  expect(await screen.findByText('3')).toBeVisible();
  expect(screen.getByText('DDoS findings')).toBeVisible();
  expect(screen.getByText('suspicious_traffic · medium confidence')).toBeVisible();
  expect(screen.queryByText('0 candidates')).not.toBeInTheDocument();
});

it('renders the real DDoS report with its dedicated AI output and without C2 candidates', async () => {
  localStorage.setItem('c2hunter-token', 'test-token');
  const requests: string[] = [];
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    const path = String(input);
    requests.push(path);
    if (path === '/api/v1/analysis-jobs/ddos-job') return new Response(JSON.stringify({
      id: 'ddos-job', name: 'DDoS case', status: 'COMPLETED', analysis: { module: 'ddos_attack' },
      sensor_ids: ['sensor-a'], ddos_attack: report, packet_count: 1200, flow_count: 24,
    }));
    return new Response(JSON.stringify({ items: [] }));
  }));
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={['/analyses/ddos-job']}><App/></MemoryRouter></QueryClientProvider>);
  expect(await screen.findByRole('heading', { name: '의심스러운 DDoS 형태 관찰' })).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: /상세 근거 보기/ }));
  expect(screen.getByRole('region', { name: 'DDoS 발견 근거' })).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: '작업 상세 / Job details' }));
  expect(screen.queryByRole('region', { name: 'DDoS 발견 근거' })).not.toBeInTheDocument();
  expect(screen.queryByText('AI C2 분석')).not.toBeInTheDocument();
  expect(requests).not.toContain('/api/v1/analysis-jobs/ddos-job/candidates?page_size=200');
  expect(requests).toContain('/api/v1/analysis-jobs/ddos-job/ai-runs');
});
