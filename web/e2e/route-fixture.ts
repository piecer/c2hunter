import type { Page, Route } from '@playwright/test';

const sensor = { sensor_id: 'sensor-a', name: 'Sensor A', status: 'ONLINE', last_heartbeat: '2026-07-20T10:00:00Z', interfaces: [{ name: 'eth0', direction: 'INBOUND' }], version: '0.1.0', cpu_percent: 12, memory_percent: 24, disk_percent: 31, received_packets: 123456, dropped_packets: 4 };
const candidate = { id: 'candidate-1', job_id: 'job-1', candidate_ip: '203.0.113.10', score: 87, severity: 'CRITICAL', distinct_internal_hosts: 50, sensor_ids: ['sensor-a', 'sensor-b'], protocols: ['TCP', 'TLS'], ports: [443], first_seen: '2026-07-20T10:00:00Z', last_seen: '2026-07-20T10:05:00Z', internal_hosts: ['10.0.0.1', '10.0.0.2'], traffic_series: [2, 4, 3, 12, 8, 20], related_attack_targets: ['198.51.100.20:53/UDP'], evidence: [{ type: 'PERIODIC_BEACON', score: 14, description: '50 hosts contacted the destination at a stable 30 second interval.', metrics: { sample_count: 50, period_seconds: 30, jitter_ratio: 0.08, confidence_score: 0.96, timing_window: { minimum_seconds: 25, maximum_seconds: 35 }, phases: ['warmup', 'steady_state', 'confirmation', 'retained'] } }, { type: 'COMMAND_ATTACK_CORRELATION', score: 24, description: 'Outbound traffic increased after synchronized inbound messages.' }] };
const flow = { flow_id: 'e2e-flow', job_id: 'job-1', sensor_id: 'sensor-a', timestamp: '2026-07-20T10:00:00Z', source_ip: '10.0.0.5', destination_ip: '203.0.113.10', source_port: 51000, destination_port: 443, internal_ip: '10.0.0.5', external_ip: '203.0.113.10', service_port: 443, protocol: 'TCP', direction: 'OUTBOUND', packet_count: 5, total_bytes: 512, payload_hash: 'fixture-hash', payload_prefix_hash: 'fixture-prefix', payload_length: 16, has_payload: true, current_label: null };
async function fulfill(route: Route, body: unknown, status = 200) { await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) }); }

export async function installApiFixture(page: Page) {
  let allowlist: Array<{ id: string; type: string; value: string; description: string }> = [];
  let integrationSettings = {
    version: 1, virustotal_enabled: true, abuseipdb_enabled: true, misp_enabled: true,
    misp_url: 'https://misp.example', misp_verify_tls: true, threat_intel_timeout_seconds: 10,
    threat_intel_request_delay_seconds: 1,
    abuseipdb_max_age_days: 90, abuseipdb_positive_threshold: 70,
    candidate_auto_enrichment_enabled: true, candidate_auto_enrichment_limit: 20,
    candidate_auto_enrichment_workers: 4, candidate_auto_enrichment_queue_capacity: 200,
    management_event_id: '100', management_auto_register: false,
    immediate_action_event_id: '200', immediate_action_auto_register: false,
    immediate_action_min_positive_providers: 2,
  };
  let currentCandidate: typeof candidate & Record<string, unknown> = {
    ...candidate,
    workflow_status: 'NEEDS_REVIEW',
    action_status: 'NOT_REQUIRED',
    ti_assessment: {
      status: 'COMPLETED',
      signal: 'POSITIVE',
      configured_providers: 3,
      successful_providers: 3,
      positive_providers: 3,
      virustotal_malicious: 8,
      virustotal_suspicious: 2,
      abuse_confidence_score: 91,
      misp_event_count: 1,
      fetched_at: '2026-07-20T10:09:00Z',
    },
    threat_intelligence: {
      status: 'COMPLETED',
      origin: 'AUTO',
      fetched_at: '2026-07-20T10:09:00Z',
      summary: { malicious: 8, suspicious: 2, harmless: 12, abuse_confidence_score: 91, misp_event_count: 1 },
      providers: {
        virustotal: { status: 'OK', malicious: 8, suspicious: 2, harmless: 12, reputation: -20 },
        abuseipdb: { status: 'OK', abuse_confidence_score: 91, total_reports: 13, country_code: 'US' },
        misp: { status: 'OK', attribute_count: 2, event_count: 1, matches: [{ event_id: '42' }] },
      },
    },
  };
  let aiRuns: Array<Record<string, unknown>> = [];
  const aiAssessment = {
    id: 'assessment-1',
    run_id: 'ai-run-1',
    candidate_id: 'candidate-1',
    external_ip: '203.0.113.10',
    review_priority: 72,
    assessment: {
      candidate: {
        external_ip: '203.0.113.10',
        verdict: 'LIKELY_C2',
        confidence: 0.93,
        summary_ko: '결정론적 근거가 주기적 비콘 동작을 지지합니다.',
        summary_en: 'Deterministic evidence supports beaconing behavior.',
      },
      supporting_factors: [{ title: 'Stable periodic callback', explanation: 'Repeated timing is stable.', strength: 'HIGH', evidence_ids: ['E-C2H-001'] }],
      counter_factors: [{ title: 'No DNS tunnel evidence', explanation: 'Only flow metadata is present.', evidence_ids: ['E-C2H-001'] }],
      missing_information: ['Destination ownership'],
      limitations: ['FakeGateway milestone output'],
    },
  };
  await page.route('**/api/v1/**', async route => {
    const request = route.request(); const path = new URL(request.url()).pathname.replace('/api/v1', ''); const method = request.method();
    if (path === '/auth/dev-login' && method === 'POST') return fulfill(route, { access_token: 'deterministic-e2e-token' });
    if (path === '/integration-settings' && method === 'GET') return fulfill(route, integrationSettings);
    if (path === '/integration-settings' && method === 'PUT') {
      integrationSettings = { ...integrationSettings, ...request.postDataJSON(), version: integrationSettings.version + 1 };
      return fulfill(route, integrationSettings);
    }
    if (path === '/dashboard') return fulfill(route, { generated_at: '2026-07-20T10:10:00Z', fleet: { total: 2, online: 2, offline: 0, degraded: 0, dropped_packets: 4 }, analyses: { total: 3, active: 1, completed_24h: 2, failed_24h: 0, partially_completed_24h: 0, by_status: { WAITING_FOR_SENSOR: 0, CAPTURING: 0, UPLOADING: 0, INGESTING: 0, ANALYZING: 1 } }, candidates: { total: 1, critical: 1, high: 0, medium: 0, low: 0, new_24h: 1, needs_review: 1, in_review: 0, action_required: 0, action_in_progress: 0, action_completed: 0, false_positive: 0, done: 0 }, candidate_trend: [{ hour: '2026-07-20T08:00:00Z', count: 0 }, { hour: '2026-07-20T09:00:00Z', count: 0 }, { hour: '2026-07-20T10:00:00Z', count: 1 }], priority_candidates: [{ ...currentCandidate, evidence_count: 2 }], recent_analyses: [{ id: 'job-1', name: 'E2E investigation', status: 'COMPLETED', candidate_count: 1, packet_count: 720000, flow_count: 18000, created_at: '2026-07-20T10:00:00Z' }], sensor_quality: [{ sensor_id: 'sensor-a', name: 'Sensor A', status: 'ONLINE', received_packets: 716000, dropped_packets: 4000, drop_rate_percent: 0.56, last_heartbeat_at: '2026-07-20T10:09:50Z', last_error: null }], attention: [{ kind: 'CRITICAL_CANDIDATE', severity: 'CRITICAL', title: '203.0.113.10 조사 필요', detail: '점수 87 · CRITICAL', href: '/candidates/candidate-1' }] });
    if (path === '/sensors') return fulfill(route, { items: [sensor, { ...sensor, sensor_id: 'sensor-b', name: 'Sensor B', interfaces: [{ name: 'eth1', direction: 'OUTBOUND' }] }] });
    if (path === '/sensors/sensor-a') return fulfill(route, sensor);
    if (path === '/sensor-pcaps' && method === 'GET') return fulfill(route, { items: [{ id: 'segment-a', sensor_id: 'sensor-a', sensor_name: 'Sensor A', analysis_job_id: 'job-1', filename: 'job-1--eth0-000001.pcap', size_bytes: 24, sha256: 'digest', uploaded_at: '2026-07-20T10:08:00Z' }], page: 1, page_size: 50, total: 1 });
    if (path === '/sensor-pcaps/segment-a/download' && method === 'GET') return route.fulfill({ status: 200, contentType: 'application/vnd.tcpdump.pcap', headers: { 'Content-Disposition': 'attachment; filename="job-1--eth0-000001.pcap"' }, body: Buffer.from([0xd4, 0xc3, 0xb2, 0xa1]) });
    if (path === '/analysis-jobs' && method === 'GET') return fulfill(route, { items: [{ id: 'job-1', name: 'E2E investigation', status: 'COMPLETED', candidate_count: 1 }] });
    if (path === '/analysis-jobs' && method === 'POST') return fulfill(route, { id: 'job-1', name: 'E2E investigation', status: 'CREATED' }, 201);
    if (path === '/analysis-jobs/job-1/ai-runs' && method === 'GET') return fulfill(route, { items: aiRuns, total: aiRuns.length });
    if (path === '/analysis-jobs/job-1/ai-runs' && method === 'POST') {
      aiRuns = [{ id: 'ai-run-1', analysis_job_id: 'job-1', status: 'COMPLETED', progress_percent: 100, candidate_count: 1, created_at: '2026-07-20T10:15:00Z' }];
      return fulfill(route, aiRuns[0], 201);
    }
    if (path === '/ai-runs/ai-run-1' && method === 'GET') return fulfill(route, aiRuns[0]);
    if (path === '/ai-runs/ai-run-1/assessments' && method === 'GET') return fulfill(route, { items: [aiAssessment], total: 1 });
    if (path === '/ai-assessments/assessment-1/artifacts' && method === 'GET') return fulfill(route, {
      items: [
        { id: 'artifact-hunt', artifact_type: 'SPLUNK_HUNT', validation_status: 'VALID', approved_status: 'PENDING', content: { purpose: 'Inspect candidate communication', spl: 'index=c2hunter earliest=-15m latest=now dst_ip="203.0.113.10" | table _time,dst_ip' } },
        { id: 'artifact-detection', artifact_type: 'SPLUNK_DETECTION', validation_status: 'VALID', approved_status: 'PENDING', content: { purpose: 'Detect repeated communication', spl: 'index=c2hunter earliest=-10m latest=now | stats count by dst_ip' } },
        { id: 'artifact-misp', artifact_type: 'MISP_DRAFT', validation_status: 'VALID', approved_status: 'PENDING', content: { Event: { info: 'C2Hunter suspected candidate', published: false, Attribute: [{ type: 'ip-dst', value: '203.0.113.10', to_ids: false }] } } },
      ],
      total: 3,
    });
    if (path === '/ai-assessments/assessment-1/feedback' && method === 'GET') return fulfill(route, {
      items: [{ id: 'feedback-1', verdict: 'NEED_MORE_DATA', note: 'Endpoint telemetry review is pending.', created_by: 'analyst', created_at: '2026-07-20T10:20:00Z' }],
      total: 1,
    });
    if (path === '/analysis-jobs/job-1' && method === 'PATCH') { const body = request.postDataJSON(); return fulfill(route, { id: 'job-1', name: body.name, description: body.description, status: 'COMPLETED' }); }
    if (path === '/analysis-jobs/job-1' && method === 'DELETE') return fulfill(route, undefined, 204);
    if (path === '/analysis-jobs/job-1' && method === 'GET') return fulfill(route, { id: 'job-1', name: 'E2E investigation', status: 'ANALYZING', progress_percent: 72, packet_count: 720000, flow_count: 18000, candidate_count: 1, sensor_ids: ['sensor-a'], internal_networks: ['10.0.0.0/8'], capture: { directions: ['OUTBOUND', 'INBOUND'], store_pcap: true, max_packets: 2000000, limits: { max_duration_seconds: 300 } }, analysis: { profile: 'ddos_botnet', minimum_candidate_score: 60, minimum_distinct_clients: 3, periodicity_min_samples: 5, ml_anomaly_enabled: true, detector_weights: { periodic_beacon: 1.5, common_destination: 0.25, dns_tunnel: 0 }, custom_policy: { mode: 'strict', tags: ['production', 'edge'] } } });
    if (path === '/analysis-jobs/job-1/cancel') return fulfill(route, { status: 'CANCELLED' });
    if (path === '/pcap-analysis-jobs' && method === 'POST') return fulfill(route, { id: 'upload-job', name: 'Uploaded E2E capture', status: 'COMPLETED' }, 201);
    if (path === '/analysis-jobs/upload-job' && method === 'GET') return fulfill(route, { id: 'upload-job', name: 'Uploaded E2E capture', status: 'COMPLETED', source_type: 'PCAP_UPLOAD', source: { filename: 'fixture.pcap', size_bytes: 4 }, packet_count: 1, flow_count: 1, candidate_count: 0 });
    if (path === '/candidates') return fulfill(route, { items: [currentCandidate], workflow_counts: { needs_review: 1, in_review: 0, action_required: 0, action_in_progress: 0, action_completed: 0, false_positive: 0, done: 0 } });
    if (path === '/candidate-bulk-operations' && method === 'POST') return fulfill(route, { status: 'COMPLETED', total: 1, succeeded: 1, failed: 0, results: [{ candidate_id: 'candidate-1', status: 'SUCCEEDED' }] });
    if (path === '/candidates/candidate-1/verdicts' && method === 'POST') {
      const body = request.postDataJSON();
      const verdict = { id: 'verdict-1', ...body, created_by: 'analyst', created_at: '2026-07-20T10:11:00Z' };
      const action = { id: 'action-pending', verdict_id: verdict.id, status: 'PENDING', note: 'Follow-up created', created_by: 'analyst', created_at: verdict.created_at };
      currentCandidate = { ...currentCandidate, workflow_status: 'ACTION_REQUIRED', action_status: 'PENDING', current_verdict: verdict, verdict_history: [verdict], current_action: action, action_history: [action] };
      return fulfill(route, currentCandidate);
    }
    if (path === '/candidates/candidate-1/actions' && method === 'POST') {
      const body = request.postDataJSON();
      const action = { id: `action-${body.status.toLowerCase()}`, verdict_id: 'verdict-1', ...body, created_by: 'analyst', created_at: '2026-07-20T10:12:00Z', completed_at: body.status === 'COMPLETED' ? '2026-07-20T10:12:00Z' : null };
      currentCandidate = { ...currentCandidate, workflow_status: body.status === 'COMPLETED' ? 'ACTION_COMPLETED' : 'ACTION_IN_PROGRESS', action_status: body.status, current_action: action, action_history: [...(currentCandidate.action_history as object[]), action] };
      return fulfill(route, currentCandidate);
    }
    if (path === '/candidates/candidate-1/threat-intelligence/lookups' && method === 'POST') {
      const result = { ip_address: candidate.candidate_ip, fetched_at: '2026-07-20T10:12:00Z', summary: { malicious: 8, suspicious: 2, harmless: 12, abuse_confidence_score: 91 }, providers: { virustotal: { status: 'OK', malicious: 8, suspicious: 2, harmless: 12, reputation: -20 }, abuseipdb: { status: 'OK', abuse_confidence_score: 91, total_reports: 13, country_code: 'US' } } };
      currentCandidate = { ...currentCandidate, threat_intelligence: result };
      return fulfill(route, result);
    }
    if (path === '/candidates/candidate-1/misp-exports' && method === 'POST') {
      const body = request.postDataJSON();
      const result = { id: 'misp-1', status: 'EXPORTED', event_id: body.event_id || '42', candidate_ip: candidate.candidate_ip, attribute_type: 'ip-src', attribute_id: '9001', created_by: 'analyst', created_at: '2026-07-20T10:13:00Z' };
      currentCandidate = { ...currentCandidate, misp_exports: [result] };
      return fulfill(route, result);
    }
    if (path === '/candidates/candidate-1') return fulfill(route, currentCandidate);
    if (path === '/analysis-jobs/job-1/flows' && method === 'GET') return fulfill(route, { items: [flow], page: 1, page_size: 50, total: 1 });
    if (path === '/analysis-jobs/job-1/flow-labels' && method === 'POST') return fulfill(route, { label: { id: 'label-e2e', flow_id: flow.flow_id, verdict: 'C2', confidence: 'HIGH', created_at: '2026-07-20T10:06:00Z' }, signature: null }, 201);
    if (path === '/analysis-jobs/job-1/flows/e2e-flow/detection-guidance' && method === 'GET') return fulfill(route, { flow_id: flow.flow_id, candidate_ip: flow.external_ip, initially_detected: false, suppressed_by_policy: false, current_score: 5, minimum_candidate_score: 20, score_gap: 15, conditions: [{ evidence_type: 'PERIODIC_BEACON', detector: 'periodic_beacon', contribution: 15, weighted_contribution: 15, description: '허용 jitter 범위 내 주기 통신', metrics: { sample_count: 5 } }], adjustments: [{ kind: 'SINGLE_HOST', points: -10, explanation: '단일 호스트 관측 감점' }], recommendations: [{ kind: 'DETECTOR_WEIGHT', detector: 'periodic_beacon', current_value: 1, recommended_value: 2, projected_score: 20, score_gain: 15, rationale: '주기 통신 가중치 조정으로 후보 기준에 도달합니다.', risk: 'MEDIUM', risk_note: '정상 주기 통신 점수도 증가합니다.' }], recommended_reanalysis: { minimum_candidate_score: 20, detector_weights: { periodic_beacon: 2 } }, warnings: ['정상 데이터셋에서 오탐 증가를 검증해야 합니다.'] });
    if (path === '/pcap-exports' && method === 'POST') return fulfill(route, { id: 'export-1', status: 'PENDING' }, 201);
    if (path.endsWith('/reanalyze') && method === 'POST') return fulfill(route, { id: 'job-2', status: 'CREATED' }, 201);
    if (path === '/allowlist' && method === 'GET') return fulfill(route, { items: allowlist });
    if (path === '/allowlist' && method === 'POST') { const body = request.postDataJSON(); allowlist.push({ id: 'allow-1', type: body.type, value: body.value, description: body.description }); return fulfill(route, allowlist[0], 201); }
    if (path === '/allowlist/allow-1' && method === 'DELETE') { allowlist = []; return fulfill(route, undefined, 204); }
    return fulfill(route, { error: { code: 'FIXTURE_ROUTE_MISSING', message: `${method} ${path}` } }, 404);
  });
}
