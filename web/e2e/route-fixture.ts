import type { Page, Route } from '@playwright/test';

const sensor = { sensor_id: 'sensor-a', name: 'Sensor A', status: 'ONLINE', last_heartbeat: '2026-07-20T10:00:00Z', interfaces: [{ name: 'eth0', direction: 'INBOUND' }], version: '0.1.0', cpu_percent: 12, memory_percent: 24, disk_percent: 31, received_packets: 123456, dropped_packets: 4 };
const candidate = { id: 'candidate-1', job_id: 'job-1', candidate_ip: '203.0.113.10', score: 87, severity: 'CRITICAL', distinct_internal_hosts: 50, sensor_ids: ['sensor-a', 'sensor-b'], protocols: ['TCP', 'TLS'], ports: [443], first_seen: '2026-07-20T10:00:00Z', last_seen: '2026-07-20T10:05:00Z', internal_hosts: ['10.0.0.1', '10.0.0.2'], traffic_series: [2, 4, 3, 12, 8, 20], related_attack_targets: ['198.51.100.20:53/UDP'], evidence: [{ type: 'PERIODIC_BEACON', score: 14, description: '50 hosts contacted the destination at a stable 30 second interval.' }, { type: 'COMMAND_ATTACK_CORRELATION', score: 24, description: 'Outbound traffic increased after synchronized inbound messages.' }] };
let allowlist: Array<{ id: string; type: string; value: string; description: string }> = [];

async function fulfill(route: Route, body: unknown, status = 200) { await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) }); }

export async function installApiFixture(page: Page) {
  allowlist = [];
  await page.route('**/api/v1/**', async route => {
    const request = route.request(); const path = new URL(request.url()).pathname.replace('/api/v1', ''); const method = request.method();
    if (path === '/auth/dev-login' && method === 'POST') return fulfill(route, { access_token: 'deterministic-e2e-token' });
    if (path === '/dashboard') return fulfill(route, { online_sensors: 2, offline_sensors: 0, capturing_jobs: 1, recent_analyses: 3, high_critical_candidates: 1, candidate_trend: [1, 2, 1, 3] });
    if (path === '/sensors') return fulfill(route, { items: [sensor, { ...sensor, sensor_id: 'sensor-b', name: 'Sensor B', interfaces: [{ name: 'eth1', direction: 'OUTBOUND' }] }] });
    if (path === '/sensors/sensor-a') return fulfill(route, sensor);
    if (path === '/analysis-jobs' && method === 'GET') return fulfill(route, { items: [{ id: 'job-1', name: 'E2E investigation', status: 'COMPLETED', candidate_count: 1 }] });
    if (path === '/analysis-jobs' && method === 'POST') return fulfill(route, { id: 'job-1', name: 'E2E investigation', status: 'CREATED' }, 201);
    if (path === '/analysis-jobs/job-1' && method === 'PATCH') { const body = request.postDataJSON(); return fulfill(route, { id: 'job-1', name: body.name, description: body.description, status: 'COMPLETED' }); }
    if (path === '/analysis-jobs/job-1' && method === 'DELETE') return fulfill(route, undefined, 204);
    if (path === '/analysis-jobs/job-1' && method === 'GET') return fulfill(route, { id: 'job-1', name: 'E2E investigation', status: 'ANALYZING', progress_percent: 72, packet_count: 720000, flow_count: 18000, candidate_count: 1 });
    if (path === '/analysis-jobs/job-1/cancel') return fulfill(route, { status: 'CANCELLED' });
    if (path === '/pcap-analysis-jobs' && method === 'POST') return fulfill(route, { id: 'upload-job', name: 'Uploaded E2E capture', status: 'COMPLETED' }, 201);
    if (path === '/analysis-jobs/upload-job' && method === 'GET') return fulfill(route, { id: 'upload-job', name: 'Uploaded E2E capture', status: 'COMPLETED', source_type: 'PCAP_UPLOAD', source: { filename: 'fixture.pcap', size_bytes: 4 }, packet_count: 1, flow_count: 1, candidate_count: 0 });
    if (path === '/candidates') return fulfill(route, { items: [candidate] });
    if (path === '/candidates/candidate-1') return fulfill(route, candidate);
    if (path === '/pcap-exports' && method === 'POST') return fulfill(route, { id: 'export-1', status: 'PENDING' }, 201);
    if (path.endsWith('/reanalyze') && method === 'POST') return fulfill(route, { id: 'job-2', status: 'CREATED' }, 201);
    if (path === '/allowlist' && method === 'GET') return fulfill(route, { items: allowlist });
    if (path === '/allowlist' && method === 'POST') { const body = request.postDataJSON(); allowlist.push({ id: 'allow-1', type: body.type, value: body.value, description: body.description }); return fulfill(route, allowlist[0], 201); }
    if (path === '/allowlist/allow-1' && method === 'DELETE') { allowlist = []; return fulfill(route, undefined, 204); }
    return fulfill(route, { error: { code: 'FIXTURE_ROUTE_MISSING', message: `${method} ${path}` } }, 404);
  });
}
