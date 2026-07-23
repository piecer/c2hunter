import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import App from '../src/App';

const responses: Record<string, unknown> = {
  '/api/v1/analysis-jobs': { items: [{ id: 'job-1', name: 'Investigation', description: 'Initial note', status: 'COMPLETED', source_type: 'PCAP_UPLOAD', source: { filename: 'capture.pcap', size_bytes: 2048 }, created_at: '2026-07-20T10:10:00Z', start_time: '2026-07-20T10:00:00Z', end_time: '2026-07-20T10:05:00Z', packet_count: 100, flow_count: 50, candidate_count: 2 }] },
  '/api/v1/sensors': { items: [{ sensor_id: 'sensor-a', name: 'Sensor A', status: 'ONLINE', last_heartbeat: '2026-07-20T10:00:00Z', interfaces: [{ name: 'eth0', direction: 'INBOUND' }], version: '0.1.0', cpu_percent: 10, memory_percent: 20, disk_percent: 30, received_packets: 1000, dropped_packets: 2 }, { sensor_id: 'sensor-b', name: 'Sensor B', status: 'ONLINE', interfaces: [{ name: 'eth1', direction: 'OUTBOUND' }] }] },
  '/api/v1/analysis-jobs/job-1': { id: 'job-1', dataset_id: 'dataset-1', name: 'Investigation', status: 'ANALYZING', sensor_ids: ['sensor-a'], internal_networks: ['10.0.0.0/8'], capture: { max_packets: 2000, directions: ['OUTBOUND'] }, analysis: { profile: 'ddos_botnet', minimum_candidate_score: 60 }, transitions: [{ to_status: 'CREATED', occurred_at: '2026-07-20T10:00:00Z', reason: 'analysis requested' }], packet_count: 100, flow_count: 50, candidate_count: 1 },
  '/api/v1/analysis-jobs/job-1/candidates?page_size=200': { items: [{ id: 'candidate-1', job_id: 'job-1', candidate_ip: '203.0.113.9', score: 80, severity: 'HIGH', hosts: ['10.0.0.5'], sensors: ['sensor-a'], first_seen: '2026-07-20T10:00:00Z', last_seen: '2026-07-20T10:05:00Z', evidence: [{ type: 'PERIODIC_BEACON', detector: 'periodic_beacon', contribution: 15, description: 'Periodic traffic' }] }] },
  '/api/v1/candidates': { items: [{ id: 'candidate-1', job_id: 'job-1', candidate_ip: '203.0.113.9', score: 80, severity: 'HIGH', hosts: ['10.0.0.5'], sensors: ['sensor-a'], first_seen: '2026-07-20T10:00:00Z', last_seen: '2026-07-20T10:05:00Z', evidence: [{ type: 'PERIODIC_BEACON', detector: 'periodic_beacon', contribution: 15, description: 'Periodic traffic' }] }] },
  '/api/v1/candidates/candidate-1': { id: 'candidate-1', job_id: 'job-1', candidate_ip: '203.0.113.9', score: 80, severity: 'HIGH', hosts: ['10.0.0.5'], sensors: ['sensor-a'], protocols: ['TCP'], ports: [443], domains: ['c2.example'], first_seen: '2026-07-20T10:00:00Z', last_seen: '2026-07-20T10:05:00Z', flow_count: 5, packet_count: 20, byte_count: 2048, traffic_buckets: [{ start: '2026-07-20T10:00:00Z', flows: 5, packets: 20, bytes: 2048 }], evidence: [{ type: 'PERIODIC_BEACON', detector: 'periodic_beacon', version: '1.0.0', raw_score: 15, contribution: 15, confidence: 0.9, description: 'Periodic traffic', hosts: ['10.0.0.5'], sensors: ['sensor-a'], metrics: { sample_count: 7, period_seconds: 30 } }], adjustments: [{ kind: 'SINGLE_HOST', points: -20, explanation: 'Single internal host observed' }] },
  '/api/v1/analysis-jobs/job-1/flows?candidate_ip=203.0.113.9&page=1&page_size=50': { items: [{ flow_id: '0123456789abcdef01234567', job_id: 'job-1', sensor_id: 'sensor-a', timestamp: '2026-07-20T10:00:00Z', source_ip: '10.0.0.5', destination_ip: '203.0.113.9', source_port: 51000, destination_port: 443, internal_ip: '10.0.0.5', external_ip: '203.0.113.9', service_port: 443, protocol: 'TCP', direction: 'OUTBOUND', packet_count: 2, total_bytes: 128, payload_hash: '8a62e967fcd6dfa5d75308c37808b4668a7faf1cdb06e09ac0a7161827603887', payload_prefix_hash: '8a62e967fcd6dfa5d75308c37808b4668a7faf1cdb06e09ac0a7161827603887', payload_length: 6, payload_entropy: 2.585, payload_printable_ratio: 1, payload_simhash: 'e627bf19152d67b3', payload_feature_version: '1', has_payload: true, current_label: null }], page: 1, page_size: 50, total: 1 },
  '/api/v1/analysis-jobs/job-1/flows/0123456789abcdef01234567/payload-preview': { flow_id: '0123456789abcdef01234567', payload_hex: '626561636f6e', payload_ascii: 'beacon', sample_bytes: 6, payload_length: 6, truncated: false, payload_hash: '8a62e967fcd6dfa5d75308c37808b4668a7faf1cdb06e09ac0a7161827603887' },
  '/api/v1/payload-signatures?page_size=200': { items: [{ id: 'signature-1', name: 'TCP beacon payload', description: 'Confirmed implant beacon', version: 1, enabled: true, source_job_id: 'job-1', source_flow_id: '0123456789abcdef01234567', source_label_id: 'label-1', protocol: 'TCP', direction: 'OUTBOUND', service_port: 443, payload_hash: '8a62e967fcd6dfa5d75308c37808b4668a7faf1cdb06e09ac0a7161827603887', payload_prefix_hash: '8a62e967fcd6dfa5d75308c37808b4668a7faf1cdb06e09ac0a7161827603887', payload_length: 6, payload_entropy: 2.585, payload_printable_ratio: 1, payload_simhash: 'e627bf19152d67b3', payload_feature_version: '1', length_tolerance_ratio: 0.15, entropy_tolerance: 0.75, simhash_max_distance: 8, created_by: 'analyst', created_at: '2026-07-20T10:06:00Z', updated_at: '2026-07-20T10:06:00Z' }] },
};
responses['/api/v1/analysis-jobs/job-1/flows?page=1&page_size=50&has_payload=true'] =
  responses['/api/v1/analysis-jobs/job-1/flows?candidate_ip=203.0.113.9&page=1&page_size=50'];

function renderAt(route: string) {
  localStorage.setItem('c2hunter-token', 'token');
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    const path = String(input);
    return new Response(JSON.stringify(responses[path]), { status: responses[path] ? 200 : 404, headers: { 'content-type': 'application/json' } });
  }));
  return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={[route]}><App /></MemoryRouter></QueryClientProvider>);
}

describe('C2Hunter UI', () => {
  it('shows dashboard operational metrics', async () => {
    renderAt('/');
    expect(await screen.findByRole('heading', { name: 'Dashboard' })).toBeInTheDocument();
    expect(await screen.findByText('Online sensors')).toBeInTheDocument();
    expect(screen.getAllByText('2', { selector: 'strong' })).toHaveLength(2);
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
    expect(screen.getByText('PERIODIC_BEACON')).toBeInTheDocument();
  });

  it('shows detector settings, state history, and candidates on analysis detail', async () => {
    renderAt('/analyses/job-1');
    expect(await screen.findByRole('heading', { name: 'Detector settings' })).toBeInTheDocument();
    expect(screen.getByText('ddos_botnet')).toBeInTheDocument();
    expect(await screen.findByRole('table', { name: 'Analysis candidates' })).toBeInTheDocument();
    expect(await screen.findByRole('table', { name: 'Analysis flows' })).toBeInTheDocument();
    expect(screen.getByText('analysis requested')).toBeInTheDocument();
  });

  it('lets an analyst browse flows that were never promoted to candidates', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path.includes('/flows?')) {
        return new Response(JSON.stringify(responses['/api/v1/analysis-jobs/job-1/flows?page=1&page_size=50&has_payload=true']), { status: 200, headers: { 'content-type': 'application/json' } });
      }
      return new Response(JSON.stringify(responses[path]), { status: responses[path] ? 200 : 404, headers: { 'content-type': 'application/json' } });
    });
    renderAt('/analyses/job-1');
    vi.stubGlobal('fetch', fetchMock);
    const user = userEvent.setup();

    expect(await screen.findByRole('table', { name: 'Analysis flows' })).toBeInTheDocument();
    await user.type(screen.getByLabelText('Endpoint IP'), '198.51.100.7');
    await user.click(screen.getByRole('button', { name: 'Apply filters' }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/analysis-jobs/job-1/flows?page=1&page_size=50&candidate_ip=198.51.100.7&has_payload=true',
      expect.any(Object),
    ));
  });

  it('renders an error state with retry when a request fails', async () => {
    localStorage.setItem('c2hunter-token', 'token');
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: { message: 'Storage unavailable' } }), { status: 503, headers: { 'content-type': 'application/json' } })));
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={['/']}><App /></MemoryRouter></QueryClientProvider>);
    expect(await screen.findByRole('alert')).toHaveTextContent('Storage unavailable');
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument();
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
    await user.click(screen.getByRole('button', { name: 'Start analysis' }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/v1/analysis-jobs', expect.objectContaining({ method: 'POST' })));
    const call = fetchMock.mock.calls.find(([url, init]) => url === '/api/v1/analysis-jobs' && init?.method === 'POST');
    const body = JSON.parse(String(call?.[1]?.body));
    expect(body).toEqual(expect.objectContaining({
      name: 'Web analysis', sensor_ids: ['sensor-a'], mode: 'LIVE', internal_networks: ['10.0.0.0/8'],
      idempotency_key: expect.any(String), start_time: expect.any(String), end_time: expect.any(String),
      analysis: expect.objectContaining({ minimum_candidate_score: 20, minimum_distinct_clients: 3 }),
    }));
    expect(new Date(body.end_time).getTime()).toBeGreaterThan(new Date(body.start_time).getTime());
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

    expect(screen.getByText('Sample Count')).toBeInTheDocument();
    expect(screen.getByRole('table', { name: 'Candidate traffic buckets' })).toBeInTheDocument();

    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/v1/analysis-jobs/job-1/reanalyze', expect.objectContaining({ method: 'POST' })));
    const exportCall = fetchMock.mock.calls.find(([url]) => url === '/api/v1/pcap-exports');
    expect(JSON.parse(String(exportCall?.[1]?.body))).toEqual({ job_id: 'job-1', candidate_id: 'candidate-1' });
    const reanalyzeCall = fetchMock.mock.calls.find(([url]) => url === '/api/v1/analysis-jobs/job-1/reanalyze');
    expect(JSON.parse(String(reanalyzeCall?.[1]?.body))).toEqual({ idempotency_key: expect.any(String) });
  });

  it('renders score adjustments safely when the Controller returns a non-string kind', async () => {
    const original = responses['/api/v1/candidates/candidate-1'] as Record<string, unknown>;
    responses['/api/v1/candidates/candidate-1'] = {
      ...original,
      adjustments: [{ kind: 7, points: -5, explanation: 'Imported adjustment' }],
    };

    try {
      renderAt('/candidates/candidate-1');
      expect(await screen.findByText('7 · Imported adjustment')).toBeInTheDocument();
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
    expect(screen.getByRole('status')).toHaveTextContent('500.0 MiB');
    fireEvent.submit(screen.getByRole('button', { name: 'Upload and analyze' }).closest('form')!);

    await waitFor(() => expect(fetchMock.mock.calls.some(([url, init]) => String(url).startsWith('/api/v1/pcap-analysis-jobs?') && init?.method === 'POST')).toBe(true));
    const uploadCall = fetchMock.mock.calls.find(([url]) => String(url).startsWith('/api/v1/pcap-analysis-jobs?'));
    const url = new URL(String(uploadCall?.[0]), 'http://localhost');
    expect(url.searchParams.get('name')).toBe('Offline case');
    expect(url.searchParams.get('filename')).toBe('sample.pcap');
    expect(uploadCall?.[1]?.body).toBe(file);
    expect(uploadCall?.[1]?.headers).toEqual(expect.objectContaining({ 'content-type': 'application/vnd.tcpdump.pcap' }));
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
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
