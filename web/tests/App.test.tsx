import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import App from '../src/App';

const responses: Record<string, unknown> = {
  '/api/v1/analysis-jobs': { items: [{ id: 'job-1', name: 'Investigation', status: 'ANALYZING', candidate_count: 2 }] },
  '/api/v1/sensors': { items: [{ sensor_id: 'sensor-a', name: 'Sensor A', status: 'ONLINE', last_heartbeat: '2026-07-20T10:00:00Z', interfaces: [{ name: 'eth0', direction: 'INBOUND' }], version: '0.1.0', cpu_percent: 10, memory_percent: 20, disk_percent: 30, received_packets: 1000, dropped_packets: 2 }, { sensor_id: 'sensor-b', name: 'Sensor B', status: 'ONLINE', interfaces: [{ name: 'eth1', direction: 'OUTBOUND' }] }] },
  '/api/v1/analysis-jobs/job-1': { id: 'job-1', name: 'Investigation', status: 'ANALYZING' },
  '/api/v1/candidates/candidate-1': { id: 'candidate-1', job_id: 'job-1', candidate_ip: '203.0.113.9', score: 80, severity: 'HIGH', distinct_internal_hosts: 4, sensor_ids: ['sensor-a'], protocols: ['TCP'], ports: [443], first_seen: '2026-07-20T10:00:00Z', last_seen: '2026-07-20T10:05:00Z', evidence: [{ type: 'PERIODIC_BEACON', score: 40, description: 'Periodic traffic' }] },
};

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

  it('renders an error state with retry when a request fails', async () => {
    localStorage.setItem('c2hunter-token', 'token');
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: { message: 'Storage unavailable' } }), { status: 503, headers: { 'content-type': 'application/json' } })));
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={['/']}><App /></MemoryRouter></QueryClientProvider>);
    expect(await screen.findByRole('alert')).toHaveTextContent('Storage unavailable');
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument();
  });

  it('submits every required Controller analysis field', async () => {
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

    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/v1/analysis-jobs/job-1/reanalyze', expect.objectContaining({ method: 'POST' })));
    const exportCall = fetchMock.mock.calls.find(([url]) => url === '/api/v1/pcap-exports');
    expect(JSON.parse(String(exportCall?.[1]?.body))).toEqual({ job_id: 'job-1', candidate_id: 'candidate-1' });
    const reanalyzeCall = fetchMock.mock.calls.find(([url]) => url === '/api/v1/analysis-jobs/job-1/reanalyze');
    expect(JSON.parse(String(reanalyzeCall?.[1]?.body))).toEqual({ idempotency_key: expect.any(String) });
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
});
