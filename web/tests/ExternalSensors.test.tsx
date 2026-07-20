import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import App from '../src/App';

const enrollments = {
  items: [
    { id: 'enroll-1', name: 'Edge pending', status: 'PENDING', expires_at: '2026-07-21T10:00:00Z' },
    { id: 'enroll-2', name: 'Branch claimed', status: 'CLAIMED', expires_at: '2026-07-21T10:00:00Z' },
    { id: 'enroll-3', name: 'Old expired', status: 'EXPIRED', expires_at: '2026-07-19T10:00:00Z' },
    { id: 'enroll-4', name: 'Lost revoked', status: 'REVOKED', expires_at: '2026-07-21T10:00:00Z' },
  ],
};

const sensor = {
  sensor_id: 'sensor-a', name: 'External edge', status: 'ONLINE', configuration_version: 7,
  desired_configuration: {
    version: 7,
    capture_sources: [{ interface: 'eth0', direction: 'INBOUND', bpf_filter: 'tcp', enabled: true }],
    internal_networks: ['10.0.0.0/8'],
  },
  observed_configuration: {
    version: 6,
    capture_sources: [{ interface: 'eth0', direction: 'OUTBOUND', bpf_filter: 'udp', enabled: true, status: 'ERROR', received_packets: 120, dropped_packets: 4, last_error: 'permission denied' }],
  },
};

type Handler = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
function renderAt(route: string, handler?: Handler) {
  localStorage.setItem('c2hunter-token', 'token');
  const fetchMock = vi.fn(handler ?? (async input => {
    const path = String(input);
    if (path === '/api/v1/sensor-enrollments') return json(enrollments);
    if (path === '/api/v1/sensors/sensor-a') return json(sensor);
    return json({ error: { message: 'Not found' } }, 404);
  }));
  vi.stubGlobal('fetch', fetchMock);
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}><MemoryRouter initialEntries={[route]}><App /></MemoryRouter></QueryClientProvider>);
  return fetchMock;
}
function json(body: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } }));
}
function bodyOf(fetchMock: ReturnType<typeof vi.fn>, path: string, method: string) {
  const call = fetchMock.mock.calls.find(([url, init]) => url === path && init?.method === method);
  return JSON.parse(String(call?.[1]?.body));
}

afterEach(() => vi.unstubAllGlobals());

describe('External sensor enrollment', () => {
  it('adds accessible navigation and lists all enrollment states', async () => {
    renderAt('/external-sensors');
    const nav = screen.getByRole('navigation', { name: 'Primary' });
    expect(within(nav).getByRole('link', { name: 'External sensors' })).toHaveAttribute('href', '/external-sensors');
    expect(within(nav).getByRole('link', { name: 'Enroll sensor' })).toHaveAttribute('href', '/external-sensors/enroll');
    expect(await screen.findByRole('table', { name: 'External sensor enrollments' })).toBeInTheDocument();
    for (const status of ['PENDING', 'CLAIMED', 'EXPIRED', 'REVOKED']) expect(screen.getByText(status)).toBeInTheDocument();
  });

  it('shows loading, empty, and retryable error states', async () => {
    let finish!: (value: Response) => void;
    const pending = new Promise<Response>(resolve => { finish = resolve; });
    renderAt('/external-sensors', async () => pending);
    expect(screen.getByRole('status')).toHaveTextContent('Loading');
    finish(await json({ items: [] }));
    expect(await screen.findByText('No external sensor enrollments')).toBeInTheDocument();
    cleanup();

    renderAt('/external-sensors', async () => json({ error: { message: 'Enrollment service unavailable' } }, 503));
    expect(await screen.findByRole('alert')).toHaveTextContent('Enrollment service unavailable');
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument();
  });

  it('adds and removes interface and CIDR rows with labelled keyboard-operable controls', async () => {
    renderAt('/external-sensors/enroll');
    const user = userEvent.setup();
    expect(screen.getByLabelText('Interface name 1')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Add interface' }));
    expect(screen.getByLabelText('Interface name 2')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Remove interface 2' }));
    expect(screen.queryByLabelText('Interface name 2')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Add internal network' }));
    expect(screen.getByLabelText('Internal CIDR 2')).toBeInTheDocument();
    screen.getByRole('button', { name: 'Remove internal network 2' }).focus();
    await user.keyboard('{Enter}');
    expect(screen.queryByLabelText('Internal CIDR 2')).not.toBeInTheDocument();
  });

  it('posts the exact enrollment API body and reveals the secret only until dismissed', async () => {
    const fetchMock = renderAt('/external-sensors/enroll', async (input, init) => {
      if (String(input) === '/api/v1/sensor-enrollments' && init?.method === 'POST') return json({ id: 'enroll-new', enrollment_token: 'secret-once', install_command: 'sensor install --token secret-once', expires_at: '2026-07-21T10:00:00Z' }, 201);
      return json({ error: { message: 'Not found' } }, 404);
    });
    const user = userEvent.setup();
    await user.type(screen.getByLabelText('Sensor name'), 'Remote office');
    await user.clear(screen.getByLabelText('Enrollment lifetime (seconds)'));
    await user.type(screen.getByLabelText('Enrollment lifetime (seconds)'), '1800');
    await user.type(screen.getByLabelText('Interface name 1'), 'eth9');
    await user.selectOptions(screen.getByLabelText('Direction 1'), 'BIDIRECTIONAL');
    await user.type(screen.getByLabelText('BPF filter 1'), 'tcp port 443');
    await user.clear(screen.getByLabelText('Internal CIDR 1'));
    await user.type(screen.getByLabelText('Internal CIDR 1'), '10.20.0.0/16');
    await user.click(screen.getByRole('button', { name: 'Create enrollment' }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/v1/sensor-enrollments', expect.objectContaining({ method: 'POST' })));
    expect(bodyOf(fetchMock, '/api/v1/sensor-enrollments', 'POST')).toEqual({
      name: 'Remote office', expires_in_seconds: 1800,
      capture_sources: [{ interface: 'eth9', direction: 'BIDIRECTIONAL', bpf_filter: 'tcp port 443', enabled: true }],
      internal_networks: ['10.20.0.0/16'],
    });
    expect(await screen.findByText('secret-once')).toBeInTheDocument();
    expect(screen.getByText(/shown only once/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Copy enrollment token' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Copy install command' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'I have stored these credentials' }));
    expect(screen.queryByText('secret-once')).not.toBeInTheDocument();
    expect(screen.getByText(/cannot be shown again/i)).toBeInTheDocument();
  });
});

describe('External sensor configuration and credentials', () => {
  it('shows desired versus observed config plus per-interface telemetry', async () => {
    renderAt('/sensors/sensor-a');
    expect(await screen.findByRole('heading', { name: 'External edge' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Desired configuration' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Observed configuration' })).toBeInTheDocument();
    expect(within(screen.getByRole('table', { name: 'Observed interface status' })).getByText('OUTBOUND')).toBeInTheDocument();
    expect(screen.getByText('ERROR')).toBeInTheDocument();
    expect(screen.getByText('120 received / 4 dropped')).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent('permission denied');
  });

  it('saves with expected_version and reports an optimistic version conflict', async () => {
    const fetchMock = renderAt('/sensors/sensor-a', async (input, init) => {
      if (String(input) === '/api/v1/sensors/sensor-a' && !init?.method) return json(sensor);
      if (String(input) === '/api/v1/sensors/sensor-a/configuration' && init?.method === 'PUT') return json({ error: { code: 'VERSION_CONFLICT', message: 'Configuration was changed by another operator' } }, 409);
      return json({}, 200);
    });
    const user = userEvent.setup();
    await screen.findByRole('heading', { name: 'Desired configuration' });
    await user.selectOptions(screen.getByLabelText('Desired direction 1'), 'OUTBOUND');
    await user.click(screen.getByRole('button', { name: 'Save configuration' }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/v1/sensors/sensor-a/configuration', expect.objectContaining({ method: 'PUT' })));
    expect(bodyOf(fetchMock, '/api/v1/sensors/sensor-a/configuration', 'PUT')).toEqual({
      config_version: 7,
      capture_sources: [{ interface: 'eth0', direction: 'OUTBOUND', bpf_filter: 'tcp', enabled: true }],
      internal_networks: ['10.0.0.0/8'],
    });
    expect(await screen.findByText(/changed by another operator/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Reload latest configuration' })).toBeInTheDocument();
  });

  it('requires confirmations before rotating or revoking credentials and calls exact endpoints', async () => {
    const fetchMock = renderAt('/sensors/sensor-a', async (input, init) => {
      if (String(input) === '/api/v1/sensors/sensor-a' && !init?.method) return json(sensor);
      if (init?.method === 'POST') return json({ status: 'ok' });
      return json({}, 200);
    });
    const user = userEvent.setup();
    await screen.findByRole('heading', { name: 'External edge' });
    await user.click(screen.getByRole('button', { name: 'Rotate credential' }));
    expect(screen.getByRole('dialog', { name: 'Rotate sensor credential' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Confirm rotate' }));
    await user.click(screen.getByRole('button', { name: 'Revoke credential' }));
    expect(screen.getByRole('dialog', { name: 'Revoke sensor credential' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Confirm revoke' }));
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith('/api/v1/sensors/sensor-a/credentials/rotate', expect.objectContaining({ method: 'POST' }));
      expect(fetchMock).toHaveBeenCalledWith('/api/v1/sensors/sensor-a/revoke', expect.objectContaining({ method: 'POST' }));
    });
  });
});
