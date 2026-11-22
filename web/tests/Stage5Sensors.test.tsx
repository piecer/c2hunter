import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, expect, it, vi } from 'vitest';
import App from '../src/App';

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
afterEach(() => vi.unstubAllGlobals());
function mount(route: string, handler: (url: string, init?: RequestInit) => Response | Promise<Response>) {
  localStorage.setItem('c2hunter-token', 'stage5-synthetic');
  vi.stubGlobal('matchMedia', () => ({ matches: false }));
  const fetcher = vi.fn((url: RequestInfo | URL, init?: RequestInit) => Promise.resolve(handler(String(url), init)));
  vi.stubGlobal('fetch', fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[route]}><App/></MemoryRouter></QueryClientProvider>);
  return { fetcher, client };
}

it.each([
  ['/sensors', '/api/v1/sensors', 'Sensors', (i: number) => ({ sensor_id: `sensor-${i}`, name: `record-${i}`, derived_status: 'ONLINE' })],
  ['/external-sensors', '/api/v1/sensor-enrollments', 'External sensor enrollments', (i: number) => ({ enrollment_id: `enrollment-${i}`, name: `record-${i}`, status: 'PENDING', expires_at: '2027-01-01T00:00:00Z' })],
  ['/sensor-pcaps', '/api/v1/sensor-pcaps', 'Sensor PCAP archives', (i: number) => ({ id: `pcap-${i}`, sensor_id: 'sensor-a', filename: `record-${i}`, size_bytes: 24, uploaded_at: '2026-11-22T00:00:00Z' })],
] as const)('reaches all 251 records through actual page metadata on %s', async (route, endpoint, table, record) => {
  const all = Array.from({ length: 251 }, (_, i) => record(i));
  const { fetcher } = mount(route, url => {
    const parsed = new URL(url, 'http://fixture');
    if (parsed.pathname !== endpoint) return json({ items: [] });
    const page = Number(parsed.searchParams.get('page') ?? 1);
    const size = Number(parsed.searchParams.get('page_size') ?? 50);
    expect(size).toBe(50);
    return json({ items: all.slice((page - 1) * size, page * size), page, page_size: size, total: all.length });
  });
  const reached: string[] = [];
  for (let page = 1; page <= 6; page++) {
    const current = await screen.findByRole('table', { name: table });
    for (const row of within(current).getAllByRole('row').slice(1)) reached.push(within(row).getByText(/^record-/).firstChild!.textContent!);
    if (page < 6) fireEvent.click(screen.getByRole('button', { name: 'Next page' }));
  }
  expect(reached).toEqual(all.map((_, i) => `record-${i}`));
  expect(screen.getByRole('button', { name: 'Next page' })).toBeDisabled();
  expect(fetcher.mock.calls.every(([, init]) => !init?.method)).toBe(true);
});

// UI transport fixtures are synthetic; maximum model/public API fixtures are separate.
export const syntheticSensor = (count = 9, cidrs = 33) => ({
  sensor_id: 'sensor-a', name: 'Synthetic sensor', config_version: 7, agent_version: 'actual-agent-1',
  capture_sources: Array.from({ length: count }, (_, i) => ({ interface: `eth${i}`, direction: 'INBOUND', bpf_filter: '', enabled: true, store_pcap: false })),
  internal_networks: Array.from({ length: cidrs }, (_, i) => `10.${Math.floor(i / 256)}.${i % 256}.0/24`),
  interfaces: Array.from({ length: count }, (_, i) => ({ interface: `eth${i}`, direction: 'OUTBOUND', status: 'ERROR', received_packets: i, dropped_packets: 1, last_error: `actual-error-${i}` })),
});

it('shows actual heartbeat first and lazily traverses maximum desired arrays without writes', async () => {
  const sensor = syntheticSensor(128, 1024);
  const { fetcher } = mount('/sensors/sensor-a', () => json(sensor));
  await screen.findByRole('heading', { name: 'Synthetic sensor' });
  expect(screen.getByText('actual-agent-1')).toBeInTheDocument();
  expect(screen.getByText('actual-error-0')).toBeInTheDocument();
  expect(screen.queryByLabelText('Desired interface name 1')).not.toBeInTheDocument();
  expect(within(screen.getByRole('table', { name: 'Observed interface status' })).getAllByRole('row')).toHaveLength(9);
  expect(document.querySelectorAll('*').length).toBeLessThanOrEqual(1200);
  await userEvent.click(screen.getByRole('button', { name: 'Edit desired configuration' }));
  expect(screen.getAllByLabelText(/^Desired interface name /)).toHaveLength(8);
  expect(screen.getAllByLabelText(/^Desired Internal CIDR /)).toHaveLength(32);
  for (const label of ['Desired interfaces pages', 'Desired networks pages', 'Observed interfaces pages']) {
    fireEvent.click(within(screen.getByRole('navigation', { name: label })).getByRole('button', { name: 'Last page' }));
  }
  expect(screen.getByLabelText('Desired interface name 128')).toHaveValue('eth127');
  expect(screen.getByLabelText('Desired Internal CIDR 1024')).toHaveValue('10.3.255.0/24');
  expect(screen.getByText('actual-error-127')).toBeInTheDocument();
  expect(document.querySelectorAll('*').length).toBeLessThanOrEqual(2500);
  await userEvent.click(screen.getByRole('button', { name: 'Close desired configuration' }));
  expect(screen.queryByLabelText('Desired interface name 128')).not.toBeInTheDocument();
  expect(fetcher.mock.calls.every(([, init]) => !init?.method)).toBe(true);
});

it.each(['', '   '])('validates full desired arrays before PUT and recovers without dropping off-page entries (%j)', async blank => {
  const sensor = syntheticSensor();
  const writes: typeof sensor[] = [];
  mount('/sensors/sensor-a', (_url, init) => {
    if (init?.method === 'PUT') { const body = JSON.parse(String(init.body)); writes.push(body); return json({ ...body, config_version: 8 }); }
    return json(sensor);
  });
  await userEvent.click(await screen.findByRole('button', { name: 'Edit desired configuration' }));
  const page = (label: string, name: string) => fireEvent.click(within(screen.getByRole('navigation', { name: label })).getByRole('button', { name }));
  page('Desired interfaces pages', 'Last page');
  fireEvent.change(screen.getByLabelText('Desired interface name 9'), { target: { value: blank } });
  page('Desired interfaces pages', 'First page');
  await userEvent.click(screen.getByRole('button', { name: 'Save configuration' }));
  expect(writes).toHaveLength(0);
  expect(screen.getByText('Interface name 9 is required.')).toBeInTheDocument();
  page('Desired interfaces pages', 'Last page');
  fireEvent.change(screen.getByLabelText('Desired interface name 9'), { target: { value: 'eth8' } });
  page('Desired networks pages', 'Last page');
  fireEvent.change(screen.getByLabelText('Desired Internal CIDR 33'), { target: { value: blank } });
  page('Desired networks pages', 'First page');
  await userEvent.click(screen.getByRole('button', { name: 'Save configuration' }));
  expect(writes).toHaveLength(0);
  expect(screen.getByText('Internal CIDR 33 is required.')).toBeInTheDocument();
  page('Desired networks pages', 'Last page');
  fireEvent.change(screen.getByLabelText('Desired Internal CIDR 33'), { target: { value: ' 10.0.32.0/24 ' } });
  page('Desired networks pages', 'First page');
  await userEvent.click(screen.getByRole('button', { name: 'Save configuration' }));
  expect(writes).toEqual([{ config_version: 7, capture_sources: sensor.capture_sources, internal_networks: sensor.internal_networks }]);
  await screen.findByText('Configuration saved.');
  await userEvent.click(screen.getByRole('button', { name: 'Close desired configuration' }));
  await userEvent.click(screen.getByRole('button', { name: 'Edit desired configuration' }));
  expect(screen.queryByText(/is required\./)).not.toBeInTheDocument();
});

it.each(['', '   '])('validates full enrollment arrays before POST and preserves 9/33 entries (%j)', async blank => {
  const writes: unknown[] = [];
  mount('/external-sensors/enroll', (_url, init) => { if (init?.method === 'POST') writes.push(JSON.parse(String(init.body))); return json({ enrollment_token: 'synthetic', install_command: 'synthetic', expires_at: '2027-01-01T00:00:00Z' }); });
  fireEvent.change(screen.getByLabelText('Sensor name'), { target: { value: 'Synthetic enrollment' } });
  for (let i = 1; i <= 9; i++) {
    if (i > 1) fireEvent.click(screen.getByRole('button', { name: 'Add interface' }));
    fireEvent.change(screen.getByLabelText(`Interface name ${i}`), { target: { value: i === 9 ? blank : `eth${i - 1}` } });
  }
  const page = (label: string, name: string) => fireEvent.click(within(screen.getByRole('navigation', { name: label })).getByRole('button', { name }));
  page('Capture interfaces pages', 'First page');
  await userEvent.click(screen.getByRole('button', { name: 'Create enrollment' }));
  expect(writes).toHaveLength(0);
  expect(screen.getByText('Interface name 9 is required.')).toBeInTheDocument();
  page('Capture interfaces pages', 'Last page');
  fireEvent.change(screen.getByLabelText('Interface name 9'), { target: { value: 'eth8' } });
  for (let i = 1; i <= 33; i++) {
    if (i > 1) fireEvent.click(screen.getByRole('button', { name: 'Add internal network' }));
    fireEvent.change(screen.getByLabelText(`Internal CIDR ${i}`), { target: { value: i === 33 ? blank : `10.0.${i - 1}.0/24` } });
  }
  page('Capture networks pages', 'First page');
  await userEvent.click(screen.getByRole('button', { name: 'Create enrollment' }));
  expect(writes).toHaveLength(0);
  expect(screen.getByText('Internal CIDR 33 is required.')).toBeInTheDocument();
  page('Capture networks pages', 'Last page');
  fireEvent.change(screen.getByLabelText('Internal CIDR 33'), { target: { value: ' 10.0.32.0/24 ' } });
  await userEvent.click(screen.getByRole('button', { name: 'Create enrollment' }));
  expect(writes).toEqual([{ name: 'Synthetic enrollment', expires_in_seconds: 3600, capture_sources: syntheticSensor().capture_sources, internal_networks: syntheticSensor().internal_networks }]);
  expect(await screen.findByText(/shown only once/)).toBeInTheDocument();
});

it('retains exact owner across pending close/reopen and A-B-A, pins version until explicit reload', async () => {
  let finish!: (value: Response) => void;
  const pending = new Promise<Response>(resolve => { finish = resolve; });
  const sensor = syntheticSensor(1, 1);
  const writes: { config_version: number; capture_sources: { bpf_filter: string }[] }[] = [];
  const { client } = mount('/sensors/sensor-a', (url, init) => {
    if (init?.method === 'PUT') { writes.push(JSON.parse(String(init.body))); return writes.length === 1 ? pending : json({ ...JSON.parse(String(init.body)), config_version: 12 }); }
    if (url.endsWith('/configuration')) return json({ ...sensor, config_version: 11 });
    if (url === '/api/v1/sensors') return json({ items: [sensor, { ...sensor, sensor_id: 'sensor-b', name: 'Sensor B' }] });
    return json(url.endsWith('sensor-b') ? { ...sensor, sensor_id: 'sensor-b', name: 'Sensor B' } : sensor);
  });
  const edit = async () => userEvent.click(await screen.findByRole('button', { name: 'Edit desired configuration' }));
  const go = async (name: string) => { await userEvent.click(screen.getByRole('link', { name: 'Sensors' })); await userEvent.click(await screen.findByRole('link', { name })); };
  await edit();
  fireEvent.change(screen.getByLabelText('Desired BPF filter 1'), { target: { value: 'tcp' } });
  act(() => { client.setQueryData<unknown>(['sensor', 'sensor-a'], { ...sensor, config_version: 10 }); });
  await userEvent.click(screen.getByRole('button', { name: 'Save configuration' }));
  expect(writes[0].config_version).toBe(7);
  await userEvent.click(screen.getByRole('button', { name: 'Close desired configuration' }));
  expect(screen.getByText('Saving configuration…')).toBeInTheDocument();
  await edit();
  expect(screen.getByRole('button', { name: 'Saving…' })).toBeDisabled();
  await go('Sensor B'); await edit();
  expect(screen.getByLabelText('Desired BPF filter 1')).toHaveValue('');
  await go('Synthetic sensor'); await edit();
  expect(screen.getByLabelText('Desired BPF filter 1')).toHaveValue('tcp');
  expect(screen.getByRole('button', { name: 'Saving…' })).toBeDisabled();
  await act(async () => finish(json({ error: { message: 'Another operator changed this configuration' } }, 409)));
  expect(await screen.findByText('Configuration conflict')).toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Reload latest configuration' }));
  expect(await screen.findByText('Configuration version 11')).toBeInTheDocument();
  expect(screen.getByLabelText('Desired BPF filter 1')).toHaveValue('');
  await userEvent.click(screen.getByRole('button', { name: 'Save configuration' }));
  expect(writes[1].config_version).toBe(11);
  await screen.findByText('Configuration saved.');
});

it('bounds add/remove at legal maxima and retains global indexes at page boundaries', async () => {
  mount('/sensors/sensor-a', () => json(syntheticSensor(128, 1024)));
  await userEvent.click(await screen.findByRole('button', { name: 'Edit desired configuration' }));
  expect(screen.getByRole('button', { name: 'Add desired interface' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Add desired internal network' })).toBeDisabled();
  const interfaces = screen.getByRole('navigation', { name: 'Desired interfaces pages' });
  fireEvent.click(within(interfaces).getByRole('button', { name: 'Last page' }));
  fireEvent.click(screen.getByRole('button', { name: 'Remove desired interface 128' }));
  expect(screen.queryByLabelText('Desired interface name 128')).not.toBeInTheDocument();
  expect(screen.getByLabelText('Desired interface name 127')).toHaveValue('eth126');
  fireEvent.click(screen.getByRole('button', { name: 'Add desired interface' }));
  expect(screen.getByLabelText('Desired interface name 128')).toHaveValue('');
  fireEvent.click(within(screen.getByRole('navigation', { name: 'Desired networks pages' })).getByRole('button', { name: 'Last page' }));
  fireEvent.click(screen.getByRole('button', { name: 'Remove internal network 1024' }));
  expect(screen.getByLabelText('Desired Internal CIDR 1023')).toHaveValue('10.3.254.0/24');
  fireEvent.click(screen.getByRole('button', { name: 'Add desired internal network' }));
  expect(screen.getByLabelText('Desired Internal CIDR 1024')).toHaveValue('');
});

it('shows observed interfaces even when no desired configuration has been reported', async () => {
  const sensor = syntheticSensor(1, 1);
  mount('/sensors/sensor-a', () => json({ sensor_id: sensor.sensor_id, name: sensor.name, agent_version: sensor.agent_version, interfaces: sensor.interfaces }));
  expect(await screen.findByText('actual-error-0')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Edit desired configuration' })).not.toBeInTheDocument();
});

it('retires a pending DDoS intent when the selected sensors change', async () => {
  let finish!: (response: Response) => void;
  const pending = new Promise<Response>(resolve => { finish = resolve; });
  mount('/analyses/new', (url, init) => {
    if (url === '/api/v1/analysis-jobs' && init?.method === 'POST') return pending;
    if (url === '/api/v1/sensors') return json({ items: [{ sensor_id: 'a', name: 'Sensor A' }] });
    if (url === '/api/v1/analysis-jobs/stale-job') return json({ id: 'stale-job', name: 'STALE NAVIGATION', status: 'COMPLETED' });
    return json({ items: [] });
  });
  await userEvent.type(screen.getByLabelText('Analysis name'), 'Synthetic DDoS');
  await userEvent.selectOptions(screen.getByLabelText('Analysis module'), 'ddos_attack');
  await userEvent.click(await screen.findByRole('checkbox', { name: 'Sensor A' }));
  await userEvent.click(screen.getByRole('button', { name: 'Start analysis' }));
  await screen.findByRole('button', { name: 'Starting…' });
  await userEvent.click(screen.getByRole('checkbox', { name: 'Sensor A' }));
  await act(async () => finish(json({ id: 'stale-job', name: 'STALE NAVIGATION', status: 'COMPLETED' })));
  expect(screen.getByRole('heading', { name: 'New analysis' })).toBeInTheDocument();
  expect(screen.queryByRole('heading', { name: 'STALE NAVIGATION' })).not.toBeInTheDocument();
});

it('offers explicit reload after an unconfirmed configuration receipt without auto retry', async () => {
  const sensor = syntheticSensor(1, 1);
  const { fetcher } = mount('/sensors/sensor-a', (url, init) => {
    if (init?.method === 'PUT') return json({});
    return json(url.endsWith('/configuration') ? { ...sensor, config_version: 8 } : sensor);
  });
  await userEvent.click(await screen.findByRole('button', { name: 'Edit desired configuration' }));
  await userEvent.click(screen.getByRole('button', { name: 'Save configuration' }));
  await screen.findByText(/save is unconfirmed/);
  expect(screen.queryByText('Configuration saved.')).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Reload latest configuration' }));
  expect(await screen.findByText('Configuration version 8')).toBeInTheDocument();
  expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(1);
});

it('keeps a bounded explicit sensor selector and submits cross-page full sensor_ids', async () => {
  let submitted: { sensor_ids: string[] } | undefined;
  mount('/analyses/new', (url, init) => {
    if (url === '/api/v1/analysis-jobs' && init?.method === 'POST') { submitted = JSON.parse(String(init.body)); return json({ error: { message: 'Synthetic stop' } }, 422); }
    const parsed = new URL(url, 'http://fixture');
    if (parsed.pathname !== '/api/v1/sensors') return json({ items: [] });
    const page = Number(parsed.searchParams.get('page') ?? 1);
    return json({ items: Array.from({ length: page === 6 ? 1 : 50 }, (_, i) => ({ sensor_id: `sensor-${(page - 1) * 50 + i}`, name: `Sensor ${(page - 1) * 50 + i}` })), page, page_size: 50, total: 251 });
  });
  await userEvent.type(screen.getByLabelText('Analysis name'), 'Synthetic selection');
  await userEvent.click(screen.getByRole('button', { name: 'Choose sensors' }));
  await userEvent.click(await screen.findByRole('checkbox', { name: 'Sensor 0' }));
  await userEvent.click(screen.getByRole('button', { name: 'Last page' }));
  await userEvent.click(await screen.findByRole('checkbox', { name: 'Sensor 250' }));
  await userEvent.click(screen.getByRole('button', { name: 'Done choosing sensors' }));
  expect(screen.queryByRole('checkbox', { name: 'Sensor 250' })).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Start analysis' }));
  expect(submitted?.sensor_ids).toEqual(['sensor-0', 'sensor-250']);
});
