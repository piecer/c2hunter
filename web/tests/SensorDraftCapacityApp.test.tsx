import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, expect, it, vi } from 'vitest';
import App from '../src/App';

// Minimal transport fixture for ownership; retained maximum-array suites are unchanged.
const configuration = { config_version: 7, capture_sources: [{ interface: 'eth0', direction: 'INBOUND', bpf_filter: '', enabled: true, store_pcap: false }], internal_networks: ['10.0.0.0/8'] };
const sensors = Array.from({ length: 19 }, (_, i) => ({ ...configuration, sensor_id: `retained-${i}`, name: `Retained sensor ${i}` }));
afterEach(() => vi.unstubAllGlobals());
function mount() {
  const writes: unknown[] = [];
  localStorage.setItem('c2hunter-token', 'retained-app-synthetic');
  vi.stubGlobal('matchMedia', () => ({ matches: false }));
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    const path = new URL(url, 'http://fixture').pathname;
    let body: unknown = { items: [] };
    if (init?.method === 'PUT') { writes.push(JSON.parse(String(init.body))); body = {}; }
    else if (path.endsWith('/configuration')) body = { ...configuration, config_version: 8 };
    else if (path === '/api/v1/sensors') body = { items: sensors };
    else body = sensors.find(sensor => path.endsWith(`/${sensor.sensor_id}`)) ?? body;
    return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/sensors/retained-0']}><App/></MemoryRouter></QueryClientProvider>);
  return writes;
}
async function go(index: number) {
  fireEvent.click(screen.getByRole('link', { name: 'Sensors' }));
  fireEvent.click(await screen.findByRole('link', { name: `Retained sensor ${index}` }));
  await screen.findByRole('heading', { name: `Retained sensor ${index}` });
}
async function edit() { fireEvent.click(await screen.findByRole('button', { name: 'Edit desired configuration' })); }

it('keeps an unconfirmed edited draft through more than sixteen real App detail visits', async () => {
  const writes = mount();
  await edit();
  fireEvent.change(screen.getByLabelText('Desired Internal CIDR 1', { exact: true }), { target: { value: '10.99.0.0/16' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save configuration' }));
  await screen.findByText(/save is unconfirmed/);
  for (let i = 1; i <= 18; i++) await go(i);
  await go(0); await edit();
  expect(screen.getByLabelText('Desired Internal CIDR 1', { exact: true })).toHaveValue('10.99.0.0/16');
  expect(screen.getByText(/save is unconfirmed/)).toBeInTheDocument();
  expect(screen.getByText('Configuration version 7', { exact: true })).toBeInTheDocument();
  expect(writes).toHaveLength(1);
});

it('refuses editing without hiding current facts and frees capacity only by explicit reload', async () => {
  const writes = mount();
  for (let i = 0; i < 16; i++) {
    if (i) await go(i);
    await edit();
    fireEvent.change(screen.getByLabelText('Desired Internal CIDR 1', { exact: true }), { target: { value: `10.${i}.0.0/16` } });
  }
  await go(16);
  expect(screen.getByText('Configuration version 7', { exact: true })).toBeInTheDocument();
  expect(screen.getByText(/16.*unsaved.*pending/)).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Edit desired configuration' })).toBeDisabled();
  expect(screen.queryByLabelText('Desired Internal CIDR 1', { exact: true })).not.toBeInTheDocument();
  expect(writes).toEqual([]);
  await go(0); await edit();
  expect(screen.getByLabelText('Desired Internal CIDR 1', { exact: true })).toHaveValue('10.0.0.0/16');
  fireEvent.click(screen.getByRole('button', { name: 'Reload latest configuration' }));
  await screen.findByText('Configuration version 8', { exact: true });
  expect(screen.getByLabelText('Desired Internal CIDR 1', { exact: true })).toHaveValue('10.0.0.0/8');
  await go(16); await edit();
  fireEvent.change(screen.getByLabelText('Desired Internal CIDR 1', { exact: true }), { target: { value: '10.16.0.0/16' } });
  expect(screen.getByLabelText('Desired Internal CIDR 1', { exact: true })).toHaveValue('10.16.0.0/16');
  await go(1); await edit();
  expect(screen.getByLabelText('Desired Internal CIDR 1', { exact: true })).toHaveValue('10.1.0.0/16');
  expect(writes).toEqual([]);
});
