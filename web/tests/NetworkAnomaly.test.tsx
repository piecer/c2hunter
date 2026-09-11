import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, expect, it, vi } from 'vitest';

beforeEach(() => localStorage.setItem('c2hunter-report-language', 'en'));
import userEvent from '@testing-library/user-event';
import App from '../src/App';

it('submits network anomaly from the existing new-analysis form', async () => {
  localStorage.setItem('c2hunter-token', 'token');
  let submitted: Record<string, unknown> | undefined;
  vi.stubGlobal('fetch', vi.fn(async (_input, init) => {
    if (init?.method === 'POST') {
      submitted = JSON.parse(init.body);
      return new Response(JSON.stringify({ id: 'network-job', name: 'Network', status: 'CREATED' }));
    }
    if (String(_input).endsWith('/analysis-jobs/network-job')) return new Response(JSON.stringify({ id: 'network-job', name: 'Network', status: 'CREATED', analysis: { module: 'network_anomaly' } }));
    return new Response(JSON.stringify({ items: String(_input).endsWith('/sensors') ? [{ sensor_id: 's1', name: 'Sensor' }] : [] }));
  }));
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={['/analyses/new']}><App/></MemoryRouter></QueryClientProvider>);
  fireEvent.change(screen.getByLabelText('Analysis name'), { target: { value: 'Network' } });
  fireEvent.change(screen.getByLabelText('Analysis module'), { target: { value: 'network_anomaly' } });
  fireEvent.click(await screen.findByLabelText('Sensor'));
  fireEvent.submit(screen.getByLabelText('Analysis name').closest('form')!);
  await waitFor(() => expect(submitted?.analysis).toEqual({ module: 'network_anomaly' }));
});

it.each(['/analyses/new', '/analyses/upload'])('isolates network controls and retains C2 settings on %s', async route => {
  localStorage.setItem('c2hunter-token', 'token');
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const fetcher = vi.fn(async () => new Response(JSON.stringify({ items: [] })));
  vi.stubGlobal('fetch', fetcher);
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[route]}><App/></MemoryRouter></QueryClientProvider>);
  const module = screen.getByLabelText('Analysis module');
  expect(module).toHaveValue('c2');
  const score = screen.getByLabelText('Minimum score');
  expect(score).toHaveValue(route.endsWith('new') ? 50 : 0);
  fireEvent.change(score, { target: { value: '71' } });
  const weight = screen.getAllByRole('spinbutton', { name: /가중치/ })[0];
  fireEvent.change(weight, { target: { value: '1.5' } });
  const ml = screen.getByLabelText('후보군 대비 이상 통신 탐지 사용');
  fireEvent.click(ml);
  await waitFor(() => expect(client.isFetching()).toBe(0));
  fireEvent.change(module, { target: { value: 'network_anomaly' } });
  expect(score).not.toBeVisible();
  expect(score).toBeDisabled();
  expect(weight).not.toBeVisible();
  expect(ml).not.toBeVisible();
  expect(screen.getByRole('heading', { name: 'Network observations and capture evidence' })).toBeVisible();
  const calls = fetcher.mock.calls.length;
  await client.invalidateQueries({ queryKey: ['detector-weight-presets'] });
  expect(fetcher.mock.calls).toHaveLength(calls);
  const form = new FormData(screen.getByLabelText('Analysis name').closest('form')!);
  for (const name of ['score', 'hosts', 'samples', 'ml_anomaly_enabled', 'detector_weights_explicit']) expect(form.has(name)).toBe(false);
  fireEvent.change(module, { target: { value: 'c2' } });
  expect(score).toBeVisible();
  expect(score).toHaveValue(71);
  expect(weight).toHaveValue(1.5);
  expect(ml).toBeChecked();
});

it('uploads network evidence without C2 query settings even when C2 inputs are invalid', async () => {
  localStorage.setItem('c2hunter-token', 'token');
  let query: URLSearchParams | undefined;
  vi.stubGlobal('fetch', vi.fn(async (input, init) => {
    if (init?.method === 'POST') {
      query = new URL(String(input), 'http://localhost').searchParams;
      return new Response(JSON.stringify({ detail: 'Test keeps form open' }), { status: 400 });
    }
    return new Response(JSON.stringify({ items: [] }));
  }));
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={['/analyses/upload']}><App/></MemoryRouter></QueryClientProvider>);
  fireEvent.change(screen.getByLabelText('Analysis name'), { target: { value: 'Network capture' } });
  await userEvent.upload(screen.getByLabelText('Capture file'), new File(['pcap'], 'test.pcap'));
  fireEvent.change(screen.getByLabelText('Minimum score'), { target: { value: '999' } });
  fireEvent.change(screen.getAllByRole('spinbutton', { name: /가중치/ })[0], { target: { value: '1.5' } });
  fireEvent.change(screen.getByLabelText('Analysis module'), { target: { value: 'network_anomaly' } });
  expect((screen.getByLabelText('Minimum score') as HTMLInputElement).willValidate).toBe(false);
  fireEvent.submit(screen.getByLabelText('Analysis name').closest('form')!);
  await waitFor(() => expect(query?.get('analysis_module')).toBe('network_anomaly'));
  expect([...query!.keys()].sort()).toEqual(['analysis_module', 'description', 'filename', 'idempotency_key', 'internal_networks', 'name']);
});

it('explains the workflow without inventing network stage percentages', async () => {
  localStorage.setItem('c2hunter-token', 'token');
  vi.stubGlobal('fetch', vi.fn(async input => new Response(JSON.stringify(String(input) === '/api/v1/analysis-jobs/running-network' ? { id: 'running-network', name: 'Running network', status: 'ANALYZING', analysis: { module: 'network_anomaly' } } : { items: [] }))));
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={['/analyses/running-network']}><App/></MemoryRouter></QueryClientProvider>);
  expect(await screen.findByRole('heading', { name: 'Running network' })).toBeVisible();
  expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
  expect(screen.getByText(/Pattern scan → detailed analysis/)).toBeVisible();
});

it('shows independent bidirectional network observations instead of C2 controls', async () => {
  localStorage.setItem('c2hunter-token', 'token');
  vi.stubGlobal('fetch', vi.fn(async input => new Response(JSON.stringify(
    String(input) === '/api/v1/analysis-jobs/network-job' ? {
      id: 'network-job', name: 'Network', status: 'COMPLETED', analysis: { module: 'network_anomaly' },
      network_anomaly: { version: 'network-anomaly-v1', summary: { flow_count: 1 }, warnings: ['INCOMPLETE_RECORDS'], limitations: ['Single-vantage observations do not prove loss.'],
        flows: [{ sensor_id: 's1', interface_id: 0, protocol: 'TCP', endpoint_a: { ip: '10.0.0.1', port: 50000 }, endpoint_b: { ip: '203.0.113.1', port: 443 }, observed_directions: { a_to_b: { packets: 3, bytes: 180 }, b_to_a: { packets: 1, bytes: 60 } }, metrics: { syn_retransmissions: 2, duplicate_acks: 0, observed_rtt_ms: { count: 0, mean: null } }, warnings: ['INCOMPLETE_PACKET_EVIDENCE'] }] },
    } : { items: [] }
  ))));
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={['/analyses/network-job']}><App/></MemoryRouter></QueryClientProvider>);
  expect(await screen.findByRole('heading', { name: 'Legacy report' })).toBeVisible();
  expect(screen.queryByRole('table', { name: 'Bidirectional network flows' })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Show legacy flow observations' }));
  expect(await screen.findByRole('table', { name: 'Bidirectional network flows' })).toBeInTheDocument();
  expect(screen.getByText('10.0.0.1:50000')).toBeInTheDocument();
  expect(screen.getByText('SYN retries')).toBeInTheDocument();
  expect(screen.getByRole('table', { name: 'Bidirectional network flows' }).querySelector('.structured-fields')).toBeNull();
  expect(screen.getByText(/INCOMPLETE_PACKET_EVIDENCE/)).toBeInTheDocument();
  expect(screen.queryByText('Candidates', { selector: 'span', exact: true })).not.toBeInTheDocument();
  expect(screen.getByText('Observed bidirectional flows')).toBeInTheDocument();
  expect(screen.queryByText('최소 후보 점수')).not.toBeInTheDocument();
  expect(screen.queryByText('Run AI analysis')).not.toBeInTheDocument();
  expect(screen.queryByRole('table', { name: 'Analysis candidates' })).not.toBeInTheDocument();
});
