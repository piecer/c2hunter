import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import App from '../src/App';

it('submits network anomaly from the existing new-analysis form', async () => {
  localStorage.setItem('c2hunter-token', 'token');
  let submitted: Record<string, unknown> | undefined;
  vi.stubGlobal('fetch', vi.fn(async (_input, init) => {
    if (init?.method === 'POST') {
      submitted = JSON.parse(init.body);
      return new Response(JSON.stringify({ id: 'network-job', name: 'Network', status: 'CREATED' }));
    }
    return new Response(JSON.stringify({ items: String(_input).endsWith('/sensors') ? [{ sensor_id: 's1', name: 'Sensor' }] : [] }));
  }));
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={['/analyses/new']}><App/></MemoryRouter></QueryClientProvider>);
  fireEvent.change(screen.getByLabelText('Analysis name'), { target: { value: 'Network' } });
  fireEvent.change(screen.getByLabelText('Analysis module'), { target: { value: 'network_anomaly' } });
  fireEvent.click(await screen.findByLabelText('Sensor'));
  fireEvent.submit(screen.getByLabelText('Analysis name').closest('form')!);
  await waitFor(() => expect(submitted?.analysis).toMatchObject({ module: 'network_anomaly' }));
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
  expect(await screen.findByRole('table', { name: 'Bidirectional network flows' })).toBeInTheDocument();
  expect(screen.getByText('10.0.0.1:50000')).toBeInTheDocument();
  expect(screen.getByText('SYN retries')).toBeInTheDocument();
  expect(screen.getByRole('table', { name: 'Bidirectional network flows' }).querySelector('.structured-fields')).toBeNull();
  expect(screen.getByText('INCOMPLETE_PACKET_EVIDENCE')).toBeInTheDocument();
  expect(screen.queryByText('Run AI analysis')).not.toBeInTheDocument();
  expect(screen.queryByRole('table', { name: 'Analysis candidates' })).not.toBeInTheDocument();
});
