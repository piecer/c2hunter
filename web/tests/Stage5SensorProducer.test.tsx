import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, expect, it, vi } from 'vitest';
import App from '../src/App';
import { sensorProducer, sensorProducerPage } from './stage5SensorFixture';

function mount(path: string) {
  localStorage.setItem('c2hunter-token', 'synthetic-producer');
  const fetcher = vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    const body = sensorProducerPage(url) ?? (url === `/api/v1/sensors/${sensorProducer.maximum.sensor_id}` ? sensorProducer.maximum : url === '/api/v1/analysis-jobs/synthetic-job' ? { id: 'synthetic-job', name: 'Synthetic job', status: 'COMPLETED' } : { items: [] });
    return new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' } });
  });
  vi.stubGlobal('fetch', fetcher);
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={[path]}><App/></MemoryRouter></QueryClientProvider>);
  return fetcher;
}
afterEach(() => vi.unstubAllGlobals());
it('renders model-valid public maximum desired/actual facts with all data retained', async () => {
  mount(`/sensors/${sensorProducer.maximum.sensor_id}`);
  expect(sensorProducer.denied_operations).toEqual([]);
  expect(sensorProducer.maximum.capture_sources).toHaveLength(128);
  expect(sensorProducer.maximum.internal_networks).toHaveLength(1024);
  await screen.findByText('synthetic-error-0');
  await userEvent.click(screen.getByRole('button', { name: 'Edit desired configuration' }));
  expect(screen.getAllByLabelText(/^Desired interface name /)).toHaveLength(8);
  expect(screen.getAllByLabelText(/^Desired Internal CIDR /)).toHaveLength(32);
});
it('pages every analysis-linked PCAP using the public producer metadata', async () => {
  const fetcher = mount('/analyses/synthetic-job');
  await userEvent.click(await screen.findByRole('button', { name: '작업 정보' }));
  const seen: string[] = [];
  for (let page = 1; page <= 6; page++) {
    const table = await screen.findByRole('table', { name: 'Analysis PCAP archives' });
    const files = within(table).getAllByText(/^synthetic-\d+\.pcap$/);
    seen.push(...files.map(file => file.textContent!));
    if (page < 6) fireEvent.click(within(screen.getByRole('navigation', { name: 'Analysis PCAP pages' })).getByRole('button', { name: 'Next page' }));
  }
  expect(seen).toEqual(Array.from({ length: 251 }, (_, i) => `synthetic-${String(i).padStart(3, '0')}.pcap`));
  expect(fetcher.mock.calls.some(([url]) => String(url).includes('page=6&page_size=50'))).toBe(true);
});
it('applies operational sensor status and PCAP sensor/job filters to server queries', async () => {
  const fetcher = mount('/sensors');
  await screen.findByRole('table', { name: 'Sensors' });
  await userEvent.selectOptions(screen.getByLabelText('Sensor status'), 'ERROR');
  expect(await screen.findByText('Page 1 of 1 · 1 records')).toBeInTheDocument();
  expect(fetcher).toHaveBeenCalledWith('/api/v1/sensors?status=ERROR&page=1&page_size=50', expect.anything());
});
it('keeps full archive identifiers and recorded enrollment dates accessible', async () => {
  mount('/sensor-pcaps');
  const table = await screen.findByRole('table', { name: 'Sensor PCAP archives' });
  const first = within(table).getAllByRole('row')[1];
  const record = sensorProducerPage('/api/v1/sensor-pcaps')!.items[0];
  expect(first).toHaveTextContent(String(record.id));
  expect(first).toHaveTextContent(String(record.sensor_id));
  expect(first).toHaveTextContent(String(record.sha256));
});
it('renders enrollment registration and claim/revocation truth without inventing dates', async () => {
  mount('/external-sensors');
  const table = await screen.findByRole('table', { name: 'External sensor enrollments' });
  const row = within(table).getAllByRole('row')[1];
  const first = sensorProducerPage('/api/v1/sensor-enrollments')!.items[0];
  expect(row).toHaveTextContent(`Created ${new Date(String(first.created_at)).toLocaleString()}`);
  expect(row).toHaveTextContent('Claimed Not reported');
  expect(row).toHaveTextContent('Revoked Not reported');
});
it('sends literal archive filters on every page', async () => {
  const fetcher = mount('/sensor-pcaps');
  await screen.findByRole('table', { name: 'Sensor PCAP archives' });
  fireEvent.change(screen.getByLabelText('Sensor ID filter'), { target: { value: sensorProducer.maximum.sensor_id } });
  fireEvent.change(screen.getByLabelText('Analysis job ID filter'), { target: { value: 'synthetic-job' } });
  await userEvent.click(screen.getByRole('button', { name: 'Apply archive filters' }));
  await screen.findByRole('table', { name: 'Sensor PCAP archives' });
  await userEvent.click(screen.getByRole('button', { name: 'Last page' }));
  await screen.findByText('synthetic-250.pcap');
  expect(fetcher).toHaveBeenCalledWith(`/api/v1/sensor-pcaps?sensor_id=${sensorProducer.maximum.sensor_id}&analysis_job_id=synthetic-job&page=6&page_size=50`, expect.anything());
});
