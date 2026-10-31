import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import App from '../src/App';
import { api } from '../src/api';

function openUpload() {
  localStorage.setItem('c2hunter-token', 'test');
  localStorage.setItem('c2hunter-report-language', 'en');
  vi.stubGlobal('fetch', vi.fn(async () => Response.json({ items: [] })));
  return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={['/analyses/upload']}><App/></MemoryRouter></QueryClientProvider>);
}

it('delayed staged attack upload reaches a preparing report state without losing its owner', async () => {
  const job = { id: 'attack', name: 'Attack triage', status: 'PARSING', source_type: 'PCAP_UPLOAD', analysis: { module: 'ddos_attack' } };
  vi.spyOn(api, 'post').mockResolvedValue({ ...job, status: 'UPLOAD_PENDING' });
  vi.spyOn(api, 'get').mockResolvedValue(job);
  let complete!: (value: typeof job) => void;
  const upload = vi.spyOn(api, 'uploadWithProgress').mockImplementation(() => new Promise(resolve => { complete = resolve; }));
  const { unmount } = openUpload();
  fireEvent.click(screen.getByRole('button', { name: 'Offline attack triage' }));
  fireEvent.change(screen.getByLabelText('Analysis name'), { target: { value: job.name } });
  const file = new File(['pcap'], 'test.pcap');
  fireEvent.change(screen.getByLabelText('Capture file'), { target: { files: [file] } });
  fireEvent.submit(screen.getByLabelText('Analysis name').closest('form')!);
  await waitFor(() => expect(upload).toHaveBeenCalledTimes(1));
  expect(upload.mock.calls[0][0]).toBe('/pcap-analysis-jobs/attack/capture');
  expect(upload.mock.calls[0][1]).toBe(file);
  expect(screen.getByRole('button', { name: 'Uploading and analyzing…' })).toBeDisabled();
  await act(async () => { complete(job); });
  await screen.findByRole('heading', { name: 'Preparing DDoS analysis' });
  expect(screen.queryByText('Unsupported analysis module.')).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Cancel analysis' })).toBeEnabled();
  unmount();
});

it('explicit attack entry retires a pending C2 upload without accepting its late completion', async () => {
  let complete!: (value: { id: string }) => void;
  vi.spyOn(api, 'post').mockResolvedValue({ id: 'old-c2' });
  const upload = vi.spyOn(api, 'uploadWithProgress').mockImplementation(() => new Promise(resolve => { complete = resolve; }));
  openUpload();
  fireEvent.change(screen.getByLabelText('Analysis name'), { target: { value: 'C2' } });
  fireEvent.change(screen.getByLabelText('Capture file'), { target: { files: [new File(['pcap'], 'test.pcap')] } });
  fireEvent.submit(screen.getByLabelText('Analysis name').closest('form')!);
  await waitFor(() => expect(upload).toHaveBeenCalledTimes(1));
  fireEvent.click(screen.getByRole('button', { name: 'Offline attack triage' }));
  await act(async () => { complete({ id: 'old-c2' }); });
  expect(screen.getByRole('heading', { name: 'Upload PCAP' })).toBeVisible();
  expect(screen.getByLabelText('Analysis module')).toHaveValue('ddos_attack');
  expect(screen.getByRole('button', { name: 'Upload and analyze' })).toBeEnabled();
});

it('explains the separate normal-reference purpose before selecting a dataset', () => {
  openUpload();
  fireEvent.click(screen.getByRole('button', { name: 'Offline attack triage' }));
  fireEvent.click(screen.getByText('Advanced DDoS thresholds and optional normal reference'));
  expect(screen.getByText(/same-capture low-traffic buckets/)).toBeVisible();
  expect(screen.getByText(/candidate predicate evaluation.*does not upgrade flood likelihood/)).toBeVisible();
  expect(screen.getByText('False positives remain unmeasured, not zero.')).toBeVisible();
});

it('explicit offline attack entry keeps legacy C2 default and submits mounted advanced defaults with protected CIDRs', async () => {
  const post = vi.spyOn(api, 'post').mockResolvedValue({ id: 'attack' });
  vi.spyOn(api, 'uploadWithProgress').mockRejectedValue(new Error('Retained test upload'));
  openUpload();
  expect(screen.getByLabelText('Analysis module')).toHaveValue('c2');
  fireEvent.click(screen.getByRole('button', { name: 'Offline attack triage' }));
  expect(screen.getByLabelText('Analysis module')).toHaveValue('ddos_attack');
  expect(screen.getByText(/not a general intrusion detector/)).toBeVisible();
  expect(screen.getByText(/public IPv4.*\/32.*IPv6/)).toBeVisible();
  const advanced = screen.getByText('Advanced DDoS thresholds and optional normal reference').closest('details')!;
  expect(advanced).not.toHaveAttribute('open');
  expect(advanced.querySelectorAll('input[type="number"]')).toHaveLength(15);
  expect(screen.getByLabelText('Minimum packets')).toHaveValue(1000);
  expect(screen.getByLabelText('Normal reference action')).toHaveValue('clear');
  fireEvent.change(screen.getByLabelText('Analysis name'), { target: { value: 'Attack triage' } });
  fireEvent.change(screen.getByLabelText('Capture file'), { target: { files: [new File(['pcap'], 'test.pcap')] } });
  fireEvent.change(screen.getByLabelText('Protected-side networks'), { target: { value: '203.0.113.80/32,2001:db8::/64' } });
  fireEvent.submit(screen.getByLabelText('Analysis name').closest('form')!);
  await screen.findByText('Retained test upload');
  expect(post.mock.calls[0][1]).toMatchObject({
    analysis_module: 'ddos_attack', internal_networks: ['203.0.113.80/32', '2001:db8::/64'],
    analysis: { module: 'ddos_attack', ddos_bucket_seconds: 1, ddos_min_duration_seconds: 3, ddos_min_source_count: 20,
      ddos_min_packet_count: 1000, ddos_min_packets_per_second: 100, ddos_min_bits_per_second: 1000000,
      ddos_baseline_min_buckets: 20, ddos_baseline_ratio: 5, ddos_mad_z_threshold: 6,
      ddos_protocol_share_threshold: 0.8, ddos_tcp_flag_share_threshold: 0.8, ddos_response_ratio_max: 0.2,
      ddos_reflection_port_share_threshold: 0.6, ddos_reflection_min_average_packet_bytes: 256, ddos_overlap_window_seconds: 10 },
  });
  expect(post.mock.calls[0][1]).not.toHaveProperty('analysis.detector_weights');
  advanced.open = true;
  fireEvent.change(screen.getByLabelText('Minimum packets'), { target: { value: '1234' } });
  advanced.open = false;
  fireEvent.submit(screen.getByLabelText('Analysis name').closest('form')!);
  await waitFor(() => expect(post).toHaveBeenCalledTimes(2));
  expect(post.mock.calls[1][1]).toHaveProperty('analysis.ddos_min_packet_count', 1234);
});
