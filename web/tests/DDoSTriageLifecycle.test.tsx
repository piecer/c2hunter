import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { readFileSync } from 'node:fs';
import { MemoryRouter } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import App from '../src/App';
import { api } from '../src/api';

const report = JSON.parse(readFileSync('tests/fixtures/ddos-report-contract.json', 'utf8'));
const baseJob = { id: 'triage', name: 'Triage job', source_type: 'PCAP_UPLOAD', analysis: { module: 'ddos_attack' } };
function openJob() {
  localStorage.setItem('c2hunter-token', 'test');
  localStorage.setItem('c2hunter-report-language', 'en');
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/analyses/triage']}><App/></MemoryRouter></QueryClientProvider>);
  return { ...view, client };
}

it.each([
  ['UPLOAD_PENDING', 'Awaiting capture upload'], ['PARSING', 'Preparing DDoS analysis'],
  ['INGESTING', 'Preparing DDoS analysis'], ['ANALYZING', 'DDoS analysis in progress'],
  ['FAILED', 'DDoS analysis failed'], ['CANCELLED', 'DDoS analysis cancelled'],
  ['COMPLETED', 'DDoS report unavailable'], ['PARTIALLY_COMPLETED', 'DDoS report unavailable'],
])('known DDoS %s without report has a truthful lifecycle state', async (status, heading) => {
  vi.spyOn(api, 'get').mockResolvedValue({ ...baseJob, status, transitions: [{ to_status: status, reason: 'Recorded lifecycle reason' }] });
  const { unmount, client } = openJob();
  await screen.findByRole('heading', { name: heading });
  expect(screen.queryByText('Unsupported analysis module.')).not.toBeInTheDocument();
  expect(screen.queryByText(/No clear DDoS attack observed/)).not.toBeInTheDocument();
  if (status === 'FAILED' || status === 'CANCELLED') expect(screen.getByText('Recorded lifecycle reason')).toBeVisible();
  if (['COMPLETED', 'PARTIALLY_COMPLETED', 'FAILED', 'CANCELLED'].includes(status)) expect(screen.queryByRole('button', { name: 'Cancel analysis' })).not.toBeInTheDocument();
  else expect(screen.getByRole('button', { name: 'Cancel analysis' })).toBeEnabled();
  expect(api.get).not.toHaveBeenCalledWith(expect.stringContaining('/candidates'));
  unmount(); client.clear();
});

it('keeps cancellation and refetch on the same pending DDoS owner', async () => {
  const get = vi.spyOn(api, 'get').mockResolvedValue({ ...baseJob, status: 'ANALYZING' });
  const post = vi.spyOn(api, 'post').mockResolvedValue({});
  const { unmount, client } = openJob();
  await screen.findByRole('heading', { name: 'DDoS analysis in progress' });
  get.mockResolvedValue({ ...baseJob, status: 'CANCELLED' });
  fireEvent.click(screen.getByRole('button', { name: 'Cancel analysis' }));
  await screen.findByRole('heading', { name: 'DDoS analysis cancelled' });
  expect(post).toHaveBeenCalledWith('/analysis-jobs/triage/cancel', { reason: 'operator requested from web console' });
  unmount(); client.clear();
});

it('polls a pending DDoS owner into its completed report and stops polling at terminal', async () => {
  const get = vi.spyOn(api, 'get').mockResolvedValue({ ...baseJob, status: 'PARSING' });
  const { unmount, client } = openJob();
  await screen.findByRole('heading', { name: 'Preparing DDoS analysis' });
  const before = get.mock.calls.length;
  get.mockImplementation(async path => path === '/analysis-jobs/triage' ? { ...baseJob, status: 'COMPLETED', ddos_attack: report } : { items: [] });
  await waitFor(() => expect(screen.getByRole('region', { name: 'DDoS at a glance' })).toBeVisible(), { timeout: 4500 });
  expect(get.mock.calls.filter(([path]) => path === '/analysis-jobs/triage').length).toBeGreaterThan(before);
  expect(screen.queryByText('Unsupported analysis module.')).not.toBeInTheDocument();
  const terminalCalls = get.mock.calls.filter(([path]) => path === '/analysis-jobs/triage').length;
  await act(async () => { await new Promise(resolve => setTimeout(resolve, 3100)); });
  expect(get.mock.calls.filter(([path]) => path === '/analysis-jobs/triage')).toHaveLength(terminalCalls);
  unmount(); client.clear();
}, 10000);
