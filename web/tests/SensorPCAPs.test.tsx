import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, expect, it, vi } from 'vitest';
import App from '../src/App';

function json(body: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } }));
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

it('lists sensor PCAP archives from navigation and downloads with API authentication', async () => {
  localStorage.setItem('c2hunter-token', 'operator-token');
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path === '/api/v1/sensor-pcaps') {
      return json({
        items: [{ id: 'segment-a', sensor_id: 'sensor-a', sensor_name: 'Edge sensor', analysis_job_id: 'job-a', filename: 'job-a--eth0-000001.pcap', size_bytes: 24, uploaded_at: '2026-08-01T01:02:03Z' }],
        total: 1,
        page: 1,
        page_size: 50,
      });
    }
    if (path === '/api/v1/sensor-pcaps/segment-a/download') {
      expect(new Headers(init?.headers).get('authorization')).toBe('Bearer operator-token');
      return new Response(new Blob(['pcap']), { status: 200, headers: { 'content-type': 'application/vnd.tcpdump.pcap', 'content-disposition': 'attachment; filename="eth0-000001.pcap"' } });
    }
    return json({ error: { message: 'Not found' } }, 404);
  });
  vi.stubGlobal('fetch', fetchMock);
  vi.stubGlobal('URL', { createObjectURL: vi.fn(() => 'blob:pcap'), revokeObjectURL: vi.fn() });
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);

  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter initialEntries={['/sensor-pcaps']}><App /></MemoryRouter>
    </QueryClientProvider>,
  );

  const nav = screen.getByRole('navigation', { name: 'Primary' });
  expect(within(nav).getByRole('link', { name: 'Sensor PCAPs' })).toHaveAttribute('href', '/sensor-pcaps');
  expect(await screen.findByText('Edge sensor')).toBeInTheDocument();
  expect(screen.getByRole('link', { name: 'job-a' })).toHaveAttribute('href', '/analyses/job-a');
  expect(screen.getByText('job-a--eth0-000001.pcap')).toBeInTheDocument();

  await userEvent.click(screen.getByRole('button', { name: 'Download job-a--eth0-000001.pcap' }));
  await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
    '/api/v1/sensor-pcaps/segment-a/download',
    expect.objectContaining({ headers: expect.objectContaining({ authorization: 'Bearer operator-token' }) }),
  ));
});

it('shows and downloads only PCAP archives linked to the current analysis', async () => {
  localStorage.setItem('c2hunter-token', 'operator-token');
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path === '/api/v1/analysis-jobs/job-a') return json({ id: 'job-a', name: 'Analysis A', status: 'COMPLETED', packet_count: 100, flow_count: 10, candidate_count: 0 });
    if (path === '/api/v1/analysis-jobs/job-a/candidates?page_size=200') return json({ items: [] });
    if (path.startsWith('/api/v1/analysis-jobs/job-a/flows?')) return json({ items: [], page: 1, page_size: 50, total: 0 });
    if (path === '/api/v1/detector-weight-presets') return json({ items: [] });
    if (path === '/api/v1/sensor-pcaps?analysis_job_id=job-a&page_size=200') return json({
      items: [
        { id: 'segment-a', sensor_id: 'sensor-a', sensor_name: 'Edge sensor', analysis_job_id: 'job-a', filename: 'job-a--eth0-000001.pcap', size_bytes: 24, uploaded_at: '2026-08-01T01:02:03Z' },
      ],
    });
    if (path === '/api/v1/sensor-pcaps/segment-a/download') {
      expect(new Headers(init?.headers).get('authorization')).toBe('Bearer operator-token');
      return new Response(new Blob(['pcap']), { status: 200, headers: { 'content-type': 'application/vnd.tcpdump.pcap' } });
    }
    return json({ error: { message: 'Not found' } }, 404);
  });
  vi.stubGlobal('fetch', fetchMock);
  vi.stubGlobal('URL', { createObjectURL: vi.fn(() => 'blob:pcap'), revokeObjectURL: vi.fn() });
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);

  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter initialEntries={['/analyses/job-a']}><App /></MemoryRouter>
    </QueryClientProvider>,
  );

  expect(await screen.findByRole('heading', { name: '분석 PCAP' })).toBeInTheDocument();
  expect(await screen.findByText('job-a--eth0-000001.pcap')).toBeInTheDocument();
  expect(screen.queryByText('job-b--eth1-000001.pcap')).not.toBeInTheDocument();
  expect(fetchMock).toHaveBeenCalledWith(
    '/api/v1/sensor-pcaps?analysis_job_id=job-a&page_size=200',
    expect.any(Object),
  );
  await userEvent.click(screen.getByRole('button', { name: 'Download job-a--eth0-000001.pcap' }));
  await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
    '/api/v1/sensor-pcaps/segment-a/download',
    expect.objectContaining({ headers: expect.objectContaining({ authorization: 'Bearer operator-token' }) }),
  ));
});
