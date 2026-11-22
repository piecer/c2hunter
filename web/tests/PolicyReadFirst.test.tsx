import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import App from '../src/App';

const signatures = Array.from({ length: 45 }, (_, index) => ({
  id: `signature-full-identifier-${index}`, name: `Beacon ${index}`, description: 'Confirmed beacon',
  version: 2, enabled: true, source_job_id: 'job-full', source_flow_id: `flow-full-${index}`, source_label_id: 'label-full',
  payload_hash: `${String(index).padStart(2, '0')}${'abcdef'.repeat(10)}ff`, payload_prefix_hash: 'prefix-full', payload_simhash: 'simhash-full',
  length_tolerance_ratio: 0.1, entropy_tolerance: 0.2, simhash_max_distance: 3,
  created_at: '2026-07-20T10:00:00Z', ...(index === 0 ? { updated_at: '2026-07-21T11:00:00Z' } : {}),
}));
function mount(path: string, fetcher: (url: string, init?: RequestInit) => Promise<Response>) {
  localStorage.setItem('c2hunter-token', 'policy-test');
  const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => fetcher(String(input), init));
  vi.stubGlobal('fetch', fetchMock);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><App/></MemoryRouter></QueryClientProvider>);
  return { fetchMock, client };
}
it('reads full signature values and recorded dates across actual server pages without writes', async () => {
  const { fetchMock } = mount('/payload-signatures', async url => {
    const query = new URL(url, 'http://fixture').searchParams;
    const page = Number(query.get('page') ?? 1), size = Number(query.get('page_size') ?? 50);
    return Response.json({ items: signatures.slice((page - 1) * size, page * size), total: signatures.length, page, page_size: size });
  });
  await screen.findByText('Beacon 0');
  expect(screen.getByText(signatures[0].payload_hash)).toBeVisible();
  expect(screen.getByText(signatures[0].id)).toBeVisible();
  expect(screen.getAllByText('prefix-full')[0]).toBeVisible();
  expect(screen.getAllByText('simhash-full')[0]).toBeVisible();
  expect(screen.getAllByText('label-full')[0]).toBeVisible();
  expect(screen.getAllByRole('link', { name: 'Source analysis job-full' })[0]).toBeVisible();
  const row = screen.getByText('Beacon 0').closest('tr')!;
  expect(within(row).getByText(/Registered/)).toHaveTextContent(new Date(signatures[0].created_at).toLocaleString());
  expect(within(row).getByText(/Changed/)).toHaveTextContent(new Date(signatures[0].updated_at!).toLocaleString());
  expect(within(screen.getByText('Beacon 1').closest('tr')!).getByText(/Changed/)).toHaveTextContent('Not reported');
  const seen: string[] = [];
  for (let page = 1; page <= 5; page++) {
    await screen.findByText(`Beacon ${(page - 1) * 10}`);
    const rows = within(screen.getByRole('table', { name: 'Payload signatures' })).getAllByRole('row').slice(1);
    expect(rows.length).toBeLessThanOrEqual(10);
    for (const row of rows) seen.push(within(row).getByText(/^signature-full-identifier-/).textContent!);
    expect(document.querySelectorAll('*').length).toBeLessThanOrEqual(1200);
    if (page < 5) fireEvent.click(screen.getByRole('button', { name: 'Next policy page' }));
  }
  expect(seen).toEqual(signatures.map(item => item.id));
  expect(fetchMock.mock.calls.every(([, init]) => !init?.method || init.method === 'GET')).toBe(true);
});

it('keeps allowlist read-first and every full-array record reachable before explicit creation', async () => {
  const entries = Array.from({ length: 45 }, (_, i) => ({ id: `entry-full-${i}`, type: 'TLS_FINGERPRINT', value: `${i}-${'f'.repeat(64)}`, enabled: true, description: `Exception ${i}`, created_at: '2026-07-20T10:00:00Z', expires_at: '2027-07-20T10:00:00Z' }));
  const { fetchMock } = mount('/allowlist', async () => Response.json(entries));
  await screen.findByText('Exception 0');
  expect(screen.queryByRole('textbox', { name: 'Value' })).not.toBeInTheDocument();
  const seen: string[] = [];
  for (let page = 1; page <= 5; page++) {
    await screen.findByText(`Exception ${(page - 1) * 10}`);
    for (const row of screen.getAllByRole('listitem')) {
      seen.push(within(row).getByText(/^entry-full-/).textContent!);
      expect(within(row).getByText(/Registered/)).toHaveTextContent(new Date(entries[0].created_at).toLocaleString());
      expect(within(row).getByText(/Changed/)).toHaveTextContent('Not reported');
      expect(within(row).getByText(/Expires/)).toHaveTextContent(new Date(entries[0].expires_at).toLocaleString());
    }
    expect(document.querySelectorAll('*').length).toBeLessThanOrEqual(1200);
    if (page < 5) fireEvent.click(screen.getByRole('button', { name: 'Next policy page' }));
  }
  expect(seen).toEqual(entries.map(item => item.id));
  fireEvent.click(screen.getByRole('button', { name: 'Create entry' }));
  expect(screen.getByRole('textbox', { name: 'Value' })).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Cancel creation' }));
  expect(screen.queryByRole('textbox', { name: 'Value' })).not.toBeInTheDocument();
  expect(fetchMock.mock.calls.every(([, init]) => !init?.method)).toBe(true);
});

const settings = {
  version: 7, virustotal_enabled: true, abuseipdb_enabled: true, misp_enabled: true,
  misp_url: 'https://misp.example', misp_verify_tls: false, threat_intel_timeout_seconds: 20,
  threat_intel_request_delay_seconds: 0.5, abuseipdb_max_age_days: 30, abuseipdb_positive_threshold: 40,
  candidate_auto_enrichment_enabled: true, candidate_auto_enrichment_limit: 50, candidate_auto_enrichment_workers: 1,
  candidate_auto_enrichment_queue_capacity: 100, management_event_id: 'full-management-event', management_auto_register: true,
  immediate_action_event_id: 'full-action-event', immediate_action_auto_register: true, immediate_action_min_positive_providers: 2,
  updated_at: '2026-07-21T11:00:00Z', updated_by: 'operator',
};
it('reads integration policy without credentials and explicitly edits the loaded version through 409', async () => {
  const { fetchMock } = mount('/settings/integrations', async (_url, init) => init?.method === 'PUT'
    ? Response.json({ error: { code: 'VERSION_CONFLICT', message: 'Settings changed elsewhere' } }, { status: 409 })
    : Response.json({ ...settings, api_key: 'DO-NOT-RENDER-KEY' }));
  await screen.findByText('full-management-event');
  expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
  expect(document.body).not.toHaveTextContent('DO-NOT-RENDER-KEY');
  expect(screen.getByText(/TLS verification is disabled/)).toBeVisible();
  expect(screen.getByText(/Automatic registration can write/)).toBeVisible();
  expect(screen.getByText(/Changed/)).toHaveTextContent(new Date(settings.updated_at).toLocaleString());
  fireEvent.click(screen.getByRole('button', { name: 'Edit integration settings' }));
  fireEvent.change(screen.getByLabelText('관리 Event ID'), { target: { value: 'edited-event' } });
  fireEvent.click(screen.getByRole('button', { name: '설정 저장' }));
  await screen.findByText('Settings changed elsewhere');
  const put = fetchMock.mock.calls.find(([, init]) => init?.method === 'PUT')!;
  expect(JSON.parse(String(put[1]?.body))).toMatchObject({ expected_version: 7, management_event_id: 'edited-event', misp_verify_tls: false });
  expect(screen.getByLabelText('관리 Event ID')).toHaveValue('edited-event');
  fireEvent.click(screen.getByRole('button', { name: 'Cancel editing' }));
  expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
  expect(fetchMock.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(1);
});
