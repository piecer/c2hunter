import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
import App from '../src/App';
import { readFileSync } from 'node:fs';
import DDoSNormalReference from '../src/DDoSNormalReference';
import { ddosReferenceParameters } from '../src/ddosReferenceRequest';

it('keeps inheritance distinct from clear and an explicitly asserted paginated selection', async () => {
  localStorage.setItem('c2hunter-report-language', 'en');
  const urls: string[] = [];
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    urls.push(url);
    const second = url.includes('page=2');
    return new Response(JSON.stringify({ items: [{ id: second ? 'normal-2' : 'self', dataset_id: second ? 'normal-data-2' : 'self-data', name: 'Known normal', status: 'COMPLETED' }], total: 21, page: second ? 2 : 1, page_size: 20 }));
  }));
  const { container } = render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><form><DDoSNormalReference inherit datasetId="self-data"/></form></QueryClientProvider>);
  const payload = () => ddosReferenceParameters(new FormData(container.querySelector('form')!));
  expect(payload()).toEqual({});
  expect(urls).toEqual([]);
  fireEvent.change(screen.getByLabelText('Normal reference action'), { target: { value: 'clear' } });
  expect(payload()).toEqual({ ddos_normal_reference: null });
  fireEvent.change(screen.getByLabelText('Normal reference action'), { target: { value: 'select' } });
  await screen.findByText('self-data');
  expect(screen.getByRole('radio')).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Next reference page' }));
  await screen.findByText('normal-data-2');
  fireEvent.click(screen.getByRole('radio'));
  expect(payload()).toEqual({ ddos_normal_reference: { job_id: 'normal-2', dataset_id: 'normal-data-2' } });
  expect(screen.getByText(/server validates eligibility/)).toBeVisible();
  await waitFor(() => expect(urls).toHaveLength(2));
  expect(urls.every(url => url.includes('page_size=20'))).toBe(true);
  expect(screen.getAllByRole('radio')).toHaveLength(1);
});

it.each(['/analyses/new', '/analyses/upload', '/analyses/owner'])('wires explicit reference at top level on %s and keeps server errors visible', async route => {
  localStorage.setItem('c2hunter-token', 'test-token');
  localStorage.setItem('c2hunter-report-language', 'en');
  const requests: { path: string; body: Record<string, unknown> }[] = [];
  const report = JSON.parse(readFileSync('tests/fixtures/ddos-report-contract.json', 'utf8'));
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    if (init?.method === 'POST') {
      requests.push({ path: url, body: JSON.parse(String(init.body)) });
      return Response.json({ error: { code: 'DDOS_REFERENCE_RECORD_LIMIT', message: 'Reference exceeds private record limit' } }, { status: 422 });
    }
    if (url.includes('analysis-jobs?')) return Response.json({ items: [{ id: 'normal', dataset_id: 'normal-data', name: 'Normal', status: 'COMPLETED' }], page: 1, page_size: 20, total: 1 });
    if (url.endsWith('/analysis-jobs/owner')) return Response.json({ id: 'owner', dataset_id: 'owner-data', name: 'Owner', status: 'COMPLETED', analysis: { module: 'ddos_attack' }, ddos_attack: report });
    return Response.json({ items: [] });
  }));
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={[route]}><App/></MemoryRouter></QueryClientProvider>);
  if (route !== '/analyses/owner') {
    fireEvent.change(screen.getByLabelText('Analysis name'), { target: { value: 'Reference test' } });
    fireEvent.change(screen.getByLabelText('Analysis module'), { target: { value: 'ddos_attack' } });
    if (route.endsWith('upload')) fireEvent.change(screen.getByLabelText('Capture file'), { target: { files: [new File(['pcap'], 'owned.pcap')] } });
  }
  fireEvent.change(await screen.findByLabelText('Normal reference action'), { target: { value: 'select' } });
  fireEvent.click(await screen.findByRole('radio'));
  const form = screen.getByLabelText('Normal reference action').closest('form')!;
  fireEvent.submit(form);
  await waitFor(() => expect(requests).toHaveLength(1));
  expect(requests[0].body.ddos_normal_reference).toEqual({ job_id: 'normal', dataset_id: 'normal-data' });
  expect(JSON.stringify(requests[0].body.analysis ?? {})).not.toContain('ddos_normal_reference');
  expect(await screen.findByText('Reference exceeds private record limit')).toBeVisible();
  fireEvent.submit(form);
  await waitFor(() => expect(requests).toHaveLength(2));
  expect(requests[1].body).toEqual(requests[0].body);
  await screen.findByText('Reference exceeds private record limit');
  fireEvent.change(screen.getByLabelText('Normal reference action'), { target: { value: 'clear' } });
  fireEvent.submit(form);
  await waitFor(() => expect(requests).toHaveLength(3));
  expect(requests[2].body.ddos_normal_reference).toBeNull();
  expect(requests[2].body.idempotency_key).not.toBe(requests[0].body.idempotency_key);
});

it('changing only report language does not retire an unchanged pending request', async () => {
  localStorage.setItem('c2hunter-token', 'test-token'); localStorage.setItem('c2hunter-report-language', 'en');
  let finish!: (response: Response) => void;
  const pending = new Promise<Response>(resolve => { finish = resolve; });
  const report = JSON.parse(readFileSync('tests/fixtures/ddos-report-contract.json', 'utf8'));
  const post = vi.fn(() => pending);
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    if (init?.method === 'POST') return post();
    if (url === '/api/v1/analysis-jobs/owner' || url === '/api/v1/analysis-jobs/created') return Response.json({ id: url.endsWith('created') ? 'created' : 'owner', name: url.endsWith('created') ? 'Created after language change' : 'Owner', dataset_id: 'owner-data', status: 'COMPLETED', analysis: { module: 'ddos_attack' }, ddos_attack: report });
    return Response.json({ items: [] });
  }));
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={['/analyses/owner']}><App/></MemoryRouter></QueryClientProvider>);
  const form = (await screen.findByLabelText('Normal reference action')).closest('form')!;
  fireEvent.submit(form); await waitFor(() => expect(post).toHaveBeenCalledOnce());
  fireEvent.change(form.querySelector('select:not([name])')!, { target: { value: 'ko' } });
  finish(Response.json({ id: 'created' }));
  expect(await screen.findByRole('heading', { name: 'Created after language change' })).toBeVisible();
});

it.each(['/analyses/new', '/analyses/upload'])('a late DDoS admission cannot publish after the module changes on %s', async route => {
  localStorage.setItem('c2hunter-token', 'test-token'); localStorage.setItem('c2hunter-report-language', 'en');
  let finish!: (response: Response) => void;
  const pending = new Promise<Response>(resolve => { finish = resolve; });
  const calls: string[] = [];
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    calls.push(url);
    if (init?.method === 'POST') return pending;
    if (url.endsWith('/late-created')) return Response.json({ id: 'late-created', name: 'Wrong owner', status: 'COMPLETED', analysis: { module: 'ddos_attack' } });
    return Response.json({ items: [] });
  }));
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={[route]}><App/></MemoryRouter></QueryClientProvider>);
  fireEvent.change(screen.getByLabelText('Analysis name'), { target: { value: 'Owned request' } });
  fireEvent.change(screen.getByLabelText('Analysis module'), { target: { value: 'ddos_attack' } });
  if (route.endsWith('upload')) fireEvent.change(screen.getByLabelText('Capture file'), { target: { files: [new File(['owned'], 'owned.pcap')] } });
  const form = screen.getByLabelText('Analysis name').closest('form')!;
  fireEvent.submit(form);
  await waitFor(() => expect(calls.some(path => path === '/api/v1/analysis-jobs' || path === '/api/v1/pcap-analysis-jobs/initiate')).toBe(true));
  fireEvent.change(screen.getByLabelText('Analysis module'), { target: { value: 'c2' } });
  finish(Response.json({ id: 'late-created' }));
  await waitFor(() => expect(form.querySelector(':scope > button:last-child')).not.toBeDisabled());
  expect(screen.getByLabelText('Analysis module')).toHaveValue('c2');
  expect(calls).not.toContain('/api/v1/analysis-jobs/late-created');
  expect(calls).not.toContain('/api/v1/pcap-analysis-jobs/late-created/capture');
});
