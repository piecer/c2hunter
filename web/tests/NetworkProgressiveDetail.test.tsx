import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { act, fireEvent, render, screen, within, waitFor } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Link, MemoryRouter } from 'react-router-dom';
import App from '../src/App';
import NetworkAnomalyPanel, { type NetworkAnomalyReport } from '../src/NetworkAnomalyPanel';

const python = process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python');
const reports = JSON.parse(execFileSync(python, ['tests/network_report_fixture.py'], { encoding: 'utf8' })) as Record<string, NetworkAnomalyReport>;
const icmpBundle = JSON.parse(execFileSync(python, ['tests/network_icmp_fixture.py'], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 }));
beforeEach(() => localStorage.setItem('c2hunter-report-language', 'en'));
it('opens explanation before one explicitly selected example and measurement detail', () => {
  render(<NetworkAnomalyPanel report={reports.supporting}/>);
  fireEvent.click(screen.getAllByRole('button', { name: /Inspect evidence/ })[0]);
  const explanation = screen.getByRole('region', { name: 'Representative flow evidence' });
  expect(explanation).toHaveFocus();
  for (const name of ['Possible cause — hypothesis', 'Representative proof', 'Uncertainty', 'Next checks']) expect(within(explanation).getByRole('heading', { name })).toBeVisible();
  expect(screen.queryByRole('region', { name: 'Supporting measurements' })).not.toBeInTheDocument();
  expect(screen.queryByText('tcp_sequence: 104')).not.toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Representative example'), { target: { value: '0' } });
  expect(screen.getByText('tcp_sequence: 104')).toBeVisible();
  expect(screen.queryByRole('region', { name: 'Supporting measurements' })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Full measurements' }));
  expect(screen.getAllByRole('region', { name: 'Supporting measurements' })).toHaveLength(1);
  expect(screen.getByRole('region', { name: 'Supporting measurements' })).toHaveTextContent('100 / 100 / 100');
  fireEvent.click(screen.getByRole('button', { name: 'Close example detail' }));
  expect(screen.queryByRole('region', { name: 'Supporting measurements' })).not.toBeInTheDocument();
  expect(screen.getByLabelText('Representative example')).toHaveFocus();
});

it('selects a single measurement kind without losing coverage, exclusions or raw zeros', () => {
  render(<NetworkAnomalyPanel report={reports.supporting}/>);
  fireEvent.click(screen.getAllByRole('button', { name: /Inspect evidence/ })[0]);
  fireEvent.change(screen.getByLabelText('Representative example'), { target: { value: '0' } });
  fireEvent.click(screen.getByRole('button', { name: 'RTT' }));
  const detail = screen.getByRole('region', { name: 'Supporting measurements' });
  expect(detail).toHaveTextContent('100 / 100 / 100');
  expect(detail).toHaveTextContent('Excluded candidate matches: ambiguous / retransmitted 1');
  expect(detail).toHaveTextContent('Measurement coverage: Complete');
  expect(detail).not.toHaveTextContent('Interarrival dispersion (ms)');
  expect(detail).not.toHaveTextContent('IPv4 TTL / IPv6 Hop Limit');
  fireEvent.click(screen.getByRole('button', { name: 'Packet spacing' }));
  expect(detail).toHaveTextContent('47.140452');
  expect(detail).not.toHaveTextContent('Observed RTT (ms)');
  fireEvent.click(screen.getByRole('button', { name: 'TTL / Hop Limit' }));
  expect(detail).toHaveTextContent('changes 0 · missing 0');
  expect(detail).not.toHaveTextContent('Interarrival dispersion (ms)');
  fireEvent.click(screen.getByRole('button', { name: 'TTL / Hop Limit' }));
  expect(screen.queryByRole('region', { name: 'Supporting measurements' })).not.toBeInTheDocument();
});

it('keeps original example ordinals after invalid siblings and retires local state on A→B→A', () => {
  const report = structuredClone(reports.supporting);
  report.issues![0].examples.unshift({ ...structuredClone(report.issues![0].examples[0]), event_count: -1 });
  const { rerender } = render(<NetworkAnomalyPanel report={report} job={{ id: 'A', status: 'COMPLETED' }}/>);
  fireEvent.click(screen.getAllByRole('button', { name: /Inspect evidence/ })[0]);
  const selector = screen.getByLabelText('Representative example');
  expect(within(selector).getAllByRole('option')).toHaveLength(2);
  expect(within(selector).getAllByRole('option')[1]).toHaveTextContent(/^2\./);
  fireEvent.change(selector, { target: { value: '1' } });
  expect(screen.getByText('tcp_sequence: 104')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Full measurements' }));
  rerender(<NetworkAnomalyPanel report={report} job={{ id: 'B', status: 'COMPLETED' }}/>);
  expect(screen.queryByRole('region', { name: 'Selected representative example' })).not.toBeInTheDocument();
  rerender(<NetworkAnomalyPanel report={report} job={{ id: 'A', status: 'COMPLETED' }}/>);
  fireEvent.click(screen.getAllByRole('button', { name: /Inspect evidence/ })[0]);
  expect(screen.getByLabelText('Representative example')).toHaveValue('');
  expect(screen.queryByRole('region', { name: 'Supporting measurements' })).not.toBeInTheDocument();
});

it('keeps ICMP events and measurements mutually exclusive and resets event selection per example', () => {
  const bundle = icmpBundle;
  render(<NetworkAnomalyPanel report={bundle.maximum}/>);
  fireEvent.click(screen.getAllByRole('button', { name: /Inspect evidence/ })[0]);
  fireEvent.change(screen.getByLabelText('Representative example'), { target: { value: '0' } });
  fireEvent.click(screen.getByRole('button', { name: 'Full measurements' }));
  fireEvent.click(screen.getByRole('button', { name: 'ICMP event details' }));
  expect(screen.queryByRole('region', { name: 'Supporting measurements' })).not.toBeInTheDocument();
  expect(screen.getByText(/Outer reporter:/)).toHaveTextContent(bundle.maximum.issues[0].examples[0].icmp_details.samples[0].reporter_ip);
  fireEvent.click(screen.getByRole('button', { name: 'Next event detail' }));
  fireEvent.change(screen.getByLabelText('Representative example'), { target: { value: '9' } });
  expect(screen.queryByText(/Outer reporter:/)).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'ICMP event details' }));
  expect(screen.getByText(/Outer reporter:/)).toHaveTextContent(bundle.maximum.issues[0].examples[9].icmp_details.samples[0].reporter_ip);
  fireEvent.click(screen.getByRole('button', { name: 'Full measurements' }));
  expect(screen.queryByText(/Outer reporter:/)).not.toBeInTheDocument();
  expect(screen.getByRole('region', { name: 'Supporting measurements' })).toBeVisible();
});

it('keeps cached B selection authoritative when an abandoned A response arrives late in the actual App', async () => {
  localStorage.setItem('c2hunter-token', 'progressive-fixture');
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  const job = (id: string, report: NetworkAnomalyReport) => ({ id, name: id, status: 'COMPLETED', analysis: { module: 'network_anomaly' }, network_anomaly: report });
  const b = job('progressive-b', reports.supporting);
  client.setQueryData(['job', b.id], b);
  let finishA!: (value: Response) => void;
  const delayedA = new Promise<Response>(resolve => { finishA = resolve; });
  const calls: string[] = [];
  vi.stubGlobal('fetch', vi.fn(async (input: unknown, init?: RequestInit) => {
    const path = String(input); calls.push(`${init?.method ?? 'GET'} ${path}`);
    if (path.endsWith('/analysis-jobs/progressive-a')) return delayedA;
    if (path.endsWith('/analysis-jobs/progressive-b')) return Response.json(b);
    return Response.json({ items: [] });
  }));
  const view = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/analyses/progressive-b']}><Link to="/analyses/progressive-a">Source A</Link><Link to="/analyses/progressive-b">Source B</Link><App/></MemoryRouter></QueryClientProvider>);
  try {
    const select = () => {
      fireEvent.click(screen.getAllByRole('button', { name: /Inspect evidence/ })[0]);
      fireEvent.change(screen.getByLabelText('Representative example'), { target: { value: '0' } });
      fireEvent.click(screen.getByRole('button', { name: 'Full measurements' }));
    };
    select();
    const oldClose = screen.getByRole('button', { name: 'Close example detail' });
    const captured = Object.values(oldClose).find(value => value && typeof value === 'object' && 'onClick' in value) as { onClick: () => void };
    expect(captured.onClick).toBeTypeOf('function');
    fireEvent.click(screen.getByRole('link', { name: 'Source A' }));
    await waitFor(() => expect(calls).toContain('GET /api/v1/analysis-jobs/progressive-a'));
    fireEvent.click(screen.getByRole('link', { name: 'Source B' }));
    await screen.findByRole('heading', { name: 'progressive-b' });
    expect(screen.queryByRole('region', { name: 'Selected representative example' })).toBeNull();
    select();
    await act(async () => { finishA(Response.json(job('progressive-a', reports.ipv6_hop_limit))); await delayedA; });
    const focused = document.activeElement;
    expect(focused).not.toBe(document.body);
    act(() => captured.onClick());
    expect(document.activeElement).toBe(focused);
    expect(screen.getByRole('heading', { name: 'progressive-b' })).toBeVisible();
    expect(screen.getByLabelText('Representative example')).toHaveValue('0');
    expect(screen.getByRole('region', { name: 'Supporting measurements' })).toHaveTextContent('100 / 100 / 100');
    fireEvent.click(screen.getByRole('link', { name: 'Source A' }));
    await screen.findByRole('heading', { name: 'progressive-a' });
    expect(screen.queryByRole('region', { name: 'Selected representative example' })).toBeNull();
    expect(calls.every(call => call.startsWith('GET '))).toBe(true);
  } finally { view.unmount(); client.clear(); }
});
