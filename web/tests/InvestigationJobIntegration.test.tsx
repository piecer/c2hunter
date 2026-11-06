import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import App from '../src/App';
import { api } from '../src/api';

it('selects actual candidate and both flow endpoints without creating candidates or changing scores', async () => {
  localStorage.setItem('c2hunter-token', 'test');
  const candidate = { id: 'candidate-6', candidate_ip: '2001:db8::dead:beef', score: 42, severity: 'MEDIUM' };
  const flow = { flow_id: 'flow-1', job_id: 'job', source_ip: '10.0.0.12', destination_ip: '2001:db8::face', timestamp: '2026-01-01T00:00:00Z', protocol: 'UDP', direction: 'OUTBOUND' };
  vi.spyOn(api, 'get').mockImplementation(async path => {
    if (path === '/analysis-jobs/job') return { id: 'job', name: 'Investigation source', status: 'COMPLETED', analysis: { module: 'c2' }, packet_count: 1, flow_count: 1 };
    if (path.includes('/candidates?')) return { items: [candidate] };
    if (path.includes('/flows?')) return { items: [flow] };
    if (path === '/ai-capabilities') return { available: false };
    return { items: [] };
  });
  vi.spyOn(api, 'boundedRequest').mockRejectedValue(new Error('Investigation unavailable'));
  const post = vi.spyOn(api, 'post');
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/analyses/job']}><App/></MemoryRouter></QueryClientProvider>);
  await screen.findByRole('button', { name: 'IP 조사 열기 / Open IP investigation' });
  expect(api.boundedRequest).not.toHaveBeenCalled();
  fireEvent.click(await screen.findByRole('button', { name: 'Investigate candidate 2001:db8::dead:beef' }));
  expect(within(screen.getByRole('region', { name: 'IP 조사 / IP investigation' })).getByLabelText('대상 IP / Target IP')).toHaveValue(candidate.candidate_ip);
  fireEvent.click(screen.getByRole('button', { name: 'Investigate source 10.0.0.12' }));
  expect(screen.getByLabelText('대상 IP / Target IP')).toHaveValue(flow.source_ip);
  expect(screen.getByLabelText('엔드포인트 / Endpoint')).toHaveValue('source');
  fireEvent.click(screen.getByRole('button', { name: 'Investigate destination 2001:db8::face' }));
  expect(screen.getByLabelText('대상 IP / Target IP')).toHaveValue(flow.destination_ip);
  expect(screen.getByLabelText('엔드포인트 / Endpoint')).toHaveValue('destination');
  expect(candidate.score).toBe(42); expect(post).not.toHaveBeenCalled();
  view.unmount(); client.clear();
});
