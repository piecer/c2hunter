import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import CandidateQueuePreview from '../src/CandidateQueuePreview';

it('shows source-specific limitations beyond the representative reasons from the actual producer', async () => {
  const python = process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python');
  const wire = execFileSync(python, [resolve('tests/candidate_queue_warning_fixture.py')], { encoding: 'utf8', timeout: 30000 });
  const { candidate } = JSON.parse(wire);
  expect(candidate.evidence.slice(0, 3).every((item: { warnings: string[] }) => item.warnings.length === 0)).toBe(true);
  expect(candidate.evidence.slice(3).flatMap((item: { warnings: string[] }) => item.warnings)).toEqual(expect.arrayContaining(['no_response_is_not_host_unavailable', 'capture_loss_or_asymmetry_possible', 'response_correlation_truncated']));
  vi.stubGlobal('fetch', vi.fn(async () => Response.json(candidate)));
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter><CandidateQueuePreview id={candidate.id}/></MemoryRouter></QueryClientProvider>);
  const limitations = await screen.findByRole('region', { name: 'Evidence limitations' });
  expect(within(limitations).getByText(/No response does not establish that the host is unavailable/)).toBeVisible();
  expect(within(limitations).getByText(/Capture loss or asymmetric visibility may hide responses/)).toBeVisible();
  expect(within(limitations).getByText(/Response correlation reached its retention limit/)).toBeVisible();
  await userEvent.click(within(limitations).getByRole('button', { name: 'Show all evidence warnings' }));
  for (const code of ['no_response_is_not_host_unavailable', 'capture_loss_or_asymmetry_possible', 'response_correlation_truncated']) expect(within(limitations).getByText(code, { exact: true })).toBeVisible();
  expect(document.querySelectorAll('*').length).toBeLessThanOrEqual(2500);
});

it('keeps every source warning reachable with bounded lazy DOM, including unknown warnings', async () => {
  const warnings = Array.from({ length: 307 }, (_, index) => `source-warning-${index}`);
  const candidate = { id: 'many', candidate_ip: '203.0.113.4', severity: 'LOW', score: 0, evidence: warnings.map(code => ({ type: 'TCP_COMMUNICATION_ATTEMPT_PATTERN', warnings: [code] })) };
  vi.stubGlobal('fetch', vi.fn(async () => Response.json(candidate)));
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter><CandidateQueuePreview id="many"/></MemoryRouter></QueryClientProvider>);
  const region = await screen.findByRole('region', { name: 'Evidence limitations' });
  expect(within(region).getByText(/Additional source warnings/)).toBeVisible();
  expect(region.querySelectorAll('code')).toHaveLength(0);
  expect(document.querySelectorAll('*').length).toBeLessThanOrEqual(1200);
  await userEvent.click(within(region).getByRole('button', { name: 'Show all evidence warnings' }));
  const reached: string[] = [];
  for (;;) {
    reached.push(...Array.from(region.querySelectorAll('code'), node => node.textContent!));
    expect(document.querySelectorAll('*').length).toBeLessThanOrEqual(2500);
    const next = within(region).getByRole('button', { name: 'Next warnings' });
    if (next.hasAttribute('disabled')) break;
    await userEvent.click(next);
  }
  expect(reached).toEqual(warnings);
  await userEvent.click(within(region).getByRole('button', { name: 'Previous warnings' }));
  expect(within(region).getByText('source-warning-290', { exact: true })).toBeVisible();
  await userEvent.click(within(region).getByRole('button', { name: 'Hide evidence warnings' }));
  expect(region.querySelectorAll('code')).toHaveLength(0);
});

it('does not transfer expanded warnings through cached A B A selection', async () => {
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    const id = String(input).split('/').at(-1)!;
    return Response.json({ id, candidate_ip: id, severity: 'LOW', score: 0, evidence: [{ type: 'TCP_COMMUNICATION_ATTEMPT_PATTERN', warnings: [id + '-warning'] }] });
  }));
  const client = new QueryClient();
  const tree = (id: string) => <QueryClientProvider client={client}><MemoryRouter><CandidateQueuePreview id={id}/></MemoryRouter></QueryClientProvider>;
  const view = render(tree('A'));
  for (const id of ['A', 'B', 'A']) {
    view.rerender(tree(id));
    const show = await screen.findByRole('button', { name: 'Show all evidence warnings' });
    expect(screen.queryByText(id + '-warning', { exact: true })).not.toBeInTheDocument();
    await userEvent.click(show);
    expect(screen.getByText(id + '-warning', { exact: true })).toBeVisible();
  }
});
