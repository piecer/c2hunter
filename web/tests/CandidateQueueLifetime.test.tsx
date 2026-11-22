import { StrictMode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import CandidateQueuePreview from '../src/CandidateQueuePreview';

// Retain the actual rendered React listener, not a replacement observer/query.
function listener(button: HTMLElement): () => void {
  const key = Object.keys(button).find(key => key.startsWith('__reactProps$'))!;
  return (button as unknown as Record<string, { onClick: () => void }>)[key].onClick;
}

it.each(['close', 'selection B', 'leave job', 'cached A B A'])(
  'retires the actual retry and original query function after %s under the same authentication', async transition => {
    localStorage.setItem('c2hunter-token', 'same-authority');
    let fail = true;
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      const id = String(input).split('/').at(-1)!;
      return fail ? Response.json({}, { status: 503 }) : Response.json({ id, candidate_ip: id, score: 1, severity: 'LOW' });
    });
    vi.stubGlobal('fetch', fetcher);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const view = (id?: string, jobId?: string) => <StrictMode><QueryClientProvider client={client}><MemoryRouter>{id && <CandidateQueuePreview id={id} jobId={jobId}/>}</MemoryRouter></QueryClientProvider></StrictMode>;
    const mounted = render(view('A', transition === 'leave job' ? 'job-A' : undefined));
    const oldRetry = listener(await screen.findByRole('button', { name: 'Retry candidate preview' }));
    const original = client.getQueryCache().find({ queryKey: ['candidate-queue-preview'], exact: false })!;
    const oldFn = original.options.queryFn as (context: { signal: AbortSignal }) => Promise<unknown>;
    fail = false;
    if (transition === 'cached A B A') {
      await userEvent.click(screen.getByRole('button', { name: 'Retry candidate preview' }));
      await screen.findByRole('heading', { name: 'A' });
    }
    mounted.rerender(view(transition === 'close' ? undefined : 'B', transition === 'leave job' ? 'job-B' : undefined));
    if (transition !== 'close') await screen.findByRole('heading', { name: 'B' });
    if (transition === 'cached A B A') {
      mounted.rerender(view('A'));
      await screen.findByRole('heading', { name: 'A' });
    }
    const before = fetcher.mock.calls.length;
    await act(async () => { oldRetry(); });
    expect(fetcher.mock.calls.length).toBe(before);
    await act(async () => { await oldFn({ signal: new AbortController().signal }).catch(() => undefined); });
    expect(fetcher.mock.calls.length).toBe(before);
    if (transition !== 'close') {
      await act(async () => { await client.invalidateQueries({ queryKey: ['candidate-queue-preview'] }); });
      expect(fetcher.mock.calls.length).toBe(before + 1);
    }
  },
);

it.each([false, true])('checks the selection lifetime after body consumption (retired=%s)', async retired => {
  const candidate = { id: 'A', candidate_ip: '203.0.113.1', severity: 'LOW', score: 0 };
  let held = false;
  let controller!: ReadableStreamDefaultController<Uint8Array>;
  const fetcher = vi.fn(async () => held ? new Response(new ReadableStream<Uint8Array>({ start(stream) { controller = stream; } })) : Response.json(candidate));
  vi.stubGlobal('fetch', fetcher);
  const client = new QueryClient();
  const mounted = render(<QueryClientProvider client={client}><MemoryRouter><CandidateQueuePreview id="A"/></MemoryRouter></QueryClientProvider>);
  await screen.findByRole('heading', { name: candidate.candidate_ip });
  const original = client.getQueryCache().find({ queryKey: ['candidate-queue-preview'], exact: false })!.options.queryFn as (context: { signal: AbortSignal }) => Promise<unknown>;
  held = true;
  const signal = new AbortController().signal;
  const completion = original({ signal }).then(data => ({ data, error: undefined }), error => ({ data: undefined, error }));
  await act(async () => { await Promise.resolve(); });
  expect(controller).toBeDefined();
  if (retired) mounted.unmount();
  await act(async () => { controller.enqueue(new TextEncoder().encode(JSON.stringify(candidate))); controller.close(); });
  const result = await completion;
  expect(signal.aborted).toBe(false);
  if (retired) { expect(result.data).toBeUndefined(); expect(result.error.message).toBe('Retired preview request'); }
  else { expect(result.data).toEqual(candidate); expect(result.error).toBeUndefined(); }
});

it('rejects a response identity mismatch without publishing its evidence or destination', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => Response.json({ id: 'wrong', candidate_ip: 'wrong-IP', score: 1, severity: 'LOW', evidence: [{ type: 'wrong-evidence' }] })));
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter><CandidateQueuePreview id="requested"/></MemoryRouter></QueryClientProvider>);
  expect(await screen.findByRole('alert')).toHaveTextContent('could not be refreshed');
  expect(screen.queryByText('wrong-evidence')).not.toBeInTheDocument();
  expect(screen.queryByRole('link')).not.toBeInTheDocument();
});

it.each([undefined, [], [{ type: 'PARTIAL', warnings: null }], [{ type: 'PARTIAL', warnings: [null] }]])('supports optional evidence without inventing complete coverage: %j', async evidence => {
  vi.stubGlobal('fetch', vi.fn(async () => Response.json({ id: 'A', candidate_ip: 'optional', score: 0, severity: 'LOW', evidence })));
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter><CandidateQueuePreview id="A"/></MemoryRouter></QueryClientProvider>);
  await screen.findByRole('heading', { name: 'optional' });
  expect(screen.getByRole('link', { name: 'Open full investigation' })).toHaveAttribute('href', '/candidates/A');
  if (evidence?.length) {
    expect(screen.getByText(/coverage remains qualified or unconfirmed/)).toBeVisible();
    await userEvent.click(screen.getByRole('button', { name: 'Show all evidence warnings' }));
    expect(screen.getByText('Warning details unconfirmed')).toBeVisible();
  } else expect(screen.getByText('No retained reasons reported.')).toBeVisible();
});
