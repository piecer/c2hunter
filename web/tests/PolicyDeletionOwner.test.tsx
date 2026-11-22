import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import App from '../src/App';
import { setAuthentication } from '../src/authentication';

const signature = (id: string) => ({ id, name: `Beacon ${id}`, version: 1, enabled: true, source_job_id: 'job', source_flow_id: 'flow', source_label_id: 'label', payload_hash: 'a'.repeat(64), length_tolerance_ratio: 0.1, entropy_tolerance: 0.2, simhash_max_distance: 3, created_at: '2026-07-20T10:00:00Z' });
const entry = (id: string) => ({ id, value: `203.0.113.${id}`, type: 'IP', description: `Entry ${id}`, enabled: true, created_at: '2026-07-20T10:00:00Z' });
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(r => { resolve = r; }); return { promise, resolve }; }
function mount(remove: (url: string) => Promise<Response>, path = '/payload-signatures', count = 2) {
  localStorage.setItem('c2hunter-token', 'policy-owner');
  vi.stubGlobal('matchMedia', vi.fn(() => ({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() })));
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (init?.method === 'DELETE') return remove(url);
    const list = Array.from({ length: count }, (_, i) => url.includes('payload-signatures') ? signature(String(i)) : entry(String(i)));
    const parsed = new URL(url, 'http://fixture'), page = Number(parsed.searchParams.get('page') ?? 1);
    return Response.json({ items: list.slice((page - 1) * 10, page * 10), page, page_size: 10, total: count });
  });
  vi.stubGlobal('fetch', fetchMock);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const view = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><App/></MemoryRouter></QueryClientProvider>);
  return { ...view, fetchMock, client, deletes: () => fetchMock.mock.calls.filter(([, init]) => init?.method === 'DELETE') };
}
async function confirm(name: string) {
  fireEvent.click(await screen.findByRole('button', { name }));
  const dialog = screen.getByRole('dialog', { name: 'Confirm policy deletion' });
  fireEvent.click(within(dialog).getByRole('button', { name: 'Confirm delete' }));
}
it('requires target confirmation, cancels without a request and retains route-independent pending/failure with exact-target retry', async () => {
  const pending = deferred<Response>();
  const { deletes } = mount(() => pending.promise);
  const user = userEvent.setup();
  const trigger = await screen.findByRole('button', { name: 'Delete Beacon 0' });
  await user.click(trigger);
  expect(deletes()).toHaveLength(0);
  const dialog = screen.getByRole('dialog', { name: 'Confirm policy deletion' });
  expect(within(dialog).getByText('0', { exact: true })).toBeVisible();
  expect(within(dialog).getByText('Beacon 0', { exact: true })).toBeVisible();
  expect(within(dialog).getByRole('button', { name: 'Cancel deletion' })).toHaveFocus();
  await user.click(within(dialog).getByRole('button', { name: 'Cancel deletion' }));
  expect(deletes()).toHaveLength(0);
  expect(trigger).toHaveFocus();
  await confirm('Delete Beacon 0');
  expect(deletes()).toHaveLength(1);
  fireEvent.click(screen.getByRole('link', { name: 'Allowlist' }));
  await screen.findByText('Entry 0');
  expect(screen.getByRole('region', { name: 'Policy deletion receipts' })).toHaveTextContent('Pending');
  await act(async () => pending.resolve(Response.json({ error: { message: 'failed' } }, { status: 409 })));
  expect(await screen.findByText(/Delete failed \(HTTP 409\)/)).toBeVisible();
  fireEvent.click(screen.getByRole('link', { name: 'Payload signatures' }));
  await screen.findByText('Beacon 1');
  fireEvent.click(screen.getByRole('button', { name: 'Retry delete Beacon 0' }));
  const retry = screen.getByRole('dialog');
  expect(within(retry).getByText('0', { exact: true })).toBeVisible();
  expect(within(retry).queryByText('1', { exact: true })).not.toBeInTheDocument();
  fireEvent.click(within(retry).getByRole('button', { name: 'Confirm delete' }));
  await waitFor(() => expect(deletes()).toHaveLength(2));
  expect(deletes().map(([url]) => url)).toEqual(['/api/v1/payload-signatures/0', '/api/v1/payload-signatures/0']);
});

it.each([
  ['signature acknowledgement', '/payload-signatures', 200, JSON.stringify({ deleted: true, signature_id: '0' }), true],
  ['wrong signature ID', '/payload-signatures', 200, JSON.stringify({ deleted: true, signature_id: '1' }), false],
  ['false deletion', '/payload-signatures', 200, JSON.stringify({ deleted: false, signature_id: '0' }), false],
  ['malformed JSON', '/payload-signatures', 200, '{broken', false],
  ['missing body', '/payload-signatures', 204, null, false],
  ['unconfirmed accepted', '/payload-signatures', 202, JSON.stringify({ deleted: true, signature_id: '0' }), false],
  ['allowlist acknowledgement', '/allowlist', 204, null, true],
  ['wrong allowlist status', '/allowlist', 200, '{}', false],
] as const)('validates actual DELETE contract: %s', async (_name, path, status, body, valid) => {
  const { deletes, client } = mount(async () => new Response(body, { status, headers: { 'content-type': 'application/json' } }), path);
  const invalidate = vi.spyOn(client, 'invalidateQueries');
  await confirm(path === '/allowlist' ? 'Delete 203.0.113.0' : 'Delete Beacon 0');
  const receipts = screen.getByRole('region', { name: 'Policy deletion receipts' });
  if (valid) {
    await within(receipts).findByText(/Server acknowledged deletion/);
    expect(receipts).toHaveTextContent('not readback proof');
    expect(invalidate).toHaveBeenCalledWith({ queryKey: [path.slice(1)] });
  } else {
    expect(await within(receipts).findByText(/Deletion outcome uncertain/)).toBeVisible();
    expect(receipts).not.toHaveTextContent('Server acknowledged deletion');
    expect(invalidate).not.toHaveBeenCalled();
  }
  expect(deletes()).toHaveLength(1);
});

it('refuses duplicate admission and never evicts pending receipts at the eight-operation capacity', async () => {
  const pending = deferred<Response>();
  const { deletes } = mount(() => pending.promise, '/payload-signatures', 45);
  await confirm('Delete Beacon 0');
  fireEvent.click(screen.getByRole('button', { name: 'Delete Beacon 0' }));
  expect(await screen.findByText(/Already pending/)).toBeVisible();
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  expect(deletes()).toHaveLength(1);
  for (let index = 1; index < 8; index++) await confirm(`Delete Beacon ${index}`);
  fireEvent.click(screen.getByRole('button', { name: 'Delete Beacon 8' }));
  expect(await screen.findByText(/Receipt capacity reached/)).toBeVisible();
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  expect(deletes()).toHaveLength(8);
  const region = screen.getByRole('region', { name: 'Policy deletion receipts' });
  expect(within(region).getAllByRole('article')).toHaveLength(8);
  expect(within(region).queryByRole('button', { name: /Dismiss/ })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Next policy page' }));
  await screen.findByText('Beacon 10');
  expect(within(region).getByText('Beacon 0')).toBeVisible();
  await act(async () => pending.resolve(Response.json({}, { status: 409 })));
  await within(region).findAllByText(/Delete failed/);
  fireEvent.click(within(region).getByRole('button', { name: 'Dismiss receipt Beacon 0' }));
  expect(within(region).getAllByRole('article')).toHaveLength(7);
  await confirm('Delete Beacon 10');
  expect(deletes()).toHaveLength(9);
  expect(within(region).getAllByRole('article')).toHaveLength(8);
});

it.each(['headers', 'body', 'unmount'] as const)('fences retired authentication after delayed %s without successor cache invalidation', async phase => {
  const headers = deferred<Response>();
  const body = deferred<unknown>();
  const response = Response.json({ deleted: true, signature_id: '0' });
  const parse = vi.fn(() => body.promise);
  if (phase === 'body') vi.spyOn(response, 'clone').mockReturnValue({ json: parse } as unknown as Response);
  const { client, unmount } = mount(() => headers.promise);
  const invalidate = vi.spyOn(client, 'invalidateQueries');
  await confirm('Delete Beacon 0');
  if (phase === 'body') {
    await act(async () => headers.resolve(response));
    expect(parse).toHaveBeenCalledTimes(1);
  }
  if (phase === 'unmount') unmount();
  else await act(async () => { setAuthentication('replacement'); setAuthentication('policy-owner'); });
  await act(async () => {
    if (phase === 'body') body.resolve({ deleted: true, signature_id: '0' });
    else headers.resolve(response);
  });
  expect(invalidate).not.toHaveBeenCalled();
  expect(screen.queryByRole('region', { name: 'Policy deletion receipts' })).not.toBeInTheDocument();
  expect(localStorage.getItem('c2hunter-token')).toBe('policy-owner');
});
it('checks live authority at confirmation even before an auth event rerenders the Shell', async () => {
  const { deletes } = mount(async () => Response.json({ deleted: true, signature_id: '0' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Delete Beacon 0' }));
  localStorage.setItem('c2hunter-token', 'replacement-before-event');
  fireEvent.click(screen.getByRole('button', { name: 'Confirm delete' }));
  expect(deletes()).toHaveLength(0);
});
it('does not let a late 401 clear the replacement authentication', async () => {
  const pending = deferred<Response>();
  mount(() => pending.promise);
  await confirm('Delete Beacon 0');
  await act(async () => setAuthentication('replacement'));
  await act(async () => pending.resolve(Response.json({ error: { message: 'expired old session' } }, { status: 401 })));
  expect(localStorage.getItem('c2hunter-token')).toBe('replacement');
  expect(screen.queryByRole('region', { name: 'Policy deletion receipts' })).not.toBeInTheDocument();
});

it('keeps A and B receipts independent when B acknowledges before A fails', async () => {
  const a = deferred<Response>(), b = deferred<Response>();
  const { deletes } = mount(url => url.endsWith('/0') ? a.promise : b.promise);
  await confirm('Delete Beacon 0'); await confirm('Delete Beacon 1');
  await act(async () => b.resolve(Response.json({ deleted: true, signature_id: '1' })));
  const region = screen.getByRole('region', { name: 'Policy deletion receipts' });
  const receiptA = within(region).getByText('Beacon 0').closest('article')!;
  const receiptB = within(region).getByText('Beacon 1').closest('article')!;
  expect(receiptA).toHaveTextContent('Pending'); expect(receiptB).toHaveTextContent('Server acknowledged');
  await act(async () => a.resolve(Response.json({}, { status: 409 })));
  expect(receiptA).toHaveTextContent('Delete failed'); expect(receiptB).toHaveTextContent('Server acknowledged');
  fireEvent.click(within(receiptA).getByRole('button', { name: 'Retry delete Beacon 0' }));
  expect(screen.getByRole('dialog')).toHaveTextContent('Beacon 0');
  fireEvent.click(screen.getByRole('button', { name: 'Confirm delete' }));
  await waitFor(() => expect(deletes()).toHaveLength(3));
  expect(deletes().map(([url]) => url)).toEqual(['/api/v1/payload-signatures/0', '/api/v1/payload-signatures/1', '/api/v1/payload-signatures/0']);
});
it('retains transport uncertainty without automatically retrying', async () => {
  const { deletes } = mount(async () => { throw new TypeError('Network lost'); });
  await confirm('Delete Beacon 0');
  expect(await screen.findByText(/Deletion outcome uncertain/)).toBeVisible();
  expect(deletes()).toHaveLength(1);
  expect(screen.getByRole('button', { name: 'Retry delete Beacon 0' })).toBeEnabled();
});
