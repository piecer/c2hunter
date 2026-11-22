import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, useLocation, useNavigate } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import App from '../src/App';
import { setAuthentication } from '../src/authentication';
import { useCandidateQueueSelection } from '../src/useCandidateQueueSelection';

const rows = ['alpha', 'beta'].map((id, index) => ({ id, job_id: 'job-one', candidate_ip: `203.0.113.${index + 1}`, score: 80, severity: 'HIGH', evidence: Array.from({ length: 8 }, (_, n) => ({ type: 'BEACON', description: `${id} reason ${n}` })) }));
function Navigation() {
  const location = useLocation(); const navigate = useNavigate();
  return <><output aria-label="Location">{location.pathname}{location.search}</output><button onClick={event => { event.currentTarget.blur(); navigate(-1); }}>Browser Back</button><button onClick={event => { event.currentTarget.blur(); navigate(1); }}>Browser Forward</button></>;
}
function setup(route = '/candidates?severity=HIGH&sort=-score&context=keep', handler?: (url: URL, init?: RequestInit) => Promise<Response | undefined>) {
  vi.spyOn(window, 'scrollTo').mockImplementation(() => undefined);
  localStorage.setItem('c2hunter-token', 'queue-test');
  localStorage.setItem('c2hunter-report-language', 'en');
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'http://localhost');
    const handled = await handler?.(url, init); if (handled) return handled;
    if (url.pathname === '/api/v1/analysis-jobs/job-one') return Response.json({ id: 'job-one', name: 'Job one', status: 'COMPLETED', analysis: { module: 'c2' } });
    const row = rows.find(row => url.pathname.endsWith(`/candidates/${row.id}`));
    return Response.json(row ?? { items: rows, total: 2, page: 1, page_size: url.searchParams.get('page_size') === '25' ? 25 : 50 });
  });
  vi.stubGlobal('fetch', fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[route]}><Navigation/><App/></MemoryRouter></QueryClientProvider>);
  return { fetcher, client };
}

it('opens one readonly preview in the actual global queue, preserves drafts and canonical links, closes only its query key', async () => {
  const { fetcher } = setup();
  await screen.findByRole('link', { name: rows[0].candidate_ip });
  expect(fetcher).toHaveBeenCalledTimes(1);
  await userEvent.click(screen.getByLabelText(`${rows[0].candidate_ip} 선택`));
  await userEvent.type(screen.getByLabelText('공통 메모'), 'retained draft');
  await userEvent.clear(screen.getByLabelText('Minimum score'));
  await userEvent.type(screen.getByLabelText('Minimum score'), '42');
  const trigger = screen.getByRole('button', { name: `Preview candidate ${rows[0].candidate_ip}` });
  await userEvent.click(trigger);
  const panel = await screen.findByRole('region', { name: 'Selected candidate detail' });
  expect(await within(panel).findByRole('heading', { name: rows[0].candidate_ip })).toBeInTheDocument();
  expect(within(panel).getAllByRole('listitem')).toHaveLength(3);
  expect(screen.queryByText('alpha reason 3')).not.toBeInTheDocument();
  expect(within(panel).getByRole('link', { name: 'Open full investigation' })).toHaveAttribute('href', '/candidates/alpha');
  expect(screen.getByRole('link', { name: rows[0].candidate_ip })).toHaveAttribute('href', '/candidates/alpha');
  expect(screen.getByLabelText('Location')).toHaveTextContent('/candidates?severity=HIGH&sort=-score&context=keep&candidate=alpha');
  expect(trigger).toHaveAttribute('aria-expanded', 'true');
  await userEvent.click(trigger);
  expect(fetcher).toHaveBeenCalledTimes(2);
  await userEvent.click(screen.getByRole('button', { name: 'Close candidate detail' }));
  expect(screen.queryByRole('region', { name: 'Selected candidate detail' })).not.toBeInTheDocument();
  expect(screen.getByLabelText('Location').textContent).toBe('/candidates?severity=HIGH&sort=-score&context=keep');
  expect(trigger).toHaveFocus();
  expect(screen.getByLabelText('Minimum score')).toHaveValue(42);
  expect(screen.getByLabelText('공통 메모')).toHaveValue('retained draft');
  expect(screen.getByLabelText(`${rows[0].candidate_ip} 선택`)).toBeChecked();
  expect(fetcher.mock.calls.every(([, init]) => !init?.method || init.method === 'GET')).toBe(true);
});


it('previews a job candidate through the membership-enforcing endpoint, not partial inventory', async () => {
  const opaque = 'literal /?#% ID';
  const { fetcher } = setup('/analyses/job-one?candidate_page=2&candidate=' + encodeURIComponent(opaque), async url => {
    if (url.pathname.endsWith('/candidates/' + encodeURIComponent(opaque))) return Response.json({ ...rows[0], id: opaque });
    if (url.pathname.endsWith('/candidates')) return Response.json({ items: [rows[1]], total: 51, page: Number(url.searchParams.get('page')), page_size: 25 });
  });
  const panel = await screen.findByRole('region', { name: 'Selected candidate detail' });
  expect(await within(panel).findByText(opaque)).toBeInTheDocument();
  expect(within(panel).getByRole('link', { name: 'Open full investigation' })).toHaveAttribute('href', '/candidates/' + encodeURIComponent(opaque));
  expect(fetcher.mock.calls.map(([url]) => String(url))).toContain('/api/v1/analysis-jobs/job-one/candidates/' + encodeURIComponent(opaque));
  expect(fetcher.mock.calls.map(([url]) => String(url))).toContain('/api/v1/analysis-jobs/job-one/candidates?page=2&page_size=25&minimum_score=0&sort=-score');
  expect(fetcher.mock.calls).toHaveLength(3);
  await userEvent.click(screen.getByRole('button', { name: 'Close candidate detail' }));
  expect(screen.getByRole('heading', { name: 'Detected candidates' })).toHaveFocus();
  expect(screen.getByLabelText('Location').textContent).toBe('/analyses/job-one?candidate_page=2');
  await userEvent.click(screen.getByRole('button', { name: 'Next candidates' }));
  expect(screen.getByLabelText('Location').textContent).toBe('/analyses/job-one?candidate_page=3');
  await userEvent.click(screen.getByRole('button', { name: 'Browser Back' }));
  expect(screen.getByLabelText('Location').textContent).toBe('/analyses/job-one?candidate_page=2');
});


it('restores selected A/B/A and list focus with cached destinations; a repeated selection is a history no-op', async () => {
  setup();
  const alpha = await screen.findByRole('button', { name: `Preview candidate ${rows[0].candidate_ip}` });
  const beta = screen.getByRole('button', { name: `Preview candidate ${rows[1].candidate_ip}` });
  await userEvent.click(alpha);
  await screen.findByText('alpha reason 0');
  await userEvent.click(beta);
  await screen.findByText('beta reason 0');
  await userEvent.click(beta);
  await userEvent.click(screen.getByRole('button', { name: 'Browser Back' }));
  await screen.findByText('alpha reason 0');
  expect(screen.queryByText('beta reason 0')).not.toBeInTheDocument();
  expect(beta).toHaveFocus();
  await userEvent.click(screen.getByRole('button', { name: 'Browser Back' }));
  expect(screen.queryByRole('region', { name: 'Selected candidate detail' })).not.toBeInTheDocument();
  expect(alpha).toHaveFocus();
  await userEvent.click(screen.getByRole('button', { name: 'Browser Forward' }));
  await screen.findByText('alpha reason 0');
});

it.each([403, 404, 410, 503])('never leaves cached detail visible after status %s; recovery stays inside the preview', async status => {
  let fail = false;
  const { client } = setup(undefined, async url => url.pathname.endsWith('/candidates/alpha') && fail ? Response.json({}, { status }) : undefined);
  await userEvent.click(await screen.findByRole('button', { name: `Preview candidate ${rows[0].candidate_ip}` }));
  await screen.findByText('alpha reason 0');
  fail = true;
  await act(async () => { await client.invalidateQueries({ queryKey: ['candidate-queue-preview'] }); });
  const panel = screen.getByRole('region', { name: 'Selected candidate detail' });
  expect(await within(panel).findByRole('alert')).toHaveTextContent(status === 503 ? 'could not be refreshed' : 'unavailable in this scope');
  expect(screen.queryByText('alpha reason 0')).not.toBeInTheDocument();
  expect(within(panel).queryByRole('link', { name: 'Open full investigation' })).not.toBeInTheDocument();
  fail = false;
  await userEvent.click(within(panel).getByRole('button', { name: 'Retry candidate preview' }));
  expect(await within(panel).findByText('alpha reason 0')).toBeInTheDocument();
});

it('ignores reversed detail responses and an authentication epoch retires callbacks and cached data', async () => {
  let release!: (response: Response) => void;
  const pending = new Promise<Response>(resolve => { release = resolve; });
  let hold = true;
  setup(undefined, async url => url.pathname.endsWith('/candidates/alpha') && hold ? pending : undefined);
  await userEvent.click(await screen.findByRole('button', { name: `Preview candidate ${rows[0].candidate_ip}` }));
  await userEvent.click(screen.getByRole('button', { name: `Preview candidate ${rows[1].candidate_ip}` }));
  await screen.findByText('beta reason 0');
  await act(async () => { release(Response.json(rows[0])); });
  expect(screen.queryByText('alpha reason 0')).not.toBeInTheDocument();
  hold = false;
  await act(async () => { setAuthentication('next-authority'); });
  await screen.findByText('beta reason 0');
  expect(screen.getAllByRole('region', { name: 'Selected candidate detail' })).toHaveLength(1);
});

it('does not publish a held old-auth body after A→B→A credentials', async () => {
  let release!: (response: Response) => void;
  let reads = 0;
  const pending = new Promise<Response>(resolve => { release = resolve; });
  setup('/candidates?candidate=alpha', async url => {
    if (!url.pathname.endsWith('/candidates/alpha')) return undefined;
    reads++;
    return reads === 1 ? pending : Response.json({ ...rows[0], evidence: [{ type: 'BEACON', description: 'new-authority reason' }] });
  });
  await waitFor(() => expect(reads).toBe(1));
  await act(async () => { setAuthentication('other'); setAuthentication('queue-test'); });
  await screen.findByText('new-authority reason');
  await act(async () => { release(Response.json(rows[0])); });
  expect(screen.queryByText('alpha reason 0')).not.toBeInTheDocument();
});


it('retired queue callbacks cannot select or close a new authentication owner', async () => {
  let captured!: ReturnType<typeof useCandidateQueueSelection>;
  function Probe() { captured = useCandidateQueueSelection('test-heading'); return <h1 id="test-heading">Queue probe</h1>; }
  localStorage.setItem('c2hunter-token', 'original');
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter initialEntries={['/candidates?context=keep']}><Navigation/><Probe/></MemoryRouter></QueryClientProvider>);
  const old = captured;
  await act(async () => { setAuthentication('successor'); });
  await act(async () => { old.buttonProps('retired').onClick({ currentTarget: document.createElement('button') } as Parameters<ReturnType<typeof old.buttonProps>['onClick']>[0]); });
  expect(screen.getByLabelText('Location').textContent).toBe('/candidates?context=keep');
});

it('keeps a pending bulk receipt, captured request and draft through queue selection and close', async () => {
  let release!: (response: Response) => void;
  const pending = new Promise<Response>(resolve => { release = resolve; });
  const { fetcher } = setup(undefined, async (_url, init) => init?.method === 'POST' ? pending : undefined);
  await userEvent.click(await screen.findByLabelText(`${rows[0].candidate_ip} 선택`));
  await userEvent.type(screen.getByLabelText('공통 메모'), 'pinned bulk draft');
  await userEvent.click(screen.getByRole('button', { name: '선택 처리' }));
  await userEvent.click(screen.getByRole('button', { name: `Preview candidate ${rows[1].candidate_ip}` }));
  await screen.findByText('beta reason 0');
  await userEvent.click(screen.getByRole('button', { name: 'Close candidate detail' }));
  expect(screen.getByRole('button', { name: '처리 중…' })).toBeDisabled();
  expect(screen.getByLabelText('공통 메모')).toHaveValue('pinned bulk draft');
  await act(async () => { release(Response.json({ error: { message: 'retained bulk rejection' } }, { status: 409 })); });
  expect(await screen.findByRole('alert')).toHaveTextContent('retained bulk rejection');
  const writes = fetcher.mock.calls.filter(([, init]) => init?.method === 'POST');
  expect(writes).toHaveLength(1);
  expect(JSON.parse(String(writes[0][1]?.body))).toEqual({ candidate_ids: ['alpha'], command: 'UNDER_REVIEW', confidence: 'HIGH', note: 'pinned bulk draft' });
});

it('rejects a candidate in another job without consulting an incomplete inventory or global cache', async () => {
  const { fetcher } = setup('/analyses/job-one?candidate=beta', async url => {
    if (url.pathname === '/api/v1/analysis-jobs/job-one/candidates/beta') return Response.json({ error: { code: 'CANDIDATE_NOT_FOUND' } }, { status: 404 });
  });
  const panel = await screen.findByRole('region', { name: 'Selected candidate detail' });
  expect(await within(panel).findByRole('alert')).toHaveTextContent('unavailable in this scope');
  expect(screen.queryByText('beta reason 0')).not.toBeInTheDocument();
  expect(fetcher.mock.calls.some(([url]) => String(url) === '/api/v1/candidates/beta')).toBe(false);
  expect(fetcher.mock.calls.some(([url]) => String(url).includes('page_size=200'))).toBe(false);
});

it('an off-page global selection is not declared deleted and is not restricted to a job', async () => {
  setup('/candidates?page=2&candidate=alpha', async url => url.pathname === '/api/v1/candidates' ? Response.json({ items: [], total: 51, page: 2, page_size: 50 }) : url.pathname === '/api/v1/candidates/alpha' ? Response.json({ ...rows[0], job_id: 'another-job' }) : undefined);
  expect(await screen.findByText('alpha reason 0')).toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Close candidate detail' }));
  expect(screen.getByRole('heading', { name: 'Candidates' })).toHaveFocus();
  expect(screen.getByLabelText('Location').textContent).toBe('/candidates?page=2');
});


it('a retained old-query retry cannot dispatch a read using the successor authentication', async () => {
  const { client, fetcher } = setup('/candidates?candidate=alpha');
  await screen.findByText('alpha reason 0');
  const retired = client.getQueryCache().find({ queryKey: ['candidate-queue-preview'], exact: false })!;
  await act(async () => { setAuthentication('successor'); });
  await screen.findByText('alpha reason 0');
  const before = fetcher.mock.calls.length;
  await act(async () => { await retired.fetch().catch(() => undefined); });
  expect(fetcher.mock.calls.length).toBe(before);
});

it.each(['close', 'B', 'leave job', 'cached A B A'])('the actual queue retires a captured UI retry on %s without changing auth', async transition => {
  vi.stubGlobal('matchMedia', vi.fn(() => ({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() })));
  let fail = true;
  const { fetcher } = setup(transition === 'leave job' ? '/analyses/job-one?candidate=alpha' : '/candidates?candidate=alpha', async url =>
    fail && url.pathname.endsWith('/candidates/alpha') ? Response.json({}, { status: 503 }) : undefined);
  const retry = await screen.findByRole('button', { name: 'Retry candidate preview' });
  const key = Object.keys(retry).find(key => key.startsWith('__reactProps$'))!;
  const callback = (retry as unknown as Record<string, { onClick: () => void }>)[key].onClick;
  fail = false;
  if (transition === 'cached A B A') {
    await userEvent.click(retry);
    await screen.findByText('alpha reason 0');
  }
  if (transition === 'leave job') {
    await userEvent.click(screen.getByRole('link', { name: 'Candidates' }));
    await screen.findByRole('heading', { name: 'Candidates' });
  } else if (transition === 'close') await userEvent.click(screen.getByRole('button', { name: 'Close candidate detail' }));
  else {
    await userEvent.click(await screen.findByRole('button', { name: `Preview candidate ${rows[1].candidate_ip}` }));
    await screen.findByText('beta reason 0');
    if (transition === 'cached A B A') {
      await userEvent.click(screen.getByRole('button', { name: `Preview candidate ${rows[0].candidate_ip}` }));
      await screen.findByText('alpha reason 0');
    }
  }
  const before = fetcher.mock.calls.length;
  await act(async () => { callback(); });
  expect(fetcher.mock.calls.length).toBe(before);
});
