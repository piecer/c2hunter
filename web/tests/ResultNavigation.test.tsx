import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, useLocation, useNavigate } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import App from '../src/App';

function Navigation() {
  const location = useLocation();
  const navigate = useNavigate();
  return <><output aria-label="Location">{location.pathname}{location.search}</output><button onClick={() => navigate(-1)}>Browser Back</button><button onClick={() => navigate(1)}>Browser Forward</button></>;
}
const candidate = { id: 'candidate-1', candidate_ip: '203.0.113.9', score: 80, severity: 'HIGH', workflow_status: 'NEEDS_REVIEW' };
function setup(route: string, handler?: (url: URL, init?: RequestInit) => Promise<Response>) {
  localStorage.setItem('c2hunter-token', 'navigation-test');
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'http://localhost');
    if (handler) return handler(url, init);
    return Response.json({ items: [candidate], page: Number(url.searchParams.get('page') || 1), page_size: 50, total: 151 });
  });
  vi.stubGlobal('fetch', fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[route]}><Navigation/><App/></MemoryRouter></QueryClientProvider>);
  return fetcher;
}


it.each([
  '/candidates?page=Infinity', '/candidates?page=-1', '/candidates?page=1.5',
  '/candidates?minimum_score=NaN', '/candidates?minimum_score=101', '/candidates?minimum_score=',
  '/candidates?minimum_score=42.5', '/candidates?minimum_score=0x2a',
  '/candidates?severity=ADMIN', '/candidates?workflow_status=DONE', '/candidates?ti_filter=ALL',
  '/candidates?sort=payload', '/candidates?include_suppressed=yes', '/candidates?page=1&page=2',
  '/analyses?page=NaN', '/analyses?status=UNKNOWN', '/analyses?source_type=REMOTE', '/analyses?sort=payload',
])('rejects malformed list context without reading or silently rewriting %s', async route => {
  const fetcher = setup(route, async () => Response.json({ items: [], page: 1, page_size: 50, total: 0 }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Invalid list filters');
  expect(fetcher).not.toHaveBeenCalled();
  expect(screen.getByLabelText('Location').textContent).toBe(route);
});

it.each(['0', '42', '100'])('reads a valid integer minimum_score=%s without rewriting its literal URL', async score => {
  const route = `/candidates?minimum_score=${score}`;
  const fetcher = setup(route);
  await screen.findByRole('link', { name: candidate.candidate_ip });
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  expect(fetcher).toHaveBeenCalledTimes(1);
  expect(new URL(String(fetcher.mock.calls[0][0]), 'http://localhost').searchParams.get('minimum_score')).toBe(score);
  expect(screen.getByLabelText('Location').textContent).toBe(route);
});

it('retires checkbox selection on browser Back while retaining the pending bulk owner, note and late error', async () => {
  let rejectBulk!: (response: Response) => void;
  const pending = new Promise<Response>(resolve => { rejectBulk = resolve; });
  const fetcher = setup('/candidates?severity=HIGH', async (url, init) => {
    if (init?.method === 'POST') return pending;
    return Response.json({ items: [candidate], page: 1, page_size: 50, total: 1 });
  });
  await screen.findByRole('link', { name: '203.0.113.9' });
  await userEvent.selectOptions(screen.getByLabelText('Severity'), 'LOW');
  await userEvent.click(screen.getByRole('button', { name: 'Apply filters' }));
  await userEvent.click(await screen.findByLabelText('203.0.113.9 선택'));
  await userEvent.type(screen.getByLabelText('공통 메모'), 'captured bulk note');
  await userEvent.click(screen.getByRole('button', { name: '선택 처리' }));
  await userEvent.click(screen.getByRole('button', { name: 'Browser Back' }));
  expect(screen.getByLabelText('203.0.113.9 선택')).not.toBeChecked();
  expect(screen.getByRole('button', { name: '처리 중…' })).toBeDisabled();
  expect(screen.getByLabelText('공통 메모')).toHaveValue('captured bulk note');
  rejectBulk(Response.json({ error: { message: 'bulk rejected' } }, { status: 409 }));
  expect(await screen.findByRole('alert')).toHaveTextContent('bulk rejected');
  const posts = fetcher.mock.calls.filter(([, init]) => init?.method === 'POST');
  expect(posts).toHaveLength(1);
  expect(JSON.parse(String(posts[0][1]?.body))).toMatchObject({ candidate_ids: ['candidate-1'], note: 'captured bulk note' });
});

it.each([false, true])('preserves a new cohort selection after late bulk success (A→B→A: %s)', async returnToA => {
  let release!: (response: Response) => void;
  const pending = new Promise<Response>(resolve => { release = resolve; });
  const second = { ...candidate, id: 'candidate-2', candidate_ip: '203.0.113.10' };
  const other = { ...candidate, id: 'candidate-3', candidate_ip: '203.0.113.11' };
  const fetcher = setup('/candidates?severity=HIGH', async (url, init) => {
    if (init?.method === 'POST') return pending;
    const items = url.searchParams.get('severity') === 'HIGH' ? [candidate, second] : [other];
    return Response.json({ items, total: items.length, page: 1, page_size: 50 });
  });
  await userEvent.click(await screen.findByLabelText(`${candidate.candidate_ip} 선택`));
  await userEvent.type(screen.getByLabelText('공통 메모'), 'captured success note');
  await userEvent.click(screen.getByRole('button', { name: '선택 처리' }));
  await userEvent.selectOptions(screen.getByLabelText('Severity'), 'LOW');
  await userEvent.click(screen.getByRole('button', { name: 'Apply filters' }));
  await userEvent.click(await screen.findByLabelText(`${other.candidate_ip} 선택`));
  if (returnToA) {
    await userEvent.click(screen.getByRole('button', { name: 'Browser Back' }));
    expect(await screen.findByLabelText(`${candidate.candidate_ip} 선택`)).not.toBeChecked();
    await userEvent.click(screen.getByLabelText(`${second.candidate_ip} 선택`));
  }
  const chosen = returnToA ? second : other;
  await userEvent.clear(screen.getByLabelText('공통 메모'));
  await userEvent.type(screen.getByLabelText('공통 메모'), 'new cohort draft');
  await userEvent.selectOptions(screen.getByLabelText('빠른 판정'), 'FALSE_POSITIVE');
  expect(screen.getByRole('button', { name: '처리 중…' })).toBeDisabled();
  const readsBefore = fetcher.mock.calls.filter(([, init]) => !init?.method || init.method === 'GET').length;
  release(Response.json({ succeeded: 1, failed: 0 }));
  expect(await screen.findByText('1건 처리 완료')).toHaveAttribute('role', 'status');
  await waitFor(() => expect(screen.getByRole('button', { name: '선택 처리' })).toBeEnabled());
  expect(fetcher.mock.calls.filter(([, init]) => !init?.method || init.method === 'GET').length).toBeGreaterThan(readsBefore);
  expect(screen.getByLabelText(`${chosen.candidate_ip} 선택`)).toBeChecked();
  if (returnToA) expect(screen.getByLabelText(`${candidate.candidate_ip} 선택`)).not.toBeChecked();
  expect(screen.getByLabelText('공통 메모')).toHaveValue('new cohort draft');
  expect(screen.getByLabelText('빠른 판정')).toHaveValue('FALSE_POSITIVE');
  expect(screen.getByLabelText('Location').textContent).toBe(`/candidates?severity=${returnToA ? 'HIGH' : 'LOW'}`);
  const posts = fetcher.mock.calls.filter(([, init]) => init?.method === 'POST');
  expect(posts).toHaveLength(1);
  expect(posts[0][0]).toBe('/api/v1/candidate-bulk-operations');
  expect(JSON.parse(String(posts[0][1]?.body))).toEqual({ candidate_ids: [candidate.id], command: 'UNDER_REVIEW', confidence: 'HIGH', note: 'captured success note' });
});


it('keeps absent pagination metadata unknown and encodes literal row identifiers without adding URL fields to writes', async () => {
  const opaque = 'opaque id?#/literal%';
  setup('/candidates?scope=ADMIN&return_to=https%3A%2F%2Fevil.example&selected=unknown', async () => Response.json({ items: [{ ...candidate, id: opaque }] }));
  expect(await screen.findByRole('link', { name: candidate.candidate_ip })).toHaveAttribute('href', `/candidates/${encodeURIComponent(opaque)}`);
  expect(screen.queryByText(/of 1$/)).not.toBeInTheDocument();
  expect(screen.getByText('Candidate total not reported')).toBeInTheDocument();
});

it('keeps empty candidate pages navigable using server totals rather than current page length', async () => {
  setup('/candidates?page=4', async () => Response.json({ items: [], page: 4, page_size: 50, total: 100 }));
  await screen.findByRole('button', { name: 'Previous candidates' });
  expect(screen.getByRole('button', { name: 'Previous candidates' })).toBeEnabled();
  await userEvent.click(screen.getByRole('button', { name: 'Previous candidates' }));
  expect(screen.getByLabelText('Location')).toHaveTextContent('page=3');
});

it('allows an explicit reset of malformed suppressed input without silently repairing it on load', async () => {
  const fetcher = setup('/candidates?include_suppressed=yes');
  expect(await screen.findByRole('alert')).toHaveTextContent('Invalid list filters');
  await userEvent.click(screen.getByRole('button', { name: 'Reset' }));
  await screen.findByRole('link', { name: candidate.candidate_ip });
  expect(screen.getByLabelText('Location').textContent).toBe('/candidates');
  expect(fetcher).toHaveBeenCalledTimes(1);
});


it('treats the same applied candidate filters as a no-op including current checkbox selection', async () => {
  const fetcher = setup('/candidates');
  await userEvent.click(await screen.findByLabelText('203.0.113.9 선택'));
  await userEvent.click(screen.getByRole('button', { name: 'Apply filters' }));
  expect(screen.getByLabelText('203.0.113.9 선택')).toBeChecked();
  expect(fetcher).toHaveBeenCalledTimes(1);
});


it('reaches every retained history entry beyond the old 200-row limit using server page metadata', async () => {
  const jobs = Array.from({ length: 201 }, (_, index) => ({ id: `all-${index}`, name: `Archive ${index}`, status: 'COMPLETED', candidate_count: 0 }));
  setup('/analyses', async url => {
    const page = Number(url.searchParams.get('page'));
    expect(url.searchParams.get('page_size')).toBe('50');
    return Response.json({ items: jobs.slice((page - 1) * 50, page * 50), total: jobs.length, page, page_size: 50 });
  });
  const reached: string[] = [];
  for (let page = 1; page <= 5; page++) {
    await screen.findByRole('link', { name: `Archive ${(page - 1) * 50}` });
    const links = screen.getAllByRole('link', { name: /^Archive / });
    expect(links).toHaveLength(page === 5 ? 1 : 50);
    reached.push(...links.map(link => link.textContent!));
    if (page < 5) await userEvent.click(screen.getByRole('button', { name: 'Next analyses' }));
  }
  expect(reached).toEqual(jobs.map(job => job.name));
  expect(screen.getByRole('button', { name: 'Next analyses' })).toBeDisabled();
  expect(screen.getByText('Analyses 201–201 of 201')).toBeInTheDocument();
});

it('keeps the history edit owner and error across query Back and encodes its captured literal identifier', async () => {
  const id = 'job ?#%/opaque';
  let release!: (response: Response) => void;
  const pending = new Promise<Response>(resolve => { release = resolve; });
  const fetcher = setup('/analyses', async (_url, init) => init?.method === 'PATCH' ? pending : Response.json({ items: [{ id, name: 'Edit owner', status: 'COMPLETED' }], total: 1, page: 1, page_size: 50 }));
  await screen.findByRole('link', { name: 'Edit owner' });
  await userEvent.type(screen.getByLabelText('Search'), 'owner');
  await userEvent.click(screen.getByRole('button', { name: 'Apply history filters' }));
  await userEvent.click(await screen.findByRole('button', { name: 'Edit Edit owner' }));
  await userEvent.type(screen.getByLabelText('Analyst note'), 'retained draft');
  await userEvent.click(screen.getByRole('button', { name: 'Save changes' }));
  await userEvent.click(screen.getByRole('button', { name: 'Browser Back' }));
  expect(screen.getByLabelText('Analyst note')).toHaveValue('retained draft');
  expect(screen.getByRole('button', { name: 'Saving…' })).toBeDisabled();
  release(Response.json({ error: { message: 'edit rejected' } }, { status: 409 }));
  expect(await screen.findByRole('alert')).toHaveTextContent('edit rejected');
  const writes = fetcher.mock.calls.filter(([, init]) => init?.method === 'PATCH');
  expect(writes).toHaveLength(1);
  expect(writes[0][0]).toBe(`/api/v1/analysis-jobs/${encodeURIComponent(id)}`);
  expect(JSON.parse(String(writes[0][1]?.body))).toEqual({ name: 'Edit owner', description: 'retained draft' });
});

it('keeps the pending history delete owner across filter Back/Forward and rejection without redirecting its write', async () => {
  const id = 'delete ?#%/opaque';
  let release!: (response: Response) => void;
  const pending = new Promise<Response>(resolve => { release = resolve; });
  const fetcher = setup('/analyses', async (url, init) => {
    if (init?.method === 'DELETE') return pending;
    const job = url.searchParams.get('search') === 'owner'
      ? { id, name: 'Delete owner', status: 'COMPLETED' }
      : { id: 'other-job', name: 'Other investigation', status: 'COMPLETED' };
    return Response.json({ items: [job], total: 1, page: 1, page_size: 50 });
  });
  await screen.findByRole('link', { name: 'Other investigation' });
  await userEvent.type(screen.getByLabelText('Search'), 'owner');
  await userEvent.click(screen.getByRole('button', { name: 'Apply history filters' }));
  await screen.findByRole('link', { name: 'Delete owner' });
  await userEvent.type(screen.getByLabelText('Search'), ' unapplied draft');
  await userEvent.click(screen.getByRole('button', { name: 'Delete Delete owner' }));
  await userEvent.click(screen.getByRole('button', { name: 'Delete permanently' }));
  expect(screen.getByLabelText('Search')).toHaveValue('owner unapplied draft');
  await userEvent.click(screen.getByRole('button', { name: 'Browser Back' }));
  await screen.findByRole('link', { name: 'Other investigation' });
  expect(screen.getByRole('dialog')).toHaveTextContent('Delete owner');
  expect(screen.getByRole('button', { name: 'Deleting…' })).toBeDisabled();
  expect(screen.getByLabelText('Search')).toHaveValue('');
  await userEvent.click(screen.getByRole('button', { name: 'Browser Forward' }));
  await screen.findByRole('link', { name: 'Delete owner' });
  expect(screen.getByLabelText('Search')).toHaveValue('owner');
  expect(screen.getByRole('button', { name: 'Deleting…' })).toBeDisabled();
  release(Response.json({ error: { message: 'delete rejected' } }, { status: 409 }));
  expect(await screen.findByRole('alert')).toHaveTextContent('delete rejected');
  expect(screen.getByRole('dialog')).toHaveTextContent('Delete owner');
  expect(screen.getByRole('dialog')).toContainElement(screen.getByRole('alert'));
  expect(screen.getByRole('button', { name: 'Delete permanently' })).toBeEnabled();
  await userEvent.click(screen.getByRole('button', { name: 'Browser Back' }));
  expect(screen.getByRole('dialog')).toHaveTextContent('delete rejected');
  expect(screen.getByRole('dialog')).toHaveTextContent('Delete owner');
  expect(screen.getByLabelText('Location').textContent).toBe('/analyses');
  const writes = fetcher.mock.calls.filter(([, init]) => init?.method === 'DELETE');
  expect(writes).toHaveLength(1);
  expect(writes[0][0]).toBe(`/api/v1/analysis-jobs/${encodeURIComponent(id)}`);
  expect(writes[0][1]?.body).toBeUndefined();
  expect(fetcher.mock.calls.filter(([, init]) => init?.method && init.method !== 'GET')).toHaveLength(1);
});

it('keeps history search drafts local, applies whitelisted URL filters, and reaches the server final page', async () => {
  const fetcher = setup('/analyses?page=4&search=beacon&status=COMPLETED&source_type=PCAP_UPLOAD&sort=name', async url => {
    const page = Number(url.searchParams.get('page') || 1);
    return Response.json({ items: [{ id: `job-${page}`, name: `Stored result ${page}`, status: 'COMPLETED', candidate_count: 0 }], page, page_size: 50, total: 201 });
  });
  await screen.findByRole('link', { name: 'Stored result 4' });
  expect(Object.fromEntries(new URL(String(fetcher.mock.calls[0][0]), 'http://localhost').searchParams)).toEqual({ page: '4', page_size: '50', search: 'beacon', status: 'COMPLETED', source_type: 'PCAP_UPLOAD', sort: 'name' });
  expect(screen.getByText('Analyses 151–200 of 201')).toBeInTheDocument();
  await userEvent.type(screen.getByLabelText('Search'), ' draft');
  expect(fetcher).toHaveBeenCalledTimes(1);
  await userEvent.click(screen.getByRole('button', { name: 'Apply history filters' }));
  await screen.findByRole('link', { name: 'Stored result 1' });
  expect(screen.getByLabelText('Location')).toHaveTextContent('search=beacon+draft');
  await userEvent.click(screen.getByRole('button', { name: 'Browser Back' }));
  expect(screen.getByLabelText('Search')).toHaveValue('beacon');
  await userEvent.click(screen.getByRole('button', { name: 'Next analyses' }));
  await screen.findByRole('link', { name: 'Stored result 5' });
  expect(screen.getByText('Analyses 201–201 of 201')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Next analyses' })).toBeDisabled();
});

it('applies candidate deep-link filters and server pages while keeping drafts out of requests and history', async () => {
  const fetcher = setup('/candidates?page=3&severity=HIGH&workflow_status=IN_REVIEW&minimum_score=42&ti_filter=MISP_MATCH&include_suppressed=true&sort=-score');
  await screen.findByRole('link', { name: '203.0.113.9' });
  const params = new URL(String(fetcher.mock.calls[0][0]), 'http://localhost').searchParams;
  expect(Object.fromEntries(params)).toEqual({ page: '3', page_size: '50', minimum_score: '42', severity: 'HIGH', workflow_status: 'IN_REVIEW', ti_filter: 'MISP_MATCH', include_suppressed: 'true', sort: '-score' });
  expect(screen.getByText('Candidates 101–150 of 151')).toBeInTheDocument();
  await userEvent.selectOptions(screen.getByLabelText('Severity'), 'LOW');
  expect(fetcher).toHaveBeenCalledTimes(1);
  expect(screen.getByLabelText('Location')).toHaveTextContent('severity=HIGH');
  await userEvent.click(screen.getByRole('button', { name: 'Apply filters' }));
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
  expect(screen.getByLabelText('Location')).toHaveTextContent('severity=LOW');
  expect(screen.getByLabelText('Location')).not.toHaveTextContent('page=3');
  await userEvent.click(screen.getByRole('button', { name: 'Browser Back' }));
  expect(screen.getByLabelText('Severity')).toHaveValue('HIGH');
  expect(screen.getByText('Candidates 101–150 of 151')).toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Apply filters' }));
  // Applying page-three filters resets to page one; repeating that exact update is a no-op.
  await userEvent.click(screen.getByRole('button', { name: 'Apply filters' }));
  await userEvent.click(screen.getByRole('button', { name: 'Browser Back' }));
  expect(screen.getByLabelText('Location')).toHaveTextContent('page=3');
});
