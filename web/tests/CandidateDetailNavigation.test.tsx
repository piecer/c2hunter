import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, useLocation, useNavigate } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import App from '../src/App';
import { captureAuthentication, setAuthentication } from '../src/authentication';
import { candidateDetailHistory } from '../src/candidateDetailHistory';

const candidate = {
  id: 'navigation-a', job_id: 'job-a', candidate_ip: '203.0.113.9', score: 80, severity: 'HIGH',
  evidence: Array.from({ length: 30 }, (_, i) => ({ type: 'PERIODIC_BEACON', description: `Reason ${i + 1}`, metrics: { sample_count: 7 } })),
};
function RouteProbe() {
  const location = useLocation(); const navigate = useNavigate();
  return <><output aria-label="Location">{location.pathname}{location.search}{location.hash}</output><button onClick={() => navigate(-1)}>Browser Back</button><button onClick={() => navigate(1)}>Browser Forward</button><button onClick={() => navigate('/candidates/navigation-b?detail=raw')}>Test candidate B</button><button onClick={() => navigate(`/candidates/visit-${Number(location.pathname.match(/visit-(\d+)/)?.[1] ?? 0) + 1}?detail=network`)}>Next test candidate</button><output aria-label="Entry">{location.key}</output><output aria-label="Entry state">{JSON.stringify(location.state)}</output></>;
}
function mount(search = '', handler?: (path: string, init?: RequestInit) => Promise<Response>, state?: unknown) {
  localStorage.setItem('c2hunter-token', 'token');
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const requests: { path: string; method: string }[] = [];
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input); requests.push({ path, method: init?.method ?? 'GET' });
    return handler ? handler(path, init) : Response.json(candidate);
  }));
  const view = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[{ pathname: '/candidates/navigation-a', search: search.split('#')[0], hash: search.includes('#') ? `#${search.split('#')[1]}` : '', state }]}><App/><RouteProbe/></MemoryRouter></QueryClientProvider>);
  return { client, requests, unmount: view.unmount };
}

it('keeps the exact route identifier ordinarily accessible when no candidate source can be loaded', async () => {
  const user = userEvent.setup();
  mount('', async () => Response.json({ error: { message: 'Source unavailable' } }, { status: 404 }));
  await screen.findByText('Source unavailable');
  const toggle = screen.getByText('Candidate identifier');
  expect(toggle.closest('details')!.children).toHaveLength(1);
  await user.click(toggle);
  expect(await screen.findByText('Candidate navigation-a', { exact: true })).toBeInTheDocument();
  await user.click(toggle);
  await waitFor(() => expect(toggle.closest('details')!.children).toHaveLength(1));
});

it('restores deep-linked evidence and rejects malformed or incompatible selection without repairing the URL', async () => {
  const user = userEvent.setup(); const { requests } = mount('?q=keep&detail=evidence&evidence=29');
  await waitFor(() => expect(document.querySelector('.evidence.detailed')).toHaveTextContent('Reason 30'));
  await user.click(screen.getByRole('button', { name: 'Network context' }));
  await user.click(screen.getByRole('button', { name: 'Browser Back' }));
  expect(document.querySelector('.evidence.detailed')).toHaveTextContent('Reason 30');
  expect(requests.every(request => request.method === 'GET')).toBe(true);
});

it.each(['detail=evidence&evidence=01', 'detail=evidence&evidence=-1', 'detail=evidence&evidence=30', 'detail=network&evidence=1', 'detail=network&detail=raw', 'detail=flows&flow_page=0', 'detail=flows&flow_page=1e2', 'detail=flows&flow=', 'detail=unknown', 'evidence=1', 'detail=raw&flow=x'])('refuses closed URL contract violation %s', async search => {
  mount(`?${search}`);
  await screen.findByRole('heading', { name: candidate.candidate_ip });
  expect(screen.queryByRole('region', { name: 'Selected candidate detail' })).not.toBeInTheDocument();
  expect(screen.getByLabelText('Location')).toHaveTextContent(`?${search}`);
});

it('does not revive replaced evidence through Back, but permits a fresh explicit choice', async () => {
  const user = userEvent.setup(); const { client } = mount('?detail=evidence&evidence=0');
  await waitFor(() => expect(document.querySelector('.evidence.detailed')).toHaveTextContent('Reason 1'));
  await act(async () => { client.setQueryData(['candidate', candidate.id], { ...candidate, evidence: [{ ...candidate.evidence[0], description: 'Replacement evidence' }] }); });
  await waitFor(() => expect(document.querySelector('.evidence.detailed')).toBeNull());
  await user.click(screen.getByRole('button', { name: 'Network context' }));
  await user.click(screen.getByRole('button', { name: 'Browser Back' }));
  expect(document.querySelector('.evidence.detailed')).toBeNull();
  await user.click(screen.getByRole('button', { name: '근거 1 · 주기적 비콘' }));
  expect(document.querySelector('.evidence.detailed')).toHaveTextContent('Replacement evidence');
});

const flow = (id: string) => ({ flow_id: id, job_id: 'job-a', timestamp: '2026-11-15T00:00:00Z', source_ip: '10.0.0.1', destination_ip: candidate.candidate_ip, protocol: 'TCP', direction: 'OUTBOUND', has_payload: true });
it.each([403, 404, 410].flatMap(status => ['operations', 'flows'].map(section => ({ status, section }))))('R1 retirement survives source-route remount and cached ABA: $section $status', async ({ status, section }) => {
  const user = userEvent.setup(); let unavailable = false;
  const isFlow = section === 'flows';
  const { client, requests } = mount(`?q=context&detail=${section}${isFlow ? '&flow_page=1&flow=flow-a' : ''}`, async path => {
    if (path.endsWith('/analysis-jobs/job-a')) return Response.json({ error: { message: 'Source analysis fixture' } }, { status: 404 });
    if (path.endsWith('/navigation-b')) return Response.json({ ...candidate, id: 'navigation-b', candidate_ip: '203.0.113.10' });
    if (unavailable && (isFlow ? path.includes('/flows?') : path.endsWith('/navigation-a'))) return Response.json({ error: { message: 'Retired source' } }, { status });
    return Response.json(path.includes('/flows?') ? { items: [flow('flow-a')], page: 1, page_size: 50, total: 1 } : candidate);
  });
  const action = isFlow ? 'Mark benign flow-a' : 'Delete candidate';
  await screen.findByRole('button', { name: action });
  unavailable = true;
  await act(async () => { await client.invalidateQueries({ queryKey: isFlow ? ['candidate-flows'] : ['candidate', candidate.id] }); });
  await waitFor(() => expect(screen.queryByRole('button', { name: action })).not.toBeInTheDocument());
  unavailable = false;
  await act(async () => { await client.invalidateQueries({ queryKey: isFlow ? ['candidate-flows'] : ['candidate', candidate.id] }); });
  await waitFor(() => expect(screen.queryByText(/Retired source/)).not.toBeInTheDocument());
  await user.click(screen.getByRole('link', { name: 'View source analysis' }));
  expect(screen.getByLabelText('Location')).toHaveTextContent('/analyses/job-a');
  await user.click(screen.getByRole('button', { name: 'Browser Back' }));
  await screen.findByRole('heading', { name: candidate.candidate_ip });
  expect(screen.queryByRole('button', { name: action })).not.toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Test candidate B' }));
  await screen.findByRole('heading', { name: '203.0.113.10' });
  await user.click(screen.getByRole('button', { name: 'Browser Back' }));
  expect(screen.queryByRole('button', { name: action })).not.toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: isFlow ? 'Flow review' : '점수 조정 및 작업' }));
  if (isFlow) await user.click(await screen.findByRole('button', { name: 'Inspect flow flow-a' }));
  expect(await screen.findByRole('button', { name: action })).toBeEnabled();
  await user.click(screen.getByRole('button', { name: 'Browser Back' }));
  if (isFlow) await user.click(screen.getByRole('button', { name: 'Browser Back' }));
  expect(screen.queryByRole('button', { name: action })).not.toBeInTheDocument();
  expect(requests.every(request => request.method === 'GET')).toBe(true);
});

it.each([403, 404, 410])('does not revive a pre-retirement operation selection through Back after source %s', async status => {
  const user = userEvent.setup(); let unavailable = false;
  const { client } = mount('?detail=operations', async () => unavailable ? Response.json({ error: { message: 'Retired source' } }, { status }) : Response.json(candidate));
  await screen.findByRole('button', { name: 'Delete candidate' });
  unavailable = true;
  await act(async () => { await client.invalidateQueries({ queryKey: ['candidate', candidate.id] }); });
  await waitFor(() => expect(screen.queryByRole('button', { name: 'Delete candidate' })).not.toBeInTheDocument());
  unavailable = false;
  await user.click(screen.getByRole('button', { name: 'Retry candidate' }));
  await waitFor(() => expect(screen.queryByText(/Retired source/)).not.toBeInTheDocument());
  await user.click(screen.getByRole('button', { name: 'Network context' }));
  await user.click(screen.getByRole('button', { name: 'Browser Back' }));
  expect(screen.queryByRole('button', { name: 'Delete candidate' })).not.toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: '점수 조정 및 작업' }));
  expect(screen.getByRole('button', { name: 'Delete candidate' })).toBeEnabled();
});

it('requires fresh selection across authentication epoch transitions', async () => {
  const user = userEvent.setup(); mount('?detail=operations');
  await screen.findByRole('button', { name: 'Delete candidate' });
  await act(async () => { setAuthentication('next-authentication'); });
  await screen.findByRole('heading', { name: candidate.candidate_ip });
  expect(screen.queryByRole('button', { name: 'Delete candidate' })).not.toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: '점수 조정 및 작업' }));
  expect(screen.getByRole('button', { name: 'Delete candidate' })).toBeEnabled();
});

it('retains evidence through metadata refetch and transient 503, but never through owner replacement and fresh selection elsewhere', async () => {
  const user = userEvent.setup(); let transient = false;
  const { client } = mount('?detail=evidence&evidence=0', async () => transient ? Response.json({ error: { message: 'Transient refresh' } }, { status: 503 }) : Response.json(candidate));
  await waitFor(() => expect(document.querySelector('.evidence.detailed')).toHaveTextContent('Reason 1'));
  await act(async () => { client.setQueryData(['candidate', candidate.id], { ...candidate, score: 82 }); });
  await waitFor(() => expect(screen.getByText('82 · HIGH')).toBeInTheDocument());
  expect(document.querySelector('.evidence.detailed')).toHaveTextContent('Reason 1');
  transient = true;
  await act(async () => { await client.invalidateQueries({ queryKey: ['candidate', candidate.id] }); });
  expect(document.querySelector('.evidence.detailed')).toHaveTextContent('Reason 1');
  await act(async () => { client.setQueryData(['candidate', candidate.id], { ...candidate, evidence: [{ ...candidate.evidence[0], description: 'New owner' }] }); });
  await waitFor(() => expect(document.querySelector('.evidence.detailed')).toBeNull());
  await user.click(screen.getByRole('button', { name: '근거 1 · 주기적 비콘' }));
  expect(document.querySelector('.evidence.detailed')).toHaveTextContent('New owner');
  await user.click(screen.getByRole('button', { name: 'Browser Back' }));
  expect(document.querySelector('.evidence.detailed')).toBeNull();
});

it('revokes URL-selected flow authority when the evidence owner changes, retaining pending work until explicit reselection', async () => {
  const user = userEvent.setup();
  const { client } = mount('?detail=flows&flow_page=1&flow=flow-a', async path => Response.json(path.includes('/flows?') ? { items: [flow('flow-a')], page: 1, page_size: 50, total: 1 } : candidate));
  await screen.findByRole('button', { name: 'Mark benign flow-a' });
  await act(async () => { client.setQueryData(['candidate', candidate.id], { ...candidate, evidence: [{ ...candidate.evidence[0], description: 'Replaced source evidence' }] }); });
  await waitFor(() => expect(screen.queryByRole('button', { name: 'Mark benign flow-a' })).not.toBeInTheDocument());
  await user.click(screen.getByRole('button', { name: 'Flow review' }));
  await user.click(await screen.findByRole('button', { name: 'Inspect flow flow-a' }));
  expect(screen.getByRole('button', { name: 'Mark benign flow-a' })).toBeEnabled();
  await user.click(screen.getByRole('button', { name: 'Browser Back' }));
  await user.click(screen.getByRole('button', { name: 'Browser Back' }));
  expect(screen.queryByRole('button', { name: 'Mark benign flow-a' })).not.toBeInTheDocument();
});

it('restores traffic bucket pages through URL history without dropping the retained list context on close', async () => {
  const user = userEvent.setup();
  mount('?q=context&detail=buckets&bucket_page=2', async () => Response.json({ ...candidate, traffic_buckets: Array.from({ length: 600 }, (_, i) => ({ start: String(i), flows: i, packets: 1, bytes: 1 })) }));
  await screen.findByText('Buckets 51–100 of 600');
  await user.click(screen.getByRole('button', { name: 'Next traffic buckets' }));
  expect(screen.getByLabelText('Location')).toHaveTextContent('bucket_page=3');
  await user.click(screen.getByRole('button', { name: 'Browser Back' }));
  expect(screen.getByText('Buckets 51–100 of 600')).toBeInTheDocument();
  await user.keyboard('{Escape}');
  expect(screen.getByLabelText('Location')).toHaveTextContent('q=context&bucket_page=2');
});

it.each([403, 404, 410])('retired flow history cannot regain authority after %s and a fresh inspection', async status => {
  const user = userEvent.setup(); let unavailable = false;
  const { client } = mount('?detail=flows&flow_page=1&flow=flow-a', async path => path.includes('/flows?') ? unavailable ? Response.json({ error: { message: 'Retired flow source' } }, { status }) : Response.json({ items: [flow('flow-a')], page: 1, page_size: 50, total: 1 }) : Response.json(candidate));
  await screen.findByRole('button', { name: 'Mark benign flow-a' });
  unavailable = true;
  await act(async () => { await client.invalidateQueries({ queryKey: ['candidate-flows'] }); });
  await waitFor(() => expect(screen.queryByRole('button', { name: 'Mark benign flow-a' })).not.toBeInTheDocument());
  unavailable = false;
  await act(async () => { await client.invalidateQueries({ queryKey: ['candidate-flows'] }); });
  await screen.findByRole('button', { name: 'Inspect flow flow-a' });
  expect(screen.queryByRole('button', { name: 'Mark benign flow-a' })).not.toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Inspect flow flow-a' }));
  expect(screen.getByRole('button', { name: 'Mark benign flow-a' })).toBeEnabled();
  await user.click(screen.getByRole('button', { name: 'Network context' }));
  await user.click(screen.getByRole('button', { name: 'Browser Back' }));
  expect(screen.getByRole('button', { name: 'Mark benign flow-a' })).toBeEnabled();
  await user.click(screen.getByRole('button', { name: 'Browser Back' }));
  expect(screen.queryByRole('button', { name: 'Mark benign flow-a' })).not.toBeInTheDocument();
});

it('makes inspection of the same deep-linked flow a no-op regardless of query order', async () => {
  const user = userEvent.setup(); mount('?detail=flows&flow_page=2&flow=flow-b&q=keep', async path => Response.json(path.includes('/flows?') ? { items: [flow('flow-b')], page: 2, page_size: 50, total: 51 } : candidate));
  await screen.findByRole('button', { name: 'Mark benign flow-b' });
  const key = screen.getByLabelText('Entry').textContent;
  await user.click(screen.getByRole('button', { name: 'Inspect flow flow-b' }));
  expect(screen.getByLabelText('Entry')).toHaveTextContent(key!);
  expect(screen.getByLabelText('Location')).toHaveTextContent('?detail=flows&flow_page=2&flow=flow-b&q=keep');
});

it('retires an admitted flow if the refreshed page is a different source page even with the same id', async () => {
  const user = userEvent.setup(); let wrongPage = false;
  const { client, requests } = mount('?detail=flows&flow_page=2&flow=flow-b', async path => Response.json(path.includes('/flows?') ? { items: [flow('flow-b')], page: wrongPage ? 1 : 2, page_size: 50, total: 51 } : candidate));
  await screen.findByRole('button', { name: 'Mark benign flow-b' });
  const preview = screen.getByRole('button', { name: 'Preview payload flow-b' });
  const captured = (Object.entries(preview).find(([key]) => key.startsWith('__reactProps$'))?.[1] as { onClick: () => void }).onClick;
  wrongPage = true;
  await act(async () => { await client.invalidateQueries({ queryKey: ['candidate-flows'] }); });
  await waitFor(() => expect(screen.queryByRole('button', { name: 'Mark benign flow-b' })).not.toBeInTheDocument());
  await user.click(screen.getByRole('button', { name: 'Inspect flow flow-b' }));
  expect(screen.queryByRole('button', { name: 'Mark benign flow-b' })).not.toBeInTheDocument();
  await act(async () => { captured(); });
  expect(requests.filter(request => request.path.includes('/payload-preview'))).toHaveLength(0);
});

it('binds deep-linked flow to the requested page, pushes inspection/page history, and keeps pending owners through Back and close', async () => {
  const user = userEvent.setup(); let release!: (response: Response) => void;
  const pending = new Promise<Response>(resolve => { release = resolve; });
  const { requests } = mount('?q=keep&detail=flows&flow_page=2&flow=flow-b', async (path, init) => {
    if (init?.method === 'POST') return pending;
    if (path.includes('/flows?')) return Response.json({ items: [flow(path.includes('page=2') ? 'flow-b' : 'flow-a')], page: path.includes('page=2') ? 2 : 1, page_size: 1, total: 2 });
    return Response.json(candidate);
  });
  await user.click(await screen.findByRole('button', { name: 'Mark benign flow-b' }));
  expect(requests.filter(request => request.path.includes('/flows?')).map(request => request.path)).toEqual(['/api/v1/analysis-jobs/job-a/flows?candidate_ip=203.0.113.9&page=2&page_size=50']);
  await user.type(screen.getByLabelText('Analyst note'), 'URL keeps this draft');
  await user.click(screen.getByRole('button', { name: 'Save BENIGN label' }));
  await user.click(screen.getByRole('button', { name: 'Previous flows' }));
  expect(screen.getByLabelText('Location')).toHaveTextContent('flow_page=1');
  expect(screen.getByLabelText('Location')).not.toHaveTextContent('flow=');
  await user.click(await screen.findByRole('button', { name: 'Inspect flow flow-a' }));
  expect(screen.getByLabelText('Location')).toHaveTextContent('flow=flow-a');
  const entry = screen.getByLabelText('Entry').textContent;
  await user.click(screen.getByRole('button', { name: 'Inspect flow flow-a' }));
  expect(screen.getByLabelText('Entry')).toHaveTextContent(entry!);
  await user.click(screen.getByRole('button', { name: 'Browser Back' }));
  await user.click(screen.getByRole('button', { name: 'Browser Back' }));
  expect(screen.getByLabelText('Analyst note')).toHaveValue('URL keeps this draft');
  expect(screen.getByRole('button', { name: 'Saving…' })).toBeDisabled();
  await user.keyboard('{Escape}');
  expect(screen.getByLabelText('Location')).toHaveTextContent('q=keep&flow_page=2');
  expect(screen.getByText('flow-b · Saving…')).toBeInTheDocument();
  await act(async () => release(Response.json({ error: { message: 'Uncertain label' } }, { status: 503 })));
  expect(await screen.findByText('Uncertain label')).toBeInTheDocument();
  expect(requests.filter(request => request.method === 'POST')).toHaveLength(1);
});

it('never manufactures deep-linked membership or searches other pages for a missing flow', async () => {
  const { requests } = mount('?detail=flows&flow_page=2&flow=flow-a', async path => Response.json(path.includes('/flows?') ? { items: [flow('flow-b')], page: 2, page_size: 1, total: 2 } : candidate));
  await screen.findByRole('button', { name: 'Inspect flow flow-b' });
  expect(screen.queryByRole('button', { name: 'Mark C2 flow-a' })).not.toBeInTheDocument();
  expect(screen.getByText('Selected flow is not available on this source page. Select a retained flow explicitly.')).toBeInTheDocument();
  expect(requests.filter(request => request.path.includes('/flows?'))).toHaveLength(1);
  expect(requests.every(request => request.method === 'GET')).toBe(true);
});

it('ignores an inverted candidate response after an ordinary route departure and never admits a write from URL intent', async () => {
  const user = userEvent.setup();
  let release!: (response: Response) => void;
  const pending = new Promise<Response>(resolve => { release = resolve; });
  const { requests } = mount('?detail=operations', async path => path.endsWith('/navigation-a') ? pending : Response.json({ ...candidate, id: 'navigation-b', candidate_ip: '203.0.113.10' }));
  await user.click(screen.getByRole('button', { name: 'Test candidate B' }));
  await screen.findByRole('heading', { name: '203.0.113.10' });
  expect(JSON.parse(screen.getByLabelText('Retained candidate JSON').textContent!).id).toBe('navigation-b');
  await act(async () => { release(Response.json(candidate)); });
  expect(screen.queryByRole('button', { name: 'Delete candidate' })).not.toBeInTheDocument();
  expect(JSON.parse(screen.getByLabelText('Retained candidate JSON').textContent!).id).toBe('navigation-b');
  expect(requests.every(request => request.method === 'GET')).toBe(true);
});

it('revokes deletion intent on evidence replacement, including a captured submit before query notification', async () => {
  const user = userEvent.setup(); const { client, requests } = mount('?detail=operations');
  await user.click(await screen.findByRole('button', { name: 'Delete candidate' }));
  const confirm = screen.getByRole('button', { name: 'Delete permanently' });
  const captured = (Object.entries(confirm).find(([key]) => key.startsWith('__reactProps$'))?.[1] as { onClick: () => void }).onClick;
  await act(async () => {
    client.getQueryCache().find({ queryKey: ['candidate', candidate.id] })!.setState({ data: { ...candidate, evidence: [{ ...candidate.evidence[0], description: 'New evidence owner' }] } });
    captured();
  });
  await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Delete candidate permanently' })).not.toBeInTheDocument());
  expect(requests.filter(request => request.method === 'DELETE')).toHaveLength(0);
  await user.click(screen.getByRole('button', { name: '점수 조정 및 작업' }));
  await user.click(screen.getByRole('button', { name: 'Delete candidate' }));
  expect(screen.getByRole('button', { name: 'Delete permanently' })).toBeEnabled();
});

it('closes a Back-restored selection to that entry’s original opener rather than the last section clicked', async () => {
  const user = userEvent.setup(); mount();
  const opener = await screen.findByRole('button', { name: '근거 1 · 주기적 비콘' });
  await user.click(opener);
  await user.click(screen.getByRole('button', { name: 'Network context' }));
  await user.click(screen.getByRole('button', { name: 'Browser Back' }));
  await user.keyboard('{Escape}');
  expect(opener).toHaveFocus();
});

it('pushes semantic section selection, makes the same selection a no-op, and replaces only owned selection on close', async () => {
  const user = userEvent.setup(); mount('?q=retained&page=4&flow_page=2');
  await user.click(await screen.findByRole('button', { name: 'Network context' }));
  expect(screen.getByLabelText('Location')).toHaveTextContent('?q=retained&page=4&flow_page=2&detail=network');
  const entry = screen.getByLabelText('Entry').textContent;
  await user.click(screen.getByRole('button', { name: 'Network context' }));
  expect(screen.getByLabelText('Entry')).toHaveTextContent(entry!);
  await user.click(screen.getByRole('button', { name: 'Raw candidate' }));
  await user.click(screen.getByRole('button', { name: 'Browser Back' }));
  expect(screen.getByRole('heading', { name: 'Network context' })).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Browser Forward' }));
  expect(screen.getByLabelText('Retained candidate JSON')).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Close candidate detail' }));
  expect(screen.getByLabelText('Location')).toHaveTextContent('/candidates/navigation-a?q=retained&page=4&flow_page=2');
  expect(screen.getByLabelText('Location')).not.toHaveTextContent('detail=');
  await user.click(screen.getByRole('button', { name: 'Browser Back' }));
  expect(screen.getByRole('heading', { name: 'Network context' })).toBeInTheDocument();
});

it('R2 bounds actual retained history at 50 and 51 across abandoned forward branches, and refuses expired remounts', async () => {
  const user = userEvent.setup();
  const { client, requests } = mount('?q=keep&detail=operations', async path => path.endsWith('/analysis-jobs/job-a') ? Response.json({ error: { message: 'Analysis fixture' } }, { status: 404 }) : Response.json(candidate));
  await screen.findByRole('button', { name: 'Delete candidate' });
  const history = candidateDetailHistory(client, captureAuthentication().epoch);
  // Branch from the original entry repeatedly, abandoning the prior forward branch.
  const branch = screen.getByRole('button', { name: 'Network context' });
  const back = screen.getByRole('button', { name: 'Browser Back' });
  while (history.entries.size < 50) {
    await user.click(branch);
    await user.click(back);
  }
  expect(branch).toBeInTheDocument(); expect(back).toBeInTheDocument();
  expect(history.entries.size).toBe(50);
  await user.click(screen.getByRole('button', { name: 'Network context' }));
  expect(history.entries.size).toBe(50);
  await user.click(screen.getByRole('button', { name: 'Browser Back' }));
  expect(screen.queryByRole('button', { name: 'Delete candidate' })).not.toBeInTheDocument();
  await user.click(screen.getByRole('link', { name: 'View source analysis' }));
  await user.click(screen.getByRole('button', { name: 'Browser Back' }));
  await screen.findByRole('heading', { name: candidate.candidate_ip });
  expect(screen.queryByRole('button', { name: 'Delete candidate' })).not.toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: '점수 조정 및 작업' }));
  expect(screen.getByRole('button', { name: 'Delete candidate' })).toBeEnabled();
  await user.click(screen.getByRole('button', { name: 'Browser Back' }));
  expect(screen.queryByRole('button', { name: 'Delete candidate' })).not.toBeInTheDocument();
  expect(history.entries.size).toBeLessThanOrEqual(50);
  expect(document.querySelectorAll('*').length).toBeLessThanOrEqual(1200);
  expect(requests.every(request => request.method === 'GET')).toBe(true);
});

it('R2 navigation stores no strong DOM, evidence or authority references in application history', async () => {
  const tracked = new Set<Map<unknown, unknown>>();
  const original = Map.prototype.set;
  const observer = vi.spyOn(Map.prototype, 'set').mockImplementation(function(this: Map<unknown, unknown>, key, value) {
    if (new Error().stack?.includes('/src/useCandidateDetailSelection.ts') && (value instanceof HTMLElement || value === null || (value && typeof value === 'object' && ('focus' in value || 'retired' in value || 'sourceCurrent' in value)))) tracked.add(this);
    return original.call(this, key, value);
  });
  try {
    const user = userEvent.setup(); const { client } = mount();
    await user.click(await screen.findByRole('button', { name: '근거 1 · 주기적 비콘' }));
    await user.tab();
    await user.click(screen.getByRole('button', { name: 'Network context' }));
    await act(async () => { client.setQueryData(['candidate', candidate.id], { ...candidate, evidence: [{ ...candidate.evidence[0], description: 'Replacement' }] }); });
    const evidence = client.getQueryData<typeof candidate>(['candidate', candidate.id])!.evidence;
    const forbidden: string[] = [];
    const visit = (value: unknown) => {
      if (value instanceof Node) { forbidden.push('DOM'); return; }
      if (typeof value === 'function') { forbidden.push('closure'); return; }
      if (value === evidence || value === evidence[0] || (value && typeof value === 'object' && 'metrics' in value)) { forbidden.push('evidence'); return; }
      if (value && typeof value === 'object') Object.values(value).forEach(visit);
    };
    for (const map of tracked) for (const value of map.values()) visit(value);
    for (const entry of candidateDetailHistory(client, captureAuthentication().epoch).entries.values()) visit(entry);
    expect(tracked.size).toBeGreaterThan(0);
    expect([...candidateDetailHistory(client, captureAuthentication().epoch).evidenceIdentities.values()].every(ref => ref instanceof WeakRef)).toBe(true);
    expect(forbidden).toEqual([]);
    console.info('C2 retained-reference census', JSON.stringify({ observedApplicationMaps: tracked.size, forbiddenStrongReferences: forbidden.length }));
  } finally { observer.mockRestore(); }
});

it('R2 shares one 50-entry budget across candidates and releases retired source identities without GC', async () => {
  const user = userEvent.setup();
  const { client } = mount('?detail=network', async path => Response.json({ ...candidate, id: path.split('/').at(-1) }));
  await screen.findByRole('heading', { name: 'Network context' });
  const history = candidateDetailHistory(client, captureAuthentication().epoch);
  const nextCandidate = screen.getByRole('button', { name: 'Next test candidate' });
  for (let index = 1; index <= 50; index++) {
    await user.click(nextCandidate);
    await screen.findByRole('heading', { name: 'Network context' });
    expect(history.entries.size).toBe(Math.min(50, index + 1));
    expect(history.evidenceIdentities.size).toBe(Math.min(50, index + 1));
    expect(document.querySelectorAll('*').length).toBeLessThanOrEqual(1200);
  }
  expect(nextCandidate).toBeInTheDocument();
  const key = JSON.parse(screen.getByLabelText('Entry state').textContent!).candidateDetailEntry;
  await act(async () => { client.setQueryData(['candidate', 'visit-50'], { ...candidate, id: 'visit-50', job_id: 'job-new', evidence: [{ type: 'NEW', description: 'New source' }] }); });
  expect(history.entries.get(key)).toEqual({ retired: true, flowRetired: true, evidenceInvalid: true });
  expect(history.evidenceIdentities.size).toBe(49);
  const network = screen.getByRole('button', { name: 'Network context' });
  for (let index = 0; index < 55; index++) {
    await user.click(network);
    await act(async () => { client.setQueryData(['candidate', 'visit-50'], { ...candidate, id: 'visit-50', evidence: [{ type: 'NEW', description: `Replacement ${index}` }] }); });
    expect(history.entries.size).toBeLessThanOrEqual(50);
    expect(history.evidenceIdentities.size).toBeLessThanOrEqual(50);
  }
  expect(history.evidenceIdentities.size).toBe(0);
  expect([...history.entries.values()].every(entry => entry.retired && Object.keys(entry).length === 3)).toBe(true);
  expect(network).toBeInTheDocument();
  console.info('C2 retired-history census', JSON.stringify({ entries: history.entries.size, weakIdentitySlots: history.evidenceIdentities.size, fieldsPerRetiredEntry: [...new Set([...history.entries.values()].map(entry => Object.keys(entry).length))] }));
});

it('R2 a recreated client refuses a registered entry but still accepts a genuinely new deep link', async () => {
  const user = userEvent.setup();
  const first = mount('?detail=operations');
  await screen.findByRole('button', { name: 'Delete candidate' });
  const state = JSON.parse(screen.getByLabelText('Entry state').textContent!);
  expect(Object.keys(state).sort()).toEqual(['candidateDetailEntry', 'candidateDetailEpoch']);
  first.unmount();
  const second = mount('?detail=operations', undefined, state);
  await screen.findByRole('heading', { name: candidate.candidate_ip });
  expect(screen.queryByRole('button', { name: 'Delete candidate' })).not.toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: '점수 조정 및 작업' }));
  expect(screen.getByRole('button', { name: 'Delete candidate' })).toBeEnabled();
  await user.click(screen.getByRole('button', { name: 'Browser Back' }));
  expect(screen.queryByRole('button', { name: 'Delete candidate' })).not.toBeInTheDocument();
  second.unmount();
  mount('?detail=operations');
  expect(await screen.findByRole('button', { name: 'Delete candidate' })).toBeEnabled();
});

it('R2 observes off-route source ABA and does not keep replaced evidence alive in history', async () => {
  const user = userEvent.setup();
  const { client } = mount('?detail=evidence&evidence=0', async path => path.endsWith('/analysis-jobs/job-a') ? Response.json({ error: { message: 'Analysis fixture' } }, { status: 404 }) : Response.json(candidate));
  await waitFor(() => expect(document.querySelector('.evidence.detailed')).toHaveTextContent('Reason 1'));
  const history = candidateDetailHistory(client, captureAuthentication().epoch);
  const key = JSON.parse(screen.getByLabelText('Entry state').textContent!).candidateDetailEntry;
  await user.keyboard('{Escape}');
  await user.click(screen.getByRole('button', { name: '근거 1 · 주기적 비콘' }));
  await user.click(screen.getByRole('link', { name: 'View source analysis' }));
  await act(async () => {
    client.setQueryData(['candidate', candidate.id], { ...candidate, job_id: 'job-new', evidence: [{ type: 'NEW' }] });
    client.setQueryData(['candidate', candidate.id], candidate);
  });
  expect(history.entries.get(key)?.retired).toBe(true);
  expect(history.evidenceIdentities.size).toBe(0);
  await user.click(screen.getByRole('button', { name: 'Browser Back' }));
  await screen.findByRole('heading', { name: candidate.candidate_ip });
  expect(document.querySelector('.evidence.detailed')).toBeNull();
  await user.click(screen.getByRole('button', { name: '근거 1 · 주기적 비콘' }));
  expect(document.querySelector('.evidence.detailed')).toHaveTextContent('Reason 1');
});

it('R3 resumes the complete deferred flow intent without writing or losing page and context', async () => {
  const user = userEvent.setup(); let release!: (response: Response) => void;
  const pending = new Promise<Response>(resolve => { release = resolve; });
  const search = '?q=keep&detail=flows&flow_page=2&flow=flow-b#retained';
  const { requests } = mount(search, async path => path.includes('/flows?') ? Response.json({ items: [flow('flow-b')], page: 2, page_size: 50, total: 51 }) : pending);
  const menu = screen.getByRole('button', { name: '메뉴 / Menu' });
  await user.click(menu);
  await act(async () => release(Response.json(candidate)));
  await screen.findByRole('heading', { name: candidate.candidate_ip });
  expect(menu).toHaveFocus();
  expect(screen.queryByRole('region', { name: 'Selected candidate detail' })).not.toBeInTheDocument();
  expect(requests.filter(request => request.path.includes('/flows?'))).toHaveLength(0);
  await user.click(screen.getByRole('button', { name: 'Open requested detail' }));
  expect(screen.getByLabelText('Location')).toHaveTextContent(search);
  expect(await screen.findByRole('button', { name: 'Mark benign flow-b' })).toBeEnabled();
  expect(requests.filter(request => request.path.includes('/flows?')).map(request => request.path)).toEqual(['/api/v1/analysis-jobs/job-a/flows?candidate_ip=203.0.113.9&page=2&page_size=50']);
  expect(requests.every(request => request.method === 'GET')).toBe(true);
});

it('R2 history eviction does not evict eight pinned pending owners or their drafts and errors', async () => {
  const user = userEvent.setup(); const releases: ((response: Response) => void)[] = [];
  const bodies: unknown[] = [];
  const { client } = mount('?detail=flows', async (path, init) => {
    if (init?.method === 'POST') { bodies.push(JSON.parse(String(init.body))); return new Promise<Response>(resolve => { releases.push(resolve); }); }
    return Response.json(path.includes('/flows?') ? { items: Array.from({ length: 9 }, (_, index) => flow(`flow-${index}`)), page: 1, page_size: 50, total: 9 } : candidate);
  });
  for (let index = 0; index < 8; index++) {
    await user.click(await screen.findByRole('button', { name: `Inspect flow flow-${index}` }));
    await user.click(screen.getByRole('button', { name: `Mark benign flow-${index}` }));
    await user.type(screen.getByLabelText('Analyst note'), `draft-${index}`);
    await user.click(screen.getByRole('button', { name: 'Save BENIGN label' }));
  }
  expect(releases).toHaveLength(8);
  // These keyed navigation controls stay mounted across all 51 transitions.
  // Resolve their accessible roles once, rather than rescanning pending owners.
  const network = screen.getByRole('button', { name: 'Network context' });
  const raw = screen.getByRole('button', { name: 'Raw candidate' });
  for (let index = 0; index < 51; index++) await user.click(index % 2 ? raw : network);
  expect(network).toBeInTheDocument(); expect(raw).toBeInTheDocument();
  expect(candidateDetailHistory(client, captureAuthentication().epoch).entries.size).toBe(50);
  expect(document.querySelectorAll('[aria-label^="Retained flow review "]')).toHaveLength(8);
  await user.click(screen.getByRole('button', { name: 'Flow review' }));
  await user.click(screen.getByRole('button', { name: 'Inspect flow flow-8' }));
  expect(screen.getByText(/Limit: 8 retained flow reviews/)).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Inspect flow flow-0' }));
  expect(screen.getByLabelText('Analyst note')).toHaveValue('draft-0');
  expect(screen.getByRole('button', { name: 'Saving…' })).toBeDisabled();
  await act(async () => { releases.forEach((release, index) => release(Response.json({ error: { message: `Uncertain-${index}` } }, { status: 503 }))); });
  for (let index = 0; index < 8; index++) expect(await screen.findByText(`Uncertain-${index}`)).toBeInTheDocument();
  expect(bodies).toEqual(Array.from({ length: 8 }, (_, index) => ({ flow_id: `flow-${index}`, verdict: 'BENIGN', confidence: 'HIGH', note: `draft-${index}`, create_signature: false, signature_description: '' })));
  expect(document.querySelectorAll('[aria-label^="Retained flow review "]')).toHaveLength(8);
  expect(document.querySelectorAll('*').length).toBeLessThanOrEqual(2500);
});
