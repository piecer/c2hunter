import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import NetworkAIInterpretation from '../src/NetworkAIInterpretation';
import DDoSAIInterpretation from '../src/DDoSAIInterpretation';
import ReportLanguageScope from '../src/ReportLanguage';
import App from '../src/App';
import { setAuthentication } from '../src/authentication';
import { MemoryRouter } from 'react-router-dom';

const clients: QueryClient[] = [];
afterEach(() => clients.splice(0).forEach(client => client.clear()));
const variants = [
  { Component: NetworkAIInterpretation, kind: 'NETWORK_ANOMALY', open: 'Open AI interpretation', submit: 'AI interpretation', output: 'network_interpretation' },
  { Component: DDoSAIInterpretation, kind: 'DDOS_ATTACK', open: 'Open DDoS AI interpretation', submit: 'Run DDoS AI interpretation', output: 'ddos_interpretation' },
];
function fixture(kind: string, id: string, summary: string, status = 'COMPLETED') {
  return { id, analysis_job_id: 'saved', analysis_kind: kind, status, language: 'en', created_at: id === 'latest' ? '2026-11-02T00:00:00Z' : '2026-11-01T00:00:00Z',
    [kind === 'DDOS_ATTACK' ? 'ddos_interpretation' : 'network_interpretation']: {
      schema_version: kind === 'DDOS_ATTACK' ? 'ddos-interpretation-v1' : 'network-interpretation-v1', kind: 'MODEL_INTERPRETATION', language: 'en', summary,
      possible_causes: [], risk_context: [], prioritized_checks: [], correlations: [], response_considerations: [], limitations: ['Capture scope only.'],
    },
  };
}
function setup(variant: typeof variants[number], active = false, completed = false) {
  localStorage.setItem('c2hunter-report-language', 'en');
  const latest = fixture(variant.kind, 'latest', 'Latest saved prose.', active ? 'ANALYZING' : 'COMPLETED');
  const older = fixture(variant.kind, 'older', 'Older saved prose.');
  const requests: { url: string; method: string }[] = [];
  vi.stubGlobal('fetch', vi.fn(async (input: unknown, init?: RequestInit) => {
    const url = String(input), method = init?.method ?? 'GET'; requests.push({ url, method });
    if (url.endsWith('/ai-capabilities')) return Response.json({ available: completed, network_interpretation: completed, ddos_interpretation: completed, remote: false });
    if (url.endsWith('/analysis-jobs/saved/ai-runs')) return Response.json({ items: [latest, older], current_page: 1, page_size: 50, total: 2 });
    if (url.endsWith('/ai-runs/latest')) return Response.json(latest);
    if (url.endsWith('/ai-runs/older')) return Response.json(older);
    if (url.endsWith('/cancel')) return Response.json({});
    throw new Error(`Unexpected ${method} ${url}`);
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } }); clients.push(client);
  const Component = variant.Component;
  const view = render(<QueryClientProvider client={client}><ReportLanguageScope><Component jobId="saved" completed={completed}/></ReportLanguageScope></QueryClientProvider>);
  return { requests, client, ...view };
}
it.each(['absent', 'unsupported'])('actual App retains DDoS saved history with %s source and one page locale', async source => {
  localStorage.setItem('c2hunter-token', 'fixture'); localStorage.setItem('c2hunter-report-language', 'en');
  const run = fixture('DDOS_ATTACK', 'latest', 'Saved without current source.');
  const job = { id: 'saved', name: 'Saved source unavailable', status: 'COMPLETED', analysis: { module: 'ddos_attack' }, ...(source === 'unsupported' ? { ddos_attack: { version: 'future' } } : {}) };
  const posts: string[] = [];
  vi.stubGlobal('fetch', vi.fn(async (input: unknown, init?: RequestInit) => {
    const path = String(input); if (init?.method === 'POST') posts.push(path);
    return Response.json(path.endsWith('/analysis-jobs/saved') ? job : path.endsWith('/ai-capabilities') ? { available: true, ddos_interpretation: true, remote: false } : path.endsWith('/ai-runs/latest') ? run : path.endsWith('/saved/ai-runs') ? { items: [run] } : { items: [] });
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } }); clients.push(client);
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/analyses/saved']}><App/></MemoryRouter></QueryClientProvider>);
  fireEvent.click(await screen.findByRole('button', { name: 'Open DDoS AI interpretation' }));
  expect(await screen.findByText('Saved without current source.')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'New AI interpretation' }));
  expect(screen.getByRole('button', { name: 'Run DDoS AI interpretation' })).toBeDisabled();
  fireEvent.change(screen.getByRole('combobox', { name: /^(보고서 언어|Report language)$/ }), { target: { value: 'ko' } });
  expect(screen.getByRole('button', { name: '새 AI 해석' })).toBeVisible();
  expect(screen.getByText('Saved without current source.')).toHaveAttribute('lang', 'en');
  expect(posts).toEqual([]);
});
it.each(variants)('$kind keeps saved provider and request provenance behind a separate metadata entry', async variant => {
  const { client } = setup(variant);
  await waitFor(() => expect(client.isFetching()).toBe(0));
  act(() => { client.setQueryData(['ai-run', 'latest'], { ...fixture(variant.kind, 'latest', 'Latest saved prose.'), provider: 'saved-provider', model_name: 'saved-model', completed_at: '2026-11-02T00:01:00Z' }); });
  fireEvent.click(screen.getByRole('button', { name: variant.open }));
  expect(screen.queryByText(/saved-provider/)).not.toBeInTheDocument();
  const entry = screen.getByText('Saved run metadata', { selector: 'summary' });
  fireEvent.click(entry); fireEvent(entry.closest('details')!, new Event('toggle'));
  expect(screen.getByText(/saved-provider.*saved-model/)).toBeVisible();
  expect(screen.getByText(/Generated language/)).toHaveTextContent('English');
  expect(screen.queryByRole('button', { name: variant.submit })).not.toBeInTheDocument();
});
it.each(variants)('$kind explicitly refuses unsupported saved output instead of claiming a healthy result', async variant => {
  const { client } = setup(variant);
  await waitFor(() => expect(client.isFetching()).toBe(0));
  const run = fixture(variant.kind, 'latest', 'Unsupported prose');
  (run[variant.output] as Record<string, unknown>).schema_version = 'future-schema';
  act(() => { client.setQueryData(['ai-run', 'latest'], run); });
  fireEvent.click(screen.getByRole('button', { name: variant.open }));
  expect(screen.getByText('No validated interpretation is available for this run.')).toBeVisible();
  expect(screen.queryByText('Unsupported prose')).not.toBeInTheDocument();
});
it.each(variants)('$kind retires full-text selection across saved result ABA', async variant => {
  setup(variant);
  fireEvent.click(await screen.findByRole('button', { name: variant.open }));
  fireEvent.click(await screen.findByRole('button', { name: 'View saved run older' }));
  expect(await screen.findByText('Older saved prose.')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'View full AI text' }));
  expect(screen.getByRole('article', { name: /Full .*AI interpretation/ })).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Follow latest run' }));
  expect(screen.queryByRole('article', { name: /Full .*AI interpretation/ })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'View saved run older' }));
  expect(await screen.findByText('Older saved prose.')).toBeVisible();
  expect(screen.queryByRole('article', { name: /Full .*AI interpretation/ })).not.toBeInTheDocument();
});
it.each(variants)('$kind never colors a failed run as a low-risk conclusion', async variant => {
  const { client } = setup(variant);
  await waitFor(() => expect(client.isFetching()).toBe(0));
  act(() => { client.setQueryData(['ai-run', 'latest'], fixture(variant.kind, 'latest', 'Not validated', 'FAILED')); });
  fireEvent.click(screen.getByRole('button', { name: variant.open }));
  expect(screen.getByRole('status', { name: 'Latest AI run' }).querySelector('.low')).toBeNull();
  expect(screen.queryByText('Not validated')).not.toBeInTheDocument();
});
it.each(variants)('$kind never admits inference after a failed latest status read', async variant => {
  const { client } = setup(variant, false, true);
  await waitFor(() => expect(client.isFetching()).toBe(0));
  const original = globalThis.fetch;
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => String(input).endsWith('/ai-runs/latest') ? Response.json({ error: { message: 'Status unavailable' } }, { status: 503 }) : original(input, init)));
  await act(async () => { await client.refetchQueries({ queryKey: ['ai-run', 'latest'] }); });
  fireEvent.click(screen.getByRole('button', { name: variant.open }));
  fireEvent.click(screen.getByRole('button', { name: 'New AI interpretation' }));
  expect(screen.getByRole('button', { name: variant.submit })).toBeDisabled();
});
it.each(variants)('$kind resolves latest ownership beyond a full mixed-kind first page before allowing admission', async variant => {
  const { client, requests } = setup(variant, false, true);
  await waitFor(() => expect(client.isFetching()).toBe(0));
  const original = globalThis.fetch;
  const active = { ...fixture(variant.kind, 'hidden-active', '', 'ANALYZING'), created_at: '2026-11-03T00:00:00Z' };
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path.endsWith('/saved/ai-runs')) return Response.json({ items: Array.from({ length: 50 }, (_, i) => fixture('C2', `other-${i}`, '')), current_page: 1, page_size: 50, total: 51 });
    if (path.endsWith('/saved/ai-runs?page=2&page_size=50')) return Response.json({ items: [active], current_page: 2, page_size: 50, total: 51 });
    if (path.endsWith('/ai-runs/hidden-active')) return Response.json(active);
    return original(input, init);
  }));
  await act(async () => { await client.invalidateQueries({ queryKey: ['ai-runs', 'saved'] }); });
  fireEvent.click(screen.getByRole('button', { name: variant.open }));
  fireEvent.click(screen.getByRole('button', { name: 'New AI interpretation' }));
  expect(screen.getByRole('button', { name: variant.submit })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Continue latest-run lookup' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Cancel AI run' }));
  await waitFor(() => expect(requests.filter(request => request.method === 'POST')).toEqual([{ url: '/api/v1/ai-runs/hidden-active/cancel', method: 'POST' }]));
});
it.each(variants)('$kind fences captured start callbacks after authentication retirement', async variant => {
  const { requests } = setup(variant, false, true);
  fireEvent.click(await screen.findByRole('button', { name: variant.open }));
  fireEvent.click(screen.getByRole('button', { name: 'New AI interpretation' }));
  await waitFor(() => expect(screen.getByRole('button', { name: variant.submit })).toBeEnabled());
  const button = screen.getByRole('button', { name: variant.submit });
  const props = Object.values(button).find(value => value && typeof value === 'object' && 'onClick' in value) as { onClick: () => void };
  act(() => { setAuthentication('replacement'); props.onClick(); });
  await act(async () => {});
  expect(requests.filter(request => request.method === 'POST')).toEqual([]);
});
it.each(variants)('$kind treats a malformed admission receipt as persistent uncertainty, not permission for a new POST', async variant => {
  const { client } = setup(variant, false, true);
  const original = globalThis.fetch;
  let posts = 0;
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    if (init?.method === 'POST') { posts += 1; return Response.json({ status: 'QUEUED' }); }
    return original(input, init);
  }));
  fireEvent.click(await screen.findByRole('button', { name: variant.open }));
  fireEvent.click(screen.getByRole('button', { name: 'New AI interpretation' }));
  await waitFor(() => expect(screen.getByRole('button', { name: variant.submit })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: variant.submit }));
  await waitFor(() => expect(client.isMutating()).toBe(0));
  expect(screen.getByRole('button', { name: variant.submit })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: variant.open.replace('Open', 'Close') }));
  expect(screen.getByText('AI admission unconfirmed. Review the request before trying again.')).toBeVisible();
  expect(posts).toBe(1);
});
it.each(variants)('$kind keeps failed cancellation explicitly unconfirmed while hidden', async variant => {
  const { client, requests } = setup(variant, true, true);
  const original = globalThis.fetch;
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    if (String(input).endsWith('/cancel')) { requests.push({ url: String(input), method: init?.method ?? 'GET' }); throw new TypeError('Unconfirmed cancellation'); }
    return original(input, init);
  }));
  fireEvent.click(await screen.findByRole('button', { name: variant.open }));
  fireEvent.click(await screen.findByRole('button', { name: 'Cancel AI run' }));
  await waitFor(() => expect(client.isMutating()).toBe(0));
  fireEvent.click(screen.getByRole('button', { name: variant.open.replace('Open', 'Close') }));
  expect(screen.getByText('AI cancellation unconfirmed — the run may still be active.')).toBeVisible();
  expect(requests.filter(request => request.method === 'POST')).toHaveLength(1);
});
it.each(variants)('$kind issues one cancellation and retains the active owner through old history selection', async variant => {
  const { requests, client } = setup(variant, true, true);
  let release!: (response: Response) => void;
  const pending = new Promise<Response>(resolve => { release = resolve; });
  const original = globalThis.fetch;
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    if (String(input).endsWith('/cancel')) { requests.push({ url: String(input), method: init?.method ?? 'GET' }); return pending; }
    return original(input, init);
  }));
  fireEvent.click(await screen.findByRole('button', { name: variant.open }));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Cancel AI run' })).toBeEnabled());
  const cancel = screen.getByRole('button', { name: 'Cancel AI run' });
  act(() => { cancel.click(); cancel.click(); });
  fireEvent.click(screen.getByRole('button', { name: 'View saved run older' }));
  expect(await screen.findByText('Older saved prose.')).toBeVisible();
  expect(screen.getByText('AI cancellation pending — stopping is not yet confirmed.')).toBeVisible();
  await act(async () => { release(Response.json({})); });
  await waitFor(() => expect(client.isMutating()).toBe(0));
  expect(requests.filter(request => request.method === 'POST')).toEqual([{ url: '/api/v1/ai-runs/latest/cancel', method: 'POST' }]);
});
it.each(variants)('$kind retires late acknowledgement publication on unmount without cancelling server work', async variant => {
  const { client, unmount } = setup(variant, false, true);
  let release!: (response: Response) => void;
  const pending = new Promise<Response>(resolve => { release = resolve; });
  const original = globalThis.fetch;
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => init?.method === 'POST' ? pending : original(input, init)));
  fireEvent.click(await screen.findByRole('button', { name: variant.open }));
  fireEvent.click(screen.getByRole('button', { name: 'New AI interpretation' }));
  await waitFor(() => expect(screen.getByRole('button', { name: variant.submit })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: variant.submit }));
  await waitFor(() => expect(client.isMutating()).toBe(1));
  const invalidations = vi.spyOn(client, 'invalidateQueries');
  unmount();
  await act(async () => { release(Response.json(fixture(variant.kind, 'late', '', 'QUEUED'))); });
  await waitFor(() => expect(client.isMutating()).toBe(0));
  expect(invalidations).not.toHaveBeenCalled();
});
it.each(variants)('$kind retains a newer observed active identity through stale lists and a late acknowledgement', async variant => {
  const { client, requests } = setup(variant, false, true);
  const original = globalThis.fetch;
  let release!: (response: Response) => void;
  const pending = new Promise<Response>(resolve => { release = resolve; });
  const newer = { ...fixture(variant.kind, 'newer', '', 'ANALYZING'), created_at: '2026-11-03T00:00:00.123900Z' };
  const admitted = { ...fixture(variant.kind, 'admitted', '', 'QUEUED'), created_at: '2026-11-03T00:00:00.123100Z' };
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    if (init?.method === 'POST' && String(input).endsWith('/saved/ai-runs')) return pending;
    if (String(input).endsWith('/ai-runs/newer')) return Response.json(newer);
    if (String(input).endsWith('/ai-runs/admitted')) return Response.json(admitted);
    return original(input, init);
  }));
  fireEvent.click(await screen.findByRole('button', { name: variant.open }));
  fireEvent.click(screen.getByRole('button', { name: 'New AI interpretation' }));
  await waitFor(() => expect(screen.getByRole('button', { name: variant.submit })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: variant.submit }));
  await waitFor(() => expect(client.isMutating()).toBe(1));
  act(() => { client.setQueryData(['ai-runs', 'saved'], { items: [newer, admitted, fixture(variant.kind, 'older', 'Older saved prose.')] }); });
  await waitFor(() => expect(client.getQueryData(['ai-run', 'newer'])).toBeDefined());
  fireEvent.click(screen.getByRole('button', { name: 'View saved run older' }));
  expect(await screen.findByText('Older saved prose.')).toBeVisible();
  act(() => { client.setQueryData(['ai-runs', 'saved'], { items: [admitted] }); });
  await act(async () => { release(Response.json(admitted)); });
  await waitFor(() => expect(client.isMutating()).toBe(0));
  expect(screen.getByText('Older saved prose.')).toBeVisible();
  expect(screen.getByRole('button', { name: variant.submit })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Cancel AI run' }));
  await waitFor(() => expect(requests.filter(request => request.method === 'POST')).toEqual([{ url: '/api/v1/ai-runs/newer/cancel', method: 'POST' }]));
});
it.each(variants)('$kind bounds the initial claims and preserves every full-text page and long qualification', async variant => {
  const { client } = setup(variant);
  await waitFor(() => expect(client.isFetching()).toBe(0));
  const value = fixture(variant.kind, 'latest', 'Latest saved prose.');
  const prose = value[variant.output] as Record<string, unknown>;
  const long = 'Qualification '.repeat(80) + 'END OF QUALIFICATION';
  prose[variant.kind === 'DDOS_ATTACK' ? 'risk_context' : 'possible_causes'] = Array.from({ length: 8 }, (_, i) => ({ hypothesis: `Claim ${i}`, interpretation: `Claim ${i}`, uncertainty: i === 7 ? long : 'Not proven.', issue_ids: ['issue-1'], finding_ids: ['ddos-1234567890abcdef'] }));
  prose.limitations = ['All limitations retained.'];
  act(() => { client.setQueryData(['ai-run', 'latest'], value); });
  fireEvent.click(screen.getByRole('button', { name: variant.open }));
  expect(screen.getByText('Claim 0')).toBeVisible();
  expect(screen.getByText('Claim 2')).toBeVisible();
  expect(screen.queryByText('Claim 3')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'View full AI text' }));
  const seen = new Set<string>();
  for (let page = 0; page < 3; page += 1) {
    screen.getAllByText(/^Claim /).forEach(node => seen.add(node.textContent!));
    if (page < 2) fireEvent.click(screen.getByRole('button', { name: 'Next AI claims' }));
  }
  expect([...seen]).toEqual(Array.from({ length: 8 }, (_, i) => `Claim ${i}`));
  expect(screen.getByText(long)).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Limitations' }));
  expect(screen.getByText('All limitations retained.')).toBeVisible();
});
it.each(variants)('$kind pins pending admission across same-turn clicks, hiding, language and old selection', async variant => {
  const { requests, client } = setup(variant, false, true);
  const original = globalThis.fetch;
  let release!: (response: Response) => void;
  const pending = new Promise<Response>(resolve => { release = resolve; });
  const bodies: string[] = [];
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    if (init?.method === 'POST' && String(input).endsWith('/analysis-jobs/saved/ai-runs')) {
      bodies.push(String(init.body));
      return pending;
    }
    return original(input, init);
  }));
  fireEvent.click(await screen.findByRole('button', { name: variant.open }));
  fireEvent.click(screen.getByRole('button', { name: 'New AI interpretation' }));
  await waitFor(() => expect(screen.getByRole('button', { name: variant.submit })).toBeEnabled());
  const button = screen.getByRole('button', { name: variant.submit });
  act(() => { button.click(); button.click(); });
  await waitFor(() => expect(bodies).toHaveLength(1));
  fireEvent.click(screen.getByRole('button', { name: 'View saved run older' }));
  expect(await screen.findByText('Older saved prose.')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: variant.open.replace('Open', 'Close') }));
  expect(screen.getByText('AI request pending — admission not yet confirmed.')).toBeVisible();
  fireEvent.change(screen.getByRole('combobox'), { target: { value: 'ko' } });
  await act(async () => { release(Response.json(fixture(variant.kind, 'latest', 'Latest saved prose.'))); });
  await waitFor(() => expect(client.isMutating()).toBe(0));
  expect(JSON.parse(bodies[0]).language).toBe('en');
  fireEvent.click(screen.getByRole('button', { name: variant.kind === 'DDOS_ATTACK' ? 'DDoS AI 해석 열기' : 'AI 해석 열기' }));
  expect(screen.getByText('Older saved prose.')).toHaveAttribute('lang', 'en');
  expect(bodies).toHaveLength(1);
  expect(requests.filter(request => request.method === 'POST')).toHaveLength(0);
});
it.each(variants)('$kind blocks a new admission after an ambiguous POST, preserving the warning while hidden', async variant => {
  const { client } = setup(variant, false, true);
  const original = globalThis.fetch;
  const bodies: string[] = [];
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    if (init?.method === 'POST') { bodies.push(String(init.body)); throw new TypeError('Connection lost'); }
    return original(input, init);
  }));
  fireEvent.click(await screen.findByRole('button', { name: variant.open }));
  fireEvent.click(screen.getByRole('button', { name: 'New AI interpretation' }));
  await waitFor(() => expect(screen.getByRole('button', { name: variant.submit })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: variant.submit }));
  await waitFor(() => expect(client.isMutating()).toBe(0));
  expect(screen.getByRole('button', { name: variant.submit })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: variant.open.replace('Open', 'Close') }));
  expect(screen.getByText('AI admission unconfirmed. Review the request before trying again.')).toBeVisible();
  expect(bodies).toHaveLength(1);
});
it.each(variants)('$kind reaches later mixed-kind history pages without poisoning latest ownership', async variant => {
  const { client, requests } = setup(variant, true, true);
  const original = globalThis.fetch;
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith('?page=2&page_size=50')) {
      requests.push({ url, method: init?.method ?? 'GET' });
      return Response.json({ items: [fixture('C2', 'unrelated', 'Not a module result')], page: 2, page_size: 50, total: 101 });
    }
    if (url.endsWith('?page=3&page_size=50')) return Response.json({ items: [fixture(variant.kind, 'older', 'Older saved prose.')], page: 3, page_size: 50, total: 101 });
    return original(input, init);
  }));
  await waitFor(() => expect(client.isFetching()).toBe(0));
  act(() => { client.setQueryData(['ai-runs', 'saved'], { items: [fixture(variant.kind, 'latest', '', 'ANALYZING')], page: 1, page_size: 50, total: 101 }); });
  fireEvent.click(screen.getByRole('button', { name: variant.open }));
  fireEvent.click(screen.getByRole('button', { name: 'Next saved runs' }));
  expect(await screen.findByText('No matching runs on this page.')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Next saved runs' }));
  fireEvent.click(await screen.findByRole('button', { name: 'View saved run older' }));
  expect(await screen.findByText('Older saved prose.')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Cancel AI run' }));
  await waitFor(() => expect(requests.filter(request => request.method === 'POST')).toEqual([{ url: '/api/v1/ai-runs/latest/cancel', method: 'POST' }]));
});
it.each(variants)('$kind reads saved results before the lazy form without current source or capability', async variant => {
  const { requests } = setup(variant);
  fireEvent.click(await screen.findByRole('button', { name: variant.open }));
  expect(await screen.findByText('Latest saved prose.')).toBeVisible();
  expect(screen.getByRole('region', { name: 'Saved AI runs' })).toBeVisible();
  expect(screen.queryByRole('button', { name: variant.submit })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'View saved run older' }));
  expect(await screen.findByText('Older saved prose.')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'New AI interpretation' }));
  expect(screen.getByRole('button', { name: variant.submit })).toBeDisabled();
  expect(requests.every(request => request.method === 'GET')).toBe(true);
});
it.each(variants)('$kind historical selection never replaces the active cancellation owner', async variant => {
  const { requests, client } = setup(variant, true, true);
  fireEvent.click(await screen.findByRole('button', { name: variant.open }));
  fireEvent.click(await screen.findByRole('button', { name: 'View saved run older' }));
  expect(await screen.findByText('Older saved prose.')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'New AI interpretation' }));
  expect(screen.getByText(variant.kind === 'DDOS_ATTACK' ? 'ANALYZING' : 'Analyzing')).toBeVisible();
  expect(screen.getByRole('button', { name: variant.submit })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Cancel AI run' }));
  await act(async () => { await client.invalidateQueries({ queryKey: ['ai-runs', 'saved'] }); });
  await waitFor(() => expect(requests.filter(request => request.method === 'POST')).toEqual([{ url: '/api/v1/ai-runs/latest/cancel', method: 'POST' }]));
  expect(screen.getByText('Older saved prose.')).toBeVisible();
});
