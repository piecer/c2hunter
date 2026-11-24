import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, expect, it, vi } from 'vitest';
import App from '../src/App';
import * as auth from '../src/authentication';

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
const csrf = { csrf_token: null, account_login_enabled: false, dev_login_enabled: true, setup_required: false };
const bearer = (subject = 'A', role = 'ADMIN') => ({ auth_kind: 'bearer', user: null, principal: { subject, role }, csrf_token: null, session_id: null, identity_scope: 'legacy:' + subject, audit_available: true });
function mount(path = '/login') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><App/></MemoryRouter></QueryClientProvider>);
  return client;
}
beforeEach(() => {
  localStorage.clear(); sessionStorage.clear(); auth.setAuthentication(null);
  localStorage.setItem('c2hunter-report-language', 'en');
  vi.stubGlobal('matchMedia', () => ({ matches: false, addEventListener() {}, removeEventListener() {} }));
});
it('development login returns to Dashboard only after real bearer introspection', async () => {
  let release!: (response: Response) => void;
  const fetcher = vi.fn(async (path: string) => {
    if (path.endsWith('/csrf')) return json(csrf);
    if (path.endsWith('/dev-login')) return json({ access_token: 'A' });
    if (path.endsWith('/me')) return new Promise<Response>(resolve => { release = resolve; });
    return json({ error: { message: 'Domain data unavailable in this authentication test' } }, 503);
  });
  vi.stubGlobal('fetch', fetcher); mount();
  await waitFor(() => expect(screen.getByRole('button', { name: 'Development login' })).toBeEnabled());
  fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'analyst' } });
  fireEvent.click(screen.getByRole('button', { name: 'Development login' }));
  await waitFor(() => expect(release).toBeTypeOf('function'));
  expect(screen.queryByRole('heading', { name: 'Dashboard' })).toBeNull();
  await act(async () => release(json(bearer())));
  await screen.findByRole('heading', { name: 'Dashboard' });
  expect(screen.queryByRole('heading', { name: 'Account' })).toBeNull();
  expect(fetcher.mock.calls.filter(([path]) => path.endsWith('/dev-login'))).toHaveLength(1);
});

async function identifyBearer() {
  auth.setAuthentication('A');
  vi.stubGlobal('fetch', vi.fn(async (path: string) => json(path.endsWith('/csrf') ? csrf : bearer())));
  await auth.initializeAccountAuthentication();
}
it('raw bearer plus public event retires authority and caches before held /me grants the replacement role', async () => {
  await identifyBearer();
  vi.stubGlobal('fetch', vi.fn(async () => json({ items: [], total: 0 })));
  const client = mount('/analyses');
  await screen.findByRole('heading', { name: 'Analysis history' });
  const old = auth.captureAuthentication();
  client.setQueryData(['private-A'], { secret: 'old-owner' });
  let release!: (response: Response) => void;
  const fetcher = vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(() => new Promise<Response>(resolve => { release = resolve; }));
  vi.stubGlobal('fetch', fetcher);
  act(() => {
    localStorage.setItem('c2hunter-token', 'B');
    window.dispatchEvent(new Event('c2hunter-auth-changed'));
    expect(auth.currentAuthentication(old)).toBe(false);
    expect(auth.captureAuthentication().epoch).not.toBe(old.epoch);
    expect(auth.captureAuthentication().identityScope).toBeUndefined();
    expect(auth.hasAuthentication()).toBe(false);
    expect(auth.hasRole('ADMIN')).toBe(false);
    expect(client.getQueryData(['private-A'])).toBeUndefined();
  });
  expect(screen.queryByRole('link', { name: 'Integration settings' })).toBeNull();
  expect(screen.queryByRole('heading', { name: 'Analysis history' })).toBeNull();
  await waitFor(() => expect(release).toBeTypeOf('function'));
  expect(fetcher).toHaveBeenCalledTimes(1);
  expect(fetcher.mock.calls[0]?.[0]).toBe('/api/v1/auth/me');
  vi.stubGlobal('fetch', vi.fn(async () => json({ items: [], total: 0 })));
  await act(async () => release(json(bearer('B', 'VIEWER'))));
  await screen.findByRole('heading', { name: 'Analysis history' });
  expect(auth.captureAuthentication()).toMatchObject({ token: 'B', identityScope: 'legacy:B', role: 'VIEWER' });
  expect(auth.hasRole('ADMIN')).toBe(false);
  expect(client.getQueryData(['private-A'])).toBeUndefined();
});
