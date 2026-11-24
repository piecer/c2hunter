import { beforeEach, expect, it, vi } from 'vitest';
import * as auth from '../src/authentication';
import { api } from '../src/api';

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
const csrf = { csrf_token: null, account_login_enabled: false, dev_login_enabled: true, setup_required: false };
const bearer = (subject = 'A', role = 'ADMIN') => ({ auth_kind: 'bearer', user: null, principal: { subject, role }, csrf_token: null, session_id: null, identity_scope: 'legacy:' + subject, audit_available: true });
const session = { auth_kind: 'session', user: { id: 'alice', username: 'alice', role: 'ANALYST', active: true, must_change_password: false }, csrf_token: 'memory-only', session_id: 'session-A', identity_scope: 'user:alice', audit_available: true };
const event = () => window.dispatchEvent(new Event('c2hunter-auth-changed'));
const storage = (oldValue: string | null, newValue: string | null) => window.dispatchEvent(new StorageEvent('storage', { key: 'c2hunter-token', oldValue, newValue }));
function held() {
  const releases: ((response: Response) => void)[] = [];
  const fetcher = vi.fn<(path: string, init?: RequestInit) => Promise<Response>>(() => new Promise(resolve => { releases.push(resolve); }));
  vi.stubGlobal('fetch', fetcher);
  return { releases, fetcher };
}
async function ready() {
  auth.setAuthentication('A');
  vi.stubGlobal('fetch', vi.fn(async (path: string) => json(path.endsWith('/csrf') ? csrf : bearer())));
  await auth.initializeAccountAuthentication();
}
beforeEach(() => { localStorage.clear(); sessionStorage.clear(); auth.setAuthentication(null); });
it('capture retires a raw replacement without recursive render-time events; duplicate notifications hydrate once', async () => {
  await ready(); const old = auth.captureAuthentication(); const { releases, fetcher } = held();
  const changed = vi.fn(() => { auth.captureAuthentication(); });
  window.addEventListener('c2hunter-auth-changed', changed);
  try {
    localStorage.setItem('c2hunter-token', 'B');
    expect(auth.captureAuthentication()).toMatchObject({ token: 'B', authKind: 'bearer' });
    expect(auth.hasAuthentication()).toBe(false); expect(auth.hasRole('ADMIN')).toBe(false);
    expect(auth.currentAuthentication(old)).toBe(false); expect(changed).not.toHaveBeenCalled();
    event(); event();
    await vi.waitFor(() => expect(releases).toHaveLength(1));
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(new Headers(fetcher.mock.calls[0][1]?.headers).get('authorization')).toBe('Bearer B');
    expect(fetcher.mock.calls[0][1]?.method ?? 'GET').toBe('GET');
    releases[0](json(bearer('B', 'VIEWER')));
    await vi.waitFor(() => expect(auth.accountState().status).toBe('ready'));
    expect(auth.captureAuthentication()).toMatchObject({ identityScope: 'legacy:B', role: 'VIEWER' });
    expect(changed).toHaveBeenCalledTimes(4); expect(fetcher).toHaveBeenCalledTimes(1);
  } finally { window.removeEventListener('c2hunter-auth-changed', changed); }
});
it.each(['event', 'storage', 'capture'] as const)('A-B-A retires old requests with %s observation and ignores late /me and stale 401', async mode => {
  await ready(); const first = auth.captureAuthentication(); const { releases, fetcher } = held();
  const observe = (oldValue: string, value: string) => {
    localStorage.setItem('c2hunter-token', value);
    if (mode === 'event') event(); else if (mode === 'storage') storage(oldValue, value); else auth.captureAuthentication();
  };
  observe('A', 'B'); const middle = auth.captureAuthentication();
  await vi.waitFor(() => expect(releases).toHaveLength(1));
  observe('B', 'A'); const last = auth.captureAuthentication();
  expect(last.epoch).not.toBe(first.epoch); expect(auth.currentAuthentication(first)).toBe(false);
  expect(auth.currentAuthentication(middle)).toBe(false); expect(auth.hasAuthentication()).toBe(false);
  await vi.waitFor(() => expect(releases).toHaveLength(2));
  releases[1](json(bearer('A', 'VIEWER')));
  await vi.waitFor(() => expect(auth.accountState().status).toBe('ready'));
  releases[0](json(bearer('B')));
  await Promise.resolve(); await Promise.resolve();
  auth.invalidateAuthentication(401, first); auth.invalidateAuthentication(401, middle);
  expect(auth.captureAuthentication()).toMatchObject({ token: 'A', role: 'VIEWER', identityScope: 'legacy:A' });
  expect(fetcher).toHaveBeenCalledTimes(2);
});
it('queued storage A-B-A events retire equal token bytes and coalesce superseded hydration', async () => {
  await ready(); const first = auth.captureAuthentication(); const { releases, fetcher } = held();
  // Both real cross-document writes have completed before this tab processes events.
  storage('A', 'B'); const middle = auth.captureAuthentication(); storage('B', 'A');
  expect(auth.currentAuthentication(first)).toBe(false); expect(auth.currentAuthentication(middle)).toBe(false);
  expect(auth.hasAuthentication()).toBe(false);
  await vi.waitFor(() => expect(releases).toHaveLength(1));
  releases[0](json(bearer('A', 'ANALYST')));
  await vi.waitFor(() => expect(auth.accountState().status).toBe('ready'));
  expect(auth.hasRole('ADMIN')).toBe(false); expect(fetcher).toHaveBeenCalledTimes(1);
});
it.each(['current', 'aborted', 'stale', 'forbidden'] as const)('managed bearer %s response preserves the correct authority', async mode => {
  await ready(); const controller = new AbortController(); const { releases, fetcher } = held();
  const pending = api.boundedRequest('/test', { signal: controller.signal }).catch(error => error);
  if (mode === 'aborted') controller.abort();
  if (mode === 'stale') {
    localStorage.setItem('c2hunter-token', 'B'); event();
    await vi.waitFor(() => expect(releases).toHaveLength(2));
    releases[1](json(bearer('B', 'VIEWER')));
    await vi.waitFor(() => expect(auth.accountState().status).toBe('ready'));
  }
  releases[0](json({ error: { code: 'AUTH_REQUIRED' } }, mode === 'forbidden' ? 403 : 401)); await pending;
  expect(auth.hasAuthentication()).toBe(mode !== 'current');
  expect(localStorage.getItem('c2hunter-token')).toBe(mode === 'current' ? null : mode === 'stale' ? 'B' : 'A');
  if (mode === 'current') expect(auth.accountState().status).toBe('anonymous');
  expect(fetcher).toHaveBeenCalledTimes(mode === 'stale' ? 2 : 1);
});
it.each([401, 503, 200])('failed or malformed replacement /me (%s) cannot inherit old role or loop', async status => {
  await ready(); const fetcher = vi.fn(async () => json({ error: { code: 'AUTH_REQUIRED' } }, status)); vi.stubGlobal('fetch', fetcher);
  localStorage.setItem('c2hunter-token', 'B'); event();
  await vi.waitFor(() => expect(auth.accountState().status).toBe(status === 401 ? 'anonymous' : 'unavailable'));
  expect(auth.hasAuthentication()).toBe(false); expect(auth.hasRole('VIEWER')).toBe(false);
  expect(auth.captureAuthentication().role).toBeUndefined(); expect(fetcher).toHaveBeenCalledTimes(1);
});
it.each(['csrf', 'me'] as const)('replacement fences late initial %s completion without stale grants', async stage => {
  auth.setAuthentication('A'); const { releases, fetcher } = held();
  const initial = auth.initializeAccountAuthentication();
  if (stage === 'me') { releases[0](json(csrf)); await vi.waitFor(() => expect(releases).toHaveLength(2)); }
  localStorage.setItem('c2hunter-token', 'B'); event();
  const count = stage === 'csrf' ? 2 : 3;
  await vi.waitFor(() => expect(releases).toHaveLength(count));
  releases[count - 1](json(bearer('B', 'VIEWER')));
  await vi.waitFor(() => expect(auth.accountState().status).toBe('ready'));
  releases[count - 2](json(stage === 'csrf' ? csrf : bearer())); await initial;
  expect(auth.captureAuthentication()).toMatchObject({ token: 'B', role: 'VIEWER', identityScope: 'legacy:B' });
  expect(fetcher).toHaveBeenCalledTimes(count);
});
it('token removal retires bearer ownership and cannot grant authority to a null-token response', async () => {
  await ready(); const old = auth.captureAuthentication(); const { releases } = held();
  localStorage.removeItem('c2hunter-token'); event();
  expect(auth.currentAuthentication(old)).toBe(false); expect(auth.hasAuthentication()).toBe(false);
  await vi.waitFor(() => expect(releases).toHaveLength(1)); releases[0](json(bearer()));
  await vi.waitFor(() => expect(auth.accountState().status).toBe('unavailable'));
  expect(auth.hasRole('ADMIN')).toBe(false);
});
it('named-cookie authority ignores raw bearer bytes and survives a storage revalidation without storing CSRF', async () => {
  vi.stubGlobal('fetch', vi.fn(async (path: string) => json(path.endsWith('/csrf') ? { ...csrf, account_login_enabled: true, dev_login_enabled: false, csrf_token: 'prelogin' } : session)));
  await auth.initializeAccountAuthentication(); const named = auth.captureAuthentication(); const { releases, fetcher } = held();
  localStorage.setItem('c2hunter-token', 'foreign'); event();
  expect(auth.currentAuthentication(named)).toBe(true); expect(auth.captureAuthentication().token).toBeNull();
  storage(null, 'foreign'); expect(auth.currentAuthentication(named)).toBe(false); expect(auth.hasAuthentication()).toBe(false);
  expect(new Headers(fetcher.mock.calls[0][1]?.headers).get('authorization')).toBeNull();
  releases[0](json(session)); await vi.waitFor(() => expect(auth.accountState().status).toBe('ready'));
  expect(auth.captureAuthentication()).toMatchObject({ token: null, identityScope: 'user:alice', sessionId: 'session-A' });
  expect(localStorage.length).toBe(0); expect(sessionStorage.length).toBe(0); expect(fetcher).toHaveBeenCalledTimes(1);
});
it('explicit legacy embedding remains synchronous and does not invent roles or bootstrap requests', () => {
  const fetcher = vi.fn(); vi.stubGlobal('fetch', fetcher);
  auth.setAuthentication('A'); const first = auth.captureAuthentication();
  localStorage.setItem('c2hunter-token', 'B'); event();
  expect(auth.currentAuthentication(first)).toBe(false); expect(auth.hasAuthentication()).toBe(true);
  expect(auth.hasRole('ADMIN')).toBe(true); expect(auth.captureAuthentication().role).toBeUndefined();
  expect(fetcher).not.toHaveBeenCalled();
});
