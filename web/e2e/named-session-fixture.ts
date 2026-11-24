import { expect, type Page } from '@playwright/test';

// Wire fixtures only: these checks do not establish backend cookie/CSRF security.
export const namedUser = { id: '0123456789abcdef0123456789abcdef', username: 'fixture-admin', role: 'ADMIN', active: true, must_change_password: false } as const;
export const sessionCookie = 'owned-named-cookie-fixture';
export const sessionCsrf = 'owned-memory-csrf-fixture';
export const preloginCsrf = { csrf_token: 'owned-prelogin-csrf', account_login_enabled: true, setup_required: false, dev_login_enabled: false };
export const namedMe = { user: namedUser, csrf_token: sessionCsrf, session_id: 'fedcba9876543210fedcba9876543210', identity_scope: `user:${namedUser.id}`, audit_available: true, auth_kind: 'session' };

/** Install after legacy domain routes, before navigation. Domain bodies and
 * actions are unchanged; only real-entrypoint authentication is substituted. */
export async function installNamedSession(page: Page) {
  await page.addInitScript(() => localStorage.removeItem('c2hunter-token'));
  await page.context().addCookies([{ name: 'c2hunter_session', value: sessionCookie, domain: '127.0.0.1', path: '/', httpOnly: true, secure: false, sameSite: 'Strict' }]);
  const requests: { path: string; authorization?: string; csrf?: string }[] = [];
  page.on('request', request => {
    const path = new URL(request.url()).pathname;
    if (path.startsWith('/api/v1/')) requests.push({ path, authorization: request.headers().authorization, csrf: request.headers()['x-csrf-token'] });
  });
  await page.route('**/api/v1/auth/csrf', route => route.fulfill({ json: preloginCsrf }));
  await page.route('**/api/v1/auth/me', async route => {
    expect(await route.request().headerValue('cookie')).toContain(`c2hunter_session=${sessionCookie}`);
    await route.fulfill({ json: namedMe });
  });
  return async () => {
    expect(requests.some(request => request.path === '/api/v1/auth/me')).toBe(true);
    for (const request of requests) {
      expect(request.authorization, request.path).toBeUndefined();
      if (!['/api/v1/auth/csrf', '/api/v1/auth/me'].includes(request.path)) expect(request.csrf, request.path).toBe(sessionCsrf);
    }
    expect((await page.context().cookies()).find(cookie => cookie.name === 'c2hunter_session')).toMatchObject({ value: sessionCookie, httpOnly: true, sameSite: 'Strict' });
    expect(await page.evaluate(() => document.cookie)).not.toContain('c2hunter_session');
    const storage = await page.evaluate(() => ({ local: { ...localStorage }, session: { ...sessionStorage } }));
    expect(storage.local['c2hunter-token']).toBeUndefined();
    for (const secret of [sessionCookie, sessionCsrf, preloginCsrf.csrf_token]) expect(JSON.stringify(storage)).not.toContain(secret);
  };
}
