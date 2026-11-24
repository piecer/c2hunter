import { randomUUID } from 'node:crypto';
import { expect, test } from '@playwright/test';
import { installNamedSession, namedMe, namedUser, preloginCsrf, sessionCookie, sessionCsrf } from './named-session-fixture';

// Real built main.tsx and native events; HTTP responses below are wire fixtures,
// not a substitute for backend authentication/authorization acceptance.
for (const activation of ['Enter', 'click'] as const) test(`credential readiness gates native ${activation} until CSRF and me hydration`, async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem('c2hunter-report-language', 'en'));
  let releaseCsrf!: () => void, releaseMe!: () => void;
  const csrfGate = new Promise<void>(resolve => { releaseCsrf = resolve; });
  const meGate = new Promise<void>(resolve => { releaseMe = resolve; });
  let loggedIn = false;
  const logins: unknown[] = [], navigations: string[] = [], apiRequests: string[] = [];
  page.on('request', request => {
    if (request.isNavigationRequest()) navigations.push(request.url());
    if (new URL(request.url()).pathname.startsWith('/api/v1/')) apiRequests.push(request.url());
  });
  await page.route('**/api/v1/**', async route => {
    const request = route.request(), path = new URL(request.url()).pathname;
    expect(request.headers().authorization).toBeUndefined();
    if (path === '/api/v1/auth/csrf') { await csrfGate; return route.fulfill({ json: preloginCsrf }); }
    if (path === '/api/v1/auth/me') {
      if (!loggedIn) return route.fulfill({ status: 401, json: { error: { code: 'AUTH_REQUIRED' } } });
      expect(await request.headerValue('cookie')).toContain(`c2hunter_session=${sessionCookie}`);
      await meGate; return route.fulfill({ json: namedMe });
    }
    if (path === '/api/v1/auth/login') {
      expect(request.method()).toBe('POST');
      expect(request.headers()['x-csrf-token']).toBe(preloginCsrf.csrf_token);
      logins.push(request.postDataJSON()); loggedIn = true;
      const { user, csrf_token, session_id, identity_scope } = namedMe;
      return route.fulfill({ json: { user, csrf_token, session_id, identity_scope }, headers: { 'set-cookie': `c2hunter_session=${sessionCookie}; HttpOnly; SameSite=Strict; Path=/` } });
    }
    expect(path).toBe('/api/v1/auth/sessions');
    expect(request.headers()['x-csrf-token']).toBe(sessionCsrf);
    return route.fulfill({ json: { items: [], total: 0 } });
  });
  try {
    await page.goto('/login');
    const username = page.getByLabel('Username', { exact: true }), password = page.getByLabel('Password', { exact: true });
    const submit = page.getByRole('button', { name: 'Sign in', exact: true });
    await username.fill(namedUser.username); await password.fill('fixture-password-123');
    await expect(submit).toBeDisabled();
    await expect(page.locator('form')).toHaveAttribute('method', 'post');
    await expect(page.locator('form')).toHaveAttribute('action', '/api/v1/auth/login');
    if (activation === 'Enter') await password.press('Enter');
    else {
      // A real pointer click on the disabled control, not force-click or JS submit.
      const box = await submit.boundingBox(); expect(box).not.toBeNull();
      await page.mouse.click(box!.x + box!.width / 2, box!.y + box!.height / 2);
    }
    expect(logins).toEqual([]); expect(navigations).toHaveLength(1);
    await expect(page).toHaveURL(/\/login$/);
    releaseCsrf(); await expect(submit).toBeEnabled();
    const introspection = page.waitForRequest(request => request.url().endsWith('/auth/me'));
    if (activation === 'Enter') await password.press('Enter'); else await submit.click();
    await introspection;
    expect(logins).toEqual([{ username: namedUser.username, password: 'fixture-password-123' }]);
    // Login's four fields alone cannot mount a protected Shell.
    await expect(page.getByRole('heading', { name: 'Account', exact: true })).toHaveCount(0);
    await expect(page.getByRole('link', { name: 'Users', exact: true })).toHaveCount(0);
    releaseMe(); await expect(page.getByRole('heading', { name: 'Account', exact: true })).toBeVisible();
    expect(navigations).toHaveLength(1);
    for (const url of apiRequests) {
      const parsed = new URL(url);
      expect([...parsed.searchParams.keys()].every(key => ['limit', 'offset'].includes(key))).toBe(true);
      for (const secret of [namedUser.username, 'fixture-password-123', sessionCookie, sessionCsrf, preloginCsrf.csrf_token]) expect(parsed.search).not.toContain(secret);
    }
    expect((await page.context().cookies()).find(cookie => cookie.name === 'c2hunter_session')).toMatchObject({ httpOnly: true, sameSite: 'Strict' });
    expect(await page.evaluate(() => document.cookie)).not.toContain('c2hunter_session');
    const storage = await page.evaluate(() => JSON.stringify([{ ...localStorage }, { ...sessionStorage }]));
    for (const secret of [sessionCookie, sessionCsrf, preloginCsrf.csrf_token, 'fixture-password-123', 'c2hunter-token']) expect(storage).not.toContain(secret);
  } finally { releaseCsrf(); releaseMe(); }
});

for (const mode of ['disabled', 'missing'] as const) test(`credential forms cannot submit with ${mode} JavaScript`, async ({ browser, baseURL }) => {
  const context = await browser.newContext({ javaScriptEnabled: mode !== 'disabled', baseURL });
  try {
    let blocked = 0;
    if (mode === 'missing') await context.route('**/*.js', route => { blocked++; return route.abort('blockedbyclient'); });
    const page = await context.newPage(), requests: string[] = [];
    page.on('request', request => requests.push(request.url()));
    await page.goto('/login');
    await expect(page.locator('input[type="password"]')).toHaveCount(0);
    await expect(page.locator('form')).toHaveCount(0);
    await page.keyboard.press('Enter');
    expect(requests.filter(url => new URL(url).pathname.startsWith('/api/'))).toEqual([]);
    expect(requests.every(url => !new URL(url).search)).toBe(true);
    if (mode === 'missing') expect(blocked).toBeGreaterThan(0);
  } finally { await context.close(); }
});

test('native create reset and own password forms preserve POST and memory-CSRF transport', async ({ page }) => {
  const temporaryPassword = randomUUID();
  await page.addInitScript(() => localStorage.setItem('c2hunter-report-language', 'en'));
  const user = { ...namedUser, id: '11111111111111111111111111111111', username: 'new-viewer', role: 'VIEWER', must_change_password: true };
  const users: object[] = [namedUser], writes: { path: string; body: unknown }[] = [];
  await page.route('**/api/v1/**', async route => {
    const request = route.request(), path = new URL(request.url()).pathname;
    expect(request.headers().authorization).toBeUndefined();
    expect(request.headers()['x-csrf-token']).toBe(sessionCsrf);
    if (request.method() !== 'GET') {
      expect(request.method()).toBe('POST'); expect(new URL(request.url()).search).toBe('');
      writes.push({ path, body: request.postDataJSON() });
    }
    if (path === '/api/v1/auth/sessions') return route.fulfill({ json: { items: [], total: 0 } });
    if (path === '/api/v1/admin/users' && request.method() === 'GET') return route.fulfill({ json: { items: users, total: users.length } });
    if (path === '/api/v1/admin/users' && request.method() === 'POST') { users.push(user); return route.fulfill({ status: 201, json: user }); }
    if (path === '/api/v1/auth/password') {
      await page.route('**/api/v1/auth/me', denied => denied.fulfill({ status: 401, json: { error: { code: 'AUTH_REQUIRED' } } }));
      return route.fulfill({ status: 204, headers: { 'set-cookie': 'c2hunter_session=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/' } });
    }
    if (path === `/api/v1/admin/users/${user.id}/reset-password`) return route.fulfill({ status: 204 });
    throw new Error(`Unexpected account fixture route ${request.method()} ${path}`);
  });
  const checkSession = await installNamedSession(page);
  await page.goto('/admin/users');
  await page.getByRole('button', { name: 'Create user', exact: true }).click();
  await page.getByLabel('Username', { exact: true }).fill(user.username);
  await page.getByRole('combobox', { name: 'Role', exact: true }).selectOption('VIEWER');
  const temporary = page.getByLabel('Temporary password', { exact: true });
  expect(await temporary.evaluate(input => (input as HTMLInputElement).form?.method)).toBe('post');
  await temporary.fill(temporaryPassword); await temporary.press('Enter');
  await page.getByRole('button', { name: 'Manage new-viewer', exact: true }).click();
  const reset = page.getByLabel('New temporary password', { exact: true });
  expect(await reset.evaluate(input => (input as HTMLInputElement).form?.method)).toBe('post');
  await reset.fill('fixture-reset-password-123'); await reset.press('Enter');
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await page.getByRole('link', { name: 'Account', exact: true }).click();
  const current = page.getByLabel('Current password', { exact: true });
  expect(await current.evaluate(input => (input as HTMLInputElement).form?.method)).toBe('post');
  await current.fill('fixture-password-123');
  await page.getByLabel('New password', { exact: true }).fill('fixture-new-password-123');
  const confirm = page.getByLabel('Confirm new password', { exact: true });
  await confirm.fill('fixture-new-password-123');
  await checkSession();
  await confirm.press('Enter');
  await expect(page.getByRole('heading', { name: 'Sign in to C2Hunter' })).toBeVisible();
  expect(writes).toEqual([
    { path: '/api/v1/admin/users', body: { username: user.username, password: temporaryPassword, role: 'VIEWER' } },
    { path: `/api/v1/admin/users/${user.id}/reset-password`, body: { password: 'fixture-reset-password-123' } },
    { path: '/api/v1/auth/password', body: { current_password: 'fixture-password-123', new_password: 'fixture-new-password-123' } },
  ]);
});
