import type { Page, Route } from '@playwright/test';

type Principal = { subject: string; role: 'VIEWER' | 'ANALYST' | 'ADMIN' };
const developmentPrincipals = new WeakMap<Page, Principal>();
const developmentLoginPages = new WeakSet<Page>();
export function enableDevelopmentLogin(page: Page) { developmentLoginPages.add(page); }

/** Explicit legacy fixture configuration, not a fabricated named human account.
 * Existing arbitrary bearer tokens represent the fixture's static ADMIN client.
 * Real development-login issues ADMIN even when its submitted name is 'analyst'.
 * Keep the original bearer bytes: receipt/owner scopes still derive from them.
 */
export function withLegacyAuthentication(handler: (route: Route) => unknown) {
  return async (route: Route) => {
    const request = route.request(), path = new URL(request.url()).pathname;
    const page = request.frame().page();
    if (path === '/api/v1/auth/csrf' && request.method() === 'GET') {
      return route.fulfill({ json: { csrf_token: null, account_login_enabled: false, setup_required: false, dev_login_enabled: developmentLoginPages.has(page) } });
    }
    if (path === '/api/v1/auth/me' && request.method() === 'GET') {
      if (!request.headers().authorization?.startsWith('Bearer ')) return route.fulfill({ status: 401, json: { error: { code: 'AUTH_REQUIRED', message: 'Authentication required' } } });
      const principal = developmentPrincipals.get(page) ?? { subject: 'static-admin', role: 'ADMIN' };
      return route.fulfill({ json: { user: null, principal, csrf_token: null, session_id: null, identity_scope: `legacy:${principal.subject}`, audit_available: true, auth_kind: 'bearer' } });
    }
    if (path === '/api/v1/auth/dev-login' && request.method() === 'POST') {
      developmentPrincipals.set(page, { subject: request.postDataJSON().username, role: 'ADMIN' });
    }
    return handler(route);
  };
}
