/** Live authority is independent of the credential. Named sessions and CSRF stay
 * in memory; only the explicit legacy transport reads the historical token key. */
const KEY = 'c2hunter-token';
const NOTICE = 'c2hunter-auth-invalidation';
function legacyToken(): string | null { try { return localStorage.getItem(KEY); } catch { return null; } }
function clearLegacyToken() { try { localStorage.removeItem(KEY); } catch { /* Named sessions do not depend on storage. */ } }
export type Role = 'VIEWER' | 'ANALYST' | 'ADMIN';
export type AccountUser = Readonly<{ id: string; username: string; role: Role; active: boolean; must_change_password: boolean }>;
export type Authentication = Readonly<{
  token: string | null; epoch: number; authKind?: 'session' | 'bearer';
  identityScope?: string; sessionId?: string; user?: AccountUser; role?: Role;
  csrfToken?: string; auditAvailable?: boolean;
}>;
export type AccountStatus = 'legacy' | 'loading' | 'ready' | 'anonymous' | 'unavailable';
let observed: string | null | undefined;
let epoch = 0;
let managed = false;
// Transport survives loading/anonymous states; a cookie is not a null bearer.
let bearerTransport = false;
let identity: Omit<Authentication, 'epoch' | 'token'> = {};
let status: AccountStatus = 'legacy';
let bootstrap = { accountLoginEnabled: false, devLoginEnabled: false, csrfToken: '' };
let failure = '';
const role = (value: unknown): value is Role => value === 'VIEWER' || value === 'ANALYST' || value === 'ADMIN';
function changed() { window.dispatchEvent(new Event('c2hunter-auth-changed')); }
function retire(next: AccountStatus) { identity = managed && bearerTransport ? { authKind: 'bearer' } : {}; epoch += 1; status = next; changed(); }
function notifyPeers() {
  // Invalidation only. No user, password, CSRF, session ID or token in this key.
  try { localStorage.setItem(NOTICE, crypto.randomUUID()); } catch { /* storage can be disabled */ }
}
function replaceBearer(token: string | null) {
  observed = token; identity = { authKind: 'bearer' }; epoch += 1;
  status = 'loading'; failure = ''; bootstrap.csrfToken = '';
  const captured: Authentication = { token, epoch, ...identity };
  // Captures also happen during React render. Retire authority immediately,
  // but notify consumers and hydrate outside the render/event call stack.
  queueMicrotask(() => {
    if (!currentAuthentication(captured)) return;
    changed();
    if (currentAuthentication(captured)) void hydrateMe(captured);
  });
}
export function captureAuthentication(): Authentication {
  const token = managed && !bearerTransport ? null : legacyToken();
  if (token !== observed) {
    if (managed && bearerTransport) replaceBearer(token);
    else { observed = token; if (!managed) epoch += 1; }
  }
  return { token, epoch, ...identity };
}
export function currentAuthentication(captured: Authentication, signal?: AbortSignal | null): boolean {
  if (signal?.aborted) return false;
  const current = captureAuthentication();
  return current.epoch === captured.epoch && current.token === captured.token;
}
export function hasAuthentication(value = captureAuthentication()): boolean {
  return value.authKind === 'session' ? Boolean(value.user?.active && value.sessionId && value.identityScope) : Boolean(value.token && (value.authKind !== 'bearer' || value.role));
}
export function hasRole(minimum: Role): boolean {
  const current = captureAuthentication();
  if (current.user?.must_change_password) return false;
  // Retain explicit legacy embedding/test compatibility, never assign a fake role.
  // The real entrypoint hydrates /me before mounting any protected application.
  if (!managed) return true;
  return hasAuthentication(current) && !!current.role && ['VIEWER','ANALYST','ADMIN'].indexOf(current.role) >= ['VIEWER','ANALYST','ADMIN'].indexOf(minimum);
}
export function accountState() { return { status, ...bootstrap, error: failure }; }
export function authenticationHeaders(captured: Authentication, initial?: HeadersInit): Headers {
  const headers = new Headers(initial);
  headers.delete('authorization'); headers.delete('x-csrf-token');
  if (captured.token) headers.set('authorization', `Bearer ${captured.token}`);
  else if (captured.csrfToken) headers.set('x-csrf-token', captured.csrfToken);
  return headers;
}
/** Explicit legacy compatibility API, not a named-account login. */
export function setAuthentication(token: string | null): void {
  if (token === null) localStorage.removeItem(KEY); else localStorage.setItem(KEY, token);
  managed = false; observed = token; bootstrap = { accountLoginEnabled: false, devLoginEnabled: false, csrfToken: '' };
  retire('legacy');
}
export function invalidateAuthentication(code: number, captured: Authentication, signal?: AbortSignal | null): void {
  if (code !== 401 || !currentAuthentication(captured, signal)) return;
  if (managed) { clearLegacyToken(); observed = null; bootstrap.csrfToken = ''; retire('anonymous'); notifyPeers(); }
  else setAuthentication(null);
  window.dispatchEvent(new Event('c2hunter-auth-invalid'));
}
export class AccountError extends Error {
  constructor(public code: string, public status: number) { super(code); this.name = 'AccountError'; }
}
async function authJSON(path: string, captured: Authentication, init: RequestInit = {}): Promise<unknown> {
  const headers = authenticationHeaders(captured, { accept: 'application/json', ...(init.body ? { 'content-type': 'application/json' } : {}) });
  const response = await fetch('/api/v1/auth/' + path, { ...init, headers, credentials: 'same-origin', cache: 'no-store', redirect: 'error' });
  const body = response.status === 204 ? undefined : await response.json().catch(() => undefined);
  if (!response.ok) {
    const code = body?.error?.code;
    throw new AccountError(typeof code === 'string' && /^[A-Z_]{1,64}$/.test(code) ? code : 'SECURITY_UNAVAILABLE', response.status);
  }
  return body;
}
function installMe(body: unknown, captured: Authentication) {
  if (!currentAuthentication(captured)) return;
  if (!body || typeof body !== 'object') throw new AccountError('SECURITY_UNAVAILABLE', 503);
  const b = body as Record<string, unknown>;
  if (typeof b.audit_available !== 'boolean') throw new AccountError('SECURITY_UNAVAILABLE', 503);
  if (b.auth_kind === 'session') {
    const u = b.user as AccountUser | null;
    if (!u || typeof u.id !== 'string' || !u.id || typeof u.username !== 'string' || !role(u.role) || u.active !== true || typeof u.must_change_password !== 'boolean' || b.identity_scope !== 'user:' + u.id || typeof b.session_id !== 'string' || !b.session_id || typeof b.csrf_token !== 'string' || !b.csrf_token) throw new AccountError('SECURITY_UNAVAILABLE', 503);
    clearLegacyToken(); observed = null; bearerTransport = false;
    identity = { authKind: 'session', user: Object.freeze({...u}), role: u.role, identityScope: b.identity_scope as string, sessionId: b.session_id, csrfToken: b.csrf_token, auditAvailable: b.audit_available };
  } else if (b.auth_kind === 'bearer') {
    const principal = b.principal as {subject?: unknown;role?: unknown} | null;
    if (!captured.token || b.user !== null || b.session_id !== null || b.csrf_token !== null || !principal || typeof principal.subject !== 'string' || !role(principal.role) || b.identity_scope !== 'legacy:' + principal.subject) throw new AccountError('SECURITY_UNAVAILABLE', 503);
    identity = { authKind: 'bearer', role: principal.role, identityScope: b.identity_scope as string, auditAvailable: b.audit_available };
  } else throw new AccountError('SECURITY_UNAVAILABLE', 503);
  status = 'ready'; failure = ''; epoch += 1; changed();
}
function unavailable(error: unknown, captured: Authentication) {
  if (!currentAuthentication(captured)) return;
  failure = error instanceof AccountError ? error.code : 'SECURITY_UNAVAILABLE';
  retire(error instanceof AccountError && error.status === 401 ? 'anonymous' : 'unavailable');
}
async function hydrateMe(captured: Authentication): Promise<void> {
  try { installMe(await authJSON('me', captured), captured); }
  catch (error) { unavailable(error, captured); }
}
export async function initializeAccountAuthentication(): Promise<void> {
  const legacy = legacyToken();
  managed = true; bearerTransport = Boolean(legacy); observed = legacy; bootstrap = { accountLoginEnabled: false, devLoginEnabled: false, csrfToken: '' }; failure = '';
  retire('loading');
  const captured = captureAuthentication();
  try {
    const body = await authJSON('csrf', { ...captured, token: null }) as Record<string, unknown>;
    if (!currentAuthentication(captured)) return;
    if (!body || body.setup_required !== false || typeof body.account_login_enabled !== 'boolean' || typeof body.dev_login_enabled !== 'boolean' || (body.account_login_enabled && (typeof body.csrf_token !== 'string' || !body.csrf_token || body.dev_login_enabled))) throw new AccountError('ACCOUNT_SETUP_REQUIRED', 503);
    bootstrap = { accountLoginEnabled: body.account_login_enabled, devLoginEnabled: !body.account_login_enabled && body.dev_login_enabled, csrfToken: typeof body.csrf_token === 'string' ? body.csrf_token : '' };
    if (!body.account_login_enabled && !legacy) { status = 'anonymous'; changed(); return; }
    await hydrateMe(captured);
  } catch (error) { unavailable(error, captured); }
}
export async function refreshAccountAuthentication(): Promise<void> {
  const old = captureAuthentication(); managed = true; bearerTransport = old.authKind === 'bearer' || Boolean(old.token); observed = old.token;
  bootstrap.csrfToken = ''; retire('loading');
  await hydrateMe(captureAuthentication());
}
export async function loginAccount(username: string, password: string): Promise<void> {
  if (!bootstrap.accountLoginEnabled || !bootstrap.csrfToken || status !== 'anonymous') throw new AccountError('SECURITY_UNAVAILABLE',503);
  const captured = captureAuthentication();
  await authJSON('login', {...captured, token:null, csrfToken:bootstrap.csrfToken}, {method:'POST', body:JSON.stringify({username,password})});
  if (!currentAuthentication(captured)) return;
  // /me, not a submitted username or login payload, establishes receipt ownership.
  await refreshAccountAuthentication(); notifyPeers();
}
export async function logoutAccount(): Promise<void> {
  const captured = captureAuthentication();
  if (captured.authKind === 'session') {
    try { await authJSON('logout', captured, {method:'POST',body:'{}'}); }
    catch (error) { if (!(error instanceof AccountError && error.status === 401)) throw error; }
    if (!currentAuthentication(captured)) return;
    bootstrap.csrfToken = ''; retire('anonymous'); notifyPeers();
  } else setAuthentication(null);
}
export function endAccountSession(captured: Authentication) {
  if (!currentAuthentication(captured)) return;
  bootstrap.csrfToken = ''; retire('anonymous'); notifyPeers();
}
// Observe raw same-document replacement before application event consumers.
window.addEventListener('c2hunter-auth-changed', () => { captureAuthentication(); });
window.addEventListener('storage', event => {
  if (event.key === NOTICE && managed) {
    // Synchronously retire before any asynchronous /me can complete.
    void refreshAccountAuthentication();
  } else if (event.key === KEY || event.key === null) {
    // Each storage event is a transition, even when queued A→B→A writes
    // leave the current bytes unchanged. Never reinterpret a named cookie.
    if (managed && bearerTransport) { replaceBearer(legacyToken()); changed(); }
    else if (managed) void refreshAccountAuthentication();
    else { observed = legacyToken(); epoch += 1; changed(); }
  }
});
