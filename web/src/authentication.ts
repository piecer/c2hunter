/** Request-local authority, not a new identity provider. Credentials stay in memory.
 * The epoch retires work on same-document login/logout and cross-tab transitions.
 */
const KEY = 'c2hunter-token';
let observed: string | null | undefined;
let epoch = 0;
export type Authentication = Readonly<{ token: string | null; epoch: number }>;
export function captureAuthentication(): Authentication {
  const token = localStorage.getItem(KEY);
  if (token !== observed) { observed = token; epoch += 1; }
  return { token, epoch };
}
export function currentAuthentication(captured: Authentication, signal?: AbortSignal | null): boolean {
  if (signal?.aborted) return false;
  const current = captureAuthentication();
  return current.epoch === captured.epoch && current.token === captured.token;
}
export function setAuthentication(token: string | null): void {
  if (token === null) localStorage.removeItem(KEY); else localStorage.setItem(KEY, token);
  observed = token; epoch += 1;
  window.dispatchEvent(new Event('c2hunter-auth-changed'));
}
export function invalidateAuthentication(status: number, captured: Authentication, signal?: AbortSignal | null): void {
  if (status !== 401 || !currentAuthentication(captured, signal)) return;
  setAuthentication(null);
  window.dispatchEvent(new Event('c2hunter-auth-invalid'));
}
// Storage events can describe A→B→A even when both arrive after the writes.
window.addEventListener('storage', event => {
  if (event.key === KEY || event.key === null) {
    observed = localStorage.getItem(KEY); epoch += 1;
    window.dispatchEvent(new Event('c2hunter-auth-changed'));
  }
});
