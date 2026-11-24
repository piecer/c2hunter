import { useEffect, useRef, useState } from 'react';
import { api, ApiError } from './api';
import { captureAuthentication, currentAuthentication, type AccountUser } from './authentication';
import { useReportLanguage } from './reportLanguageContext';
export function validAccountPassword(value: string): boolean {
  const length = Array.from(value).length;
  return length >= 12 && length <= 128;
}
export function useSecurityText() { const language = useReportLanguage(); return (en: string, ko: string) => language === 'ko' ? ko : en; }
export function safeAccountError(error: unknown): string {
  const code = error instanceof ApiError ? error.code : 'SECURITY_UNAVAILABLE';
  return ['AUTH_REQUIRED','INVALID_CREDENTIALS','INSUFFICIENT_ROLE','CSRF_INVALID','ORIGIN_INVALID','PASSWORD_CHANGE_REQUIRED','LAST_ADMIN','USER_EXISTS','RATE_LIMIT_EXCEEDED','ACCOUNT_SETUP_REQUIRED','SECURITY_UNAVAILABLE'].includes(code) ? code : 'REQUEST_REJECTED';
}
export async function accountRequest<T>(path: string, method='GET', body?: unknown): Promise<T> {
  const captured = captureAuthentication();
  if (captured.authKind !== 'session' || !captured.csrfToken || !captured.user?.active) throw new ApiError('Named session required',403,'INSUFFICIENT_ROLE');
  const value = method === 'GET' ? await api.boundedRequest(path) : method === 'PATCH' ? await api.patch(path, body) : await api.post(path, body);
  if (!currentAuthentication(captured)) throw new DOMException('Retired account request','AbortError');
  return value as T;
}
export function useAccountOperation() {
  const [pending, setPending] = useState(false), [error, setError] = useState(''), [notice, setNotice] = useState('');
  const busy = useRef(false), live = useRef(false);
  useEffect(() => { live.current = true; return () => { live.current = false; }; }, []);
  const run = async (task: () => Promise<void>, success: string) => {
    if (busy.current) return; busy.current = true; setPending(true); setError(''); setNotice('');
    const captured = captureAuthentication();
    try { await task(); if (live.current && currentAuthentication(captured)) setNotice(success); }
    catch (e) { if (live.current && currentAuthentication(captured)) setError(safeAccountError(e)); }
    finally { busy.current = false; if (live.current && currentAuthentication(captured)) setPending(false); }
  };
  return { pending, error, notice, run };
}
export type AccountPage<T> = {items:T[];total:number};
export function accountPage<T>(body: unknown, validate: (item: unknown) => item is T, limit=50): AccountPage<T> {
  const page = body as AccountPage<unknown>;
  if (!page || !Array.isArray(page.items) || page.items.length > limit || !Number.isSafeInteger(page.total) || page.total < page.items.length || !page.items.every(validate)) throw new Error('Invalid account page');
  return page as AccountPage<T>;
}
export function isAccountUser(value: unknown): value is AccountUser {
  const u = value as AccountUser;
  return !!u && typeof u.id === 'string' && !!u.id && typeof u.username === 'string' && ['VIEWER','ANALYST','ADMIN'].includes(u.role) && typeof u.active === 'boolean' && typeof u.must_change_password === 'boolean';
}
