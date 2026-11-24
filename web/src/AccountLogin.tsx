import { useEffect, useState, type FormEvent } from 'react';
import { Navigate } from 'react-router-dom';
import { api } from './api';
import { accountState, captureAuthentication, currentAuthentication, hasAuthentication, initializeAccountAuthentication, loginAccount, setAuthentication } from './authentication';
import ReportLanguageScope from './ReportLanguage';
import { useReportLanguage } from './reportLanguageContext';
import './accountSecurity.css';

export default function AccountLogin() { return <ReportLanguageScope><LoginForm/></ReportLanguageScope>; }
function LoginForm() {
  const language = useReportLanguage(), t = (en: string, ko: string) => language === 'ko' ? ko : en;
  const [, update] = useState(0);
  const [username, setUsername] = useState(''), [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false), [error, setError] = useState('');
  const state = accountState(), authority = captureAuthentication();
  useEffect(() => {
    const changed = () => update(value => value + 1);
    window.addEventListener('c2hunter-auth-changed', changed);
    return () => window.removeEventListener('c2hunter-auth-changed', changed);
  }, []);
  useEffect(() => {
    if (state.status === 'legacy' || state.status === 'anonymous' && state.accountLoginEnabled && !state.csrfToken) void initializeAccountAuthentication();
  }, [state.status, state.csrfToken, state.accountLoginEnabled]);
  if (hasAuthentication(authority)) return <Navigate to={authority.authKind === 'session' ? '/account' : '/'} replace/>;
  const ready = state.status === 'anonymous' && (state.accountLoginEnabled && Boolean(state.csrfToken) || state.devLoginEnabled);
  const submit = async (event: FormEvent) => {
    event.preventDefault(); if (!ready || busy) return;
    setBusy(true); setError('');
    const captured = captureAuthentication();
    try {
      if (state.accountLoginEnabled) await loginAccount(username, password);
      else if (state.devLoginEnabled) {
        const result = await api.post<{access_token: string}>('/auth/dev-login', {username});
        if (currentAuthentication(captured)) { setAuthentication(result.access_token); await initializeAccountAuthentication(); }
      }
    } catch {
      if (currentAuthentication(captured)) setError(t('Sign-in failed. Check your credentials or try again later.', '로그인 실패. 자격 증명을 확인하거나 나중에 다시 시도하세요.'));
    } finally { setPassword(''); setBusy(false); }
  };
  return <main className="login account-login"><form method="post" action="/api/v1/auth/login" className="panel account-form" onSubmit={submit}>
    <div className="brand">C2<span>Hunter</span></div><p className="eyebrow">SECURE WORKSPACE</p>
    <h1>{t('Sign in to C2Hunter', 'C2Hunter 로그인')}</h1>
    <p className="muted">{t('Use your administrator-provisioned account. Sessions are private to this browser.', '관리자가 발급한 계정을 사용하세요. 세션은 이 브라우저에서만 사용됩니다.')}</p>
    <label>{t('Username','사용자 이름')}<input name="username" autoComplete="username" value={username} onChange={event => setUsername(event.target.value)} maxLength={64} pattern={'[A-Za-z0-9_.@\\-]+'} required/></label>
    {!state.devLoginEnabled && <label>{t('Password','비밀번호')}<input name="password" type="password" autoComplete="current-password" value={password} onChange={event => setPassword(event.target.value)} maxLength={256} required/></label>}
    {state.status === 'loading' && <p role="status">{t('Checking secure sign-in…','보안 로그인 확인 중…')}</p>}
    {state.error && state.status === 'unavailable' && <p role="alert">{t('Authentication is unavailable. Ask an administrator to check account setup.', '인증을 사용할 수 없습니다. 관리자에게 계정 설정 확인을 요청하세요.')} <code>{state.error}</code></p>}
    {error && <p role="alert">{error}</p>}
    <button type="submit" disabled={!ready || busy}>{busy ? t('Signing in…','로그인 중…') : state.devLoginEnabled ? t('Development login','개발 로그인') : t('Sign in','로그인')}</button>
    <button type="button" className="secondary" disabled={busy || state.status === 'loading'} onClick={() => {setError('');void initializeAccountAuthentication();}}>{t('Retry secure connection','보안 연결 다시 확인')}</button>
    {!state.accountLoginEnabled && !state.devLoginEnabled && state.status === 'anonymous' && <p role="status">{t('Account login is disabled. Use the explicitly configured service authentication client.', '계정 로그인이 비활성화되어 있습니다. 명시적으로 구성된 서비스 인증 클라이언트를 사용하세요.')}</p>}
  </form></main>;
}
