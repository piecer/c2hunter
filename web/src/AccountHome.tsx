import { useState, type FormEvent } from 'react';
import { captureAuthentication, endAccountSession } from './authentication';
import { accountRequest, useAccountOperation, useSecurityText, validAccountPassword } from './accountSecurity';
import ReportLanguageScope from './ReportLanguage';
import AccountSessions from './AccountSessions';
import './accountSecurity.css';
export default function AccountHome() { return <ReportLanguageScope><AccountContent/></ReportLanguageScope>; }
function AccountContent() {
  const t = useSecurityText(), a = captureAuthentication();
  return <section className="account-security"><header><p className="eyebrow">IDENTITY & ACCESS</p><h1>{t('Account','계정')}</h1><p><strong>{a.user?.username ?? a.identityScope ?? t('Legacy client','레거시 클라이언트')}</strong> · {a.role ?? t('Unverified role','역할 미확인')}</p></header>
    {a.authKind === 'session' ? <>
      {a.user?.must_change_password && <p role="alert" className="warning">{t('Change your temporary password before accessing the workspace. All sessions will end; sign in again.', '작업 공간을 사용하기 전에 임시 비밀번호를 변경하세요. 모든 세션이 종료되므로 다시 로그인해야 합니다.')}</p>}
      {a.auditAvailable === false && <p role="alert">{t('Security audit is unavailable. Protected operations may be blocked.', '보안 감사 저장소를 사용할 수 없습니다. 보호된 작업이 차단될 수 있습니다.')}</p>}
      <PasswordForm/>{!a.user?.must_change_password && <AccountSessions/>}
    </> : <p>{t('Account self-service requires a named human session. Service credentials have no account record.', '계정 관리는 사용자 세션에서만 가능합니다. 서비스 자격 증명에는 계정 레코드가 없습니다.')}</p>}
  </section>;
}
function PasswordForm() {
  const t=useSecurityText(), operation=useAccountOperation();
  const [current,setCurrent]=useState(''),[next,setNext]=useState(''),[confirm,setConfirm]=useState('');
  const a=captureAuthentication(), ready=a.authKind==='session' && !!a.csrfToken;
  const submit=(event:FormEvent)=>{
    event.preventDefault(); if(!ready || operation.pending || !validAccountPassword(next) || next!==confirm) return;
    void operation.run(async()=>{
      try { await accountRequest('/auth/password','POST',{current_password:current,new_password:next}); endAccountSession(a); }
      finally {setCurrent('');setNext('');setConfirm('');}
    },t('Password changed. Sign in again.','비밀번호가 변경되었습니다. 다시 로그인하세요.'));
  };
  return <form method="post" action="/api/v1/auth/password" className="panel account-form" onSubmit={submit}>
    <h2>{t('Change password','비밀번호 변경')}</h2><p className="muted">{t('12–128 characters. Changing your password ends every session, including this one.', '12~128자. 비밀번호를 변경하면 현재 세션을 포함한 모든 세션이 종료됩니다.')}</p>
    <label>{t('Current password','현재 비밀번호')}<input type="password" name="current_password" autoComplete="current-password" value={current} onChange={e=>setCurrent(e.target.value)} required maxLength={256}/></label>
    <label>{t('New password','새 비밀번호')}<input type="password" name="new_password" autoComplete="new-password" value={next} onChange={e=>setNext(e.target.value)} required minLength={12} maxLength={256}/></label>
    <label>{t('Confirm new password','새 비밀번호 확인')}<input type="password" autoComplete="new-password" value={confirm} onChange={e=>setConfirm(e.target.value)} required minLength={12} maxLength={256}/></label>
    {confirm && next!==confirm && <p role="status">{t('Passwords do not match.','비밀번호가 일치하지 않습니다.')}</p>}
    <button type="submit" disabled={!ready || operation.pending || !current || !validAccountPassword(next) || next!==confirm}>{t('Change password','비밀번호 변경')}</button>
    {operation.error && <p role="alert">{t('Password change was not confirmed. Check before trying again.','비밀번호 변경이 확인되지 않았습니다. 다시 시도하기 전에 확인하세요.')} <code>{operation.error}</code></p>}
  </form>;
}
