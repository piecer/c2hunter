import { useEffect, useState } from 'react';
import { NavLink } from 'react-router-dom';
import { captureAuthentication, logoutAccount } from './authentication';
export default function AccountNavigation() {
  const a=captureAuthentication(),[error,setError]=useState(false),[busy,setBusy]=useState(false);
  const [language,setLanguage]=useState(()=>{try{return localStorage.getItem('c2hunter-report-language')==='en'?'en':'ko';}catch{return 'ko';}});
  useEffect(()=>{
    // Existing reports own their language scope. Follow their explicit selector
    // without remounting the protected shell or retiring in-flight operations.
    const change=(event:Event)=>{const select=event.target;if(select instanceof HTMLSelectElement && select.closest('.network-report-language') && (select.value==='en'||select.value==='ko'))setLanguage(select.value);};
    document.addEventListener('change',change);return()=>document.removeEventListener('change',change);
  },[]);
  const t=(en:string,ko:string)=>language==='en'?en:ko;
  return <div className="account-identity">
    {a.user && <p><strong>{a.user.username}</strong> · {a.role}</p>}
    <nav aria-label={t('Account navigation','계정 메뉴')}><NavLink to="/account">{t('Account','계정')}</NavLink>
      {a.authKind==='session' && !a.user?.must_change_password && <><NavLink to="/account/activity">{t('My activity','내 활동')}</NavLink>{a.role==='ADMIN' && <><NavLink to="/admin/users">{t('Users','사용자')}</NavLink><NavLink to="/admin/audit">{t('Security audit','보안 감사')}</NavLink></>}</>}
    </nav>
    <button className="quiet" disabled={busy} onClick={()=>{setBusy(true);setError(false);void logoutAccount().catch(()=>{setError(true);setBusy(false);});}}>{t('Sign out','로그아웃')}</button>
    {error && <p role="alert">{t('Sign-out was not confirmed. Retry to revoke this session.','로그아웃이 확인되지 않았습니다. 세션을 취소하려면 다시 시도하세요.')}</p>}
  </div>;
}
