import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { captureAuthentication, endAccountSession } from './authentication';
import { accountPage, accountRequest, safeAccountError, useAccountOperation, useSecurityText } from './accountSecurity';
import { AccountDialog, AccountNotice, AccountPagination } from './AccountWidgets';
type Session={id:string;created_at:number;last_seen_at:number;expires_at:number;current:boolean};
function isSession(v:unknown):v is Session{const s=v as Session;return !!s&&typeof s.id==='string'&&!!s.id&&typeof s.current==='boolean'&&[s.created_at,s.last_seen_at,s.expires_at].every(n=>typeof n==='number'&&Number.isFinite(n));}
export default function AccountSessions(){
 const t=useSecurityText(),a=captureAuthentication(),operation=useAccountOperation();
 const [offset,setOffset]=useState(0),[target,setTarget]=useState<Session|'all'>();
 const q=useQuery({queryKey:['account-sessions',a.epoch,offset],queryFn:async()=>accountPage(await accountRequest(`/auth/sessions?limit=50&offset=${offset}`),isSession),retry:false});
 const confirm=()=>{if(!target)return;const selected=target;void operation.run(async()=>{await accountRequest('/auth/sessions/revoke','POST',selected==='all'?{}:{session_id:selected.id});setTarget(undefined);if(selected==='all'||selected.current)endAccountSession(a);else await q.refetch();},t('Session revoked.','세션을 취소했습니다.'));};
 return <section className="panel"><div className="section-heading"><h2>{t('Your sessions','내 세션')}</h2><button type="button" className="secondary" disabled={q.isFetching||operation.pending} onClick={()=>void q.refetch()}>{t('Refresh sessions','세션 새로고침')}</button></div><p className="muted">{t('Only your sessions are listed. Revoking the current or all sessions signs you out.','내 세션만 표시됩니다. 현재 세션 또는 모든 세션을 취소하면 로그아웃됩니다.')}</p>
  {q.isPending && <p role="status">{t('Loading sessions…','세션 불러오는 중…')}</p>}<AccountNotice error={operation.error || (q.error?safeAccountError(q.error):undefined)} notice={operation.notice}/>
  {q.data&&!q.isError&&<ul className="account-list">{q.data.items.map(s=><li key={s.id}><strong>{s.current?t('This session','현재 세션'):t('Other session','다른 세션')}</strong><code> {s.id}</code><dl><dt>{t('Created','생성')}</dt><dd>{new Date(s.created_at*1000).toLocaleString()}</dd><dt>{t('Last seen','마지막 활동')}</dt><dd>{new Date(s.last_seen_at*1000).toLocaleString()}</dd><dt>{t('Expires','만료')}</dt><dd>{new Date(s.expires_at*1000).toLocaleString()}</dd></dl><button type="button" disabled={operation.pending||q.isFetching} aria-label={t(`Revoke session ${s.id}`,`세션 취소 ${s.id}`)} onClick={()=>setTarget(s)}>{t('Revoke session','세션 취소')}</button></li>)}</ul>}
  {q.data?.total===0&&<p>{t('No sessions on this page.','이 페이지에 세션이 없습니다.')}</p>}
  <AccountPagination offset={offset} total={q.isError?undefined:q.data?.total} count={q.data?.items.length??0} pending={q.isFetching||operation.pending} onChange={setOffset}/>
  <button type="button" className="danger" disabled={operation.pending} onClick={()=>setTarget('all')}>{t('Revoke all my sessions','내 모든 세션 취소')}</button>
  {target&&<AccountDialog title={t('Confirm session revocation','세션 취소 확인')} onClose={()=>setTarget(undefined)} pending={operation.pending}><p>{target==='all'?t('End all your sessions, including this browser?','이 브라우저를 포함한 모든 세션을 종료할까요?'):target.id}</p><AccountNotice error={operation.error}/><button type="button" className="danger" disabled={operation.pending} onClick={confirm}>{t('Confirm revocation','취소 확인')}</button></AccountDialog>}
 </section>;
}
