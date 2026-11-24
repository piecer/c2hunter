import { useState, type FormEvent } from 'react';
import { useQuery } from '@tanstack/react-query';
import { captureAuthentication, endAccountSession, type AccountUser, type Role } from './authentication';
import { accountPage, accountRequest, isAccountUser, safeAccountError, useAccountOperation, useSecurityText, validAccountPassword } from './accountSecurity';
import { AccountDialog, AccountNotice, AccountPagination } from './AccountWidgets';
import ReportLanguageScope from './ReportLanguage';
export default function AccountUsers(){return <ReportLanguageScope><Users/></ReportLanguageScope>;}
function RoleOptions(){return <><option value="VIEWER">VIEWER</option><option value="ANALYST">ANALYST</option><option value="ADMIN">ADMIN</option></>;}
function Users(){
 const t=useSecurityText(),a=captureAuthentication();const [offset,setOffset]=useState(0),[creating,setCreating]=useState(false),[selected,setSelected]=useState<AccountUser>();
 const q=useQuery({queryKey:['account-users',a.epoch,offset],queryFn:async()=>accountPage(await accountRequest(`/admin/users?limit=50&offset=${offset}`),isAccountUser),retry:false});
 const refreshed=async()=>{setCreating(false);setSelected(undefined);await q.refetch();};
 return <section className="account-security"><header><p className="eyebrow">ACCESS MANAGEMENT</p><h1>{t('Users','사용자')}</h1><p className="muted">{t('Shared-team access. Account IDs and historical ownership never change. Disable accounts rather than delete them.','공유 팀 접근 권한. 계정 ID와 과거 소유권은 변경되지 않습니다. 계정을 삭제하는 대신 비활성화하세요.')}</p></header>
 <div className="account-actions"><button type="button" disabled={creating||q.isFetching} onClick={()=>setCreating(true)}>{t('Create user','사용자 만들기')}</button><button type="button" className="secondary" disabled={q.isFetching} onClick={()=>void q.refetch()}>{t('Refresh users','사용자 새로고침')}</button></div>
 {creating&&<CreateUser onDone={refreshed} onCancel={()=>setCreating(false)}/>}
 {q.isPending&&<p role="status">{t('Loading users…','사용자 불러오는 중…')}</p>}<AccountNotice error={q.error?safeAccountError(q.error):undefined}/>
 {q.data&&!q.isError&&<ul className="account-list">{q.data.items.map(u=><li key={u.id}><div className="section-heading"><h2>{u.username}</h2><span className="badge">{u.role}</span></div><code>{u.id}</code><p>{u.active?t('Active','활성'):t('Disabled','비활성')} · {u.must_change_password?t('Password change required','비밀번호 변경 필요'):t('Password set','비밀번호 설정됨')}</p><button type="button" disabled={q.isFetching||!!selected} aria-label={t(`Manage ${u.username}`,`${u.username} 관리`)} onClick={()=>setSelected(u)}>{t('Manage','관리')}</button></li>)}</ul>}
 {q.data?.total===0&&<p>{t('No accounts found.','계정이 없습니다.')}</p>}
 <AccountPagination offset={offset} total={q.isError?undefined:q.data?.total} count={q.data?.items.length??0} pending={q.isFetching||!!selected||creating} onChange={setOffset}/>
 {selected&&<ManageUser key={selected.id} user={selected} onDone={refreshed} onCancel={()=>setSelected(undefined)}/>}
 </section>;
}
function CreateUser({onDone,onCancel}:{onDone:()=>Promise<void>;onCancel:()=>void}){
 const t=useSecurityText(),operation=useAccountOperation(),a=captureAuthentication();
 const [username,setUsername]=useState(''),[password,setPassword]=useState(''),[role,setRole]=useState<Role>('VIEWER');
 const ready=a.authKind==='session'&&a.role==='ADMIN'&&!!a.csrfToken;
 const submit=(e:FormEvent)=>{e.preventDefault();if(!ready||operation.pending)return;void operation.run(async()=>{try{const created=await accountRequest('/admin/users','POST',{username,password,role});if(!isAccountUser(created))throw new Error('Invalid user');await onDone();}finally{setPassword('');}},t('Account created.','계정을 만들었습니다.'));};
 return <form aria-label={t('Create account','계정 만들기')} method="post" action="/api/v1/admin/users" className="panel account-form" onSubmit={submit}><h2>{t('Create account','계정 만들기')}</h2><p>{t('The user must change this temporary password at first sign-in. Share it through a secure channel.','사용자는 첫 로그인 시 임시 비밀번호를 변경해야 합니다. 안전한 채널로 전달하세요.')}</p>
 <label>{t('Username','사용자 이름')}<input name="username" autoComplete="off" value={username} onChange={e=>setUsername(e.target.value)} maxLength={64} required pattern={'[A-Za-z0-9_.@\\-]+'}/></label>
 <label>{t('Temporary password','임시 비밀번호')}<input name="password" type="password" autoComplete="new-password" value={password} onChange={e=>setPassword(e.target.value)} minLength={12} maxLength={256} required/></label>
 <label>{t('Role','역할')}<select value={role} onChange={e=>setRole(e.target.value as Role)}><RoleOptions/></select></label>
 <AccountNotice error={operation.error}/><div className="account-actions"><button type="submit" disabled={!ready||operation.pending||!username||!validAccountPassword(password)}>{t('Create account','계정 만들기')}</button><button type="button" className="secondary" disabled={operation.pending} onClick={onCancel}>{t('Cancel creation','생성 취소')}</button></div></form>;
}
function ManageUser({user,onDone,onCancel}:{user:AccountUser;onDone:()=>Promise<void>;onCancel:()=>void}){
 const t=useSecurityText(),operation=useAccountOperation(),a=captureAuthentication();
 const [role,setRole]=useState<Role>(user.role),[active,setActive]=useState(user.active),[password,setPassword]=useState('');
 const ready=a.authKind==='session'&&a.role==='ADMIN'&&!!a.csrfToken;
 const base='/admin/users/'+encodeURIComponent(user.id);
 const mutate=(suffix:string,method:string,body:unknown)=>{if(!ready||operation.pending)return;void operation.run(async()=>{try{await accountRequest(base+suffix,method,body);if(user.id===a.user?.id)endAccountSession(a);else await onDone();}finally{setPassword('');}},t('User updated.','사용자가 갱신되었습니다.'));};
 return <AccountDialog title={t(`Manage ${user.username}`,`${user.username} 관리`)} pending={operation.pending} onClose={onCancel}>
 <p><code>{user.id}</code></p><p className="warning">{t('Every change revokes all of this user’s sessions, even if permissions are unchanged. The last active administrator cannot be disabled or demoted.','권한이 동일해도 모든 변경은 해당 사용자의 세션을 취소합니다. 마지막 활성 관리자는 비활성화하거나 강등할 수 없습니다.')}</p>
 <form method="post" className="account-form" onSubmit={e=>{e.preventDefault();mutate('','PATCH',{role,active});}}><label>{t('Role','역할')}<select value={role} onChange={e=>setRole(e.target.value as Role)}><RoleOptions/></select></label><label className="check"><input type="checkbox" checked={active} onChange={e=>setActive(e.target.checked)}/>{t('Active','활성')}</label><button type="submit" disabled={!ready||operation.pending}>{t('Save permissions','권한 저장')}</button></form>
 <hr/><form method="post" action={'/api/v1'+base+'/reset-password'} className="account-form" onSubmit={e=>{e.preventDefault();mutate('/reset-password','POST',{password});}}><label>{t('New temporary password','새 임시 비밀번호')}<input type="password" name="password" autoComplete="new-password" value={password} onChange={e=>setPassword(e.target.value)} minLength={12} maxLength={256} required/></label><p>{t('Reset forces another password change at next login.','재설정하면 다음 로그인 시 비밀번호를 다시 변경해야 합니다.')}</p><button type="submit" disabled={!ready||operation.pending||!validAccountPassword(password)}>{t('Reset password','비밀번호 재설정')}</button></form>
 <div className="account-actions"><button type="button" className="danger" disabled={!ready||operation.pending} onClick={()=>mutate('/revoke-sessions','POST',{})}>{t('Revoke user sessions','사용자 세션 취소')}</button></div><AccountNotice error={operation.error}/>
 </AccountDialog>;
}
