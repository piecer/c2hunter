import { randomUUID } from 'node:crypto';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, expect, it, vi } from 'vitest';
import App from '../src/App';
import * as auth from '../src/authentication';
const user=(id='alice',role='ADMIN')=>({id,username:id,role,active:true,must_change_password:false});
const me=(role='ADMIN')=>({user:user('alice',role),csrf_token:'session-private',session_id:'s1',identity_scope:'user:alice',audit_available:true,auth_kind:'session'});
const json=(b:unknown,status=200)=>new Response(JSON.stringify(b),{status});
const csrf={csrf_token:'pre',account_login_enabled:true,setup_required:false,dev_login_enabled:false};
const audit={id:'a'.repeat(32),timestamp:1700000000,actor_id:'alice',actor_name:'alice',actor_role:'ADMIN',auth_kind:'session',action:'account.create',target:'bob',outcome:'succeeded',request_id:'11111111-1111-4111-8111-111111111111',source_ip:'127.0.0.1',status:201,job_id:null,details:{role:'VIEWER'}};
function mount(path:string){return render(<QueryClientProvider client={new QueryClient({defaultOptions:{queries:{retry:false}}})}><MemoryRouter initialEntries={[path]}><App/></MemoryRouter></QueryClientProvider>);}
beforeEach(()=>{auth.setAuthentication(null);localStorage.setItem('c2hunter-report-language','en');vi.stubGlobal('matchMedia',()=>({matches:false,addEventListener(){},removeEventListener(){}}));});
it('lists own sessions, revokes exact selected session and re-reads the list; all-session revocation ends local identity',async()=>{
 let revoked=false;
 const fetcher=vi.fn(async(path:string,init?:RequestInit)=>{
  if(path.endsWith('/revoke')){const body=JSON.parse(String(init?.body));if(body.session_id){expect(body).toEqual({session_id:'s2'});revoked=true;}return new Response(null,{status:204});}
  return json(path.endsWith('/csrf')?csrf:path.endsWith('/me')?me():path.includes('/auth/sessions')?{items:revoked?[]:[{id:'s2',created_at:1700000000,last_seen_at:1700000010,expires_at:1700000100,current:false}],total:revoked?0:1}:{items:[],total:0});
 });vi.stubGlobal('fetch',fetcher);await auth.initializeAccountAuthentication();mount('/account');
 fireEvent.click(await screen.findByRole('button',{name:'Revoke session s2'}));fireEvent.click(await screen.findByRole('button',{name:'Confirm revocation'}));
 await waitFor(()=>expect(screen.queryByRole('button',{name:'Revoke session s2'})).toBeNull());
 fireEvent.click(screen.getByRole('button',{name:'Revoke all my sessions'}));fireEvent.click(await screen.findByRole('button',{name:'Confirm revocation'}));await waitFor(()=>expect(auth.hasAuthentication()).toBe(false));
});
it('admin creates a forced-change account, changes role/status, resets password and revokes sessions with exact frozen routes',async()=>{
 const temporaryPassword=randomUUID();
 const users=[user()];const writes:{path:string;method:string;body:unknown}[]=[];
 const fetcher=vi.fn(async(path:string,init?:RequestInit)=>{
  if(init?.method && init.method!=='GET'){
   const body=JSON.parse(String(init.body));writes.push({path,method:init.method,body});
   if(path==='/api/v1/admin/users'){const u={...user(body.username,body.role),must_change_password:true};users.push(u);return json(u,201);}
   if(init.method==='PATCH'){Object.assign(users[1],body);return json(users[1]);}
   return new Response(null,{status:204});
  }
  return json(path.endsWith('/csrf')?csrf:path.endsWith('/me')?me():{items:users,total:users.length});
 });vi.stubGlobal('fetch',fetcher);await auth.initializeAccountAuthentication();mount('/admin/users');
 await waitFor(()=>expect(screen.getByRole('button',{name:'Create user'})).toBeEnabled());fireEvent.click(screen.getByRole('button',{name:'Create user'}));
 const create=screen.getByRole('form',{name:'Create account'});expect(create.getAttribute('method')).toBe('post');
 fireEvent.change(within(create).getByLabelText('Username'),{target:{value:'bob'}});fireEvent.change(within(create).getByLabelText('Temporary password'),{target:{value:temporaryPassword}});fireEvent.click(within(create).getByRole('button',{name:'Create account'}));
 await screen.findByRole('heading',{name:'bob'});fireEvent.click(screen.getByRole('button',{name:'Manage bob'}));
 const dialog=await screen.findByRole('dialog');fireEvent.change(within(dialog).getByLabelText('Role'),{target:{value:'ANALYST'}});fireEvent.click(within(dialog).getByRole('checkbox',{name:'Active'}));fireEvent.click(within(dialog).getByRole('button',{name:'Save permissions'}));
 await waitFor(()=>expect(writes.some(w=>w.method==='PATCH')).toBe(true));
 await waitFor(()=>expect(screen.getByRole('button',{name:'Manage bob'})).toBeEnabled());fireEvent.click(screen.getByRole('button',{name:'Manage bob'}));
 fireEvent.change(screen.getByLabelText('New temporary password'),{target:{value:'reset-password-123'}});fireEvent.click(screen.getByRole('button',{name:'Reset password'}));
 await waitFor(()=>expect(writes.some(w=>w.path.endsWith('/reset-password'))).toBe(true));
 await waitFor(()=>expect(screen.getByRole('button',{name:'Manage bob'})).toBeEnabled());fireEvent.click(screen.getByRole('button',{name:'Manage bob'}));fireEvent.click(screen.getByRole('button',{name:'Revoke user sessions'}));
 await waitFor(()=>expect(writes).toEqual([
  {path:'/api/v1/admin/users',method:'POST',body:{username:'bob',password:temporaryPassword,role:'VIEWER'}},
  {path:'/api/v1/admin/users/bob',method:'PATCH',body:{role:'ANALYST',active:false}},
  {path:'/api/v1/admin/users/bob/reset-password',method:'POST',body:{password:'reset-password-123'}},
  {path:'/api/v1/admin/users/bob/revoke-sessions',method:'POST',body:{}},
 ]));
});
it('own activity never sends actor override; admin JSONL export is one bounded filtered page and uses server continuation',async()=>{
 const fetcher=vi.fn(async(path:string,init?:RequestInit)=>{
  if(path.endsWith('/audit/export')){expect(init?.method).toBe('POST');return new Response(JSON.stringify(audit)+'\n',{headers:{'content-type':'application/x-ndjson','x-total-count':'130','x-next-offset':'50'}});}
  return json(path.endsWith('/csrf')?csrf:path.endsWith('/me')?me():{items:[audit],total:130});
 });vi.stubGlobal('fetch',fetcher);await auth.initializeAccountAuthentication();let view=mount('/account/activity');
 await screen.findByText('account.create');expect(screen.queryByLabelText('Actor ID')).toBeNull();expect(fetcher.mock.calls.some(c=>c[0].includes('/auth/activity?'))).toBe(true);view.unmount();
 const click=vi.spyOn(HTMLAnchorElement.prototype,'click').mockImplementation(()=>{});URL.createObjectURL=vi.fn(()=>'blob:owned');URL.revokeObjectURL=vi.fn();
 view=mount('/admin/audit');await screen.findByText('account.create');fireEvent.change(screen.getByLabelText('Actor ID'),{target:{value:'alice'}});await waitFor(()=>expect(screen.getByRole('button',{name:'Apply filters'})).toBeEnabled());fireEvent.click(screen.getByRole('button',{name:'Apply filters'}));
 await waitFor(()=>expect(fetcher.mock.calls.some(c=>c[0].includes('user_id=alice'))).toBe(true));await waitFor(()=>expect(screen.getByRole('button',{name:'Export this page (JSONL)'})).toBeEnabled());fireEvent.click(screen.getByRole('button',{name:'Export this page (JSONL)'}));
 await waitFor(()=>expect(click).toHaveBeenCalledOnce());expect(fetcher.mock.calls.filter(c=>c[0].endsWith('/audit/export'))).toHaveLength(1);const call=fetcher.mock.calls.find(c=>c[0].endsWith('/audit/export'))!;expect(JSON.parse(String(call[1]?.body))).toMatchObject({user_id:'alice',limit:50,offset:0});await screen.findByText(/Next export offset: 50/);
 await act(async()=>auth.setAuthentication(null));expect(document.body.textContent).not.toContain('account.create');
});
