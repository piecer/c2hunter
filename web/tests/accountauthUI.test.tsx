import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, expect, it, vi } from 'vitest';
import App from '../src/App';
import * as auth from '../src/authentication';
const json=(b:unknown,status=200)=>new Response(JSON.stringify(b),{status});
const csrf={csrf_token:'pre-private',account_login_enabled:true,setup_required:false,dev_login_enabled:false};
const me=(role='ADMIN',forced=false)=>({user:{id:'alice',username:'alice',role,active:true,must_change_password:forced},csrf_token:'session-private',session_id:'public-session',identity_scope:'user:alice',audit_available:true,auth_kind:'session'});
function mount(path='/login'){const client=new QueryClient({defaultOptions:{queries:{retry:false},mutations:{retry:false}}});return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><App/></MemoryRouter></QueryClientProvider>);}
beforeEach(()=>{auth.setAuthentication(null);localStorage.setItem('c2hunter-report-language','en');vi.stubGlobal('matchMedia',()=>({matches:false,addEventListener(){},removeEventListener(){}}));});
it('password login is POST/inert until real CSRF, supports native Enter, then verifies /me before entering account',async()=>{
 let release!:(r:Response)=>void;let signed=false;
 const fetcher=vi.fn(async(path:string,init?:RequestInit)=>{
  if(path.endsWith('/csrf'))return new Promise<Response>(r=>release=r);
  if(path.endsWith('/login')){expect(JSON.parse(String(init?.body))).toEqual({username:'alice',password:'secret-password-123'});expect(new Headers(init?.headers).get('x-csrf-token')).toBe('pre-private');signed=true;const {user,csrf_token,session_id,identity_scope}=me();return json({user,csrf_token,session_id,identity_scope});}
  if(path.endsWith('/me'))return signed?json(me()):json({error:{code:'AUTH_REQUIRED'}},401);
  return json({items:[],total:0});
 });vi.stubGlobal('fetch',fetcher);mount();
 const password=await screen.findByLabelText('Password');const form=password.closest('form')!;expect(form.method).toBe('post');expect(screen.getByRole('button',{name:'Sign in'})).toBeDisabled();
 fireEvent.change(screen.getByLabelText('Username'),{target:{value:'alice'}});fireEvent.change(password,{target:{value:'secret-password-123'}});fireEvent.submit(form);expect(fetcher.mock.calls.some(c=>c[0].endsWith('/login'))).toBe(false);
 await act(async()=>release(json(csrf)));await waitFor(()=>expect(screen.getByRole('button',{name:'Sign in'})).toBeEnabled());
 await userEvent.click(password);await userEvent.keyboard('{Enter}');await screen.findByRole('heading',{name:'Account'});
 expect(fetcher.mock.calls.filter(c=>c[0].endsWith('/login'))).toHaveLength(1);expect(localStorage.getItem('c2hunter-token')).toBeNull();
});
it('initial session introspection preserves a deep link instead of routing an already signed-in user to account',async()=>{
 let release!:(r:Response)=>void;const f=vi.fn(async(path:string)=>path.endsWith('/me')?new Promise<Response>(r=>release=r):json(path.endsWith('/csrf')?csrf:{items:[],total:0}));vi.stubGlobal('fetch',f);
 const pending=auth.initializeAccountAuthentication();mount('/analyses');await waitFor(()=>expect(release).toBeTypeOf('function'));await act(async()=>{release(json(me('VIEWER')));await pending;});await screen.findByRole('heading',{name:'Analysis history'});
});
it('cross-tab logout obtains a fresh challenge before enabling sign-in again',async()=>{
 let signed=true;
 const fetcher=vi.fn(async(path:string)=>json(path.endsWith('/csrf')?csrf:path.endsWith('/me')?(signed?me():{error:{code:'AUTH_REQUIRED'}}):{items:[],total:0},path.endsWith('/me')&&!signed?401:200));
 vi.stubGlobal('fetch',fetcher);await auth.initializeAccountAuthentication();mount('/account');await screen.findByRole('heading',{name:'Account'});
 signed=false;await act(async()=>window.dispatchEvent(new StorageEvent('storage',{key:'c2hunter-auth-invalidation',newValue:'new-nonce'})));
 await waitFor(()=>expect(screen.getByRole('button',{name:'Sign in'})).toBeEnabled());expect(fetcher.mock.calls.filter(c=>c[0].endsWith('/csrf')).length).toBe(2);
});
it('setup failure never enables development login or credential submission',async()=>{
 vi.stubGlobal('fetch',vi.fn(async()=>json({error:{code:'ACCOUNT_SETUP_REQUIRED',message:'secret raw exception'}},503)));mount();
 await screen.findByText(/ACCOUNT_SETUP_REQUIRED/);expect(screen.getByRole('button',{name:'Sign in'})).toBeDisabled();expect(screen.queryByRole('button',{name:'Development login'})).toBeNull();expect(document.body.textContent).not.toContain('secret raw exception');
});
it('forced change shows only a safe POST password form, revokes session and asks for re-login',async()=>{
 const fetcher=vi.fn(async(path:string,init?:RequestInit)=>{
  if(path.endsWith('/password')) {expect(JSON.parse(String(init?.body))).toEqual({current_password:'old-password-123',new_password:'new-password-123'});return new Response(null,{status:204});}
  return json(path.endsWith('/csrf')?csrf:path.endsWith('/me')?me('ANALYST',true):{items:[],total:0});
 });vi.stubGlobal('fetch',fetcher);await auth.initializeAccountAuthentication();mount('/analyses');
 const current=await screen.findByLabelText('Current password');expect(current.closest('form')?.method).toBe('post');expect(screen.queryByRole('link',{name:'Analysis history'})).toBeNull();
 fireEvent.change(current,{target:{value:'old-password-123'}});fireEvent.change(screen.getByLabelText('New password'),{target:{value:'new-password-123'}});fireEvent.change(screen.getByLabelText('Confirm new password'),{target:{value:'new-password-123'}});
 fireEvent.click(screen.getByRole('button',{name:'Change password'}));await waitFor(()=>expect(fetcher.mock.calls.filter(c=>c[0].endsWith('/password'))).toHaveLength(1));
});
it('account language choice updates both content and account navigation without reauthentication',async()=>{
 vi.stubGlobal('fetch',vi.fn(async(path:string)=>json(path.endsWith('/csrf')?csrf:path.endsWith('/me')?me():{items:[],total:0})));await auth.initializeAccountAuthentication();mount('/account');
 fireEvent.change(screen.getByRole('combobox',{name:'Report language'}),{target:{value:'ko'}});expect(await screen.findByRole('heading',{name:'계정'})).toBeVisible();expect(screen.getByRole('link',{name:'내 활동'})).toBeVisible();expect(auth.hasAuthentication()).toBe(true);
});
it('viewer keeps stored analysis history but cannot navigate to submission/settings/admin',async()=>{
 vi.stubGlobal('fetch',vi.fn(async(path:string)=>json(path.endsWith('/csrf')?csrf:path.endsWith('/me')?me('VIEWER'):{items:[],total:0})));
 await auth.initializeAccountAuthentication();mount('/analyses');await screen.findByRole('heading',{name:'Analysis history'});
 expect(screen.queryByRole('link',{name:'New analysis'})).toBeNull();expect(screen.queryByRole('link',{name:'Upload PCAP'})).toBeNull();expect(screen.queryByRole('link',{name:'Integration settings'})).toBeNull();expect(screen.queryByRole('link',{name:'Users'})).toBeNull();expect(screen.getByRole('link',{name:'My activity'})).toBeVisible();
});
