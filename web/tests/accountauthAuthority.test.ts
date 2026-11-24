import { beforeEach, expect, it, vi } from 'vitest';
import * as auth from '../src/authentication';
import { api } from '../src/api';
import { jobApi } from '../src/jobInvestigationApi';
import { JobIntent } from '../src/jobInvestigationLifecycle';
import { captureJobRequest } from '../src/jobInvestigationApi';

const user = (id='alice', role='ANALYST') => ({id,username:id,role,active:true,must_change_password:false});
const me = (id='alice',sid='session-1',role='ANALYST') => ({user:user(id,role),csrf_token:'csrf-private',session_id:sid,identity_scope:'user:'+id,audit_available:true,auth_kind:'session'});
const csrf = {csrf_token:'pre-private',account_login_enabled:true,setup_required:false,dev_login_enabled:false};
beforeEach(()=>{localStorage.clear();sessionStorage.clear();auth.setAuthentication(null);});
const json=(body:unknown,status=200)=>new Response(JSON.stringify(body),{status});
async function identify(id='alice',sid='session-1',role='ANALYST') {
 vi.stubGlobal('fetch',vi.fn(async(path:string)=>json(path.endsWith('/csrf')?csrf:me(id,sid,role))));
 await auth.initializeAccountAuthentication();
}
it('hydrates named identity without a bearer or persistent CSRF and sends cookie+CSRF on JSON and bounded/JOB transports',async()=>{
 await identify();
 expect(auth.captureAuthentication()).toMatchObject({token:null,identityScope:'user:alice',sessionId:'session-1',authKind:'session'});
 expect(auth.hasAuthentication(auth.captureAuthentication())).toBe(true);
 expect(localStorage.length).toBe(0);expect(sessionStorage.length).toBe(0);
 const fetcher=vi.fn(async()=>json({items:[],next_cursor:null}));vi.stubGlobal('fetch',fetcher);
 await api.get('/dashboard');await api.post('/analysis-jobs',{});await api.boundedRequest('/ai-investigations/capabilities');await jobApi.history('job',null,new AbortController().signal);
 for(const [,init] of fetcher.mock.calls as unknown as [string,RequestInit][]){expect(init.credentials).toBe('same-origin');expect(new Headers(init.headers).get('authorization')).toBeNull();expect(new Headers(init.headers).get('x-csrf-token')).toBe('csrf-private');}
});
it('fences late introspection and A-B-A 401 while current 403 retains authority',async()=>{
 await identify();const a=auth.captureAuthentication();
 let release!:(r:Response)=>void;vi.stubGlobal('fetch',vi.fn(()=>new Promise<Response>(r=>release=r)));
 const old=auth.refreshAccountAuthentication();await identify('bob');await identify('alice','session-2');release(json(me('bob')));await old;
 expect(auth.captureAuthentication().identityScope).toBe('user:alice');auth.invalidateAuthentication(401,a);expect(auth.hasAuthentication(auth.captureAuthentication())).toBe(true);
 auth.invalidateAuthentication(403,auth.captureAuthentication());expect(auth.hasAuthentication(auth.captureAuthentication())).toBe(true);
 auth.invalidateAuthentication(401,auth.captureAuthentication());expect(auth.hasAuthentication(auth.captureAuthentication())).toBe(false);
});
it('hydrates explicit service bearer metadata without fabricating a user or granting account endpoints',async()=>{
 auth.setAuthentication('service-token');vi.stubGlobal('fetch',vi.fn(async(path:string)=>json(path.endsWith('/csrf')?{csrf_token:null,account_login_enabled:false,dev_login_enabled:false,setup_required:false}:{user:null,principal:{subject:'static-viewer',role:'VIEWER'},csrf_token:null,session_id:null,identity_scope:'legacy:static-viewer',audit_available:true,auth_kind:'bearer'})));
 await auth.initializeAccountAuthentication();expect(auth.captureAuthentication()).toMatchObject({token:'service-token',authKind:'bearer',role:'VIEWER',identityScope:'legacy:static-viewer'});expect(auth.captureAuthentication().user).toBeUndefined();expect(auth.hasRole('ADMIN')).toBe(false);
});
it('cross-tab nonce immediately retires identity; a late /me cannot override a newer introspection',async()=>{
 await identify();const a=auth.captureAuthentication();let release!:(r:Response)=>void;vi.stubGlobal('fetch',vi.fn(()=>new Promise<Response>(r=>release=r)));
 window.dispatchEvent(new StorageEvent('storage',{key:'c2hunter-auth-invalidation',newValue:'nonce-only'}));expect(auth.currentAuthentication(a)).toBe(false);expect(auth.hasAuthentication()).toBe(false);
 await identify('bob');release(json(me('alice')));await Promise.resolve();await Promise.resolve();expect(auth.captureAuthentication().identityScope).toBe('user:bob');
});
for(const [name,invoke] of Object.entries({json:()=>api.get('/test'),bounded:(signal:AbortSignal)=>api.boundedRequest('/test',{signal}),job:(signal:AbortSignal)=>jobApi.history('job',null,signal),download:()=>api.download('/test','capture.pcap')})) {
 it.each(['current','stale','aba','forbidden'] as const)(`cookie ${name} response %s`,async mode=>{
  await identify();let release!:(r:Response)=>void;vi.stubGlobal('fetch',vi.fn(()=>new Promise<Response>(r=>release=r)));
  const pending=invoke(new AbortController().signal).catch(e=>e);
  if(mode==='stale'||mode==='aba')await identify('bob');if(mode==='aba')await identify('alice','new-session');release(new Response('malformed',{status:mode==='forbidden'?403:401}));await pending;
  expect(auth.hasAuthentication()).toBe(mode!=='current');
 });
}
it('cookie XHR carries CSRF and same-origin credentials, and an aborted 401 cannot retire its session',async()=>{
 await identify();class XHR {static latest:XHR;headers=new Headers();withCredentials=false;status=401;responseText='not json';upload={onprogress:null};onload:(()=>void)|null=null;onabort:(()=>void)|null=null;constructor(){XHR.latest=this;}open(){}setRequestHeader(k:string,v:string){this.headers.set(k,v);}send(){}abort(){this.onabort?.();}}
 vi.stubGlobal('XMLHttpRequest',XHR);const controller=new AbortController();const p=api.uploadWithProgress('/test',new Blob(['x']),'application/octet-stream',vi.fn(),controller.signal).catch(e=>e);
 expect(XHR.latest.headers.get('authorization')).toBeNull();expect(XHR.latest.headers.get('x-csrf-token')).toBe('csrf-private');expect(XHR.latest.withCredentials).toBe(true);controller.abort();XHR.latest.onload?.();await p;expect(auth.hasAuthentication()).toBe(true);
});
it('revoked-session revalidation discards obsolete prelogin CSRF instead of enabling stale login',async()=>{
 await identify();vi.stubGlobal('fetch',vi.fn(async()=>json({error:{code:'AUTH_REQUIRED'}},401)));await auth.refreshAccountAuthentication();expect(auth.accountState().csrfToken).toBe('');expect(auth.hasAuthentication()).toBe(false);
});
it('cookie transports refuse redirects rather than forward session-bound CSRF to another origin',async()=>{
 await identify();const f=vi.fn(async()=>json({items:[],next_cursor:null}));vi.stubGlobal('fetch',f);await api.get('/test');await api.boundedRequest('/test');await jobApi.history('job',null,new AbortController().signal);
 for(const [,init] of f.mock.calls as unknown as [string,RequestInit][])expect(init.redirect).toBe('error');
});
it('named-session hydration works without readable or writable browser storage',async()=>{
 vi.spyOn(Storage.prototype,'getItem').mockImplementation(()=>{throw new DOMException('blocked','SecurityError');});vi.spyOn(Storage.prototype,'removeItem').mockImplementation(()=>{throw new DOMException('blocked','SecurityError');});await identify();expect(auth.hasAuthentication()).toBe(true);expect(auth.captureAuthentication().token).toBeNull();
});
it('anonymous account mode cannot create a null-token receipt owner before /me confirmation',async()=>{
 vi.stubGlobal('fetch',vi.fn(async(path:string)=>path.endsWith('/csrf')?json(csrf):json({error:{code:'AUTH_REQUIRED'}},401)));await auth.initializeAccountAuthentication();expect(()=>new JobIntent(sessionStorage).pending()).toThrow();
});
it('recovers cookie receipt only after same-user server validation; neither another user nor legacy token adopts/deletes it',async()=>{
 await identify();const intent=new JobIntent(sessionStorage),body=captureJobRequest('Private question','en',false);intent.capture('job',body);const raw=sessionStorage.getItem('c2hunter-job-investigation-pending-v1');
 await identify('bob');expect(()=>new JobIntent(sessionStorage).pending()).toThrow();expect(sessionStorage.getItem('c2hunter-job-investigation-pending-v1')).toBe(raw);
 await identify('alice','session-2');expect(()=>intent.pending()).toThrow();expect(new JobIntent(sessionStorage).pending()).toEqual({job:'job',body});
 auth.setAuthentication('legacy');expect(()=>new JobIntent(sessionStorage).pending()).toThrow();expect(sessionStorage.getItem('c2hunter-job-investigation-pending-v1')).toBe(raw);
});
