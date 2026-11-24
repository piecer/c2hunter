import { beforeEach, expect, it, vi } from 'vitest';
import { exportAuditPage, isAuditItem } from '../src/accountAudit';
import { accountPage, accountRequest, isAccountUser, safeAccountError } from '../src/accountSecurity';
import { ApiError } from '../src/api';
import * as auth from '../src/authentication';
const user=(id='alice')=>({id,username:id,role:'ADMIN',active:true,must_change_password:false});
const event={id:'a'.repeat(32),timestamp:1700000000,actor_id:'alice',actor_name:'alice',actor_role:'ADMIN',auth_kind:'session',action:'job.lifecycle',target:'job',outcome:'succeeded',request_id:'11111111-1111-4111-8111-111111111111',source_ip:'127.0.0.1',status:200,job_id:'job',details:{family:'analysis',domain_status:'COMPLETED',intent_id:'b'.repeat(32),count:1,active:true,must_change_password:false,role:'VIEWER',reason:'completed'}};
const json=(b:unknown,status=200)=>Response.json(b,{status});
async function identify(id='alice'){
 vi.stubGlobal('fetch',vi.fn(async(path:string)=>json(path.endsWith('/csrf')?{csrf_token:'pre',account_login_enabled:true,setup_required:false,dev_login_enabled:false}:{user:user(id),csrf_token:'csrf',session_id:'sid-'+id,identity_scope:'user:'+id,audit_available:true,auth_kind:'session'})));await auth.initializeAccountAuthentication();
}
beforeEach(()=>{auth.setAuthentication(null);URL.createObjectURL=vi.fn(()=>'blob:owned');URL.revokeObjectURL=vi.fn();vi.spyOn(HTMLAnchorElement.prototype,'click').mockImplementation(()=>{});});
it('accepts the full closed audit details vocabulary',()=>expect(isAuditItem(event)).toBe(true));
it.each([
 {password:'must-not-export'}, {id:'not-an-id'}, {timestamp:NaN}, {actor_id:1}, {actor_name:1}, {actor_role:'OWNER'}, {auth_kind:'anonymous-admin'}, {action:'a'.repeat(81)}, {target:'x'.repeat(301)}, {outcome:'success'}, {request_id:1}, {source_ip:1}, {job_id:1}, {status:600}, {details:null}, {details:[]}, {details:{cookie:'secret'}}, {details:{count:-1}}, {details:{intent_id:'wrong'}}, {details:{family:'other'}}, {details:{reason:'raw exception with credentials'}}, {details:{role:['ADMIN']}},
])('rejects malformed or secret-bearing audit wire %#',change=>expect(isAuditItem({...event,...change})).toBe(false));
it.each([
 ['malformed','not JSON',{'x-total-count':'1'}],
 ['secret',JSON.stringify({...event,details:{password:'secret'}}),{'x-total-count':'1'}],
 ['too many',Array.from({length:51},()=>JSON.stringify(event)).join('\n'),{'x-total-count':'51'}],
 ['oversize',JSON.stringify(event),{'x-total-count':'1','content-length':'2097153'}],
 ['missing count',JSON.stringify(event),{}],
 ['invalid count',JSON.stringify(event),{'x-total-count':'-1'}],
 ['backwards offset',JSON.stringify(event),{'x-total-count':'100','x-next-offset':'0'}],
 ['overshooting offset',JSON.stringify(event),{'x-total-count':'100','x-next-offset':'51'}],
] as const)('refuses %s export before creating a download',async(_name,body,headers)=>{
 await identify();vi.stubGlobal('fetch',vi.fn(async()=>new Response(body,{headers})));await expect(exportAuditPage({limit:50,offset:0})).rejects.toThrow();expect(URL.createObjectURL).not.toHaveBeenCalled();
});
it('bounds streamed audit bytes even without content-length',async()=>{
 await identify();const cancel=vi.fn();let count=0;const stream=new ReadableStream<Uint8Array>({pull(c){count++;c.enqueue(new Uint8Array(1024*1024));},cancel});vi.stubGlobal('fetch',vi.fn(async()=>new Response(stream,{headers:{'x-total-count':'1'}})));
 await expect(exportAuditPage({limit:50,offset:0})).rejects.toThrow('Export exceeds limit');expect(cancel).toHaveBeenCalledOnce();expect(count).toBeLessThanOrEqual(4);expect(URL.createObjectURL).not.toHaveBeenCalled();
});
it('downloads one terminal page with no continuation',async()=>{
 await identify();const f=vi.fn(async()=>new Response(JSON.stringify(event)+'\n',{headers:{'x-total-count':'1','x-next-offset':''}}));vi.stubGlobal('fetch',f);
 await expect(exportAuditPage({limit:50,offset:0})).resolves.toEqual({total:1,nextOffset:null});expect(f).toHaveBeenCalledOnce();expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:owned');
});
it('late export bytes cannot publish a predecessor file to another account',async()=>{
 await identify();let release!:(r:Response)=>void;vi.stubGlobal('fetch',vi.fn(()=>new Promise<Response>(r=>release=r)));const pending=exportAuditPage({limit:50,offset:0}).catch(e=>e);await identify('bob');release(new Response(JSON.stringify(event)+'\n',{headers:{'x-total-count':'1'}}));await pending;expect(URL.createObjectURL).not.toHaveBeenCalled();
});
it('strict server 403 denies publication without logging out or retrying the POST',async()=>{
 await identify();const f=vi.fn(async()=>json({error:{code:'INSUFFICIENT_ROLE',message:'raw secret exception'}},403));vi.stubGlobal('fetch',f);await expect(exportAuditPage({limit:50,offset:0})).rejects.toMatchObject({code:'INSUFFICIENT_ROLE',status:403});expect(f).toHaveBeenCalledOnce();expect(auth.hasAuthentication()).toBe(true);expect(URL.createObjectURL).not.toHaveBeenCalled();
});
it('legacy service authority cannot call named account APIs or audit export',async()=>{
 auth.setAuthentication('static-admin');const f=vi.fn();vi.stubGlobal('fetch',f);await expect(accountRequest('/admin/users','POST',{})).rejects.toMatchObject({status:403});await expect(exportAuditPage({limit:50,offset:0})).rejects.toMatchObject({status:403});expect(f).not.toHaveBeenCalled();
});
it('account list and error boundaries retain no arbitrary response messages',()=>{
 expect(accountPage({items:[user()],total:1},isAccountUser)).toEqual({items:[user()],total:1});expect(()=>accountPage({items:[user()],total:0},isAccountUser)).toThrow();expect(()=>accountPage({items:[{...user(),role:'OWNER'}],total:1},isAccountUser)).toThrow();expect(safeAccountError(new ApiError('password=secret',409,'LAST_ADMIN'))).toBe('LAST_ADMIN');expect(safeAccountError(new Error('password=secret'))).toBe('SECURITY_UNAVAILABLE');expect(safeAccountError(new ApiError('password=secret',400,'ARBITRARY'))).toBe('REQUEST_REJECTED');
});
it.each([204,401,503])('logout status %s has explicit safe retention semantics',async status=>{
 await identify();vi.stubGlobal('fetch',vi.fn(async()=>status===204?new Response(null,{status}):json({error:{code:'SECURITY_UNAVAILABLE',message:'secret'}},status)));
 if(status===503)await expect(auth.logoutAccount()).rejects.toThrow();else await auth.logoutAccount();expect(auth.hasAuthentication()).toBe(status===503);
});
