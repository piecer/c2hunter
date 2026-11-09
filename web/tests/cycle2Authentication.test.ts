import { beforeEach, expect, it, vi } from 'vitest';
import { api } from '../src/api';
import { jobApi } from '../src/jobInvestigationApi';
import { setAuthentication } from '../src/authentication';
beforeEach(()=>localStorage.setItem('c2hunter-token','principal-A'));
const clients={
 request: (s:AbortSignal)=>{void s;return api.get('/test');},
 download: (s:AbortSignal)=>{void s;return api.download('/test','test.pcap');},
 bounded: (s:AbortSignal)=>api.boundedRequest('/test',{signal:s}),
 job: (s:AbortSignal)=>jobApi.history('job',null,s),
};
for(const [name,invoke] of Object.entries(clients)) {
 it.each(['changed','current','malformed','aba'] as const)(`${name} 401 authority %s`,async mode=>{
  const invalid=vi.fn();window.addEventListener('c2hunter-auth-invalid',invalid);
  let release!:(r:Response)=>void;vi.stubGlobal('fetch',vi.fn(()=>new Promise<Response>(r=>{release=r;})));
  const pending=invoke(new AbortController().signal).catch(e=>e);
  if(mode==='changed')localStorage.setItem('c2hunter-token','principal-B');
  if(mode==='aba'){setAuthentication('principal-B');setAuthentication('principal-A');}
  release(new Response(mode==='malformed'?'not JSON':'{}',{status:401}));await pending;
  expect(invalid).toHaveBeenCalledTimes(mode==='current'||mode==='malformed'?1:0);
  expect(localStorage.getItem('c2hunter-token')).toBe(mode==='changed'?'principal-B':mode==='aba'?'principal-A':null);
  window.removeEventListener('c2hunter-auth-invalid',invalid);
 });
}
it.each(['bounded','job'] as const)('retired same-authority %s 401 cannot invalidate',async name=>{
 let release!:(r:Response)=>void;const invalid=vi.fn();window.addEventListener('c2hunter-auth-invalid',invalid);
 vi.stubGlobal('fetch',vi.fn(()=>new Promise<Response>(r=>{release=r;})));
 const controller=new AbortController(),pending=clients[name](controller.signal).catch(e=>e);controller.abort();release(new Response('{}',{status:401}));await pending;
 expect(localStorage.getItem('c2hunter-token')).toBe('principal-A');expect(invalid).not.toHaveBeenCalled();window.removeEventListener('c2hunter-auth-invalid',invalid);
});
class FakeXHR {
 static latest:FakeXHR;
 status=401;responseText='not JSON';upload={onprogress:null};onload:(()=>void)|null=null;onerror:(()=>void)|null=null;onabort:(()=>void)|null=null;
 constructor(){FakeXHR.latest=this;}
 open(){} setRequestHeader(){} send(){} abort(){this.onabort?.();}
}
it.each(['changed','retired','current','aba','transport-failed'] as const)('XHR 401 authority %s',async mode=>{
 vi.stubGlobal('XMLHttpRequest',FakeXHR);const invalid=vi.fn();window.addEventListener('c2hunter-auth-invalid',invalid);
 const controller=new AbortController(),pending=api.uploadWithProgress('/test',new Blob(['x']),'test',vi.fn(),controller.signal).catch(e=>e);
 if(mode==='changed')localStorage.setItem('c2hunter-token','principal-B');
 if(mode==='retired')controller.abort();
 if(mode==='transport-failed')FakeXHR.latest.onerror?.();
 if(mode==='aba'){setAuthentication('principal-B');setAuthentication('principal-A');}
 FakeXHR.latest.onload?.();await pending;
 expect(invalid).toHaveBeenCalledTimes(mode==='current'?1:0);
 expect(localStorage.getItem('c2hunter-token')).toBe(mode==='changed'?'principal-B':mode==='current'?null:'principal-A');window.removeEventListener('c2hunter-auth-invalid',invalid);
});
