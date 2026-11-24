import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import App from '../src/App';
import { initializeAccountAuthentication, setAuthentication } from '../src/authentication';
const candidate={id:'c',job_id:'job',candidate_ip:'203.0.113.8',score:80,severity:'HIGH',hosts:[],sensors:[],protocols:[],ports:[],domains:[],flow_count:1,packet_count:1,byte_count:1,evidence:[],adjustments:[]};
it.each(['unmount','other-user'] as const)('cookie PCAP admission never automatically cancels or downloads after %s',async mode=>{
 setAuthentication(null);let user='alice';let release!:(r:Response)=>void;localStorage.setItem('c2hunter-report-language','en');vi.stubGlobal('matchMedia',()=>({matches:false,addEventListener(){},removeEventListener(){}}));
 const f=vi.fn(async(path:string,init?:RequestInit)=>{
  if(path.endsWith('/csrf'))return Response.json({csrf_token:'pre',account_login_enabled:true,setup_required:false,dev_login_enabled:false});
  if(path.endsWith('/me'))return Response.json({user:{id:user,username:user,role:'ANALYST',active:true,must_change_password:false},csrf_token:'csrf',session_id:'sid-'+user,identity_scope:'user:'+user,audit_available:true,auth_kind:'session'});
  if(path==='/api/v1/pcap-exports'&&init?.method==='POST')return new Promise<Response>(r=>release=r);
  if(path.endsWith('/candidates/c'))return Response.json(candidate);
  return Response.json({items:[],total:0});
 });vi.stubGlobal('fetch',f);await initializeAccountAuthentication();
 const client=new QueryClient({defaultOptions:{queries:{retry:false}}});const view=render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/candidates/c']}><App/></MemoryRouter></QueryClientProvider>);
 fireEvent.click(await screen.findByRole('button',{name:'점수 조정 및 작업'}));fireEvent.click(await screen.findByRole('button',{name:'Export candidate PCAP'}));await waitFor(()=>expect(release).toBeTypeOf('function'));view.unmount();
 if(mode==='other-user'){user='bob';await initializeAccountAuthentication();}
 await act(async()=>{release(Response.json({id:'export-a',status:'QUEUED'}));});
 expect(f.mock.calls.filter(c=>c[1]?.method==='POST').map(c=>c[0])).toEqual(['/api/v1/pcap-exports']);expect(f.mock.calls.some(c=>c[0].endsWith('/download'))).toBe(false);client.clear();
});
