import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, expect, it, vi } from 'vitest';
import App from '../src/App';
import NetworkAIInterpretation from '../src/NetworkAIInterpretation';
import DDoSAIInterpretation from '../src/DDoSAIInterpretation';
import { initializeAccountAuthentication, setAuthentication } from '../src/authentication';
const json=(b:unknown,status=200)=>new Response(JSON.stringify(b),{status});
const entry={id:'entry',type:'IP',value:'203.0.113.8',description:'Known service',enabled:true};
const signature={id:'sig',name:'Beacon',enabled:true,version:1,length_tolerance_ratio:.1,entropy_tolerance:.2,simhash_max_distance:3,source_job_id:'job',source_flow_id:'flow',source_label_id:'label'};
beforeEach(()=>{setAuthentication(null);localStorage.setItem('c2hunter-report-language','en');vi.stubGlobal('matchMedia',()=>({matches:false,addEventListener(){},removeEventListener(){}}));});
async function setup(role:string,path:string){
 const fetcher=vi.fn(async(url:string,init?:RequestInit)=>{
  if(url.endsWith('/csrf'))return json({csrf_token:'pre',account_login_enabled:true,setup_required:false,dev_login_enabled:false});
  if(url.endsWith('/me'))return json({user:{id:'a',username:'a',role,active:true,must_change_password:false},csrf_token:'csrf',session_id:'sid',identity_scope:'user:a',audit_available:true,auth_kind:'session'});
  if(init?.method==='DELETE')return new Response(null,{status:204});
  if(url.includes('/allowlist'))return json({items:[entry],total:1,page:1,page_size:10});
  if(url.includes('/payload-signatures'))return json({items:[signature],total:1,page:1,page_size:10});
  if(url.includes('/analysis-jobs'))return json({items:[{id:'job',name:'Stored result',status:'COMPLETED',analysis:{module:'c2'}}],total:1,page:1,page_size:20});
  return json({items:[],total:0});
 });vi.stubGlobal('fetch',fetcher);await initializeAccountAuthentication();render(<QueryClientProvider client={new QueryClient({defaultOptions:{queries:{retry:false}}})}><MemoryRouter initialEntries={[path]}><App/></MemoryRouter></QueryClientProvider>);return fetcher;
}
it('cookie analyst policy deletion is live authority despite null bearer',async()=>{
 const f=await setup('ANALYST','/allowlist');fireEvent.click(await screen.findByRole('button',{name:'Delete 203.0.113.8'}));fireEvent.click(await screen.findByRole('button',{name:'Confirm delete'}));await waitFor(()=>expect(f.mock.calls.filter(c=>c[1]?.method==='DELETE')).toHaveLength(1));
});
it.each(['/allowlist','/payload-signatures','/analyses'])('viewer retains %s records but no mutation controls',async path=>{
 await setup('VIEWER',path);await screen.findByText(path==='/allowlist'?'Known service':path==='/payload-signatures'?'Beacon':'Stored result');
 expect(screen.queryByRole('button',{name:/^Delete/})).toBeNull();expect(screen.queryByRole('button',{name:/^Edit/})).toBeNull();expect(screen.queryByRole('button',{name:/^Disable/})).toBeNull();expect(screen.queryByRole('button',{name:'Create entry'})).toBeNull();
});
it.each([NetworkAIInterpretation,DDoSAIInterpretation])('viewer AI result readers never probe external model capabilities',async Component=>{
 const f=await setup('VIEWER','/allowlist');await screen.findByText('Known service');
 render(<QueryClientProvider client={new QueryClient({defaultOptions:{queries:{retry:false}}})}><Component jobId="job" completed={false}/></QueryClientProvider>);
 await waitFor(()=>expect(f.mock.calls.some(c=>c[0].includes('/ai-runs'))).toBe(true));expect(f.mock.calls.some(c=>c[0].endsWith('/ai-capabilities'))).toBe(false);
 expect(screen.queryByRole('button',{name:/New AI interpretation|새 AI 해석/})).toBeNull();
});
it.each(['/analyses/new','/analyses/upload','/settings/integrations','/admin/users','/admin/audit'])('viewer direct route %s is denied before protected query or form mount',async path=>{
 const f=await setup('VIEWER',path);expect(await screen.findByRole('alert')).toHaveTextContent('INSUFFICIENT_ROLE');expect(f.mock.calls.filter(c=>!c[0].includes('/auth/'))).toHaveLength(0);
});
