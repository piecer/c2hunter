import { QueryClient,QueryClientProvider } from '@tanstack/react-query';
import { act,fireEvent,render,screen,waitFor } from '@testing-library/react';
import { MemoryRouter, useNavigate } from 'react-router-dom';
import { beforeEach,expect,it,vi } from 'vitest';
import { writeFileSync } from 'node:fs';
import App from '../src/App';
import { api,ApiError } from '../src/api';
import { jobApi } from '../src/jobInvestigationApi';
import { producer } from './jobInvestigationFixtures';
import { parseJobWire } from '../src/jobInvestigationContract';
const record=(name:string,value:unknown)=>{if(process.env.C2HUNTER_JOB_CORPUS_OUTPUT)writeFileSync(process.env.C2HUNTER_JOB_CORPUS_OUTPUT+'.'+name,JSON.stringify(value,null,2));};
beforeEach(()=>{sessionStorage.clear();localStorage.setItem('c2hunter-token','principal-A');vi.stubGlobal('matchMedia',()=>({matches:false}));});
function setupGet(){vi.spyOn(api,'get').mockImplementation(async(path:string)=>path==='/analysis-jobs/job'?{id:'job',name:'Saved job',status:'COMPLETED',analysis:{module:'c2'}}:path==='/analysis-jobs/B'?{id:'B',name:'Other job',status:'COMPLETED',analysis:{module:'c2'}}:path==='/ai-capabilities'?{available:false}:{items:[]});}
function Nav(){const nav=useNavigate();return <><button onClick={()=>nav('/analyses/job')}>test route A</button><button onClick={()=>nav('/analyses/B')}>test route B</button></>;}
function mount(path='/analyses/job'){const client=new QueryClient({defaultOptions:{queries:{retry:false,staleTime:Infinity}}});const view=render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><Nav/><App/></MemoryRouter></QueryClientProvider>);return {view,client,close(){view.unmount();client.clear();}};}
it('normal App sign-out/login must not transfer an unresolved principal-A POST to principal-B',async()=>{
 setupGet();const posts:{token:string|null;body:string}[]=[];
 vi.stubGlobal('fetch',vi.fn(async(path:string,init?:RequestInit)=>{
  if(init?.method==='POST'){posts.push({token:new Headers(init.headers).get('authorization'),body:String(init.body)});throw new Error('acknowledgment lost');}
  return new Response(path.endsWith('/capabilities')?producer.fixtures.capabilities:'{"items":[],"next_cursor":null}');
 }));
 const first=mount();fireEvent.click(await screen.findByRole('button',{name:/Open experimental investigation/}));
 await waitFor(()=>expect(screen.getByRole('button',{name:/Start experimental investigation/})).toBeEnabled());
 fireEvent.change(screen.getByRole('textbox',{name:/Question/}),{target:{value:'Principal A private analyst question'}});
 fireEvent.click(screen.getByRole('button',{name:/Start experimental investigation/}));await screen.findByRole('alert');
 expect(posts).toHaveLength(1);const pending=sessionStorage.getItem('c2hunter-job-investigation-pending-v1');
 fireEvent.click(screen.getByRole('button',{name:'Sign out'}));expect(await screen.findByRole('button',{name:'Development login'})).toBeInTheDocument();
 expect(screen.queryByRole('region',{name:'Experimental job investigation'})).toBeNull();
 vi.spyOn(api,'post').mockResolvedValue({access_token:'principal-B'});
 fireEvent.change(screen.getByRole('textbox',{name:'Username'}),{target:{value:'bob'}});
 fireEvent.click(screen.getByRole('button',{name:'Development login'}));await waitFor(()=>expect(localStorage.getItem('c2hunter-token')).toBe('principal-B'));
 // jsdom cannot navigate: the actual Login stored B's token and called assign('/').
 // Explicit document remount models that ordinary full load, retaining sessionStorage.
 first.close();const second=mount();
 fireEvent.click(await screen.findByRole('button',{name:/Open experimental investigation/}));
 await screen.findByText(/Admission intent is unreadable/);
 expect(screen.queryByRole('button',{name:/Retry exact request/})).toBeNull();
 expect(screen.getByRole('button',{name:/Start experimental investigation/})).toBeDisabled();
 expect(document.body.textContent).not.toContain('Principal A private analyst question');
 expect(sessionStorage.getItem('c2hunter-job-investigation-pending-v1')).toBe(pending);
 record('review-principal-replay.json',{posts,pendingAfterSignout:pending,storageAfterLogin:sessionStorage.getItem('c2hunter-job-investigation-pending-v1'),reload:'explicit App remount after actual Login; jsdom no navigation'});
 second.close();expect(posts.filter(p=>p.token==='Bearer principal-B')).toHaveLength(0);
 localStorage.setItem('c2hunter-token','principal-A');const third=mount();
 fireEvent.click(await screen.findByRole('button',{name:/Open experimental investigation/}));
 const retry=await screen.findByRole('button',{name:/Retry exact request/});expect(retry).toBeEnabled();
 fireEvent.click(retry);await screen.findByText('acknowledgment lost');
 expect(posts).toHaveLength(2);expect(posts[1]).toEqual(posts[0]);third.close();
});
it('actual App route should retain saved investigations when mutable analysis source is gone',async()=>{
 setupGet();vi.mocked(api.get).mockImplementation(async(path:string)=>{if(path==='/analysis-jobs/job')throw new ApiError('Source deleted',404);return {items:[]};});
 const run=parseJobWire('run',producer.fixtures.run_completed),peer=run.selection.peer_ids[0];
 const evidence=producer.fixtures.evidence_protocol;
 const decoded=parseJobWire('evidence',evidence);
 const transport=vi.fn(async(path:string,init?:RequestInit)=>{expect(init?.method).toBe('GET');return new Response(path.endsWith('/capabilities')?producer.fixtures.capabilities:path.includes('/evidence/')?evidence:'{"items":['+producer.fixtures.run_completed+'],"next_cursor":null}');});
 vi.stubGlobal('fetch',transport);
 const app=mount();await screen.findByText('Source deleted');
 const hasEntry=screen.queryByRole('button',{name:/Open experimental investigation/})!==null;
 expect(hasEntry).toBe(true);fireEvent.click(screen.getByRole('button',{name:/Open experimental investigation/}));
 fireEvent.click(await screen.findByRole('button',{name:/View saved run/}));
 expect(screen.getByRole('button',{name:/Start experimental investigation/})).toBeDisabled();
 expect(screen.getByText('Source deleted')).toBeInTheDocument();
 fireEvent.click(screen.getByRole('button',{name:`Peer details ${peer}`}));
 fireEvent.click(screen.getByRole('button',{name:`Evidence ${decoded.evidence_id}`}));
 await screen.findByRole('region',{name:/Evidence detail/});
 expect(screen.getByText(/COMPLETED alone does not prove/)).toBeInTheDocument();
 expect(transport.mock.calls.some(c=>c[0].includes('/evidence/'))).toBe(true);
 record('review-missing-source-route.json',{hasEntry,paths:transport.mock.calls.map(c=>c[0]),text:document.body.textContent});
 expect(transport.mock.calls.every(c=>c[1]?.method==='GET')).toBe(true);app.close();
});
it('late 401 after route retirement must not invalidate the current App session',async()=>{
 setupGet();let release!:(r:Response)=>void;let fired=false;let oldSignal:AbortSignal|undefined;
 vi.stubGlobal('fetch',vi.fn((path:string,init?:RequestInit)=>{
  if(path.endsWith('/capabilities'))return Promise.resolve(new Response(producer.fixtures.capabilities));
  if(path.includes('/job/ai-job-investigations')){oldSignal=init?.signal as AbortSignal;return new Promise<Response>(r=>{release=(v)=>{fired=true;r(v);};});}
  return Promise.resolve(new Response('{"items":[],"next_cursor":null}'));
 }));
 const app=mount();fireEvent.click(await screen.findByRole('button',{name:/Open experimental investigation/}));await waitFor(()=>expect(release).toBeTypeOf('function'));
 fireEvent.click(screen.getByRole('button',{name:'test route B'}));await screen.findByRole('heading',{name:'Other job'});expect(oldSignal?.aborted).toBe(true);
 // Browser-observable storage event models another same-origin tab completing Login.
 localStorage.setItem('c2hunter-token','principal-B');
 window.dispatchEvent(new StorageEvent('storage',{key:'c2hunter-token',oldValue:'principal-A',newValue:'principal-B',storageArea:localStorage}));
 await act(async()=>{release(new Response('{}',{status:401}));});
 record('review-retired-401.json',{fired,aborted:oldSignal?.aborted,token:localStorage.getItem('c2hunter-token'),login:!!screen.queryByRole('button',{name:'Development login'})});
 const stillAuthenticated=localStorage.getItem('c2hunter-token')==='principal-B';app.close();expect(fired).toBe(true);expect(stillAuthenticated).toBe(true);
});
it('cached real App A-B-A retires expanded detail and allows fresh history',async()=>{
 setupGet();const original=parseJobWire('run',producer.fixtures.run_completed);
 vi.spyOn(jobApi,'capabilities').mockResolvedValue(parseJobWire('capabilities',producer.fixtures.capabilities));
 const history=vi.spyOn(jobApi,'history').mockImplementation(async job=>({items:job==='job'?[original]:[],next_cursor:null}));
 const post=vi.spyOn(jobApi,'create');const app=mount();
 fireEvent.click(await screen.findByRole('button',{name:/Open experimental investigation/}));fireEvent.click(await screen.findByRole('button',{name:/View saved run/}));
 fireEvent.click(screen.getByRole('button',{name:`Peer details ${original.selection.peer_ids[0]}`}));expect(screen.getByRole('region',{name:'Peer assessment detail'})).toBeInTheDocument();
 fireEvent.click(screen.getByRole('button',{name:'test route B'}));await screen.findByRole('heading',{name:'Other job'});
 fireEvent.click(screen.getByRole('button',{name:'test route A'}));fireEvent.click(await screen.findByRole('button',{name:/Open experimental investigation/}));fireEvent.click(await screen.findByRole('button',{name:/View saved run/}));
 expect(screen.queryByRole('region',{name:'Peer assessment detail'})).toBeNull();expect(history).toHaveBeenCalledTimes(2);expect(post).not.toHaveBeenCalled();app.close();
});

it.each(['job','shared'] as const)('current malformed %s 401 executes actual App invalidation without clearing pending receipt',async client=>{
 setupGet();const pending='preserved-unresolved-receipt';sessionStorage.setItem('c2hunter-job-investigation-pending-v1',pending);
 const app=mount();await screen.findByRole('heading',{name:'Saved job'});
 vi.stubGlobal('fetch',vi.fn(async()=>new Response('not JSON',{status:401})));
 await act(async()=>{try{const signal=new AbortController().signal;await (client==='job'?jobApi.history('job',null,signal):api.boundedRequest('/test',{signal}));}catch{/* malformed error remains refused */}});
 expect(localStorage.getItem('c2hunter-token')).toBeNull();expect(await screen.findByRole('button',{name:'Development login'})).toBeInTheDocument();
 expect(sessionStorage.getItem('c2hunter-job-investigation-pending-v1')).toBe(pending);app.close();
});
