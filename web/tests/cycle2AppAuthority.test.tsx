import { QueryClient,QueryClientProvider } from '@tanstack/react-query';
import { act,fireEvent,render,screen,waitFor } from '@testing-library/react';
import { MemoryRouter, useNavigate } from 'react-router-dom';
import { beforeEach,expect,it,vi } from 'vitest';
import App from '../src/App';
import { api } from '../src/api';
import { producer } from './jobInvestigationFixtures';
beforeEach(()=>{sessionStorage.clear();localStorage.setItem('c2hunter-token','principal-A');vi.stubGlobal('matchMedia',()=>({matches:false}));});
function setupGet(){vi.spyOn(api,'get').mockImplementation(async(path:string)=>path==='/analysis-jobs/job'?{id:'job',name:'Saved job',status:'COMPLETED',analysis:{module:'c2'}}:path==='/analysis-jobs/B'?{id:'B',name:'Other job',status:'COMPLETED',analysis:{module:'c2'}}:path==='/ai-capabilities'?{available:false}:{items:[]});}
function Nav(){const nav=useNavigate();return <><button onClick={()=>nav('/analyses/job')}>test route A</button><button onClick={()=>nav('/analyses/B')}>test route B</button></>;}
function mount(path='/analyses/job'){const client=new QueryClient({defaultOptions:{queries:{retry:false,staleTime:Infinity}}});const view=render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><Nav/><App/></MemoryRouter></QueryClientProvider>);return {view,client,close(){view.unmount();client.clear();}};}
it('cross-tab authentication transition retires pending UI and cached source immediately, A may recover after reload',async()=>{
 setupGet();let release!:(r:Response)=>void;let oldSignal:AbortSignal|undefined;
 const fetcher=vi.fn((path:string,init?:RequestInit)=>{
  if(init?.method==='POST'){oldSignal=init.signal as AbortSignal;return new Promise<Response>(r=>{release=r;});}
  return Promise.resolve(new Response(path.endsWith('/capabilities')?producer.fixtures.capabilities:'{"items":[],"next_cursor":null}'));
 });vi.stubGlobal('fetch',fetcher);
 const app=mount();fireEvent.click(await screen.findByRole('button',{name:/Open experimental investigation/}));
 await waitFor(()=>expect(screen.getByRole('button',{name:/Start experimental investigation/})).toBeEnabled());
 fireEvent.change(screen.getByRole('textbox',{name:/Question/}),{target:{value:'A private pending question'}});
 fireEvent.click(screen.getByRole('button',{name:/Start experimental investigation/}));await waitFor(()=>expect(release).toBeTypeOf('function'));
 const receipt=sessionStorage.getItem('c2hunter-job-investigation-pending-v1');
 act(()=>{localStorage.setItem('c2hunter-token','principal-B');window.dispatchEvent(new StorageEvent('storage',{key:'c2hunter-token',oldValue:'principal-A',newValue:'principal-B',storageArea:localStorage}));});
 expect(oldSignal?.aborted).toBe(true);expect(document.body.textContent).not.toContain('A private pending question');
 await act(async()=>{release(new Response(producer.fixtures.run_queued));});
 expect(sessionStorage.getItem('c2hunter-job-investigation-pending-v1')).toBe(receipt);
 expect(screen.queryByRole('region',{name:'Saved job investigation'})).toBeNull();
 expect(fetcher.mock.calls.filter(c=>c[1]?.method==='POST')).toHaveLength(1);app.close();
});
