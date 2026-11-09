import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import JobInvestigationPanel, { JobInvestigationEntry } from '../src/JobInvestigationPanel';
import { jobApi } from '../src/jobInvestigationApi';
import { parseJobWire } from '../src/jobInvestigationContract';
import { producer } from './jobInvestigationFixtures';
const run=()=>parseJobWire('run',producer.fixtures.run_completed);
beforeEach(()=>{sessionStorage.clear();vi.spyOn(jobApi,'capabilities').mockResolvedValue(parseJobWire('capabilities',producer.fixtures.capabilities));vi.spyOn(jobApi,'history').mockResolvedValue({items:[run()],next_cursor:null});});
it('real entry is opt-in, no POST on open, history readable separately from capability', async()=>{
  const create=vi.spyOn(jobApi,'create');render(<JobInvestigationEntry jobId="job"/>);
  expect(jobApi.history).not.toHaveBeenCalled();fireEvent.click(screen.getByRole('button',{name:/Open experimental/}));
  await screen.findByRole('button',{name:/View saved run/});expect(create).not.toHaveBeenCalled();
  expect(screen.getByText(/expected_source_sha256=null/)).toBeInTheDocument();
  expect(screen.getByText(/CONFIGURED_NOT_PROBED/)).toBeInTheDocument();
});
it('failed POST retains exact body/key/null for explicit retry; no duplicate on edit', async()=>{
  const create=vi.spyOn(jobApi,'create').mockRejectedValue(new Error('Unconfirmed'));
  render(<JobInvestigationPanel jobId="job"/>);await screen.findByRole('button',{name:/View saved run/});
  fireEvent.click(screen.getByRole('button',{name:/Start experimental/}));await screen.findByRole('button',{name:/Retry exact/});
  expect(create).toHaveBeenCalledTimes(1);const body=create.mock.calls[0][1];expect(JSON.parse(body).expected_source_sha256).toBeNull();
  expect(screen.getByRole('textbox',{name:/Question/})).toBeDisabled();
  fireEvent.click(screen.getByRole('button',{name:/Retry exact/}));await waitFor(()=>expect(create).toHaveBeenCalledTimes(2));expect(create.mock.calls[1][1]).toBe(body);
});
it('saved report separates facts/hypothesis, preserves full IPv6 and lazy single evidence', async()=>{
  vi.spyOn(jobApi,'evidence').mockResolvedValue(parseJobWire('evidence',producer.fixtures.evidence_protocol));
  render(<JobInvestigationPanel jobId="job"/>);fireEvent.click(await screen.findByRole('button',{name:/View saved run/}));
  expect(screen.getByText(/whole-job conclusion: NOT_ESTABLISHED/)).toBeInTheDocument();
  expect(screen.getByText('2001:db8::1')).toBeInTheDocument();expect(screen.queryByRole('region',{name:/Evidence details/})).not.toBeInTheDocument();
  const peer=run().selection.peer_ids[0];fireEvent.click(screen.getByRole('button',{name:`Peer details ${peer}`}));
  expect(screen.getByRole('heading',{name:/Observed facts/})).toBeInTheDocument();expect(screen.getByRole('heading',{name:/Model hypotheses/})).toBeInTheDocument();
  const id=parseJobWire('evidence',producer.fixtures.evidence_protocol).evidence_id;
  fireEvent.click(screen.getByRole('button',{name:`Evidence ${id}`}));await screen.findByRole('region',{name:/Evidence details/});
  fireEvent.click(screen.getByRole('button',{name:/Close evidence/}));expect(screen.queryByRole('region',{name:/Evidence details/})).not.toBeInTheDocument();
});
it('job changes retire late history; A→B→A has no inherited expanded detail', async()=>{
  let release!:(v:Awaited<ReturnType<typeof jobApi.history>>)=>void;
  vi.mocked(jobApi.history).mockImplementationOnce(()=>new Promise(r=>{release=r;}));
  const view=render(<JobInvestigationPanel jobId="job"/>);view.rerender(<JobInvestigationPanel jobId="B"/>);
  release({items:[run()],next_cursor:null});view.rerender(<JobInvestigationPanel jobId="job"/>);
  await screen.findByRole('button',{name:/View saved run/});expect(screen.queryByRole('heading',{name:/Observed facts/})).not.toBeInTheDocument();
});

it('all 32 retained peers are reachable eight at a time with bounded DOM and escaped prose',async()=>{
  const max=parseJobWire('run',producer.additional.run_max_completed);
  vi.mocked(jobApi.history).mockResolvedValue({items:[max],next_cursor:null});
  render(<JobInvestigationPanel jobId="job"/>);fireEvent.click(await screen.findByRole('button',{name:/View saved run/}));
  const seen=new Set<string>();let peak=0;
  for(let page=0;page<4;page++){
    const buttons=screen.getAllByRole('button',{name:/^Peer details /});expect(buttons).toHaveLength(8);
    for(const button of buttons){seen.add(button.getAttribute('aria-label')!);fireEvent.click(button);expect(screen.getAllByRole('region',{name:'Peer assessment detail'})).toHaveLength(1);peak=Math.max(peak,document.querySelectorAll('*').length);}
    if(page<3)fireEvent.click(screen.getByRole('button',{name:/Next peers/}));
  }
  expect(seen.size).toBe(32);expect(peak).toBeLessThan(700);
  expect(document.querySelector('img')).toBeNull();expect(document.querySelector('a[href^="javascript:"]')).toBeNull();
  console.log(JSON.stringify({retained_peers_reached:seen.size,peak_mounted_elements:peak,geometry:'NOT_BROWSER_TESTED'}));
});
it('unavailable capability and missing native crypto do not hide saved history',async()=>{
  vi.mocked(jobApi.capabilities).mockRejectedValue(new Error('Unavailable'));vi.stubGlobal('crypto',undefined);
  render(<JobInvestigationPanel jobId="job"/>);fireEvent.click(await screen.findByRole('button',{name:/View saved run/}));
  expect(screen.getByRole('button',{name:/Start experimental/})).toBeDisabled();expect(screen.getByRole('region',{name:'Saved job investigation'})).toBeInTheDocument();
});
it('late evidence on cached A→B→A does not reopen the old detail',async()=>{
  let release!:(v:EvidenceResult)=>void;
  type EvidenceResult=Awaited<ReturnType<typeof jobApi.evidence>>;
  vi.spyOn(jobApi,'evidence').mockImplementation(()=>new Promise(r=>{release=r;}));
  const view=render(<JobInvestigationPanel jobId="job"/>);fireEvent.click(await screen.findByRole('button',{name:/View saved run/}));
  fireEvent.click(screen.getByRole('button',{name:`Peer details ${run().selection.peer_ids[0]}`}));
  const e=parseJobWire('evidence',producer.fixtures.evidence_protocol);fireEvent.click(screen.getByRole('button',{name:`Evidence ${e.evidence_id}`}));
  view.rerender(<JobInvestigationPanel jobId="B"/>);view.rerender(<JobInvestigationPanel jobId="job"/>);
  await act(async()=>{release(e);});fireEvent.click(await screen.findByRole('button',{name:/View saved run/}));
  expect(screen.queryByRole('region',{name:'Peer assessment detail'})).not.toBeInTheDocument();expect(screen.queryByRole('region',{name:/Evidence details/})).not.toBeInTheDocument();
});
it('late POST after navigation preserves an exact retry receipt without publishing stale run',async()=>{
  let reject!:(e:Error)=>void;const create=vi.spyOn(jobApi,'create').mockImplementation(()=>new Promise((_,r)=>{reject=r;}));
  const view=render(<JobInvestigationPanel jobId="job"/>);await screen.findByRole('button',{name:/View saved run/});fireEvent.click(screen.getByRole('button',{name:/Start experimental/}));
  const body=create.mock.calls[0][1];view.rerender(<JobInvestigationPanel jobId="B"/>);view.rerender(<JobInvestigationPanel jobId="job"/>);
  await act(async()=>{reject(new Error('late'));});expect(screen.queryByRole('region',{name:'Saved job investigation'})).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button',{name:/Retry exact/}));expect(create.mock.calls[1][1]).toBe(body);
});
it('cancelling a viewed unrelated run cannot clear or rebind unresolved admission',async()=>{
  const queued=parseJobWire('run',producer.fixtures.run_queued);
  vi.mocked(jobApi.history).mockResolvedValue({items:[queued],next_cursor:null});vi.spyOn(jobApi,'create').mockRejectedValue(new Error('unconfirmed'));
  const cancel=vi.spyOn(jobApi,'cancel').mockRejectedValue(new Error('cancel unconfirmed'));
  render(<JobInvestigationPanel jobId="job"/>);await screen.findByRole('button',{name:/View saved run/});fireEvent.click(screen.getByRole('button',{name:/Start experimental/}));await screen.findByRole('alert');
  const pending=sessionStorage.getItem('c2hunter-job-investigation-pending-v1');fireEvent.click(screen.getByRole('button',{name:/View saved run/}));fireEvent.click(screen.getByRole('button',{name:/Request cancellation/}));
  await waitFor(()=>expect(cancel).toHaveBeenCalledTimes(1));expect(cancel.mock.calls[0][1].id).toBe(queued.id);expect(sessionStorage.getItem('c2hunter-job-investigation-pending-v1')).toBe(pending);
});
it('late poll and cancel callbacks after job replacement cannot publish or cancel a successor',async()=>{
  vi.useFakeTimers();
  try {
    const queued=parseJobWire('run',producer.fixtures.run_queued);vi.mocked(jobApi.history).mockResolvedValue({items:[queued],next_cursor:null});
    let pollRelease!:(v:ReturnType<typeof run>)=>void,cancelReject!:(e:Error)=>void;
    const poll=vi.spyOn(jobApi,'run').mockImplementation(()=>new Promise(r=>{pollRelease=r;}));
    const cancel=vi.spyOn(jobApi,'cancel').mockImplementation(()=>new Promise((_,r)=>{cancelReject=r;}));
    const view=render(<JobInvestigationPanel jobId="job"/>);await act(async()=>{});fireEvent.click(screen.getByRole('button',{name:/View saved run/}));
    await act(async()=>{await vi.advanceTimersByTimeAsync(2001);});expect(poll).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole('button',{name:/Request cancellation/}));view.rerender(<JobInvestigationPanel jobId="B"/>);view.rerender(<JobInvestigationPanel jobId="job"/>);
    await act(async()=>{pollRelease(run());cancelReject(new Error('late cancel'));});
    expect(screen.queryByRole('region',{name:'Saved job investigation'})).not.toBeInTheDocument();expect(cancel).toHaveBeenCalledTimes(1);
  } finally {vi.useRealTimers();}
});

it('blocked session storage access disables admission without crashing historical reads',async()=>{
  vi.spyOn(window,'sessionStorage','get').mockImplementation(()=>{throw new Error('storage denied');});
  render(<JobInvestigationPanel jobId="job"/>);await screen.findByRole('button',{name:/View saved run/});
  expect(screen.getByRole('button',{name:/Start experimental/})).toBeDisabled();expect(screen.getByRole('alert')).toHaveTextContent('unreadable');
});
