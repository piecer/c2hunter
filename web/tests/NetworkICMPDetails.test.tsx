import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { expect, it, vi } from 'vitest';
import { evidenceSignature } from '../src/networkEvidenceContext';
import { parseICMPDetails } from '../src/networkICMPDetails';
import { projectNetworkReport } from '../src/networkReportValidation';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach } from 'vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import App from '../src/App';
import userEvent from '@testing-library/user-event';
import NetworkPatternReport from '../src/NetworkPatternReport';
import { ReportLanguageContext } from '../src/reportLanguageContext';

const python = process.env.C2HUNTER_PYTHON ?? resolve('../.venv/bin/python');
const bundle = JSON.parse(execFileSync(python, ['tests/network_icmp_fixture.py'], { encoding: 'utf8', timeout: 60000, maxBuffer: 16 * 1024 * 1024 }));
const report = bundle.case.report;
const legacy = JSON.parse(readFileSync('tests/fixtures/network-icmp-legacy.json', 'utf8'));

const clients: QueryClient[] = [];
afterEach(() => clients.splice(0).forEach(c => c.clear()));
async function openAI() {
  fireEvent.click(await screen.findByRole('button',{name:'Open AI interpretation'}));
  fireEvent.click(await screen.findByRole('button',{name:'View full AI text'}));
}
async function setupApp(maximum = false) {
  const job = structuredClone(bundle.case.job);
  if (maximum) job.network_anomaly = structuredClone(bundle.maximum);
  const run = {id:'icmp-run',analysis_job_id:job.id,dataset_id:job.dataset_id,analysis_kind:'NETWORK_ANOMALY',status:'COMPLETED',network_input:maximum ? bundle.maximum_ai : bundle.case.ai,network_interpretation:{schema_version:'network-interpretation-v1',kind:'MODEL_INTERPRETATION',language:'en',summary:'Synthetic ICMP citation control.',possible_causes:[{hypothesis:'A device reported an error.',issue_ids:['pattern-1'],uncertainty:'Reporter is not a fault location.'}],prioritized_checks:[],correlations:[],limitations:['No model invoked.']}};
  localStorage.setItem('c2hunter-token','icmp-fixture-token'); localStorage.setItem('c2hunter-report-language','en');
  const fetcher = vi.fn(async (input: unknown, init?: RequestInit) => {
    expect(init?.method ?? 'GET').toBe('GET');
    const path = String(input);
    if(path.endsWith('/ai-capabilities')) return Response.json({available:true,network_interpretation:true,remote:false});
    if(path.endsWith('/ai-runs/icmp-run')) return Response.json(run);
    if(path.endsWith(`/${job.id}/ai-runs`)) return Response.json({items:[run]});
    if(path.endsWith(`/analysis-jobs/${job.id}`)) return Response.json(job);
    return Response.json({items:[]});
  });
  vi.stubGlobal('fetch',fetcher);
  const client = new QueryClient({defaultOptions:{queries:{retry:false,staleTime:Infinity}}}); clients.push(client);
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[`/analyses/${job.id}`]}><App/></MemoryRouter></QueryClientProvider>);
  await screen.findByRole('heading',{name:'Anomaly observed'});
  await waitFor(() => expect(client.isFetching()).toBe(0));
  await openAI();
  return {client,job,run,fetcher};
}
it.each(['absent','null','extra','reporter'])('blocks captured/new old-run callbacks across ICMP %s A→B→A and recovers with a fresh run', async fault => {
  const {client,job,run,fetcher} = await setupApp();
  const button = () => screen.getByRole('button',{name:'pattern-1'});
  const captured = Object.values(button()).find(v => v && typeof v === 'object' && 'onClick' in v) as {onClick:()=>void};
  expect(captured.onClick).toBeTypeOf('function');
  fireEvent.click(button());
  expect(screen.getByRole('region',{name:'Representative flow evidence'})).toHaveFocus();
  const changed = structuredClone(job), e = changed.network_anomaly.issues[0].examples[0];
  if(fault === 'absent') delete e.icmp_details;
  if(fault === 'null') e.icmp_details = null;
  if(fault === 'extra') e.icmp_details.extra = null;
  if(fault === 'reporter') e.icmp_details.samples[1].reporter_ip = '192.0.2.99';
  const before = fetcher.mock.calls.length;
  for(const value of [changed,job]) {
    await act(async () => {client.setQueryData(['job',job.id],value); await new Promise(resolve => setTimeout(resolve,0));});
    await openAI();
    act(() => captured.onClick());
    expect(button()).toBeDisabled(); fireEvent.click(button());
    expect(screen.queryByRole('region',{name:'Representative flow evidence'})).toBeNull();
  }
  const fresh = {...run,id:'icmp-fresh',network_interpretation:{...run.network_interpretation,summary:'Fresh ICMP review.'}};
  await act(async () => {client.setQueryData(['ai-run',fresh.id],fresh); client.setQueryData(['ai-runs',job.id],{items:[fresh,run]}); await new Promise(resolve => setTimeout(resolve,0));});
  await screen.findByText('Fresh ICMP review.');
  fireEvent.click(screen.getByRole('button',{name:'View full AI text'}));
  expect(button()).toBeEnabled(); fireEvent.click(button());
  expect(screen.getByRole('region',{name:'Representative flow evidence'})).toHaveFocus();
  fireEvent.click(screen.getByRole('button',{name:'ICMP event details'}));
  expect(fetcher.mock.calls).toHaveLength(before);
  expect(document.querySelectorAll('*').length).toBeLessThanOrEqual(2500);
});
it('keeps unchanged ICMP details actionable after a metadata-only refetch', async () => {
  const {client,job,fetcher} = await setupApp();
  fireEvent.click(screen.getByRole('button',{name:'pattern-1'}));
  const before = fetcher.mock.calls.length;
  await act(async () => {client.setQueryData(['job',job.id],{...structuredClone(job),description:'metadata only'}); await new Promise(resolve => setTimeout(resolve,0));});
  await openAI();
  const button = screen.getByRole('button',{name:'pattern-1'});
  expect(button).toBeEnabled(); fireEvent.click(button);
  expect(screen.getByRole('region',{name:'Representative flow evidence'})).toHaveFocus();
  expect(fetcher.mock.calls).toHaveLength(before);
});
it('supports keyboard disclosure/paging and removes the collapsed event subtree', async () => {
  const user = userEvent.setup();
  render(<ReportLanguageContext value="en"><NetworkPatternReport report={report}/></ReportLanguageContext>);
  const inspect = screen.getByRole('button',{name:/Inspect evidence/}); inspect.focus();
  await user.keyboard('{Enter}');
  const toggle = screen.getByRole('button',{name:'ICMP event details'}); toggle.focus();
  await user.keyboard('{Enter}');
  const next = screen.getByRole('button',{name:'Next event detail'}); next.focus(); await user.keyboard('{Enter}');
  expect(screen.getByText(/Outer reporter: 192\.0\.2\.2/)).toBeVisible();
  toggle.focus(); await user.keyboard('{Enter}');
  expect(toggle).toHaveFocus();
  expect(within(screen.getByRole('region',{name:'ICMP reporter evidence'})).queryByRole('navigation')).toBeNull();
  expect(screen.queryByText(/Outer reporter:/)).toBeNull();
});


it.each(Array.from({length:13},(_,i)=>i))('every retained ICMP detail on maximum report page %s is reachable with bounded DOM', page => {
  const r = bundle.maximum;
  render(<ReportLanguageContext value="en"><NetworkPatternReport report={r}/></ReportLanguageContext>);
  fireEvent.click(screen.getByRole('button',{name:'View all anomaly items'}));
  for(let p=0;p<page;p++) fireEvent.click(screen.getByRole('button',{name:'Next groups'}));
  const articles = screen.getAllByRole('article');
  for(let group=0;group<articles.length;group++) {
    const issue = r.issues[page*8+group];
    expect(articles[group]).toHaveTextContent(issue.id);
    fireEvent.click(within(articles[group]).getByRole('button',{name:/representative evidence/}));
    fireEvent.click(screen.getByRole('button',{name:'ICMP event details'}));
    for(let example=0;example<issue.examples.length;example++) {
      const d = issue.examples[example].icmp_details;
      const region = screen.getByRole('region',{name:'ICMP reporter evidence'});
      expect(region).toHaveTextContent(`${d.omitted_event_details} event details omitted`);
      for(let sample=0;sample<d.samples.length;sample++) {
        expect(region).toHaveTextContent(`Outer reporter: ${d.samples[sample].reporter_ip}`);
        expect(region).toHaveTextContent(`type / code: ${d.samples[sample].type} / ${d.samples[sample].code}`);
        expect(document.querySelectorAll('*').length).toBeLessThan(500);
        if(sample+1<d.samples.length) fireEvent.click(within(region).getByRole('button',{name:'Next event detail'}));
      }
      expect(document.querySelectorAll('*').length).toBeLessThan(500);
      if(example+1<issue.examples.length) fireEvent.click(within(region).getByRole('button',{name:'Next representative'}));
    }
  }
});
it('maximum valid analyzer report stays bounded inside the full App/AI owner', async () => {
  const {fetcher} = await setupApp(true);
  expect(document.querySelectorAll('*').length).toBeLessThanOrEqual(2500);
  const before = fetcher.mock.calls.length;
  fireEvent.click(screen.getByRole('button',{name:'pattern-1'}));
  fireEvent.click(screen.getByRole('button',{name:'ICMP event details'}));
  expect(document.querySelectorAll('*').length).toBeLessThanOrEqual(2500);
  expect(fetcher.mock.calls).toHaveLength(before);
});
it.each(['en','ko'] as const)('malformed present details show local feedback and preserve positives/raw facts (%s)', language => {
  const r = structuredClone(report), before = JSON.stringify(r.issues[0].examples[0].facts);
  r.issues[0].examples[0].icmp_details = null;
  render(<ReportLanguageContext value={language}><NetworkPatternReport report={r}/></ReportLanguageContext>);
  expect(screen.getByRole('heading',{name:language === 'en' ? 'Anomaly observed' : '이상 징후 관찰됨'})).toBeVisible();
  fireEvent.click(screen.getByRole('button',{name:language === 'en' ? /Inspect evidence/ : /근거 확인/}));
  fireEvent.click(screen.getByRole('button',{name:language === 'en' ? 'ICMP event details' : 'ICMP 이벤트 상세'}));
  expect(screen.getByRole('alert')).toHaveTextContent(language === 'en' ? 'Invalid ICMP details' : '잘못된 ICMP 상세');
  expect(JSON.stringify(r.issues[0].examples[0].facts)).toBe(before);
});

it('accepts actual worker/public GET reporter detail bytes through the existing projection', () => {
  const p = projectNetworkReport(report);
  expect(p.slots[0].issue?.examples[0]).toHaveProperty('icmpDetails.state', 'valid');
  expect(bundle.case.job.network_anomaly).toEqual(report);
});
it.each(['en', 'ko'] as const)('lazily displays distinct reporters and directional quote (%s)', language => {
  render(<ReportLanguageContext value={language}><NetworkPatternReport report={report}/></ReportLanguageContext>);
  expect(screen.queryByText(/192\.0\.2\.2/)).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: language === 'en' ? /Inspect evidence/ : /근거 확인/ }));
  fireEvent.click(screen.getByRole('button', { name: language === 'en' ? 'ICMP event details' : 'ICMP 이벤트 상세' }));
  expect(screen.getByText(/192\.0\.2\.1/)).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: language === 'en' ? 'Next event detail' : '다음 이벤트 상세' }));
  expect(screen.getByText(/192\.0\.2\.2/)).toBeVisible();
  expect(screen.getByText(/10\.0\.0\.1:50000 → 203\.0\.113\.1:443/)).toBeVisible();
});
it('retains genuine legacy absence as unknown without mutating saved facts', () => {
  const before = JSON.stringify(legacy);
  expect(projectNetworkReport(legacy).slots[0].issue?.examples[0]).toHaveProperty('icmpDetails.state', 'absent');
  expect(JSON.stringify(legacy)).toBe(before);
});

it.each(bundle.numeric_wires as {name:string; wire:string; python:boolean; expected:boolean; syntax_error?:boolean}[])('same exact wire numeric spelling parity $name', c => {
  if (c.syntax_error) {
    // JSON syntax refusal is routed nonacceptance, not a parser-validator PASS.
    expect(() => JSON.parse(c.wire)).toThrow(SyntaxError);
    expect(c.python).toBe(false);
    expect(c.expected).toBe(false);
    return;
  }
  const e = JSON.parse(c.wire), r = structuredClone(report);
  r.issues[0].examples[0] = e;
  const before = structuredClone(r);
  const direct = parseICMPDetails(e, e.event_count, 'icmp_errors').state;
  const slot = projectNetworkReport(r).slots[0];
  const projected = slot.issue?.examples[0]?.icmpDetails?.state;
  if (c.name.startsWith('event_count-') && !c.expected) {
    expect(slot.examplesInvalid).toBe(true);
    expect(slot.issue?.examples).toHaveLength(0);
  }
  expect(direct === 'valid').toBe(c.python);
  expect(c.python).toBe(c.expected);
  expect(projected === 'valid').toBe(c.expected);
  expect(r).toEqual(before);
});

it.each(['code','type','omission','event_count','source_port','destination_port'])('rejects direct nonfinite/custom numbers without callbacks: %s', field => {
  const hook = vi.fn(() => { throw new Error('numeric hook'); });
  for (const value of [NaN, Infinity, -Infinity, {valueOf:hook, toString:hook}]) {
    const r = structuredClone(report), e = r.issues[0].examples[0];
    if (field === 'event_count') e.event_count = value;
    else if (field === 'omission') e.icmp_details.omitted_event_details = value;
    else if (field === 'code' || field === 'type') e.icmp_details.samples[0][field] = value;
    else e.icmp_details.samples[0].quoted_flow[field] = value;
    expect(parseICMPDetails(e, e.event_count, 'icmp_errors').state).toBe('invalid');
    const slot = projectNetworkReport(r).slots[0];
    expect(slot.issue?.examples[0]?.icmpDetails?.state).not.toBe('valid');
    if (field === 'event_count') {
      expect(slot.examplesInvalid).toBe(true);
      expect(slot.issue?.examples).toHaveLength(0);
    }
    expect(hook).not.toHaveBeenCalled();
  }
});

it.each(bundle.mutations as {name:string; example:object; accepted:boolean}[])('matches Python validator on identical serialized mutation bytes: $name', value => {
  expect(parseICMPDetails(value.example, 2, 'icmp_errors').state === 'valid').toBe(value.accepted);
});

it.each(['root-getter','hidden','inherited','sample-getter','array-hole','array-getter','symbol','toJSON','huge-array'])('rejects hooks and lossy-copy bypasses without invoking them: %s', fault => {
  const r = structuredClone(report), e = r.issues[0].examples[0], d = e.icmp_details;
  const hook = vi.fn(() => {throw new Error('hook');});
  if (fault === 'root-getter') Object.defineProperty(e,'icmp_details',{get:hook,enumerable:true});
  if (fault === 'hidden') Object.defineProperty(e,'icmp_details',{value:d,enumerable:false});
  if (fault === 'inherited') {delete e.icmp_details; Object.setPrototypeOf(e,{icmp_details:d});}
  if (fault === 'sample-getter') Object.defineProperty(d.samples[0],'code',{get:hook,enumerable:true});
  if (fault === 'array-hole') delete d.samples[0];
  if (fault === 'array-getter') Object.defineProperty(d.samples,'0',{get:hook,enumerable:true});
  if (fault === 'symbol') d[Symbol('extra')] = null;
  if (fault === 'toJSON') Object.defineProperty(d,'toJSON',{get:hook});
  if (fault === 'huge-array') {d.samples.length = 1000000; Object.defineProperty(d.samples,'0',{get:hook,enumerable:true});}
  const p = projectNetworkReport(r);
  expect(p.slots[0].issue?.examples[0].icmpDetails).toEqual({state:'invalid'});
  evidenceSignature(p);
  expect(hook).not.toHaveBeenCalled();
});

it('binds absent, invalid and actual valid detail semantics in evidence identity', () => {
  const invalid = structuredClone(report); invalid.issues[0].examples[0].icmp_details = null;
  const changed = structuredClone(report); changed.issues[0].examples[0].icmp_details.samples[1].reporter_ip = '192.0.2.99';
  expect(new Set([legacy,invalid,report,changed].map(r => evidenceSignature(projectNetworkReport(r)))).size).toBe(4);
});

it('rejects aggregate metadata above the publication budget instead of trusting every small item', () => {
  const r = structuredClone(bundle.maximum);
  for (const i of r.issues) for (const e of i.examples) {
    e.icmp_details.samples = Array.from({length:4},() => structuredClone(report.issues[0].examples[0].icmp_details.samples[0]));
    e.icmp_details.omitted_event_details = 0;
  }
  const p = projectNetworkReport(r);
  expect(p.slots.every(s => s.issue?.examples.every(e => e.icmpDetails?.state === 'invalid'))).toBe(true);
  expect(p.slots.every(s => s.issue && !s.invalid)).toBe(true);
});

it('accepts checksum-valid IPv6 worker/public evidence without pretending IPv4', () => {
  const r = bundle.ipv6.report;
  const result = projectNetworkReport(r).slots[0].issue?.examples[0].icmpDetails;
  expect(result?.state).toBe('valid');
  if (result?.state !== 'valid') throw new Error('missing IPv6');
  expect(result.value.samples.map(s => [s.protocol,s.reporter_ip,s.code])).toEqual([['ICMPV6','2001:db8:1::1',0],['ICMPV6','2001:db8:1::2',4]]);
});

it('keeps actual 100x10 production-bounded details valid and the mounted report below 500', () => {
  const r = bundle.maximum;
  expect(r.issues).toHaveLength(100);
  expect(r.issues.every((i: {examples:unknown[]}) => i.examples.length === 10)).toBe(true);
  expect(projectNetworkReport(r).slots.every(s => s.issue?.examples.every(e => e.icmpDetails?.state === 'valid'))).toBe(true);
  render(<ReportLanguageContext value="en"><NetworkPatternReport report={r}/></ReportLanguageContext>);
  const bound = () => expect(document.querySelectorAll('*').length).toBeLessThan(500);
  bound();
  fireEvent.click(screen.getAllByRole('button',{name:/Inspect evidence/})[0]);
  fireEvent.click(screen.getByRole('button',{name:'ICMP event details'}));
  bound();
  for (let index=0; index<10; index++) {
    const samples = r.issues[0].examples[index].icmp_details.samples;
    for (let event=0; event<samples.length; event++) {
      expect(screen.getByText(new RegExp(`Outer reporter: ${samples[event].reporter_ip.replaceAll('.','\\.')}`))).toBeVisible();
      bound();
      if (event+1<samples.length) fireEvent.click(screen.getByRole('button',{name:'Next event detail'}));
    }
    if(index<9) fireEvent.click(screen.getByRole('button',{name:'Next representative'}));
  }
});
