import { test, expect, type Page, type Locator } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { readFileSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';

type Job = { id: string; dataset_id: string; name: string };
type Body = { analysis_module: string; idempotency_key: string; ddos_normal_reference?: { job_id: string; dataset_id: string } | null; analysis: Record<string, unknown>; [key: string]: unknown };
const root = process.env.C2HUNTER_DDOS_FIXTURE ?? mkdtempSync(join(tmpdir(), 'pcap-owner-'));
if (!process.env.C2HUNTER_DDOS_FIXTURE) execFileSync(process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python'), ['tests/ddos_stage3_fixture.py', root]);
const fixture = JSON.parse(readFileSync(join(root, 'browser-fixture.json'), 'utf8'));
const A: Job = fixture.jobs.measured, N: Job = fixture.jobs.normal, N2: Job = fixture.jobs.unmeasured;
async function install(page: Page) {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => { localStorage.setItem('c2hunter-token', 'owned-browser-fixture'); localStorage.setItem('c2hunter-report-language', 'en'); });
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname.replace('/api/v1', '');
    let body: unknown = { items: [] };
    if (path === '/analysis-jobs') body = { items: [N, N2], page: 1, page_size: 20, total: 2 };
    else if (/^\/analysis-jobs\/[^/]+$/.test(path)) body = { ...A, id: path.split('/').at(-1), name: 'Accepted result' };
    else if (path === '/ai-capabilities') body = { available: false, ddos_interpretation: false };
    await route.fulfill({ json: body });
  });
  return { errors };
}
async function form(page: Page, route = '/analyses/upload', module = 'ddos_attack') {
  await page.goto(route);
  await page.getByLabel('Analysis name').fill('Owned independent request');
  await page.getByLabel('Analysis module').selectOption(module);
  await page.getByLabel('Capture file').setInputFiles(join(root, 'unmeasured.pcap'));
  return page.getByLabel('Analysis name').locator('xpath=ancestor::form');
}
const submit = (f: Locator) => f.evaluate((element: HTMLFormElement) => element.requestSubmit());
async function normal(page: Page, index = 0) {
  await page.getByLabel('Normal reference action').selectOption('select');
  await page.getByRole('radio').nth(index).check();
}

// Original independent B1 assertions, retained without expected-failure markers.
for(const module of ['ddos_attack','c2','network_anomaly'])test(`after failed capture new module intent requires matching admission ${module}`,async({page},info)=>{
 const obs=await install(page);const f=await form(page,'/analyses/upload');await page.getByLabel('Normal reference action').selectOption('select');await page.getByRole('radio').first().check();
 const initiated:Body[]=[],puts:string[]=[];let fail=true;
 await page.route('**/api/v1/pcap-analysis-jobs/initiate',async r=>{initiated.push(r.request().postDataJSON());await r.fulfill({status:201,json:{id:initiated.length===1?'created-ddos':'created-current'}});});
 await page.route('**/api/v1/pcap-analysis-jobs/*/capture',async r=>{puts.push(new URL(r.request().url()).pathname);await r.fulfill(fail?{status:500,json:{error:{code:'EXPECTED_UPLOAD_FAILURE',message:'Owned capture interruption'}}}:{status:202,json:{id:puts.at(-1)!.split('/').at(-2)}});});
 await f.evaluate((e:HTMLFormElement)=>e.requestSubmit());await expect(page.getByText('Owned capture interruption')).toBeVisible();expect(initiated).toHaveLength(1);expect(initiated[0].ddos_normal_reference).toEqual({job_id:N.id,dataset_id:N.dataset_id});
 if(module==='ddos_attack')await page.getByLabel('Normal reference action').selectOption('clear');else await page.getByLabel('Analysis module').selectOption(module);
 fail=false;await page.screenshot({path:info.outputPath('before-new-intent.png'),fullPage:true});await f.evaluate((e:HTMLFormElement)=>e.requestSubmit());await expect(page).toHaveURL(/\/analyses\/created-/);
 const observed={intendedModule:module,initiated,puts,url:page.url(),errors:obs.errors};writeFileSync(info.outputPath('admission-observed.json'),JSON.stringify(observed,null,2));await info.attach('admission-observed',{body:JSON.stringify(observed),contentType:'application/json'});await page.screenshot({path:info.outputPath('after-new-intent.png'),fullPage:true});
 expect(initiated,'changed module/reference must acquire a new matching job, not reuse the DDoS reference-bearing job').toHaveLength(2);expect(initiated[1].analysis_module).toBe(module);expect(initiated[1].ddos_normal_reference).toBe(module==='ddos_attack'?null:undefined);expect(puts.at(-1)).toContain('created-current');expect(obs.errors).toEqual([]);
});

async function transport(page: Page) {
  const initiated: Body[] = [], puts: string[] = [];
  const control = { failAdmission: false, failCapture: true };
  await page.route('**/api/v1/pcap-analysis-jobs/initiate', async route => {
    initiated.push(route.request().postDataJSON());
    await route.fulfill(control.failAdmission ? { status: 503, json: { error: { message: 'Owned initiation failure' } } } : { status: 201, json: { id: `job-${initiated.length}` } });
  });
  await page.route('**/api/v1/pcap-analysis-jobs/*/capture', async route => {
    puts.push(new URL(route.request().url()).pathname);
    await route.fulfill(control.failCapture ? { status: 500, json: { error: { message: 'Owned capture interruption' } } } : { status: 202, json: { id: puts.at(-1)!.split('/').at(-2) } });
  });
  return { initiated, puts, control };
}

for (const module of ['ddos_attack', 'c2', 'network_anomaly']) for (const explicit of [false, true]) test(`same ${module} intent retries exact owner via ${explicit ? 'explicit' : 'ordinary'} control`, async ({ page }, info) => {
  const obs = await install(page), f = await form(page, '/analyses/upload', module), wire = await transport(page);
  if (module === 'ddos_attack') await normal(page);
  await submit(f); await expect(page.getByText('Owned capture interruption')).toBeVisible();
  const key = wire.initiated[0].idempotency_key;
  wire.control.failCapture = false;
  if (explicit) await page.getByRole('button', { name: '기존 작업으로 업로드 재시도' }).click(); else await submit(f);
  await expect(page).toHaveURL(/\/analyses\/job-1$/);
  expect(wire.initiated).toHaveLength(1); expect(wire.initiated[0].idempotency_key).toBe(key);
  expect(wire.puts).toEqual(['/api/v1/pcap-analysis-jobs/job-1/capture', '/api/v1/pcap-analysis-jobs/job-1/capture']);
  expect(obs.errors).toEqual([]);
  writeFileSync(info.outputPath('same-intent-observed.json'), JSON.stringify({ intendedModule: module, ...wire, errors: obs.errors }, null, 2));
});

for (const [from, to] of [['c2', 'ddos_attack'], ['network_anomaly', 'ddos_attack'], ['c2', 'network_anomaly'], ['network_anomaly', 'c2']]) test(`admitted ${from} cannot become ${to}`, async ({ page }) => {
  await install(page); const f = await form(page, '/analyses/upload', from), wire = await transport(page);
  await submit(f); await expect(page.getByText('Owned capture interruption')).toBeVisible();
  await page.getByLabel('Analysis module').selectOption(to);
  wire.control.failCapture = false; await submit(f); await expect(page).toHaveURL(/\/analyses\/job-2$/);
  expect(wire.initiated).toHaveLength(2); expect(wire.initiated[1].analysis_module).toBe(to);
  expect(wire.initiated[1].analysis.module).toBe(to);
  if (to !== 'ddos_attack') expect(wire.initiated[1]).not.toHaveProperty('ddos_normal_reference');
  expect(wire.puts.at(-1)).toContain('/job-2/');
});

test('a different explicit normal source requires a new admission', async ({ page }) => {
  await install(page); const f = await form(page), wire = await transport(page); await normal(page);
  await submit(f); await expect(page.getByText('Owned capture interruption')).toBeVisible();
  await normal(page, 1); wire.control.failCapture = false;
  await submit(f); await expect(page).toHaveURL(/\/analyses\/job-2$/);
  expect(wire.initiated).toHaveLength(2);
  expect(wire.initiated[1].ddos_normal_reference).toEqual({ job_id: N2.id, dataset_id: N2.dataset_id });
  expect(wire.initiated[1].idempotency_key).not.toBe(wire.initiated[0].idempotency_key);
});

for (const change of ['different-file', 'same-metadata-file', 'networks', 'threshold', 'weights', 'preset-button']) test(`wire ownership follows ${change}, not only module or filename`, async ({ page }) => {
  await install(page); const f = await form(page, '/analyses/upload', 'c2'), wire = await transport(page);
  await submit(f); await expect(page.getByText('Owned capture interruption')).toBeVisible();
  if (change.endsWith('file')) await page.getByLabel('Capture file').setInputFiles({ name: change === 'different-file' ? 'other.pcap' : 'unmeasured.pcap', mimeType: 'application/vnd.tcpdump.pcap', buffer: readFileSync(join(root, 'unmeasured.pcap')) });
  else if (change === 'networks') await page.getByLabel('Internal networks').fill('192.0.2.0/24');
  else if (change === 'threshold') await page.getByLabel('Minimum score').fill('12');
  else if (change === 'weights') await page.getByRole('spinbutton', { name: / 가중치$/ }).first().fill('0.25');
  else await page.getByRole('button', { name: '대형 서비스 노이즈 줄이기' }).click();
  wire.control.failCapture = false; await submit(f); await expect(page).toHaveURL(/\/analyses\/job-2$/);
  expect(wire.initiated).toHaveLength(2); expect(wire.puts.at(-1)).toContain('/job-2/');
  const [a, b] = wire.initiated;
  expect(b.idempotency_key).not.toBe(a.idempotency_key);
  if (!change.endsWith('file')) expect(b).not.toEqual({ ...a, idempotency_key: b.idempotency_key });
});

for (const module of ['ddos_attack', 'c2', 'network_anomaly']) test(`A capture fails, B initiation fails, ${module} B retry cannot PUT A`, async ({ page }) => {
  await install(page); const f = await form(page, '/analyses/upload', module), wire = await transport(page);
  await submit(f); await expect(page.getByText('Owned capture interruption')).toBeVisible();
  await page.getByLabel('Internal networks').fill('192.0.2.0/24'); wire.control.failAdmission = true;
  await submit(f); await expect(page.getByText('Owned initiation failure')).toBeVisible();
  expect(wire.puts).toHaveLength(1);
  wire.control.failAdmission = false; wire.control.failCapture = false;
  await submit(f); await expect(page).toHaveURL(/\/analyses\/job-3$/);
  expect(wire.initiated).toHaveLength(3); expect(wire.initiated[2]).toEqual(wire.initiated[1]);
  expect(wire.puts.at(-1)).toContain('/job-3/');
});

for (const change of ['module', 'file', 'form', 'weights', 'unmount']) test(`captured real React retry is inert after ${change}`, async ({ page }) => {
  await install(page); const f = await form(page, '/analyses/upload', 'c2'), wire = await transport(page);
  await submit(f); await expect(page.getByText('Owned capture interruption')).toBeVisible();
  await page.getByRole('button', { name: '기존 작업으로 업로드 재시도' }).evaluate(element => {
    const key = Object.keys(element).find(k => k.startsWith('__reactProps$'))!;
    (window as unknown as { oldRetry: () => void }).oldRetry = (element as unknown as Record<string, { onClick: () => void }>)[key].onClick;
  });
  if (change === 'module') { await page.getByLabel('Analysis module').selectOption('network_anomaly'); await page.getByLabel('Analysis module').selectOption('c2'); }
  else if (change === 'file') await page.getByLabel('Capture file').setInputFiles({ name: 'unmeasured.pcap', mimeType: 'application/vnd.tcpdump.pcap', buffer: readFileSync(join(root, 'unmeasured.pcap')) });
  else if (change === 'form') await page.getByLabel('Analysis name').fill('New intent');
  else if (change === 'weights') await page.getByRole('button', { name: '대형 서비스 노이즈 줄이기' }).click();
  else {
    await page.getByRole('link', { name: 'View analysis history' }).click();
    await expect(page.getByRole('heading', { name: 'Analysis history' })).toBeVisible();
    await expect(f).toHaveCount(0);
  }
  await page.evaluate(() => { (window as unknown as { oldRetry: () => void }).oldRetry(); });
  // A round trip through this page's event loop, not a time-based race assertion.
  await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
  expect(wire.initiated).toHaveLength(1); expect(wire.puts).toHaveLength(1);
  expect(new URL(page.url()).pathname).toBe(change === 'unmount' ? '/analyses' : '/analyses/upload');
});

for (const phase of ['initiation', 'upload']) test(`pending ${phase} cannot publish or unlock B after A -> B -> A and file reset`, async ({ page }) => {
  await install(page); const f = await form(page, '/analyses/upload', 'c2');
  let releaseA!: () => void, releaseB!: () => void;
  const gateA = new Promise<void>(resolve => { releaseA = resolve; }), gateB = new Promise<void>(resolve => { releaseB = resolve; });
  const bodies: Body[] = [], puts: string[] = [];
  await page.route('**/api/v1/pcap-analysis-jobs/initiate', async route => {
    bodies.push(route.request().postDataJSON()); const index = bodies.length;
    if (phase === 'initiation') await (index === 1 ? gateA : gateB);
    await route.fulfill({ status: 201, json: { id: `job-${index}` } });
  });
  await page.route('**/api/v1/pcap-analysis-jobs/*/capture', async route => {
    const path = new URL(route.request().url()).pathname; puts.push(path);
    if (phase === 'upload') await (path.includes('/job-1/') ? gateA : gateB);
    await route.fulfill({ status: 202, json: { id: path.split('/').at(-2) } });
  });
  await submit(f); await expect.poll(() => phase === 'initiation' ? bodies.length : puts.length).toBe(1);
  await page.getByLabel('Analysis module').selectOption('network_anomaly'); await page.getByLabel('Analysis module').selectOption('c2');
  await page.getByLabel('Capture file').setInputFiles({ name: 'unmeasured.pcap', mimeType: 'application/vnd.tcpdump.pcap', buffer: readFileSync(join(root, 'unmeasured.pcap')) });
  await submit(f); await expect.poll(() => phase === 'initiation' ? bodies.length : puts.length).toBe(2);
  const responseA = page.waitForResponse(response => response.url().includes(phase === 'initiation' ? '/initiate' : '/job-1/capture'));
  releaseA(); await responseA;
  await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
  await expect(page.getByRole('button', { name: 'Uploading and analyzing…' })).toBeDisabled();
  expect(new URL(page.url()).pathname).toBe('/analyses/upload');
  await submit(f); expect(bodies).toHaveLength(2); expect(puts).toHaveLength(phase === 'initiation' ? 0 : 2);
  releaseB(); await expect(page).toHaveURL(/\/analyses\/job-2$/);
  expect(bodies[1].idempotency_key).not.toBe(bodies[0].idempotency_key);
});

for (const phase of ['initiation', 'upload']) test(`unnamed preset default/explicit mode retires pending ${phase}`, async ({ page }) => {
  await install(page);
  await page.route('**/api/v1/detector-weight-presets', route => route.fulfill({ json: { items: [{ id: 'default', name: 'Default preset', is_default: true, detector_weights: { periodic_beacon: 0.5 } }] } }));
  const f = await form(page, '/analyses/upload', 'c2');
  await expect(page.getByLabel('저장된 탐지 가중치 프리셋')).toHaveValue('default');
  const bodies: Body[] = [], puts: string[] = [];
  let release!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  await page.route('**/api/v1/pcap-analysis-jobs/initiate', async route => {
    bodies.push(route.request().postDataJSON()); const index = bodies.length;
    if (phase === 'initiation' && index === 1) await gate;
    await route.fulfill({ status: 201, json: { id: `job-${index}` } });
  });
  await page.route('**/api/v1/pcap-analysis-jobs/*/capture', async route => {
    const path = new URL(route.request().url()).pathname; puts.push(path);
    if (phase === 'upload' && path.includes('/job-1/')) await gate;
    await route.fulfill({ status: 202, json: { id: path.split('/').at(-2) } });
  });
  await submit(f); await expect.poll(() => phase === 'initiation' ? bodies.length : puts.length).toBe(1);
  expect(bodies[0].analysis).not.toHaveProperty('detector_weights');
  await page.getByLabel('저장된 탐지 가중치 프리셋').selectOption('');
  const response = page.waitForResponse(r => r.url().includes(phase === 'initiation' ? '/initiate' : '/job-1/capture'));
  release(); await response;
  await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
  await expect(page.getByRole('heading', { name: 'Upload PCAP' })).toBeVisible();
  expect(puts).toHaveLength(phase === 'initiation' ? 0 : 1);
  await submit(f); await expect(page).toHaveURL(/\/analyses\/job-2$/);
  expect(bodies[1].analysis).toHaveProperty('detector_weights');
  expect(bodies[1].idempotency_key).not.toBe(bodies[0].idempotency_key);
});
