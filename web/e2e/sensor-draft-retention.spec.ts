import { withLegacyAuthentication } from './auth-fixture';
import { expect, test, type Page } from '@playwright/test';
import { sensorProducer } from '../tests/stage5SensorFixture';

// All detail fixtures retain the producer's full 128 sources / 1024 CIDRs.
const sensors = Array.from({ length: 19 }, (_, index) => ({ ...sensorProducer.maximum, sensor_id: `retained-${index}`, name: `Retained sensor ${index}` }));
async function install(page: Page, mode: 'unsaved' | 'unconfirmed' | 'failed') {
  await page.addInitScript(() => { localStorage.setItem('c2hunter-token', 'retained-browser-synthetic'); localStorage.setItem('c2hunter-report-language', 'en'); });
  const errors: string[] = [], writes: Record<string, unknown>[] = [], reloads: string[] = [];
  let finishFailure: (() => Promise<void>) | undefined;
  page.on('pageerror', error => errors.push(error.message));
  page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
  await page.route('**/api/v1/**', withLegacyAuthentication(route => {
    const request = route.request(), path = new URL(request.url()).pathname;
    if (request.method() !== 'GET') {
      writes.push(request.postDataJSON());
      if (mode === 'failed') return new Promise<void>(resolve => { finishFailure = async () => { await route.fulfill({ status: 409, json: { error: { message: 'Retained pending failure' } } }); resolve(); }; });
      return route.fulfill({ json: {} });
    }
    if (path.endsWith('/configuration')) {
      reloads.push(path);
      return route.fulfill({ json: { ...sensorProducer.maximum, config_version: sensorProducer.maximum.config_version + 1 } });
    }
    if (path === '/api/v1/sensors') return route.fulfill({ json: { items: sensors, page: 1, page_size: 50, total: sensors.length } });
    return route.fulfill({ json: sensors.find(sensor => path.endsWith(`/${sensor.sensor_id}`)) ?? { items: [] } });
  }));
  return { errors, writes, reloads, fail: async () => { expect(finishFailure).toBeDefined(); await finishFailure!(); } };
}
async function go(page: Page, index: number) {
  const link = page.getByRole('link', { name: 'Sensors', exact: true });
  if (!await link.isVisible()) await page.getByRole('button', { name: '메뉴 / Menu', exact: true }).click();
  await link.click();
  await page.getByRole('link', { name: `Retained sensor ${index}`, exact: true }).click();
  await expect(page.getByRole('heading', { name: `Retained sensor ${index}`, exact: true })).toBeVisible();
}
async function edit(page: Page) { await page.getByRole('button', { name: 'Edit desired configuration', exact: true }).click(); }
async function measure(page: Page, width: number) {
  const sample = await page.evaluate(() => ({ nodes: document.querySelectorAll('*').length, width: document.documentElement.scrollWidth, bodyWidth: document.body.scrollWidth }));
  expect(sample.nodes).toBeLessThanOrEqual(2500);
  expect(sample.width).toBeLessThanOrEqual(width); expect(sample.bodyWidth).toBeLessThanOrEqual(width);
  return sample;
}
for (const width of [1280, 390]) {
  for (const mode of ['unsaved', 'unconfirmed', 'failed'] as const) test(`Retained ${mode} draft survives eighteen read-only detail visits ${width}`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: 900 });
    const state = await install(page, mode);
    await page.goto('/sensors/retained-0'); await edit(page);
    await page.getByLabel('Desired Internal CIDR 1', { exact: true }).fill('10.99.0.0/16');
    if (mode !== 'unsaved') {
      await page.getByRole('button', { name: 'Save configuration', exact: true }).click();
      if (mode === 'failed') await expect(page.getByRole('button', { name: 'Saving…', exact: true })).toBeDisabled();
      else await expect(page.getByText(/save is unconfirmed/)).toBeVisible();
    }
    const visits: number[] = [];
    for (let i = 1; i <= 18; i++) {
      await go(page, i); visits.push(i);
      await expect(page.getByRole('button', { name: 'Edit desired configuration', exact: true })).toBeEnabled();
      await expect(page.getByLabel('Desired Internal CIDR 1', { exact: true })).toHaveCount(0);
    }
    if (mode === 'failed') await state.fail();
    await go(page, 0); await edit(page);
    await expect(page.getByLabel('Desired Internal CIDR 1', { exact: true })).toHaveValue('10.99.0.0/16');
    await expect(page.getByText(`Configuration version ${sensorProducer.maximum.config_version}`, { exact: true })).toBeVisible();
    if (mode === 'unconfirmed') await expect(page.getByText(/save is unconfirmed/)).toBeVisible();
    if (mode === 'failed') await expect(page.getByText('Retained pending failure', { exact: true })).toBeVisible();
    expect(state.writes).toHaveLength(mode === 'unsaved' ? 0 : 1);
    if (mode !== 'unsaved') {
      expect(state.writes[0].capture_sources).toEqual(sensorProducer.maximum.capture_sources.map(({ interface: name, direction, bpf_filter, enabled, store_pcap }) => ({ interface: name, direction, bpf_filter, enabled, store_pcap })));
      expect(state.writes[0].internal_networks).toEqual(['10.99.0.0/16', ...sensorProducer.maximum.internal_networks.slice(1)]);
      expect(state.writes[0].config_version).toBe(sensorProducer.maximum.config_version);
    }
    expect(state.reloads).toEqual([]);
    expect(state.errors).toEqual(mode === 'failed' ? ['Failed to load resource: the server responded with a status of 409 (Conflict)'] : []);
    const sample = await measure(page, width);
    await info.attach('retained-owner-evidence', { body: JSON.stringify({ mode, width, visits, sample, writes: state.writes, errors: state.errors }), contentType: 'application/json' });
    await info.attach('retained-owner-screen', { body: await page.screenshot(), contentType: 'image/png' });
  });

  test(`Sixteen protected drafts refuse seventeenth editor with explicit reload recovery ${width}`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: 900 });
    const state = await install(page, 'unsaved');
    await page.goto('/sensors/retained-0');
    for (let i = 0; i < 16; i++) {
      if (i) await go(page, i);
      await edit(page);
      await page.getByLabel('Desired Internal CIDR 1', { exact: true }).fill(`10.${i}.0.0/16`);
    }
    await go(page, 16);
    await expect(page.getByText(/16.*unsaved.*pending/)).toBeVisible();
    await expect(page.getByText(`Configuration version ${sensorProducer.maximum.config_version}`, { exact: true })).toBeVisible();
    await expect(page.getByText('synthetic-error-0', { exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Edit desired configuration', exact: true })).toBeDisabled();
    await expect(page.getByLabel('Desired Internal CIDR 1', { exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Save configuration', exact: true })).toHaveCount(0);
    const refused = await measure(page, width);
    await info.attach('capacity-refusal-screen', { body: await page.screenshot(), contentType: 'image/png' });
    await page.getByRole('link', { name: 'Return to sensors to resolve a retained draft', exact: true }).click();
    await page.getByRole('link', { name: 'Retained sensor 0', exact: true }).click(); await edit(page);
    await expect(page.getByLabel('Desired Internal CIDR 1', { exact: true })).toHaveValue('10.0.0.0/16');
    await expect(page.getByText(/Reload replaces this draft.*discards unsaved changes/)).toBeVisible();
    await page.getByRole('button', { name: 'Reload latest configuration', exact: true }).click();
    await expect(page.getByText(`Configuration version ${sensorProducer.maximum.config_version + 1}`, { exact: true })).toBeVisible();
    await expect(page.getByLabel('Desired Internal CIDR 1', { exact: true })).toHaveValue(sensorProducer.maximum.internal_networks[0]);
    await go(page, 16); await edit(page);
    await page.getByLabel('Desired Internal CIDR 1', { exact: true }).fill('10.16.0.0/16');
    await expect(page.getByLabel('Desired Internal CIDR 1', { exact: true })).toHaveValue('10.16.0.0/16');
    await go(page, 1); await edit(page);
    await expect(page.getByLabel('Desired Internal CIDR 1', { exact: true })).toHaveValue('10.1.0.0/16');
    expect(state.writes).toEqual([]); expect(state.reloads).toEqual(['/api/v1/sensors/retained-0/configuration']); expect(state.errors).toEqual([]);
    await info.attach('capacity-recovery-evidence', { body: JSON.stringify({ width, protected: 16, refused, recovered: await measure(page, width), reloads: state.reloads, writes: state.writes }), contentType: 'application/json' });
  });
}
