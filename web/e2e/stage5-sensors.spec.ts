import { withLegacyAuthentication } from './auth-fixture';
import { expect, test, type Page } from '@playwright/test';
import { sensorProducer, sensorProducerPage } from '../tests/stage5SensorFixture';

async function install(page: Page, maximum = sensorProducer.maximum) {
  await page.addInitScript(() => { localStorage.setItem('c2hunter-token', 'synthetic-browser'); localStorage.setItem('c2hunter-report-language', 'en'); });
  const errors: string[] = [], writes: { path: string; body: Record<string, unknown> }[] = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
  await page.route('**/api/v1/**', withLegacyAuthentication(route => {
    const request = route.request(), parsed = new URL(request.url()), path = parsed.pathname;
    if (request.method() !== 'GET') {
      const body = request.postDataJSON(); writes.push({ path, body });
      if (request.method() === 'PUT') return route.fulfill({ json: { ...body, config_version: Number(body.config_version) + 1 } });
      if (path === '/api/v1/sensor-enrollments') return route.fulfill({ status: 201, json: { enrollment_token: 'synthetic-once', install_command: 'synthetic command', expires_at: '2027-01-01T00:00:00Z' } });
      return route.fulfill({ status: 422, json: { error: { message: 'Synthetic stop' } } });
    }
    if (path === `/api/v1/sensors/${maximum.sensor_id}`) return route.fulfill({ json: maximum });
    if (path === '/api/v1/analysis-jobs/synthetic-job') return route.fulfill({ json: { id: 'synthetic-job', name: 'Synthetic job', status: 'COMPLETED' } });
    return route.fulfill({ json: sensorProducerPage(parsed.pathname + parsed.search) ?? { items: [] } });
  }));
  return { errors, writes };
}
async function measure(page: Page, width: number, limit = 2500) {
  const sample = await page.evaluate(() => ({ nodes: document.querySelectorAll('*').length, width: document.documentElement.scrollWidth, bodyWidth: document.body.scrollWidth }));
  expect(sample.nodes).toBeLessThanOrEqual(limit); expect(sample.width).toBeLessThanOrEqual(width); expect(sample.bodyWidth).toBeLessThanOrEqual(width);
  return sample;
}
const small = { ...sensorProducer.maximum, capture_sources: sensorProducer.maximum.capture_sources.slice(0, 9), internal_networks: sensorProducer.maximum.internal_networks.slice(0, 33), interfaces: sensorProducer.maximum.interfaces.slice(0, 9) };
for (const width of [1280, 390]) {
  test(`Maximum model-valid 128/1024/128 reachable with bounded mounted DOM ${width}`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: 900 });
    const { writes, errors } = await install(page);
    await page.goto(`/sensors/${sensorProducer.maximum.sensor_id}`);
    await expect(page.getByText('synthetic-error-0', { exact: true })).toBeVisible();
    await expect(page.getByLabel('Desired interface name 1', { exact: true })).toHaveCount(0);
    const samples = [await measure(page, width, 1200)];
    await page.getByRole('button', { name: 'Edit desired configuration', exact: true }).click();
    const sources: string[] = [], networks: string[] = [], errorsSeen: string[] = [];
    for (const [label, pages, selector, collected] of [
      ['Desired interfaces pages', 16, '.source-row input[required]', sources],
      ['Desired networks pages', 32, '.cidr-list input', networks],
      ['Observed interfaces pages', 16, 'table[aria-label="Observed interface status"] [role="alert"]', errorsSeen],
    ] as const) {
      const navigation = page.getByRole('navigation', { name: label });
      for (let number = 1; number <= pages; number++) {
        collected.push(...await page.locator(selector).evaluateAll(elements => elements.map(element => element instanceof HTMLInputElement ? element.value : element.textContent!)));
        samples.push(await measure(page, width));
        if (number < pages) await navigation.getByRole('button', { name: 'Next page', exact: true }).click();
      }
    }
    expect(sources).toEqual(sensorProducer.maximum.capture_sources.map(source => source.interface));
    expect(networks).toEqual(sensorProducer.maximum.internal_networks);
    expect(errorsSeen).toEqual(sensorProducer.maximum.interfaces.map(source => source.last_error));
    expect(writes).toEqual([]);
    await page.getByRole('button', { name: 'Save configuration', exact: true }).click();
    await expect(page.getByText('Configuration saved.', { exact: true })).toBeVisible();
    expect(writes).toHaveLength(1);
    expect(writes[0].body.internal_networks).toEqual(sensorProducer.maximum.internal_networks);
    expect(writes[0].body.capture_sources).toEqual(sensorProducer.maximum.capture_sources.map(({ interface: name, direction, bpf_filter, enabled, store_pcap }) => ({ interface: name, direction, bpf_filter, enabled, store_pcap })));
    expect(writes[0].body.config_version).toBe(sensorProducer.maximum.config_version);
    await page.getByRole('button', { name: 'Close desired configuration', exact: true }).click();
    samples.push(await measure(page, width, 1200));
    expect(errors).toEqual([]);
    await info.attach('maximum-dom-and-public-provenance', { body: JSON.stringify({ samples, peak: Math.max(...samples.map(s => s.nodes)), provenance: sensorProducer.provenance, origins: sensorProducer.producer_origins, payload: writes[0].body }), contentType: 'application/json' });
  });

  test(`Native required control and off-page full desired guard ${width}`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: 900 });
    const { writes, errors } = await install(page, small);
    await page.goto(`/sensors/${small.sensor_id}`);
    await page.getByRole('button', { name: 'Edit desired configuration', exact: true }).click();
    const save = page.getByRole('button', { name: 'Save configuration', exact: true });
    const visible = page.getByLabel('Desired interface name 1', { exact: true });
    await visible.fill(''); await save.click();
    expect(await visible.evaluate((input: HTMLInputElement) => input.validity.valueMissing)).toBe(true);
    expect(writes).toEqual([]);
    await visible.fill('eth0');
    for (const blank of ['', '   ']) for (const [nav, field, original, message] of [
      ['Desired interfaces pages', 'Desired interface name 9', 'eth8', 'Interface name 9 is required.'],
      ['Desired networks pages', 'Desired Internal CIDR 33', '10.0.32.0/24', 'Internal CIDR 33 is required.'],
    ]) {
      const navigation = page.getByRole('navigation', { name: nav });
      await navigation.getByRole('button', { name: 'Last page', exact: true }).click();
      await page.getByLabel(field, { exact: true }).fill(blank);
      await navigation.getByRole('button', { name: 'First page', exact: true }).click();
      await save.click();
      await expect(page.getByText(message, { exact: true })).toBeVisible();
      expect(writes).toEqual([]);
      await navigation.getByRole('button', { name: 'Last page', exact: true }).click();
      await page.getByLabel(field, { exact: true }).fill(original);
      await navigation.getByRole('button', { name: 'First page', exact: true }).click();
    }
    await save.click(); await expect(page.getByText('Configuration saved.', { exact: true })).toBeVisible();
    expect(writes[0].body.internal_networks).toEqual(small.internal_networks);
    expect(writes[0].body.capture_sources).toHaveLength(9);
    await page.getByRole('button', { name: 'Close desired configuration', exact: true }).click();
    await page.getByRole('button', { name: 'Edit desired configuration', exact: true }).click();
    await expect(page.getByText(/is required\./)).toHaveCount(0);
    expect(errors).toEqual([]);
    await info.attach('full-desired-recovery', { body: JSON.stringify(writes), contentType: 'application/json' });
  });

  test(`Enrollment native and off-page required fields preserve full 9/33 payload ${width}`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: 900 });
    const { writes, errors } = await install(page);
    await page.goto('/external-sensors/enroll');
    await page.getByLabel('Sensor name', { exact: true }).fill('Synthetic enrollment');
    const submit = page.getByRole('button', { name: 'Create enrollment', exact: true });
    await submit.click();
    expect(await page.getByLabel('Interface name 1', { exact: true }).evaluate((input: HTMLInputElement) => input.validity.valueMissing)).toBe(true);
    expect(writes).toEqual([]);
    for (let i = 1; i <= 9; i++) {
      if (i > 1) await page.getByRole('button', { name: 'Add interface', exact: true }).click();
      await page.getByLabel(`Interface name ${i}`, { exact: true }).fill(i === 9 ? '   ' : `eth${i - 1}`);
    }
    const interfaces = page.getByRole('navigation', { name: 'Capture interfaces pages' });
    await interfaces.getByRole('button', { name: 'First page', exact: true }).click();
    await submit.click(); await expect(page.getByText('Interface name 9 is required.', { exact: true })).toBeVisible(); expect(writes).toEqual([]);
    await interfaces.getByRole('button', { name: 'Last page', exact: true }).click(); await page.getByLabel('Interface name 9', { exact: true }).fill('eth8');
    for (let i = 1; i <= 33; i++) {
      if (i > 1) await page.getByRole('button', { name: 'Add internal network', exact: true }).click();
      await page.getByLabel(`Internal CIDR ${i}`, { exact: true }).fill(i === 33 ? '' : `10.0.${i - 1}.0/24`);
    }
    const networks = page.getByRole('navigation', { name: 'Capture networks pages' });
    await networks.getByRole('button', { name: 'First page', exact: true }).click();
    await submit.click(); await expect(page.getByText('Internal CIDR 33 is required.', { exact: true })).toBeVisible(); expect(writes).toEqual([]);
    await networks.getByRole('button', { name: 'Last page', exact: true }).click(); await page.getByLabel('Internal CIDR 33', { exact: true }).fill(' 10.0.32.0/24 ');
    await submit.click(); await expect(page.getByText(/shown only once/)).toBeVisible();
    expect(writes).toHaveLength(1); expect(writes[0].body.capture_sources).toHaveLength(9); expect(writes[0].body.internal_networks).toEqual(small.internal_networks);
    expect(errors).toEqual([]);
    await info.attach('full-enrollment-recovery', { body: JSON.stringify(writes), contentType: 'application/json' });
  });

  for (const [path, table, pager] of [['/sensors', 'Sensors', 'Pages'], ['/external-sensors', 'External sensor enrollments', 'Pages'], ['/sensor-pcaps', 'Sensor PCAP archives', 'Pages'], ['/analyses/synthetic-job', 'Analysis PCAP archives', 'Analysis PCAP pages']]) {
    test(`All 251 public records ${path} at ${width}`, async ({ page }, info) => {
      await page.setViewportSize({ width, height: 900 });
      const { writes, errors } = await install(page);
      await page.goto(path);
      if (path.startsWith('/analyses/')) await page.getByRole('button', { name: 'Work information', exact: true }).click();
      const rows: string[] = [], samples = [];
      for (let number = 1; number <= 6; number++) {
        await expect(page.getByRole('table', { name: table }).locator('tbody tr')).toHaveCount(number === 6 ? 1 : 50);
        rows.push(...await page.getByRole('table', { name: table }).locator('tbody tr').allTextContents());
        samples.push(await measure(page, width, number === 1 ? 1200 : 2500));
        if (number < 6) await page.getByRole('navigation', { name: pager, exact: true }).getByRole('button', { name: 'Next page', exact: true }).click();
      }
      expect(rows).toHaveLength(251); expect(new Set(rows).size).toBe(251); expect(writes).toEqual([]); expect(errors).toEqual([]);
      await info.attach('public-pages-dom', { body: JSON.stringify({ rows, samples }), contentType: 'application/json' });
    });
  }

  test(`Owned pending conflict survives close and A-B-A with explicit reload ${width}`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: 900 });
    const { errors } = await install(page, small);
    const puts: Record<string, unknown>[] = [];
    let conflict!: () => Promise<void>;
    await page.route('**/api/v1/sensors', route => route.fulfill({ json: { items: [small, { ...small, sensor_id: 'sensor-b', name: 'Sensor B' }] } }));
    await page.route('**/api/v1/sensors/sensor-b', route => route.fulfill({ json: { ...small, sensor_id: 'sensor-b', name: 'Sensor B' } }));
    await page.route(`**/api/v1/sensors/${small.sensor_id}/configuration`, route => {
      if (route.request().method() === 'GET') return route.fulfill({ json: { ...small, config_version: 7 } });
      const body = route.request().postDataJSON(); puts.push(body);
      if (puts.length === 1) return new Promise<void>(resolve => { conflict = async () => { await route.fulfill({ status: 409, json: { error: { message: 'Synthetic version conflict' } } }); resolve(); }; });
      return route.fulfill({ json: { ...body, config_version: 8 } });
    });
    await page.goto(`/sensors/${small.sensor_id}`);
    const edit = () => page.getByRole('button', { name: 'Edit desired configuration', exact: true }).click();
    const go = async (name: string) => {
      const sensors = page.getByRole('link', { name: 'Sensors', exact: true });
      if (!await sensors.isVisible()) await page.getByRole('button', { name: '메뉴 / Menu', exact: true }).click();
      await sensors.click(); await page.getByRole('link', { name, exact: true }).click();
    };
    await edit(); await page.getByLabel('Desired BPF filter 1', { exact: true }).fill('udp');
    await page.getByRole('button', { name: 'Save configuration', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Saving…', exact: true })).toBeDisabled();
    await page.getByRole('button', { name: 'Close desired configuration', exact: true }).click();
    await expect(page.getByText('Saving configuration…', { exact: true })).toBeVisible();
    await go('Sensor B'); await edit(); await expect(page.getByLabel('Desired BPF filter 1', { exact: true })).toHaveValue('tcp');
    await go(small.name); await edit(); await expect(page.getByLabel('Desired BPF filter 1', { exact: true })).toHaveValue('udp');
    await expect(page.getByRole('button', { name: 'Saving…', exact: true })).toBeDisabled();
    expect(puts).toHaveLength(1); expect(puts[0].config_version).toBe(small.config_version);
    await conflict(); await expect(page.getByText('Configuration conflict', { exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Reload latest configuration', exact: true }).click();
    await expect(page.getByText('Configuration version 7', { exact: true })).toBeVisible();
    await expect(page.getByLabel('Desired BPF filter 1', { exact: true })).toHaveValue('tcp');
    await page.getByRole('button', { name: 'Save configuration', exact: true }).click();
    await expect(page.getByText('Configuration saved.', { exact: true })).toBeVisible();
    expect(puts).toHaveLength(2); expect(puts[1].config_version).toBe(7);
    expect(errors).toEqual(['Failed to load resource: the server responded with a status of 409 (Conflict)']);
    await info.attach('owner-pending-conflict-recovery', { body: JSON.stringify({ puts, expectedHTTPConsole: errors }), contentType: 'application/json' });
  });

  for (const module of ['network_anomaly', 'ddos_attack']) test(`Cross-page selection retains first-fold warnings ${module} ${width}`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: 900 });
    const { writes, errors } = await install(page);
    await page.goto('/analyses/new');
    await page.getByLabel('Analysis name', { exact: true }).fill('Synthetic selection');
    await page.getByRole('combobox', { name: 'Analysis module', exact: true }).selectOption(module);
    const initial = await measure(page, width, 1200);
    await page.getByRole('button', { name: 'Choose sensors', exact: true }).click();
    const dialog = page.getByRole('dialog', { name: 'Choose sensors', exact: true });
    const selected: string[] = [], seen: string[] = [], samples = [initial];
    for (let number = 1; number <= 6; number++) {
      const checkboxes = dialog.getByRole('checkbox');
      await expect(checkboxes).toHaveCount(number === 6 ? 1 : 50);
      seen.push(...await checkboxes.evaluateAll(elements => elements.map(element => element.getAttribute('aria-label')!)));
      await checkboxes.first().check();
      selected.push((await dialog.locator('label.check small').first().textContent())!);
      samples.push(await measure(page, width));
      if (number < 6) await dialog.getByRole('button', { name: 'Next page', exact: true }).click();
    }
    expect(seen).toHaveLength(251); expect(new Set(seen).size).toBe(251);
    await dialog.getByRole('button', { name: 'Done choosing sensors', exact: true }).click();
    await expect(dialog).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Choose sensors', exact: true })).toBeFocused();
    await page.evaluate(() => scrollTo(0, 0));
    const bounds = [];
    for (const control of [page.getByRole('region', { name: 'Interpretation limits' }), page.getByRole('button', { name: 'Start analysis', exact: true }), page.getByRole('status', { name: 'Submission phase' })]) {
      const box = await control.boundingBox(); expect(box).not.toBeNull(); expect(box!.y).toBeGreaterThanOrEqual(0); expect(box!.y + box!.height).toBeLessThanOrEqual(900); bounds.push(box);
    }
    expect(writes).toEqual([]);
    await page.getByRole('button', { name: 'Start analysis', exact: true }).click();
    await expect(page.getByText('Synthetic stop', { exact: true })).toBeVisible();
    expect(writes[0].body.sensor_ids).toEqual(selected);
    expect(errors).toEqual(['Failed to load resource: the server responded with a status of 422 (Unprocessable Entity)']);
    await info.attach('selection-payload-first-fold', { body: JSON.stringify({ samples, bounds, selected, writes, expectedHTTPConsole: errors, provenance: sensorProducer.provenance }), contentType: 'application/json' });
  });
}
