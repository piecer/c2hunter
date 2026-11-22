import { expect, test, type Page } from '@playwright/test';

const id = (index: number) => `00000000-0000-4000-8000-${String(index).padStart(12, '0')}`;
const hash = (index: number) => `${String(index).padStart(4, '0')}${'abcdef'.repeat(10)}`;
const signatures = Array.from({ length: 45 }, (_, i) => ({ id: id(i), name: `Beacon ${i}`, description: 'Confirmed C2 flow', version: 2, enabled: true, source_job_id: id(100), source_flow_id: `full-flow-${i}`, source_label_id: id(200), payload_hash: hash(i), payload_prefix_hash: hash(100), payload_simhash: '123456789abcdef0', length_tolerance_ratio: 0.1, entropy_tolerance: 0.2, simhash_max_distance: 3, created_at: '2026-07-20T10:00:00Z', ...(i === 0 ? { updated_at: '2026-07-21T11:00:00Z' } : {}) }));
const entries = signatures.map((s, i) => ({ id: s.id, type: 'TLS_FINGERPRINT', value: hash(i), description: `Exception ${i}`, enabled: true, created_at: s.created_at, expires_at: '2027-07-20T10:00:00Z' }));
const settings = { version: 7, virustotal_enabled: true, abuseipdb_enabled: true, misp_enabled: true, misp_url: 'https://misp.example', misp_verify_tls: false, threat_intel_timeout_seconds: 20, threat_intel_request_delay_seconds: 0.5, abuseipdb_max_age_days: 30, abuseipdb_positive_threshold: 40, candidate_auto_enrichment_enabled: true, candidate_auto_enrichment_limit: 50, candidate_auto_enrichment_workers: 1, candidate_auto_enrichment_queue_capacity: 100, management_event_id: '12345678901234567890', management_auto_register: true, immediate_action_event_id: '98765432109876543210', immediate_action_auto_register: true, immediate_action_min_positive_providers: 2, updated_at: '2026-07-21T11:00:00Z', updated_by: 'operator' };
async function setup(page: Page) {
  await page.addInitScript(() => {
    localStorage.setItem('c2hunter-token', 'policy-browser');
    const measure = () => { const n = document.querySelectorAll('*').length; (window as unknown as { policyPeak: number }).policyPeak = Math.max((window as unknown as { policyPeak: number }).policyPeak || 0, n); };
    new MutationObserver(measure).observe(document, { childList: true, subtree: true });
  });
  const writes: string[] = [];
  await page.route('**/api/v1/**', async route => {
    const url = new URL(route.request().url());
    if (route.request().method() !== 'GET') writes.push(`${route.request().method()} ${url.pathname}`);
    if (url.pathname.endsWith('/integration-settings')) return route.fulfill({ json: settings });
    const all = url.pathname.endsWith('/payload-signatures') ? signatures : entries;
    const current = Number(url.searchParams.get('page') || 1), size = Number(url.searchParams.get('page_size') || 50);
    await route.fulfill({ json: { items: all.slice((current - 1) * size, current * size), page: current, page_size: size, total: all.length } });
  });
  return writes;
}
async function geometry(page: Page, width: number) {
  const result = await page.evaluate(() => ({ nodes: document.querySelectorAll('*').length, peak: (window as unknown as { policyPeak: number }).policyPeak, width: document.documentElement.scrollWidth }));
  expect(result.nodes).toBeLessThanOrEqual(1200);
  expect(result.peak).toBeLessThanOrEqual(2500);
  expect(result.width).toBeLessThanOrEqual(width + 1);
  return result;
}
async function navigate(page: Page, label: string, width: number) {
  if (width < 800) await page.getByRole('button', { name: '메뉴 / Menu' }).click();
  await page.getByRole('link', { name: label, exact: true }).click();
}
for (const width of [1280, 390]) {
  test(`policy all 45 records and full values with bounded DOM at ${width}`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: 900 });
    const writes = await setup(page);
    const observations = [];
    for (const resource of ['payload-signatures', 'allowlist']) {
      await page.goto(`/${resource}`);
      const seen: string[] = [];
      for (let current = 1; current <= 5; current++) {
        await expect(page.getByText(resource === 'allowlist' ? `Exception ${(current - 1) * 10}` : `Beacon ${(current - 1) * 10}`, { exact: true })).toBeVisible();
        const rows = resource === 'allowlist' ? page.locator('.policy-records > li') : page.getByRole('table', { name: 'Payload signatures' }).locator('tbody > tr');
        expect(await rows.count()).toBeLessThanOrEqual(10);
        for (let index = 0; index < await rows.count(); index++) {
          const itemIndex = (current - 1) * 10 + index, row = rows.nth(index);
          await expect(row.getByText(id(itemIndex), { exact: true })).toBeVisible();
          await expect(row.getByText(hash(itemIndex), { exact: true })).toBeVisible();
          await expect(row.getByText(/Registered/)).toContainText('2026');
          await expect(row.getByText(/Changed/)).toContainText(resource === 'payload-signatures' && itemIndex === 0 ? '2026' : 'Not reported');
          if (resource === 'allowlist') await expect(row.getByText(/Expires/)).toContainText('2027');
          const box = await row.boundingBox();
          expect(box!.x + box!.width).toBeLessThanOrEqual(width + 1);
          seen.push((await row.getByText(id(itemIndex), { exact: true }).textContent())!);
        }
        observations.push({ resource, current, ...await geometry(page, width) });
        if (current < 5) {
          const next = page.getByRole('button', { name: 'Next policy page' });
          await next.focus(); await page.keyboard.press('Enter');
        }
      }
      expect(seen).toEqual(signatures.map(s => s.id));
      if (resource === 'allowlist') {
        await expect(page.getByText('IP, CIDR, domain, and fingerprint entries fully suppress matching candidates.')).toBeVisible();
        await expect(page.getByLabel('Value', { exact: true })).toHaveCount(0);
        await page.getByRole('button', { name: 'Create entry' }).click();
        await expect(page.getByLabel('Value', { exact: true })).toBeVisible();
        await page.getByRole('button', { name: 'Cancel creation' }).click();
      }
    }
    expect(writes).toEqual([]);
    await info.attach('policy-dom.json', { body: JSON.stringify(observations), contentType: 'application/json' });
    await page.screenshot({ path: info.outputPath(`policy-${width}.png`), fullPage: true });
  });
  test(`policy target confirmation, pending navigation, late failure and correct retry at ${width}`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: 900 });
    await setup(page);
    let release!: () => void;
    const held = new Promise<void>(resolve => { release = resolve; });
    const targets: string[] = [];
    await page.route('**/api/v1/payload-signatures/*', async route => {
      targets.push(new URL(route.request().url()).pathname);
      if (targets.length === 1) { await held; await route.fulfill({ status: 409, json: { error: { message: 'conflict' } } }); }
      else await route.fulfill({ status: 200, body: '{malformed', contentType: 'application/json' });
    });
    await page.goto('/payload-signatures');
    const trigger = page.getByRole('button', { name: 'Delete Beacon 0', exact: true });
    await trigger.focus(); await page.keyboard.press('Enter');
    const dialog = page.getByRole('dialog', { name: 'Confirm policy deletion' });
    await expect(dialog.getByText(id(0), { exact: true })).toBeVisible();
    await expect(dialog.getByRole('button', { name: 'Cancel deletion' })).toBeFocused();
    await page.keyboard.press('Shift+Tab');
    await expect(dialog.getByRole('button', { name: 'Confirm delete' })).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(dialog.getByRole('button', { name: 'Cancel deletion' })).toBeFocused();
    expect(targets).toEqual([]);
    await page.keyboard.press('Escape');
    await expect(dialog).toHaveCount(0);
    await expect(trigger).toBeFocused();
    await trigger.click(); await dialog.getByRole('button', { name: 'Confirm delete' }).click();
    await expect(page.getByText(/Pending —/)).toBeVisible();
    await navigate(page, 'Allowlist', width);
    await expect(page.getByText('Exception 0', { exact: true })).toBeVisible();
    release();
    await expect(page.getByText(/Delete failed \(HTTP 409\)/)).toBeVisible();
    await navigate(page, 'Payload signatures', width);
    await expect(page.getByText('Beacon 1', { exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Retry delete Beacon 0', exact: true }).click();
    await expect(dialog.getByText(id(0), { exact: true })).toBeVisible();
    expect(targets).toHaveLength(1);
    await dialog.getByRole('button', { name: 'Confirm delete' }).click();
    await expect(page.getByText(/Deletion outcome uncertain/)).toBeVisible();
    expect(targets).toEqual([`/api/v1/payload-signatures/${id(0)}`, `/api/v1/payload-signatures/${id(0)}`]);
    await info.attach('policy-lifecycle-dom.json', { body: JSON.stringify(await geometry(page, width)), contentType: 'application/json' });
  });
  test(`integration read-first warnings and version conflict at ${width}`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: 900 });
    const writes = await setup(page);
    await page.goto('/settings/integrations');
    await expect(page.getByRole('region', { name: 'Current integration policy' })).toBeVisible();
    await expect(page.getByRole('checkbox')).toHaveCount(0);
    await expect(page.getByText(/TLS verification is disabled/)).toBeVisible();
    await expect(page.getByText(/TLS verification is disabled/)).toBeInViewport();
    await expect(page.getByText(/Automatic registration can write/)).toBeInViewport();
    await expect(page.getByText(/Automatic registration can write/)).toBeVisible();
    await expect(page.getByText(settings.management_event_id, { exact: true })).toBeVisible();
    expect(writes).toEqual([]);
    await page.getByRole('button', { name: 'Edit integration settings' }).click();
    await page.getByLabel('관리 Event ID', { exact: true }).fill('edited-event');
    let posted: Record<string, unknown> | undefined;
    await page.route('**/api/v1/integration-settings', async route => {
      posted = route.request().postDataJSON();
      await route.fulfill({ status: 409, json: { error: { message: 'Settings changed elsewhere' } } });
    });
    await page.getByRole('button', { name: '설정 저장', exact: true }).click();
    await expect(page.getByText('Settings changed elsewhere')).toBeVisible();
    expect(posted).toMatchObject({ expected_version: 7, management_event_id: 'edited-event', misp_verify_tls: false });
    await expect(page.getByLabel('관리 Event ID', { exact: true })).toHaveValue('edited-event');
    await page.getByRole('button', { name: 'Cancel editing' }).click();
    await info.attach('policy-settings-dom.json', { body: JSON.stringify(await geometry(page, width)), contentType: 'application/json' });
    await page.screenshot({ path: info.outputPath(`integration-${width}.png`), fullPage: true });
  });
}

for (const width of [1280, 390]) {
  test(`late authentication response never publishes into replacement session at ${width}`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await setup(page);
    let release!: () => void;
    const hold = new Promise<void>(resolve => { release = resolve; });
    let dispatched = 0;
    await page.route('**/api/v1/payload-signatures/*', async route => {
      dispatched++;
      await hold;
      await route.fulfill({ status: 401, json: { error: { message: 'old authentication' } } });
    });
    await page.goto('/payload-signatures');
    await page.getByRole('button', { name: 'Delete Beacon 0', exact: true }).click();
    await page.getByRole('button', { name: 'Confirm delete', exact: true }).click();
    await expect.poll(() => dispatched).toBe(1);
    await expect(page.getByText(/Pending —/)).toBeVisible();
    await page.evaluate(() => { localStorage.setItem('c2hunter-token', 'replacement'); window.dispatchEvent(new Event('c2hunter-auth-changed')); });
    await expect(page.getByRole('region', { name: 'Policy deletion receipts' })).toHaveCount(0);
    const reply = page.waitForResponse(response => response.status() === 401);
    release(); await reply;
    await expect(page.getByRole('heading', { name: 'Payload signatures', exact: true })).toBeVisible();
    await expect(page.getByRole('region', { name: 'Policy deletion receipts' })).toHaveCount(0);
    expect(await page.evaluate(() => localStorage.getItem('c2hunter-token'))).toBe('replacement');
  });
  test(`eight retained pending receipts stay bounded and cannot evict at ${width}`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: 900 });
    await setup(page);
    let release!: () => void;
    const hold = new Promise<void>(resolve => { release = resolve; });
    let dispatched = 0;
    await page.route('**/api/v1/payload-signatures/*', async route => { dispatched++; await hold; await route.fulfill({ status: 409, json: {} }); });
    await page.goto('/payload-signatures');
    for (let i = 0; i < 8; i++) {
      await page.getByRole('button', { name: `Delete Beacon ${i}`, exact: true }).click();
      await page.getByRole('button', { name: 'Confirm delete', exact: true }).click();
    }
    await expect.poll(() => dispatched).toBe(8);
    await page.getByRole('button', { name: 'Delete Beacon 8', exact: true }).click();
    await expect(page.getByText(/Receipt capacity reached/)).toBeVisible();
    const receipts = page.getByRole('region', { name: 'Policy deletion receipts' });
    await expect(receipts.getByRole('article')).toHaveCount(8);
    await expect(receipts.getByRole('button', { name: /Dismiss/ })).toHaveCount(0);
    await page.getByRole('button', { name: 'Next policy page' }).click();
    await expect(page.getByText('Beacon 10', { exact: true })).toBeVisible();
    await expect(receipts.getByText('Beacon 0', { exact: true })).toBeVisible();
    release();
    await expect(receipts.getByText(/Delete failed/)).toHaveCount(8);
    expect(dispatched).toBe(8);
    await info.attach('policy-capacity-dom.json', { body: JSON.stringify(await geometry(page, width)), contentType: 'application/json' });
  });
}
