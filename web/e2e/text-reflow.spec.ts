import { withLegacyAuthentication } from './auth-fixture';
import { test, expect, type Page, type TestInfo } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { installApiFixture } from './route-fixture';
import { sensorProducer, sensorProducerPage } from '../tests/stage5SensorFixture';
import { historyProducer, historyListing } from '../tests/stage5HistoryFixture';
import { fileURLToPath } from 'node:url';
const C = fileURLToPath(new URL('../../', import.meta.url));
const warningWire = execFileSync(process.env.C2HUNTER_TEST_PYTHON ?? C + '/.venv/bin/python', ['-B', C + '/web/tests/candidate_queue_warning_fixture.py'], { encoding: 'utf8', timeout: 30000 });
const warning = JSON.parse(warningWire);
async function setup(page: Page, language: string, width: number) {
    const record = { requests: [] as {
            method: string;
            url: string;
        }[], console: [] as {
            type: string;
            text: string;
        }[], errors: [] as string[], failed: [] as string[], geometry: [] as unknown[], method: '200% root text enlargement plus CSS viewport stress; NOT native browser zoom or screen-reader testing' };
    page.on('request', r => record.requests.push({ method: r.method(), url: r.url() }));
    page.on('console', m => record.console.push({ type: m.type(), text: m.text() }));
    page.on('pageerror', e => record.errors.push(e.message));
    page.on('requestfailed', r => record.failed.push(r.url()));
    await page.setViewportSize({ width, height: width === 640 ? 450 : 900 });
    await page.addInitScript(lang => { localStorage.setItem('c2hunter-token', 'stage6-readonly-fixture'); localStorage.setItem('c2hunter-report-language', lang); }, language);
    await installApiFixture(page);
    await page.route('**/api/v1/**', withLegacyAuthentication(r => r.request().method() === 'GET' ? r.fallback() : r.abort('blockedbyclient')));
    return record;
}
async function stress(page: Page) { await page.addStyleTag({ content: 'html { font-size: 200%; }' }); }
async function measure(page: Page, info: TestInfo, record: Awaited<ReturnType<typeof setup>>, name: string, limit = 2500) {
    const data = await page.evaluate(() => ({ viewport: innerWidth, height: innerHeight, body: document.body.scrollWidth, document: document.documentElement.scrollWidth, nodes: document.querySelectorAll('*').length, rootFont: getComputedStyle(document.documentElement).fontSize, zoom: getComputedStyle(document.documentElement).zoom, scroll: scrollY, dialogs: [...document.querySelectorAll('[role="dialog"]')].map(e => ({ name: e.getAttribute('aria-label'), width: e.clientWidth, scroll: e.scrollWidth, box: e.getBoundingClientRect().toJSON() })) }));
    const overflow = await page.evaluate(() => [...document.querySelectorAll('body *')].flatMap(el => {
        const box = el.getBoundingClientRect(), css = getComputedStyle(el);
        if (box.width === 0 || (box.right <= innerWidth && el.scrollWidth <= el.clientWidth + 1))
            return [];
        const parent = el.parentElement;
        return [{ tag: el.tagName, className: el.className, text: el.textContent, box: box.toJSON(), client: el.clientWidth, scroll: el.scrollWidth, display: css.display, minWidth: css.minWidth, width: css.width, grid: css.gridTemplateColumns, whiteSpace: css.whiteSpace, overflowWrap: css.overflowWrap, overflowX: css.overflowX, font: css.fontSize, parent: parent ? { tag: parent.tagName, className: parent.className, box: parent.getBoundingClientRect().toJSON(), grid: getComputedStyle(parent).gridTemplateColumns } : null }];
    }));
    record.geometry.push({ name, ...data, overflow });
    expect(data.rootFont).toBe('32px');
    await page.screenshot({ path: info.outputPath(name + '.png') });
    expect(data.body).toBeLessThanOrEqual(data.viewport);
    expect(data.document).toBeLessThanOrEqual(data.viewport);
    expect(data.nodes).toBeLessThanOrEqual(limit);
    for (const modal of data.dialogs)
        expect(modal.scroll).toBeLessThanOrEqual(modal.width);
    const contained = await page.locator('.shell > aside, .shell > aside > .brand, .shell > aside > .navigation-toggle, .content > .grid > .panel > dl, .content .form, .content .form form, .content .form fieldset, .content .form label, .content .actions').evaluateAll(elements => elements.map(el => ({ name: el.className || el.tagName, client: el.clientWidth, scroll: el.scrollWidth, box: el.getBoundingClientRect().toJSON() })));
    const brand = await page.locator('.shell > aside > .brand').evaluate(el => ({ text: el.textContent, height: el.getBoundingClientRect().height, font: parseFloat(getComputedStyle(el).fontSize) }));
    expect(brand.text).toBe('C2Hunter');
    expect(brand.height).toBeLessThanOrEqual(brand.font * 3);
    for (const item of contained) {
        expect(item.scroll, item.name).toBeLessThanOrEqual(item.client + 1);
        expect(item.box.right, item.name).toBeLessThanOrEqual(data.viewport);
    }
}
async function finish(page: Page, info: TestInfo, record: Awaited<ReturnType<typeof setup>>) {
    const cdp = await page.context().newCDPSession(page);
    const ax = await cdp.send('Accessibility.getFullAXTree');
    await info.attach('accessibility-tree', { body: JSON.stringify(ax), contentType: 'application/json' });
    await cdp.detach();
    await info.attach('observations', { body: JSON.stringify(record, null, 2), contentType: 'application/json' });
    expect(record.requests.filter(r => r.url.includes('/api/v1/') && r.method !== 'GET')).toEqual([]);
    expect(record.requests.every(r => new URL(r.url).origin === 'http://127.0.0.1:4173')).toBe(true);
    expect(record.errors).toEqual([]);
    expect(record.console.filter(m => m.type === 'error')).toEqual([]);
}
for (const width of [640, 390])
    for (const language of ['en', 'ko'])
        test(`C2 producer warnings text-200 reflow ${width} ${language}`, async ({ page }, info) => {
            const record = await setup(page, language, width);
            await page.route('**/api/v1/candidates/queue-warning-candidate', r => r.fulfill({ json: warning.candidate }));
            try {
                await page.goto('/candidates?candidate=queue-warning-candidate');
                const modal = page.getByRole('dialog', { name: 'Selected candidate detail', exact: true });
                await expect(modal).toBeVisible();
                await stress(page);
                await measure(page, info, record, 'warning-modal');
                const limits = modal.getByRole('region', { name: 'Evidence limitations', exact: true });
                for (const text of ['No response does not establish', 'Capture loss or asymmetric visibility', 'Response correlation reached its retention limit'])
                    await expect(limits.getByText(text, { exact: false })).toBeVisible();
                const toggle = limits.getByRole('button', { name: 'Show all evidence warnings' });
                await toggle.focus();
                await page.keyboard.press('Space');
                await expect(limits.locator('li code')).toHaveText(warning.candidate.evidence.flatMap((e: {
                    warnings: string[];
                }) => e.warnings));
                await limits.locator('li code').last().scrollIntoViewIfNeeded();
                await expect(limits.locator('li code').last()).toBeInViewport();
                await measure(page, info, record, 'all-warning-codes');
                await page.keyboard.press('Escape');
                await expect(modal).toHaveCount(0);
                await expect(page.getByRole('heading', { name: 'Candidates', exact: true })).toBeFocused();
                await measure(page, info, record, 'closed', 1200);
                await info.attach('producer-wire', { body: warningWire, contentType: 'application/json' });
            }
            finally {
                await finish(page, info, record);
            }
        });
for (const width of [640, 390])
    test(`maximum sensor text-200 keyboard reflow ${width}`, async ({ page }, info) => {
        const record = await setup(page, 'en', width);
        await page.route('**/api/v1/**', withLegacyAuthentication(r => { const u = new URL(r.request().url()); if (r.request().method() !== 'GET')
            return r.abort(); return r.fulfill({ json: u.pathname === `/api/v1/sensors/${sensorProducer.maximum.sensor_id}` ? sensorProducer.maximum : sensorProducerPage(u.pathname + u.search) ?? { items: [] } }); }));
        try {
            await page.goto('/sensors/' + sensorProducer.maximum.sensor_id);
            await expect(page.getByText('synthetic-error-0', { exact: true })).toBeVisible();
            await stress(page);
            await measure(page, info, record, 'sensor-readonly', 1200);
            await page.getByRole('heading', { name: 'Resources', exact: true }).scrollIntoViewIfNeeded();
            await page.screenshot({ path: info.outputPath('sensor-resources.png') });
            const edit = page.getByRole('button', { name: 'Edit desired configuration', exact: true });
            await edit.focus();
            await page.keyboard.press('Enter');
            await expect(page.getByLabel('Desired interface name 1', { exact: true })).toHaveValue(sensorProducer.maximum.capture_sources[0].interface);
            for (const name of ['Desired interfaces pages', 'Desired networks pages', 'Observed interfaces pages']) {
                const last = page.getByRole('navigation', { name, exact: true }).getByRole('button', { name: 'Last page', exact: true });
                await last.focus();
                await page.keyboard.press('Space');
            }
            await expect(page.getByLabel('Desired interface name 128', { exact: true })).toHaveValue(sensorProducer.maximum.capture_sources[127].interface);
            await expect(page.getByLabel('Desired Internal CIDR 1024', { exact: true })).toHaveValue(sensorProducer.maximum.internal_networks[1023]);
            await expect(page.getByText('synthetic-error-127', { exact: true })).toBeVisible();
            await measure(page, info, record, 'sensor-last-pages');
            for (const target of [page.getByLabel('Desired interface name 128', { exact: true }), page.getByLabel('Desired Internal CIDR 1024', { exact: true }), page.getByText('synthetic-error-127', { exact: true })]) {
                await target.scrollIntoViewIfNeeded();
                await expect(target).toBeInViewport();
            }
            await page.screenshot({ path: info.outputPath('sensor-last-error.png') });
            await page.getByRole('button', { name: 'Close desired configuration', exact: true }).click();
            await expect(page.getByLabel('Desired interface name 128', { exact: true })).toHaveCount(0);
            await info.attach('producer-provenance', { body: JSON.stringify({ origins: sensorProducer.producer_origins, denied: sensorProducer.denied_operations }), contentType: 'application/json' });
        }
        finally {
            await finish(page, info, record);
        }
    });
for (const width of [640, 390])
    test(`producer history warning and Back text-200 ${width}`, async ({ page }, info) => {
        const record = await setup(page, 'en', width);
        await page.route('**/api/v1/**', withLegacyAuthentication(r => { const p = new URL(r.request().url()).pathname; if (p === '/api/v1/analysis-jobs')
            return r.fulfill({ contentType: 'application/json', body: historyProducer.list_wire }); if (p === historyProducer.detail_path + '/ai-runs')
            return r.fulfill({ contentType: 'application/json', body: historyProducer.ai_runs_wire }); if (p === historyProducer.detail_path)
            return r.fulfill({ contentType: 'application/json', body: historyProducer.detail_wire }); return r.fallback(); }));
        try {
            await page.goto('/analyses?search=Producer%20limited%20DDoS&status=COMPLETED&sort=name&page=1');
            const invoker = page.getByRole('link', { name: historyListing.items[0].name, exact: true });
            await expect(invoker).toBeVisible();
            await stress(page);
            await measure(page, info, record, 'history', 1200);
            await invoker.focus();
            const top = await page.evaluate(() => scrollY);
            await page.keyboard.press('Enter');
            const warning = page.getByText('Coverage is incomplete; Counts are lower bounds — not a clean result.', { exact: true });
            await expect(warning).toBeVisible();
            await warning.scrollIntoViewIfNeeded();
            await expect(warning).toBeInViewport();
            await measure(page, info, record, 'history-detail-warning');
            await page.goBack();
            await expect(invoker).toBeFocused();
            await expect.poll(() => page.evaluate(() => scrollY)).toBe(top);
            await expect(page.getByLabel('Search', { exact: true })).toHaveValue('Producer limited DDoS');
            await expect(page.getByLabel('Sort analyses')).toHaveValue('name');
            await info.attach('producer-provenance', { body: JSON.stringify(historyProducer), contentType: 'application/json' });
        }
        finally {
            await finish(page, info, record);
        }
    });
for (const width of [640, 390])
    test(`integration read-only editor text-200 reflow ${width}`, async ({ page }, info) => {
        const record = await setup(page, 'en', width);
        try {
            await page.goto('/settings/integrations');
            await expect(page.getByRole('region', { name: 'Current integration policy' })).toBeVisible();
            await stress(page);
            await measure(page, info, record, 'integration-readonly', 1200);
            const edit = page.getByRole('button', { name: 'Edit integration settings' });
            await edit.focus();
            await page.keyboard.press('Enter');
            const version = await page.getByLabel('관리 Event ID', { exact: true }).inputValue();
            await measure(page, info, record, 'integration-editor');
            await expect(page.getByLabel('관리 Event ID', { exact: true })).toHaveValue(version);
            await page.getByLabel('관리 Event ID', { exact: true }).scrollIntoViewIfNeeded();
            await page.screenshot({ path: info.outputPath('integration-event-editor.png') });
        }
        finally {
            await finish(page, info, record);
        }
    });
