import { test, expect } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';

const jobs = JSON.parse(execFileSync(process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python'), ['tests/ddos_source_budget_fixture.py'], { encoding: 'utf8' }));
for (const name of Object.keys(jobs)) test(`supported source budgets ${name} preserve report and child entry points`, async ({ page }, info) => {
  const job = jobs[name], writes: string[] = [], errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => { localStorage.setItem('c2hunter-token', 'owned-budget'); localStorage.setItem('c2hunter-report-language', 'en'); });
  await page.route('**/api/v1/**', async route => {
    const req = route.request(), path = new URL(req.url()).pathname.replace('/api/v1', '');
    if (req.method() !== 'GET') writes.push(path);
    await route.fulfill({ json: path === `/analysis-jobs/${job.id}` ? job : path === '/ai-capabilities' ? { available: false, ddos_interpretation: false, reason: 'Offline budget fixture' } : { items: [] } });
  });
  await page.goto(`/analyses/${job.id}`);
  await expect(page.getByRole('region', { name: 'DDoS at a glance' })).toBeVisible();
  await expect(page.getByText('Unsupported DDoS report. Review coverage and update the client.')).toHaveCount(0);
  await page.getByRole('button', { name: /Show detailed evidence/ }).first().click();
  await page.getByRole('button', { name: /Inspect candidate/ }).first().click();
  await expect(page.getByRole('region', { name: 'Candidate inspection' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Download passive BPF v1' })).toHaveCount(0);
  await expect(page.getByRole('region', { name: 'Candidate inspection' })).toContainText(name.startsWith('ipv4') ? 'BOUNDED_IPV4_NETWORK_CONTEXT_REQUIRED' : 'IPV4_UDP_ONLY');
  await page.getByRole('button', { name: 'Open PCAP review windows' }).click();
  await page.getByRole('button', { name: 'Review window 1', exact: true }).click();
  await expect(page.getByRole('region', { name: 'Candidate evidence' })).toBeVisible();
  await page.getByRole('button', { name: 'Open DDoS AI interpretation' }).click();
  await expect(page.getByText('Offline budget fixture')).toBeVisible();
  expect(writes).toEqual([]); expect(errors).toEqual([]);
  await page.screenshot({ path: info.outputPath(`${name}-children-accessible.png`) });
});
