import { expect, test } from '@playwright/test';
import { installApiFixture } from './route-fixture';

test('analyst workflow: login, inspect, analyze, export, allowlist, reanalyze', async ({ page }) => {
  await installApiFixture(page);
  await page.goto('/login');
  await page.getByLabel('Username').fill('analyst');
  await page.getByRole('button', { name: 'Development login' }).click();
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();

  await page.getByRole('link', { name: 'Sensors', exact: true }).click();
  await page.getByRole('link', { name: 'Sensor A' }).click();
  await expect(page.getByRole('heading', { name: 'Sensor A' })).toBeVisible();

  await page.getByRole('link', { name: 'New analysis' }).click();
  await page.getByLabel('Analysis name').fill('E2E investigation');
  await page.getByLabel('Sensor A').check();
  await page.getByRole('button', { name: 'Start analysis' }).click();
  await expect(page.getByText('ANALYZING')).toBeVisible();
  await page.getByRole('button', { name: 'Cancel analysis' }).click();
  await expect(page.getByText('Cancellation requested')).toBeVisible();

  await page.getByRole('link', { name: 'Candidates' }).click();
  await page.getByRole('link', { name: '203.0.113.10' }).click();
  await expect(page.getByRole('img', { name: 'Traffic over time' })).toBeVisible();
  await expect(page.getByText('PERIODIC_BEACON')).toBeVisible();
  await page.getByRole('button', { name: 'Export candidate PCAP' }).click();
  await expect(page.getByText('PCAP export requested')).toBeVisible();
  await page.getByRole('button', { name: 'Reanalyze' }).click();
  await expect(page.getByText('Reanalysis created')).toBeVisible();

  await page.getByRole('link', { name: 'Allowlist' }).click();
  await page.getByLabel('Value').fill('203.0.113.10');
  await page.getByRole('button', { name: 'Add entry' }).click();
  await expect(page.getByText('203.0.113.10')).toBeVisible();
  await page.getByRole('button', { name: 'Delete 203.0.113.10' }).click();
  await expect(page.getByText('No allowlist entries')).toBeVisible();
});

test('analyst can manage history and upload an offline PCAP', async ({ page }) => {
  await installApiFixture(page);
  await page.goto('/login');
  await page.getByLabel('Username').fill('analyst');
  await page.getByRole('button', { name: 'Development login' }).click();

  await page.getByRole('link', { name: 'Analysis history' }).click();
  await expect(page.getByRole('table', { name: 'Analysis history' })).toBeVisible();
  await page.getByRole('button', { name: 'Edit E2E investigation' }).click();
  await page.getByLabel('Analyst note').fill('Reviewed in E2E');
  await page.getByRole('button', { name: 'Save changes' }).click();
  await expect(page.getByRole('dialog', { name: 'Edit analysis metadata' })).not.toBeVisible();

  await page.getByRole('link', { name: 'Upload PCAP', exact: true }).first().click();
  await page.getByLabel('Analysis name').fill('Uploaded E2E capture');
  await page.getByLabel('Capture file').setInputFiles({
    name: 'fixture.pcap',
    mimeType: 'application/vnd.tcpdump.pcap',
    buffer: Buffer.from([0xd4, 0xc3, 0xb2, 0xa1]),
  });
  await page.getByRole('button', { name: 'Upload and analyze' }).click();
  await expect(page.getByRole('heading', { name: 'Uploaded E2E capture' })).toBeVisible();
  await expect(page.getByText('PCAP upload')).toBeVisible();
});
