import { expect, test } from '@playwright/test';
import { installApiFixture } from './route-fixture';

test('narrow validation keeps freshness warning and retry accessible with stable pending ownership', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 900 });
  await installApiFixture(page);
  let reads = 0; let recovered = false; let writes = 0;
  let settle!: () => void;
  const pending = new Promise<void>(resolve => { settle = resolve; });
  await page.route('**/api/v1/candidates/candidate-1', async route => {
    reads++;
    await route.fulfill({ status: reads === 1 || recovered ? 200 : 503, contentType: 'application/json', body: JSON.stringify(reads === 1 || recovered
      ? { id: 'candidate-1', job_id: 'job-1', candidate_ip: '203.0.113.10', severity: 'HIGH', score: 80, evidence: [], threat_intelligence: { status: recovered ? 'COMPLETED' : 'PENDING', providers: {} } }
      : { error: { message: 'Temporary candidate refresh failure' } }) });
  });
  await page.route('**/api/v1/candidates/candidate-1/verdicts', async route => {
    writes++;
    expect(route.request().postDataJSON().note).toBe('Owned validation draft');
    await pending;
    await route.fulfill({ status: 200, contentType: 'application/json', body: '{}' });
  });
  await page.goto('/login');
  await page.getByLabel(/^(Username|사용자 이름)$/).fill('analyst');
  await page.getByRole('button', { name: /^(Development login|개발 로그인)$/ }).click();
  await expect(page.getByRole('heading', { name: 'Dashboard', exact: true })).toBeVisible();
  await page.goto('/candidates/candidate-1');
  await page.getByRole('button', { name: '판정 및 외부 검증', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'Selected candidate detail' });
  await dialog.getByLabel('Verdict note').fill('Owned validation draft');
  await dialog.getByRole('button', { name: '판정 저장', exact: true }).click();
  await expect(dialog.getByRole('alert')).toContainText('Candidate refresh failed; retained result may be stale.');
  const retry = dialog.getByRole('button', { name: 'Retry candidate', exact: true });
  await expect(retry).toBeVisible();
  expect(await retry.evaluate(node => node.closest('[inert]') === null)).toBe(true);
  expect(await page.locator('aside').evaluate((node: HTMLElement) => node.inert)).toBe(true);
  await expect(dialog.getByLabel('Verdict note')).toHaveValue('Owned validation draft');
  await expect(dialog.getByRole('button', { name: '저장 중…', exact: true })).toBeDisabled();
  recovered = true;
  await retry.focus(); await page.keyboard.press('Enter');
  await expect(dialog.getByRole('alert')).toHaveCount(0);
  await expect(dialog.getByLabel('Verdict note')).toHaveValue('Owned validation draft');
  settle();
  await expect(dialog.getByRole('status')).toHaveText('Candidate verdict recorded');
  expect(writes).toBe(1);
  await page.keyboard.press('Escape');
  expect(await page.locator('[inert]').count()).toBe(0);
});

for (const width of [1280, 390]) {
  test(`delete confirmation owns keyboard modality at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await installApiFixture(page);
    await page.goto('/login');
    await page.getByLabel(/^(Username|사용자 이름)$/).fill('analyst');
    await page.getByRole('button', { name: /^(Development login|개발 로그인)$/ }).click();
    await expect(page.getByRole('heading', { name: 'Dashboard', exact: true })).toBeVisible();
    await page.goto('/candidates/candidate-1');
    const actions = page.getByRole('button', { name: '점수 조정 및 작업', exact: true });
    await actions.focus(); await page.keyboard.press('Enter');
    const trigger = page.getByRole('button', { name: 'Delete candidate', exact: true });
    await trigger.focus(); await page.keyboard.press('Enter');
    const dialog = page.getByRole('dialog', { name: 'Delete candidate permanently' });
    const cancel = dialog.getByRole('button', { name: 'Cancel', exact: true });
    await expect(cancel).toBeFocused();
    await expect(page.getByRole('dialog')).toHaveCount(1);
    await page.keyboard.press('Tab');
    await expect(dialog.getByRole('button', { name: 'Delete permanently', exact: true })).toBeFocused();
    await page.keyboard.press('Shift+Tab'); await expect(cancel).toBeFocused();
    await actions.evaluate((node: HTMLElement) => node.focus());
    expect(await dialog.evaluate(node => node.contains(document.activeElement))).toBe(true);
    await page.keyboard.press('Escape');
    await expect(dialog).toHaveCount(0); await expect(trigger).toBeFocused();
    await page.keyboard.press('Enter'); await expect(cancel).toBeFocused();
    await page.keyboard.press('Enter'); await expect(dialog).toHaveCount(0); await expect(trigger).toBeFocused();
    await page.keyboard.press('Escape'); await expect(actions).toBeFocused();
    expect(await page.locator('[inert]').count()).toBe(0);
  });
}
