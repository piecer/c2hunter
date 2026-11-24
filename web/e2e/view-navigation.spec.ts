import { withLegacyAuthentication } from './auth-fixture';
import { expect, test } from '@playwright/test';

for (const kind of ['candidates', 'analyses'] as const) {
  for (const retained of [true, false]) {
    for (const choice of ['focused', 'blurred', 'untouched'] as const) {
      test(`${kind}: uncached Back with ${choice} filter when invoker is ${retained ? 'retained' : 'removed'}`, async ({ page }) => {
        await page.addInitScript(() => localStorage.setItem('c2hunter-token', 'navigation-fixture'));
        await page.clock.install({ time: new Date('2026-11-15T00:00:00Z') });
        let reads = 0;
        let release!: () => void;
        const delayed = new Promise<void>(resolve => { release = resolve; });
        const root = kind === 'candidates' ? '/api/v1/candidates' : '/api/v1/analysis-jobs';
        const rows = Array.from({ length: 50 }, (_, index) => ({ id: `uncached-${index}`, name: `Uncached investigation ${index}`, candidate_ip: `203.0.113.${index + 1}`, status: 'COMPLETED', score: 80, severity: 'HIGH', candidate_count: 0 }));
        const row = rows[30];
        await page.route('**/api/v1/**', withLegacyAuthentication(async route => {
          const path = new URL(route.request().url()).pathname;
          if (path === root) {
            const read = ++reads;
            if (read > 1) await delayed;
            const items = read === 1 || retained ? rows : rows.filter(item => item.id !== row.id);
            return route.fulfill({ json: { items, page: 1, page_size: 50, total: items.length } });
          }
          return route.fulfill({ json: path === `${root}/${row.id}` ? row : { items: [], total: 0, page: 1, page_size: 25 } });
        }));
        await page.goto(`/${kind}`);
        const invoker = page.getByRole('link', { name: kind === 'candidates' ? row.candidate_ip : row.name, exact: true });
        await invoker.scrollIntoViewIfNeeded();
        const savedTop = await page.evaluate(() => window.scrollY);
        expect(savedTop).toBeGreaterThan(500);
        await invoker.click();
        await expect(page.getByRole('heading', { name: kind === 'candidates' ? row.candidate_ip : row.name, exact: true })).toBeVisible();
        // main.tsx leaves gcTime unset. Installed Query v5 collects idle,
        // unobserved queries after five minutes; staleTime alone is NOT eviction.
        await page.clock.fastForward(300_001);
        const refresh = page.waitForRequest(request => new URL(request.url()).pathname === root);
        await page.goBack();
        await refresh;
        // A cached/stale list would still contain the invoker during this barrier.
        await expect(invoker).toHaveCount(0);
        await expect(page.getByRole('table')).toHaveCount(0);
        const filter = page.getByLabel(kind === 'candidates' ? 'Minimum score' : 'Search', { exact: true });
        if (choice !== 'untouched') {
          await filter.fill(kind === 'candidates' ? '42' : 'local draft');
          await expect(filter).toBeFocused();
          if (choice === 'blurred') await filter.blur();
        }
        await expect(invoker).toHaveCount(0);
        await expect(page.getByRole('table')).toHaveCount(0);
        const chosenTop = await page.evaluate(() => window.scrollY);
        expect(chosenTop).not.toBe(savedTop);
        release();
        await expect(page.getByRole('table')).toBeVisible();
        await expect(invoker).toHaveCount(retained ? 1 : 0);
        if (choice === 'untouched') {
          const target = retained ? invoker : page.getByRole('heading', { name: kind === 'candidates' ? 'Candidates' : 'Analysis history', exact: true });
          await expect(target).toBeFocused();
          if (retained) await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(savedTop);
        } else {
          if (choice === 'focused') await expect(filter).toBeFocused();
          else await expect(page.locator('body')).toBeFocused();
          await expect(filter).toHaveValue(kind === 'candidates' ? '42' : 'local draft');
          await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(chosenTop);
        }
        expect(reads).toBe(2);
      });
    }
  }

  test(`${kind}: a delayed refreshed page losing its invoker restores the stable list heading`, async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem('c2hunter-token', 'navigation-fixture'));
    await page.clock.setFixedTime(new Date('2026-11-15T00:00:00Z'));
    let reads = 0;
    let release!: () => void;
    const delayed = new Promise<void>(resolve => { release = resolve; });
    const root = kind === 'candidates' ? '/api/v1/candidates' : '/api/v1/analysis-jobs';
    const row = { id: 'deleted-row', name: 'Deleted investigation', candidate_ip: '203.0.113.88', status: 'COMPLETED', score: 80, severity: 'HIGH', candidate_count: 0 };
    await page.route('**/api/v1/**', withLegacyAuthentication(async route => {
      const path = new URL(route.request().url()).pathname;
      if (path === root) {
        reads++;
        if (reads > 1) await delayed;
        return route.fulfill({ json: { items: reads === 1 ? [row] : [], page: 1, page_size: 50, total: reads === 1 ? 1 : 0 } });
      }
      return route.fulfill({ json: path === `${root}/${row.id}` ? row : { items: [], total: 0, page: 1, page_size: 25 } });
    }));
    await page.goto(`/${kind}`);
    const invoker = page.getByRole('link', { name: kind === 'candidates' ? row.candidate_ip : row.name, exact: true });
    await invoker.click();
    await expect(page.getByRole('heading', { name: kind === 'candidates' ? row.candidate_ip : row.name, exact: true })).toBeVisible();
    // Expire the real app's ten-second cache clock, without sleeping or changing its policy.
    await page.clock.setFixedTime(new Date('2026-11-15T00:00:11Z'));
    const refresh = page.waitForRequest(request => new URL(request.url()).pathname === root);
    await page.goBack();
    await refresh;
    await expect(invoker).toBeFocused();
    release();
    await expect(invoker).toHaveCount(0);
    await expect(page.getByRole('heading', { name: kind === 'candidates' ? 'Candidates' : 'Analysis history', exact: true })).toBeFocused();
  });

  test(`${kind}: ordinary Back restores page, applied filters, invoker and scroll with both destinations cached`, async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem('c2hunter-token', 'navigation-fixture'));
    const writes: string[] = [];
    const detailReads: string[] = [];
    const rows = Array.from({ length: 151 }, (_, index) => ({ id: `record-${index + 1}`, name: `Stored investigation ${index + 1}`, candidate_ip: `203.0.113.${index + 1}`, score: 80, severity: 'HIGH', status: 'COMPLETED', candidate_count: 0 }));
    await page.route('**/api/v1/**', withLegacyAuthentication(async route => {
      const url = new URL(route.request().url());
      if (route.request().method() !== 'GET') writes.push(url.pathname);
      const root = kind === 'candidates' ? '/api/v1/candidates' : '/api/v1/analysis-jobs';
      let body: unknown = { items: [], page: 1, page_size: 25, total: 0 };
      if (url.pathname === root) {
        const current = Number(url.searchParams.get('page') || 1);
        body = { items: rows.slice((current - 1) * 50, current * 50), page: current, page_size: 50, total: rows.length };
      } else if (rows.some(row => `${root}/${row.id}` === url.pathname)) {
        detailReads.push(url.pathname);
        body = rows.find(row => `${root}/${row.id}` === url.pathname);
      }
      await route.fulfill({ json: body });
    }));
    const listURL = kind === 'candidates' ? '/candidates?page=2&severity=HIGH&sort=-score' : '/analyses?page=2&search=Stored&status=COMPLETED&sort=name';
    await page.goto(listURL);
    const name = (index: number) => kind === 'candidates' ? rows[index - 1].candidate_ip : rows[index - 1].name;
    // Prime A and B using actual user navigation, then repeat A/B/A with both in Query cache.
    for (const index of [80, 81, 80, 81, 80]) {
      const invoker = page.getByRole('link', { name: name(index), exact: true });
      await invoker.scrollIntoViewIfNeeded();
      await invoker.focus();
      const top = await page.evaluate(() => window.scrollY);
      expect(top).toBeGreaterThan(500);
      await invoker.click();
      await expect(page.getByRole('heading', { name: name(index), exact: true })).toBeVisible();
      await expect(page.getByRole('heading', { name: name(index === 80 ? 81 : 80), exact: true })).toHaveCount(0);
      await page.goBack();
      await expect(page).toHaveURL(new RegExp(listURL.replace(/[?]/g, '\\?') + '$'));
      await expect(invoker).toBeFocused();
      await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(top);
      if (kind === 'candidates') await expect(page.getByRole('combobox', { name: /^Severity/ })).toHaveValue('HIGH');
      else await expect(page.getByLabel('Search', { exact: true })).toHaveValue('Stored');
    }
    expect(detailReads.some(path => path.endsWith('/record-80'))).toBe(true);
    expect(detailReads.some(path => path.endsWith('/record-81'))).toBe(true);
    expect(writes).toEqual([]);
  });
}
