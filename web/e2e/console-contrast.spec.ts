import { expect, test, type Locator, type Page } from '@playwright/test';
import { installApiFixture } from './route-fixture';
import { withLegacyAuthentication } from './auth-fixture';

type Language = 'default-ko' | 'en';

// Exercise the real App and its shipped CSS, with HTTP fixtures only.
// The existing job-1 detail fixture is ANALYZING; the list fixture is COMPLETED.
async function openFixture(page: Page, path: string, language: Language, writes: string[]) {
  await installApiFixture(page);
  await page.route('**/api/v1/**', withLegacyAuthentication(async route => {
    const request = route.request();
    if (!['GET', 'HEAD', 'OPTIONS'].includes(request.method())) {
      writes.push(`${request.method()} ${new URL(request.url()).pathname}`);
      return route.abort('blockedbyclient');
    }
    return route.fallback();
  }));
  await page.addInitScript(language => {
    localStorage.setItem('c2hunter-token', 'console-contrast-fixture');
    // ReportLanguage defaults to Korean when no preference is stored.
    if (language === 'en') localStorage.setItem('c2hunter-report-language', 'en');
    else localStorage.removeItem('c2hunter-report-language');
  }, language);
  await page.goto(path);
}

async function contrast(button: Locator) {
  return button.evaluate(element => {
    const style = getComputedStyle(element);
    const rgb = (value: string) => {
      const match = value.match(/^rgba?\(([^)]+)\)$/);
      if (!match) throw new Error(`Unsupported contrast color: ${value}`);
      const channels = match[1].split(',').map(Number);
      if (channels.length !== 3 && !(channels.length === 4 && channels[3] === 1)) {
        throw new Error(`Contrast requires opaque RGB: ${value}`);
      }
      return channels.slice(0, 3);
    };
    if (style.backgroundImage !== 'none' || style.opacity !== '1') {
      throw new Error('Active danger button must have an opaque, solid background');
    }
    const foreground = rgb(style.color), background = rgb(style.backgroundColor);
    const luminance = (channels: number[]) => channels.map(channel => {
      const value = channel / 255;
      return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
    }).reduce((sum, value, index) => sum + value * [0.2126, 0.7152, 0.0722][index], 0);
    const ratio = (front: number[], back: number[]) => {
      const a = luminance(front), b = luminance(back);
      return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
    };
    // Computed RGB excludes the console's hover brightness filter. Check both
    // the computed color pair and the filtered pair; fail on unsupported paints.
    const brightness = style.filter.match(/^brightness\(([\d.]+)(%)?\)$/);
    if (style.filter !== 'none' && !brightness) throw new Error(`Unsupported filter: ${style.filter}`);
    const factor = brightness ? Number(brightness[1]) / (brightness[2] ? 100 : 1) : 1;
    const filtered = (channels: number[]) => channels.map(channel => Math.min(255, channel * factor));
    return {
      foreground: style.color, background: style.backgroundColor, filter: style.filter,
      ratio: ratio(foreground, background),
      filteredRatio: ratio(filtered(foreground), filtered(background)),
    };
  });
}

async function checkDangerButton(page: Page, button: Locator, width: number) {
  await expect(button).toBeVisible();
  await expect(button).toBeEnabled();
  await expect(button).toHaveClass(/\bdanger\b/);
  await button.scrollIntoViewIfNeeded();
  await page.mouse.move(0, 0);
  expect(await button.evaluate(element => element.matches(':hover'))).toBe(false);
  for (const state of ['default', 'hover'] as const) {
    if (state === 'hover') {
      await button.hover();
      expect(await button.evaluate(element => element.matches(':hover'))).toBe(true);
    }
    const measured = await contrast(button);
    expect.soft(measured.ratio, `${state} computed contrast: ${JSON.stringify(measured)}`).toBeGreaterThanOrEqual(4.5);
    expect.soft(measured.filteredRatio, `${state} filtered contrast: ${JSON.stringify(measured)}`).toBeGreaterThanOrEqual(4.5);
  }
  await page.mouse.move(0, 0);
  await button.focus();
  await page.keyboard.press('Tab');
  await page.keyboard.press('Shift+Tab');
  await expect(button).toBeFocused();
  expect(await button.evaluate(element => element.matches(':focus-visible'))).toBe(true);
  await expect(button).toHaveCSS('outline-style', 'solid');
  expect(await button.evaluate(element => parseFloat(getComputedStyle(element).outlineWidth))).toBeGreaterThanOrEqual(2);
  await expect(button).toBeEnabled();
  if (width === 390) {
    expect(await button.evaluate(element => element.getBoundingClientRect().height)).toBeGreaterThanOrEqual(44);
  }
}

for (const width of [1440, 390]) for (const language of ['default-ko', 'en'] as const) {
  test(`active Cancel analysis contrast ${width} ${language}`, async ({ page }) => {
    const writes: string[] = [];
    await page.setViewportSize({ width, height: 900 });
    try {
      await openFixture(page, '/analyses/job-1', language, writes);
      await expect(page.getByRole('button', {
        name: language === 'en' ? 'Work information' : '작업 정보', exact: true,
      })).toBeVisible();
      // The active C2 summary exposes Cancel without opening Work information.
      const cancel = page.getByRole('button', {
        name: language === 'en' ? 'Cancel analysis' : '분석 취소', exact: true,
      });
      await checkDangerButton(page, cancel, width);
      // Never activate Cancel: enabled styling must not mutate the job.
    } finally {
      expect(writes, 'No API mutation may be attempted').toEqual([]);
    }
  });

  test(`active Delete confirmation contrast ${width} ${language}`, async ({ page }) => {
    const writes: string[] = [];
    await page.setViewportSize({ width, height: 900 });
    try {
      await openFixture(page, '/analyses', language, writes);
      // This existing list action opens a local confirmation, not a DELETE.
      await page.getByRole('button', { name: 'Delete E2E investigation', exact: true }).click();
      const dialog = page.getByRole('dialog', { name: 'Delete analysis', exact: true });
      await expect(dialog).toBeVisible();
      await checkDangerButton(page, dialog.getByRole('button', { name: 'Delete permanently', exact: true }), width);
      // Do not activate the destructive confirmation.
    } finally {
      expect(writes, 'No API mutation may be attempted').toEqual([]);
    }
  });
}
