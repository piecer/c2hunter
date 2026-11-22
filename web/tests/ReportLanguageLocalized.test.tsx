import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { expect, it, vi } from 'vitest';
import ReportLanguageScope from '../src/ReportLanguage';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import DDoSNormalReference from '../src/DDoSNormalReference';

it.each([null, 'ko', 'en', 'invalid'])('uses one exact locale label and the same control in both directions: %s', async stored => {
  if (stored !== null) localStorage.setItem('c2hunter-report-language', stored);
  const user = userEvent.setup();
  render(<ReportLanguageScope><p>Stored English model prose.</p></ReportLanguageScope>);
  const start = stored === 'en' ? 'en' : 'ko';
  const control = screen.getByRole('combobox', { name: start === 'ko' ? '보고서 언어' : 'Report language' });
  expect(screen.getAllByRole('combobox')).toHaveLength(1);
  expect(within(control).getByRole('option', { name: '한국어' })).toHaveValue('ko');
  expect(within(control).getByRole('option', { name: 'English' })).toHaveValue('en');
  for (const language of start === 'ko' ? ['en', 'ko'] : ['ko', 'en']) {
    await user.selectOptions(control, language);
    expect(screen.getByRole('combobox', { name: language === 'ko' ? '보고서 언어' : 'Report language' })).toBe(control);
    expect(control).toHaveValue(language);
    expect(control).toHaveFocus();
    expect(screen.queryByRole('combobox', { name: language === 'ko' ? 'Report language' : '보고서 언어' })).not.toBeInTheDocument();
    expect(localStorage.getItem('c2hunter-report-language')).toBe(language);
    expect(screen.getByText('Stored English model prose.', { exact: true })).toBeVisible();
  }
});

it('defaults to Korean and switches without readable or writable optional storage', async () => {
  vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new Error('storage refused'); });
  vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('storage refused'); });
  const user = userEvent.setup();
  render(<ReportLanguageScope>{null}</ReportLanguageScope>);
  const control = screen.getByRole('combobox', { name: '보고서 언어' });
  expect(control).toHaveValue('ko');
  await user.selectOptions(control, 'en');
  expect(screen.getByRole('combobox', { name: 'Report language' })).toBe(control);
  await user.selectOptions(control, 'ko');
  expect(screen.getByRole('combobox', { name: '보고서 언어' })).toBe(control);
});

it('keeps mounted independent scopes independent when one chooser changes', async () => {
  const user = userEvent.setup();
  render(<><section aria-label="primary"><ReportLanguageScope>{null}</ReportLanguageScope></section><section aria-label="independent"><ReportLanguageScope>{null}</ReportLanguageScope></section></>);
  const primary = within(screen.getByRole('region', { name: 'primary' }));
  const independent = within(screen.getByRole('region', { name: 'independent' }));
  await user.selectOptions(primary.getByRole('combobox', { name: '보고서 언어' }), 'en');
  expect(primary.getByRole('combobox', { name: 'Report language' })).toHaveValue('en');
  expect(independent.getByRole('combobox', { name: '보고서 언어' })).toHaveValue('ko');
});

it('preserves the actual normal-reference local choice independently of the report scope', async () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const fetch = vi.fn();
  vi.stubGlobal('fetch', fetch);
  const user = userEvent.setup();
  const view = render(<QueryClientProvider client={client}><ReportLanguageScope><section aria-label="normal reference"><DDoSNormalReference inherit datasetId="dataset"/></section></ReportLanguageScope></QueryClientProvider>);
  try {
    const independent = within(screen.getByRole('region', { name: 'normal reference' }));
    const outer = screen.getAllByRole('combobox', { name: '보고서 언어' })[0];
    await user.selectOptions(independent.getByRole('combobox', { name: '정상 참조 작업' }), 'clear');
    await user.selectOptions(outer, 'en');
    expect(outer).toHaveAccessibleName('Report language');
    expect(independent.getByRole('combobox', { name: '보고서 언어' })).toHaveValue('ko');
    expect(independent.getByRole('combobox', { name: '정상 참조 작업' })).toHaveValue('clear');
    await user.selectOptions(independent.getByRole('combobox', { name: '보고서 언어' }), 'en');
    await user.selectOptions(outer, 'ko');
    expect(independent.getByRole('combobox', { name: 'Report language' })).toHaveValue('en');
    expect(independent.getByRole('combobox', { name: 'Normal reference action' })).toHaveValue('clear');
    expect(outer).toHaveAccessibleName('보고서 언어');
    expect(fetch).not.toHaveBeenCalled();
  } finally { view.unmount(); client.clear(); }
});
