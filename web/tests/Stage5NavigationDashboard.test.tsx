import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import App from '../src/App';

function renderAt(route: string) {
  localStorage.setItem('c2hunter-token', 'test');
  vi.stubGlobal('matchMedia', vi.fn(() => ({ matches: false })));
  const fetch = vi.fn<(input: RequestInfo | URL) => Promise<Response>>(async () => Response.json({ items: [] }));
  vi.stubGlobal('fetch', fetch);
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={[route]}><App/></MemoryRouter></QueryClientProvider>);
  return fetch;
}

it('separates primary analysis from management while retaining every original route and keyboard access', async () => {
  const fetch = renderAt('/sensors');
  await screen.findByText('표시할 데이터가 없습니다');
  const primary = screen.getByRole('navigation', { name: 'Primary' });
  const management = screen.getByRole('navigation', { name: 'Management' });
  expect(within(primary).getAllByRole('link').map(link => link.getAttribute('href'))).toEqual([
    '/', '/candidates', '/analyses', '/analyses/new', '/analyses/upload', '/sensor-pcaps',
  ]);
  expect(within(management).getAllByRole('link').map(link => link.getAttribute('href'))).toEqual([
    '/sensors', '/external-sensors', '/external-sensors/enroll', '/payload-signatures', '/allowlist', '/settings/integrations',
  ]);
  expect(within(management).getByRole('link', { name: 'Sensors' })).toHaveAttribute('aria-current', 'page');
  const external = within(management).getByRole('link', { name: 'External sensors' });
  external.focus();
  await userEvent.keyboard('{Enter}');
  expect(await screen.findByRole('heading', { name: 'External sensors' })).toBeInTheDocument();
  expect(fetch.mock.calls.map(call => String(call[0]))).toEqual(['/api/v1/sensors', '/api/v1/sensor-enrollments']);
});
