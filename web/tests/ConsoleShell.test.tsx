import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import App from '../src/App';

it('offers a keyboard skip link targeting the existing focusable main landmark', async () => {
  localStorage.setItem('c2hunter-token', 'test');
  vi.stubGlobal('fetch', vi.fn(async () => Response.json({ items: [] })));
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
    <MemoryRouter initialEntries={['/sensors']}><App/></MemoryRouter>
  </QueryClientProvider>);
  await screen.findByText('표시할 데이터가 없습니다');
  expect(screen.getByRole('link', { name: '본문으로 건너뛰기 / Skip to content' })).toHaveAttribute('href', '#main-content');
  expect(screen.getByRole('main')).toHaveAttribute('id', 'main-content');
  expect(screen.getByRole('main')).toHaveAttribute('tabindex', '-1');
});
