import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Link, MemoryRouter, Route, Routes, useNavigate } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import { useCandidateQueueReturn, useCandidateQueueSelection } from '../src/useCandidateQueueSelection';

it.each(['pointerdown', 'keydown', 'wheel'])('delayed queue return never overrides intervening %s interaction', async event => {
  const scroll = vi.spyOn(window, 'scrollTo').mockImplementation(() => undefined);
  let ready = true;
  function Queue() {
    const queue = useCandidateQueueSelection('queue-heading');
    useCandidateQueueReturn(queue, ready, ready);
    return <><h1 id="queue-heading" tabIndex={-1}>Queue</h1>{ready && <button {...queue.buttonProps('A')}>Preview A</button>}<Link to="/full" onClick={queue.depart}>Full</Link></>;
  }
  function Full() { const navigate = useNavigate(); return <button onClick={() => navigate(-1)}>Back</button>; }
  const client = new QueryClient();
  const tree = () => <QueryClientProvider client={client}><MemoryRouter initialEntries={['/queue']}><Routes><Route path="/queue" element={<Queue/>}/><Route path="/full" element={<Full/>}/></Routes></MemoryRouter></QueryClientProvider>;
  const mounted = render(tree());
  await userEvent.click(screen.getByRole('button', { name: 'Preview A' }));
  await userEvent.click(screen.getByRole('link', { name: 'Full' }));
  ready = false;
  await userEvent.click(screen.getByRole('button', { name: 'Back' }));
  const before = scroll.mock.calls.length;
  fireEvent(document, new Event(event, { bubbles: true }));
  ready = true;
  await act(async () => { mounted.rerender(tree()); });
  expect(document.body).toHaveFocus();
  expect(scroll.mock.calls.length).toBe(before);
});
