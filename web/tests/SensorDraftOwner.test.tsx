import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, renderHook } from '@testing-library/react';
import { type ReactNode } from 'react';
import { afterEach, expect, it, vi } from 'vitest';
import { api } from '../src/api';
import { setAuthentication } from '../src/authentication';
import { useSensorConfigurationDraft } from '../src/useSensorConfigurationDraft';

const initial = { config_version: 7, capture_sources: [{ interface: 'eth0', direction: 'INBOUND', bpf_filter: '', enabled: true, store_pcap: false }], internal_networks: ['10.0.0.0/8'] };
function setup(client = new QueryClient()) {
  const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
  return (id: string) => renderHook(() => useSensorConfigurationDraft(id, initial), { wrapper });
}
afterEach(() => vi.restoreAllMocks());

it('caps retained owners at 16 and never evicts a pending operation', async () => {
  setAuthentication('owner-a');
  const open = setup();
  const finishes: ((value: unknown) => void)[] = [];
  vi.spyOn(api, 'put').mockImplementation(() => new Promise(resolve => finishes.push(resolve)));
  for (let i = 0; i < 16; i++) {
    const view = open(`sensor-${i}`);
    act(() => { void view.result.current.save(); });
    view.unmount();
  }
  const blocked = open('sensor-16');
  expect(blocked.result.current.error?.message).toMatch(/16.*pending/);
  await act(async () => { await blocked.result.current.save(); });
  expect(api.put).toHaveBeenCalledTimes(16);
  const first = open('sensor-0');
  expect(first.result.current.pending).toBe(true);
  await act(async () => { finishes[0]({ ...initial, config_version: 8 }); });
  expect(first.result.current.saved).toBe(true);
  expect(first.result.current.config_version).toBe(8);
});

// Unmounted is not completed: unsaved work must never be capacity eviction fodder.
it('retains unsaved idle drafts when the per-client scope reaches 16', () => {
  setAuthentication('owner-a');
  const open = setup();
  for (let i = 0; i < 17; i++) {
    const view = open(`sensor-${i}`);
    act(() => view.result.current.update({ internal_networks: [`10.${i}.0.0/16`] }));
    view.unmount();
  }
  const first = open('sensor-0');
  expect(first.result.current.internal_networks).toEqual(['10.0.0.0/16']);
});

it.each([{}, { ...initial, config_version: 7 }, { ...initial, config_version: 8, capture_sources: [] }, { ...initial, config_version: 8, internal_networks: ['   '] }])('does not label malformed or nonadvancing receipt as saved', async result => {
  setAuthentication('owner-a');
  vi.spyOn(api, 'put').mockResolvedValue(result);
  const view = setup()('sensor-a');
  await act(async () => { await view.result.current.save(); });
  expect(view.result.current.saved).toBe(false);
  expect(view.result.current.config_version).toBe(7);
  expect(view.result.current.error?.message).toMatch(/unconfirmed/i);
});

it('uses latest owned draft and separates failure from prior saved state', async () => {
  setAuthentication('owner-a');
  const put = vi.spyOn(api, 'put').mockResolvedValue({ ...initial, config_version: 8 });
  const view = setup()('sensor-a');
  const retainedSave = view.result.current.save;
  act(() => view.result.current.update({ internal_networks: [' 10.2.0.0/16 '], capture_sources: [{ ...initial.capture_sources[0], interface: 'literal.eth0' }] }));
  await act(async () => { await retainedSave(); });
  expect(put).toHaveBeenLastCalledWith('/sensors/sensor-a/configuration', { ...initial, internal_networks: ['10.2.0.0/16'], capture_sources: [{ ...initial.capture_sources[0], interface: 'literal.eth0' }] });
  put.mockRejectedValueOnce(new Error('current failed'));
  await act(async () => { await view.result.current.save(); });
  expect(view.result.current.saved).toBe(false);
  expect(view.result.current.error?.message).toBe('current failed');
});

it('retires old callbacks and delayed receipts across auth A-B-A, unmount and client replacement', async () => {
  setAuthentication('owner-a');
  let finish!: (result: unknown) => void;
  const put = vi.spyOn(api, 'put').mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  const open = setup();
  const first = open('sensor-a');
  const oldSave = first.result.current.save;
  act(() => { void oldSave(); });
  first.unmount();
  act(() => { setAuthentication('owner-b'); setAuthentication('owner-a'); });
  const fresh = open('sensor-a');
  await act(async () => { finish({ ...initial, config_version: 8 }); await oldSave(); });
  expect(put).toHaveBeenCalledTimes(1);
  expect(fresh.result.current.saved).toBe(false);
  expect(fresh.result.current.pending).toBe(false);
  expect(fresh.result.current.config_version).toBe(7);
  act(() => fresh.result.current.update({ internal_networks: ['10.3.0.0/16'] }));
  const otherClient = setup()('sensor-a');
  expect(otherClient.result.current.internal_networks).toEqual(initial.internal_networks);
});
