import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, renderHook } from '@testing-library/react';
import { type ReactNode } from 'react';
import { afterEach, expect, it, vi } from 'vitest';
import { api } from '../src/api';
import { setAuthentication } from '../src/authentication';
import { useSensorConfigurationDraft } from '../src/useSensorConfigurationDraft';

const initial = { config_version: 7, capture_sources: [{ interface: 'eth0', direction: 'INBOUND', bpf_filter: '', enabled: true, store_pcap: false }], internal_networks: ['10.0.0.0/8'] };
function setup() {
  setAuthentication('capacity-synthetic');
  const client = new QueryClient();
  const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
  return (id: string) => renderHook(() => useSensorConfigurationDraft(id, initial), { wrapper });
}
afterEach(() => vi.restoreAllMocks());

it.each(['save', 'reload'] as const)('refuses the seventeenth protected owner with server facts and recovers after validated %s', async operation => {
  const open = setup();
  const put = vi.spyOn(api, 'put').mockResolvedValue({ ...initial, config_version: 8 });
  const get = vi.spyOn(api, 'get').mockResolvedValue({ ...initial, config_version: 9 });
  for (let i = 0; i < 16; i++) {
    const view = open(`sensor-${i}`);
    act(() => view.result.current.update({ internal_networks: [`10.${i}.0.0/16`] }));
    view.unmount();
  }
  const blocked = open('sensor-16');
  expect(blocked.result.current.config_version).toBe(7);
  expect(blocked.result.current.internal_networks).toEqual(initial.internal_networks);
  expect(blocked.result.current.error?.message).toMatch(/16.*unsaved.*pending/);
  expect(blocked.result.current.error?.message).toMatch(/reload.*discard/i);
  act(() => blocked.result.current.update({ internal_networks: ['invalid'] }));
  await act(async () => { await blocked.result.current.save(); await blocked.result.current.reload(); });
  expect(put).not.toHaveBeenCalled(); expect(get).not.toHaveBeenCalled();
  blocked.unmount();
  const first = open('sensor-0');
  expect(first.result.current.internal_networks).toEqual(['10.0.0.0/16']);
  await act(async () => { await first.result.current[operation](); });
  expect(first.result.current.error).toBeUndefined();
  first.unmount();
  const admitted = open('sensor-16');
  act(() => admitted.result.current.update({ internal_networks: ['10.16.0.0/16'] }));
  expect(admitted.result.current.internal_networks).toEqual(['10.16.0.0/16']);
  for (let i = 1; i < 16; i++) {
    const retained = open(`sensor-${i}`);
    expect(retained.result.current.internal_networks).toEqual([`10.${i}.0.0/16`]);
    retained.unmount();
  }
});

it.each(['failed save', 'unconfirmed save', 'failed reload', 'unconfirmed reload', 'validation'] as const)('keeps %s unresolved across edits and capacity pressure', async mode => {
  const open = setup(), first = open('sensor-a');
  vi.spyOn(api, 'put').mockImplementation(() => mode === 'failed save' ? Promise.reject(new Error('save rejected')) : Promise.resolve({}));
  vi.spyOn(api, 'get').mockImplementation(() => mode === 'failed reload' ? Promise.reject(new Error('reload rejected')) : Promise.resolve({}));
  if (mode === 'validation') act(() => first.result.current.update({ internal_networks: [''] }));
  await act(async () => { await first.result.current[mode.includes('reload') ? 'reload' : 'save'](); });
  const message = first.result.current.error?.message;
  expect(message).toBeTruthy();
  act(() => first.result.current.update({ internal_networks: ['10.99.0.0/16'] }));
  expect(first.result.current.error?.message).toBe(message);
  first.unmount();
  for (let i = 0; i < 18; i++) { const other = open(`sensor-${i}`); other.unmount(); }
  const returned = open('sensor-a');
  expect(returned.result.current.internal_networks).toEqual(['10.99.0.0/16']);
  expect(returned.result.current.error?.message).toBe(message);
  expect(returned.result.current.config_version).toBe(7);
});

it('retains dirty work and the error when an unmounted pending request fails', async () => {
  const open = setup(), first = open('sensor-a');
  let reject!: (error: Error) => void;
  vi.spyOn(api, 'put').mockImplementation(() => new Promise((_resolve, fail) => { reject = fail; }));
  act(() => first.result.current.update({ internal_networks: ['10.99.0.0/16'] }));
  act(() => { void first.result.current.save(); });
  first.unmount();
  for (let i = 0; i < 18; i++) { const other = open(`sensor-${i}`); other.unmount(); }
  await act(async () => { reject(new Error('delayed failure')); });
  for (let i = 18; i < 36; i++) { const other = open(`sensor-${i}`); other.unmount(); }
  const returned = open('sensor-a');
  expect(returned.result.current.pending).toBe(false);
  expect(returned.result.current.error?.message).toBe('delayed failure');
  expect(returned.result.current.internal_networks).toEqual(['10.99.0.0/16']);
});

it.each(['read only', 'save', 'reload'] as const)('evicts only clean idle owners after %s and retires their old callbacks', async mode => {
  const open = setup(), first = open('sensor-a');
  const put = vi.spyOn(api, 'put').mockResolvedValue({ ...initial, config_version: 8 });
  vi.spyOn(api, 'get').mockResolvedValue({ ...initial, config_version: 9 });
  if (mode !== 'read only') {
    act(() => first.result.current.update({ internal_networks: ['10.99.0.0/16'] }));
    await act(async () => { await first.result.current[mode](); });
  }
  const stale = first.result.current;
  first.unmount();
  for (let i = 0; i < 16; i++) { const other = open(`sensor-${i}`); other.unmount(); }
  const count = put.mock.calls.length;
  await act(async () => { stale.update({ internal_networks: ['stale'] }); await stale.save(); await stale.reload(); });
  expect(put).toHaveBeenCalledTimes(count);
  const returned = open('sensor-a');
  expect(returned.result.current.config_version).toBe(7);
  expect(returned.result.current.internal_networks).toEqual(initial.internal_networks);
  expect(returned.result.current.error).toBeUndefined();
});
