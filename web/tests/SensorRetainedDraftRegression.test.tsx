import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, renderHook } from '@testing-library/react';
import { type ReactNode } from 'react';
import { afterEach, expect, it, vi } from 'vitest';
import { api } from '../src/api';
import { setAuthentication } from '../src/authentication';
import { useSensorConfigurationDraft } from '../src/useSensorConfigurationDraft';

const initial = { config_version: 7, capture_sources: [{ interface: 'eth0', direction: 'INBOUND', bpf_filter: '', enabled: true, store_pcap: false }], internal_networks: ['10.0.0.0/8'] };
afterEach(() => vi.restoreAllMocks());

it.each(['unsaved', 'unconfirmed', 'failed'] as const)('retains %s work after visiting other sensors beyond owner capacity', async mode => {
  setAuthentication('retained-draft-regression');
  const client = new QueryClient();
  const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
  const open = (id: string) => renderHook(() => useSensorConfigurationDraft(id, initial), { wrapper });
  const first = open('sensor-a');
  if (mode === 'unsaved') {
    act(() => first.result.current.update({ internal_networks: ['10.99.0.0/16'] }));
  } else {
    const put = vi.spyOn(api, 'put');
    if (mode === 'unconfirmed') put.mockResolvedValue({});
    else put.mockRejectedValue(new Error('Original save failure'));
    await act(async () => { await first.result.current.save(); });
    expect(first.result.current.error).toBeDefined();
  }
  const retainedNetworks = [...first.result.current.internal_networks];
  const retainedError = first.result.current.error?.message;
  first.unmount();
  for (let index = 0; index < 16; index++) {
    const other = open(`visited-only-${index}`);
    other.unmount();
  }
  const returned = open('sensor-a');
  expect(returned.result.current.internal_networks).toEqual(retainedNetworks);
  expect(returned.result.current.error?.message).toBe(retainedError);
  expect(returned.result.current.config_version).toBe(7);
  expect(returned.result.current.pending).toBe(false);
});
