import { describe, expect, it, vi } from 'vitest';
import { runPcapExportLifecycle, type PcapExportLifecycleResult } from '../src/pcapExportLifecycle';

const completed = (id = 'id/one'): PcapExportLifecycleResult => ({
  id, status: 'COMPLETED', matched_packet_count: 1, filename: 'capture.pcap',
});

const dependencies = () => ({
  create: vi.fn(async () => completed()),
  poll: vi.fn(async () => completed()),
  cancel: vi.fn(async () => undefined),
  download: vi.fn(async () => undefined),
  wait: vi.fn(async () => undefined),
  onStatus: vi.fn(),
  isCurrent: vi.fn(() => true),
});

describe('runPcapExportLifecycle', () => {
  it('preserves immediate 201 completion and URL-encodes downloads', async () => {
    const deps = dependencies();
    const result = await runPcapExportLifecycle({}, deps);
    expect(result.status).toBe('COMPLETED');
    expect(deps.poll).not.toHaveBeenCalled();
    expect(deps.download).toHaveBeenCalledWith('/pcap-exports/id%2Fone/download', 'capture.pcap');
    expect(deps.cancel).not.toHaveBeenCalled();
  });

  it('records 202 immediately, polls truthful progress, and downloads at completion', async () => {
    const deps = dependencies();
    deps.create.mockResolvedValue({ id: 'async', status: 'QUEUED', progress: { percent: 0 } });
    deps.poll
      .mockResolvedValueOnce({ id: 'async', status: 'RUNNING', progress: { percent: 40 } })
      .mockResolvedValueOnce(completed('async'));
    await runPcapExportLifecycle({}, deps);
    expect(deps.onStatus.mock.calls.map(([value]) => value.status)).toEqual(['QUEUED', 'RUNNING', 'COMPLETED']);
    expect(deps.download).toHaveBeenCalledOnce();
  });

  it('cancels exactly once when superseded during the create acknowledgement race', async () => {
    const deps = dependencies();
    deps.create.mockImplementation(async () => {
      deps.isCurrent.mockReturnValue(false);
      return { id: 'stale', status: 'QUEUED' };
    });
    await expect(runPcapExportLifecycle({}, deps)).rejects.toThrow('superseded');
    expect(deps.cancel).toHaveBeenCalledOnce();
    expect(deps.poll).not.toHaveBeenCalled();
  });

  it('best-effort cancels exactly once after a poll failure', async () => {
    const deps = dependencies();
    deps.create.mockResolvedValue({ id: 'async', status: 'QUEUED' });
    deps.poll.mockRejectedValue(new Error('network down'));
    await expect(runPcapExportLifecycle({}, deps)).rejects.toThrow('network down');
    expect(deps.cancel).toHaveBeenCalledOnce();
  });

  it('does not cancel terminal failed or completed exports', async () => {
    const deps = dependencies();
    deps.create.mockResolvedValue({ id: 'failed', status: 'FAILED', error: 'No match' });
    await expect(runPcapExportLifecycle({}, deps)).rejects.toThrow('No match');
    expect(deps.cancel).not.toHaveBeenCalled();
  });
});
