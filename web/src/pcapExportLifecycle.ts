export type PcapExportLifecycleResult = {
  id: string;
  status: string;
  matched_packet_count?: number;
  exported_packet_count?: number;
  omitted_packet_count?: number;
  omitted_source_capture_count?: number;
  truncated?: boolean;
  truncation_reasons?: string[];
  filename?: string;
  error?: string | null;
  progress?: { phase?: string; percent?: number };
};

type Dependencies = {
  create: (body: unknown) => Promise<PcapExportLifecycleResult>;
  poll: (path: string) => Promise<PcapExportLifecycleResult>;
  cancel: (path: string) => Promise<unknown>;
  download: (path: string, filename: string) => Promise<void>;
  onStatus: (result: PcapExportLifecycleResult) => void;
  isCurrent: () => boolean;
  wait?: (milliseconds: number) => Promise<void>;
  maxPolls?: number;
  pollDelayMilliseconds?: number;
};

const terminal = new Set(['COMPLETED', 'FAILED', 'CANCELLED']);
const truncationReasonLabels: Record<string, string> = {
  OUTPUT_BYTE_LIMIT: 'output byte limit reached',
  SOURCE_BYTE_LIMIT: 'source scan byte limit reached',
  SOURCE_PACKET_LIMIT: 'source scan packet limit reached',
};

function terminalError(result: PcapExportLifecycleResult, fallback: string): Error {
  const reasons = (result.truncation_reasons ?? [])
    .map(reason => truncationReasonLabels[reason] ?? reason)
    .join(', ');
  const message = result.error || fallback;
  return new Error(reasons ? `${message} (${reasons})` : message);
}

export async function runPcapExportLifecycle(
  body: unknown,
  dependencies: Dependencies,
): Promise<PcapExportLifecycleResult> {
  const wait = dependencies.wait ?? (milliseconds => new Promise(resolve => window.setTimeout(resolve, milliseconds)));
  const maxPolls = dependencies.maxPolls ?? 1800;
  const delay = dependencies.pollDelayMilliseconds ?? 1000;
  let exportId: string | undefined;
  let cancelIssued = false;
  let current: PcapExportLifecycleResult | undefined;

  const cancelOnce = async () => {
    if (!exportId || cancelIssued) return;
    cancelIssued = true;
    try {
      await dependencies.cancel(`/pcap-exports/${encodeURIComponent(exportId)}/cancel`);
    } catch {
      // Cancellation is best effort and must not hide the original lifecycle error.
    }
  };

  try {
    // Deliberately no replaceable AbortSignal: an acknowledgement may allocate a durable job.
    current = await dependencies.create(body);
    exportId = current.id;
    if (!dependencies.isCurrent()) {
      await cancelOnce();
      throw new Error('PCAP export was superseded');
    }
    dependencies.onStatus(current);

    for (let poll = 0; !terminal.has(current.status); poll += 1) {
      if (poll >= maxPolls) throw new Error('PCAP export timed out');
      await wait(delay);
      if (!dependencies.isCurrent()) {
        await cancelOnce();
        throw new Error('PCAP export was superseded');
      }
      current = await dependencies.poll(`/pcap-exports/${encodeURIComponent(exportId)}`);
      if (!dependencies.isCurrent()) {
        await cancelOnce();
        throw new Error('PCAP export was superseded');
      }
      dependencies.onStatus(current);
    }

    if (current.status === 'COMPLETED') {
      await dependencies.download(
        `/pcap-exports/${encodeURIComponent(exportId)}/download`,
        current.filename || `c2hunter-${exportId}.pcap`,
      );
      return current;
    }
    if (current.status === 'CANCELLED') throw terminalError(current, 'PCAP export was cancelled');
    throw terminalError(current, 'PCAP export failed');
  } catch (error) {
    if (exportId && current && !terminal.has(current.status)) await cancelOnce();
    throw error;
  }
}
