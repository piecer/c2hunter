import { createContext, useContext, useLayoutEffect, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from './api';
import { matchingInterpretationRecord } from './interpretationRuns';
import { captureAuthentication, currentAuthentication } from './authentication';
export type InterpretationRun = { id: string; analysis_kind: string; status: string; language: 'ko' | 'en'; created_at?: string; analysis_job_id?: string; dataset_id?: string };
export function newerInterpretationRun<T extends InterpretationRun>(candidate: T, previous?: T, orderedRuns?: T[]): T {
  if (!previous || candidate.id === previous.id) return candidate;
  const a = Date.parse(candidate.created_at ?? ''), b = Date.parse(previous.created_at ?? '');
  if (Number.isFinite(a) && Number.isFinite(b) && a !== b) return a > b ? candidate : previous;
  return !orderedRuns || orderedRuns.some(run => run.id === previous.id) ? candidate : previous;
}
export const CANCELLATION_RECEIPT_CAP = 4;
export type CancellationReceipt = { run: InterpretationRun; state: 'pending' | 'unconfirmed' | 'acknowledged' | 'reconciled'; acknowledged: boolean; reconciliation?: 'pending' | 'unknown' | 'active' | 'terminal' | 'terminal-unacknowledged' };
type Destination = { remote: boolean; destination?: string | null; provider?: string; model_name?: string };
type Request = { destination?: Destination; current: () => boolean; knownRunId?: string; body: { idempotency_key: string; analysis_kind: string; language: 'ko' | 'en'; allow_remote: boolean } };
export function useLocalInterpretationAdmission(jobId: string, kind: string, enabled = true) {
  const [authentication] = useState(captureAuthentication);
  const [ownerJob] = useState(jobId);
  const mounted = useRef(true);
  useLayoutEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const current = () => enabled && mounted.current && ownerJob === jobId && currentAuthentication(authentication);
  const client = useQueryClient();
  const admission = useRef(false);
  // Fixed metadata-only receipts; no silent eviction of unresolved work.
  const receiptsRef = useRef<CancellationReceipt[]>([]);
  const [cancellationReceipts, setCancellationReceipts] = useState<CancellationReceipt[]>([]);
  const publishReceipts = () => { if (current()) setCancellationReceipts([...receiptsRef.current]); };
  const [knownRun, setKnownRun] = useState<InterpretationRun>();
  const statusQuery = useQuery<InterpretationRun, Error>({
    queryKey: ['ai-run', knownRun?.id],
    enabled: Boolean(knownRun && current()), retry: false,
    queryFn: async ({ signal }) => {
      if (!current() || signal.aborted) throw new Error('Status owner retired');
      const value = await api.get<InterpretationRun>(`/ai-runs/${encodeURIComponent(knownRun!.id)}`);
      if (!current() || signal.aborted) throw new Error('Status owner retired');
      return value;
    },
    refetchInterval: query => {
      if (!current() || !knownRun || query.state.error) return false;
      const observed = matchingInterpretationRecord(query.state.data, knownRun, jobId);
      // A failed/malformed observation stays unknown until explicit GET retry;
      // parent-report failure alone does not stop a valid active status owner.
      return observed && ['QUEUED', 'PREPARING', 'ANALYZING', 'VALIDATING'].includes(observed.status) ? 2000 : false;
    },
  });
  const observed = knownRun && statusQuery.isSuccess ? matchingInterpretationRecord(statusQuery.data, knownRun, jobId) : undefined;
  const active = Boolean(observed && ['QUEUED', 'PREPARING', 'ANALYZING', 'VALIDATING'].includes(observed.status));
  const retryStatus = () => { if (current() && knownRun && !statusQuery.isFetching) void statusQuery.refetch(); };
  const [selectedId, setSelectedId] = useState<string>();

  const retryAdmissionLock = useRef(false);
  const [admissionRecovery, setAdmissionRecovery] = useState<'pending' | 'blocked'>();
  const start = useMutation({
    retry: false,
    onMutate: (request: Request) => ({ knownRunId: request.knownRunId }),
    mutationFn: async (request: Request) => {
      if (!current() || !request.current()) throw new Error('Request owner retired');
      const receipt = await api.post<InterpretationRun>(`/analysis-jobs/${encodeURIComponent(jobId)}/ai-runs`, request.body);
      if (!receipt || typeof receipt.id !== 'string' || !receipt.id || receipt.analysis_kind !== kind || !['QUEUED', 'PREPARING', 'ANALYZING', 'VALIDATING', 'COMPLETED', 'FAILED', 'CANCELLED'].includes(receipt.status) || receipt.language !== request.body.language || receipt.id.length > 200 || Object.hasOwn(receipt, 'analysis_job_id') && receipt.analysis_job_id !== jobId) throw new Error('AI admission receipt could not be confirmed');
      return receipt;
    },
    onSuccess: async (created, _request, context) => {
      if (!current()) return;
      admission.current = false;
      setKnownRun(previous => previous && previous.id !== context.knownRunId ? newerInterpretationRun(previous, created) : newerInterpretationRun(created, previous));
      await client.invalidateQueries({ queryKey: ['ai-runs', jobId] });
    },
  });
  const retryAdmission = async () => {
    const request = start.variables;
    if (!current() || !request || !start.isError || start.isPending || retryAdmissionLock.current) return;
    retryAdmissionLock.current = true; setAdmissionRecovery('pending');
    try {
      // Capabilities expose only the configured origin, not an immutable server
      // destination token. Compare that exact contract; never add a DTO field.
      const capability = await api.get<Destination & { available: boolean; network_interpretation: boolean; ddos_interpretation: boolean }>('/ai-capabilities');
      if (!current()) return;
      const captured = request.destination;
      if (!captured || !capability || !capability.available || !(kind === 'NETWORK_ANOMALY' ? capability.network_interpretation : capability.ddos_interpretation)
        || capability.remote !== captured.remote || capability.destination !== captured.destination || capability.provider !== captured.provider || capability.model_name !== captured.model_name
        || captured.remote && (!request.body.allow_remote || !captured.destination)) { setAdmissionRecovery('blocked'); return; }
      await start.mutateAsync(request);
      if (current()) setAdmissionRecovery(undefined);
    } catch { if (current()) setAdmissionRecovery('blocked'); }
    finally { retryAdmissionLock.current = false; }
  };
  const ownsReceipt = (held: CancellationReceipt) => current() && receiptsRef.current.includes(held);
  const cancelTransport = useMutation({
    retry: false,
    mutationFn: (request: { held: CancellationReceipt; current: () => boolean }) => {
      if (!ownsReceipt(request.held) || !request.current()) throw new Error('Request owner retired');
      return api.post<InterpretationRun>(`/ai-runs/${encodeURIComponent(request.held.run.id)}/cancel`, { reason: 'operator requested from web console' });
    },
    onSuccess: async (value, request) => {
      const held = request.held;
      if (!ownsReceipt(held)) return;
      const receipt = matchingInterpretationRecord(value, held.run, jobId);
      held.acknowledged = Boolean(receipt && receipt.language === held.run.language);
      held.state = request.current() && held.acknowledged ? 'acknowledged' : 'unconfirmed';
      publishReceipts();
      // Retired source callbacks retain only their identified receipt. They must
      // not invalidate newer source/status observations or release another lock.
      if (held.state === 'acknowledged') await Promise.all([client.invalidateQueries({ queryKey: ['ai-run', held.run.id] }), client.invalidateQueries({ queryKey: ['ai-runs', jobId] })]);
    },
    onError: (_error, request) => {
      if (!ownsReceipt(request.held)) return;
      request.held.state = 'unconfirmed'; publishReceipts();
    },
  });
  const cancellationFor = (id?: string) => {
    const receipt = cancellationReceipts.find(row => row.run.id === id);
    return { pending: receipt?.state === 'pending', blocked: receipt?.state === 'pending' || receipt?.state === 'unconfirmed' || receipt?.reconciliation === 'pending', capacity: !receipt && cancellationReceipts.length >= CANCELLATION_RECEIPT_CAP };
  };
  const requestCancellation = (run: InterpretationRun, sourceCurrent: () => boolean) => {
    const controlled = knownRun && statusQuery.data === undefined && !statusQuery.isError ? knownRun : observed;
    if (!current() || !sourceCurrent() || statusQuery.isError || !controlled || !['QUEUED', 'PREPARING', 'ANALYZING', 'VALIDATING'].includes(controlled.status) || !matchingInterpretationRecord(run, controlled, jobId) || run.language !== controlled.language) return;
    const prior = receiptsRef.current.find(row => row.run.id === run.id);
    if (prior && (prior.state === 'pending' || prior.state === 'unconfirmed' || prior.reconciliation === 'pending')) return;
    if (!prior && receiptsRef.current.length >= CANCELLATION_RECEIPT_CAP) return;
    // Capture only bounded identity metadata, never the source or model output.
    const held: CancellationReceipt = { run: { id: run.id, analysis_kind: kind, language: run.language, status: run.status, ...(run.dataset_id === undefined ? {} : { dataset_id: run.dataset_id }) }, state: 'pending', acknowledged: false };
    receiptsRef.current = prior ? receiptsRef.current.map(row => row === prior ? held : row) : [...receiptsRef.current, held];
    publishReceipts();
    cancelTransport.mutate({ held, current: sourceCurrent });
  };
  const reconcileCancellation = async (held: CancellationReceipt) => {
    if (!ownsReceipt(held) || held.state !== 'unconfirmed' || held.reconciliation === 'pending') return;
    held.reconciliation = 'pending'; publishReceipts();
    try {
      const value = await api.get<InterpretationRun>(`/ai-runs/${encodeURIComponent(held.run.id)}`);
      if (!ownsReceipt(held)) return;
      const verified = matchingInterpretationRecord(value, held.run, jobId);
      if (!verified || verified.language !== held.run.language) { held.reconciliation = 'unknown'; return; }
      const terminal = ['COMPLETED', 'FAILED', 'CANCELLED'].includes(verified.status);
      held.reconciliation = terminal ? held.acknowledged ? 'terminal' : 'terminal-unacknowledged' : 'active';
      held.state = 'reconciled';
      // Publish only this exact read; never reset a shared mutation observer.
      client.setQueryData(['ai-run', held.run.id], value);
    } catch { if (ownsReceipt(held)) held.reconciliation = 'unknown'; }
    finally { if (ownsReceipt(held)) publishReceipts(); }
  };
  const dismissCancellation = (held: CancellationReceipt) => {
    if (!ownsReceipt(held) || !['acknowledged', 'reconciled'].includes(held.state) || held.reconciliation === 'pending') return;
    receiptsRef.current = receiptsRef.current.filter(row => row !== held); publishReceipts();
  };
  return { current, retryAdmission, admissionRecovery, statusQuery, observed, active, retryStatus, reconcileCancellation, dismissCancellation, cancellationReceipts, cancellationFor, requestCancellation, admission, knownRun, setKnownRun, selectedId, setSelectedId, start };
}
type Controller = ReturnType<typeof useLocalInterpretationAdmission>;
export const InterpretationAdmissionContext = createContext<Record<string, Controller> | undefined>(undefined);
export function useInterpretationAdmission(jobId: string, kind: string) {
  const inherited = useContext(InterpretationAdmissionContext);
  const local = useLocalInterpretationAdmission(jobId, kind, !inherited?.[kind]);
  return inherited?.[kind] ?? local;
}
