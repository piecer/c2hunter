import type { QueryClient } from '@tanstack/react-query';
import { ApiError } from './api';

export type DetailSource = { id: string; job_id?: string; candidate_ip: string; evidence?: unknown[]; traffic_buckets?: unknown[] };
export type FocusTarget = { tag: string; label: string | null; text: string | null };
export type DetailSnapshot = { focus?: FocusTarget; x: number; y: number; detailY: number };
export type DetailHistoryEntry = {
  retired: boolean; flowRetired: boolean; evidenceInvalid?: boolean;
  candidateId?: string; jobId?: string; ip?: string; evidenceIdentity?: string;
  flowId?: string; flowPage?: number; opener?: FocusTarget; snapshot?: DetailSnapshot;
};
export const DETAIL_HISTORY_CAPACITY = 50;
const retiredError = (error: unknown) => error instanceof ApiError && [403, 404, 410].includes(error.status);

/** One FIFO budget per client/auth scope, never a per-candidate map. Entries
 * contain descriptors only. The bounded weak identity index cannot keep evidence
 * alive; it is pruned synchronously, without waiting for garbage collection.
 * Mutation owners and their authority callbacks are deliberately NOT stored here.
 */
class DetailHistory {
  readonly entries = new Map<string, DetailHistoryEntry>();
  readonly evidenceIdentities = new Map<string, WeakRef<object>>();
  constructor(public epoch: number) {}

  pruneIdentities() {
    const used = new Set(Array.from(this.entries.values(), entry => entry.evidenceIdentity));
    for (const key of this.evidenceIdentities.keys()) if (!used.has(key)) this.evidenceIdentities.delete(key);
  }
  create(opener?: FocusTarget) {
    const key = crypto.randomUUID();
    if (this.entries.size === DETAIL_HISTORY_CAPACITY) this.entries.delete(this.entries.keys().next().value!);
    this.entries.set(key, { retired: false, flowRetired: false, opener });
    this.pruneIdentities();
    return key;
  }
  retire(key: string, evidenceInvalid = false) {
    if (this.entries.has(key)) this.entries.set(key, { retired: true, flowRetired: true, evidenceInvalid });
    this.pruneIdentities();
  }
  retireFlow(key: string) {
    const entry = this.entries.get(key);
    if (entry) { entry.flowRetired = true; delete entry.flowId; delete entry.flowPage; delete entry.snapshot; }
  }
  bind(key: string, source: DetailSource) {
    const entry = this.entries.get(key);
    if (!entry || entry.retired) return;
    if (entry.candidateId !== undefined) {
      const changed = entry.evidenceIdentity ? this.evidenceIdentities.get(entry.evidenceIdentity)?.deref() !== source.evidence : source.evidence !== undefined;
      if (entry.candidateId !== source.id || entry.jobId !== source.job_id || entry.ip !== source.candidate_ip || changed) this.retire(key, changed);
      return;
    }
    entry.candidateId = source.id; entry.jobId = source.job_id; entry.ip = source.candidate_ip;
    if (source.evidence) {
      let identity = Array.from(this.evidenceIdentities).find(([, ref]) => ref.deref() === source.evidence)?.[0];
      if (!identity) { identity = crypto.randomUUID(); this.evidenceIdentities.set(identity, new WeakRef(source.evidence)); }
      entry.evidenceIdentity = identity;
    }
  }
}
const histories = new WeakMap<QueryClient, DetailHistory>();

export function candidateDetailHistory(client: QueryClient, epoch: number) {
  let history = histories.get(client);
  if (!history) {
    const created = new DetailHistory(epoch);
    history = created;
    histories.set(client, created);
    // Observe authoritative changes even while a different application route is
    // mounted. No retained source object or per-entry callback is captured.
    client.getQueryCache().subscribe(event => {
      const { queryKey, state } = event.query;
      if (queryKey[0] !== 'candidate' && queryKey[0] !== 'candidate-flows') return;
      for (const [key, entry] of created.entries) {
        if (entry.retired) continue;
        if (queryKey[0] === 'candidate' && entry.candidateId === queryKey[1]) {
          if (event.type === 'removed' || retiredError(state.error)) created.retire(key);
          else if (state.data) created.bind(key, state.data as DetailSource);
        } else if (queryKey[0] === 'candidate-flows' && entry.flowId && entry.jobId === queryKey[1] && entry.ip === queryKey[2] && entry.flowPage === queryKey[3]) {
          const data = state.data as { page?: number; items?: { flow_id: string; job_id: string }[] } | undefined;
          if (event.type === 'removed' || retiredError(state.error) || (data && ((data.page !== undefined && data.page !== entry.flowPage) || !data.items?.some(flow => flow.flow_id === entry.flowId && flow.job_id === entry.jobId)))) created.retireFlow(key);
        }
      }
    });
  }
  if (history.epoch !== epoch) { history.entries.clear(); history.evidenceIdentities.clear(); history.epoch = epoch; }
  return history;
}

/** Called only by a current global preview after its bounded error body is read.
 * Keep the historical summary, but revoke both cached authority and every old
 * selection. Cancel reads before publication: even a transport ignoring abort
 * cannot let its old retryer overwrite the definitive error with stale success.
 * This does not touch mutations or flow-review business owners.
 */
export function retireCandidateSource(client: QueryClient, epoch: number, id: string, error: ApiError) {
  const history = candidateDetailHistory(client, epoch);
  for (const [key, entry] of history.entries) if (entry.candidateId === id) history.retire(key);
  const queryKey = ['candidate', id];
  void client.cancelQueries({ queryKey, exact: true }, { silent: true, revert: false });
  client.getQueryCache().find({ queryKey, exact: true })?.setState({ error, status: 'error', fetchStatus: 'idle', isInvalidated: true });
}

export function focusTarget(element: HTMLElement | null): FocusTarget | undefined {
  if (!element) return;
  const label = element.getAttribute('aria-label'); const text = element.textContent;
  // A focus descriptor must not copy a raw report or a long evidence value.
  if ((label?.length ?? 0) > 256 || (!label && (text?.length ?? 0) > 256)) return;
  return { tag: element.tagName, label, text: label ? null : text };
}
export function resolveFocus(target?: FocusTarget) {
  if (!target) return null;
  return Array.from(document.querySelectorAll<HTMLElement>('button, select, input, textarea, summary, [tabindex]')).find(element => element.tagName === target.tag && (target.label ? element.getAttribute('aria-label') === target.label : element.textContent === target.text)) ?? null;
}
