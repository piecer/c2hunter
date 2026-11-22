import { useLayoutEffect, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from './api';
import { captureAuthentication, currentAuthentication } from './authentication';
import { interpretationPage, readInterpretationRuns, type InterpretationRuns } from './interpretationRuns';

export function useInterpretationRuns<T extends { analysis_kind: string }>(jobId: string, kind: string) {
  const query = useQuery<InterpretationRuns<T>, Error>({ queryKey: ['ai-runs', jobId], queryFn: ({ signal }) => readInterpretationRuns<T>(jobId, kind, signal), retry: false });
  const [continuation, setContinuation] = useState<{ source: unknown; data?: InterpretationRuns<T>; pending?: boolean; error?: boolean }>();
  const live = useRef<object | undefined>(undefined);
  const lock = useRef(false);
  const token = useRef({ data: query.data, updated: query.dataUpdatedAt, fetching: query.isFetching, jobId, kind });
  if (token.current.data !== query.data || token.current.updated !== query.dataUpdatedAt || token.current.fetching !== query.isFetching || token.current.jobId !== jobId || token.current.kind !== kind) {
    token.current = { data: query.data, updated: query.dataUpdatedAt, fetching: query.isFetching, jobId, kind };
    lock.current = false;
  }
  live.current = token.current;
  useLayoutEffect(() => () => { live.current = undefined; }, []);
  const held = continuation?.source === token.current ? continuation : undefined;
  const data = held?.data ?? query.data;
  const continueLookup = async () => {
    const owner = token.current;
    const authentication = captureAuthentication();
    const current = () => live.current === owner && currentAuthentication(authentication);
    if (!current() || lock.current || query.isFetching || data?.discovery !== 'incomplete' || !data.nextPage) return;
    lock.current = true;
    setContinuation({ source: owner, data, pending: true });
    try {
      const page = data.nextPage;
      const raw = await api.get<InterpretationRuns<T>>(`/analysis-jobs/${encodeURIComponent(jobId)}/ai-runs?page=${page}&page_size=${data.page_size}`);
      if (!current()) return;
      const next = interpretationPage(raw, page);
      if (next.discovery === 'unknown' || next.total !== data.total || next.page_size !== data.page_size) throw new Error('Saved pagination changed');
      const latestModule = next.items.find(item => item.analysis_kind === kind);
      setContinuation({ source: owner, data: { ...data, latestModule, discovery: latestModule || page * data.page_size! >= data.total! ? 'resolved' : 'incomplete', nextPage: page + 1 } });
    } catch {
      if (current()) setContinuation({ source: owner, data, error: true });
    } finally { if (current()) lock.current = false; }
  };
  return { ...query, data, continueLookup, continuationPending: held?.pending === true, discoveryError: held?.error === true };
}
