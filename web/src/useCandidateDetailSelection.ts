import { type RefObject, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { flushSync } from 'react-dom';
import { useLocation, useNavigate } from 'react-router-dom';
import { captureAuthentication } from './authentication';
import { useQueryClient } from '@tanstack/react-query';
import { candidateDetailHistory, focusTarget, resolveFocus, type DetailSource } from './candidateDetailHistory';

const sections = {
  buckets: 'Traffic buckets', network: 'Network context', ai: 'AI assessment',
  validation: '판정 및 외부 검증', flows: 'Flow review', operations: '점수 조정 및 작업', raw: 'Raw candidate',
} as const;
const selectionKeys = ['detail', 'evidence', 'flow'];
const ownedKeys = [...selectionKeys, 'flow_page', 'bucket_page'];
const integer = (value: string | null, minimum: number) => value !== null && /^(0|[1-9][0-9]*)$/.test(value) && Number.isSafeInteger(Number(value)) && Number(value) >= minimum;

/** URL values are presentation intent, not membership or mutation authority. */
export function useCandidateDetailSelection(source: DetailSource | undefined, unavailable: boolean, returnFocus: RefObject<HTMLElement | null>) {
  const location = useLocation(); const navigate = useNavigate();
  const [closingEntry, setClosingEntry] = useState<string>();
  const currentLocation = useRef(location);
  currentLocation.current = location;
  const epoch = captureAuthentication().epoch;
  const history = candidateDetailHistory(useQueryClient(), epoch);
  const historyState = useMemo(() => location.state && typeof location.state === 'object' ? location.state : {}, [location.state]);
  const epochMismatch = historyState.candidateDetailEpoch !== undefined && historyState.candidateDetailEpoch !== epoch;
  const initial = useRef<{ locationKey: string; key: string } | undefined>(undefined);
  if (historyState.candidateDetailEntry === undefined && initial.current?.locationKey !== location.key) initial.current = { locationKey: location.key, key: history.create() };
  // Marked but forgotten entries expire; only an unmarked deep link is new.
  const entryKey: string = historyState.candidateDetailEntry ?? initial.current!.key;
  if (source) history.bind(entryKey, source);
  if (unavailable || epochMismatch) history.retire(entryKey);
  const entry = history.entries.get(entryKey);
  useLayoutEffect(() => { returnFocus.current = resolveFocus(history.entries.get(entryKey)?.opener); }, [history, entryKey, returnFocus]);
  useEffect(() => {
    if (historyState.candidateDetailEntry === undefined) navigate(location, { replace: true, state: { ...historyState, candidateDetailEpoch: epoch, candidateDetailEntry: entryKey } });
  }, [location, navigate, epoch, historyState, entryKey]);
  const waiting = useRef(!source);
  waiting.current = !source;
  const deferred = useRef(false);
  const snapshot = () => ({ focus: focusTarget(document.activeElement instanceof HTMLElement ? document.activeElement : null), x: window.scrollX, y: window.scrollY, detailY: document.getElementById('candidate-selected-detail')?.scrollTop ?? 0 });
  const save = () => { const current = history.entries.get(entryKey); if (current && !current.retired) current.snapshot = snapshot(); };
  useEffect(() => {
    const interact = () => { if (waiting.current) deferred.current = true; };
    document.addEventListener('pointerdown', interact, true);
    document.addEventListener('keydown', interact, true);
    document.addEventListener('wheel', interact, true);
    return () => {
      document.removeEventListener('pointerdown', interact, true);
      document.removeEventListener('keydown', interact, true);
      document.removeEventListener('wheel', interact, true);
    };
  }, []);
  useEffect(() => {
    const saved = history.entries.get(entryKey)?.snapshot;
    if (saved && !deferred.current) {
      resolveFocus(saved.focus)?.focus({ preventScroll: true });
      if (window.scrollX !== saved.x || window.scrollY !== saved.y) window.scrollTo(saved.x, saved.y);
      const panel = document.getElementById('candidate-selected-detail');
      if (panel) panel.scrollTop = saved.detailY;
    }
    const record = () => { const current = history.entries.get(entryKey); if (current && !current.retired) current.snapshot = snapshot(); };
    document.addEventListener('focusin', record);
    document.addEventListener('scroll', record, true);
    return () => { document.removeEventListener('focusin', record); document.removeEventListener('scroll', record, true); };
  }, [history, entryKey]);
  const params = new URLSearchParams(location.search);
  const code = params.get('detail'); const evidence = params.get('evidence'); const flow = params.get('flow');
  const valid = ownedKeys.every(key => params.getAll(key).length <= 1)
    && (!params.has('flow_page') || integer(params.get('flow_page'), 1))
    && (!params.has('bucket_page') || integer(params.get('bucket_page'), 1))
    && (code !== 'buckets' || Number(params.get('bucket_page') ?? 1) <= Math.max(1, Math.ceil((source?.traffic_buckets?.length ?? 0) / 50)))
    && (!params.has('evidence') || code === 'evidence')
    && (!params.has('flow') || (code === 'flows' && flow !== '' && !Array.from(flow!).some(character => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127)))
    && (code !== 'evidence' || (integer(evidence, 0) && Number(evidence) < (source?.evidence?.length ?? 0)));
  const requested = valid ? code === 'evidence' ? `evidence-${evidence}` : code && Object.hasOwn(sections, code) ? sections[code as keyof typeof sections] : undefined : undefined;
  const entryRetired = !entry || entry.retired || epochMismatch;
  const evidenceInvalid = Boolean(!unavailable && requested?.startsWith('evidence-') && entry?.evidenceInvalid);
  const selection = source && !unavailable && !deferred.current && closingEntry !== location.key && (!entryRetired || evidenceInvalid) ? requested : undefined;
  if (entry && !entry.retired && !entry.flowRetired && selection === 'Flow review' && flow) { entry.flowId = flow; entry.flowPage = Number(params.get('flow_page') ?? 1); }
  const nextState = () => ({ ...historyState, candidateDetailEpoch: epoch, candidateDetailEntry: history.create(focusTarget(returnFocus.current)) });
  const resume = () => {
    if (!deferred.current || !requested || !source || unavailable) return;
    save();
    deferred.current = false;
    // Preserve the literal validated intent, including flow membership/page and
    // unrelated context. The flow panel still validates the requested page.
    navigate(location, { state: nextState() });
  };
  const select = (value?: string) => {
    if (value === selection && !entryRetired) return;
    if (value && (!source || unavailable)) return;
    save();
    // Retire presentation synchronously; operation owners remain mounted.
    if (!value) flushSync(() => setClosingEntry(location.key));
    if (value) deferred.current = false;
    const next = new URLSearchParams(location.search);
    selectionKeys.forEach(key => next.delete(key));
    if (value?.startsWith('evidence-')) { next.set('detail', 'evidence'); next.set('evidence', value.slice(9)); }
    else if (value) {
      const found = Object.entries(sections).find(([, label]) => label === value);
      if (!found) return;
      next.set('detail', found[0]);
    }
    navigate({ pathname: location.pathname, search: next.toString(), hash: location.hash }, { replace: !value, state: nextState() });
  };
  const page = valid && params.has('flow_page') ? Number(params.get('flow_page')) : 1;
  const bucketPage = valid && params.has('bucket_page') ? Number(params.get('bucket_page')) - 1 : 0;
  const changeBucketPage = (page: number) => {
    const next = new URLSearchParams(location.search);
    next.set('bucket_page', String(page + 1));
    if (next.toString() === params.toString()) return;
    save();
    navigate({ pathname: location.pathname, search: next.toString(), hash: location.hash }, { state: nextState() });
  };
  const changeFlow = (flowId?: string, nextPage = page, fresh = false) => {
    if (!fresh && currentLocation.current.key === location.key && valid && selection === 'Flow review' && nextPage === page && flowId === (flow ?? undefined)) return;
    const next = new URLSearchParams(currentLocation.current.search);
    selectionKeys.forEach(key => next.delete(key));
    next.set('detail', 'flows'); next.set('flow_page', String(nextPage));
    if (flowId !== undefined) next.set('flow', flowId);
    if (next.toString() === new URLSearchParams(currentLocation.current.search).toString() && !fresh) return;
    save();
    navigate({ pathname: location.pathname, search: next.toString(), hash: location.hash }, { state: nextState() });
  };
  return { selection, select, resume, evidenceInvalid, retiredSelection: entryRetired, deferredSelection: deferred.current ? requested : undefined, flow: selection === 'Flow review' ? flow ?? undefined : undefined, page, changeFlow, bucketPage, changeBucketPage, entryKey,
    retireFlowEntry: (key: string) => history.retireFlow(key),
    flowEntryRetired: (key: string) => history.entries.get(key)?.flowRetired ?? true };
}
