import { useEffect, useLayoutEffect, useRef, useState, type MouseEvent } from 'react';
import { useQueryClient, type QueryClient } from '@tanstack/react-query';
import { captureAuthentication, currentAuthentication } from './authentication';
import { useLocation, useNavigate, useNavigationType } from 'react-router-dom';

type ReturnPoint = { invoker: string; x: number; y: number };
const history = new WeakMap<QueryClient, { epoch: number; entries: Map<string, ReturnPoint> }>();

/** Queue-only URL contract: candidate is a literal opaque ID, never a return URL.
 * Job queues additionally own candidate_page (25 server rows); global page/filter
 * keys remain owned by the existing list navigator. No row absence proves deletion.
 * Explicit selection PUSHes; close REPLACEs just this key, including deep links.
 * The queue's bulk owner and unapplied filter drafts must not be keyed by it.
 */
export function useCandidateQueueSelection(headingId: string) {
  const location = useLocation();
  const navigate = useNavigate();
  const client = useQueryClient();
  const authority = captureAuthentication();
  const epoch = authority.epoch;
  const action = useNavigationType();
  const entry = `${location.key}:${location.pathname}${location.search}`;
  const lifetime = useRef<string | undefined>(entry);
  useLayoutEffect(() => { lifetime.current = entry; return () => { lifetime.current = undefined; }; }, [entry]);
  const current = () => lifetime.current === entry && currentAuthentication(authority);
  const memory = history.get(client);
  const saved = memory?.epoch === epoch ? memory.entries.get(entry) : undefined;
  const remember = (target?: HTMLElement) => {
    if (!current()) return;
    let memory = history.get(client);
    if (!memory || memory.epoch !== epoch) { memory = { epoch, entries: new Map() }; history.set(client, memory); }
    memory.entries.delete(entry);
    memory.entries.set(entry, { invoker: target?.id || headingId, x: window.scrollX, y: window.scrollY });
    if (memory.entries.size > 50) memory.entries.delete(memory.entries.keys().next().value!);
  };
  const returnFocus = useRef<HTMLElement | null>(null);
  const params = new URLSearchParams(location.search);
  const selected = params.get('candidate') || undefined;
  const [opened, setOpened] = useState(Boolean(selected));
  if (selected && !opened) setOpened(true);
  const pageValue = params.get('candidate_page') ?? '1';
  const page = /^[1-9]\d*$/.test(pageValue) && Number.isSafeInteger(Number(pageValue)) ? Number(pageValue) : undefined;
  const setPage = (value: number) => {
    if (!current() || value === page) return;
    remember(document.activeElement instanceof HTMLElement ? document.activeElement : undefined);
    const next = new URLSearchParams(location.search);
    if (value === 1) next.delete('candidate_page'); else next.set('candidate_page', String(value));
    navigate({ pathname: location.pathname, search: next.toString(), hash: location.hash });
  };
  const depart = () => remember(returnFocus.current ?? undefined);
  const close = () => {
    if (!current()) return;
    const next = new URLSearchParams(location.search); next.delete('candidate');
    if (!returnFocus.current?.isConnected) returnFocus.current = (saved && document.getElementById(saved.invoker)) || document.getElementById(headingId);
    navigate({ pathname: location.pathname, search: next.toString(), hash: location.hash }, { replace: true });
  };
  const buttonProps = (id: string) => ({
    id: `${headingId}-preview-${encodeURIComponent(id)}`,
    'aria-expanded': selected === id,
    'aria-controls': 'candidate-selected-detail',
    onClick: (event: MouseEvent<HTMLButtonElement>) => {
      if (!current() || selected === id) return;
      returnFocus.current = event.currentTarget;
      remember(event.currentTarget);
      const next = new URLSearchParams(location.search); next.set('candidate', id);
      navigate({ pathname: location.pathname, search: next.toString(), hash: location.hash });
    },
  });
  return { selected, opened, close, returnFocus, buttonProps, page, setPage, remember, depart, entry, saved, headingId, restoring: action === 'POP' && Boolean(saved) };
}


/** Restore only an explicit queue navigation, never overwrite focus chosen during a read. */
export function useCandidateQueueReturn(queue: ReturnType<typeof useCandidateQueueSelection>, ready: boolean, rowsVersion: unknown) {
  const restored = useRef<string | undefined>(undefined);
  const abandoned = useRef<string | undefined>(undefined);
  const { entry, saved, restoring, headingId, selected, returnFocus } = queue;
  // Passive phase follows ResultDetailPanel's inert cleanup on narrow Back.
  useEffect(() => {
    if (!restoring) { restored.current = undefined; abandoned.current = undefined; return; }
    if (!saved || abandoned.current === entry) return;
    const narrow = window.matchMedia?.('(max-width: 1199px)').matches ?? false;
    const invoker = document.getElementById(saved.invoker);
    const modalHeading = selected && narrow ? document.getElementById('candidate-selected-heading') : null;
    const active = document.activeElement;
    if (active !== document.body && active !== invoker && active?.id !== 'candidate-selected-heading' && !active?.id.startsWith(`${headingId}-preview-`)) { abandoned.current = entry; return; }
    if (ready && !(restored.current === entry && invoker)) {
      restored.current = entry;
      (modalHeading ?? invoker ?? document.getElementById(headingId))?.focus({ preventScroll: true });
      if (invoker) window.scrollTo(saved.x, saved.y);
      if (selected) returnFocus.current = document.getElementById(`${headingId}-preview-${encodeURIComponent(selected)}`);
    }
    const abandon = () => { abandoned.current = entry; };
    const interactions = ['focusin', 'pointerdown', 'keydown', 'wheel', 'touchstart'];
    interactions.forEach(event => document.addEventListener(event, abandon, { passive: true }));
    return () => interactions.forEach(event => document.removeEventListener(event, abandon));
  }, [entry, saved, restoring, ready, rowsVersion, headingId, selected, returnFocus]);
}
