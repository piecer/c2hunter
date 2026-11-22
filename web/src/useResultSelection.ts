import { useLayoutEffect, useRef, type MouseEvent } from 'react';
import { useQueryClient, type QueryClient } from '@tanstack/react-query';
import { useLocation, useNavigate, useNavigationType } from 'react-router-dom';
import { captureAuthentication } from './authentication';

type ReturnPoint = { invoker: string; x: number; y: number };
const returnPoints = new WeakMap<QueryClient, { epoch: number; entries: Map<string, ReturnPoint> }>();

/** Same-document, bounded presentation memory; never a return URL or business state. */
export function useListReturn(ready: boolean, headingId: string, rowsVersion: unknown) {
  const client = useQueryClient();
  const location = useLocation();
  const action = useNavigationType();
  const epoch = captureAuthentication().epoch;
  const restored = useRef<string | undefined>(undefined);
  const abandoned = useRef<string | undefined>(undefined);
  const entry = `${location.key}:${location.pathname}${location.search}`;
  useLayoutEffect(() => {
    if (action !== 'POP' || abandoned.current === entry) return;
    const memory = returnPoints.get(client);
    const saved = memory?.epoch === epoch ? memory.entries.get(entry) : undefined;
    if (!saved) return;
    const invoker = document.getElementById(saved.invoker);
    const abandon = () => { abandoned.current = entry; };
    // A user's focus choice retires this restoration, even before uncached data
    // arrives and even if that control subsequently loses focus.
    if (document.activeElement !== document.body && document.activeElement !== invoker) {
      abandon();
      return;
    }
    if (ready && !(restored.current === entry && invoker)) {
      restored.current = entry;
      const target = invoker ?? document.getElementById(headingId);
      target?.focus({ preventScroll: true });
      if (invoker) window.scrollTo(saved.x, saved.y);
      else target?.scrollIntoView({ block: 'start' });
    }
    // Subscribe after our own focus, including while the first read is pending.
    document.addEventListener('focusin', abandon);
    return () => document.removeEventListener('focusin', abandon);
  }, [ready, action, entry, client, epoch, headingId, rowsVersion]);
  const linkProps = (id: string) => {
    const invoker = `${headingId}-row-${encodeURIComponent(id)}`;
    return { id: invoker, onClick: (event: MouseEvent<HTMLAnchorElement>) => {
      if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || event.defaultPrevented) return;
      let memory = returnPoints.get(client);
      if (!memory || memory.epoch !== epoch) {
        memory = { epoch, entries: new Map() };
        returnPoints.set(client, memory);
      }
      memory.entries.delete(entry);
      memory.entries.set(entry, { invoker, x: window.scrollX, y: window.scrollY });
      if (memory.entries.size > 50) memory.entries.delete(memory.entries.keys().next().value!);
    } };
  };
  return { linkProps, headingProps: { id: headingId, tabIndex: -1 } };
}

/** Only list display state belongs here. Drafts and mutation owners stay in their caller. */
export function useResultSelection<T>(read: (params: URLSearchParams) => T, write: (value: T) => URLSearchParams) {
  const location = useLocation();
  const navigate = useNavigate();
  const params = new URLSearchParams(location.search);
  const value = read(params);
  const unique = [...params.keys()].every(key => params.getAll(key).length === 1);
  const signature = write(value).toString();
  const apply = (next: T, repairInvalid = false) => {
    const search = write(next).toString();
    if (search === signature && unique && !repairInvalid) return;
    navigate({ pathname: location.pathname, search: search ? `?${search}` : '' });
  };
  return { value, signature, apply, unique, params };
}

export function listPage(params: URLSearchParams): number {
  const raw = params.get('page') ?? '1';
  return /^[1-9]\d*$/.test(raw) && Number.isSafeInteger(Number(raw)) ? Number(raw) : NaN;
}

export function listEnum(params: URLSearchParams, key: string, allowed: readonly string[], fallback = ''): string {
  const value = params.get(key) ?? fallback;
  return allowed.includes(value) ? value : '!invalid';
}
