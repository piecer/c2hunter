import { type ReactNode, type RefObject, useCallback, useEffect, useRef, useState } from 'react';

import './ResultDetailPanel.css';

/** Stable candidate-owned surface: never conditionally retire its mutation children. */
export default function ResultDetailPanel({ selection, onClose, returnFocus, children, suspended = false, focusOnSelection = true, headingLabel = 'Selected candidate detail', closeLabel = 'Close candidate detail' }: {
  focusOnSelection?: boolean; headingLabel?: string; closeLabel?: string;
  suspended?: boolean; selection?: string; onClose: () => void; returnFocus: RefObject<HTMLElement | null>; children: ReactNode;
}) {
  const panel = useRef<HTMLElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const [narrow, setNarrow] = useState(() => window.matchMedia?.('(max-width: 1199px)').matches ?? false);
  useEffect(() => {
    const media = window.matchMedia?.('(max-width: 1199px)');
    if (!media) return;
    const change = () => setNarrow(media.matches);
    media.addEventListener('change', change);
    return () => media.removeEventListener('change', change);
  }, []);
  useEffect(() => { if (selection && focusOnSelection) heading.current?.focus(); }, [selection, focusOnSelection]);
  useEffect(() => {
    if (!selection || suspended || !narrow || !panel.current) return;
    const restored: Array<[HTMLElement, boolean]> = [];
    let current: HTMLElement = panel.current;
    while (current.parentElement && current.parentElement !== document.body) {
      for (const sibling of current.parentElement.children) {
        if (sibling !== current && sibling instanceof HTMLElement) {
          restored.push([sibling, sibling.inert]);
          sibling.inert = true;
        }
      }
      current = current.parentElement;
    }
    return () => { restored.forEach(([element, inert]) => { element.inert = inert; }); };
  }, [selection, narrow, suspended]);
  const closing = useRef(false);
  useEffect(() => {
    if (selection || !closing.current) return;
    closing.current = false;
    const target = returnFocus.current?.isConnected ? returnFocus.current : document.querySelector<HTMLElement>('[aria-label="Candidate detail selection"]');
    target?.focus();
  }, [selection, returnFocus]);
  const close = useCallback(() => {
    closing.current = true;
    onClose();
  }, [onClose]);
  useEffect(() => {
    if (!selection || suspended) return;
    // A just-disabled pagination control can leave focus on body in Chromium.
    const escape = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !event.defaultPrevented) { event.preventDefault(); close(); }
    };
    document.addEventListener('keydown', escape);
    return () => document.removeEventListener('keydown', escape);
  }, [selection, close, suspended]);
  return <section ref={panel} id="candidate-selected-detail" className={selection ? `candidate-detail-surface${narrow && !suspended ? ' candidate-detail-modal' : ''}` : undefined}
    role={selection && !suspended ? narrow ? 'dialog' : 'region' : undefined} aria-modal={selection && narrow && !suspended ? true : undefined}
    aria-labelledby={selection ? 'candidate-selected-heading' : undefined}
    onKeyDown={event => {
      if (!selection || suspended) return;
      if (event.key === 'Tab' && narrow) {
        const controls = Array.from(panel.current?.querySelectorAll<HTMLElement>('button:not(:disabled), a[href], input:not(:disabled), select:not(:disabled), textarea:not(:disabled), summary, [tabindex="0"]') ?? []);
        const first = controls[0]; const last = controls.at(-1);
        if (event.shiftKey && (document.activeElement === first || document.activeElement === heading.current)) { event.preventDefault(); last?.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
      }
    }}>
    {selection && <div className="section-heading"><h2 ref={heading} tabIndex={-1} id="candidate-selected-heading">{headingLabel}</h2><button type="button" onClick={close}>{closeLabel}</button></div>}
    {children}
  </section>;
}

/** Native top-layer confirmation; the underlying operation owners stay mounted. */
export function CandidateDeleteConfirmation({ pending, onCancel, children }: {
  pending: boolean; onCancel: () => void; children: ReactNode;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const element = dialog.current!;
    const trigger = document.activeElement as HTMLElement | null;
    if (element.showModal) element.showModal();
    else element.setAttribute('open', ''); // DOM-only test environments lack native dialogs.
    element.querySelector<HTMLElement>('[data-cancel]')?.focus();
    return () => {
      if (element.close) element.close();
      const target = trigger?.isConnected ? trigger : document.querySelector<HTMLElement>('[aria-label="Candidate detail selection"]');
      target?.focus();
    };
  }, []);
  return <dialog ref={dialog} className="panel candidate-delete-dialog" aria-labelledby="delete-candidate-title" aria-modal="true"
    onCancel={event => { event.preventDefault(); if (!pending) onCancel(); }}
    onKeyDown={event => {
      if (event.key !== 'Tab') return;
      const controls = Array.from(dialog.current?.querySelectorAll<HTMLElement>('button:not(:disabled), a[href], input:not(:disabled), [tabindex="0"]') ?? []);
      const first = controls[0]; const last = controls.at(-1);
      if (!first) { event.preventDefault(); dialog.current?.focus(); }
      else if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    }}>
    {children}
  </dialog>;
}
