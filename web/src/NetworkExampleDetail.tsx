import { type ReactNode, type RefObject, useCallback, useEffect, useId, useLayoutEffect, useRef, useState } from 'react';

/** Network-local variant: unique labels, same-source fallback, no unmount focus.
 * The candidate panel's fixed IDs/fallback are deliberately not reused here.
 * The selector stays in this surface so every example is usable while modal.
 */
export default function NetworkExampleDetail({ open, onClose, returnFocus, fallbackFocus, headingLabel, closeLabel, children }: {
  open: boolean; onClose: () => void; returnFocus: RefObject<HTMLElement | null>;
  fallbackFocus: RefObject<HTMLElement | null>; headingLabel: string; closeLabel: string; children: ReactNode;
}) {
  const panel = useRef<HTMLElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const headingId = useId();
  const live = useRef(false);
  const closing = useRef(false);
  const [narrow, setNarrow] = useState(() => window.matchMedia?.('(max-width: 1199px)').matches ?? false);
  useLayoutEffect(() => { live.current = true; return () => { live.current = false; }; }, []);
  useEffect(() => {
    const media = window.matchMedia?.('(max-width: 1199px)');
    if (!media) return;
    const change = () => setNarrow(media.matches);
    media.addEventListener('change', change);
    return () => media.removeEventListener('change', change);
  }, []);
  useLayoutEffect(() => {
    if (open) heading.current?.focus();
  }, [open]);
  useLayoutEffect(() => {
    if (!open || !narrow || !panel.current) return;
    const element = panel.current;
    if (!element.contains(document.activeElement)) heading.current?.focus();
    const restored: Array<[HTMLElement, boolean]> = [];
    let current: HTMLElement = element;
    while (current.parentElement) {
      for (const sibling of current.parentElement.children) {
        if (sibling !== current && sibling instanceof HTMLElement) {
          restored.push([sibling, sibling.inert]); sibling.inert = true;
        }
      }
      if (current.parentElement === document.body) break;
      current = current.parentElement;
    }
    const contain = (event: FocusEvent) => {
      if (live.current && event.target instanceof Node && !element.contains(event.target)) heading.current?.focus();
    };
    document.addEventListener('focusin', contain);
    return () => {
      document.removeEventListener('focusin', contain);
      restored.forEach(([node, inert]) => { node.inert = inert; });
    };
  }, [open, narrow]);
  useLayoutEffect(() => {
    if (open || !closing.current) return;
    closing.current = false;
    const target = returnFocus.current?.isConnected ? returnFocus.current : fallbackFocus.current;
    if (live.current && target?.isConnected) target.focus();
  }, [open, returnFocus, fallbackFocus]);
  const close = useCallback(() => {
    if (!live.current || !open) return;
    closing.current = true;
    onClose();
  }, [open, onClose]);
  useEffect(() => {
    if (!open) return;
    const escape = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !event.defaultPrevented) { event.preventDefault(); close(); }
    };
    document.addEventListener('keydown', escape);
    return () => document.removeEventListener('keydown', escape);
  }, [open, close]);
  return <section ref={panel} className={open ? `network-example-detail${narrow ? ' is-modal' : ''}` : undefined}
    role={open ? narrow ? 'dialog' : 'region' : undefined} aria-modal={open && narrow ? true : undefined}
    aria-labelledby={open ? headingId : undefined}
    onKeyDown={event => {
      if (!open || !narrow || event.key !== 'Tab') return;
      const controls = Array.from(panel.current?.querySelectorAll<HTMLElement>('button:not(:disabled), a[href], input:not(:disabled), select:not(:disabled), textarea:not(:disabled), summary, [tabindex="0"]') ?? []);
      const first = controls[0], last = controls.at(-1);
      if (event.shiftKey && (document.activeElement === first || document.activeElement === heading.current)) { event.preventDefault(); last?.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
    }}>
    {open && <div className="network-example-heading"><h2 ref={heading} tabIndex={-1} id={headingId}>{headingLabel}</h2><button type="button" className="secondary" onClick={close}>{closeLabel}</button></div>}
    {children}
  </section>;
}
