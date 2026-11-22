import { useCallback, useContext, useEffect, useId, useLayoutEffect, useRef, useState, type ReactNode } from 'react';
import { InvestigationReceiptContext } from './investigationReceiptContext';
import { InvestigationActivityContext } from './investigationActivityContext';
import { useInvestigationText } from './investigationLanguage';

/** One selected detail. Closing is presentation-only, never mutation retirement. */
export default function InvestigationEvidenceDetail({ children, onClose, invoker, fallback }: {
  children: ReactNode; onClose: () => void; invoker: HTMLElement | null; fallback: HTMLElement | null;
}) {
  const l = useInvestigationText();
  const activity = useContext(InvestigationActivityContext);
  const { register } = useContext(InvestigationReceiptContext);
  const owner = useRef(Symbol('evidence-surface'));
  const receiptRef = useCallback((node: HTMLDivElement | null) => register(owner.current, node), [register]);
  const [narrow, setNarrow] = useState(() => globalThis.matchMedia?.('(max-width: 640px)').matches ?? false);
  const dialog = useRef<HTMLDialogElement>(null);
  const region = useRef<HTMLElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const id = useId();
  useEffect(() => {
    const media = globalThis.matchMedia?.('(max-width: 640px)');
    if (!media) return;
    const changed = () => setNarrow(media.matches);
    media.addEventListener('change', changed);
    return () => media.removeEventListener('change', changed);
  }, []);
  useLayoutEffect(() => {
    const node = dialog.current;
    if (narrow && node && !node.open) node.showModal();
    heading.current?.focus();
    return () => { if (node?.open) node.close(); };
  }, [narrow]);
  const close = () => {
    const owner = dialog.current ?? region.current;
    const restore = owner?.contains(document.activeElement) || document.activeElement === document.body;
    // Native dialog close restores focus too; make it precede our same-owner fallback.
    dialog.current?.close();
    onClose();
    if (restore) (invoker?.isConnected ? invoker : fallback?.isConnected ? fallback : null)?.focus();
  };
  const content = <><header className="investigation-actions"><h4 id={id} tabIndex={-1} ref={heading}>{l('선택 근거', 'Selected evidence')}</h4><button type="button" onClick={close}>{l('근거 닫기', 'Close evidence')}</button></header>{narrow && <div onClickCapture={event => { if ((event.target as HTMLElement).closest('button')) { dialog.current?.close(); onClose(); } }}>{activity}</div>}{narrow && <div ref={receiptRef}/>} {children}</>;
  return narrow
    ? <dialog className="investigation-evidence-detail" ref={dialog} aria-labelledby={id} onCancel={event => { event.preventDefault(); close(); }}>{content}</dialog>
    : <section className="investigation-evidence-detail" ref={region} aria-labelledby={id} onKeyDown={event => { if (event.key === 'Escape') { event.stopPropagation(); close(); } }}>{content}</section>;
}
