import { type ReactNode, useId, useLayoutEffect, useRef, useState } from 'react';
import { useDDoSDetail } from './ddosDetailContext';
import { useReportLanguage } from './reportLanguageContext';
import './ddosProgressive.css';

// Domain-local presentation only: controller owners remain at their old stable
// positions. Native modal focus containment applies only below 600 CSS pixels.
export default function DDoSResponsiveDetail({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  const id = useId();
  const panel = useRef<HTMLDialogElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const slot = useRef<HTMLDivElement>(null);
  const close = useRef(onClose);
  close.current = onClose;
  const [narrow, setNarrow] = useState(() => window.matchMedia?.('(max-width: 599px)').matches ?? false);
  const publishStatusTarget = useDDoSDetail()?.setStatusTarget;
  const language = useReportLanguage();
  useLayoutEffect(() => {
    const dialog = panel.current!;
    const invoker = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const media = window.matchMedia?.('(max-width: 599px)');
    const present = () => {
      const modal = media?.matches ?? false;
      setNarrow(modal);
      if (dialog.open) dialog.close?.();
      if (modal && dialog.showModal) dialog.showModal();
      else if (dialog.show) dialog.show();
      else dialog.setAttribute('open', ''); // jsdom contract tests, not browser containment
      heading.current?.focus();
    };
    present();
    media?.addEventListener('change', present);
    publishStatusTarget?.(slot.current);
    return () => {
      media?.removeEventListener('change', present);
      publishStatusTarget?.(null);
      dialog.close?.();
      const fallback = document.getElementById('ddos-heading') ?? document.querySelector<HTMLElement>('main h1');
      const target = invoker?.isConnected && invoker !== document.body ? invoker : fallback;
      if (target) { if (!target.hasAttribute('tabindex')) target.setAttribute('tabindex', '-1'); target.focus(); }
    };
  }, [publishStatusTarget]);
  return <dialog ref={panel} className="ddos-responsive-detail" role={narrow ? 'dialog' : 'region'} aria-modal={narrow || undefined} aria-labelledby={id}
    onCancel={event => { event.preventDefault(); close.current(); }}
    onKeyDown={event => { if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); close.current(); } }}>
    <h3 id={id} ref={heading} tabIndex={-1}>{title}</h3>
    <button type="button" className="secondary" onClick={onClose}>{language === 'en' ? 'Close detail' : '상세 닫기'}</button>
    <div ref={slot}/>
    {children}
  </dialog>;
}
