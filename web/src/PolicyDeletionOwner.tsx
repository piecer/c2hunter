import { type ReactNode, useEffect, useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { api, ApiError } from './api';
import { captureAuthentication, currentAuthentication } from './authentication';
import { PolicyDeleteContext, type PolicyDeleteReceipt, type PolicyDeleteTarget } from './policyDeleteContext';

function Confirmation({ target, cancel, confirm }: { target: PolicyDeleteTarget; cancel: () => void; confirm: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const element = dialog.current!;
    const trigger = document.activeElement as HTMLElement | null;
    if (element.showModal) element.showModal(); else element.setAttribute('open', '');
    element.querySelector<HTMLButtonElement>('[data-cancel]')?.focus();
    return () => { if (element.close) element.close(); if (trigger?.isConnected) trigger.focus(); };
  }, []);
  return <dialog ref={dialog} className="panel policy-delete-dialog" aria-labelledby="policy-delete-title" aria-modal="true"
    onCancel={event => { event.preventDefault(); cancel(); }}
    onKeyDown={event => {
      if (event.key !== 'Tab') return;
      const controls = dialog.current!.querySelectorAll<HTMLButtonElement>('button');
      const first = controls[0], last = controls[controls.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    }}>
    <h2 id="policy-delete-title">Confirm policy deletion</h2>
    <p>{target.resource}</p><strong>{target.name}</strong><code>{target.id}</code>
    <p>Delete this exact record? This cannot be undone. Existing completed analysis snapshots are not rewritten.</p>
    <button type="button" data-cancel className="secondary" onClick={cancel}>Cancel deletion</button>
    <button type="button" className="danger" onClick={confirm}>Confirm delete</button>
  </dialog>;
}

export default function PolicyDeletionOwner({ children }: { children: ReactNode }) {
  const client = useQueryClient();
  const [authority] = useState(captureAuthentication);
  const live = useRef(false);
  useEffect(() => { live.current = true; return () => { live.current = false; }; }, []);
  const current = () => live.current && Boolean(authority.token) && currentAuthentication(authority);
  const records = useRef<PolicyDeleteReceipt[]>([]);
  const [receipts, setReceipts] = useState<PolicyDeleteReceipt[]>([]);
  const [confirmation, setConfirmation] = useState<PolicyDeleteTarget>();
  const [notice, setNotice] = useState<string>();
  const publish = () => { if (current()) setReceipts([...records.current]); };
  const admissible = (target: PolicyDeleteTarget) => {
    if (!current()) return false;
    const previous = records.current.find(item => item.target.resource === target.resource && item.target.id === target.id);
    if (previous?.state === 'pending' || previous?.state === 'acknowledged') {
      setNotice(`${previous.state === 'pending' ? 'Already pending' : 'Already acknowledged'}: ${target.name} · ${target.id}. Review the retained receipt.`);
      return false;
    }
    if (!previous && records.current.length >= 8) {
      setNotice(`Receipt capacity reached (8). ${target.name} · ${target.id} was not submitted. Dismiss a completed receipt first; pending operations are never evicted.`);
      return false;
    }
    setNotice(undefined);
    return true;
  };
  const ask = (target: PolicyDeleteTarget) => { if (admissible(target)) setConfirmation(Object.freeze({ ...target })); };
  const start = async (target: PolicyDeleteTarget) => {
    if (!current()) return;
    setConfirmation(undefined);
    if (!admissible(target)) return;
    const receipt: PolicyDeleteReceipt = { target, state: 'pending', message: 'Pending — waiting for server acknowledgement.' };
    records.current = [...records.current.filter(item => item.target.resource !== target.resource || item.target.id !== target.id), receipt];
    publish();
    try {
      const response = await api.deleteReceipt(`/${target.resource}/${encodeURIComponent(target.id)}`);
      // Authority must still match after asynchronous response-body parsing.
      if (!current()) return;
      const body = response.body;
      const confirmed = target.resource === 'allowlist' ? response.status === 204
        : response.status === 200 && body !== null && typeof body === 'object'
          && 'deleted' in body && body.deleted === true && 'signature_id' in body && body.signature_id === target.id;
      if (!confirmed) {
        receipt.state = 'uncertain';
        receipt.message = 'Deletion outcome uncertain. Response did not confirm this exact target; check the server before retrying.';
        publish();
        return;
      }
      receipt.state = 'acknowledged';
      receipt.message = 'Server acknowledged deletion. List refresh is not readback proof.';
      void client.invalidateQueries({ queryKey: [target.resource] });
    } catch (error) {
      if (!current()) return;
      receipt.state = error instanceof ApiError ? 'failed' : 'uncertain';
      receipt.message = error instanceof ApiError ? `Delete failed (HTTP ${error.status}).` : 'Deletion outcome uncertain. Check the server before retrying.';
    }
    publish();
  };
  return <PolicyDeleteContext.Provider value={{ ask, receipts }}>
    {notice && <p role="alert" className="policy-delete-notice">{notice}</p>}
    {receipts.length > 0 && <section className="panel policy-delete-receipts" aria-label="Policy deletion receipts">
      <h2>Policy deletion receipts</h2><p>Session memory only: sign out or reload clears receipts, not server work. No automatic retry.</p>
      {receipts.map(receipt => <article key={`${receipt.target.resource}/${receipt.target.id}`}>
        <strong>{receipt.target.name}</strong><code>{receipt.target.id}</code><small>{receipt.target.resource}</small>
        <p role={receipt.state === 'failed' || receipt.state === 'uncertain' ? 'alert' : 'status'}>{receipt.message}</p>
        {receipt.state !== 'pending' && receipt.state !== 'acknowledged' && <button type="button" onClick={() => ask(receipt.target)} aria-label={`Retry delete ${receipt.target.name}`}>Review and retry</button>}
        {receipt.state !== 'pending' && <button type="button" className="secondary" aria-label={`Dismiss receipt ${receipt.target.name}`} onClick={() => { records.current = records.current.filter(item => item !== receipt); setNotice(undefined); publish(); }}>Dismiss receipt</button>}
      </article>)}
    </section>}
    {children}
    {confirmation && <Confirmation target={confirmation} cancel={() => setConfirmation(undefined)} confirm={() => { void start(confirmation); }}/>}
  </PolicyDeleteContext.Provider>;
}
