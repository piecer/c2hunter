import { useEffect, useRef } from 'react';

// Retain the exact submitted intent (including its clock and idempotency key)
// for retry. A changed form/file/owner is a new intent, never an upload retry.
export function useDDoSSubmission(owner: string) {
  const state = useRef<{ owner: string; signature: string; file?: File; body: Record<string, unknown> } | undefined>(undefined);
  const activeOwner = useRef(owner);
  const active = useRef(true);
  const pending = useRef(false);
  activeOwner.current = owner;
  useEffect(() => { active.current = true; return () => { active.current = false; }; }, []);
  return {
    prepare(form: FormData, create: () => Record<string, unknown>, file?: File) {
      if (pending.current) return undefined;
      const signature = JSON.stringify([...form].filter(([key]) => !['pcap', 'ddos_reference_choice'].includes(key)));
      if (!state.current || state.current.owner !== owner || state.current.signature !== signature || state.current.file !== file) state.current = { owner, signature, file, body: create() };
      pending.current = true;
      return state.current.body;
    },
    owns(expectedOwner: string) { return active.current && activeOwner.current === expectedOwner; },
    current(body: unknown) { return active.current && state.current?.owner === activeOwner.current && state.current?.body === body; },
    invalidate() { state.current = undefined; },
    settled() { pending.current = false; },
  };
}
