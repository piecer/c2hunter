import { useCallback, useEffect, useRef } from 'react';

type Intent = Readonly<{ body: Record<string, unknown>; signature: string; file: File }>;
export type PcapInvocation<Job> = Readonly<{ intent: Intent; job?: Job }>;

// Detach the wire snapshot from React-controlled values, including nested weights.
function freezeWire(value: unknown): void {
  if (value && typeof value === 'object') {
    Object.values(value).forEach(freezeWire);
    Object.freeze(value);
  }
}

// An admission belongs to one immutable wire intent and one File object. Latest
// mutation variables are not admission evidence. Retirement is irreversible even
// when the form later returns to the same values (A -> B -> A).
export function usePcapSubmission<Job>() {
  const state = useRef<{
    active: boolean;
    intent?: Intent;
    admitted?: { intent: Intent; job: Job };
    invocation?: PcapInvocation<Job>;
  }>({ active: true });
  useEffect(() => {
    state.current.active = true;
    return () => {
      state.current = { active: false };
    };
  }, []);
  const current = (invocation: PcapInvocation<Job>) => state.current.active && state.current.invocation === invocation && state.current.intent === invocation.intent;
  const retire = useCallback(() => { state.current = { active: state.current.active }; }, []);
  return {
    begin(body: Record<string, unknown>, file: File, retry?: PcapInvocation<Job>): PcapInvocation<Job> | undefined {
      const s = state.current;
      if (!s.active || s.invocation || (retry && s.intent !== retry.intent)) return;
      const signature = JSON.stringify({ ...body, idempotency_key: undefined });
      if (!s.intent || s.intent.signature !== signature || s.intent.file !== file) {
        if (retry) return;
        const snapshot = JSON.parse(JSON.stringify(body)) as Record<string, unknown>;
        freezeWire(snapshot);
        s.intent = Object.freeze({ body: snapshot, signature, file });
        s.admitted = undefined;
      }
      s.invocation = Object.freeze({ intent: s.intent, job: s.admitted?.intent === s.intent ? s.admitted.job : undefined });
      return s.invocation;
    },
    current,
    admit(invocation: PcapInvocation<Job>, job: Job) {
      if (!current(invocation)) return false;
      state.current.admitted = { intent: invocation.intent, job };
      return true;
    },
    retire,
    settled(invocation: PcapInvocation<Job>) {
      if (current(invocation)) state.current.invocation = undefined;
    },
  };
}
