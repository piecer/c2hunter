import { createContext, useContext } from 'react';

export type PolicyDeleteTarget = Readonly<{ resource: 'payload-signatures' | 'allowlist'; id: string; name: string }>;
export type PolicyDeleteReceipt = { target: PolicyDeleteTarget; state: 'pending' | 'failed' | 'uncertain' | 'acknowledged'; message: string };
export const PolicyDeleteContext = createContext<{ ask: (target: PolicyDeleteTarget) => void; receipts: PolicyDeleteReceipt[] } | null>(null);
export function usePolicyDeletion() {
  const value = useContext(PolicyDeleteContext);
  if (!value) throw new Error('Policy deletion requires the authenticated Shell owner');
  return value;
}
