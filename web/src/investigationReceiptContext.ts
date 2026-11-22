import { createContext, useCallback, useContext, useState } from 'react';

type Surface = { owner: symbol; node: HTMLElement };
type Registry = { target: HTMLElement | null; register: (owner: symbol, node: HTMLElement | null) => void };
export const InvestigationReceiptContext = createContext<Registry>({ target: null, register: () => {} });

/** One modal destination; stale instance cleanup cannot clear its successor. */
export function useReceiptSurface(): Registry {
  const [surface, setSurface] = useState<Surface | null>(null);
  const register = useCallback((owner: symbol, node: HTMLElement | null) => {
    setSurface(previous => node
      ? previous?.owner === owner && previous.node === node ? previous : { owner, node }
      : previous?.owner === owner ? null : previous);
  }, []);
  return { target: surface?.node ?? null, register };
}
export const useReceiptTarget = () => useContext(InvestigationReceiptContext).target;
