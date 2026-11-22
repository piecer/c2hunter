import { createContext, useContext } from 'react';

// Presentation ownership only. Admitted mutations and their receipts live in
// stable controllers; switching a surface never cancels business work.
export const DDoSDetailContext = createContext<{
  owner: string | undefined;
  select: (owner: string | undefined) => void;
  current: () => boolean;
  prefix: string;
  jobId?: string;
  datasetId?: string;
  hasFinding?: (id: string) => boolean;
  navigateFinding?: (id: string) => void;
  statusTarget: HTMLElement | null;
  setStatusTarget: (target: HTMLElement | null) => void;
} | undefined>(undefined);
export const useDDoSDetail = () => useContext(DDoSDetailContext);
