import { createContext, useContext } from 'react';

// A single expanded detail surface keeps deterministic evidence and optional AI
// from mounting two long reports at once. Status/errors remain independently live.
export type ReportDetail = 'coverage' | 'evidence' | 'ai';
export const ReportDetailContext = createContext<{ owner: ReportDetail | undefined; claim: (owner: ReportDetail) => void } | undefined>(undefined);
export const useReportDetail = () => useContext(ReportDetailContext);
