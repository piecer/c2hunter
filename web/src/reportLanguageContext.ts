import { createContext, useContext } from 'react';

export type ReportLanguage = 'ko' | 'en';
export const ReportLanguageContext = createContext<ReportLanguage>('ko');
export function useReportLanguage() { return useContext(ReportLanguageContext); }
