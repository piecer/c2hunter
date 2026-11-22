import { createContext, useContext } from 'react';

export type ReportLanguage = 'ko' | 'en';
export const ReportLanguageContext = createContext<ReportLanguage>('ko');
export const ReportLanguageChangeContext = createContext<(language: ReportLanguage) => void>(() => {});
export function useReportLanguage() { return useContext(ReportLanguageContext); }
