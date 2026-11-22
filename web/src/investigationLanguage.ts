import { useReportLanguage } from './reportLanguageContext';

/** Display labels only. Never apply to stored model/source prose or request bodies. */
export function useInvestigationText() {
  const language = useReportLanguage();
  return (ko: string, en: string) => language === 'ko' ? ko : en;
}
