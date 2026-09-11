import { useState, type ReactNode } from 'react';
import { ReportLanguageContext as Context, type ReportLanguage } from './reportLanguageContext';
const preferenceKey = 'c2hunter-report-language';
function initialLanguage(): ReportLanguage {
  try { return localStorage.getItem(preferenceKey) === 'en' ? 'en' : 'ko'; }
  catch { return 'ko'; }
}
export default function ReportLanguageScope({ children }: { children: ReactNode }) {
  const [language, setLanguage] = useState<ReportLanguage>(initialLanguage);
  return <Context.Provider value={language}><div lang={language} className="network-report-language">
    <label>보고서 언어 / Report language <select value={language} onChange={event => {
      const next = event.target.value;
      if (next !== 'ko' && next !== 'en') return;
      setLanguage(next);
      try { localStorage.setItem(preferenceKey, next); } catch { /* Storage is optional. */ }
    }}><option value="ko">한국어</option><option value="en">English</option></select></label>
    {children}
  </div></Context.Provider>;
}
