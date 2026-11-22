import { useContext, useState, type ReactNode } from 'react';
import { ReportLanguageContext as Context, ReportLanguageChangeContext, type ReportLanguage } from './reportLanguageContext';
const preferenceKey = 'c2hunter-report-language';
function initialLanguage(): ReportLanguage {
  try { return localStorage.getItem(preferenceKey) === 'en' ? 'en' : 'ko'; }
  catch { return 'ko'; }
}
export function ReportLanguageSelector() {
  const language = useContext(Context);
  const setLanguage = useContext(ReportLanguageChangeContext);
  return <label>보고서 언어 / Report language <select value={language} onChange={event => {
    const next = event.target.value;
    if (next !== 'ko' && next !== 'en') return;
    setLanguage(next);
    try { localStorage.setItem(preferenceKey, next); } catch { /* Storage is optional. */ }
  }}><option value="ko">한국어</option><option value="en">English</option></select></label>;
}
export default function ReportLanguageScope({ children, showControl = true }: { children: ReactNode; showControl?: boolean }) {
  const [language, setLanguage] = useState<ReportLanguage>(initialLanguage);
  return <Context.Provider value={language}><ReportLanguageChangeContext.Provider value={setLanguage}>
    {showControl ? <div lang={language} className="network-report-language"><ReportLanguageSelector/>{children}</div> : children}
  </ReportLanguageChangeContext.Provider></Context.Provider>;
}
