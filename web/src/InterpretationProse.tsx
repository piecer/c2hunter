import { useState, type ReactNode } from 'react';
import { useReportLanguage } from './reportLanguageContext';

type Section = { title: string; count: number; render: (index: number) => ReactNode };
export default function InterpretationProse({ summary, language, sections, full, setFull, title, initialPosition, onPositionChange }: { initialPosition?: { section: number; page: number }; onPositionChange?: (value: { section: number; page: number }) => void; summary: string; language: 'ko' | 'en'; sections: Section[]; full: boolean; setFull: (value: boolean) => void; title: string }) {
  const locale = useReportLanguage();
  const t = (en: string, ko: string) => locale === 'ko' ? ko : en;
  // Paging is presentation-only. Retain a small return descriptor without
  // rerendering the authority owner and revalidating the complete saved run.
  // A changed run remounts this component; source/auth updates still validate.
  const [local, setLocal] = useState(initialPosition ?? { section: 0, page: 0 });
  const { section, page } = local;
  const update = (value: { section: number; page: number }) => { setLocal(value); onPositionChange?.(value); };
  const selected = sections[section];
  let remaining = 3;
  return <div className="interpretation-prose" style={{ minWidth: 0, overflowWrap: 'anywhere' }}>
    {!full && <>
      <p lang={language}>{summary.length <= 240 ? summary : t('Long AI summary: open the full text to preserve all qualifications.', '긴 AI 요약: 조건과 한계를 포함한 전체 원문을 펼쳐 확인하세요.')}</p>
      {sections.map((item, index) => {
        const count = Math.min(remaining, item.count); remaining -= count;
        return count ? <section key={index}><h4>{item.title}</h4>{Array.from({ length: count }, (_, i) => <div key={i}>{item.render(i)}</div>)}</section> : null;
      })}
    </>}
    <button type="button" className="secondary" aria-expanded={full} onClick={() => { setFull(!full); update({ section: 0, page: 0 }); }}>{t('View full AI text', 'AI 원문 전체 보기')}</button>
    {full && <article aria-label={title} className="ai-assessment">
      <h3>{t('AI-generated interpretation — analyst review required', 'AI 생성 해석 — 분석가 검토 필요')}</h3>
      <p lang={language}>{summary}</p>
      <nav aria-label={t('AI text sections', 'AI 원문 항목')}>{sections.map((item, index) => <button type="button" className="secondary" key={index} aria-pressed={index === section} onClick={() => { update({ section: index, page: 0 }); }}>{item.title}</button>)}</nav>
      <h4>{selected.title}</h4>
      {Array.from({ length: Math.max(0, Math.min(3, selected.count - page * 3)) }, (_, i) => <div key={i}>{selected.render(page * 3 + i)}</div>)}
      <nav aria-label={t('AI claim pages', 'AI 주장 페이지')}>
        <button type="button" className="secondary" disabled={page === 0} onClick={() => update({ section, page: page - 1 })}>{t('Previous AI claims', '이전 AI 주장')}</button>
        <span>{page + 1} / {Math.max(1, Math.ceil(selected.count / 3))} · {t('Retained entries', '보존 항목')} {selected.count}</span>
        <button type="button" className="secondary" disabled={(page + 1) * 3 >= selected.count} onClick={() => update({ section, page: page + 1 })}>{t('Next AI claims', '다음 AI 주장')}</button>
      </nav>
    </article>}
  </div>;
}
