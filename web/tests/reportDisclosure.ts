import { fireEvent, screen } from '@testing-library/react';

// Explicit operator disclosure steps, shared by evidence-level regressions.
export function openGroups() {
  const button = screen.getByRole('button', { name: /^(View all anomaly items|전체 이상 항목 보기)$/ });
  if (button.getAttribute('aria-expanded') !== 'true') fireEvent.click(button);
}
export function openCoverage() {
  const button = screen.getByRole('button', { name: /^(Coverage details and limitations|분석 범위 상세 및 한계)$/ });
  if (button.getAttribute('aria-expanded') !== 'true') fireEvent.click(button);
}
export function openEvidence(index = 0) {
  openGroups();
  const button = screen.getAllByRole('button', { name: /^(Show|Hide) representative evidence|^(보기|숨기기) 대표 증거/ })[index];
  if (button.getAttribute('aria-expanded') !== 'true') fireEvent.click(button);
}
export async function openAI(full = false) {
  const button = await screen.findByRole('button', { name: /^(Open AI interpretation|AI 해석 열기)$/ });
  fireEvent.click(button);
  if (full) fireEvent.click(await screen.findByRole('button', { name: /^(View full AI text|AI 원문 전체 보기)$/ }));
}
