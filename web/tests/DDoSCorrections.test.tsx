import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fireEvent, render, screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import DDoSAttackPanel from '../src/DDoSAttackPanel';

const bytes = readFileSync('tests/fixtures/ddos-correction-corpus.json', 'utf8');
const corpus = JSON.parse(bytes) as Array<{ name: string; accepted: boolean; report: unknown }>;
it('freezes the real producer shared corruption corpus byte for byte', () => {
  const python = process.env.C2HUNTER_TEST_PYTHON ?? (existsSync('../.venv/bin/python') ? resolve('../.venv/bin/python') : 'python3');
  expect(execFileSync(python, ['tests/ddos_correction_corpus.py'], { encoding: 'utf8', maxBuffer: 2 * 1024 * 1024 })).toBe(bytes);
  expect(corpus).toHaveLength(164);
});
it.each(corpus)('validates identical serialized bytes: $name', ({ report, accepted }) => {
  const { unmount } = render(<DDoSAttackPanel report={JSON.parse(JSON.stringify(report))}/>);
  expect(screen.queryByRole('alert') === null).toBe(accepted);
  unmount();
});

it('shows known reverse-request loss instead of complete response support', () => {
  const source = corpus.find(item => item.name === 'producer/reverse-request-loss')!;
  render(<DDoSAttackPanel report={JSON.parse(JSON.stringify(source.report))}/>);
  fireEvent.click(screen.getByRole('button', { name: /상세 근거 보기/ }));
  expect(screen.getAllByText(/근거 범위가 제한되어 조율 주장을 유보합니다/).length).toBeGreaterThan(0);
});
