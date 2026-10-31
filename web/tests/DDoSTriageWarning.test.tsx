import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { render, screen, within } from '@testing-library/react';
import { expect, it } from 'vitest';
import DDoSAttackPanel, { type DDoSAttackReport } from '../src/DDoSAttackPanel';

const python = process.env.C2HUNTER_TEST_PYTHON ?? (existsSync('../.venv/bin/python') ? resolve('../.venv/bin/python') : 'python3');
const reports = JSON.parse(execFileSync(python, ['tests/ddos_triage_low_source_fixture.py'], { encoding: 'utf8' })) as Record<string, DDoSAttackReport>;
it.each(['en', 'ko'])('describes actual one/two-source producer warnings without single-source or high-rate claims in %s', language => {
  localStorage.setItem('c2hunter-report-language', language);
  for (const sourceCount of ['1', '2']) {
    const { unmount } = render(<DDoSAttackPanel report={reports[sourceCount]}/>);
    const glance = screen.getByRole('region', { name: language === 'en' ? 'DDoS at a glance' : 'DDoS 한눈에 보기' });
    expect(within(glance).getByText(language === 'en' ? /packet-count threshold.*below the configured source-count threshold/ : /패킷 수 임계값.*설정된 source 수 임계값/)).toBeVisible();
    expect(glance).not.toHaveTextContent(/single-source|단일 source|High-volume|고용량/);
    expect(screen.getByRole('heading', { name: language === 'en' ? 'Insufficient evidence for a DDoS conclusion' : 'DDoS 결론을 위한 증거 부족' })).toBeVisible();
    unmount();
  }
});
