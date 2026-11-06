import { expect, it, vi } from 'vitest';
import { investigationApi } from '../src/investigationApi';
import { InvestigationContractError, parseInvestigation } from '../src/investigationContract';
import schemas from '../src/investigationSchemas.json';
import type { InvestigationRun, InvestigationStep } from '../src/investigationTypes';
import { fixture, producer } from './investigationFixtures';

const fields = Object.keys(schemas.InvestigationRun.$defs.Progress.properties);
const signal = () => new AbortController().signal;

it('binds complete serialized Progress to the actual producer definition, preserving explicit zeros', () => {
  expect(producer.schemas).toEqual(schemas);
  expect(fields.filter(field => field !== 'source_bytes_accounting').sort()).toEqual([
    'model_calls', 'source_bytes', 'source_records', 'tool_calls', 'transport_attempts',
  ]);
  const queued = parseInvestigation('InvestigationRun', fixture('run_queued'));
  expect(Object.keys(queued.progress).sort()).toEqual([...fields].sort());
  expect(queued.progress).toEqual({
    source_bytes_accounting: 'RESERVED_READER_UPPER_BOUND_NOT_MEASURED',
    model_calls: 0, tool_calls: 0, transport_attempts: 0, source_bytes: 0, source_records: 0,
  });
});

// Bounded producer-shape/public-route matrix, not a general parser audit.
const cases = [
  ['create', 'run_queued'],
  ['run', 'run_preparing'],
  ['cancel', 'run_cancelled'],
  ['history', 'run_completed'],
  ['history', 'run_partial'],
  ['history', 'run_failed'],
] as const;
it.each(cases)('%s requires every serialized Progress field in %s', async (route, name) => {
  const valid = parseInvestigation('InvestigationRun', fixture(name));
  const read = (run: InvestigationRun) => {
    vi.stubGlobal('fetch', vi.fn(async () => Response.json(route === 'history' ? { items: [run], next_cursor: null } : run)));
    if (route === 'history') return investigationApi.history(valid.job_id, null, signal());
    if (route === 'create') return investigationApi.create(valid.job_id, JSON.stringify(valid.request), signal());
    return investigationApi[route](valid.job_id, valid, signal());
  };
  await expect(read(valid)).resolves.toBeDefined();
  const locations = valid.result ? ['run', 'result', 'both'] as const : ['run'] as const;
  for (const location of locations) {
    for (const field of [...fields, '<whole progress>']) {
      const bad = structuredClone(valid);
      const targets = location === 'run' ? [bad] : location === 'result' ? [bad.result!] : [bad, bad.result!];
      for (const target of targets) {
        if (field === '<whole progress>') Reflect.deleteProperty(target, 'progress');
        else Reflect.deleteProperty(target.progress, field);
      }
      await expect(read(bad), `${name}:${location}:${field}`).rejects.toThrow(InvestigationContractError);
    }
  }
});

it.each(['step_model', 'step_tool'])('steps require complete Progress for %s', async name => {
  const run = parseInvestigation('InvestigationRun', fixture('run_completed'));
  const valid = parseInvestigation('InvestigationStep', fixture(name));
  const read = (step: InvestigationStep) => {
    vi.stubGlobal('fetch', vi.fn(async () => Response.json({ items: [step], next_cursor: null })));
    return investigationApi.steps(run.job_id, run, 0, signal());
  };
  await expect(read(valid)).resolves.toEqual({ items: [valid], next_cursor: null });
  for (const field of [...fields, '<whole progress>']) {
    const bad = structuredClone(valid);
    if (field === '<whole progress>') Reflect.deleteProperty(bad, 'progress');
    else Reflect.deleteProperty(bad.progress, field);
    await expect(read(bad), `${name}:${field}`).rejects.toThrow(InvestigationContractError);
  }
});

it('standalone successful results require complete serialized Progress', () => {
  const valid = parseInvestigation('InvestigationResult', fixture('result_completed'));
  for (const field of [...fields, '<whole progress>']) {
    const bad = structuredClone(valid);
    if (field === '<whole progress>') Reflect.deleteProperty(bad, 'progress');
    else Reflect.deleteProperty(bad.progress, field);
    expect(() => parseInvestigation('InvestigationResult', bad), field).toThrow(InvestigationContractError);
  }
});
