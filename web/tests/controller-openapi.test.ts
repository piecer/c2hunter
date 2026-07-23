import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const repositoryRoot = resolve(import.meta.dirname, '../..');
const python = process.env.C2HUNTER_PYTHON ?? resolve(repositoryRoot, '.venv/bin/python');
const pythonPath = [
  resolve(repositoryRoot, 'controller/src'),
  resolve(repositoryRoot, 'analysis/src'),
].join(':');

const openapi = JSON.parse(execFileSync(python, ['-c', [
  'import json',
  'from c2hunter_controller.app import create_app',
  'from c2hunter_controller.config import Settings',
  'from c2hunter_controller.repositories import MemoryRepository',
  'print(json.dumps(create_app(Settings(environment="test"), MemoryRepository()).openapi()))',
].join(';')], { encoding: 'utf8', env: { ...process.env, PYTHONPATH: pythonPath } }));

function requestSchema(path: string, method: 'post' | 'put') {
  const schema = openapi.paths[path][method].requestBody.content['application/json'].schema;
  if (!schema.$ref) return schema;
  const name = String(schema.$ref).split('/').at(-1);
  if (!name) throw new Error(`Missing request schema reference for ${path}`);
  return openapi.components.schemas[name];
}

describe('Controller OpenAPI contract consumed by the web UI', () => {
  it.each([
    ['/api/v1/auth/dev-login', 'post'],
    ['/api/v1/candidates', 'get'],
    ['/api/v1/candidates/{candidate_id}', 'get'],
    ['/api/v1/analysis-jobs', 'post'],
    ['/api/v1/analysis-jobs/{job_id}', 'patch'],
    ['/api/v1/analysis-jobs/{job_id}', 'delete'],
    ['/api/v1/analysis-jobs/{job_id}/cancel', 'post'],
    ['/api/v1/analysis-jobs/{job_id}/reanalyze', 'post'],
    ['/api/v1/analysis-jobs/{job_id}/flows', 'get'],
    ['/api/v1/analysis-jobs/{job_id}/flows/{requested_flow_id}/payload-preview', 'get'],
    ['/api/v1/analysis-jobs/{job_id}/flow-labels', 'post'],
    ['/api/v1/payload-signatures', 'get'],
    ['/api/v1/payload-signatures/{signature_id}', 'patch'],
    ['/api/v1/pcap-analysis-jobs', 'post'],
    ['/api/v1/pcap-exports', 'post'],
    ['/api/v1/sensor-enrollments', 'get'],
    ['/api/v1/sensor-enrollments', 'post'],
    ['/api/v1/sensors/{sensor_id}/configuration', 'put'],
    ['/api/v1/sensors/{sensor_id}/credentials/rotate', 'post'],
    ['/api/v1/sensors/{sensor_id}/revoke', 'post'],
  ])('exposes %s %s', (path, method) => {
    expect(openapi.paths[path]?.[method]).toBeDefined();
  });

  it('keeps required web analysis fields aligned with AnalysisJobCreate', () => {
    const schema = requestSchema('/api/v1/analysis-jobs', 'post');
    expect(schema.required).toEqual(expect.arrayContaining([
      'name', 'idempotency_key', 'sensor_ids', 'mode', 'start_time', 'end_time',
      'capture', 'analysis', 'internal_networks',
    ]));
  });

  it('requires job context for export and idempotency for reanalysis', () => {
    expect(requestSchema('/api/v1/pcap-exports', 'post').required).toContain('job_id');
    expect(requestSchema('/api/v1/analysis-jobs/{job_id}/reanalyze', 'post').required).toContain('idempotency_key');
    expect(requestSchema('/api/v1/analysis-jobs/{job_id}/cancel', 'post').properties).toHaveProperty('reason');
  });

  it('keeps external sensor enrollment and configuration bodies aligned', () => {
    expect(requestSchema('/api/v1/sensor-enrollments', 'post').required).toEqual(expect.arrayContaining([
      'name', 'expires_in_seconds', 'capture_sources', 'internal_networks',
    ]));
    expect(requestSchema('/api/v1/sensors/{sensor_id}/configuration', 'put').required).toEqual(expect.arrayContaining([
      'config_version', 'capture_sources', 'internal_networks',
    ]));
  });
});
