"""Export skill contracts from an isolated C2Hunter app, never a live server."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile

OPS = {
    'health': ('GET', '/api/v1/health'),
    'ready': ('GET', '/api/v1/ready'),
    'capabilities': ('GET', '/api/v1/ai-capabilities'),
    'sensors-list': ('GET', '/api/v1/sensors'),
    'jobs-list': ('GET', '/api/v1/analysis-jobs'),
    'job-get': ('GET', '/api/v1/analysis-jobs/{job_id}'),
    'job-create': ('POST', '/api/v1/analysis-jobs'),
    'job-cancel': ('POST', '/api/v1/analysis-jobs/{job_id}/cancel'),
    'pcap-initiate': ('POST', '/api/v1/pcap-analysis-jobs/initiate'),
    'pcap-upload': ('PUT', '/api/v1/pcap-analysis-jobs/{job_id}/capture'),
    'job-candidates': ('GET', '/api/v1/analysis-jobs/{job_id}/candidates'),
    'ai-create': ('POST', '/api/v1/analysis-jobs/{job_id}/ai-runs'),
    'ai-list': ('GET', '/api/v1/analysis-jobs/{job_id}/ai-runs'),
    'ai-get': ('GET', '/api/v1/ai-runs/{run_id}'),
    'ai-cancel': ('POST', '/api/v1/ai-runs/{run_id}/cancel'),
    'ai-selection': ('GET', '/api/v1/ai-runs/{run_id}/selection'),
    'ai-assessments': ('GET', '/api/v1/ai-runs/{run_id}/assessments'),
    'assessment-get': ('GET', '/api/v1/ai-assessments/{assessment_id}'),
    'assessment-evidence': ('GET', '/api/v1/ai-assessments/{assessment_id}/evidence-bundle'),
    'baseline-scopes': ('GET', '/api/v1/historical-baselines/scopes'),
    'baseline-scope': ('GET', '/api/v1/historical-baselines/scopes/{scope_id}'),
    'baseline-comparisons': ('GET', '/api/v1/ai-runs/{run_id}/baseline-comparisons'),
    'baseline-sources': ('GET', '/api/v1/ai-runs/{run_id}/baseline-sources'),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    root = args.repo.resolve()
    out = args.output.resolve()
    commit = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD']).decode().strip()
    scratch = Path(tempfile.mkdtemp(prefix='c2hunter-skill-export-', dir=os.environ.get('TMPDIR')))
    os.environ.clear()
    os.environ.update(HOME=str(scratch), TMPDIR=str(scratch), PYTHONDONTWRITEBYTECODE='1')
    sys.dont_write_bytecode = True
    sys.pycache_prefix = str(scratch / 'cache')
    sys.path[:0] = [str(root / p) for p in ('controller/src', 'analysis/src', 'controller')]

    def blocked(*args, **kwargs):
        raise RuntimeError('contract export must not use network')
    socket.socket.connect = blocked
    socket.create_connection = blocked
    socket.getaddrinfo = blocked
    from c2hunter_controller.app import create_app
    from c2hunter_controller.config import Settings
    from c2hunter_controller.repositories import MemoryRepository
    from c2hunter_controller.ai_analysis import FakeGateway
    from c2hunter_controller.security import required_role

    app = create_app(Settings(_env_file=None, environment='test', api_auth_required=True,
        ai_analysis_enabled=True, ai_model_provider='fake', database_url='memory://',
        redis_url='memory://', clickhouse_url='memory://', s3_endpoint='memory://',
        candidate_auto_enrichment_limit=0), MemoryRepository(), ai_gateway=FakeGateway())
    schema = app.openapi()
    operations = {}
    for name, (method, path) in OPS.items():
        assert path in schema['paths'] and method.lower() in schema['paths'][path], (name, method, path)
        doc = schema['paths'][path][method.lower()]
        role = required_role(method, path)
        if name in ('baseline-comparisons', 'baseline-sources'):
            role_name = 'ANALYST'  # middleware and handler override generic GET role
        else:
            role_name = role.name if role else 'PUBLIC'
        query = [x['name'] for x in doc.get('parameters', []) if x['in'] == 'query']
        if name == 'baseline-scopes':
            query = ['offset', 'limit']  # parsed manually by _page_args, absent from OpenAPI
        operations[name] = {
            'method': method, 'path': path, 'write': method != 'GET',
            'minimum_role': role_name,
            'path_parameters': [x['name'] for x in doc.get('parameters', []) if x['in'] == 'path'],
            'query_parameters': query,
            'body': 'binary' if name == 'pcap-upload' else 'json' if method != 'GET' else 'none',
            'request_body': doc.get('requestBody'),
            'response_statuses': sorted(doc.get('responses', {})),
        }
    assert app.openapi_url == '/openapi.json'
    operations['openapi-get'] = {
        'method': 'GET', 'path': app.openapi_url, 'write': False,
        'minimum_role': required_role('GET', app.openapi_url).name,
        'path_parameters': [], 'query_parameters': [], 'body': 'none',
        'request_body': None, 'response_statuses': ['200'],
        'source': 'FastAPI.openapi_url; discovery route is not listed inside OpenAPI paths',
    }
    encoded = (json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + '\n').encode()
    contract = {'schema_version': 1, 'source_commit': commit,
        'openapi_sha256': hashlib.sha256(encoded).hexdigest(),
        'scope': 'allowlisted analyst workflow; not all administrative API routes',
        'authentication': 'Bearer token checked by middleware; OpenAPI omission is not permission to bypass auth',
        'manual_supplements': {'baseline-scopes': 'offset integer 0..16, limit 1..20; canonical ASCII decimal without leading zeros'},
        'operations': operations,
        'terminal_states': {'job-get': ['COMPLETED', 'PARTIALLY_COMPLETED', 'FAILED', 'CANCELLED'], 'ai-get': ['COMPLETED', 'FAILED', 'CANCELLED']},
        'source_hashes': {p: hashlib.sha256((root/p).read_bytes()).hexdigest() for p in [
            'controller/src/c2hunter_controller/app.py','controller/src/c2hunter_controller/schemas.py',
            'controller/src/c2hunter_controller/security.py','controller/src/c2hunter_controller/historical_baseline_api.py',
            'controller/src/c2hunter_controller/historical_ai_http.py','controller/src/c2hunter_controller/jobs.py']}}
    payloads = {'openapi.json': encoded, 'operations.json': (json.dumps(contract, ensure_ascii=False, indent=2, sort_keys=True)+'\n').encode()}
    out.mkdir(parents=True, exist_ok=True)
    for name, data in payloads.items():
        if args.check:
            assert (out/name).read_bytes() == data, name
        else:
            with (out/name).open('xb') as f:
                f.write(data)
    print(json.dumps({'operations': len(operations), 'source_commit': commit, 'exact_parity': args.check, 'live_calls': 0}))

if __name__ == '__main__':
    main()
