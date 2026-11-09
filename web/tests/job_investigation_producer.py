"""Fresh real JOB producer and exact-wire oracle; never a provider listener.

The module-local checkout is authoritative, including under ordinary Vitest.
No shared heavy lock here: the caller may already own it. Each process owns its
in-memory repository, ASGI app and MockTransport; execution is bounded by caller.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVENTS = []


def audit(event, args):
    if event in {'socket.bind', 'socket.connect', 'socket.connect_ex', 'socket.getaddrinfo',
                 'socket.gethostbyname', 'subprocess.Popen', 'os.system', 'os.exec', 'os.posix_spawn'}:
        EVENTS.append(event)
        raise RuntimeError('JOB fixture denies network/process operation: ' + event)


sys.addaudithook(audit)
sys.path[:0] = [str(ROOT / 'controller'), str(ROOT / 'controller/src'), str(ROOT / 'analysis/src')]
from c2hunter_controller import ai_job_investigation_runtime_schema as runtime
from c2hunter_controller.ai_job_investigation_schema import JobRequest, JobPool
from tests.test_ai_job_investigation_fixtures import producer_fixtures


def parse(kind, raw):
    if kind == 'action':
        return runtime.parse_action(raw)
    if kind == 'evidence':
        return runtime.parse_job_evidence(raw.encode())
    return {'run': runtime.JobRun, 'result': runtime.JobResult, 'step': runtime.JobStep,
            'capabilities': runtime.JobCapabilities, 'request': JobRequest, 'pool': JobPool}[kind].model_validate_json(raw)


def additional_fixtures():
    import pytest
    from c2hunter_controller.ai_investigation_contract import canonical_bytes
    from c2hunter_controller.ai_investigation_http import encoded
    from c2hunter_controller.ai_job_investigation_pool import build_pool
    from c2hunter_controller.ai_job_investigation_schema import DiscoveryCoverage
    from c2hunter_controller.ai_job_investigation_store import initialize_job_investigation_store
    from c2hunter_controller.repositories import MemoryRepository
    from tests.test_ai_job_investigation_service import scripted, service_for, request_for
    from tests.test_ai_job_investigation_source import job, flow
    output = {}
    for mode in ('max_completed', 'three_facts'):
        repo = MemoryRepository()
        rows = [flow(destination_ip=f'2001:db8:ffff:ffff:ffff:ffff:ffff:{i:x}') for i in range(1, 41)]
        repo.save_job(job(rows))
        initialize_job_investigation_store(repo)
        def respond(data, index):
            if index == 1:
                return dict(action='select_peers', pool_sha256=data['pool']['pool_sha256'],
                            peer_ids=[p['peer_id'] for p in data['pool']['entries'][:3]])
            assessments = []
            if mode == 'max_completed':
                for peer in data['selection']['peer_ids']:
                    evidence = next(e for e in data['observations'] if e['peer_id'] == peer)
                    assessments.append(dict(peer_id=peer, verdict='NEEDS_REVIEW',
                        support=[dict(text='<img src=x onerror=alert(1)> hypothesis, not HTML', evidence_ids=[evidence['evidence_id']], metric_refs=[])],
                        counterevidence=[], uncertainty=['Capture is incomplete'], next_checks=['Inspect retained source']))
            return dict(action='finish', assessments=assessments)
        with pytest.MonkeyPatch.context() as patcher:
            with scripted(patcher, respond) as (gateway, _):
                service = service_for(repo, gateway)
                service.store.clock = lambda: 1000.0
                queued, _ = service.admit('alice', 'job', request_for(mode))
                output['run_' + mode + '_queued'] = encoded(queued).body.decode()
                outcome = service.run_next('web-worker')
                current = service.get('alice', 'job', queued.id)
                assert current.status == ('COMPLETED' if mode == 'max_completed' else 'PARTIAL'), current.model_dump_json()
                output['run_' + mode] = encoded(current).body.decode()
                for step in service.steps('alice', 'job', current.id, limit=10):
                    if step.evidence_id:
                        output['evidence_' + step.evidence_id] = encoded(service.evidence('alice', 'job', current.id, step.evidence_id)).body.decode()
                assert service.store.worker_exited(outcome.claim)
        preparation = repo.read_job_investigation_source('job')
        if mode == 'max_completed':
            for index, score in enumerate([0.0, -0.0, 0.1, 1e-7, 1e20]):
                pool = build_pool(preparation.snapshot, {'10.0.0.1': score}, DiscoveryCoverage(state='AVAILABLE', examined_peers=41, excluded_peers=0, warnings=()))
                output['pool_float_' + str(index)] = canonical_bytes(pool.model_dump(mode='json')).decode()
        repo.close()
    # Real review-repair producer siblings, not manually edited DTOs.
    from tests.job_review_helpers import execute, responder, verdict
    for mode in ('bad_action', 'final_cap', 'missing_measurement', 'cohort_unavailable'):
        repo = MemoryRepository()
        rows = [flow(domain='x.test'), flow(destination_ip='2001:db8::2', domain='y.test')]
        if mode == 'missing_measurement':
            for row in rows:
                del row['total_bytes']
        if mode == 'cohort_unavailable':
            for row in rows:
                row['protocol'] = 'OTHER'
        repo.save_job(job(rows))
        def reviewed(data, index):
            if mode == 'bad_action':
                return {'action': []}
            if mode == 'missing_measurement' and index > 1:
                return {'action': 'finish', 'assessments': []}
            if mode == 'cohort_unavailable' and index > 1:
                if index == 2:
                    return dict(action='request_tools', tools=[dict(peer_id=p, tool='compare_peer_cohort', arguments={}) for p in data['selection']['peer_ids']])
                return dict(action='finish', assessments=[dict(peer_id=p, verdict='NEEDS_REVIEW', support=[], counterevidence=[], uncertainty=['Unknown cohort'], next_checks=[]) for p in data['selection']['peer_ids']])
            if mode != 'final_cap' or index < 3:
                return responder(data, index)
            action = verdict(data, text='界' * 180)
            for item in action['assessments']:
                item['support'] *= 2
                item['counterevidence'] *= 2
                item['uncertainty'] = ['界' * 180] * 2
                item['next_checks'] = ['界' * 180] * 2
            assert len(canonical_bytes(action)) <= 16384
            return action
        try:
            with pytest.MonkeyPatch.context() as patcher:
                service, outcome, current, calls = execute(repo, patcher, reviewed, key=mode)
                assert outcome.acknowledge_exit
                assert current.status == ('COMPLETED' if mode == 'cohort_unavailable' else 'PARTIAL')
                if mode == 'final_cap':
                    assert current.result.reason == 'FINAL_LIMIT' and len(calls) == 4
                output['run_review_' + mode] = encoded(current).body.decode()
                assert service.store.worker_exited(outcome.claim)
        finally:
            repo.close()
    return output


if '--validate' in sys.argv:
    cases = json.load(sys.stdin)
    assert type(cases) is list and len(cases) <= 2000
    answers = []
    for case in cases:
        try:
            parse(case['kind'], case['raw'])
            answers.append({'accepted': True})
        except (ValueError, TypeError, UnicodeError) as exc:
            answers.append({'accepted': False, 'exception': type(exc).__name__})
    print(json.dumps(answers))
else:
    fixtures = producer_fixtures()
    assert len(fixtures) == 23
    schemas = {key.removeprefix('schema_'): json.loads(raw) for key, raw in fixtures.items() if key.startswith('schema_')}
    schemas.update(request=JobRequest.model_json_schema(), pool=JobPool.model_json_schema())
    additional = additional_fixtures()
    origins = {name: str(Path(module.__file__).resolve()) for name, module in tuple(sys.modules.items())
               if name.startswith(('c2hunter_controller', 'c2hunter_analysis', 'tests.test_ai_', 'tests.job_review_'))
               and getattr(module, '__file__', None)}
    assert all(Path(origin).is_relative_to(ROOT) for origin in origins.values()), origins
    print(json.dumps(dict(mode='FRESH_ASGI_PRODUCER', fixtures={key: raw.decode() for key, raw in fixtures.items()},
                          schemas=schemas, additional=additional, origins=origins, executable=sys.executable, prefix=sys.prefix,
                          isolated=sys.flags.isolated, network_events=EVENTS, python=sys.version)))
