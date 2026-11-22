"""Fresh, real producer reports with all run-scoped citation bodies.

Scripted model content is fixture input, not real inference. No DTO repair.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'controller'), str(ROOT / 'controller/src'), str(ROOT / 'analysis/src')]

import pytest
from c2hunter_controller.ai_investigation import InvestigationService
from c2hunter_controller.ai_investigation_store import InvestigationRunStore, initialize_investigation_store
from c2hunter_controller.ai_job_investigation_store import initialize_job_investigation_store
from c2hunter_controller.repositories import MemoryRepository
from tests.test_ai_investigation_evidence import flow, job
from tests.test_ai_investigation_loop import adaptive, structured_provider, request_for
from tests.test_ai_job_investigation_service import scripted, service_for, request_for as job_request
from tests.test_ai_job_investigation_source import flow as job_flow, job as job_source

output = {}
repo = MemoryRepository()
try:
    repo.save_job(job([flow(domain='updates.example.test'), flow(source_ip='10.0.0.2')]))
    initialize_investigation_store(repo)
    store = InvestigationRunStore(repo, clock=lambda: 1000.0)
    def respond(body, index):
        action = adaptive(body, index)
        if action['action'] == 'finish':
            original = action['support'][0]
            action['support'] = [dict(original, text=f'IP support {i}: 관측 가설') for i in range(4)]
            action['counterevidence'] = [dict(original, text=f'IP counter {i}: 대안 가설') for i in range(4)]
            action['uncertainty'] = [f'IP uncertainty {i}' for i in range(4)]
            action['next_checks'] = [f'IP check {i}' for i in range(4)]
        return action
    with structured_provider(respond) as (gateway, _):
        service = InvestigationService(repo, store, gateway)
        run, _ = service.admit('alice', 'job', request_for(repo))
        output['ip_queued'] = run.model_dump(mode='json')
        outcome = service.run_next('saved-navigation-worker')
        completed = service.get('alice', 'job', run.id)
        assert completed.status == 'COMPLETED', completed.model_dump_json()
        output['ip'] = completed.model_dump(mode='json')
        output['ip_evidence'] = {q.evidence_id: service.evidence('alice', 'job', run.id, q.evidence_id).model_dump(mode='json') for q in completed.result.evidence_quality}
        assert store.worker_exited(outcome.claim)
finally:
    repo.close()

repo = MemoryRepository()
try:
    repo.save_job(job_source([job_flow(destination_ip=f'2001:db8:ffff:ffff:ffff:ffff:ffff:{i:x}') for i in range(1, 41)]))
    initialize_job_investigation_store(repo)
    def respond_job(data, index):
        if index == 1:
            return dict(action='select_peers', pool_sha256=data['pool']['pool_sha256'], peer_ids=[p['peer_id'] for p in data['pool']['entries'][:3]])
        assessments = []
        for peer in data['selection']['peer_ids']:
            evidence = next(e for e in data['observations'] if e['peer_id'] == peer)
            def claim(i, kind):
                return dict(text=f'{kind} {i}: 관측 가설', evidence_ids=[evidence['evidence_id']], metric_refs=[])
            assessments.append(dict(peer_id=peer, verdict='NEEDS_REVIEW', support=[claim(i, 'support') for i in range(2)], counterevidence=[claim(i, 'counter') for i in range(2)], uncertainty=[f'uncertainty {i}' for i in range(2)], next_checks=[f'check {i}' for i in range(2)]))
        return dict(action='finish', assessments=assessments)
    with pytest.MonkeyPatch.context() as patcher:
        with scripted(patcher, respond_job) as (gateway, _):
            service = service_for(repo, gateway)
            service.store.clock = lambda: 1000.0
            run, _ = service.admit('alice', 'job', job_request('saved-navigation'))
            output['job_queued'] = run.model_dump(mode='json')
            outcome = service.run_next('saved-navigation-worker')
            completed = service.get('alice', 'job', run.id)
            assert completed.status == 'COMPLETED', completed.model_dump_json()
            output['job'] = completed.model_dump(mode='json')
            output['job_evidence'] = {q.evidence_id: service.evidence('alice', 'job', run.id, q.evidence_id).model_dump(mode='json') for a in completed.result.assessments for q in a.evidence_quality}
            assert service.store.worker_exited(outcome.claim)
finally:
    repo.close()
print(json.dumps(output, ensure_ascii=False))
