"""Additional fresh, socket-free MemoryRepository witnesses, NOT sealed fixtures.

Only model actions are scripted in-process. Preview, evidence, admission, stored
run/result and HTTP serialization all use the source-bound production methods.
"""
import json
from pathlib import Path
from types import SimpleNamespace


def produce():
    from c2hunter_controller.ai_investigation import InvestigationService
    from c2hunter_controller.ai_investigation_contract import InvestigationError, InvestigationScope
    from c2hunter_controller.ai_investigation_evidence import EvidenceService
    from c2hunter_controller.ai_investigation_gateway import InvestigationModelGateway
    from c2hunter_controller.ai_investigation_http import encoded, failure
    from c2hunter_controller.ai_investigation_store import InvestigationRunStore, initialize_investigation_store
    from c2hunter_controller.repositories import MemoryRepository
    from c2hunter_controller.schemas import FlowRecord
    from starlette.requests import Request
    from tests.test_ai_investigation_evidence import flow, job
    from tests.test_ai_investigation_loop import finish

    class ScriptedActions(InvestigationModelGateway):
        def complete(self, messages, *_args, **_kwargs):
            # Not an HTTP transport witness; never invoke before_attempt.
            seen = json.loads(messages[-1]['content'])['observations']
            if not any(e['tool'] == 'compare_peer_cohort' for e in seen):
                action = {'action': 'request_tools', 'tools': [{'tool': 'compare_peer_cohort', 'arguments': {}}]}
            else:
                action = finish(seen[0])
            return SimpleNamespace(content=json.dumps(action))

    gateway = ScriptedActions(provider='openai-compatible', base_url='http://127.0.0.1:1',
                              model='in-memory-actions-no-inference', api_key='', temperature=0.0,
                              context_tokens=65536, max_output_tokens=2048)
    output = {}
    cases = {
        'absent': ([flow(destination_ip='2001:db8::2')], 'COMPLETED', None),
        'partial': ([flow(destination_ip='2001:db8::2')], 'PARTIALLY_COMPLETED', None),
        'unknown': ([flow(direction='BIDIRECTIONAL')], 'COMPLETED', 'OUTBOUND'),
        'mixed': ([flow(direction='BIDIRECTIONAL'), flow(domain='known.example', total_bytes=0)], 'COMPLETED', 'OUTBOUND'),
        'cohort': ([flow(), flow(source_ip='10.0.0.2', destination_ip='203.0.113.2'),
                    flow(protocol='IP_50', source_ip='10.0.0.3', destination_ip='203.0.113.3')], 'COMPLETED', None),
        'cohort_unknown': ([flow(protocol='OTHER')], 'COMPLETED', None),
        'zero': ([flow(total_bytes=0)], 'COMPLETED', None),
    }
    for name, (rows, status, direction) in cases.items():
        repo = MemoryRepository()
        try:
            # Model-normalized source rows, not hand-authored evidence DTOs.
            source = job([FlowRecord.model_validate(row).model_dump(mode='json') for row in rows])
            source['status'] = status
            repo.save_job(source)
            initialize_investigation_store(repo)
            store = InvestigationRunStore(repo, clock=lambda: 1000.0)
            service = InvestigationService(repo, store, gateway)
            scope = InvestigationScope(target_ip='2001:db8::1', traffic_direction=direction)
            preview = service.source_preview('alice', 'job', scope.model_dump(mode='json'))
            output[f'preview_{name}'] = encoded(preview).body.decode()
            tools = EvidenceService(repo.read_investigation_source('job'), scope)
            for tool in ('peer_overview', 'peer_flow_samples', 'compare_peer_cohort'):
                evidence = tools.call(tool, {})
                output[f'{name}_{tool}'] = encoded(evidence).body.decode()
            request = dict(scope.model_dump(mode='json'), question='Explain known facts and uncertainty',
                           language='en', idempotency_key=name,
                           expected_source_sha256=preview.source.source_sha256)
            if name in {'absent', 'partial', 'unknown'}:
                try:
                    service.admit('alice', 'job', request)
                except InvestigationError as exc:
                    response = failure(Request({'type': 'http'}), exc.code)
                    assert response.status_code == 422
                    output[f'error_{name}'] = response.body.decode()
                else:
                    raise AssertionError('unmatched target admitted')
                assert not store.page('alice', 'job', limit=20)
            elif name in {'mixed', 'cohort'}:
                admitted, created = service.admit('alice', 'job', request)
                assert created
                outcome = service.run_next('web-witness')
                assert outcome.code is None, outcome.code
                run = service.get('alice', 'job', admitted.id)
                assert run.status == 'COMPLETED'
                assert run.progress.transport_attempts == 0
                output[f'run_{name}'] = encoded(run).body.decode()
                output[f'result_{name}'] = encoded(run.result).body.decode()
                assert store.worker_exited(outcome.claim)
        finally:
            repo.close()
    return {'mode': 'FRESH_IN_MEMORY_SCRIPTED_ACTIONS_NO_HTTP_NO_INFERENCE', 'fixtures': output,
            'helper': str(Path(__file__).resolve())}
