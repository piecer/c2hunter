"""Replay exact browser-produced request bodies through real ASGI/SQLite.
The offline queue is the product's explicit MemoryControllerQueue; no PG/LIVE claim.
"""
import hashlib
import json
import shutil
import sys
from pathlib import Path

from fastapi.testclient import TestClient
from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import SQLiteRepository
from c2hunter_worker.analysis import execute_analysis


def verify(root, payload_path):
    import c2hunter_controller.app as controller_module
    import c2hunter_analysis.ddos_attack as analysis_module
    import c2hunter_worker.analysis as worker_module
    checkout = Path(__file__).parents[2]
    origins = {name: module.__file__ for name, module in [('controller', controller_module), ('analysis', analysis_module), ('worker', worker_module)]}
    assert all(Path(path).is_relative_to(checkout) for path in origins.values()), origins
    database = root / ('replay-' + hashlib.sha256(str(payload_path).encode()).hexdigest()[:16] + '.sqlite')
    assert not database.exists(), 'Use a fresh replay output identity'
    shutil.copy2(root / 'fixture.sqlite', database)
    repo = SQLiteRepository(database)
    repo.upsert_sensor({'sensor_id': 'owned-offline-sensor', 'name': 'Owned offline sensor', 'status': 'ONLINE'})
    client = TestClient(create_app(Settings(environment='test'), repo))
    payloads = json.loads(payload_path.read_text())
    fixture = json.loads((root/'browser-fixture.json').read_text())
    receipts = []
    for request in payloads:
        path, body = request['path'], request['body']
        response = client.post('/api/v1' + path, json=body)
        assert response.status_code == 201, (path, response.status_code, response.text)
        created = response.json(); job_id = created['id']
        replay = client.post('/api/v1' + path, json=body)
        assert replay.status_code == 201 and replay.json()['id'] == job_id, replay.text
        if path == '/pcap-analysis-jobs/initiate':
            uploaded = client.put('/api/v1/pcap-analysis-jobs/' + job_id + '/capture', content=(root/'unmeasured.pcap').read_bytes(), headers={'content-type': 'application/vnd.tcpdump.pcap'})
            assert uploaded.status_code == 202, uploaded.text
            assert client.app.state.process_pcap_preparations_once()
        # If the product queued an offline job, execute its real worker then drain
        # the actual result envelope through the controller (no invented report).
        queue = client.app.state.queue
        for envelope in list(queue.jobs):
            if envelope['id'] != job_id:
                continue
            stored = repo.get_job(job_id)
            result = execute_analysis(stored)
            queue.results.append({**envelope, 'job_id': job_id, 'receipt': 'owned-ui-' + job_id, 'status': 'COMPLETED', 'result': result})
            assert client.app.state.process_results_once()
            queue.jobs.remove(envelope)
        observed = client.get('/api/v1/analysis-jobs/' + job_id)
        assert observed.status_code == 200
        public = observed.json(); stored = repo.get_job(job_id)
        selection = body.get('ddos_normal_reference', 'INHERIT')
        if selection is None:
            assert stored.get('ddos_reference_snapshot') is None
        else:
            snapshot = stored.get('ddos_reference_snapshot')
            assert snapshot and snapshot['reference']['job_id'] == fixture['jobs']['normal']['id']
        assert 'ddos_reference_snapshot' not in json.dumps(public)
        report = public.get('ddos_attack')
        if path != '/analysis-jobs':
            assert public['status'] == 'COMPLETED', public
            assert report and report['version'] == 'ddos-attack-report-v4'
            assert report['findings'], report
            for finding in report['findings']:
                for candidate in finding['signature_candidates']:
                    normal = candidate['evaluation']['normal']
                    assert normal['status'] == ('UNMEASURED' if selection is None else 'MEASURED')
                    if selection is not None:
                        assert normal['result']['matched_packets'] == 0
                        assert normal['result']['eligible_packets'] == 120
        receipts.append({'path': path, 'job_id': job_id, 'status': public['status'], 'report_version': report and report['version'], 'reference': None if not report else report['normal_reference'], 'idempotent_replay': True})
    # Inherit and same-key replay do not reacquire a deleted source.
    normal_id = fixture['jobs']['normal']['id']; repo.delete_job(normal_id)
    inherited = next(r for r in payloads if r['path'].endswith('/reanalyze') and 'ddos_normal_reference' not in r['body'])
    response = client.post('/api/v1' + inherited['path'], json=inherited['body'])
    assert response.status_code == 201, response.text
    fresh = {**inherited['body'], 'idempotency_key': inherited['body']['idempotency_key'] + '-source-deleted'}
    response = client.post('/api/v1' + inherited['path'], json=fresh)
    assert response.status_code == 201, response.text
    observed = client.get('/api/v1/analysis-jobs/' + response.json()['id']).json()
    assert observed['ddos_attack']['normal_reference']['job_id'] == normal_id
    repo.close()
    result = {'module_origins': origins, 'transport': 'real ASGI HTTP TestClient', 'storage': 'real SQLite copy', 'model_calls': 0, 'interface_capture': False, 'requests': receipts, 'deleted_source_inheritance': True}
    (payload_path.parent/'http-pipeline.json').write_text(json.dumps(result, indent=2))
    return result

if __name__ == '__main__':
    print(json.dumps(verify(Path(sys.argv[1]), Path(sys.argv[2]))))
