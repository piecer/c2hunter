"""Offline producer/ASGI tests; requires C2HUNTER_SOURCE_ROOT and project Python."""
import hashlib

import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest

ROOT = Path(os.environ['C2HUNTER_SOURCE_ROOT']).resolve()
BUNDLE = Path(__file__).resolve().parents[1]
WORK = Path(tempfile.mkdtemp(prefix='c2hunter-skill-producer-', dir=os.environ.get('TMPDIR')))
os.environ.clear()
os.environ.update(HOME=str(WORK), TMPDIR=str(WORK), PYTHONDONTWRITEBYTECODE='1')
sys.dont_write_bytecode = True
sys.pycache_prefix = str(WORK / 'cache')
sys.path[:0] = [str(ROOT / p) for p in ('controller/src', 'analysis/src', 'controller')]

from unittest.mock import patch
from fastapi.testclient import TestClient
from c2hunter_controller.ai_analysis import FakeGateway
from c2hunter_controller.ai_queueing import MemoryAIAnalysisTaskQueue
from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import MemoryRepository
from c2hunter_controller.schemas import AIAnalysisRunCreate, AIAnalysisRunCancel, PcapAnalysisJobCreate
from c2hunter_controller.security import required_role

CONTRACT = json.loads((BUNDLE / 'references/operations.json').read_text())
OPENAPI = json.loads((BUNDLE / 'references/openapi.json').read_text())
TOKENS = {'VIEWER': 'synthetic-skill-viewer', 'ANALYST': 'synthetic-skill-analyst'}


def blocked(*args, **kwargs):
    raise AssertionError('producer tests must not access a network')


class ProducerContractTests(unittest.TestCase):
    def setUp(self):
        self.guards = [patch.object(socket.socket, 'connect', blocked),
                       patch.object(socket, 'create_connection', blocked),
                       patch.object(socket, 'getaddrinfo', blocked)]
        for guard in self.guards:
            guard.start()
            self.addCleanup(guard.stop)
        self.repository = MemoryRepository()
        self.queue = MemoryAIAnalysisTaskQueue()
        self.app = create_app(Settings(_env_file=None, environment='test', api_auth_required=True,
            ai_analysis_enabled=True, ai_model_provider='fake', database_url='memory://',
            redis_url='memory://', clickhouse_url='memory://', s3_endpoint='memory://',
            candidate_auto_enrichment_limit=0,
            viewer_token_sha256=hashlib.sha256(TOKENS['VIEWER'].encode()).hexdigest(),
            analyst_token_sha256=hashlib.sha256(TOKENS['ANALYST'].encode()).hexdigest()),
            self.repository, ai_gateway=FakeGateway(), ai_task_queue=self.queue)
        self.client = TestClient(self.app)
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)

    def headers(self, role):
        return {'Authorization': 'Bearer ' + TOKENS[role]}

    def test_exact_producer_openapi_and_source_identity(self):
        self.assertEqual(self.app.openapi(), OPENAPI)
        for path, expected in CONTRACT['source_hashes'].items():
            with self.subTest(path=path):
                self.assertEqual(hashlib.sha256((ROOT/path).read_bytes()).hexdigest(), expected)
        self.assertEqual(self.client.get('/openapi.json').status_code, 401)
        response = self.client.get('/openapi.json', headers=self.headers('VIEWER'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), OPENAPI)

    def test_all_operations_exist_and_roles_match(self):
        for name, op in CONTRACT['operations'].items():
            with self.subTest(operation=name):
                if name == 'openapi-get':
                    self.assertEqual(op['path'], self.app.openapi_url)
                else:
                    self.assertIn(op['method'].lower(), OPENAPI['paths'][op['path']])
                expected = required_role(op['method'], op['path'])
                expected = expected.name if expected else 'PUBLIC'
                if name in ('baseline-comparisons', 'baseline-sources'):
                    expected = 'ANALYST'
                self.assertEqual(op['minimum_role'], expected)
                self.assertEqual(op['write'], op['method'] != 'GET')

    def test_mounted_authentication_for_every_protected_operation(self):
        for name, op in CONTRACT['operations'].items():
            if op['minimum_role'] == 'PUBLIC':
                continue
            path = op['path'].format(**{key: 'missing-id' for key in op['path_parameters']})
            with self.subTest(operation=name):
                response = self.client.request(op['method'], path)
                self.assertEqual(response.status_code, 401)

    def test_viewer_cannot_mutate_or_read_analyst_evidence(self):
        for name, op in CONTRACT['operations'].items():
            if op['minimum_role'] != 'ANALYST':
                continue
            path = op['path'].format(**{key: 'missing-id' for key in op['path_parameters']})
            with self.subTest(operation=name):
                response = self.client.request(op['method'], path, headers=self.headers('VIEWER'))
                self.assertEqual(response.status_code, 403)

    def test_examples_match_real_models(self):
        for filename, model in [('pcap-initiate.json', PcapAnalysisJobCreate),
                                ('ai-create.json', AIAnalysisRunCreate),
                                ('cancel.json', AIAnalysisRunCancel)]:
            with self.subTest(example=filename):
                model.model_validate(json.loads((BUNDLE/'examples'/filename).read_text()))

    def test_pcap_initiate_and_cancel_dispatch_through_auth(self):
        payload = json.loads((BUNDLE/'examples/pcap-initiate.json').read_text())
        response = self.client.post('/api/v1/pcap-analysis-jobs/initiate', json=payload,
                                    headers=self.headers('ANALYST'))
        self.assertEqual(response.status_code, 201, response.text)
        job_id = response.json()['id']
        response = self.client.get('/api/v1/analysis-jobs/'+job_id, headers=self.headers('VIEWER'))
        self.assertEqual(response.status_code, 200)
        cancel = json.loads((BUNDLE/'examples/cancel.json').read_text())
        response = self.client.post('/api/v1/analysis-jobs/'+job_id+'/cancel', json=cancel,
                                    headers=self.headers('ANALYST'))
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['status'], 'CANCELLED')

    def test_ai_acceptance_is_queued_not_completed_and_same_key_is_stable(self):
        self.repository.jobs['source-job'] = {'id': 'source-job', 'status': 'COMPLETED',
            'created_at': '2026-01-01T00:00:00+00:00', 'updated_at': '2026-01-01T00:01:00+00:00',
            'analysis': {'module': 'c2'}}
        payload = json.loads((BUNDLE/'examples/ai-create.json').read_text())
        response = self.client.post('/api/v1/analysis-jobs/source-job/ai-runs', json=payload,
                                    headers=self.headers('ANALYST'))
        self.assertEqual(response.status_code, 201, response.text)
        run = response.json()
        self.assertEqual(run['status'], 'QUEUED')
        self.assertEqual(run['candidate_limit'], 1)
        duplicate = self.client.post('/api/v1/analysis-jobs/source-job/ai-runs', json=payload,
                                     headers=self.headers('ANALYST'))
        self.assertEqual(duplicate.status_code, 200, duplicate.text)
        self.assertEqual(duplicate.json()['id'], run['id'])
        self.assertEqual(self.queue.run_ids, [run['id']])
        response = self.client.get('/api/v1/ai-runs/'+run['id'], headers=self.headers('VIEWER'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['status'], 'QUEUED')

    def test_documented_query_names_exist_in_contract(self):
        expected = {'jobs-list': ['page', 'page_size'], 'job-candidates': ['page', 'page_size'],
                    'ai-selection': ['offset', 'limit'], 'baseline-comparisons': ['offset', 'limit'],
                    'baseline-sources': ['offset', 'limit'], 'baseline-scopes': ['offset', 'limit']}
        for name, keys in expected.items():
            with self.subTest(operation=name):
                self.assertTrue(set(keys) <= set(CONTRACT['operations'][name]['query_parameters']))


if __name__ == '__main__':
    unittest.main()
