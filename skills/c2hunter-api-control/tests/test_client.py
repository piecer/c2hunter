"""Isolated real-loopback acceptance tests; credentials are synthetic."""
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
import io
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
CLIENT = ROOT / 'scripts' / 'client.py'
TOKEN = 'synthetic-client-credential-only'


@contextmanager
def fake_server(replies=None):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def handle_request(self):
            body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
            self.server.records.append((self.command, self.path, dict(self.headers), body))
            reply = self.server.replies.pop(0) if self.server.replies else (200, {}, b'{"ok":true}')
            if callable(reply):
                reply(self)
                return
            if reply is None:
                self.close_connection = True
                return
            status, headers, payload = reply
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            if 'Content-Length' not in headers and 'Transfer-Encoding' not in headers:
                self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass

        do_GET = do_POST = do_PUT = handle_request

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = False
    server.records = []
    server.replies = list(replies or [])
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .02})
    thread.start()
    try:
        yield 'http://127.0.0.1:' + str(server.server_port), server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(3)
        assert not thread.is_alive()



def invoke(*args, base=None, token=TOKEN, input=None, extra_env=None):
    env = {"PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": os.environ['TMPDIR']}
    if base is not None:
        env["C2HUNTER_BASE_URL"] = base
    if token is not None:
        env["C2HUNTER_API_TOKEN"] = token
    env.update(extra_env or {})
    return subprocess.run([sys.executable, "-B", str(CLIENT), *args],
                          env=env, input=input, capture_output=True,
                          text=True, timeout=15)


def load_client():
    spec = importlib.util.spec_from_file_location('owned_client', CLIENT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ClientTests(unittest.TestCase):
    def assert_error(self, result, code, status=None, unknown=False):
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')
        self.assertTrue(result.stderr.startswith('{'), 'fixed JSON diagnostic missing')
        self.assertEqual(json.loads(result.stderr), {
            'error': code, 'http_status': status, 'write_outcome_unknown': unknown})
        self.assertNotIn(TOKEN, result.stdout + result.stderr)

    def test_preflight_refuses_unconsented_writes_before_files_or_network(self):
        contract = json.loads((ROOT / 'references/operations.json').read_text())
        with fake_server() as (base, server):
            for name, op in contract['operations'].items():
                if op['write']:
                    with self.subTest(operation=name):
                        result = invoke('request', name, '--json', '/not-a-real-body-file', base=base)
                        self.assert_error(result, 'WRITE_REQUIRES_ALLOW_WRITE')
            self.assertEqual(server.records, [])

    def test_preflight_validation_is_fixed_and_secret_safe(self):
        with fake_server() as (base, server):
            cases = [
                (['request', TOKEN], 'INVALID_OPERATION'),
                (['request', 'health', '--token', TOKEN], 'CLI_ERROR'),
                (['request', 'health', '--timeout', TOKEN], 'CLI_ERROR'),
                (['request', 'job-get'], 'INVALID_PARAMETERS'),
                (['request', 'job-get', '--param', 'job_id=..'], 'INVALID_PARAMETERS'),
                (['request', 'job-get', '--param', 'job_id=a/b'], 'INVALID_PARAMETERS'),
                (['request', 'job-get', '--param', 'job_id=%2f'], 'INVALID_PARAMETERS'),
                (['request', 'job-get', '--param', 'job_id=x', '--param', 'job_id=y'], 'INVALID_PARAMETERS'),
                (['request', 'health', '--param', 'url=' + base], 'INVALID_PARAMETERS'),
                (['request', 'health', '--query', 'token=' + TOKEN], 'INVALID_PARAMETERS'),
                (['request', 'jobs-list', '--query', 'page=1', '--query', 'page=2'], 'INVALID_PARAMETERS'),
                (['request', 'jobs-list', '--query', 'search=x\r\ny'], 'INVALID_PARAMETERS'),
                (['request', 'health', '--json', '/not-a-real-body-file'], 'INVALID_BODY'),
                (['request', 'health', '--timeout', '0'], 'CLI_ERROR'),
                (['request', 'health', '--timeout', '61'], 'CLI_ERROR'),
            ]
            for args, error in cases:
                with self.subTest(error=error, case=cases.index((args, error))):
                    self.assert_error(invoke(*args, base=base), error)
            self.assertEqual(server.records, [])

    def test_bad_origins_and_tokens_never_reach_loopback(self):
        with fake_server() as (base, server):
            origins = [None, base + '/', base + '/api', base + '?', base + '#',
                       base.replace('://', '://user@'), base + '\n', ' ' + base,
                       base.replace('http:', 'ftp:'), base + ':999', base + '%00']
            for origin in origins:
                with self.subTest(origin_index=origins.index(origin)):
                    self.assert_error(invoke('request', 'health', base=origin), 'CONFIG_ERROR')
            for token in [None, '', ' leading', 'trailing ', 'a\tb', 'a\rb', 'a\nb', 'nonasciié']:
                with self.subTest(token_index=[None, '', ' leading', 'trailing ', 'a\tb', 'a\rb', 'a\nb', 'nonasciié'].index(token)):
                    self.assert_error(invoke('request', 'health', base=base, token=token), 'CONFIG_ERROR')
            self.assertEqual(server.records, [])

    def test_ai_create_defaults_and_explicit_remote_consent(self):
        with fake_server([(201, {}, b'{"status":"QUEUED"}')]) as (base, server):
            args = ['request', 'ai-create', '--param', 'job_id=Job_01', '--allow-write', '--json', '-']
            result = invoke(*args, base=base, input='{"idempotency_key":"test-key"}')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['data']['status'], 'QUEUED')
            method, path, headers, body = server.records[0]
            self.assertEqual((method, path), ('POST', '/api/v1/analysis-jobs/Job_01/ai-runs'))
            self.assertEqual(headers['Content-Type'], 'application/json')
            self.assertEqual(json.loads(body), {'idempotency_key': 'test-key', 'candidate_limit': 1,
                'allow_remote': False, 'analysis_kind': 'C2', 'language': 'ko',
                'discovery_mode': 'legacy', 'baseline_mode': 'off'})
            remote = '{"idempotency_key":"remote-test","allow_remote":true}'
            self.assert_error(invoke(*args, base=base, input=remote), 'REMOTE_MODEL_REQUIRES_CONSENT')
            result = invoke(*args, '--allow-remote-model', base=base, input=remote)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(server.records[-1][3])['allow_remote'])
            self.assertEqual(len(server.records), 2)

    def test_ai_candidates_and_json_shape_rejected_before_send(self):
        with fake_server() as (base, server):
            args = ['request', 'ai-create', '--param', 'job_id=x', '--allow-write', '--json', '-']
            invalid = ['[]', 'null', '{', '{"idempotency_key":"a","x":NaN}', '{}',
                       '{"idempotency_key":"a","candidate_limit":1,"candidate_limit":2}']
            for candidate in [True, False, 0, 6, 1.2, '2', None]:
                invalid.append(json.dumps({'idempotency_key': 'x', 'candidate_limit': candidate}))
            for body in invalid:
                with self.subTest(body_index=invalid.index(body)):
                    self.assert_error(invoke(*args, base=base, input=body), 'INVALID_BODY')
            for value in ['yes', 1, None]:
                self.assert_error(invoke(*args, base=base, input=json.dumps({
                    'idempotency_key': 'x', 'allow_remote': value})), 'INVALID_BODY')
            self.assertEqual(server.records, [])

    def test_job_create_needs_bounded_capture_and_ordered_timestamps(self):
        valid = {'capture': {'duration_seconds': 10, 'max_packets': 100, 'max_bytes': 10000},
                 'start_time': '2026-01-01T00:00:00Z', 'end_time': '2026-01-01T00:00:10Z'}
        with fake_server() as (base, server):
            args = ['request', 'job-create', '--allow-write', '--json', '-']
            bad = [{}, {'capture': {}}, dict(valid, end_time=valid['start_time']),
                   dict(valid, start_time='not-a-time')]
            for key in valid['capture']:
                for value in [0, -1, True, None, float('inf')]:
                    bad.append(dict(valid, capture=dict(valid['capture'], **{key: value})))
            for data in bad:
                self.assert_error(invoke(*args, base=base, input=json.dumps(data)), 'INVALID_BODY')
            self.assertEqual(server.records, [])
            result = invoke(*args, base=base, input=json.dumps(valid))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(server.records[0][3]), valid)

    def test_binary_and_json_actual_byte_limits_before_send(self):
        temporary = tempfile.TemporaryDirectory(prefix='c2hunter-client-', dir=os.environ['TMPDIR'])
        self.addCleanup(temporary.cleanup)
        work = Path(temporary.name)
        small = work / 'small.bin'
        large = work / 'large.bin'
        small.write_bytes(b'\x00\xffsynthetic-capture')
        with large.open('wb') as stream:
            stream.truncate(64 * 1024 * 1024 + 1)
        try:
            with fake_server([(202, {}, b'{"status":"QUEUED"}')]) as (base, server):
                args = ['request', 'pcap-upload', '--param', 'job_id=p1', '--allow-write']
                result = invoke(*args, '--binary', str(small), base=base)
                self.assertEqual(result.returncode, 0, result.stderr)
                method, path, headers, body = server.records[0]
                self.assertEqual((method, path, body), ('PUT', '/api/v1/pcap-analysis-jobs/p1/capture', small.read_bytes()))
                self.assertEqual(headers['Content-Type'], 'application/octet-stream')
                self.assert_error(invoke(*args, '--binary', str(large), base=base), 'BODY_TOO_LARGE')
                self.assert_error(invoke(*args, '--json', '-', base=base, input='{}'), 'INVALID_BODY')
                self.assert_error(invoke('request', 'pcap-initiate', '--allow-write', '--json', '-',
                                        base=base, input=' ' * (1024 * 1024) + '{}'), 'BODY_TOO_LARGE')
                self.assertEqual(len(server.records), 1)
        finally:
            small.unlink()
            large.unlink()

    def test_redirects_never_follow_same_or_other_origin(self):
        with fake_server() as (sink_url, sink):
            for write in [False, True]:
                for status in [301, 302, 303, 307, 308]:
                    with fake_server() as (base, server):
                        for location in [base + '/second', sink_url + '/second']:
                            server.replies.append((status, {'Location': location}, b'{}'))
                            args = ['request', 'job-cancel', '--param', 'job_id=x', '--allow-write', '--json', '-'] if write else ['request', 'health']
                            result = invoke(*args, base=base, input='{}')
                            self.assert_error(result, 'WRITE_OUTCOME_UNKNOWN' if write else 'REDIRECT_REFUSED', status, write)
                        self.assertEqual(len(server.records), 2)
            self.assertEqual(sink.records, [])

    def test_http_failures_and_dropped_connection_never_retry_writes(self):
        for status in [401, 429, 500]:
            for write in [False, True]:
                with fake_server([(status, {}, TOKEN.encode())]) as (base, server):
                    args = ['request', 'job-cancel', '--param', 'job_id=x', '--allow-write', '--json', '-'] if write else ['request', 'health']
                    unknown = write and status >= 500
                    result = invoke(*args, base=base, input='{}')
                    self.assert_error(result, 'WRITE_OUTCOME_UNKNOWN' if unknown else 'HTTP_ERROR', status, unknown)
                    self.assertEqual(len(server.records), 1)
        with fake_server([None]) as (base, server):
            result = invoke('request', 'job-cancel', '--param', 'job_id=x', '--allow-write', '--json', '-', base=base, input='{}')
            self.assert_error(result, 'WRITE_OUTCOME_UNKNOWN', unknown=True)
            self.assertEqual(len(server.records), 1)

    def test_invalid_oversized_and_truncated_responses(self):
        cases = [({}, TOKEN.encode(), 'INVALID_RESPONSE'),
                 ({}, b'{"x":NaN}', 'INVALID_RESPONSE'),
                 ({}, b'{"x":1e999}', 'INVALID_RESPONSE'),
                 ({'Content-Length': str(2 * 1024 * 1024 + 1)}, b'{}', 'RESPONSE_TOO_LARGE'),
                 ({}, b' ' * (2 * 1024 * 1024) + b'{}', 'RESPONSE_TOO_LARGE'),
                 ({'Content-Length': '100'}, b'{}', 'INVALID_RESPONSE'),
                 ({'Content-Length': '-1'}, b'{}', 'INVALID_RESPONSE')]
        for headers, body, code in cases:
            for write in [False, True]:
                with self.subTest(case=cases.index((headers, body, code)), write=write):
                    with fake_server([(200, headers, body)]) as (base, server):
                        args = ['request', 'job-cancel', '--param', 'job_id=x', '--allow-write', '--json', '-'] if write else ['request', 'health']
                        result = invoke(*args, base=base, input='{}')
                        self.assert_error(result, 'WRITE_OUTCOME_UNKNOWN' if write else code, 200, write)
                        self.assertEqual(len(server.records), 1)

    def test_secret_redaction_decodes_json_escapes_and_nested_keys(self):
        token = 'synthetic-"quoted"-credential'
        data = {token: [{'prefix-' + token: token}], 'safe': 'prefix' + token + 'suffix'}
        payload = json.dumps(data).replace('synthetic', '\\u0073ynthetic').encode()
        with fake_server([(200, {}, payload)]) as (base, server):
            result = invoke('request', 'health', base=base, token=token)
            self.assertEqual(result.returncode, 0, result.stderr)
            decoded = json.loads(result.stdout)
            self.assertEqual(decoded['data'], {'[REDACTED]': [{'prefix-[REDACTED]': '[REDACTED]'}],
                                               'safe': 'prefix[REDACTED]suffix'})
            self.assertNotIn(token, json.dumps(decoded))
            self.assertEqual(result.stderr, '')

    def test_deadline_bounds_trickling_headers_and_chunk_metadata(self):
        for phase in ['header', 'chunk']:
            def slow(handler):
                try:
                    if phase == 'header':
                        handler.wfile.write(b'HTTP/1.1 200 OK\r\nX-Slow: ')
                    else:
                        handler.wfile.write(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;')
                    for _ in range(22):
                        handler.wfile.write(b'x')
                        handler.wfile.flush()
                        time.sleep(.1)
                    handler.wfile.write(b'\r\nContent-Length: 2\r\n\r\n{}' if phase == 'header' else b'\r\n{}\r\n0\r\n\r\n')
                except (OSError, ValueError):
                    pass
            with fake_server([slow]) as (base, server):
                start = time.monotonic()
                result = invoke('request', 'job-cancel', '--param', 'job_id=x', '--allow-write',
                                '--json', '-', '--timeout', '1', base=base, input='{}')
                elapsed = time.monotonic() - start
                self.assert_error(result, 'WRITE_OUTCOME_UNKNOWN', None if phase == 'header' else 200, True)
                self.assertLess(elapsed, 1.8)
                self.assertEqual(len(server.records), 1)

    def test_actual_chunked_byte_limit_and_boundary(self):
        for count in [2 * 1024 * 1024, 2 * 1024 * 1024 + 1]:
            payload = b'{"x":"' + b'a' * (count - 8) + b'"}'
            wire = hex(len(payload))[2:].encode() + b'\r\n' + payload + b'\r\n0\r\n\r\n'
            with fake_server([(200, {'Transfer-Encoding': 'chunked'}, wire)]) as (base, server):
                result = invoke('request', 'health', base=base)
                if count == 2 * 1024 * 1024:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(len(json.loads(result.stdout)['data']['x']), count - 8)
                else:
                    self.assert_error(result, 'RESPONSE_TOO_LARGE', 200)
                self.assertEqual(len(server.records), 1)

    def test_watch_queued_to_completed_only_gets(self):
        for op, param, path in [('job-get', 'job_id=x', '/api/v1/analysis-jobs/x'),
                                ('ai-get', 'run_id=x', '/api/v1/ai-runs/x')]:
            replies = [(200, {}, json.dumps({'status': state}).encode()) for state in ['QUEUED', 'COMPLETED']]
            with fake_server(replies) as (base, server):
                start = time.monotonic()
                result = invoke('watch', op, '--param', param, '--max-polls', '2', '--interval', '1', base=base)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), {'status': 200, 'data': {'status': 'COMPLETED'},
                                                            'state': 'COMPLETED', 'polls': 2})
                self.assertGreaterEqual(time.monotonic() - start, 1)
                self.assertEqual([(r[0], r[1]) for r in server.records], [('GET', path)] * 2)

    def test_watch_partial_failed_cancelled_and_exhausted(self):
        for state, error in [('PARTIALLY_COMPLETED', 'PARTIALLY_COMPLETED'), ('FAILED', 'FAILED'),
                             ('CANCELLED', 'CANCELLED'), ('QUEUED', 'INCOMPLETE')]:
            with fake_server([(200, {}, json.dumps({'status': state}).encode())]) as (base, server):
                result = invoke('watch', 'job-get', '--param', 'job_id=x', '--max-polls', '1', base=base)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')
                self.assertEqual(json.loads(result.stderr), {'error': error, 'http_status': 200,
                    'write_outcome_unknown': False, 'polls': 1, 'state': state})
                self.assertEqual(len(server.records), 1)
                self.assertEqual(server.records[0][0], 'GET')

    def test_watch_preserves_producer_nonterminal_states_at_budget(self):
        for operation, parameter, states in [
            ('job-get', 'job_id=x', ['CREATED', 'WAITING_FOR_SENSOR', 'UPLOADING', 'INGESTING']),
            ('ai-get', 'run_id=x', ['PREPARING']),
        ]:
            for state in states:
                with self.subTest(operation=operation, state=state):
                    reply = (200, {}, json.dumps({'status': state}).encode())
                    with fake_server([reply]) as (base, server):
                        result = invoke('watch', operation, '--param', parameter,
                                        '--max-polls', '1', base=base)
                        self.assertEqual(result.returncode, 6)
                        self.assertEqual(json.loads(result.stderr), {
                            'error': 'INCOMPLETE', 'http_status': 200,
                            'write_outcome_unknown': False, 'polls': 1, 'state': state,
                        })
                        self.assertEqual(len(server.records), 1)

    def test_watch_validation_and_unknown_server_status_diagnostics(self):
        with fake_server([(200, {}, json.dumps({'status': TOKEN}).encode())]) as (base, server):
            for args in [['watch', 'job-cancel'], ['watch', 'health'],
                         ['watch', 'job-get', '--max-polls', '0'],
                         ['watch', 'job-get', '--max-polls', '101'],
                         ['watch', 'job-get', '--interval', '0'],
                         ['watch', 'job-get', '--interval', 'nan'],
                         ['watch', 'job-get', '--allow-write']]:
                result = invoke(*args, base=base)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')
            self.assertEqual(server.records, [])
            result = invoke('watch', 'ai-get', '--param', 'run_id=x', '--max-polls', '1', base=base)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(TOKEN, result.stderr)
            self.assertEqual(json.loads(result.stderr)['error'], 'INCOMPLETE')
            self.assertNotIn('data', json.loads(result.stderr))
            self.assertEqual(len(server.records), 1)

    def test_baseline_scopes_query_canonical_bounds(self):
        with fake_server() as (base, server):
            for query in ['offset=01', 'offset=-1', 'offset=17', 'offset=1.0', 'limit=0', 'limit=21', 'limit=+1']:
                self.assert_error(invoke('request', 'baseline-scopes', '--query', query, base=base), 'INVALID_PARAMETERS')
            self.assertEqual(server.records, [])
            result = invoke('request', 'baseline-scopes', '--query', 'offset=16', '--query', 'limit=20', base=base)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(server.records[0][1], '/api/v1/historical-baselines/scopes?offset=16&limit=20')

    def test_origin_policy_and_tls_verification_without_remote_dials(self):
        client = load_client()
        invalid = ['http://example.invalid', 'http://192.0.2.1', 'http://127.1',
                   'http://2130706433', 'http://localhost.',
                   'http://127.0.0.1:0', 'https://a\\b', 'https://%65xample.invalid',
                   'https://user:pass@example.invalid', 'https://example.invalid#',
                   'http://127.0.0.1:\t80', 'https://example.invalid\x7f',
                   'http://[::1]trailing', 'https://a..invalid', 'https://-bad.invalid']
        with mock.patch.object(client.socket, 'create_connection', side_effect=AssertionError('unexpected dial')) as dial:
            for origin in invalid:
                with mock.patch.object(client.os, 'environ', {'C2HUNTER_BASE_URL': origin, 'C2HUNTER_API_TOKEN': TOKEN}):
                    with self.assertRaises(client.ClientError) as raised:
                        client.configuration()
                    self.assertEqual(raised.exception.code, 'CONFIG_ERROR')
            for origin in ['http://[::1]:1234', 'http://localhost:1234', 'https://example.invalid:443']:
                with mock.patch.object(client.os, 'environ', {'C2HUNTER_BASE_URL': origin, 'C2HUNTER_API_TOKEN': TOKEN}):
                    url, token = client.configuration()
                    self.assertEqual(token, TOKEN)
            dial.assert_not_called()
        contexts = []
        def no_connect(connection):
            contexts.append(connection._context)
            raise OSError('synthetic transport failure')
        with mock.patch.object(client.http.client.HTTPSConnection, 'connect', no_connect):
            with self.assertRaises(client.ClientError):
                client.request(url, TOKEN, {'write': False, 'method': 'GET'}, '/api/v1/health', 1)
        self.assertEqual(len(contexts), 1)
        self.assertTrue(contexts[0].check_hostname)
        self.assertEqual(contexts[0].verify_mode, ssl.CERT_REQUIRED)

    def test_all_contract_operations_dispatch_exact_method_path_auth(self):
        contract = json.loads((ROOT / 'references/operations.json').read_text())
        self.assertIn('openapi-get', contract['operations'])
        with tempfile.TemporaryDirectory(prefix='c2hunter-client-all-', dir=os.environ['TMPDIR']) as tmp:
            binary = Path(tmp) / 'capture.bin'
            binary.write_bytes(b'fake-capture')
            with fake_server() as (base, server):
                for name, op in contract['operations'].items():
                    args = ['request', name]
                    params = {key: 'Preserve_ID-01' for key in op['path_parameters']}
                    for key, value in params.items():
                        args.extend(['--param', key + '=' + value])
                    body = '{}'
                    if op['write']:
                        args.append('--allow-write')
                    if op['body'] == 'json':
                        args.extend(['--json', '-'])
                        if name == 'ai-create':
                            body = '{"idempotency_key":"test"}'
                        elif name == 'job-create':
                            body = json.dumps({'capture': {'duration_seconds': 1, 'max_packets': 1, 'max_bytes': 1},
                                'start_time': '2026-01-01T00:00:00Z', 'end_time': '2026-01-01T00:00:01Z'})
                    elif op['body'] == 'binary':
                        args.extend(['--binary', str(binary)])
                    result = invoke(*args, base=base, input=body)
                    self.assertEqual(result.returncode, 0, name + ': ' + result.stderr)
                    method, path, headers, sent = server.records[-1]
                    self.assertEqual((method, path), (op['method'], op['path'].format(**params)))
                    self.assertEqual(headers['Authorization'], 'Bearer ' + TOKEN)
                self.assertEqual(len(server.records), len(contract['operations']))

    def test_tls_does_not_enable_ambient_key_logging(self):
        client = load_client()
        contexts = []
        def no_connect(connection):
            contexts.append(connection._context)
            raise OSError('synthetic TLS transport failure')
        with tempfile.TemporaryDirectory(prefix='c2hunter-client-tls-', dir=os.environ['TMPDIR']) as tmp:
            keylog = Path(tmp) / 'forbidden-keylog.txt'
            with mock.patch.object(client.os, 'environ', {'SSLKEYLOGFILE': str(keylog)}), \
                    mock.patch.object(client.http.client.HTTPSConnection, 'connect', no_connect):
                with self.assertRaises(client.ClientError):
                    client.request(client.urlsplit('https://example.invalid'), TOKEN,
                                   {'write': False, 'method': 'GET'}, '/api/v1/health', 1)
            self.assertIsNone(contexts[0].keylog_filename)
            self.assertFalse(keylog.exists())

    def test_secret_echo_numeric_values_are_redacted(self):
        with fake_server([(200, {}, b'{"credential":123456789,"safe":true}')]) as (base, server):
            result = invoke('request', 'health', base=base, token='123456789')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('123456789', result.stdout)
            self.assertEqual(json.loads(result.stdout)['data']['credential'], '[REDACTED]')

    def test_binary_exact_limit_is_accepted_as_raw_bytes(self):
        size = 64 * 1024 * 1024
        with tempfile.TemporaryDirectory(prefix='c2hunter-client-boundary-', dir=os.environ['TMPDIR']) as tmp:
            path = Path(tmp) / 'exact-limit.bin'
            with path.open('wb') as stream:
                stream.truncate(size)
            with fake_server([(202, {}, b'{"status":"QUEUED"}')]) as (base, server):
                result = invoke('request', 'pcap-upload', '--param', 'job_id=x', '--allow-write',
                                '--binary', str(path), base=base)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(server.records), 1)
                self.assertEqual(len(server.records[0][3]), size)
                self.assertEqual(server.records[0][2]['Content-Length'], str(size))
                self.assertEqual(server.records[0][3].count(0), size)

    def test_get_dispatch_auth_query_and_ignores_proxy_environment(self):
        with fake_server() as (base, server), fake_server() as (proxy, sink):
            result = invoke('request', 'job-candidates', '--param', 'job_id=Job_01',
                            '--query', 'page=2', '--query', 'sort=score:desc', base=base,
                            extra_env={'HTTP_PROXY': proxy, 'http_proxy': proxy,
                                       'ALL_PROXY': proxy, 'NO_PROXY': ''})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), {'status': 200, 'data': {'ok': True}})
            self.assertEqual(result.stderr, '')
            self.assertEqual(len(server.records), 1)
            method, path, headers, body = server.records[0]
            self.assertEqual((method, path, body), ('GET', '/api/v1/analysis-jobs/Job_01/candidates?page=2&sort=score%3Adesc', b''))
            self.assertEqual(headers['Authorization'], 'Bearer ' + TOKEN)
            self.assertEqual(sink.records, [])

    def test_describe_is_offline_and_matches_contract(self):
        self.assertTrue(CLIENT.is_file(), "client implementation missing")
        result = invoke("describe", token=None)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        expected = json.loads((ROOT / "references" / "operations.json").read_text())
        self.assertEqual(json.loads(result.stdout), expected)
        result = invoke("describe", "ai-create", token=None)
        self.assertEqual(json.loads(result.stdout), expected["operations"]["ai-create"])


class F1Tests(unittest.TestCase):
    write_args = ['request', 'job-cancel', '--param', 'job_id=x', '--allow-write', '--json', '-']

    def assert_diagnostic(self, code, stderr, expected, status=None, unknown=False):
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(stderr), {'error': expected, 'http_status': status,
                                            'write_outcome_unknown': unknown})
        self.assertNotIn(TOKEN, stderr)
        self.assertNotIn('raw-response-marker', stderr)

    def cleanup_case(self, reply, faults, expected, status=None, unknown=False,
                     write=True, connect_fault=False):
        client = load_client()
        events = []

        def closing(original, phase):
            def close(instance, *args, **kwargs):
                original(instance, *args, **kwargs)
                events.append(phase)
                if phase in faults:
                    raise OSError('synthetic cleanup failure: ' + TOKEN)
            return close

        out, err = io.StringIO(), io.StringIO()
        with fake_server([reply]) as (base, server), ExitStack() as stack:
            for cls, method, phase in [
                (client.threading.Timer, 'cancel', 'cancel'),
                (client.threading.Timer, 'join', 'join'),
                (client.http.client.HTTPResponse, 'close', 'response'),
                (client.http.client.HTTPConnection, 'close', 'connection'),
            ]:
                stack.enter_context(mock.patch.object(cls, method, closing(getattr(cls, method), phase)))
            if connect_fault:
                stack.enter_context(mock.patch.object(client.http.client.HTTPConnection, 'connect',
                                                      side_effect=OSError(TOKEN)))
            stack.enter_context(mock.patch.dict(os.environ, {
                'C2HUNTER_BASE_URL': base, 'C2HUNTER_API_TOKEN': TOKEN}, clear=True))
            stdin = stack.enter_context(io.TextIOWrapper(io.BytesIO(b'{}')))
            stack.enter_context(mock.patch.object(client.sys, 'stdin', stdin))
            stack.enter_context(redirect_stdout(out))
            stack.enter_context(redirect_stderr(err))
            code = client.main(self.write_args if write else ['request', 'health'])
            self.assertEqual(len(server.records), 0 if connect_fault else 1)
            if server.records:
                self.assertEqual(server.records[0][0], 'POST' if write else 'GET')
        self.assertEqual(out.getvalue(), '')
        self.assert_diagnostic(code, err.getvalue(), expected, status, unknown)
        expected_cleanup = ['connection'] if connect_fault else (
            ['cancel', 'join', 'connection'] if reply is None else ['cancel', 'join', 'response', 'connection'])
        # Connection close can also run inside stdlib getresponse(). The final
        # independent cleanup sequence must still run after every injected fault.
        self.assertEqual(events[-len(expected_cleanup):], expected_cleanup)

    def test_close_faults_preserve_write_status(self):
        for phase in ['response', 'connection']:
            for status in [200, 500]:
                with self.subTest(phase=phase, status=status):
                    self.cleanup_case((status, {}, b'{"accepted":true}'), {phase},
                                      'WRITE_OUTCOME_UNKNOWN', status, True)

    def test_secondary_cleanup_preserves_drop_and_invalid_json_uncertainty(self):
        for reply, status in [(None, None), (200, 200)]:
            with self.subTest(status=status):
                payload = None if reply is None else (200, {}, b'raw-response-marker' + TOKEN.encode())
                self.cleanup_case(payload, {'connection', 'response'}, 'WRITE_OUTCOME_UNKNOWN', status, True)

    def test_every_cleanup_is_attempted_even_when_earlier_cleanup_fails(self):
        phases = {'cancel', 'join', 'response', 'connection'}
        for faults in [{phase} for phase in sorted(phases)] + [phases]:
            with self.subTest(faults=sorted(faults)):
                self.cleanup_case((200, {}, b'{}'), faults, 'WRITE_OUTCOME_UNKNOWN', 200, True)

    def test_known_http_rejections_survive_all_cleanup_faults(self):
        for status in [401, 429]:
            with self.subTest(status=status):
                self.cleanup_case((status, {}, TOKEN.encode()), {'cancel', 'join', 'response', 'connection'},
                                  'HTTP_ERROR', status)

    def test_read_failures_survive_secondary_cleanup_without_write_uncertainty(self):
        for reply, error, status in [(None, 'NETWORK_ERROR', None),
                                     ((500, {}, TOKEN.encode()), 'HTTP_ERROR', 500),
                                     ((200, {}, TOKEN.encode()), 'INVALID_RESPONSE', 200)]:
            with self.subTest(error=error):
                self.cleanup_case(reply, {'cancel', 'join', 'response', 'connection'},
                                  error, status, write=False)

    def test_connect_failure_with_cleanup_fault_has_no_write_dispatch(self):
        self.cleanup_case(None, {'connection'}, 'NETWORK_ERROR', connect_fault=True)

    def closed_pipe(self, args, reply):
        with fake_server([reply]) as (base, server):
            env = {'TMPDIR': os.environ['TMPDIR'], 'PYTHONDONTWRITEBYTECODE': '1',
                   'C2HUNTER_BASE_URL': base, 'C2HUNTER_API_TOKEN': TOKEN}
            read_fd, write_fd = os.pipe()
            os.close(read_fd)  # No reader exists before spawn: real, deterministic EPIPE.
            try:
                with subprocess.Popen([sys.executable, '-B', str(CLIENT), *args],
                                      stdin=subprocess.PIPE, stdout=write_fd, stderr=subprocess.PIPE,
                                      env=env, text=True) as child:
                    _, stderr = child.communicate('{}', timeout=10)
                    code = child.returncode
            finally:
                os.close(write_fd)
            records = list(server.records)
        return code, stderr, records

    def test_closed_stdout_small_and_large_write_receipts_are_uncertain(self):
        for size in [0, 65536]:
            with self.subTest(size=size):
                body = json.dumps({'accepted': True, 'padding': 'x' * size}).encode()
                code, stderr, records = self.closed_pipe(self.write_args, (202, {}, body))
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0][0], 'POST')
                self.assert_diagnostic(code, stderr, 'WRITE_OUTCOME_UNKNOWN', 202, True)

    def test_closed_stdout_read_and_offline_outputs_are_not_uncertain_writes(self):
        for args, count, status in [(['request', 'health'], 1, 200), (['describe'], 0, None)]:
            with self.subTest(args=args):
                code, stderr, records = self.closed_pipe(args, (200, {}, b'{}'))
                self.assertEqual(len(records), count)
                self.assert_diagnostic(code, stderr, 'CLIENT_ERROR', status)

    def test_closed_stdout_keeps_preflight_and_primary_write_diagnostics(self):
        cases = [(['request', 'job-cancel'], (200, {}, b'{}'), 'WRITE_REQUIRES_ALLOW_WRITE', None, False, 0),
                 (self.write_args, (429, {}, TOKEN.encode()), 'HTTP_ERROR', 429, False, 1),
                 (self.write_args, (500, {}, TOKEN.encode()), 'WRITE_OUTCOME_UNKNOWN', 500, True, 1),
                 (self.write_args, (200, {}, TOKEN.encode()), 'WRITE_OUTCOME_UNKNOWN', 200, True, 1),
                 (self.write_args, None, 'WRITE_OUTCOME_UNKNOWN', None, True, 1)]
        for args, reply, error, status, unknown, count in cases:
            with self.subTest(error=error, status=status):
                code, stderr, records = self.closed_pipe(args, reply)
                self.assertEqual(len(records), count)
                self.assert_diagnostic(code, stderr, error, status, unknown)

    def test_main_flushes_but_does_not_close_or_redirect_caller_stdout(self):
        for size in [0, 65536]:
            with self.subTest(size=size):
                client = load_client()
                body = json.dumps({'accepted': True, 'padding': 'x' * size}).encode()
                read_fd, write_fd = os.pipe()
                os.close(read_fd)
                stream = os.fdopen(write_fd, 'w')
                identity = os.fstat(write_fd)
                err = io.StringIO()
                try:
                    with fake_server([(200, {}, body)]) as (base, server), \
                            mock.patch.dict(os.environ, {'C2HUNTER_BASE_URL': base,
                                                        'C2HUNTER_API_TOKEN': TOKEN}, clear=True), \
                            io.TextIOWrapper(io.BytesIO(b'{}')) as stdin, \
                            mock.patch.object(client.sys, 'stdin', stdin), \
                            redirect_stdout(stream), redirect_stderr(err):
                        code = client.main(self.write_args)
                        self.assertIs(client.sys.stdout, stream)
                        self.assertFalse(stream.closed)
                        after = os.fstat(write_fd)
                        self.assertEqual((after.st_dev, after.st_ino), (identity.st_dev, identity.st_ino))
                        self.assertEqual(len(server.records), 1)
                    self.assert_diagnostic(code, err.getvalue(), 'WRITE_OUTCOME_UNKNOWN', 200, True)
                finally:
                    try:
                        stream.close()
                    except BrokenPipeError:
                        pass


if __name__ == "__main__":
    unittest.main()
