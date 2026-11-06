"""Source-bound producer witnesses; sealed mode never opens a provider socket.

Default: fresh real service/evidence generation, using a loopback scripted provider.
Review mode: exact producer-owned bytes + hash-bound source/schema manifests;
Python producer freshness is a separate gate, not claimed by this loader.
"""
import fcntl
import hashlib
import json
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(os.environ.get('C2HUNTER_INVESTIGATION_PRODUCER_ROOT', Path(__file__).resolve().parents[2])).resolve()
SOURCE_MANIFEST = os.environ.get('C2HUNTER_INVESTIGATION_SOURCE_MANIFEST')
SERVICE_MANIFEST = os.environ.get('C2HUNTER_INVESTIGATION_SERVICE_MANIFEST')
assert bool(SOURCE_MANIFEST) == bool(SERVICE_MANIFEST), 'incomplete sealed fixture binding'
if SOURCE_MANIFEST:
    def forbid_network(event, args):
        if event in {'socket.bind', 'socket.connect', 'socket.getaddrinfo'}:
            raise AssertionError('sealed producer loader forbids network operations')
    sys.addaudithook(forbid_network)


def read_manifest(path, digest_name):
    raw = Path(path).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == os.environ[digest_name], 'manifest identity mismatch'
    return json.loads(raw)


source_manifest = read_manifest(SOURCE_MANIFEST, 'C2HUNTER_INVESTIGATION_SOURCE_SHA256') if SOURCE_MANIFEST else None
service_manifest = read_manifest(SERVICE_MANIFEST, 'C2HUNTER_INVESTIGATION_SERVICE_SHA256') if SERVICE_MANIFEST else None
if source_manifest:
    source_paths = sorted(ROOT / name for name in source_manifest if name.endswith('.py') and (
        name.startswith(('controller/src/', 'analysis/src/')) or name.startswith('controller/tests/test_ai_investigation')))
else:
    source_paths = sorted([*(ROOT / 'controller/src').rglob('*.py'), *(ROOT / 'analysis/src').rglob('*.py'), *(ROOT / 'controller/tests').glob('test_ai_investigation*.py')])
source_before = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in source_paths}
if source_manifest:
    assert all(source_manifest[name]['sha256'] == digest for name, digest in source_before.items()), 'source differs from sealed producer'

# Explicit source origins; never fall back to a main checkout's hard-coded .venv.
sys.path[:0] = [str(ROOT / 'controller'), str(ROOT / 'controller/src'), str(ROOT / 'analysis/src')]
import c2hunter_controller.ai_investigation_schema as schema
from c2hunter_controller.ai_investigation_contract import Evidence

assert Path(schema.__file__).resolve().is_relative_to(ROOT / 'controller/src')
models = [schema.InvestigationCapabilities, schema.SourcePreview, schema.InvestigationRequest,
          schema.InvestigationRun, schema.InvestigationStep, schema.InvestigationResult, Evidence]
schemas = {model.__name__: model.model_json_schema() for model in models}
assert source_before == {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in source_paths}, 'producer changed during schema generation'
if '--schemas' in sys.argv:
    print(json.dumps(schemas, ensure_ascii=False, sort_keys=True, indent=2))
else:
    fixtures = {}
    counts = {}
    if source_manifest:
        generated = []
        for directory in ['ai_investigation_service', 'ai_investigation']:
            prefix = f'controller/tests/fixtures/{directory}/'
            produced = {}
            for name, metadata in source_manifest.items():
                if not name.startswith(prefix) or not name.endswith('.json'):
                    continue
                raw = (ROOT / name).read_bytes()
                assert hashlib.sha256(raw).hexdigest() == metadata['sha256'], f'fixture identity mismatch: {name}'
                if directory == 'ai_investigation_service':
                    assert service_manifest[Path(name).name] == metadata['sha256']
                produced[Path(name).stem] = raw
            generated.append((directory, produced))
        assert set(service_manifest) == {name + '.json' for name in generated[0][1]}
    else:
        from tests.test_ai_investigation_service_fixtures import producer_fixtures as service
        from tests.test_ai_investigation_fixtures import producer_fixtures as evidence
        # Execution identity commits the fixture endpoint, so ports are fixed.
        # Serialize Web consumers; do not run concurrently with external producer
        # review on those ports. Use sealed mode for parallel review instead.
        with (Path(tempfile.gettempdir()) / 'c2hunter-investigation-web-producer.lock').open('a') as lock:
            deadline = time.monotonic() + 15
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError('Web producer fixture lock timeout') from None
                    time.sleep(0.02)
            generated = [('ai_investigation_service', service()), ('ai_investigation', evidence())]
    for directory, produced in generated:
        saved_names = {path.stem for path in (ROOT / 'controller/tests/fixtures' / directory).glob('*.json')}
        assert set(produced) == saved_names, f'unconsumed producer witnesses: {directory}'
        counts[directory] = len(produced)
        for name, raw in produced.items():
            saved = ROOT / 'controller/tests/fixtures' / directory / (name + '.json')
            canonical = raw.rstrip(b'\n') + b'\n'
            assert saved.read_bytes() == canonical, f'producer fixture drift: {saved}'
            fixtures[f'{directory}/{name}'] = canonical.decode()
    assert counts['ai_investigation_service'] >= 19 and counts['ai_investigation'] == 5
    import runpy
    additional = runpy.run_path(str(Path(__file__).with_name('investigation_uncertainty_producer.py')))['produce']()
    origins = {name: str(Path(module.__file__).resolve()) for name, module in tuple(sys.modules.items())
               if name.startswith(('c2hunter_controller.', 'c2hunter_analysis.', 'tests.test_ai_investigation'))
               and getattr(module, '__file__', None)}
    for name, origin in origins.items():
        assert Path(origin).is_relative_to(ROOT), f'foreign nested producer import: {name}: {origin}'
        relative = str(Path(origin).relative_to(ROOT))
        assert relative in source_before, f'unbound nested producer import: {relative}'
    # Recheck all consumed fixture bytes as well as sources after fresh in-memory work.
    for key, raw in fixtures.items():
        assert (ROOT / 'controller/tests/fixtures' / (key + '.json')).read_bytes() == raw.encode()
    assert source_before == {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in source_paths}, 'producer changed during generation'
    print(json.dumps({'fixtures': fixtures, 'schemas': schemas, 'counts': counts, 'additional': additional,
                      'mode': 'SEALED_SOURCE_BOUND' if source_manifest else 'FRESH_PRODUCER',
                      'origins': origins, 'isolated': sys.flags.isolated, 'prefix': sys.prefix,
                      'executable': sys.executable, 'pydantic': sys.modules['pydantic'].__file__,
                      'network_policy': 'DENY_BIND_CONNECT_DNS' if source_manifest else 'FRESH_PROVIDER_NETWORK',
                      'origin': str(schema.__file__), 'python': sys.version,
                      'source_manifest': source_before, 'source_sha256': hashlib.sha256(Path(schema.__file__).read_bytes()).hexdigest()}))
