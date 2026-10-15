"""Owned ASGI/SQLite fixture; real parser, admission, worker and readback.
No deployed service, model, network capture or generated traffic.
"""
import contextlib
import io
import json
import runpy
import struct
import sys
from pathlib import Path

from fastapi.testclient import TestClient
from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import SQLiteRepository


def capture(port):
    content = bytearray(struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
    for i in range(120):
        payload = b'owned-offline-control'
        udp = struct.pack('!HHHH', 53000 + i % 20, port, 8 + len(payload), 0) + payload
        packet = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), i, 0, 64, 17, 0, bytes([198, 51, 100, i % 20 + 1]), bytes([10, 0, 0, 10])) + udp
        content.extend(struct.pack('<IIII', 1784505600 + i // 4, 0, len(packet), len(packet)) + packet)
    return bytes(content)


def generate(root):
    root.mkdir(parents=True, exist_ok=True)
    repo = SQLiteRepository(root / 'fixture.sqlite')
    client = TestClient(create_app(Settings(environment='test'), repo))
    url = '/api/v1/pcap-analysis-jobs?name=owned-offline&filename=owned.pcap&analysis_module=ddos_attack&ddos_min_source_count=3&ddos_min_packet_count=6&ddos_min_packets_per_second=1&ddos_min_bits_per_second=1'
    jobs = {}
    for name, port in [('normal', 80), ('unmeasured', 443), ('measured', 443)]:
        path = url
        if name == 'measured':
            n = jobs['normal']; path += f"&ddos_normal_reference_job_id={n['id']}&ddos_normal_reference_dataset_id={n['dataset_id']}"
        content = capture(port); (root / f'{name}.pcap').write_bytes(content)
        response = client.post(path, content=content, headers={'content-type': 'application/vnd.tcpdump.pcap'})
        assert response.status_code == 201, response.text
        job = response.json(); observed = client.get('/api/v1/analysis-jobs/' + job['id'])
        assert observed.status_code == 200 and observed.json()['ddos_attack'] == job['ddos_attack']
        jobs[name] = observed.json()
    base = Path(__file__).parent
    with contextlib.redirect_stdout(io.StringIO()):
        source_scenarios = runpy.run_path(str(base / 'ddos_report_scenarios.py'))
        scenarios = source_scenarios['scenarios']
        maximum = runpy.run_path(str(base / 'ddos_maximum_fixture.py'))['report']
    scenarios['maximum'] = maximum
    from c2hunter_analysis.ddos_attack import analyze_ddos_attack
    scenarios['mixed_delivery'] = source_scenarios['analyze'](source_scenarios['syn'] + source_scenarios['dns_packets']())
    scenarios['qualified_coverage'] = analyze_ddos_attack(repo.get_job(jobs['unmeasured']['id'])['flow_records'], parameters=jobs['unmeasured']['analysis'], coverage_context={'parser_skipped_packet_count': 1, 'sensor_dropped_packet_count': 2, 'sensor_clock_skew_detected': True, 'sensor_capture_quality_unavailable': True, 'capture_partial': True})
    for version in ['v1', 'v2', 'v3']:
        scenarios['legacy-' + version] = json.loads((base / f'fixtures/ddos-report-contract-{version}.json').read_text())
    result = {'jobs': jobs, 'reports': scenarios}
    (root / 'browser-fixture.json').write_text(json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n')
    repo.close()
    return {'jobs': {k: v['id'] for k, v in jobs.items()}, 'report_names': list(scenarios), 'database': str(root/'fixture.sqlite')}

if __name__ == '__main__':
    print(json.dumps(generate(Path(sys.argv[1]))))
