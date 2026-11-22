"""Actual upload/schema/public-readback witnesses for source authority budgets."""
import json
import struct
from ipaddress import ip_address, ip_network
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urlencode

from fastapi.testclient import TestClient
from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import SQLiteRepository
from c2hunter_controller.schemas import AnalysisJobCreate, PcapAnalysisJobCreate


def networks(count, family):
    if family == 4:
        return [f"10.{i}.0.7/16" for i in range(count)]
    return [f"abcd:abcd:abcd:abcd:abcd::{0x1000 + i:x}/128" for i in range(count)]


def capture(family):
    content = bytearray(struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
    for i in range(1200):
        payload = b'owned-offline-budget-control'
        udp = struct.pack('!HHHH', 53000 + i % 20, 443, 8 + len(payload), 0) + payload
        if family == 4:
            packet = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), i, 0, 64, 17, 0, ip_address(f'198.51.100.{i % 20 + 1}').packed, ip_address('10.0.0.10').packed) + udp
        else:
            packet = struct.pack('!IHBB16s16s', 6 << 28, len(udp), 17, 64, ip_address(f'2001:db8::{i % 20 + 1:x}').packed, ip_address(networks(1, 6)[0].split('/')[0]).packed) + udp
        content.extend(struct.pack('<IIII', 1784505600 + i // 300, 0, len(packet), len(packet)) + packet)
    return bytes(content)


def generate(root):
    repo = SQLiteRepository(root / 'source-budget.sqlite')
    jobs = {}
    try:
        with TestClient(create_app(Settings(environment='test'), repo)) as client:
            for count in (101, 256):
                for family in (4, 6):
                    raw = networks(count, family)
                    expected = [str(ip_network(n, strict=False)) for n in raw]
                    # Both actual admission schemas normalize the same raw input.
                    assert AnalysisJobCreate.bounded_internal_networks(raw) == expected
                    schema = PcapAnalysisJobCreate(name='budget', filename='budget.pcap', idempotency_key=f'{count}-{family}', internal_networks=raw)
                    assert schema.internal_networks == expected
                    query = urlencode(dict(name='budget', filename='budget.pcap', analysis_module='ddos_attack', internal_networks=','.join(raw), ddos_min_duration_seconds=2, ddos_min_source_count=3, ddos_min_packet_count=6, ddos_min_packets_per_second=1, ddos_min_bits_per_second=1))
                    response = client.post('/api/v1/pcap-analysis-jobs?' + query, content=capture(family), headers={'content-type': 'application/vnd.tcpdump.pcap'})
                    assert response.status_code == 201, response.text
                    job = response.json()
                    observed = client.get('/api/v1/analysis-jobs/' + job['id'])
                    assert observed.status_code == 200
                    job = observed.json()
                    assert job['internal_networks'] == expected
                    assert job['ddos_attack']['findings'] and job['pcap_attack_guidance']['candidates'], (count, family, job['ddos_attack'], job['pcap_attack_guidance'])
                    jobs[f'ipv{family}-{count}'] = job
    finally:
        repo.close()
    return jobs


if __name__ == '__main__':
    with TemporaryDirectory(prefix='ddos-source-budget-') as directory:
        print(json.dumps(generate(Path(directory)), sort_keys=True, separators=(',', ':')))
