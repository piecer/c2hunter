"""Schema-normalized topology and full uint16 link census from actual parser.

This is a boundary composition witness, not a claim that all link types decode.
Unknown link types still belong to the published source capture census.
"""
import contextlib
import hashlib
import io
import json
import runpy
import struct
from pathlib import Path

from c2hunter_analysis.pcap import parse_pcap
from c2hunter_controller.app import _public_job
from c2hunter_controller.schemas import PcapAnalysisJobCreate


def block(kind, body):
    size = len(body) + 12
    return struct.pack('<II', kind, size) + body + struct.pack('<I', size)


def generate():
    content = bytearray(block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)))
    for link in range(65536):
        content.extend(block(1, struct.pack('<HHI', link, 0, 65535)))
        content.extend(block(6, struct.pack('<IIIII', link, 0, 1_000_000, 0, 0)))
    parsed = parse_pcap(bytes(content), sensor_id='owned', internal_networks=['10.0.0.0/8'], allow_no_supported_packets=True)
    assert parsed.link_types == tuple(range(65536))
    # Scoped IPv6 is accepted by the actual schema/ipaddress dependency.
    # 64 Python code points can normalize to 68, or 124 UTF-16 code units.
    raw = ['fe80::1%' + chr(0x1F600 + i) * 56 for i in range(256)]
    metadata = PcapAnalysisJobCreate(name='boundary', filename='boundary.pcapng', idempotency_key='boundary', internal_networks=raw)
    assert all(len(n) == 68 for n in metadata.internal_networks)
    long_ipv6 = PcapAnalysisJobCreate(name='long', filename='long.pcap', idempotency_key='long', internal_networks=[f'abcd:abcd:abcd:abcd:abcd:abcd:abcd:{4096 + i:x}/128' for i in range(256)]).internal_networks
    assert all(len(n) == 43 for n in long_ipv6)
    with contextlib.redirect_stdout(io.StringIO()):
        report = runpy.run_path(str(Path(__file__).with_name('ddos_maximum_fixture.py')))['report']
    source = _public_job({'id': 'j' * 200, 'dataset_id': 'd' * 200, 'source_type': 'PCAP_UPLOAD', 'internal_networks': metadata.internal_networks, 'source': {'sha256': hashlib.sha256(content).hexdigest(), 'link_types': list(parsed.link_types)}})
    return {'report': report, 'source': source, 'long_ipv6': long_ipv6}


if __name__ == '__main__':
    print(json.dumps(generate(), sort_keys=True, separators=(',', ':')))
