"""Actual libpcap selection vs independent predicate replay on owned PCAPs."""
import hashlib
import re
import ctypes
import ctypes.util
import ipaddress
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from c2hunter_analysis.pcap import parse_pcap


def packets():
    def udp(src="198.51.100.1", dst="10.0.0.10", sport=53, dport=443):
        body = struct.pack("!HHHH", sport, dport, 12, 0) + b"test"
        return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 1, 0, 64, 17, 0, ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed) + body
    original = udp()
    controls = [original, udp(sport=54), udp(dport=80), udp(dst="10.0.0.11"), udp(src="10.2.3.4"), udp(src="10.2.3.4", dst="203.0.113.80"), udp(dst="203.0.113.80")]
    for index, value in [(0, 0x65), (0, 0x44), (0, 0x46), (9, 6), (6, 0x20), (7, 1)]:
        mutated = bytearray(original); mutated[index] = value; controls.append(bytes(mutated))
    for total in [0, 19, 20, 23, 27, 28, 100]:
        mutated = bytearray(original); mutated[2:4] = struct.pack("!H", total); controls.append(bytes(mutated))
    for length in [0, 7, 8, 65535]:
        mutated = bytearray(original); mutated[24:26] = struct.pack("!H", length); controls.append(bytes(mutated))
    controls += [original[:n] for n in range(len(original))]
    # Valid options, IPv6 UDP, and transport bytes that are not valid DNS.
    options = bytearray(original[:20] + b"\0" * 4 + original[20:]); options[0] = 0x46; options[2:4] = struct.pack("!H", len(options)); controls.append(bytes(options))
    controls.append(struct.pack("!IHBB16s16s", 6 << 28, 12, 17, 64, ipaddress.ip_address("2001:db8::1").packed, ipaddress.ip_address("2001:db8::10").packed) + original[20:])
    return controls


def replay(predicate, row, networks):
    # Independent implementation; intentionally does not import ddos_signatures.match.
    source, destination = ipaddress.ip_address(row["source_ip"]), ipaddress.ip_address(row["destination_ip"])
    inside = lambda address: any(address in ipaddress.ip_network(n, strict=False) for n in networks)
    direction = "INBOUND" if inside(destination) and not inside(source) else "OUTBOUND" if inside(source) and not inside(destination) else "UNKNOWN"
    return (row["destination_ip"] == predicate["target_ip"] and direction == predicate["direction"] and row["protocol"] == predicate["protocol"] and all(options is None or row.get(field) in options for field, options in [("source_port", predicate["source_ports"]), ("destination_port", predicate["destination_ports"])]))


def verify(request):
    link = request["link"]
    raw = packets()
    if link == 1:
        frames = []
        for packet in raw:
            ethertype = 0x86DD if packet and packet[0] >> 4 == 6 else 0x0800
            for tags in [[], [0x8100], [0x88A8, 0x9100], [0x8100, 0x8100, 0x8100]]:
                frame = b"\x01" * 12
                for tag in tags: frame += struct.pack("!HH", tag, 1)
                frames.append(frame + struct.pack("!H", ethertype) + packet)
        raw = frames
    content = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, link))
    for i, packet in enumerate(raw):
        content.extend(struct.pack("<IIII", 1700000000 + i, 0, len(packet), max(len(packet), 64)) + packet)
    with tempfile.TemporaryDirectory(prefix="ddos-filter-") as directory:
        path = Path(directory) / "owned.pcap"; path.write_bytes(content)
        records = parse_pcap(bytes(content), sensor_id="native-proof", internal_networks=request["networks"], retain_network_evidence=True).records
        expected = [r["raw_packet_index"] for r in records if replay(request["predicate"], r, request["networks"])]
        lib = ctypes.CDLL(ctypes.util.find_library("pcap"))
        class Program(ctypes.Structure): _fields_ = [("length", ctypes.c_uint), ("insns", ctypes.c_void_p)]
        class Timeval(ctypes.Structure): _fields_ = [("seconds", ctypes.c_long), ("microseconds", ctypes.c_long)]
        class Header(ctypes.Structure): _fields_ = [("time", Timeval), ("caplen", ctypes.c_uint32), ("length", ctypes.c_uint32)]
        lib.pcap_open_offline.argtypes = [ctypes.c_char_p, ctypes.c_char_p]; lib.pcap_open_offline.restype = ctypes.c_void_p
        lib.pcap_compile.argtypes = [ctypes.c_void_p, ctypes.POINTER(Program), ctypes.c_char_p, ctypes.c_int, ctypes.c_uint32]
        lib.pcap_geterr.argtypes = [ctypes.c_void_p]; lib.pcap_geterr.restype = ctypes.c_char_p
        lib.pcap_offline_filter.argtypes = [ctypes.POINTER(Program), ctypes.POINTER(Header), ctypes.c_void_p]
        lib.pcap_freecode.argtypes = [ctypes.POINTER(Program)]; lib.pcap_close.argtypes = [ctypes.c_void_p]
        error = ctypes.create_string_buffer(256); handle = lib.pcap_open_offline(str(path).encode(), error)
        assert handle, error.value
        program = Program()
        try:
            assert lib.pcap_compile(handle, ctypes.byref(program), request["expression"].encode(), 1, 0xffffffff) == 0, lib.pcap_geterr(handle)
            actual = [i for i, packet in enumerate(raw) if lib.pcap_offline_filter(ctypes.byref(program), ctypes.byref(Header(Timeval(0, 0), len(packet), max(len(packet), 64))), ctypes.create_string_buffer(packet))]
            assert actual == expected, {"actual": actual, "expected": expected, "expression": request["expression"]}
            native = subprocess.run(['/usr/bin/tcpdump', '-n', '-tt', '-r', str(path), request['expression']], capture_output=True, text=True, check=True)
            decoded_ids = [int(line.split('.')[0]) - 1700000000 for line in native.stdout.splitlines() if line.startswith('170000')]
            assert decoded_ids == expected, native.stdout
            lib.pcap_lib_version.restype = ctypes.c_char_p
            return {"packets": len(raw), "selected": actual, "instructions": program.length, "link": link, "native_engine": lib.pcap_lib_version().decode(), "tcpdump_selected": decoded_ids}
        finally:
            lib.pcap_freecode(ctypes.byref(program)); lib.pcap_close(handle)

def verify_download(capture_path, json_path, filter_path):
    capture_bytes = capture_path.read_bytes()
    envelope = json.loads(json_path.read_text())
    filter_bytes = filter_path.read_bytes()
    assert len(filter_bytes) <= 65536 and json_path.stat().st_size <= 65536
    selection = envelope['packet_selection']
    assert hashlib.sha256(capture_bytes).hexdigest() == selection['capture_sha256']
    assert selection['link_type'] == 101
    lines = filter_bytes.decode().splitlines()
    assert json.loads('\n'.join(line[2:] for line in lines if line.startswith('# '))) == envelope
    assert '\n'.join(line for line in lines if not line.startswith('# ')) == selection['expression']
    rows = parse_pcap(capture_bytes, sensor_id='download-proof', internal_networks=selection['internal_networks'], retain_network_evidence=True).records
    expected = []
    for row in rows:
        packet_id = int.from_bytes(bytes.fromhex(row['raw_packet_hex'])[4:6], 'big')
        assert packet_id == row['raw_packet_index']  # This owned fixture uses unique IPv4 IDs.
        if replay(envelope['evaluation']['predicate'], row, selection['internal_networks']): expected.append(packet_id)
    native = subprocess.run(['/usr/bin/tcpdump', '-n', '-tt', '-v', '-r', str(capture_path), '-F', str(filter_path)], capture_output=True, text=True, check=True)
    actual = [int(value) for value in re.findall(r'\bid (\d+),', native.stdout)]
    assert actual == expected and actual
    return {'capture_sha256': selection['capture_sha256'], 'filter_sha256': hashlib.sha256(filter_bytes).hexdigest(), 'filter_bytes': len(filter_bytes), 'packet_ids': actual, 'native_filter_file': True}


if __name__ == "__main__":
    if len(sys.argv) > 1:
        print(json.dumps(verify_download(*(Path(value) for value in sys.argv[1:]))))
    else:
        print(json.dumps(verify(json.load(sys.stdin))))
