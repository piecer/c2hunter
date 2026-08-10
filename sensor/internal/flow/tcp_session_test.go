package flow

import (
	"net/netip"
	"testing"
	"time"

	"c2hunter/sensor/internal/direction"
	"c2hunter/sensor/internal/packet"
)

func handshakePacket(
	at time.Time,
	src, dst string,
	sport, dport uint16,
	packetDirection direction.Direction,
	flags packet.TCPFlags,
) packet.Packet {
	return packet.Packet{
		Timestamp:       at,
		WireLength:      60,
		Direction:       packetDirection,
		IPVersion:       4,
		SourceIP:        netip.MustParseAddr(src),
		DestinationIP:   netip.MustParseAddr(dst),
		SourcePort:      sport,
		DestinationPort: dport,
		Protocol:        packet.TCP,
		TCPFlags:        flags,
	}
}

func TestAggregatorTracksTCPHandshakeCombinations(t *testing.T) {
	aggregator := NewAggregator("sensor-a", "job-a", time.Minute)
	start := time.Unix(100, 0).UTC()

	aggregator.Add(handshakePacket(
		start,
		"10.0.0.10", "203.0.113.10", 50000, 443,
		direction.Outbound,
		packet.TCPFlags{SYN: true},
	))
	aggregator.Add(handshakePacket(
		start.Add(time.Millisecond),
		"203.0.113.10", "10.0.0.10", 443, 50000,
		direction.Inbound,
		packet.TCPFlags{SYN: true, ACK: true},
	))
	aggregator.Add(handshakePacket(
		start.Add(2*time.Millisecond),
		"10.0.0.10", "203.0.113.10", 50000, 443,
		direction.Outbound,
		packet.TCPFlags{ACK: true},
	))

	records := aggregator.Flush()
	if len(records) != 2 {
		t.Fatalf("records = %+v", records)
	}
	for _, record := range records {
		if !record.TCPFlagsObserved || !record.Bidirectional {
			t.Fatalf("TCP metadata missing: %+v", record)
		}
		switch record.Key.Direction {
		case direction.Outbound:
			if record.TCPSYNOnlyCount != 1 || record.TCPACKOnlyCount != 1 {
				t.Fatalf("outbound combinations = %+v", record)
			}
		case direction.Inbound:
			if record.TCPSYNACKCount != 1 || record.TCPACKOnlyCount != 0 {
				t.Fatalf("inbound combinations = %+v", record)
			}
		default:
			t.Fatalf("unexpected direction: %+v", record)
		}
	}
}

func TestAggregatorDoesNotTreatRSTACKAsSessionACK(t *testing.T) {
	aggregator := NewAggregator("sensor-a", "job-a", time.Minute)
	packet := handshakePacket(
		time.Unix(100, 0).UTC(),
		"10.0.0.10", "198.51.100.20", 22, 50000,
		direction.Outbound,
		packet.TCPFlags{RST: true, ACK: true},
	)
	aggregator.Add(packet)
	record := aggregator.Flush()[0]
	if !record.TCPFlagsObserved || record.TCPFlags.ACK != 1 || record.TCPFlags.RST != 1 {
		t.Fatalf("flag totals = %+v", record)
	}
	if record.TCPACKOnlyCount != 0 {
		t.Fatalf("RST+ACK counted as established-session ACK: %+v", record)
	}
}
