package flow

import (
	"net/netip"
	"testing"
	"time"

	"c2hunter/sensor/internal/direction"
	"c2hunter/sensor/internal/packet"
)

func flowPacket(ts time.Time, src, dst string, sport, dport uint16, payload string) packet.Packet {
	return packet.Packet{Timestamp: ts, WireLength: 100, Direction: direction.Outbound, IPVersion: 4, SourceIP: netip.MustParseAddr(src), DestinationIP: netip.MustParseAddr(dst), SourcePort: sport, DestinationPort: dport, Protocol: packet.TCP, TCPFlags: packet.TCPFlags{SYN: true, ACK: true}, Payload: []byte(payload)}
}

func TestAggregatorBuildsKeyAndStatistics(t *testing.T) {
	a := NewAggregator("sensor-a", "job-1", 60*time.Second)
	t0 := time.Unix(100, 0)
	p1 := flowPacket(t0, "10.0.0.1", "203.0.113.1", 1000, 443, "one")
	p2 := flowPacket(t0.Add(time.Second), "10.0.0.1", "203.0.113.1", 1000, 443, "different")
	p2.WireLength = 200
	if expired := a.Add(p1); len(expired) != 0 {
		t.Fatal("unexpected expiry")
	}
	a.Add(p2)
	records := a.Flush()
	if len(records) != 1 {
		t.Fatalf("records=%d", len(records))
	}
	r := records[0]
	if r.Key.SensorID != "sensor-a" || r.CaptureJobID != "job-1" || r.PacketCount != 2 || r.TotalBytes != 300 || r.MinPacketSize != 100 || r.MaxPacketSize != 200 || r.AvgPacketSize != 150 {
		t.Fatalf("bad record: %+v", r)
	}
	if r.TCPFlags.SYN != 2 || r.TCPFlags.ACK != 2 || r.FirstPayloadHash == "" || r.FirstPayloadHash == r.LastPayloadHash {
		t.Fatalf("bad flags/hash: %+v", r)
	}
	if len(r.FirstPayloadHash) != 64 {
		t.Fatalf("hash not SHA-256: %q", r.FirstPayloadHash)
	}
}

func TestAggregatorRetainsBoundedFirstPayloadPreviewWhenEnabled(t *testing.T) {
	a := NewAggregatorWithPayloadPreview("sensor-a", "job-1", time.Minute, 4)
	p := flowPacket(time.Unix(100, 0), "10.0.0.1", "203.0.113.1", 1000, 4444, "abcdef")
	a.Add(p)
	records := a.Flush()
	if len(records) != 1 || records[0].PayloadSampleHex != "61626364" {
		t.Fatalf("payload preview = %+v", records)
	}

	disabled := NewAggregator("sensor-a", "job-2", time.Minute)
	disabled.Add(p)
	if got := disabled.Flush()[0].PayloadSampleHex; got != "" {
		t.Fatalf("payload preview should be disabled, got %q", got)
	}
}

func TestAggregatorExpiresAtIdleTimeout(t *testing.T) {
	a := NewAggregator("s", "j", time.Second)
	t0 := time.Unix(10, 0)
	p := flowPacket(t0, "10.0.0.1", "8.8.8.8", 1, 2, "")
	a.Add(p)
	p.Timestamp = t0.Add(time.Second)
	expired := a.Add(p)
	if len(expired) != 1 || expired[0].PacketCount != 1 {
		t.Fatalf("expected expired flow: %+v", expired)
	}
	if got := a.Flush(); len(got) != 1 || got[0].PacketCount != 1 {
		t.Fatalf("new flow missing: %+v", got)
	}
}

func TestAggregatorMarksReverseFlowsBidirectional(t *testing.T) {
	a := NewAggregator("s", "j", time.Minute)
	t0 := time.Unix(1, 0)
	a.Add(flowPacket(t0, "10.0.0.1", "8.8.8.8", 1, 2, ""))
	reverse := flowPacket(t0, "8.8.8.8", "10.0.0.1", 2, 1, "")
	reverse.Direction = direction.Inbound
	a.Add(reverse)
	for _, r := range a.Flush() {
		if !r.Bidirectional {
			t.Fatalf("not marked bidirectional: %+v", r)
		}
	}
}
