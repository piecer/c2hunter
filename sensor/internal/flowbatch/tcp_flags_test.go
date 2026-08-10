package flowbatch

import (
	"net/netip"
	"testing"
	"time"

	"c2hunter/sensor/internal/direction"
	"c2hunter/sensor/internal/flow"
	"c2hunter/sensor/internal/packet"
)

func TestNewPreservesTCPConnectionMetadata(t *testing.T) {
	record := flow.Record{
		Key: flow.Key{
			SensorID:        "sensor-a",
			Direction:       direction.Outbound,
			IPVersion:       4,
			SourceIP:        netip.MustParseAddr("10.0.0.10"),
			DestinationIP:   netip.MustParseAddr("203.0.113.10"),
			SourcePort:      50000,
			DestinationPort: 443,
			Protocol:        packet.TCP,
		},
		StartTime:        time.Unix(1, 0).UTC(),
		PacketCount:      3,
		TotalBytes:       180,
		TCPFlags:         flow.FlagCounts{SYN: 1, ACK: 1},
		TCPFlagsObserved: true,
		TCPSYNOnlyCount:  1,
		TCPACKOnlyCount:  1,
		Bidirectional:    true,
	}

	batch, err := New([]flow.Record{record})
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Flows) != 1 {
		t.Fatalf("flows = %+v", batch.Flows)
	}
	got := batch.Flows[0]
	if !got.TCPFlagsObserved || !got.Bidirectional {
		t.Fatalf("connection metadata = %+v", got)
	}
	if got.TCPSYNCount != 1 || got.TCPACKCount != 1 ||
		got.TCPSYNOnlyCount != 1 || got.TCPACKOnlyCount != 1 {
		t.Fatalf("TCP counters = %+v", got)
	}
}
