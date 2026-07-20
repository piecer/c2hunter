package flowbatch

import (
	"net/netip"
	"testing"
	"time"

	"c2hunter/sensor/internal/direction"
	"c2hunter/sensor/internal/flow"
	"c2hunter/sensor/internal/metadata"
	"c2hunter/sensor/internal/packet"
)

func TestNewProducesStableContentAddressedIDAndControllerSchema(t *testing.T) {
	record := flow.Record{
		Key:       flow.Key{SensorID: "sensor-a", Direction: direction.Outbound, IPVersion: 4, SourceIP: netip.MustParseAddr("10.0.0.2"), DestinationIP: netip.MustParseAddr("203.0.113.8"), SourcePort: 40000, DestinationPort: 443, Protocol: packet.TCP},
		StartTime: time.Unix(1, 0).UTC(), EndTime: time.Unix(2, 0).UTC(), PacketCount: 2, TotalBytes: 300,
		FirstPayloadHash: "payload", ProtocolMetadata: metadata.Metadata{Kind: metadata.KindTLS, TLS: &metadata.TLS{ClientHelloFingerprint: "tls", SNI: "c2.example"}},
	}
	first, err := New([]flow.Record{record})
	if err != nil {
		t.Fatal(err)
	}
	second, err := New([]flow.Record{record})
	if err != nil {
		t.Fatal(err)
	}
	if first.BatchID == "" || first.BatchID != second.BatchID {
		t.Fatalf("unstable batch IDs: %q %q", first.BatchID, second.BatchID)
	}
	if len(first.Flows) != 1 {
		t.Fatalf("flows = %+v", first.Flows)
	}
	got := first.Flows[0]
	if got.SensorID != "sensor-a" || got.Timestamp != record.StartTime || got.Protocol != "TCP" || got.PayloadHash != "payload" || got.TLSFingerprint != "tls" || got.Domain != "c2.example" {
		t.Fatalf("flow = %+v", got)
	}
}
