package flowbatch

import (
	"encoding/json"
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
		FirstPayloadHash: "payload", LastPayloadHash: "last-payload", PayloadPrefixHash: "prefix", PayloadSampleHex: "626f74", FirstPayloadLength: 12,
		PayloadEntropy: 4.25, PayloadPrintable: 0.5, PayloadSimHash: "0123456789abcdef",
		PayloadFeatureVersion: "1",
		ProtocolMetadata:      metadata.Metadata{Kind: metadata.KindTLS, TLS: &metadata.TLS{ClientHelloFingerprint: "tls", SNI: "c2.example"}},
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
	if got.SensorID != "sensor-a" || got.Timestamp != record.StartTime || got.Protocol != "TCP" || got.PayloadHash != "payload" || got.LastPayloadHash != "last-payload" || got.PayloadSampleHex != "626f74" || got.TLSFingerprint != "tls" || got.Domain != "c2.example" {
		t.Fatalf("flow = %+v", got)
	}
	if got.PayloadLength == nil || got.PayloadEntropy == nil || got.PayloadPrintableRatio == nil {
		t.Fatalf("optional payload features were omitted: %+v", got)
	}
	if got.PayloadPrefixHash != "prefix" || *got.PayloadLength != 12 || *got.PayloadEntropy != 4.25 || *got.PayloadPrintableRatio != 0.5 || got.PayloadSimHash != "0123456789abcdef" || got.PayloadFeatureVersion != "1" {
		t.Fatalf("payload features were not preserved: %+v", got)
	}
}

func TestPayloadFeatureZeroValuesRemainPresent(t *testing.T) {
	record := flow.Record{
		Key:                   flow.Key{SensorID: "sensor-a", Direction: direction.Outbound, IPVersion: 4, SourceIP: netip.MustParseAddr("10.0.0.2"), DestinationIP: netip.MustParseAddr("203.0.113.8"), SourcePort: 40000, DestinationPort: 443, Protocol: packet.TCP},
		StartTime:             time.Unix(1, 0).UTC(),
		PacketCount:           1,
		FirstPayloadHash:      "payload",
		FirstPayloadLength:    1,
		PayloadEntropy:        0,
		PayloadPrintable:      0,
		PayloadFeatureVersion: "1",
	}
	batch, err := New([]flow.Record{record})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := Encode(batch)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	flows, ok := decoded["flows"].([]any)
	if !ok || len(flows) != 1 {
		t.Fatalf("unexpected encoded flows: %s", encoded)
	}
	payload, ok := flows[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected encoded flow: %s", encoded)
	}
	if _, ok := payload["payload_entropy"]; !ok {
		t.Fatalf("zero entropy was omitted: %s", encoded)
	}
	if _, ok := payload["payload_printable_ratio"]; !ok {
		t.Fatalf("zero printable ratio was omitted: %s", encoded)
	}
}
