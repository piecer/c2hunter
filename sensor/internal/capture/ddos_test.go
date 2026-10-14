package capture

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"c2hunter/sensor/internal/direction"
	"c2hunter/sensor/internal/flow"
	"c2hunter/sensor/internal/flowbatch"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestDDoSRealDecoderFlowBatchEvidence(t *testing.T) {
	for _, tc := range []struct {
		port     layers.UDPPort
		payload  []byte
		semantic string
	}{
		{53, []byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 1, 'a', 0, 0, 1, 0, 1}, "DNS_RESPONSE"},
		{123, append([]byte{0x24, 2}, make([]byte, 46)...), "NTP_RESPONSE"},
	} {
		t.Run(tc.semantic, func(t *testing.T) {
			eth := &layers.Ethernet{SrcMAC: []byte{0, 1, 2, 3, 4, 5}, DstMAC: []byte{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
			ip := &layers.IPv4{Version: 4, TTL: 64, Id: 97, SrcIP: netip.MustParseAddr("198.51.100.1").AsSlice(), DstIP: netip.MustParseAddr("10.0.0.10").AsSlice(), Protocol: layers.IPProtocolUDP}
			udp := &layers.UDP{SrcPort: tc.port, DstPort: 53000}
			if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
				t.Fatal(err)
			}
			buf := gopacket.NewSerializeBuffer()
			if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload(tc.payload)); err != nil {
				t.Fatal(err)
			}
			classifier, _ := direction.NewClassifier(nil, nil, []string{"10.0.0.0/8"})
			for _, count := range []int{16, 17} {
				a := flow.NewAggregator("fixture", "job", time.Minute)
				for i := 0; i < count; i++ {
					p, err := decodePacket(buf.Bytes(), gopacket.CaptureInfo{Timestamp: time.Unix(1784544000+int64(i), 0).UTC(), CaptureLength: len(buf.Bytes()), Length: len(buf.Bytes())}, "fixture", classifier)
					if err != nil {
						t.Fatal(err)
					}
					a.Add(p)
				}
				batch, err := flowbatch.New(a.Flush())
				if err != nil {
					t.Fatal(err)
				}
				data, err := flowbatch.Encode(batch)
				if err != nil {
					t.Fatal(err)
				}
				if count == 16 {
					frozen, err := os.ReadFile("../../../analysis/tests/fixtures/ddos-live-" + strings.ToLower(tc.semantic) + ".json")
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(bytes.TrimSpace(frozen), data) {
						t.Fatalf("producer fixture drift: %s", data)
					}
				}
				var doc struct {
					Flows []map[string]any `json:"flows"`
				}
				if err = json.Unmarshal(data, &doc); err != nil {
					t.Fatal(err)
				}
				raw, ok := doc.Flows[0]["ddos_packet_evidence"].(map[string]any)
				if !ok {
					t.Fatal("real decoder/aggregator omitted DDoS packet evidence")
				}
				samples := raw["samples"].([]any)
				if len(samples) != 16 || raw["omitted_samples"] != float64(count-16) {
					t.Fatalf("bounds: %s", data)
				}
				if samples[0].(map[string]any)["semantic"] != tc.semantic {
					t.Fatalf("semantics: %s", data)
				}
			}
		})
	}
}
