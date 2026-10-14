package capture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"c2hunter/sensor/internal/direction"
	"c2hunter/sensor/internal/flow"
	"c2hunter/sensor/internal/flowbatch"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Real decoder/aggregator/encoder, with no live interfaces or trusted L7 flags.
func correctionAdd(t *testing.T, a *flow.Aggregator, stamp time.Time, src, dst string, sp, dp uint16, body []byte, id uint16) {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: []byte{0, 1, 2, 3, 4, 5}, DstMAC: []byte{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Id: id, SrcIP: netip.MustParseAddr(src).AsSlice(), DstIP: netip.MustParseAddr(dst).AsSlice(), Protocol: layers.IPProtocolUDP}
	udp := &layers.UDP{SrcPort: layers.UDPPort(sp), DstPort: layers.UDPPort(dp)}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	b := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload(body)); err != nil {
		t.Fatal(err)
	}
	classifier, err := direction.NewClassifier(nil, nil, []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := decodePacket(b.Bytes(), gopacket.CaptureInfo{Timestamp: stamp, CaptureLength: len(b.Bytes()), Length: len(b.Bytes())}, "fixture", classifier)
	if err != nil {
		t.Fatal(err)
	}
	a.Add(p)
}

func correctionBatch(t *testing.T, a *flow.Aggregator) flowbatch.Batch {
	t.Helper()
	b, err := flowbatch.New(a.Flush())
	if err != nil {
		t.Fatal(err)
	}
	data, err := flowbatch.Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	var decoded flowbatch.Batch
	if err = json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func correctionFixture(t *testing.T, name string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	// Explicit opt-in writer for fixture maintenance; CI only compares.
	if output := os.Getenv("DDOS_CORRECTION_FIXTURE_OUTPUT"); output != "" {
		if err = os.WriteFile(filepath.Join(output, name), data, 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	frozen, err := os.ReadFile("../../../analysis/tests/fixtures/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(frozen, data) {
		t.Fatalf("producer fixture drift: %s", name)
	}
}

func TestDDoSCorrectionTimestampWire(t *testing.T) {
	base := time.Unix(1784544000, 0).UTC()
	output := map[string]flowbatch.Batch{}
	for _, tc := range []struct {
		name       string
		start, end time.Time
	}{
		{"nano_long", base.Add(900 * time.Nanosecond), base.Add(time.Second + 1100*time.Nanosecond)},
		{"nano_short", base.Add(900 * time.Nanosecond), base.Add(time.Second + 100*time.Nanosecond)},
		{"micro", base, base.Add(time.Second)},
		{"micro_rollover", base.Add(999 * time.Nanosecond), base.Add(1001 * time.Nanosecond)},
		{"second_rollover", base.Add(time.Second - time.Nanosecond), base.Add(time.Second + time.Nanosecond)},
		{"historical", time.Date(2005, 1, 1, 0, 0, 0, 2000, time.UTC), time.Date(2005, 1, 1, 0, 0, 0, 2000, time.UTC)},
		{"pre_epoch", time.Unix(-1, 500000000).UTC(), time.Unix(-1, 500000000).UTC()},
		{"safe_positive", time.UnixMicro(9007199254740991).UTC(), time.UnixMicro(9007199254740991).UTC()},
		{"safe_negative", time.UnixMicro(-9007199254740991).UTC(), time.UnixMicro(-9007199254740991).UTC()},
		{"outside_positive", time.UnixMicro(9007199254740992).UTC(), time.UnixMicro(9007199254740992).UTC()},
		{"outside_negative", time.UnixMicro(-9007199254740992).UTC(), time.UnixMicro(-9007199254740992).UTC()},
	} {
		a := flow.NewAggregator("fixture", "job", time.Minute)
		for _, stamp := range []time.Time{tc.start, tc.end} {
			correctionAdd(t, a, stamp, "198.51.100.1", "10.0.0.10", 40000, 53000, []byte("same"), 1)
		}
		b := correctionBatch(t, a)
		if len(b.Flows) != 1 {
			t.Fatalf("%s: flow count", tc.name)
		}
		evidence := b.Flows[0].DDoSPacketEvidence
		if b.Flows[0].PacketCount != 2 || b.Flows[0].DurationSeconds != tc.end.Sub(tc.start).Seconds() {
			t.Fatal("legacy counters/timing changed")
		}
		if tc.start.UnixMicro() < -9007199254740991 || tc.start.UnixMicro() > 9007199254740991 {
			if evidence == nil || len(evidence.Samples) != 0 || evidence.OmittedSamples != 2 {
				t.Fatalf("unqualified timestamp abstention: %+v", evidence)
			}
		} else if evidence == nil || len(evidence.Samples) != 2 || evidence.Samples[0].TimestampUS != tc.start.UnixMicro() || evidence.Samples[1].TimestampUS != tc.end.UnixMicro() {
			t.Fatalf("exact signed timestamp lost: %+v", evidence)
		}
		output[tc.name] = b
	}
	correctionFixture(t, "ddos-live-timestamp-boundaries.json", output)
}

func TestDDoSCorrectionReverseRequestQuotaWire(t *testing.T) {
	start := time.Unix(1784544000, 0).UTC()
	question := []byte{1, 'a', 0, 0, 1, 0, 1}
	output := map[string]flowbatch.Batch{}
	for _, count := range []int{32, 33, 1000} {
		a := flow.NewAggregator("fixture", "job", time.Minute)
		for i := 0; i < count; i++ {
			// Distinct real capture times make the producer's start-time-only
			// flow order deterministic without sorting/rewriting emitted JSON.
			n, s := i/100, i%100+1
			req := append([]byte{byte(n >> 8), byte(n), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}, question...)
			resp := append([]byte{byte(n >> 8), byte(n), 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}, question...)
			resp = append(resp, []byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1}...)
			server := fmt.Sprintf("198.51.100.%d", s)
			correctionAdd(t, a, start.Add(time.Duration(n)*time.Second+time.Duration(s)*time.Microsecond), "10.0.0.10", server, 53000, 53, req, 1)
			correctionAdd(t, a, start.Add(time.Duration(n)*time.Second+100*time.Millisecond+time.Duration(s)*time.Microsecond), server, "10.0.0.10", 53, 53000, resp, 1)
		}
		batch := correctionBatch(t, a)
		raw, err := json.Marshal(batch)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Flows []struct {
				PacketCount int `json:"packet_count"`
				SourcePort  int `json:"source_port"`
				Evidence    struct {
					Samples []any `json:"samples"`
					Omitted int   `json:"omitted_samples"`
				} `json:"ddos_packet_evidence"`
			} `json:"flows"`
		}
		if err = json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		requests, responses, omitted, packets := 0, 0, 0, 0
		for _, r := range doc.Flows {
			packets += r.PacketCount
			if r.SourcePort == 53 {
				responses += len(r.Evidence.Samples)
			} else {
				requests += len(r.Evidence.Samples)
				omitted += r.Evidence.Omitted
			}
		}
		if requests != 32 || responses != count || omitted != count-32 || packets != 2*count {
			t.Fatalf("count %d: requests=%d responses=%d omitted=%d packets=%d", count, requests, responses, omitted, packets)
		}
		output[fmt.Sprint(count)] = batch
	}
	correctionFixture(t, "ddos-live-reverse-requests.json", output)
}
