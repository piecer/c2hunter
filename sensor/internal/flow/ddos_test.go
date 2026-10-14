package flow

import (
	"c2hunter/sensor/internal/packet"
	"net/netip"
	"testing"
	"time"
)

func TestDDoSGlobalAndTargetBudgetExactAndPlusOne(t *testing.T) {
	for _, limit := range []int{2048, 32768} {
		a := NewAggregator("fixture", "job", time.Minute)
		for i := 0; i <= limit; i++ {
			// #nosec G115 -- loop i <= 32768; byte slices intentionally encode the low 16 address bits.
			src := netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i & 255)})
			target := netip.MustParseAddr("10.0.0.1")
			if limit == 32768 {
				// #nosec G115 -- i/2048+1 is in [1,17].
				target = netip.AddrFrom4([4]byte{10, 0, 0, byte(i/2048 + 1)})
			}
			a.Add(packet.Packet{Timestamp: time.Unix(1784544000, 0).UTC(), WireLength: 60, SourceIP: src, DestinationIP: target, Protocol: packet.UDP, IPLength: 46, EvidenceComplete: true})
			if i == limit-1 && a.ddosSamples != limit {
				t.Fatalf("exact bound %d: %d", limit, a.ddosSamples)
			}
		}
		samples := 0
		omitted := uint64(0)
		for _, r := range a.Flush() {
			if r.DDoSPacketEvidence != nil {
				samples += len(r.DDoSPacketEvidence.Samples)
				omitted += r.DDoSPacketEvidence.OmittedSamples
			}
		}
		if samples != limit || omitted != 1 {
			t.Fatalf("limit %d: samples=%d omitted=%d", limit, samples, omitted)
		}
		if len(a.ddosSources) > 32768 || len(a.ddosTargets) > 32768 {
			t.Fatal("unbounded admission maps")
		}
	}
}

func TestDDoSPerSourceBudgetAcrossFlows(t *testing.T) {
	a := NewAggregator("fixture", "job", time.Minute)
	p := packet.Packet{Timestamp: time.Unix(1784544000, 0).UTC(), WireLength: 60, SourceIP: netip.MustParseAddr("198.51.100.1"), DestinationIP: netip.MustParseAddr("10.0.0.10"), Protocol: packet.UDP, IPLength: 46, EvidenceComplete: true}
	for i := 0; i < 33; i++ {
		p.SourcePort = uint16(i)
		a.Add(p)
	}
	samples := 0
	omitted := uint64(0)
	for _, r := range a.Flush() {
		if r.DDoSPacketEvidence != nil {
			samples += len(r.DDoSPacketEvidence.Samples)
			omitted += r.DDoSPacketEvidence.OmittedSamples
		}
	}
	if samples != 32 || omitted != 1 {
		t.Fatalf("cross-flow source cap: samples=%d omitted=%d", samples, omitted)
	}
}

func TestDDoSReorderingDoesNotRewriteLegacyFlowInterval(t *testing.T) {
	start := time.Unix(1784544000, 0).UTC()
	a := NewAggregator("fixture", "job", time.Minute)
	p := packet.Packet{Timestamp: start, WireLength: 60, CapturedLength: 60, SourceIP: netip.MustParseAddr("198.51.100.1"), DestinationIP: netip.MustParseAddr("10.0.0.10"), Protocol: packet.UDP, IPLength: 46, EvidenceComplete: true, Payload: []byte("shared")}
	a.Add(p)
	p.Timestamp = start.Add(-time.Second)
	a.Add(p)
	r := a.Flush()[0]
	if !r.StartTime.Equal(start) {
		t.Fatal("packet evidence rewrote legacy aggregation interval")
	}
	if r.DDoSPacketEvidence.OmittedSamples != 1 || len(r.DDoSPacketEvidence.Samples) != 1 {
		t.Fatal("out-of-interval sample must abstain")
	}
	legacy := NewAggregator("fixture", "legacy", time.Minute)
	p.EvidenceComplete = false
	legacy.Add(p)
	if legacy.Flush()[0].DDoSPacketEvidence != nil {
		t.Fatal("legacy packet invented complete evidence")
	}
}
