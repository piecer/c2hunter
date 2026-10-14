package flow

import (
	"c2hunter/sensor/internal/packet"
	"net/netip"
)

// Lifetime quotas per capture aggregator; flushing never replenishes evidence
// admission. Counters only enter the maps on admitted samples, bounding both maps.
const (
	maxDDoSSamples       = 32768
	maxDDoSSamplesTarget = 2048
	maxDDoSSamplesSource = 32
	maxDDoSSamplesFlow   = 16
)

type ddosTarget struct {
	IP       netip.Addr
	Port     uint16
	Protocol packet.Protocol
}

func (a *Aggregator) trackDDoS(r *Record, p packet.Packet) {
	if !p.EvidenceComplete || (p.Protocol != packet.TCP && p.Protocol != packet.UDP) {
		return
	}
	if r.DDoSPacketEvidence == nil {
		r.DDoSPacketEvidence = &packet.DDoSEvidence{Version: 1, Samples: make([]packet.DDoSSample, 0)}
	}
	target := ddosTarget{p.DestinationIP, p.DestinationPort, p.Protocol}
	if a.ddosSamples >= maxDDoSSamples || a.ddosSources[p.SourceIP] >= maxDDoSSamplesSource || a.ddosTargets[target] >= maxDDoSSamplesTarget || len(r.DDoSPacketEvidence.Samples) >= maxDDoSSamplesFlow || p.Timestamp.Before(r.StartTime) {
		r.DDoSPacketEvidence.OmittedSamples++
		return
	}
	sample := p.DDoSSample()
	if sample == nil {
		r.DDoSPacketEvidence.OmittedSamples++
		return
	}
	if a.ddosSources == nil {
		a.ddosSources = make(map[netip.Addr]int)
		a.ddosTargets = make(map[ddosTarget]int)
	}
	a.ddosSamples++
	a.ddosSources[p.SourceIP]++
	a.ddosTargets[target]++
	r.DDoSPacketEvidence.Samples = append(r.DDoSPacketEvidence.Samples, *sample)
}
