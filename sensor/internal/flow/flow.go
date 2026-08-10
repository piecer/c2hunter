package flow

import (
	"encoding/hex"
	"net/netip"
	"sort"
	"time"

	"c2hunter/sensor/internal/direction"
	"c2hunter/sensor/internal/metadata"
	"c2hunter/sensor/internal/packet"
	"c2hunter/sensor/internal/payloadfeature"
)

type Key struct {
	SensorID                    string
	Direction                   direction.Direction
	IPVersion                   uint8
	SourceIP, DestinationIP     netip.Addr
	SourcePort, DestinationPort uint16
	Protocol                    packet.Protocol
}
type FlagCounts struct{ FIN, SYN, RST, PSH, ACK, URG, ECE, CWR uint64 }
type Record struct {
	Key                                Key
	CaptureJobID                       string
	StartTime, EndTime                 time.Time
	PacketCount, TotalBytes            uint64
	MinPacketSize, MaxPacketSize       uint32
	AvgPacketSize                      float64
	TCPFlags                           FlagCounts
	TCPFlagsObserved                   bool
	TCPSYNOnlyCount, TCPSYNACKCount    uint64
	TCPACKOnlyCount                    uint64
	SYNACKRatio                        *float64 `json:"syn_ack_ratio,omitempty"`
	RSTRatio                           *float64 `json:"rst_ratio,omitempty"`
	ConnectionCount                    *uint64  `json:"connection_count,omitempty"`
	Bidirectional                      bool
	MinPayloadLength, MaxPayloadLength uint32
	AvgPayloadLength                   float64
	FirstPayloadHash, LastPayloadHash  string
	PayloadPrefixHash, PayloadSimHash  string
	PayloadSampleHex                   string
	FirstPayloadLength                 uint32
	PayloadEntropy, PayloadPrintable   float64
	PayloadFeatureVersion              string
	PCAPObjectReference                string
	ProtocolMetadata                   metadata.Metadata
	packetSizeSum, payloadLengthSum    uint64
}
type Aggregator struct {
	sensorID, jobID     string
	idle                time.Duration
	payloadPreviewBytes int
	active              map[Key]*Record
}

func NewAggregator(sensorID, jobID string, idle time.Duration) *Aggregator {
	return NewAggregatorWithPayloadPreview(sensorID, jobID, idle, 0)
}

func NewAggregatorWithPayloadPreview(sensorID, jobID string, idle time.Duration, payloadPreviewBytes int) *Aggregator {
	if idle <= 0 {
		idle = 60 * time.Second
	}
	if payloadPreviewBytes < 0 {
		payloadPreviewBytes = 0
	} else if payloadPreviewBytes > 256 {
		payloadPreviewBytes = 256
	}
	return &Aggregator{sensorID: sensorID, jobID: jobID, idle: idle, payloadPreviewBytes: payloadPreviewBytes, active: make(map[Key]*Record)}
}
func (a *Aggregator) Add(p packet.Packet) []Record {
	return a.AddWithMetadata(p, metadata.Metadata{})
}

func (a *Aggregator) AddWithMetadata(p packet.Packet, protocolMetadata metadata.Metadata) []Record {
	key := Key{a.sensorID, p.Direction, p.IPVersion, p.SourceIP, p.DestinationIP, p.SourcePort, p.DestinationPort, p.Protocol}
	r := a.active[key]
	var expired []Record
	if r != nil && !p.Timestamp.Before(r.EndTime.Add(a.idle)) {
		expired = append(expired, finalize(*r))
		delete(a.active, key)
		r = nil
	}
	if r == nil {
		r = &Record{Key: key, CaptureJobID: a.jobID, StartTime: p.Timestamp, MinPacketSize: uint32(p.WireLength), MinPayloadLength: uint32(len(p.Payload))}
		a.active[key] = r
	}
	r.EndTime = p.Timestamp
	r.PacketCount++
	r.TotalBytes += uint64(p.WireLength)
	r.packetSizeSum += uint64(p.WireLength)
	if uint32(p.WireLength) < r.MinPacketSize {
		r.MinPacketSize = uint32(p.WireLength)
	}
	if uint32(p.WireLength) > r.MaxPacketSize {
		r.MaxPacketSize = uint32(p.WireLength)
	}
	payloadLen := uint32(len(p.Payload))
	r.payloadLengthSum += uint64(payloadLen)
	if payloadLen < r.MinPayloadLength {
		r.MinPayloadLength = payloadLen
	}
	if payloadLen > r.MaxPayloadLength {
		r.MaxPayloadLength = payloadLen
	}
	if len(p.Payload) > 0 {
		features := payloadfeature.Compute(p.Payload)
		if r.FirstPayloadHash == "" {
			r.FirstPayloadHash = features.Hash
			r.PayloadPrefixHash = features.PrefixHash
			r.FirstPayloadLength = features.Length
			r.PayloadEntropy = features.Entropy
			r.PayloadPrintable = features.PrintableRatio
			r.PayloadSimHash = features.SimHash
			r.PayloadFeatureVersion = features.Version
			if a.payloadPreviewBytes > 0 {
				sample := p.Payload
				if len(sample) > a.payloadPreviewBytes {
					sample = sample[:a.payloadPreviewBytes]
				}
				r.PayloadSampleHex = hex.EncodeToString(sample)
			}
		}
		r.LastPayloadHash = features.Hash
	}
	addFlags(&r.TCPFlags, p.TCPFlags)
	trackTCPFlagCombinations(r, p)
	if protocolMetadata.Kind != "" {
		r.ProtocolMetadata = protocolMetadata
	}
	reverse := Key{a.sensorID, reverseDirection(p.Direction), p.IPVersion, p.DestinationIP, p.SourceIP, p.DestinationPort, p.SourcePort, p.Protocol}
	if other := a.active[reverse]; other != nil {
		r.Bidirectional = true
		other.Bidirectional = true
	}
	return expired
}
func (a *Aggregator) Expire(now time.Time) []Record { return a.expire(now) }
func (a *Aggregator) expire(now time.Time) []Record {
	var out []Record
	for key, r := range a.active {
		if !now.Before(r.EndTime.Add(a.idle)) {
			out = append(out, finalize(*r))
			delete(a.active, key)
		}
	}
	sortRecords(out)
	return out
}
func (a *Aggregator) Flush() []Record {
	out := make([]Record, 0, len(a.active))
	for key, r := range a.active {
		out = append(out, finalize(*r))
		delete(a.active, key)
	}
	sortRecords(out)
	return out
}
func finalize(r Record) Record {
	if r.PacketCount > 0 {
		r.AvgPacketSize = float64(r.packetSizeSum) / float64(r.PacketCount)
		r.AvgPayloadLength = float64(r.payloadLengthSum) / float64(r.PacketCount)
		addTCPFlagCombinations(&r)
	}
	return r
}
func reverseDirection(d direction.Direction) direction.Direction {
	if d == direction.Inbound {
		return direction.Outbound
	}
	if d == direction.Outbound {
		return direction.Inbound
	}
	return d
}
func sortRecords(records []Record) {
	sort.Slice(records, func(i, j int) bool { return records[i].StartTime.Before(records[j].StartTime) })
}
func addFlags(c *FlagCounts, f packet.TCPFlags) {
	if f.FIN {
		c.FIN++
	}
	if f.SYN {
		c.SYN++
	}
	if f.RST {
		c.RST++
	}
	if f.PSH {
		c.PSH++
	}
	if f.ACK {
		c.ACK++
	}
	if f.URG {
		c.URG++
	}
	if f.ECE {
		c.ECE++
	}
	if f.CWR {
		c.CWR++
	}
}

func trackTCPFlagCombinations(record *Record, p packet.Packet) {
	if p.Protocol != packet.TCP {
		return
	}
	record.TCPFlagsObserved = true
	switch {
	case p.TCPFlags.SYN && p.TCPFlags.ACK && !p.TCPFlags.RST:
		record.TCPSYNACKCount++
	case p.TCPFlags.SYN && !p.TCPFlags.ACK && !p.TCPFlags.RST:
		record.TCPSYNOnlyCount++
	case p.TCPFlags.ACK && !p.TCPFlags.SYN && !p.TCPFlags.RST:
		// FIN/PSH + ACK packets are valid post-handshake traffic. RST+ACK is
		// intentionally excluded so a closed-port response cannot look like
		// an established session.
		record.TCPACKOnlyCount++
	}
}

// addTCPFlagCombinations computes SYN/ACK ratio, RST ratio, and connection count.
func addTCPFlagCombinations(r *Record) {
	if r.TCPFlags.SYN > 0 && r.TCPFlags.ACK > 0 {
		ratio := float64(r.TCPFlags.SYN) / float64(r.TCPFlags.ACK)
		r.SYNACKRatio = &ratio
	}
	if r.PacketCount > 0 {
		rstRatio := float64(r.TCPFlags.RST) / float64(r.PacketCount)
		r.RSTRatio = &rstRatio
	}
	connections := r.TCPFlags.SYN
	if connections > 0 {
		r.ConnectionCount = &connections
	}
}
