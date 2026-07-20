package flow

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"sort"
	"time"

	"c2hunter/sensor/internal/direction"
	"c2hunter/sensor/internal/metadata"
	"c2hunter/sensor/internal/packet"
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
	Bidirectional                      bool
	MinPayloadLength, MaxPayloadLength uint32
	AvgPayloadLength                   float64
	FirstPayloadHash, LastPayloadHash  string
	PCAPObjectReference                string
	ProtocolMetadata                   metadata.Metadata
	packetSizeSum, payloadLengthSum    uint64
}
type Aggregator struct {
	sensorID, jobID string
	idle            time.Duration
	active          map[Key]*Record
}

func NewAggregator(sensorID, jobID string, idle time.Duration) *Aggregator {
	if idle <= 0 {
		idle = 60 * time.Second
	}
	return &Aggregator{sensorID: sensorID, jobID: jobID, idle: idle, active: make(map[Key]*Record)}
}
func (a *Aggregator) Add(p packet.Packet) []Record {
	return a.AddWithMetadata(p, metadata.Metadata{})
}

func (a *Aggregator) AddWithMetadata(p packet.Packet, protocolMetadata metadata.Metadata) []Record {
	expired := a.expire(p.Timestamp)
	key := Key{a.sensorID, p.Direction, p.IPVersion, p.SourceIP, p.DestinationIP, p.SourcePort, p.DestinationPort, p.Protocol}
	r := a.active[key]
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
		h := sha256.Sum256(p.Payload)
		encoded := hex.EncodeToString(h[:])
		if r.FirstPayloadHash == "" {
			r.FirstPayloadHash = encoded
		}
		r.LastPayloadHash = encoded
	}
	addFlags(&r.TCPFlags, p.TCPFlags)
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
