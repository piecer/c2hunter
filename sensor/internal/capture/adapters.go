package capture

import (
	"context"
	"fmt"
	"io"
	"net/netip"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"c2hunter/sensor/internal/direction"
	"c2hunter/sensor/internal/packet"
)

type directionClassifier interface {
	Classify(string, uint16, netip.Addr, netip.Addr) (direction.Direction, direction.Source)
}
type OfflineReader struct {
	reader     *pcapgo.Reader
	iface      string
	classifier directionClassifier
	decoder    *packetDecoder
}

func NewOfflineReader(r io.Reader, iface string, classifier directionClassifier) (*OfflineReader, error) {
	reader, err := pcapgo.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("open PCAP: %w", err)
	}
	return &OfflineReader{reader: reader, iface: iface, classifier: classifier, decoder: newPacketDecoder()}, nil
}
func (r *OfflineReader) Next(ctx context.Context) (packet.Packet, error) {
	if err := ctx.Err(); err != nil {
		return packet.Packet{}, err
	}
	data, info, err := r.reader.ReadPacketData()
	if err != nil {
		return packet.Packet{}, err
	}
	return r.decoder.Decode(data, info, r.iface, r.classifier)
}
func (*OfflineReader) Close() error { return nil }

type RawSource interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	Close() error
}
type DropCounter interface{ DroppedPackets() uint64 }
type rawDropCounter interface{ DroppedPackets() uint64 }
type LiveOpener interface {
	Open(interfaceName string, tpacketVersion int) (RawSource, error)
}
type LiveReader struct {
	source     RawSource
	iface      string
	classifier directionClassifier
	decoder    *packetDecoder
}

func NewLiveReader(iface string, opener LiveOpener, classifier directionClassifier) (*LiveReader, error) {
	if opener == nil {
		return nil, fmt.Errorf("live opener is required")
	}
	source, err := opener.Open(iface, 3)
	if err != nil {
		return nil, fmt.Errorf("open AF_PACKET on %s: %w", iface, err)
	}
	return &LiveReader{source: source, iface: iface, classifier: classifier, decoder: newPacketDecoder()}, nil
}
func (r *LiveReader) Next(ctx context.Context) (packet.Packet, error) {
	if err := ctx.Err(); err != nil {
		return packet.Packet{}, err
	}
	data, info, err := r.source.ReadPacketData()
	if err != nil {
		return packet.Packet{}, err
	}
	return r.decoder.Decode(data, info, r.iface, r.classifier)
}
func (r *LiveReader) Close() error { return r.source.Close() }
func (r *LiveReader) DroppedPackets() uint64 {
	if source, ok := r.source.(rawDropCounter); ok {
		return source.DroppedPackets()
	}
	return 0
}

type packetDecoder struct {
	ethernet     layers.Ethernet
	vlan         layers.Dot1Q
	ip4          layers.IPv4
	ip6          layers.IPv6
	ip6Extension layers.IPv6ExtensionSkipper
	tcp          layers.TCP
	udp          layers.UDP
	icmp4        layers.ICMPv4
	icmp6        layers.ICMPv6
	parser       *gopacket.DecodingLayerParser
	decoded      []gopacket.LayerType
}

func newPacketDecoder() *packetDecoder {
	d := &packetDecoder{decoded: make([]gopacket.LayerType, 0, 8)}
	d.parser = gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&d.ethernet,
		&d.vlan,
		&d.ip4,
		&d.ip6,
		&d.ip6Extension,
		&d.tcp,
		&d.udp,
		&d.icmp4,
		&d.icmp6,
	)
	// The sensor consumes L2-L4 fields and the original transport payload. Do
	// not invoke application decoders selected only by a well-known port: a
	// non-SIP payload on UDP/5060 must not terminate the capture loop.
	d.parser.IgnoreUnsupported = true
	return d
}

func (d *packetDecoder) Decode(data []byte, info gopacket.CaptureInfo, iface string, classifier directionClassifier) (packet.Packet, error) {
	if err := d.parser.DecodeLayers(data, &d.decoded); err != nil {
		return packet.Packet{}, fmt.Errorf("%w: %v", ErrMalformedPacket, err)
	}
	if d.parser.Truncated {
		return packet.Packet{}, fmt.Errorf("%w: captured frame is truncated", ErrMalformedPacket)
	}
	p := packet.Packet{Timestamp: info.Timestamp, CapturedLength: info.CaptureLength, WireLength: info.Length, Interface: iface}
	if decodedLayer(d.decoded, layers.LayerTypeDot1Q) {
		// The reusable decoder contains the innermost tag after QinQ. Decode
		// once from Ethernet payload to preserve the previous outer-VLAN
		// classification behavior.
		var outerVLAN layers.Dot1Q
		if err := outerVLAN.DecodeFromBytes(d.ethernet.Payload, gopacket.NilDecodeFeedback); err != nil {
			return packet.Packet{}, fmt.Errorf("%w: invalid VLAN header", ErrMalformedPacket)
		}
		p.VLAN = outerVLAN.VLANIdentifier
	}
	if decodedLayer(d.decoded, layers.LayerTypeIPv4) {
		p.IPVersion = 4
		p.SourceIP = netip.AddrFrom4([4]byte(d.ip4.SrcIP))
		p.DestinationIP = netip.AddrFrom4([4]byte(d.ip4.DstIP))
		p.IPID = d.ip4.Id
	} else if decodedLayer(d.decoded, layers.LayerTypeIPv6) {
		src, ok1 := netip.AddrFromSlice(d.ip6.SrcIP)
		dst, ok2 := netip.AddrFromSlice(d.ip6.DstIP)
		if !ok1 || !ok2 {
			return packet.Packet{}, fmt.Errorf("%w: invalid IPv6 address", ErrMalformedPacket)
		}
		p.IPVersion = 6
		p.SourceIP = src
		p.DestinationIP = dst
	} else {
		return packet.Packet{}, fmt.Errorf("%w: non-IP packet", ErrUnsupportedPacket)
	}
	if decodedLayer(d.decoded, layers.LayerTypeTCP) {
		p.Protocol = packet.TCP
		p.SourcePort = uint16(d.tcp.SrcPort)
		p.DestinationPort = uint16(d.tcp.DstPort)
		p.TCPSequence = d.tcp.Seq
		p.TCPFlags = packet.TCPFlags{FIN: d.tcp.FIN, SYN: d.tcp.SYN, RST: d.tcp.RST, PSH: d.tcp.PSH, ACK: d.tcp.ACK, URG: d.tcp.URG, ECE: d.tcp.ECE, CWR: d.tcp.CWR}
		p.Payload = append([]byte(nil), d.tcp.Payload...)
	} else if decodedLayer(d.decoded, layers.LayerTypeUDP) {
		p.Protocol = packet.UDP
		p.SourcePort = uint16(d.udp.SrcPort)
		p.DestinationPort = uint16(d.udp.DstPort)
		p.Payload = append([]byte(nil), d.udp.Payload...)
	} else if decodedLayer(d.decoded, layers.LayerTypeICMPv4) || decodedLayer(d.decoded, layers.LayerTypeICMPv6) {
		p.Protocol = packet.ICMP
	} else {
		p.Protocol = packet.UnknownProtocol
	}
	if classifier != nil {
		p.Direction, _ = classifier.Classify(iface, p.VLAN, p.SourceIP, p.DestinationIP)
	} else {
		p.Direction = direction.Unknown
	}
	return p, nil
}

func decodePacket(data []byte, info gopacket.CaptureInfo, iface string, classifier directionClassifier) (packet.Packet, error) {
	return newPacketDecoder().Decode(data, info, iface, classifier)
}

func decodedLayer(decoded []gopacket.LayerType, target gopacket.LayerType) bool {
	for _, layerType := range decoded {
		if layerType == target {
			return true
		}
	}
	return false
}
