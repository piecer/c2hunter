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
}

func NewOfflineReader(r io.Reader, iface string, classifier directionClassifier) (*OfflineReader, error) {
	reader, err := pcapgo.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("open PCAP: %w", err)
	}
	return &OfflineReader{reader: reader, iface: iface, classifier: classifier}, nil
}
func (r *OfflineReader) Next(ctx context.Context) (packet.Packet, error) {
	if err := ctx.Err(); err != nil {
		return packet.Packet{}, err
	}
	data, info, err := r.reader.ReadPacketData()
	if err != nil {
		return packet.Packet{}, err
	}
	return decodePacket(data, info, r.iface, r.classifier)
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
}

func NewLiveReader(iface string, opener LiveOpener, classifier directionClassifier) (*LiveReader, error) {
	if opener == nil {
		return nil, fmt.Errorf("live opener is required")
	}
	source, err := opener.Open(iface, 3)
	if err != nil {
		return nil, fmt.Errorf("open AF_PACKET on %s: %w", iface, err)
	}
	return &LiveReader{source: source, iface: iface, classifier: classifier}, nil
}
func (r *LiveReader) Next(ctx context.Context) (packet.Packet, error) {
	if err := ctx.Err(); err != nil {
		return packet.Packet{}, err
	}
	data, info, err := r.source.ReadPacketData()
	if err != nil {
		return packet.Packet{}, err
	}
	return decodePacket(data, info, r.iface, r.classifier)
}
func (r *LiveReader) Close() error { return r.source.Close() }
func (r *LiveReader) DroppedPackets() uint64 {
	if source, ok := r.source.(rawDropCounter); ok {
		return source.DroppedPackets()
	}
	return 0
}

func decodePacket(data []byte, info gopacket.CaptureInfo, iface string, classifier directionClassifier) (packet.Packet, error) {
	decoded := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: false, NoCopy: true})
	if errLayer := decoded.ErrorLayer(); errLayer != nil {
		return packet.Packet{}, fmt.Errorf("decode packet: %v", errLayer.Error())
	}
	p := packet.Packet{Timestamp: info.Timestamp, CapturedLength: info.CaptureLength, WireLength: info.Length, Interface: iface}
	if vlanLayer := decoded.Layer(layers.LayerTypeDot1Q); vlanLayer != nil {
		p.VLAN = vlanLayer.(*layers.Dot1Q).VLANIdentifier
	}
	if ip4Layer := decoded.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		ip4 := ip4Layer.(*layers.IPv4)
		p.IPVersion = 4
		p.SourceIP = netip.AddrFrom4([4]byte(ip4.SrcIP))
		p.DestinationIP = netip.AddrFrom4([4]byte(ip4.DstIP))
		p.IPID = ip4.Id
	} else if ip6Layer := decoded.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		ip6 := ip6Layer.(*layers.IPv6)
		src, ok1 := netip.AddrFromSlice(ip6.SrcIP)
		dst, ok2 := netip.AddrFromSlice(ip6.DstIP)
		if !ok1 || !ok2 {
			return packet.Packet{}, fmt.Errorf("invalid IPv6 address")
		}
		p.IPVersion = 6
		p.SourceIP = src
		p.DestinationIP = dst
	} else {
		return packet.Packet{}, fmt.Errorf("%w: non-IP packet", ErrUnsupportedPacket)
	}
	if layer := decoded.Layer(layers.LayerTypeTCP); layer != nil {
		tcp := layer.(*layers.TCP)
		p.Protocol = packet.TCP
		p.SourcePort = uint16(tcp.SrcPort)
		p.DestinationPort = uint16(tcp.DstPort)
		p.TCPSequence = tcp.Seq
		p.TCPFlags = packet.TCPFlags{FIN: tcp.FIN, SYN: tcp.SYN, RST: tcp.RST, PSH: tcp.PSH, ACK: tcp.ACK, URG: tcp.URG, ECE: tcp.ECE, CWR: tcp.CWR}
		p.Payload = append([]byte(nil), tcp.Payload...)
	} else if layer := decoded.Layer(layers.LayerTypeUDP); layer != nil {
		udp := layer.(*layers.UDP)
		p.Protocol = packet.UDP
		p.SourcePort = uint16(udp.SrcPort)
		p.DestinationPort = uint16(udp.DstPort)
		p.Payload = append([]byte(nil), udp.Payload...)
	} else if decoded.Layer(layers.LayerTypeICMPv4) != nil || decoded.Layer(layers.LayerTypeICMPv6) != nil {
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
