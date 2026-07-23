package capture

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"c2hunter/sensor/internal/direction"
	"c2hunter/sensor/internal/packet"
)

func TestOfflineReaderStreamsPCAP(t *testing.T) {
	payload := []byte("hello")
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	eth := &layers.Ethernet{SrcMAC: []byte{0, 1, 2, 3, 4, 5}, DstMAC: []byte{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: netip.MustParseAddr("10.0.0.1").AsSlice(), DstIP: netip.MustParseAddr("192.0.2.1").AsSlice(), Protocol: layers.IPProtocolTCP}
	tcp := &layers.TCP{SrcPort: 1234, DstPort: 443, SYN: true}
	tcp.SetNetworkLayerForChecksum(ip)
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	var file bytes.Buffer
	w := pcapgo.NewWriter(&file)
	w.WriteFileHeader(65535, layers.LinkTypeEthernet)
	w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1, 0), CaptureLength: len(buf.Bytes()), Length: len(buf.Bytes())}, buf.Bytes())
	classifier, _ := direction.NewClassifier(nil, nil, []string{"10.0.0.0/8"})
	r, err := NewOfflineReader(bytes.NewReader(file.Bytes()), "fixture", classifier)
	if err != nil {
		t.Fatal(err)
	}
	p, err := r.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p.Protocol != 1 || p.SourcePort != 1234 || p.DestinationPort != 443 || string(p.Payload) != "hello" || p.Direction != direction.Outbound {
		t.Fatalf("decoded packet: %+v", p)
	}
	if _, err := r.Next(context.Background()); !errors.Is(err, EndOfInput) {
		t.Fatalf("expected EOF: %v", err)
	}
}

type rawStub struct {
	data    []byte
	info    gopacket.CaptureInfo
	closed  bool
	dropped uint64
}

func (r *rawStub) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) { return r.data, r.info, nil }
func (r *rawStub) Close() error                                          { r.closed = true; return nil }
func (r *rawStub) DroppedPackets() uint64                                { return r.dropped }

type openerStub struct {
	source  RawSource
	iface   string
	version int
}

func (o *openerStub) Open(iface string, version int) (RawSource, error) {
	o.iface = iface
	o.version = version
	return o.source, nil
}
func TestLiveAdapterRequestsTPacketV3WithoutPrivileges(t *testing.T) {
	raw := &rawStub{}
	opener := &openerStub{source: raw}
	live, err := NewLiveReader("eth-test", opener, nil)
	if err != nil {
		t.Fatal(err)
	}
	if opener.iface != "eth-test" || opener.version != 3 {
		t.Fatalf("wrong live options: %+v", opener)
	}
	if err := live.Close(); err != nil || !raw.closed {
		t.Fatal("source not closed")
	}
}

func TestLiveReaderExposesAFPacketDrops(t *testing.T) {
	live, err := NewLiveReader("eth-test", &openerStub{source: &rawStub{dropped: 9}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := live.DroppedPackets(); got != 9 {
		t.Fatalf("drops = %d", got)
	}
}

func TestDecodePacketKeepsTransportPayloadWhenAutomaticSIPDecodeWouldFail(t *testing.T) {
	payload := []byte("invalid\r\n")
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	eth := &layers.Ethernet{SrcMAC: []byte{0, 1, 2, 3, 4, 5}, DstMAC: []byte{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: netip.MustParseAddr("10.0.0.1").AsSlice(), DstIP: netip.MustParseAddr("192.0.2.1").AsSlice(), Protocol: layers.IPProtocolUDP}
	udp := &layers.UDP{SrcPort: 40000, DstPort: 5060}
	udp.SetNetworkLayerForChecksum(ip)
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}

	eager := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.DecodeOptions{NoCopy: true})
	if errLayer := eager.ErrorLayer(); errLayer == nil || !strings.Contains(errLayer.Error().Error(), "invalid first SIP line") {
		t.Fatalf("fixture did not reproduce the SIP decoder failure: %v", errLayer)
	}

	decoder := newPacketDecoder()
	if _, err := decoder.Decode([]byte{0, 1, 2}, gopacket.CaptureInfo{CaptureLength: 3, Length: 60}, "eth-test", nil); !errors.Is(err, ErrMalformedPacket) {
		t.Fatalf("initial malformed frame error = %v", err)
	}
	info := gopacket.CaptureInfo{Timestamp: time.Unix(2, 0), CaptureLength: len(buf.Bytes()), Length: len(buf.Bytes())}
	got, err := decoder.Decode(buf.Bytes(), info, "eth-test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Protocol != packet.UDP || got.SourcePort != 40000 || got.DestinationPort != 5060 || string(got.Payload) != string(payload) {
		t.Fatalf("decoded packet = %+v", got)
	}
}

func TestDecodePacketClassifiesTruncatedFramesAsRecoverable(t *testing.T) {
	_, err := decodePacket([]byte{0, 1, 2}, gopacket.CaptureInfo{CaptureLength: 3, Length: 60}, "eth-test", nil)
	if !errors.Is(err, ErrMalformedPacket) {
		t.Fatalf("error = %v", err)
	}
}

func TestDecodePacketPreservesVLANAndIPv6Transport(t *testing.T) {
	payload := []byte("payload")
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	eth := &layers.Ethernet{SrcMAC: []byte{0, 1, 2, 3, 4, 5}, DstMAC: []byte{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeDot1Q}
	vlan := &layers.Dot1Q{VLANIdentifier: 123, Type: layers.EthernetTypeIPv6}
	ip := &layers.IPv6{Version: 6, HopLimit: 64, SrcIP: netip.MustParseAddr("2001:db8::1").AsSlice(), DstIP: netip.MustParseAddr("2001:db8::2").AsSlice(), NextHeader: layers.IPProtocolTCP}
	tcp := &layers.TCP{SrcPort: 12345, DstPort: 443, ACK: true}
	tcp.SetNetworkLayerForChecksum(ip)
	if err := gopacket.SerializeLayers(buf, opts, eth, vlan, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}

	info := gopacket.CaptureInfo{Timestamp: time.Unix(3, 0), CaptureLength: len(buf.Bytes()), Length: len(buf.Bytes())}
	got, err := decodePacket(buf.Bytes(), info, "eth-test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.VLAN != 123 || got.IPVersion != 6 || got.Protocol != packet.TCP || got.SourcePort != 12345 || got.DestinationPort != 443 || string(got.Payload) != string(payload) {
		t.Fatalf("decoded packet = %+v", got)
	}
}
