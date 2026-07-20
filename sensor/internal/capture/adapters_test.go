package capture

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"c2hunter/sensor/internal/direction"
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
