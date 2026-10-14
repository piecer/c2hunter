package packet

import (
	"testing"
	"time"
)

func TestDDoSUnsupportedResponseAbstention(t *testing.T) {
	for _, port := range []uint16{17, 19, 53, 123, 389, 1900, 11211} {
		p := Packet{Protocol: UDP, SourcePort: port, DestinationPort: 53000, EvidenceComplete: true, Timestamp: time.Unix(1784544000, 0), Payload: []byte("unsupported-reply")}
		if s := p.DDoSSample(); s == nil || s.Semantic != "UNKNOWN" || s.Transaction != nil {
			t.Fatalf("port %d: unsupported response must abstain: %+v", port, s)
		}
	}
	p := Packet{Protocol: UDP, SourcePort: 40000, DestinationPort: 53000, EvidenceComplete: true, Timestamp: time.Unix(1784544000, 0), Payload: []byte("direct")}
	if s := p.DDoSSample(); s == nil || s.Semantic != "OTHER" {
		t.Fatal(s)
	}
}

func TestDDoSSignedSafeTimestampBoundary(t *testing.T) {
	for _, stamp := range []int64{-9007199254740992, -9007199254740991, -500000, 0, 9007199254740991, 9007199254740992} {
		p := Packet{Protocol: UDP, SourcePort: 40000, DestinationPort: 53000, EvidenceComplete: true, Timestamp: time.UnixMicro(stamp)}
		s := p.DDoSSample()
		if stamp < -9007199254740991 || stamp > 9007199254740991 {
			if s != nil {
				t.Fatalf("out-of-safe-range sample: %+v", s)
			}
		} else if s == nil || s.TimestampUS != stamp {
			t.Fatalf("signed exact timestamp %d: %+v", stamp, s)
		}
	}
}
