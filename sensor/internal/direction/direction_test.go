package direction

import (
	"net/netip"
	"testing"
)

func TestDirectionValuesAndParsing(t *testing.T) {
	for _, s := range []string{"INBOUND", "OUTBOUND", "BIDIRECTIONAL", "UNKNOWN"} {
		d, err := Parse(s)
		if err != nil || d.String() != s {
			t.Fatalf("Parse(%q)=%v,%v", s, d, err)
		}
	}
	if _, err := Parse("guess"); err == nil {
		t.Fatal("invalid direction accepted")
	}
}

func TestClassifierUsesInterfaceThenVLANThenCIDR(t *testing.T) {
	c, err := NewClassifier(map[string]Direction{"in0": Inbound}, map[uint16]Direction{20: Outbound}, []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, iface string
		vlan        uint16
		src, dst    string
		want        Direction
		source      Source
	}{
		{"interface", "in0", 20, "10.0.0.1", "8.8.8.8", Inbound, SourceInterface},
		{"vlan", "other", 20, "10.0.0.1", "8.8.8.8", Outbound, SourceVLAN},
		{"cidr outbound", "other", 0, "10.0.0.1", "8.8.8.8", Outbound, SourceCIDR},
		{"cidr inbound", "other", 0, "8.8.8.8", "10.0.0.1", Inbound, SourceCIDR},
		{"both internal ambiguous", "other", 0, "10.0.0.1", "10.1.0.2", Unknown, SourceNone},
		{"both external ambiguous", "other", 0, "8.8.8.8", "1.1.1.1", Unknown, SourceNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, source := c.Classify(tt.iface, tt.vlan, netip.MustParseAddr(tt.src), netip.MustParseAddr(tt.dst))
			if got != tt.want || source != tt.source {
				t.Fatalf("got %v/%v want %v/%v", got, source, tt.want, tt.source)
			}
		})
	}
}
