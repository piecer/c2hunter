package packet

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"c2hunter/sensor/internal/direction"
)

func basePacket() Packet {
	return Packet{Timestamp: time.Unix(1, 0), CapturedLength: 60, WireLength: 100, Interface: "eth0", Direction: direction.Outbound, IPVersion: 4, SourceIP: netip.MustParseAddr("10.0.0.2"), DestinationIP: netip.MustParseAddr("203.0.113.2"), SourcePort: 1234, DestinationPort: 443, Protocol: TCP, Payload: []byte("secret")}
}

func TestFilterMatchesAllConfiguredFields(t *testing.T) {
	f, err := NewFilter(FilterSpec{SourceCIDRs: []string{"10.0.0.0/8"}, DestinationCIDRs: []string{"203.0.113.0/24"}, SourcePorts: []uint16{1234}, DestinationPorts: []uint16{443}, Protocols: []Protocol{TCP}, IPVersions: []uint8{4}, Directions: []direction.Direction{direction.Outbound}})
	if err != nil {
		t.Fatal(err)
	}
	p := basePacket()
	if !f.Match(p) {
		t.Fatal("matching packet rejected")
	}
	p.DestinationPort = 80
	if f.Match(p) {
		t.Fatal("non-matching packet accepted")
	}
}

func TestFilterDelegatesBPFAndRejectsInvalidCIDR(t *testing.T) {
	if _, err := NewFilter(FilterSpec{SourceCIDRs: []string{"invalid"}}); err == nil {
		t.Fatal("invalid CIDR accepted")
	}
	called := false
	f, err := NewFilter(FilterSpec{BPFExpression: "tcp port 443", BPFMatcher: func(expression string, p Packet) bool { called = true; return expression == "tcp port 443" }})
	if err != nil {
		t.Fatal(err)
	}
	if !f.Match(basePacket()) || !called {
		t.Fatal("BPF matcher not used")
	}
}

func TestPrivacyDefaultDropsPayload(t *testing.T) {
	p := basePacket()
	got := p.ForStorage(false)
	if got.Payload != nil {
		t.Fatalf("payload retained: %q", got.Payload)
	}
	if string(p.Payload) != "secret" {
		t.Fatal("source packet mutated")
	}
}

func TestCompileBPFMatcherAppliesSupportedExpressionAndRejectsUnknownSyntax(t *testing.T) {
	matcher, err := CompileBPFMatcher("ip and tcp and port 443")
	if err != nil {
		t.Fatal(err)
	}
	p := Packet{IPVersion: 4, Protocol: TCP, DestinationPort: 443}
	if !matcher("ip and tcp and port 443", p) {
		t.Fatal("matching packet rejected")
	}
	p.DestinationPort = 80
	if matcher("ip and tcp and port 443", p) {
		t.Fatal("non-matching port accepted")
	}
	if _, err := CompileBPFMatcher("tcp[13] & 2 != 0"); err == nil {
		t.Fatal("unsupported BPF syntax accepted")
	}
}

func TestCompileBPFMatcherSupportsBooleanOperatorsAndParentheses(t *testing.T) {
	matcher, err := CompileBPFMatcher("(tcp and dst port 443) or (udp and port 53)")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		packet Packet
		want   bool
	}{
		{packet: Packet{Protocol: TCP, DestinationPort: 443}, want: true},
		{packet: Packet{Protocol: UDP, SourcePort: 53}, want: true},
		{packet: Packet{Protocol: TCP, DestinationPort: 80}, want: false},
	}
	for _, test := range tests {
		if got := matcher("ignored after compilation", test.packet); got != test.want {
			t.Fatalf("match=%t, want %t for %+v", got, test.want, test.packet)
		}
	}

	notSSH, err := CompileBPFMatcher("tcp and not src port 22")
	if err != nil {
		t.Fatal(err)
	}
	if notSSH("", Packet{Protocol: TCP, SourcePort: 22}) {
		t.Fatal("negated source port accepted")
	}
	if !notSSH("", Packet{Protocol: TCP, SourcePort: 12345}) {
		t.Fatal("non-negated TCP packet rejected")
	}
}

func TestCompileBPFMatcherRejectsMalformedBooleanExpression(t *testing.T) {
	for _, expression := range []string{"and", "tcp and", "or tcp", "(tcp or udp"} {
		if _, err := CompileBPFMatcher(expression); err == nil {
			t.Fatalf("malformed BPF expression %q accepted", expression)
		}
	}
}

func TestCompileBPFMatcherRejectsExcessiveComplexity(t *testing.T) {
	const (
		testMaxBPFNesting = 32
		testMaxBPFNodes   = 128
		testMaxBPFTokens  = 512
	)
	tests := []struct {
		name       string
		expression string
	}{
		{
			name:       "unary nesting",
			expression: strings.Repeat("not ", testMaxBPFNesting+1) + "tcp",
		},
		{
			name: "parenthesis nesting",
			expression: strings.Repeat("(", testMaxBPFNesting+1) + "tcp" +
				strings.Repeat(")", testMaxBPFNesting+1),
		},
		{
			name:       "predicate nodes",
			expression: strings.Repeat("tcp or ", testMaxBPFNodes) + "tcp",
		},
		{
			name:       "tokens",
			expression: strings.Repeat("tcp ", testMaxBPFTokens+1),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := CompileBPFMatcher(test.expression); err == nil {
				t.Fatalf("excessively complex BPF expression %q accepted", test.name)
			}
		})
	}
}
