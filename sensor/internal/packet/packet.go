package packet

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"c2hunter/sensor/internal/direction"
)

type Protocol uint8

const (
	UnknownProtocol Protocol = iota
	TCP
	UDP
	ICMP
)

type TCPFlags struct{ FIN, SYN, RST, PSH, ACK, URG, ECE, CWR bool }
type Packet struct {
	Timestamp                   time.Time
	CapturedLength, WireLength  int
	Interface                   string
	VLAN                        uint16
	Direction                   direction.Direction
	IPVersion                   uint8
	SourceIP, DestinationIP     netip.Addr
	SourcePort, DestinationPort uint16
	Protocol                    Protocol
	TCPFlags                    TCPFlags
	Payload                     []byte
	IPID                        uint16
	TCPSequence                 uint32
}

func (p Packet) ForStorage(storePayload bool) Packet {
	out := p
	if !storePayload {
		out.Payload = nil
	} else {
		out.Payload = append([]byte(nil), p.Payload...)
	}
	return out
}

type BPFMatcher func(string, Packet) bool

type bpfPredicate func(Packet) bool

const (
	maxBPFTokens  = 512
	maxBPFNodes   = 128
	maxBPFNesting = 32
)

type bpfParser struct {
	tokens     []string
	position   int
	expression string
	nodes      int
	nesting    int
}

func CompileBPFMatcher(expression string) (BPFMatcher, error) {
	normalized := strings.NewReplacer("(", " ( ", ")", " ) ").Replace(strings.ToLower(strings.TrimSpace(expression)))
	tokens := strings.Fields(normalized)
	if len(tokens) == 0 {
		return func(string, Packet) bool { return true }, nil
	}
	if len(tokens) > maxBPFTokens {
		return nil, fmt.Errorf("BPF expression exceeds token limit of %d", maxBPFTokens)
	}
	parser := bpfParser{tokens: tokens, expression: expression}
	predicate, err := parser.parseExpression()
	if err != nil {
		return nil, err
	}
	if parser.position != len(parser.tokens) {
		return nil, fmt.Errorf("unsupported BPF token %q", parser.tokens[parser.position])
	}
	return func(_ string, packet Packet) bool {
		return predicate(packet)
	}, nil
}

func (p *bpfParser) parseExpression() (bpfPredicate, error) {
	return p.parseOr()
}

func (p *bpfParser) parseOr() (bpfPredicate, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.consume("or") {
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		if err := p.addNode(); err != nil {
			return nil, err
		}
		previous := left
		left = func(packet Packet) bool { return previous(packet) || right(packet) }
	}
	return left, nil
}

func (p *bpfParser) parseAnd() (bpfPredicate, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.position < len(p.tokens) && p.tokens[p.position] != "or" && p.tokens[p.position] != ")" {
		p.consume("and")
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		if err := p.addNode(); err != nil {
			return nil, err
		}
		previous := left
		left = func(packet Packet) bool { return previous(packet) && right(packet) }
	}
	return left, nil
}

func (p *bpfParser) parseUnary() (bpfPredicate, error) {
	if p.consume("not") {
		if err := p.enterNesting(); err != nil {
			return nil, err
		}
		predicate, err := p.parseUnary()
		p.nesting--
		if err != nil {
			return nil, err
		}
		if err := p.addNode(); err != nil {
			return nil, err
		}
		return func(packet Packet) bool { return !predicate(packet) }, nil
	}
	if p.consume("(") {
		if err := p.enterNesting(); err != nil {
			return nil, err
		}
		predicate, err := p.parseExpression()
		p.nesting--
		if err != nil {
			return nil, err
		}
		if !p.consume(")") {
			return nil, fmt.Errorf("unclosed parenthesis in BPF expression %q", p.expression)
		}
		return predicate, nil
	}
	return p.parsePrimitive()
}

func (p *bpfParser) parsePrimitive() (bpfPredicate, error) {
	if p.position >= len(p.tokens) {
		return nil, fmt.Errorf("incomplete BPF expression %q", p.expression)
	}
	token := p.tokens[p.position]
	p.position++
	if err := p.addNode(); err != nil {
		return nil, err
	}
	switch token {
	case "ip":
		return func(packet Packet) bool { return packet.IPVersion == 4 }, nil
	case "ip6":
		return func(packet Packet) bool { return packet.IPVersion == 6 }, nil
	case "tcp":
		return func(packet Packet) bool { return packet.Protocol == TCP }, nil
	case "udp":
		return func(packet Packet) bool { return packet.Protocol == UDP }, nil
	case "icmp":
		return func(packet Packet) bool { return packet.Protocol == ICMP }, nil
	case "port", "src", "dst":
		return p.parsePort(token)
	default:
		return nil, fmt.Errorf("unsupported BPF token %q", token)
	}
}

func (p *bpfParser) parsePort(kind string) (bpfPredicate, error) {
	if kind != "port" && !p.consume("port") {
		return nil, fmt.Errorf("unsupported BPF expression %q", p.expression)
	}
	if p.position >= len(p.tokens) {
		return nil, fmt.Errorf("missing BPF port")
	}
	raw := p.tokens[p.position]
	p.position++
	value, err := strconv.ParseUint(raw, 10, 16)
	if err != nil || value == 0 {
		return nil, fmt.Errorf("invalid BPF port %q", raw)
	}
	port := uint16(value)
	switch kind {
	case "src":
		return func(packet Packet) bool { return packet.SourcePort == port }, nil
	case "dst":
		return func(packet Packet) bool { return packet.DestinationPort == port }, nil
	default:
		return func(packet Packet) bool { return packet.SourcePort == port || packet.DestinationPort == port }, nil
	}
}

func (p *bpfParser) consume(token string) bool {
	if p.position >= len(p.tokens) || p.tokens[p.position] != token {
		return false
	}
	p.position++
	return true
}

func (p *bpfParser) addNode() error {
	if p.nodes >= maxBPFNodes {
		return fmt.Errorf("BPF expression exceeds node limit of %d", maxBPFNodes)
	}
	p.nodes++
	return nil
}

func (p *bpfParser) enterNesting() error {
	if p.nesting >= maxBPFNesting {
		return fmt.Errorf("BPF expression exceeds nesting limit of %d", maxBPFNesting)
	}
	p.nesting++
	return nil
}

type FilterSpec struct {
	BPFExpression                 string
	BPFMatcher                    BPFMatcher
	SourceCIDRs, DestinationCIDRs []string
	SourcePorts, DestinationPorts []uint16
	Protocols                     []Protocol
	IPVersions                    []uint8
	Directions                    []direction.Direction
}
type Filter struct {
	spec     FilterSpec
	src, dst []netip.Prefix
}

func NewFilter(spec FilterSpec) (*Filter, error) {
	if spec.BPFExpression != "" && spec.BPFMatcher == nil {
		return nil, fmt.Errorf("BPF expression requires capture backend matcher")
	}
	f := &Filter{spec: spec}
	var err error
	if f.src, err = parsePrefixes(spec.SourceCIDRs); err != nil {
		return nil, err
	}
	if f.dst, err = parsePrefixes(spec.DestinationCIDRs); err != nil {
		return nil, err
	}
	return f, nil
}
func parsePrefixes(raw []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(raw))
	for _, s := range raw {
		p, e := netip.ParsePrefix(s)
		if e != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", s, e)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}
func (f *Filter) Match(p Packet) bool {
	if f.spec.BPFExpression != "" && !f.spec.BPFMatcher(f.spec.BPFExpression, p) {
		return false
	}
	return matchAddr(f.src, p.SourceIP) && matchAddr(f.dst, p.DestinationIP) && contains(f.spec.SourcePorts, p.SourcePort) && contains(f.spec.DestinationPorts, p.DestinationPort) && contains(f.spec.Protocols, p.Protocol) && contains(f.spec.IPVersions, p.IPVersion) && contains(f.spec.Directions, p.Direction)
}
func matchAddr(want []netip.Prefix, got netip.Addr) bool {
	if len(want) == 0 {
		return true
	}
	for _, p := range want {
		if p.Contains(got) {
			return true
		}
	}
	return false
}
func contains[T comparable](want []T, got T) bool {
	if len(want) == 0 {
		return true
	}
	for _, v := range want {
		if v == got {
			return true
		}
	}
	return false
}
