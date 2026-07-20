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

func CompileBPFMatcher(expression string) (BPFMatcher, error) {
	tokens := strings.Fields(strings.ToLower(strings.TrimSpace(expression)))
	if len(tokens) == 0 {
		return func(string, Packet) bool { return true }, nil
	}
	type predicate func(Packet) bool
	predicates := make([]predicate, 0, len(tokens))
	for index := 0; index < len(tokens); {
		token := tokens[index]
		if token == "and" {
			index++
			continue
		}
		switch token {
		case "ip":
			predicates = append(predicates, func(p Packet) bool { return p.IPVersion == 4 })
		case "ip6":
			predicates = append(predicates, func(p Packet) bool { return p.IPVersion == 6 })
		case "tcp":
			predicates = append(predicates, func(p Packet) bool { return p.Protocol == TCP })
		case "udp":
			predicates = append(predicates, func(p Packet) bool { return p.Protocol == UDP })
		case "icmp":
			predicates = append(predicates, func(p Packet) bool { return p.Protocol == ICMP })
		case "port", "src", "dst":
			kind := token
			if kind != "port" {
				index++
				if index >= len(tokens) || tokens[index] != "port" {
					return nil, fmt.Errorf("unsupported BPF expression %q", expression)
				}
			}
			index++
			if index >= len(tokens) {
				return nil, fmt.Errorf("missing BPF port")
			}
			value, err := strconv.ParseUint(tokens[index], 10, 16)
			if err != nil || value == 0 {
				return nil, fmt.Errorf("invalid BPF port %q", tokens[index])
			}
			port := uint16(value)
			switch kind {
			case "src":
				predicates = append(predicates, func(p Packet) bool { return p.SourcePort == port })
			case "dst":
				predicates = append(predicates, func(p Packet) bool { return p.DestinationPort == port })
			default:
				predicates = append(predicates, func(p Packet) bool { return p.SourcePort == port || p.DestinationPort == port })
			}
		default:
			return nil, fmt.Errorf("unsupported BPF token %q", token)
		}
		index++
	}
	return func(_ string, packet Packet) bool {
		for _, match := range predicates {
			if !match(packet) {
				return false
			}
		}
		return true
	}, nil
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
