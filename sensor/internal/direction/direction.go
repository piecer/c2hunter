package direction

import (
	"fmt"
	"net/netip"
)

type Direction uint8

const (
	Unknown Direction = iota
	Inbound
	Outbound
	Bidirectional
)

var names = map[Direction]string{Unknown: "UNKNOWN", Inbound: "INBOUND", Outbound: "OUTBOUND", Bidirectional: "BIDIRECTIONAL"}

func (d Direction) String() string {
	if s, ok := names[d]; ok {
		return s
	}
	return "UNKNOWN"
}
func Parse(s string) (Direction, error) {
	for d, name := range names {
		if name == s {
			return d, nil
		}
	}
	return Unknown, fmt.Errorf("invalid direction %q", s)
}

type Source uint8

const (
	SourceNone Source = iota
	SourceInterface
	SourceVLAN
	SourceCIDR
)

type Classifier struct {
	interfaces map[string]Direction
	vlans      map[uint16]Direction
	internal   []netip.Prefix
}

func NewClassifier(interfaces map[string]Direction, vlans map[uint16]Direction, cidrs []string) (*Classifier, error) {
	c := &Classifier{interfaces: interfaces, vlans: vlans}
	for _, raw := range cidrs {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("internal network %q: %w", raw, err)
		}
		c.internal = append(c.internal, p.Masked())
	}
	return c, nil
}
func (c *Classifier) Classify(iface string, vlan uint16, src, dst netip.Addr) (Direction, Source) {
	if d, ok := c.interfaces[iface]; ok && d != Unknown {
		return d, SourceInterface
	}
	if d, ok := c.vlans[vlan]; ok && d != Unknown {
		return d, SourceVLAN
	}
	srcInternal, dstInternal := c.isInternal(src), c.isInternal(dst)
	if srcInternal && !dstInternal {
		return Outbound, SourceCIDR
	}
	if !srcInternal && dstInternal {
		return Inbound, SourceCIDR
	}
	return Unknown, SourceNone
}
func (c *Classifier) isInternal(addr netip.Addr) bool {
	for _, p := range c.internal {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
