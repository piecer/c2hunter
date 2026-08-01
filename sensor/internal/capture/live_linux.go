//go:build linux

package capture

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"golang.org/x/net/bpf"
)

type AFPacketOpener struct{ PollTimeout time.Duration }

func (o AFPacketOpener) Open(interfaceName string, version int) (RawSource, error) {
	if version != 3 {
		return nil, fmt.Errorf("unsupported TPACKET version %d", version)
	}
	timeout := o.PollTimeout
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	handle, err := afpacket.NewTPacket(afpacket.OptInterface(interfaceName), afpacket.OptTPacketVersion(afpacket.TPacketVersion3), afpacket.OptPollTimeout(timeout))
	if err != nil {
		return nil, err
	}
	return &afPacketSource{handle: handle}, nil
}

type afPacketSource struct{ handle *afpacket.TPacket }

func (s *afPacketSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	data, info, err := s.handle.ReadPacketData()
	if errors.Is(err, afpacket.ErrTimeout) {
		err = ErrPollTimeout
	}
	return data, info, err
}
func (s *afPacketSource) Close() error { s.handle.Close(); return nil }
func (s *afPacketSource) DroppedPackets() uint64 {
	stats, statsV3, err := s.handle.SocketStats()
	if err != nil {
		return 0
	}
	return uint64(stats.Drops()) + uint64(statsV3.Drops())
}

// SetBPF pushes a classic BPF program into the kernel via SO_ATTACH_FILTER.
func (s *afPacketSource) SetBPF(filter []bpf.Instruction) error {
	prog, err := bpf.Assemble(filter)
	if err != nil {
		return fmt.Errorf("assemble BPF: %w", err)
	}
	return s.handle.SetBPF(prog)
}
