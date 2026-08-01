package capture

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/google/gopacket"
	"golang.org/x/net/bpf"
)

// mockRawSourceWithBPF implements BPFSetter and stores what was set.
type mockRawSourceWithBPF struct {
	bpfSet []bpf.Instruction
	called int
}

func (s *mockRawSourceWithBPF) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	s.called++
	return nil, gopacket.CaptureInfo{Timestamp: time.Now()}, io.EOF
}
func (*mockRawSourceWithBPF) Close() error           { return nil }
func (*mockRawSourceWithBPF) DroppedPackets() uint64 { return 0 }
func (s *mockRawSourceWithBPF) SetBPF(instrs []bpf.Instruction) error {
	s.bpfSet = append([]bpf.Instruction(nil), instrs...)
	return nil
}

// rawSourceNoBPF does not implement BPFSetter — graceful fallback path.
type rawSourceNoBPF struct{}

func (*rawSourceNoBPF) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return nil, gopacket.CaptureInfo{Timestamp: time.Now()}, io.EOF
}
func (*rawSourceNoBPF) Close() error           { return nil }
func (*rawSourceNoBPF) DroppedPackets() uint64 { return 0 }

func TestLiveReaderSetsKernelBPFWhenSupported(t *testing.T) {
	source := &mockRawSourceWithBPF{}
	reader, err := NewLiveReaderWithSource("eth0", source, nil)
	if err != nil {
		t.Fatal(err)
	}

	filter := []bpf.Instruction{
		bpf.LoadAbsolute{Off: 0, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipTrue: 1},
		bpf.RetConstant{Val: 65535}, // accept IPv4
		bpf.RetConstant{Val: 0},     // drop rest
	}
	if err := reader.SetKernelBPF(filter); err != nil {
		t.Fatal(err)
	}

	if len(source.bpfSet) == 0 {
		t.Fatal("expected kernel BPF to be set on RawSource")
	}
	if source.bpfSet[0].(bpf.LoadAbsolute).Size != 2 {
		t.Fatalf("unexpected first instruction: %+v", source.bpfSet[0])
	}
}

func TestLiveReaderKernelBPFGracefulFallback(t *testing.T) {
	source := &rawSourceNoBPF{}
	reader, err := NewLiveReaderWithSource("eth0", source, nil)
	if err != nil {
		t.Fatal(err)
	}

	filter := []bpf.Instruction{bpf.RetConstant{Val: 65535}}
	// Source doesn't implement BPFSetter — should be a no-op.
	if err := reader.SetKernelBPF(filter); err != nil {
		t.Fatalf("expected no error for unsupported BPF source, got: %v", err)
	}
}

func TestLiveReaderPassesThroughPackets(t *testing.T) {
	source := &mockRawSourceWithBPF{}
	reader, err := NewLiveReaderWithSource("eth0", source, nil)
	if err != nil {
		t.Fatal(err)
	}

	pkt, err := reader.Next(context.Background())
	// ReadPacketData returns io.EOF which gets forwarded.
	_ = pkt
	if source.called == 0 {
		t.Fatal("expected at least one ReadPacketData call")
	}
}
