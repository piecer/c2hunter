package pcap

import (
	"testing"
	"time"
)

type memorySegment struct {
	reasons *[]RotationReason
	writes  int
}

func (m *memorySegment) WritePacket(PacketInfo, []byte) error { m.writes++; return nil }
func (m *memorySegment) Close(reason RotationReason) error {
	*m.reasons = append(*m.reasons, reason)
	return nil
}

type memoryFactory struct {
	reasons  []RotationReason
	segments []*memorySegment
}

func (f *memoryFactory) Open(int, time.Time) (Segment, error) {
	s := &memorySegment{reasons: &f.reasons}
	f.segments = append(f.segments, s)
	return s, nil
}
func TestRotatorRotatesBySizeTimeAndExplicitReasons(t *testing.T) {
	t0 := time.Unix(10, 0)
	f := &memoryFactory{}
	r, err := NewRotator(f, Limits{MaxBytes: 5, MaxDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.WritePacket(PacketInfo{Timestamp: t0, CaptureLength: 3, WireLength: 3}, []byte("123")); err != nil {
		t.Fatal(err)
	}
	r.WritePacket(PacketInfo{Timestamp: t0, CaptureLength: 3, WireLength: 3}, []byte("456"))
	r.WritePacket(PacketInfo{Timestamp: t0.Add(2 * time.Second), CaptureLength: 1, WireLength: 1}, []byte("7"))
	if err := r.Rotate(RotateRestart); err != nil {
		t.Fatal(err)
	}
	r.WritePacket(PacketInfo{Timestamp: t0.Add(3 * time.Second), CaptureLength: 1, WireLength: 1}, []byte("8"))
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	want := []RotationReason{RotateSize, RotateTime, RotateRestart, RotateJobEnd}
	if len(f.reasons) != len(want) {
		t.Fatalf("reasons=%v", f.reasons)
	}
	for i := range want {
		if f.reasons[i] != want[i] {
			t.Fatalf("reasons=%v", f.reasons)
		}
	}
}
func TestRotatorValidatesLimits(t *testing.T) {
	if _, err := NewRotator(&memoryFactory{}, Limits{}); err == nil {
		t.Fatal("unbounded rotator accepted")
	}
}
