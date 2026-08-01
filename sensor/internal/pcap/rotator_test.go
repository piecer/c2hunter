package pcap

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
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
	r, err := NewRotator(f, Limits{MaxBytes: 60, MaxDuration: time.Second})
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

func TestFileRotatorWritesReadablePCAPAndFinalizesPartialFile(t *testing.T) {
	dir := t.TempDir()
	r, err := NewRotator(FileFactory{Directory: dir, Prefix: "eth0"}, Limits{MaxBytes: 43})
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Unix(10, 0)
	for _, data := range [][]byte{[]byte("123"), []byte("456")} {
		if err := r.WritePacket(PacketInfo{Timestamp: t0, CaptureLength: len(data), WireLength: len(data)}, data); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	partials, err := filepath.Glob(filepath.Join(dir, "*.partial"))
	if err != nil || len(partials) != 0 {
		t.Fatalf("partial files = %v, %v", partials, err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.pcap"))
	if err != nil || len(files) != 2 {
		t.Fatalf("pcap files = %v, %v", files, err)
	}
	for _, path := range files {
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		reader, err := pcapgo.NewReader(file)
		if err != nil {
			file.Close()
			t.Fatal(err)
		}
		if _, _, err := reader.ReadPacketData(); err != nil && err != io.EOF {
			file.Close()
			t.Fatal(err)
		}
		file.Close()
	}
}

func TestRecoverPartialSegmentsTruncatesIncompleteRecord(t *testing.T) {
	dir := t.TempDir()
	partial := filepath.Join(dir, "eth0-000001-1.pcap.partial")
	file, err := os.Create(partial)
	if err != nil {
		t.Fatal(err)
	}
	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	data := []byte{1, 2, 3}
	if err := writer.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1, 0), CaptureLength: len(data), Length: len(data)}, data); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := RecoverPartialSegments(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(partial); !os.IsNotExist(err) {
		t.Fatalf("partial still exists: %v", err)
	}
	finalPath := partial[:len(partial)-len(".partial")]
	recovered, err := os.Open(finalPath)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	reader, err := pcapgo.NewReader(recovered)
	if err != nil {
		t.Fatal(err)
	}
	if got, _, err := reader.ReadPacketData(); err != nil || len(got) != len(data) {
		t.Fatalf("recovered packet = %v, err = %v", got, err)
	}
	if _, _, err := reader.ReadPacketData(); err != io.EOF {
		t.Fatalf("truncated record survived recovery: %v", err)
	}
}

func TestRecoverPartialSegmentsQuarantinesInvalidHeader(t *testing.T) {
	dir := t.TempDir()
	partial := filepath.Join(dir, "invalid.pcap.partial")
	if err := os.WriteFile(partial, []byte("not a pcap"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := RecoverPartialSegments(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(partial); !os.IsNotExist(err) {
		t.Fatalf("invalid partial still exists: %v", err)
	}
	quarantined, err := filepath.Glob(filepath.Join(dir, "invalid.pcap.corrupt-*"))
	if err != nil || len(quarantined) != 1 {
		t.Fatalf("quarantined files = %v, err = %v", quarantined, err)
	}
}

func TestFileFactoryDoesNotOverwriteExistingSegment(t *testing.T) {
	dir := t.TempDir()
	factory := FileFactory{Directory: dir, Prefix: "eth0"}
	started := time.Unix(1, 0)
	for range 2 {
		segment, err := factory.Open(0, started)
		if err != nil {
			t.Fatal(err)
		}
		if err := segment.Close(RotateJobEnd); err != nil {
			t.Fatal(err)
		}
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.pcap"))
	if err != nil || len(files) != 2 {
		t.Fatalf("segments = %v, err = %v", files, err)
	}
}
