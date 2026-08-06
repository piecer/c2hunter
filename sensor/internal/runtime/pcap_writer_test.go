package runtime

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"c2hunter/sensor/internal/packet"
	pcapstore "c2hunter/sensor/internal/pcap"
)

func TestPCAPWriterQueueDoesNotBlockAndReportsDrops(t *testing.T) {
	factory := &blockingPCAPFactory{opened: make(chan struct{}), release: make(chan struct{})}
	rotator, err := pcapstore.NewRotator(factory, pcapstore.Limits{MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	writer, err := NewPCAPWriter(PCAPWriterConfig{Rotator: rotator, QueueSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- writer.Run(ctx) }()
	packetAt := func(value byte) packet.Packet {
		return packet.Packet{Timestamp: time.Unix(1, 0), CapturedLength: 1, WireLength: 1, RawFrame: []byte{value}}
	}
	if !writer.Enqueue(packetAt(1)) {
		t.Fatal("first packet was rejected")
	}
	select {
	case <-factory.opened:
	case <-time.After(time.Second):
		t.Fatal("writer did not start")
	}
	if !writer.Enqueue(packetAt(2)) {
		t.Fatal("second packet should fit the bounded queue")
	}
	start := time.Now()
	if writer.Enqueue(packetAt(3)) {
		t.Fatal("full queue accepted a packet")
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Fatal("full PCAP queue blocked capture path")
	}
	if writer.Snapshot().PCAPDroppedPackets != 1 {
		t.Fatalf("snapshot = %+v", writer.Snapshot())
	}
	fullPacket := packetAt(4)
	if allocations := testing.AllocsPerRun(100, func() { writer.Enqueue(fullPacket) }); allocations != 0 {
		t.Fatalf("full-queue enqueue allocations = %f", allocations)
	}
	close(factory.release)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPCAPWriterClearsRecoveredWriteError(t *testing.T) {
	dir := t.TempDir()
	rotator, err := pcapstore.NewRotator(
		pcapstore.FileFactory{Directory: dir, Prefix: "eth0"},
		pcapstore.Limits{MaxBytes: 1 << 20},
	)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := NewPCAPWriter(PCAPWriterConfig{Rotator: rotator, QueueSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	writer.drop("write PCAP packet: permission denied")
	writer.write(packet.Packet{Timestamp: time.Unix(1, 0), WireLength: 4, RawFrame: []byte("pcap")})
	if got := writer.Snapshot().LastError; got != "" {
		t.Fatalf("recovered write left stale error %q", got)
	}
	if err := rotator.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPCAPWriterReportsAnalysisJobWhileRunning(t *testing.T) {
	dir := t.TempDir()
	rotator, err := pcapstore.NewRotator(
		pcapstore.FileFactory{Directory: dir, Prefix: "job-a--eth0"},
		pcapstore.Limits{MaxBytes: 1 << 20},
	)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := NewPCAPWriter(PCAPWriterConfig{JobID: "job-a", Rotator: rotator, QueueSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- writer.Run(ctx) }()
	deadline := time.Now().Add(time.Second)
	for len(writer.Snapshot().ActiveJobs) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := writer.Snapshot().ActiveJobs; len(got) != 1 || got[0] != "job-a" {
		t.Fatalf("active jobs = %v", got)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := writer.Snapshot().ActiveJobs; len(got) != 0 {
		t.Fatalf("stopped writer active jobs = %v", got)
	}
}

func TestPCAPWriterEnforcesDirectoryQuotaWithoutDeletingPartialSegment(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "old.pcap.uploaded")
	if err := os.WriteFile(old, make([]byte, 80), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(old, time.Unix(1, 0), time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	rotator, err := pcapstore.NewRotator(pcapstore.FileFactory{Directory: dir, Prefix: "eth0"}, pcapstore.Limits{MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	writer, err := NewPCAPWriter(PCAPWriterConfig{Rotator: rotator, QueueSize: 2, Directory: dir, MaxDiskBytes: 100})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- writer.Run(ctx) }()
	frame := make([]byte, 40)
	if !writer.Enqueue(packet.Packet{Timestamp: time.Unix(2, 0), CapturedLength: len(frame), WireLength: len(frame), RawFrame: frame}) {
		t.Fatal("packet enqueue failed")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("old uploaded segment was not evicted: %v", err)
	}
	partials, err := filepath.Glob(filepath.Join(dir, "*.partial"))
	if err != nil || len(partials) != 0 {
		t.Fatalf("partial segments remain: %v, %v", partials, err)
	}
}

func TestMakePCAPRoomProtectsPendingUpload(t *testing.T) {
	dir := t.TempDir()
	pending := filepath.Join(dir, "pending.pcap")
	if err := os.WriteFile(pending, make([]byte, 80), 0600); err != nil {
		t.Fatal(err)
	}
	ok, err := makePCAPRoom(dir, 100, 40)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("quota reported room by evicting an unacknowledged segment")
	}
	if _, err := os.Stat(pending); err != nil {
		t.Fatalf("pending segment was removed: %v", err)
	}
}

func TestPCAPStartupDefersCrashRecoveryUntilNewGroupRuns(t *testing.T) {
	dir := t.TempDir()
	partial := filepath.Join(dir, "active.pcap.partial")
	if err := os.WriteFile(partial, []byte("open segment"), 0600); err != nil {
		t.Fatal(err)
	}
	startup := NewPCAPStartup(dir)
	if _, err := os.Stat(partial); err != nil {
		t.Fatalf("startup construction modified active partial: %v", err)
	}
	if err := startup.Prepare(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(partial); !os.IsNotExist(err) {
		t.Fatalf("partial was not recovered: %v", err)
	}
	if err := startup.Prepare(); err != nil {
		t.Fatalf("shared startup was not idempotent: %v", err)
	}
}

type blockingPCAPFactory struct {
	opened  chan struct{}
	release chan struct{}
}

func (f *blockingPCAPFactory) Open(int, time.Time) (pcapstore.Segment, error) {
	close(f.opened)
	return &blockingPCAPSegment{release: f.release}, nil
}

type blockingPCAPSegment struct{ release <-chan struct{} }

func (s *blockingPCAPSegment) WritePacket(pcapstore.PacketInfo, []byte) error {
	<-s.release
	return nil
}
func (*blockingPCAPSegment) Close(pcapstore.RotationReason) error { return nil }

func TestPCAPBudgetIsSharedAcrossInterfaceWriters(t *testing.T) {
	dir := t.TempDir()
	budget := NewPCAPBudget(0, 70)
	newWriter := func(prefix string) *PCAPWriter {
		rotator, err := pcapstore.NewRotator(
			pcapstore.FileFactory{Directory: dir, Prefix: prefix},
			pcapstore.Limits{MaxBytes: 1 << 20},
		)
		if err != nil {
			t.Fatal(err)
		}
		writer, err := NewPCAPWriter(PCAPWriterConfig{JobID: "job-a", Rotator: rotator, QueueSize: 1, Budget: budget})
		if err != nil {
			t.Fatal(err)
		}
		return writer
	}
	first, second := newWriter("job-a--eth0"), newWriter("job-a--eth1")
	packet := packet.Packet{Timestamp: time.Unix(1, 0), WireLength: 10, RawFrame: make([]byte, 10)}
	first.write(packet)
	second.write(packet)
	if err := first.cfg.Rotator.Close(); err != nil {
		t.Fatal(err)
	}
	if err := second.cfg.Rotator.Close(); err != nil {
		t.Fatal(err)
	}

	files, err := filepath.Glob(filepath.Join(dir, "*.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("PCAP files = %v", files)
	}
	if second.Snapshot().PCAPDroppedPackets != 1 {
		t.Fatalf("second writer snapshot = %+v", second.Snapshot())
	}
}
