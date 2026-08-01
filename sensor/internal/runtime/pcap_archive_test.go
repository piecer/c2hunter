package runtime

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type pcapArchiveUploaderStub struct {
	mu       sync.Mutex
	segments map[string][]byte
	jobIDs   []string
	err      error
}

func (u *pcapArchiveUploaderStub) UploadPCAPSegment(_ context.Context, sensorID, segmentID, jobID, filename string, content io.Reader, size int64) error {
	data, err := io.ReadAll(content)
	if err != nil {
		return err
	}
	if int64(len(data)) != size {
		return io.ErrUnexpectedEOF
	}
	if u.err != nil {
		return u.err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.segments == nil {
		u.segments = make(map[string][]byte)
	}
	u.jobIDs = append(u.jobIDs, jobID)
	u.segments[sensorID+":"+segmentID+":"+filename] = data
	return nil
}

func (u *pcapArchiveUploaderStub) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.segments)
}

func TestPCAPArchiveRestoresAnalysisJobIDFromFilename(t *testing.T) {
	if got := analysisJobIDFromPCAPFilename("job-a--eth0-outbound-000001.pcap"); got != "job-a" {
		t.Fatalf("job ID = %q", got)
	}
	if got := analysisJobIDFromPCAPFilename("legacy-eth0-000001.pcap"); got != "" {
		t.Fatalf("legacy job ID = %q", got)
	}
}

func TestPCAPArchiveManagerClaimsUploadsAndMarksFinalizedSegment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eth0-000001.pcap")
	if err := os.WriteFile(path, []byte("pcap"), 0600); err != nil {
		t.Fatal(err)
	}
	uploader := &pcapArchiveUploaderStub{}
	manager, err := NewPCAPArchiveManager(PCAPArchiveManagerConfig{SensorID: "sensor-a", Directory: dir, Uploader: uploader, ScanInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- manager.Run(ctx) }()
	deadline := time.Now().Add(time.Second)
	for uploader.count() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if uploader.count() != 1 {
		t.Fatal("segment was not uploaded")
	}
	if _, err := os.Stat(path + ".uploaded"); err != nil {
		t.Fatalf("uploaded marker missing: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("unclaimed finalized segment remains: %v", err)
	}
}

func TestPCAPArchiveManagerRestoresInterruptedClaimBeforeRetry(t *testing.T) {
	dir := t.TempDir()
	claimed := filepath.Join(dir, "eth0-000001.pcap.uploading")
	if err := os.WriteFile(claimed, []byte("pcap"), 0600); err != nil {
		t.Fatal(err)
	}
	uploader := &pcapArchiveUploaderStub{}
	manager, err := NewPCAPArchiveManager(PCAPArchiveManagerConfig{SensorID: "sensor-a", Directory: dir, Uploader: uploader, ScanInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := manager.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if uploader.count() != 1 {
		t.Fatal("interrupted claim was not retried")
	}
	if _, err := os.Stat(filepath.Join(dir, "eth0-000001.pcap.uploaded")); err != nil {
		t.Fatalf("retried segment was not marked uploaded: %v", err)
	}
}

func TestPCAPArchiveManagerIgnoresSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "outside.pcap")
	if err := os.WriteFile(target, []byte("pcap"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked.pcap")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	uploader := &pcapArchiveUploaderStub{}
	manager, err := NewPCAPArchiveManager(PCAPArchiveManagerConfig{SensorID: "sensor-a", Directory: dir, Uploader: uploader, ScanInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := manager.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if uploader.count() != 0 {
		t.Fatal("symlink was uploaded")
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("symlink was modified: %v", err)
	}
}

func TestPCAPArchiveManagerUploadsSegmentFinalizedDuringShutdown(t *testing.T) {
	dir := t.TempDir()
	partial := filepath.Join(dir, "eth0-000001.pcap.partial")
	if err := os.WriteFile(partial, []byte("pcap"), 0600); err != nil {
		t.Fatal(err)
	}
	uploader := &pcapArchiveUploaderStub{}
	manager, err := NewPCAPArchiveManager(PCAPArchiveManagerConfig{SensorID: "sensor-a", Directory: dir, Uploader: uploader, ScanInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- manager.Run(ctx) }()
	cancel()
	finalized := strings.TrimSuffix(partial, ".partial")
	if err := os.Rename(partial, finalized); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if uploader.count() != 1 {
		t.Fatal("segment finalized during shutdown was not uploaded")
	}
}
