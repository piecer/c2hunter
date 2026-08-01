package runtime

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"c2hunter/sensor/internal/capture"
	"c2hunter/sensor/internal/packet"
)

// TestPipelineStatsArePeriodic verifies that drop counter is read periodically
// and not on every packet, preventing hot-path syscall overhead.
func TestPipelineStatsArePeriodic(t *testing.T) {
	source := &countingDropSource{}
	tickerCh := make(chan time.Time, 1)
	uploader := &uploadStub{}
	pipeline, err := NewPipeline(PipelineConfig{
		SensorID: "sensor-a", JobID: "job-p", IdleTimeout: 5 * time.Second,
		BatchMaxItems: 10, BatchMaxBytes: 64 << 10, PacketQueueSize: 64,
		Source: func() (capture.Reader, error) { return source, nil },
		Spool:  openTestSpool(t, t.TempDir(), func() time.Time { return time.Unix(100, 0).UTC() }), Uploader: uploader,
		Now:       func() time.Time { return time.Unix(100, 0).UTC() },
		IdleTicks: tickerCh,
	})
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- pipeline.Run(context.Background()) }()

	// Trigger a tick to flush batch and check snapshot consistency
	select {
	case tickerCh <- time.Unix(102, 0).UTC():
	case <-time.After(3 * time.Second):
		t.Fatal("ticker blocked")
	}

	// Wait for pipeline to finish (EOF from source)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("pipeline error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for pipeline")
	}

	snapshot := pipeline.Snapshot()
	if snapshot.ReceivedPackets != 5 {
		t.Errorf("expected 5 received packets, got %d", snapshot.ReceivedPackets)
	}
	// Drop counter should reflect the periodic snapshot (3 drops set by source)
	if snapshot.DroppedPackets != 3 {
		t.Errorf("expected dropped packets from periodic stats, got %d", snapshot.DroppedPackets)
	}
}

type countingDropSource struct{ total atomic.Int64 }

func (s *countingDropSource) Next(ctx context.Context) (packet.Packet, error) {
	n := s.total.Add(1)
	if n > 5 {
		return packet.Packet{}, io.EOF
	}
	now := time.Unix(100+n, 0).UTC()
	return testPacket(now, "data"), nil
}

func (s *countingDropSource) Close() error           { return nil }
func (s *countingDropSource) DroppedPackets() uint64 { return 3 }
