package runtime

import (
	"context"
	"errors"
	"testing"
)

func TestCaptureGroupAggregatesInterfaceMetricsAndErrors(t *testing.T) {
	group, err := NewCaptureGroup([]CaptureRuntime{
		&captureRuntimeStub{snapshot: CaptureSnapshot{ReceivedPackets: 5, DroppedPackets: 1, DecodeErrors: 1, PendingBytes: 10, ActiveJobs: []string{"job-a"}}},
		&captureRuntimeStub{snapshot: CaptureSnapshot{ReceivedPackets: 7, DroppedPackets: 2, DecodeErrors: 2, PendingBytes: 20, ActiveJobs: []string{"job-a"}, LastError: "eth1 failed"}, err: errors.New("eth1 failed")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := group.Run(context.Background()); err == nil {
		t.Fatal("capture error was hidden")
	}
	got := group.Snapshot()
	if got.ReceivedPackets != 12 || got.DroppedPackets != 3 || got.DecodeErrors != 3 || got.PendingBytes != 20 || len(got.ActiveJobs) != 1 || got.LastError == "" {
		t.Fatalf("snapshot = %+v", got)
	}
}
