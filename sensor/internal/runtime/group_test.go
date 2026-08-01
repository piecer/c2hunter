package runtime

import (
	"context"
	"errors"
	"testing"
	"time"
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

type waitingCaptureRuntime struct {
	stopped chan struct{}
}

func (r *waitingCaptureRuntime) Run(ctx context.Context) error {
	<-ctx.Done()
	close(r.stopped)
	return ctx.Err()
}
func (*waitingCaptureRuntime) Snapshot() CaptureSnapshot { return CaptureSnapshot{} }

type backgroundWaitingRuntime struct{ *waitingCaptureRuntime }

func (*backgroundWaitingRuntime) backgroundRuntime() {}

type backgroundErrorRuntime struct{ *captureRuntimeStub }

func (*backgroundErrorRuntime) backgroundRuntime() {}

type orderedShutdownRuntime struct {
	*waitingCaptureRuntime
	predecessor <-chan struct{}
	ordered     chan bool
}

func (*orderedShutdownRuntime) backgroundRuntime()         {}
func (*orderedShutdownRuntime) trailingBackgroundRuntime() {}

func (r *orderedShutdownRuntime) Run(ctx context.Context) error {
	<-ctx.Done()
	select {
	case <-r.predecessor:
		r.ordered <- true
	default:
		r.ordered <- false
	}
	close(r.stopped)
	return nil
}

func TestCaptureGroupCancelsRemainingMembersAfterForegroundFailure(t *testing.T) {
	waiting := &waitingCaptureRuntime{stopped: make(chan struct{})}
	background := &backgroundWaitingRuntime{waitingCaptureRuntime: &waitingCaptureRuntime{stopped: make(chan struct{})}}
	group, err := NewCaptureGroup([]CaptureRuntime{
		&captureRuntimeStub{err: errors.New("capture failed")},
		waiting,
		background,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := group.Run(context.Background()); err == nil {
		t.Fatal("foreground failure was hidden")
	}
	for name, stopped := range map[string]<-chan struct{}{"foreground": waiting.stopped, "background": background.stopped} {
		select {
		case <-stopped:
		case <-time.After(time.Second):
			t.Fatalf("%s runtime was not canceled", name)
		}
	}
}

func TestCaptureGroupCancelsForegroundAfterBackgroundFailure(t *testing.T) {
	waiting := &waitingCaptureRuntime{stopped: make(chan struct{})}
	group, err := NewCaptureGroup([]CaptureRuntime{
		waiting,
		&backgroundErrorRuntime{captureRuntimeStub: &captureRuntimeStub{err: errors.New("PCAP startup failed")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := group.Run(context.Background()); err == nil {
		t.Fatal("background failure was hidden")
	}
	select {
	case <-waiting.stopped:
	case <-time.After(time.Second):
		t.Fatal("foreground runtime was not canceled")
	}
}

func TestCaptureGroupStopsTrailingBackgroundAfterOtherBackgrounds(t *testing.T) {
	foreground := &waitingCaptureRuntime{stopped: make(chan struct{})}
	background := &backgroundWaitingRuntime{waitingCaptureRuntime: &waitingCaptureRuntime{stopped: make(chan struct{})}}
	trailing := &orderedShutdownRuntime{
		waitingCaptureRuntime: &waitingCaptureRuntime{stopped: make(chan struct{})},
		predecessor:           background.stopped,
		ordered:               make(chan bool, 1),
	}
	group, err := NewCaptureGroup([]CaptureRuntime{foreground, background, trailing})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- group.Run(ctx) }()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !<-trailing.ordered {
		t.Fatal("trailing background stopped before regular background")
	}
}
