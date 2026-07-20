package runtime

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type controllableCapture struct {
	started chan struct{}
	stopped chan struct{}
	once    sync.Once
	snap    CaptureSnapshot
	err     error
}

func (c *controllableCapture) Run(ctx context.Context) error {
	c.once.Do(func() { close(c.started) })
	if c.err != nil {
		return c.err
	}
	<-ctx.Done()
	close(c.stopped)
	return nil
}
func (c *controllableCapture) Snapshot() CaptureSnapshot { return c.snap }

func TestSupervisorReconfiguresSafelyAndKeepsHealthyInterfacesRunning(t *testing.T) {
	good := &controllableCapture{started: make(chan struct{}), stopped: make(chan struct{}), snap: CaptureSnapshot{Interfaces: []InterfaceSnapshot{{Interface: "eth0", Status: "RUNNING"}}}}
	failed := &controllableCapture{started: make(chan struct{}), stopped: make(chan struct{}), err: errors.New("eth1 denied"), snap: CaptureSnapshot{LastError: "eth1 denied", Interfaces: []InterfaceSnapshot{{Interface: "eth1", Status: "ERROR", LastError: "eth1 denied"}}}}
	next := &controllableCapture{started: make(chan struct{}), stopped: make(chan struct{}), snap: CaptureSnapshot{Interfaces: []InterfaceSnapshot{{Interface: "eth2", Status: "RUNNING"}}}}

	s := NewSupervisor()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	if err := s.Apply(1, []CaptureRuntime{good, failed}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-good.started:
	case <-time.After(time.Second):
		t.Fatal("healthy interface did not start")
	}
	time.Sleep(10 * time.Millisecond)
	snap := s.Snapshot()
	if snap.LastError == "" || len(snap.Interfaces) != 2 {
		t.Fatalf("partial snapshot = %+v", snap)
	}
	if err := s.Apply(2, []CaptureRuntime{next}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-good.stopped:
	case <-time.After(time.Second):
		t.Fatal("old pipeline was not stopped before replacement")
	}
	select {
	case <-next.started:
	case <-time.After(time.Second):
		t.Fatal("replacement did not start")
	}
	if s.Version() != 2 {
		t.Fatalf("version = %d", s.Version())
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
